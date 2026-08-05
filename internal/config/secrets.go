package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// SecretKind classifies how a required secret is generated and validated.
type SecretKind int

const (
	// SecretPassword is any non-empty string.
	SecretPassword SecretKind = iota
	// SecretBase64Bytes is base64(std) of exactly Bytes random bytes.
	SecretBase64Bytes
)

// SecretSpec describes one required secret.
type SecretSpec struct {
	Key   string
	Kind  SecretKind
	Bytes int
}

// RequiredSecrets lists the secrets init-secrets manages, in generation order.
// POSTGRES_PASSWORD is generated before PACKMON_DB_PASSWORD so the latter can
// mirror it.
func RequiredSecrets() []SecretSpec {
	return []SecretSpec{
		{Key: "POSTGRES_PASSWORD", Kind: SecretPassword},
		{Key: "PACKMON_DB_PASSWORD", Kind: SecretPassword},
		{Key: "PACKMON_ADMIN_INITIAL_PASSWORD", Kind: SecretPassword},
		{Key: "PACKMON_ENCRYPTION_KEY", Kind: SecretBase64Bytes, Bytes: 32},
		{Key: "PACKMON_ADMIN_AUDIT_HMAC_KEY", Kind: SecretBase64Bytes, Bytes: 32},
	}
}

// Generate returns a fresh value satisfying the spec.
func (s SecretSpec) Generate() (string, error) {
	switch s.Kind {
	case SecretBase64Bytes:
		buf := make([]byte, s.Bytes)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate %s: %w", s.Key, err)
		}
		return base64.StdEncoding.EncodeToString(buf), nil
	default:
		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate %s: %w", s.Key, err)
		}
		return base64.RawURLEncoding.EncodeToString(buf), nil
	}
}

// Validate returns a human-readable reason string via error when value is
// unusable, or nil when valid.
func (s SecretSpec) Validate(value string) error {
	v := strings.TrimSpace(value)
	if v == "" || v == `""` || v == `''` {
		if s.Kind == SecretBase64Bytes {
			return fmt.Errorf("empty (expected base64-encoded %d bytes)", s.Bytes)
		}
		return fmt.Errorf("empty")
	}
	if s.Kind == SecretBase64Bytes {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return fmt.Errorf("not valid base64 (expected base64-encoded %d bytes)", s.Bytes)
		}
		if len(raw) != s.Bytes {
			return fmt.Errorf("decoded to %d bytes (expected %d)", len(raw), s.Bytes)
		}
	}
	return nil
}

// ValidateProductionSecrets aggregates all invalid format-constrained secrets
// into a single actionable error. It returns nil in development mode.
//
// The development-mode check mirrors (*Config).IsDevelopment: an exact match
// against ModeDevelopment, so a caller passing os.Getenv sees the same
// production/development determination the rest of the config package uses.
func ValidateProductionSecrets(getenv func(string) string) error {
	if ServerMode(getenv("PACKMON_SERVER_MODE")) == ModeDevelopment {
		return nil
	}
	var problems []string
	for _, s := range RequiredSecrets() {
		if s.Kind != SecretBase64Bytes {
			continue
		}
		if err := s.Validate(getenv(s.Key)); err != nil {
			problems = append(problems, fmt.Sprintf("  • %s: %s", s.Key, err.Error()))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("configuration incomplete — %d secret(s) missing or invalid:\n%s\n"+
		"Fix locally:  docker compose run --rm init-secrets\n"+
		"Details:      README → Troubleshooting",
		len(problems), strings.Join(problems, "\n"))
}
