package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestF092GeneratedSecretsHaveIndependentFormats(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		password, err := (SecretSpec{Key: "POSTGRES_PASSWORD", Kind: SecretPassword}).Generate()
		if err != nil {
			t.Fatalf("Generate(password) error = %v", err)
		}
		if len(password) != 32 {
			t.Fatalf("generated password length = %d, want 32 RawURL characters", len(password))
		}
		decodedPassword, err := base64.RawURLEncoding.DecodeString(password)
		if err != nil {
			t.Fatalf("generated password is not raw URL base64: %v", err)
		}
		if len(decodedPassword) != 24 {
			t.Fatalf("generated password entropy bytes = %d, want 24", len(decodedPassword))
		}
		for _, c := range password {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			t.Fatalf("generated password contains non-URL-safe character %q", c)
		}
	})

	t.Run("base64 key", func(t *testing.T) {
		key, err := (SecretSpec{Key: "PACKMON_ENCRYPTION_KEY", Kind: SecretBase64Bytes, Bytes: 32}).Generate()
		if err != nil {
			t.Fatalf("Generate(base64 key) error = %v", err)
		}
		if len(key) != 44 || !strings.HasSuffix(key, "=") {
			t.Fatalf("generated key format = %q (len %d), want padded 44-character standard base64", key, len(key))
		}
		decodedKey, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			t.Fatalf("generated key is not standard base64: %v", err)
		}
		if len(decodedKey) != 32 {
			t.Fatalf("generated key entropy bytes = %d, want 32", len(decodedKey))
		}
	})
}

func TestF092Base64ValidationBoundaries(t *testing.T) {
	spec := SecretSpec{Key: "PACKMON_ENCRYPTION_KEY", Kind: SecretBase64Bytes, Bytes: 32}
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, value := range []string{" \t" + valid + "\n ", valid} {
		if err := spec.Validate(value); err != nil {
			t.Fatalf("Validate(%q) error = %v, want valid", value, err)
		}
	}
	for _, value := range []string{`""`, `''`} {
		if err := spec.Validate(value); err == nil || !strings.Contains(err.Error(), "empty") || !strings.Contains(err.Error(), "32") {
			t.Fatalf("Validate(%q) error = %v, want empty exact-length diagnostic", value, err)
		}
	}
	oversized := base64.StdEncoding.EncodeToString(make([]byte, 33))
	if err := spec.Validate(oversized); err == nil || !strings.Contains(err.Error(), "decoded to 33 bytes") || !strings.Contains(err.Error(), "expected 32") {
		t.Fatalf("Validate(33-byte key) error = %v, want exact-length diagnostic", err)
	}
}

func TestF092ProductionSecretModesAndDeterministicDiagnostics(t *testing.T) {
	validEncryption := base64.StdEncoding.EncodeToString(make([]byte, 32))
	validHMAC := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	const invalidEncryption = "encryption-secret-value-not-base64"
	const invalidHMAC = "hmac-secret-value-not-base64"

	tests := []struct {
		name      string
		env       map[string]string
		wantKeys  []string
		wantNoErr bool
		wantCount string
	}{
		{
			name: "exact development skips validation",
			env: map[string]string{
				"PACKMON_SERVER_MODE":          "development",
				"PACKMON_ENCRYPTION_KEY":       invalidEncryption,
				"PACKMON_ADMIN_AUDIT_HMAC_KEY": invalidHMAC,
			},
			wantNoErr: true,
		},
		{
			name: "production accepts two valid keys",
			env: map[string]string{
				"PACKMON_SERVER_MODE":          "production",
				"PACKMON_ENCRYPTION_KEY":       validEncryption,
				"PACKMON_ADMIN_AUDIT_HMAC_KEY": validHMAC,
			},
			wantNoErr: true,
		},
		{
			name:      "unset mode remains production-like",
			env:       map[string]string{"PACKMON_ENCRYPTION_KEY": invalidEncryption, "PACKMON_ADMIN_AUDIT_HMAC_KEY": invalidHMAC},
			wantKeys:  []string{"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY"},
			wantCount: "2 secret(s)",
		},
		{
			name: "misspelled development remains production-like",
			env: map[string]string{
				"PACKMON_SERVER_MODE":          "developmnt",
				"PACKMON_ENCRYPTION_KEY":       invalidEncryption,
				"PACKMON_ADMIN_AUDIT_HMAC_KEY": invalidHMAC,
			},
			wantKeys:  []string{"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY"},
			wantCount: "2 secret(s)",
		},
		{
			name: "padded development remains production-like",
			env: map[string]string{
				"PACKMON_SERVER_MODE":          " development ",
				"PACKMON_ENCRYPTION_KEY":       invalidEncryption,
				"PACKMON_ADMIN_AUDIT_HMAC_KEY": invalidHMAC,
			},
			wantKeys:  []string{"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY"},
			wantCount: "2 secret(s)",
		},
		{
			name: "one invalid key",
			env: map[string]string{
				"PACKMON_SERVER_MODE":          "production",
				"PACKMON_ENCRYPTION_KEY":       invalidEncryption,
				"PACKMON_ADMIN_AUDIT_HMAC_KEY": validHMAC,
			},
			wantKeys:  []string{"PACKMON_ENCRYPTION_KEY"},
			wantCount: "1 secret(s)",
		},
		{
			name: "two invalid keys retain required order",
			env: map[string]string{
				"PACKMON_SERVER_MODE":          "production",
				"PACKMON_ENCRYPTION_KEY":       invalidEncryption,
				"PACKMON_ADMIN_AUDIT_HMAC_KEY": invalidHMAC,
			},
			wantKeys:  []string{"PACKMON_ENCRYPTION_KEY", "PACKMON_ADMIN_AUDIT_HMAC_KEY"},
			wantCount: "2 secret(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProductionSecrets(func(key string) string { return tt.env[key] })
			if tt.wantNoErr {
				if err != nil {
					t.Fatalf("ValidateProductionSecrets() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ValidateProductionSecrets() error = nil")
			}
			message := err.Error()
			if !strings.Contains(message, tt.wantCount) {
				t.Fatalf("error = %q, want count %q", message, tt.wantCount)
			}
			previous := -1
			for _, key := range tt.wantKeys {
				index := strings.Index(message, key)
				if index < 0 {
					t.Fatalf("error = %q, want key %s", message, key)
				}
				if index <= previous {
					t.Fatalf("error keys not in required order: %q", message)
				}
				previous = index
			}
			for _, secret := range []string{invalidEncryption, invalidHMAC} {
				if strings.Contains(message, secret) {
					t.Fatalf("error disclosed configured secret %q: %q", secret, message)
				}
			}
		})
	}
}

func TestGeneratedBase64KeyValidates(t *testing.T) {
	s := SecretSpec{Key: "PACKMON_ENCRYPTION_KEY", Kind: SecretBase64Bytes, Bytes: 32}
	v, err := s.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := s.Validate(v); err != nil {
		t.Fatalf("validate generated: %v", err)
	}
}

func TestValidateBase64Failures(t *testing.T) {
	s := SecretSpec{Key: "K", Kind: SecretBase64Bytes, Bytes: 32}
	if err := s.Validate(""); err == nil {
		t.Fatal("empty must fail")
	}
	if err := s.Validate("not base64 %%%"); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("bad base64 err = %v", err)
	}
	short := s.Validate("YWJj") // "abc" -> 3 bytes
	if short == nil || !strings.Contains(short.Error(), "expected 32") {
		t.Fatalf("short err = %v", short)
	}
}

func TestSecretPasswordValidateRejectsBlankValues(t *testing.T) {
	s := SecretSpec{Key: "POSTGRES_PASSWORD", Kind: SecretPassword}
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "empty", value: "", wantErr: true},
		{name: "whitespace", value: " \t\n ", wantErr: true},
		{name: "double quoted empty", value: `""`, wantErr: true},
		{name: "single quoted empty", value: `''`, wantErr: true},
		{name: "nonempty", value: "correct horse battery staple"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Validate(tc.value)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate(%q) error = %v, wantErr %t", tc.value, err, tc.wantErr)
			}
			if tc.wantErr && (err == nil || err.Error() != "empty") {
				t.Fatalf("Validate(%q) error = %v, want empty error", tc.value, err)
			}
		})
	}
}

func TestValidateProductionSecretsAggregates(t *testing.T) {
	env := map[string]string{
		"PACKMON_SERVER_MODE":          "production",
		"PACKMON_ENCRYPTION_KEY":       "YWJj", // 3 bytes -> wrong length
		"PACKMON_ADMIN_AUDIT_HMAC_KEY": "",     // empty
	}
	err := ValidateProductionSecrets(func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("want aggregated error")
	}
	msg := err.Error()
	for _, want := range []string{
		"PACKMON_ENCRYPTION_KEY",
		"PACKMON_ADMIN_AUDIT_HMAC_KEY",
		"docker compose --profile bootstrap run --rm --no-deps init-secrets",
		"Troubleshooting",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("aggregated error missing %q in:\n%s", want, msg)
		}
	}
}

func TestValidateProductionSecretsSkipsDevelopment(t *testing.T) {
	env := map[string]string{"PACKMON_SERVER_MODE": "development"}
	if err := ValidateProductionSecrets(func(k string) string { return env[k] }); err != nil {
		t.Fatalf("development must skip, got %v", err)
	}
}
