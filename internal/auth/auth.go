// Package auth implements admin authentication for the Packmon server.
// It provides password hashing via bcrypt, admin bootstrap logic, and
// session management using secure, in-memory sessions.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the work factor for bcrypt hashing. 12 provides a good
// balance between security and latency (~250ms on modern hardware).
const bcryptCost = 12

// MinAdminPasswordLength is the shared minimum length for bootstrap and
// rotated admin passwords, counted in Unicode characters (code points), not
// bytes.
const MinAdminPasswordLength = 12

// MaxAdminPasswordBytes is the longest admin password in bytes (UTF-8), not
// characters. It is bcrypt's input limit: HashPassword refuses longer input,
// so the policy rejects it up front with its own error.
const MaxAdminPasswordBytes = 72

var (
	// ErrAdminPasswordTooShort reports a password with fewer than
	// MinAdminPasswordLength characters.
	ErrAdminPasswordTooShort = fmt.Errorf("auth: admin password must be at least %d characters", MinAdminPasswordLength)
	// ErrAdminPasswordTooLong reports a password longer than
	// MaxAdminPasswordBytes bytes.
	ErrAdminPasswordTooLong = fmt.Errorf("auth: admin password must be at most %d bytes", MaxAdminPasswordBytes)
)

// AdminBootstrapStore is the persistence surface needed to bootstrap the
// shared admin account and audit that event.
type AdminBootstrapStore interface {
	GetAdminBootstrapAuth(ctx context.Context) (*AdminBootstrapAuth, error)
	UpsertAdminBootstrapAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *AdminBootstrapAuditEntry) error
}

// AdminBootstrapAuth is the auth-owned view of the shared admin credential.
type AdminBootstrapAuth struct {
	PasswordHash        string
	PasswordIsBootstrap bool
}

// AdminBootstrapAuditEntry is the auth-owned audit payload emitted during
// bootstrap. Persistence adapters translate it to their storage record type.
type AdminBootstrapAuditEntry struct {
	Action        string
	Details       json.RawMessage
	IP            string
	CorrelationID string
}

// ValidateAdminPassword enforces the shared admin password policy. The
// minimum counts code points so multi-byte characters cannot satisfy it with
// fewer than MinAdminPasswordLength characters; the maximum counts bytes
// because bcrypt does. It returns ErrAdminPasswordTooShort or
// ErrAdminPasswordTooLong.
func ValidateAdminPassword(password string) error {
	if utf8.RuneCountInString(password) < MinAdminPasswordLength {
		return ErrAdminPasswordTooShort
	}
	if len(password) > MaxAdminPasswordBytes {
		return ErrAdminPasswordTooLong
	}
	return nil
}

// HashPassword returns a bcrypt hash of the given plaintext password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword returns true if the plaintext password matches the
// bcrypt hash. It returns false for any mismatch or error, and never
// leaks timing information about the hash comparison.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// fallbackLoginEqualizerHash is a bcrypt hash at bcryptCost of a random value
// that was discarded after hashing; it protects nothing and matches no
// password. EqualizePasswordCheck compares against it when a fresh dummy hash
// cannot be generated, so login timing equalization never silently turns into
// an instant rejection.
const fallbackLoginEqualizerHash = "$2a$12$yWqtWCvstq4DKlyPJMOSQ.rO/OSyC3hEDDlEMqToSLhJLgfxiL8la" // #nosec G101 -- dummy timing-equalizer hash of a discarded random value, not a credential.

var (
	dummyPasswordHashOnce sync.Once
	dummyPasswordHash     []byte
)

// PrepareLoginEqualizer generates the dummy hash EqualizePasswordCheck
// compares against. Server startup calls it before serving so the first
// failed login pays for one comparison, not a generation plus a comparison,
// and concurrent first logins do not wait on the generation. It is idempotent.
func PrepareLoginEqualizer() {
	dummyPasswordHashOnce.Do(func() {
		dummyPasswordHash = loginEqualizerHash(generateLoginEqualizerHash)
	})
}

// EqualizePasswordCheck spends the cost of one CheckPassword call on a login
// failure that has no stored hash to compare against (an unknown username or
// a missing admin account), so those failures cannot be told apart from a
// wrong password by response time. The result is always discarded.
func EqualizePasswordCheck(password string) {
	PrepareLoginEqualizer()
	_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
}

func generateLoginEqualizerHash() ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(secret)), bcryptCost)
}

// loginEqualizerHash returns the generated dummy hash, or the embedded
// fallback when generation fails or yields anything but a bcryptCost hash.
func loginEqualizerHash(generate func() ([]byte, error)) []byte {
	hash, err := generate()
	if err == nil {
		if cost, costErr := bcrypt.Cost(hash); costErr == nil && cost == bcryptCost {
			return hash
		}
	}
	return []byte(fallbackLoginEqualizerHash)
}

// BootstrapAdmin creates the admin row in the database if it does not
// exist yet (DE-9). The initialPassword is the plaintext value from
// PACKMON_ADMIN_INITIAL_PASSWORD. If the admin row already exists, the
// environment variable is silently ignored and a log message is emitted.
//
// This function must only be called once during server startup.
func BootstrapAdmin(ctx context.Context, store AdminBootstrapStore, initialPassword string, logger *slog.Logger) error {
	existing, err := store.GetAdminBootstrapAuth(ctx)
	if err != nil {
		return fmt.Errorf("auth: check existing admin: %w", err)
	}

	if existing != nil {
		logger.Info("admin account already exists, skipping bootstrap")
		return nil
	}

	// No admin row exists -- this is the first start.
	if initialPassword == "" {
		logger.Warn("no admin account exists and PACKMON_ADMIN_INITIAL_PASSWORD is not set -- admin login will be unavailable until a password is configured")
		return nil
	}
	if err := ValidateAdminPassword(initialPassword); err != nil {
		return err
	}

	hash, err := HashPassword(initialPassword)
	if err != nil {
		return fmt.Errorf("auth: bootstrap admin: %w", err)
	}

	// Audit the bootstrap event.
	details, _ := json.Marshal(map[string]string{
		"actor": "system",
		"event": "admin_bootstrap",
		"note":  "initial admin password set from environment variable",
	})
	audit := &AdminBootstrapAuditEntry{
		Action:  "admin_bootstrap",
		Details: details,
	}

	if err := store.UpsertAdminBootstrapAuthWithAudit(ctx, hash, true, audit); err != nil {
		return fmt.Errorf("auth: bootstrap admin: %w", err)
	}

	logger.Info("initial admin password was set from environment")
	return nil
}
