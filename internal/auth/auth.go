// Package auth implements admin authentication for the Packmon server.
// It provides password hashing via bcrypt, admin bootstrap logic, and
// session management using secure, in-memory sessions.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/8linkz-sec/packmon/internal/db"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is the work factor for bcrypt hashing. 12 provides a good
// balance between security and latency (~250ms on modern hardware).
const bcryptCost = 12

// MinAdminPasswordLength is the shared minimum length for bootstrap and
// rotated admin passwords.
const MinAdminPasswordLength = 12

// AdminBootstrapStore is the persistence surface needed to bootstrap the
// shared admin account and audit that event.
type AdminBootstrapStore interface {
	GetAdminAuth(ctx context.Context) (*db.AdminAuth, error)
	UpsertAdminAuth(ctx context.Context, passwordHash string, isBootstrap bool) error
	InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error
}

// ValidateAdminPassword enforces the shared admin password policy.
func ValidateAdminPassword(password string) error {
	if len(password) < MinAdminPasswordLength {
		return fmt.Errorf("auth: admin password must be at least %d characters", MinAdminPasswordLength)
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

// BootstrapAdmin creates the admin row in the database if it does not
// exist yet (DE-9). The initialPassword is the plaintext value from
// PACKMON_ADMIN_INITIAL_PASSWORD. If the admin row already exists, the
// environment variable is silently ignored and a log message is emitted.
//
// This function must only be called once during server startup.
func BootstrapAdmin(ctx context.Context, store AdminBootstrapStore, initialPassword string, logger *slog.Logger) error {
	existing, err := store.GetAdminAuth(ctx)
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

	if err := store.UpsertAdminAuth(ctx, hash, true); err != nil {
		return fmt.Errorf("auth: bootstrap admin: %w", err)
	}

	// Audit the bootstrap event.
	details, _ := json.Marshal(map[string]string{
		"actor": "system",
		"event": "admin_bootstrap",
		"note":  "initial admin password set from environment variable",
	})
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
		Action:  "admin_bootstrap",
		Details: details,
	}); err != nil {
		return fmt.Errorf("auth: audit bootstrap admin: %w", err)
	}

	logger.Info("initial admin password was set from environment")
	return nil
}
