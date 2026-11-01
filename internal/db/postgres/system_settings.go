package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetSystemSettings(ctx context.Context) (*db.SystemSettings, error) {
	const query = `
		SELECT
			block_threshold,
			rate_limit_per_minute,
			rate_limit_burst,
			scan_log_retention_seconds,
			admin_audit_retention_seconds,
			updated_at
		FROM system_settings
		WHERE id = 1`

	var settings db.SystemSettings
	var scanLogRetentionSeconds int64
	var adminAuditRetentionSeconds int64
	err := s.pool.QueryRow(ctx, query).Scan(
		&settings.BlockThreshold,
		&settings.RateLimitPerMinute,
		&settings.RateLimitBurst,
		&scanLogRetentionSeconds,
		&adminAuditRetentionSeconds,
		&settings.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get system settings: %w", err)
	}
	settings.ScanLogRetention = time.Duration(scanLogRetentionSeconds) * time.Second
	settings.AdminAuditRetention = time.Duration(adminAuditRetentionSeconds) * time.Second
	return &settings, nil
}

func (s *Store) UpsertSystemSettings(ctx context.Context, settings *db.SystemSettings) error {
	return upsertSystemSettingsTx(ctx, s.pool, settings)
}

func (s *Store) UpsertSystemSettingsWithAudit(ctx context.Context, settings *db.SystemSettings, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return upsertSystemSettingsWithAuditTx(ctx, tx, settings, audit)
	})
}

func upsertSystemSettingsWithAuditTx(ctx context.Context, tx pgx.Tx, settings *db.SystemSettings, audit *db.AdminAuditEntry) error {
	if err := writeSystemSettingsAtRevisionTx(ctx, tx, settings); err != nil {
		return err
	}
	if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	return nil
}

const (
	upsertSystemSettingsSQL = `
		INSERT INTO system_settings (
			id,
			block_threshold,
			rate_limit_per_minute,
			rate_limit_burst,
			scan_log_retention_seconds,
			admin_audit_retention_seconds
		) VALUES (
			1, $1, $2, $3, $4, $5
		)
		ON CONFLICT (id) DO UPDATE SET
			block_threshold = EXCLUDED.block_threshold,
			rate_limit_per_minute = EXCLUDED.rate_limit_per_minute,
			rate_limit_burst = EXCLUDED.rate_limit_burst,
			scan_log_retention_seconds = EXCLUDED.scan_log_retention_seconds,
			admin_audit_retention_seconds = EXCLUDED.admin_audit_retention_seconds,
			updated_at = NOW()`

	// insertNewSystemSettingsSQL is the first save of a revision-checked write:
	// it only inserts when the singleton row does not exist yet.
	insertNewSystemSettingsSQL = `
		INSERT INTO system_settings (
			id,
			block_threshold,
			rate_limit_per_minute,
			rate_limit_burst,
			scan_log_retention_seconds,
			admin_audit_retention_seconds
		) VALUES (
			1, $1, $2, $3, $4, $5
		)
		ON CONFLICT (id) DO NOTHING`

	// updateSystemSettingsAtRevisionSQL compares the revision in the writing
	// statement itself, so a writer that waited for a concurrent commit
	// re-evaluates it against the new row version and matches nothing.
	updateSystemSettingsAtRevisionSQL = `
		UPDATE system_settings SET
			block_threshold = $1,
			rate_limit_per_minute = $2,
			rate_limit_burst = $3,
			scan_log_retention_seconds = $4,
			admin_audit_retention_seconds = $5,
			updated_at = NOW()
		WHERE id = 1 AND updated_at = $6`
)

// writeSystemSettingsAtRevisionTx writes settings only when the stored
// revision still matches the expected one, checked and written in a single
// statement so two saves holding the same revision cannot both succeed.
func writeSystemSettingsAtRevisionTx(ctx context.Context, execer postgresExecer, settings *db.SystemSettings) error {
	expected, ok := expectedSystemSettingsUpdatedAt(settings)
	if !ok {
		return upsertSystemSettingsTx(ctx, execer, settings)
	}
	if expected.IsZero() {
		return execSystemSettingsWrite(ctx, execer, insertNewSystemSettingsSQL, settings, true)
	}
	return execSystemSettingsWrite(ctx, execer, updateSystemSettingsAtRevisionSQL, settings, true, expected.UTC())
}

func upsertSystemSettingsTx(ctx context.Context, execer postgresExecer, settings *db.SystemSettings) error {
	return execSystemSettingsWrite(ctx, execer, upsertSystemSettingsSQL, settings, false)
}

// execSystemSettingsWrite runs one of the system settings write statements
// with the shared column arguments ($1-$5) followed by extra. When requireRow
// is set, a statement that wrote no row is a lost revision race:
// db.ErrConflict.
func execSystemSettingsWrite(ctx context.Context, execer postgresExecer, query string, settings *db.SystemSettings, requireRow bool, extra ...any) error {
	args := append([]any{
		settings.BlockThreshold,
		settings.RateLimitPerMinute,
		settings.RateLimitBurst,
		int64(settings.ScanLogRetention / time.Second),
		int64(settings.AdminAuditRetention / time.Second),
	}, extra...)
	tag, err := execer.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("postgres: upsert system settings: %w", err)
	}
	if requireRow && tag.RowsAffected() == 0 {
		return db.ErrConflict
	}
	return nil
}

func expectedSystemSettingsUpdatedAt(settings *db.SystemSettings) (time.Time, bool) {
	if settings == nil {
		return time.Time{}, false
	}
	if settings.ExpectedUpdatedAt != nil {
		return *settings.ExpectedUpdatedAt, true
	}
	if !settings.UpdatedAt.IsZero() {
		return settings.UpdatedAt, true
	}
	return time.Time{}, false
}
