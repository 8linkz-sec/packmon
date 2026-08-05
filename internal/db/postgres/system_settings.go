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
		if err := checkSystemSettingsRevisionTx(ctx, tx, settings); err != nil {
			return err
		}
		if err := upsertSystemSettingsTx(ctx, tx, settings); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func upsertSystemSettingsTx(ctx context.Context, execer postgresExecer, settings *db.SystemSettings) error {
	const query = `
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

	_, err := execer.Exec(ctx, query,
		settings.BlockThreshold,
		settings.RateLimitPerMinute,
		settings.RateLimitBurst,
		int64(settings.ScanLogRetention/time.Second),
		int64(settings.AdminAuditRetention/time.Second),
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert system settings: %w", err)
	}
	return nil
}

func checkSystemSettingsRevisionTx(ctx context.Context, tx pgx.Tx, settings *db.SystemSettings) error {
	expected, ok := expectedSystemSettingsUpdatedAt(settings)
	if !ok {
		return nil
	}

	current, found, err := getSystemSettingsUpdatedAtTx(ctx, tx)
	if err != nil {
		return err
	}
	if expected.IsZero() {
		if found {
			return db.ErrConflict
		}
		return nil
	}
	if !found || !current.Equal(expected.UTC()) {
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

func getSystemSettingsUpdatedAtTx(ctx context.Context, tx pgx.Tx) (time.Time, bool, error) {
	var updatedAt time.Time
	err := tx.QueryRow(ctx, `SELECT updated_at FROM system_settings WHERE id = 1`).Scan(&updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("postgres: get system settings revision: %w", err)
	}
	return updatedAt, true, nil
}
