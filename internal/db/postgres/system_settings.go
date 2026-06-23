package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetSystemSettings(ctx context.Context) (*db.SystemSettings, error) {
	const query = `
		SELECT block_threshold, rate_limit_per_minute, rate_limit_burst, updated_at
		FROM system_settings
		WHERE id = 1`

	var settings db.SystemSettings
	err := s.pool.QueryRow(ctx, query).Scan(
		&settings.BlockThreshold,
		&settings.RateLimitPerMinute,
		&settings.RateLimitBurst,
		&settings.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get system settings: %w", err)
	}
	return &settings, nil
}

func (s *Store) UpsertSystemSettings(ctx context.Context, settings *db.SystemSettings) error {
	const query = `
		INSERT INTO system_settings (
			id, block_threshold, rate_limit_per_minute, rate_limit_burst
		) VALUES (
			1, $1, $2, $3
		)
		ON CONFLICT (id) DO UPDATE SET
			block_threshold = EXCLUDED.block_threshold,
			rate_limit_per_minute = EXCLUDED.rate_limit_per_minute,
			rate_limit_burst = EXCLUDED.rate_limit_burst,
			updated_at = NOW()`

	_, err := s.pool.Exec(ctx, query,
		settings.BlockThreshold,
		settings.RateLimitPerMinute,
		settings.RateLimitBurst,
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert system settings: %w", err)
	}
	return nil
}
