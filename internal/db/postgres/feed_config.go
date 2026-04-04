package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) GetFeedConfig(ctx context.Context, feedName string) (*db.FeedConfig, error) {
	const query = `
		SELECT
			feed_name,
			enabled,
			mode,
			EXTRACT(EPOCH FROM sync_interval),
			api_key,
			updated_at
		FROM feed_configs
		WHERE feed_name = $1`

	var (
		item         db.FeedConfig
		intervalSecs *float64
		apiKey       *string
	)

	err := s.pool.QueryRow(ctx, query, feedName).Scan(
		&item.FeedName,
		&item.Enabled,
		&item.Mode,
		&intervalSecs,
		&apiKey,
		&item.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get feed config %s: %w", feedName, err)
	}

	if intervalSecs != nil {
		d := time.Duration(*intervalSecs * float64(time.Second))
		item.SyncInterval = &d
	}
	if apiKey != nil {
		item.APIKey = *apiKey
	}

	return &item, nil
}

func (s *Store) UpsertFeedConfig(ctx context.Context, cfg *db.FeedConfig) error {
	const query = `
		INSERT INTO feed_configs (feed_name, enabled, mode, sync_interval, api_key)
		VALUES ($1, $2, $3, ($4 * interval '1 microsecond'), $5)
		ON CONFLICT (feed_name) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			mode = EXCLUDED.mode,
			sync_interval = EXCLUDED.sync_interval,
			api_key = EXCLUDED.api_key,
			updated_at = NOW()`

	var intervalMicros any
	if cfg.SyncInterval != nil {
		intervalMicros = cfg.SyncInterval.Microseconds()
	}

	_, err := s.pool.Exec(ctx, query,
		cfg.FeedName,
		cfg.Enabled,
		cfg.Mode,
		intervalMicros,
		nullableString(cfg.APIKey),
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert feed config %s: %w", cfg.FeedName, err)
	}
	return nil
}

func (s *Store) DeleteFeedConfig(ctx context.Context, feedName string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM feed_configs WHERE feed_name = $1`, feedName); err != nil {
		return fmt.Errorf("postgres: delete feed config %s: %w", feedName, err)
	}
	return nil
}

func (s *Store) ListFeedConfigs(ctx context.Context) ([]db.FeedConfig, error) {
	const query = `
		SELECT
			feed_name,
			enabled,
			mode,
			EXTRACT(EPOCH FROM sync_interval),
			api_key,
			updated_at
		FROM feed_configs
		ORDER BY feed_name`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("postgres: list feed configs: %w", err)
	}
	defer rows.Close()

	out := make([]db.FeedConfig, 0)
	for rows.Next() {
		var (
			item         db.FeedConfig
			intervalSecs *float64
			apiKey       *string
		)

		if err := rows.Scan(
			&item.FeedName,
			&item.Enabled,
			&item.Mode,
			&intervalSecs,
			&apiKey,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan feed config row: %w", err)
		}

		if intervalSecs != nil {
			d := time.Duration(*intervalSecs * float64(time.Second))
			item.SyncInterval = &d
		}
		if apiKey != nil {
			item.APIKey = *apiKey
		}

		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate feed configs: %w", err)
	}

	return out, nil
}
