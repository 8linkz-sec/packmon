package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/secret"
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
		item.APIKeyEncrypted = isEncryptedFeedAPIKeyValue(*apiKey)
		decrypted, err := s.encryptor.Decrypt(*apiKey)
		if err != nil {
			return nil, fmt.Errorf("postgres: decrypt feed api key %s: %w", feedName, err)
		}
		item.APIKey = decrypted
	}

	return &item, nil
}

func (s *Store) UpsertFeedConfig(ctx context.Context, cfg *db.FeedConfig) error {
	if err := validateFeedConfigSyncInterval(cfg); err != nil {
		return err
	}
	return s.upsertFeedConfigTx(ctx, s.pool, cfg)
}

func (s *Store) UpsertFeedConfigWithAudit(ctx context.Context, cfg *db.FeedConfig, audit *db.AdminAuditEntry) error {
	if err := validateFeedConfigSyncInterval(cfg); err != nil {
		return err
	}
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkFeedConfigRevisionTx(ctx, tx, cfg); err != nil {
			return err
		}
		if err := s.upsertFeedConfigTx(ctx, tx, cfg); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func checkFeedConfigRevisionTx(ctx context.Context, tx pgx.Tx, cfg *db.FeedConfig) error {
	expected, ok := expectedFeedConfigUpdatedAt(cfg)
	if !ok {
		return nil
	}

	current, found, err := getFeedConfigUpdatedAtTx(ctx, tx, cfg.FeedName)
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

func expectedFeedConfigUpdatedAt(cfg *db.FeedConfig) (time.Time, bool) {
	if cfg == nil {
		return time.Time{}, false
	}
	if cfg.ExpectedUpdatedAt != nil {
		return *cfg.ExpectedUpdatedAt, true
	}
	if !cfg.UpdatedAt.IsZero() {
		return cfg.UpdatedAt, true
	}
	return time.Time{}, false
}

func getFeedConfigUpdatedAtTx(ctx context.Context, tx pgx.Tx, feedName string) (time.Time, bool, error) {
	var updatedAt time.Time
	err := tx.QueryRow(ctx, `SELECT updated_at FROM feed_configs WHERE feed_name = $1`, feedName).Scan(&updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("postgres: get feed config revision %s: %w", feedName, err)
	}
	return updatedAt, true, nil
}

func (s *Store) upsertFeedConfigTx(ctx context.Context, execer postgresExecer, cfg *db.FeedConfig) error {
	if err := validateFeedConfigSyncInterval(cfg); err != nil {
		return err
	}

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

	// Encrypt the API key before storing (SEC-C2).
	apiKeyVal := cfg.APIKey
	if apiKeyVal != "" {
		encrypted, encErr := s.encryptor.Encrypt(apiKeyVal)
		if encErr != nil {
			return fmt.Errorf("postgres: encrypt feed api key %s: %w", cfg.FeedName, encErr)
		}
		apiKeyVal = encrypted
	}

	_, err := execer.Exec(ctx, query,
		cfg.FeedName,
		cfg.Enabled,
		cfg.Mode,
		intervalMicros,
		nullableString(apiKeyVal),
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert feed config %s: %w", cfg.FeedName, err)
	}
	return nil
}

func validateFeedConfigSyncInterval(cfg *db.FeedConfig) error {
	if cfg == nil || cfg.SyncInterval == nil {
		return nil
	}
	if *cfg.SyncInterval < config.FeedSyncMinInterval {
		return fmt.Errorf("postgres: feed config %s sync interval must be at least %s", cfg.FeedName, config.FeedSyncMinInterval)
	}
	return nil
}

func (s *Store) DeleteFeedConfig(ctx context.Context, feedName string) error {
	return deleteFeedConfigTx(ctx, s.pool, feedName)
}

func (s *Store) DeleteFeedConfigWithAudit(ctx context.Context, feedName string, expectedUpdatedAt *time.Time, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := checkFeedConfigDeleteRevisionTx(ctx, tx, feedName, expectedUpdatedAt); err != nil {
			return err
		}
		if err := deleteFeedConfigTx(ctx, tx, feedName); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func checkFeedConfigDeleteRevisionTx(ctx context.Context, tx pgx.Tx, feedName string, expectedUpdatedAt *time.Time) error {
	if expectedUpdatedAt == nil {
		return nil
	}
	current, found, err := getFeedConfigUpdatedAtTx(ctx, tx, feedName)
	if err != nil {
		return err
	}
	expected := expectedUpdatedAt.UTC()
	if expected.IsZero() {
		if found {
			return db.ErrConflict
		}
		return nil
	}
	if !found || !current.Equal(expected) {
		return db.ErrConflict
	}
	return nil
}

func deleteFeedConfigTx(ctx context.Context, execer postgresExecer, feedName string) error {
	if _, err := execer.Exec(ctx, `DELETE FROM feed_configs WHERE feed_name = $1`, feedName); err != nil {
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
	defer ioutils.CloseSilently(rows)

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
			item.APIKeyEncrypted = isEncryptedFeedAPIKeyValue(*apiKey)
			decrypted, decErr := s.encryptor.Decrypt(*apiKey)
			if decErr != nil {
				return nil, fmt.Errorf("postgres: decrypt feed api key %s: %w", item.FeedName, decErr)
			}
			item.APIKey = decrypted
		}

		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate feed configs: %w", err)
	}

	return out, nil
}

func isEncryptedFeedAPIKeyValue(value string) bool {
	return strings.HasPrefix(value, secret.EncryptedPrefix)
}
