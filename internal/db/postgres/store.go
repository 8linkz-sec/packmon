package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the PostgreSQL-backed implementation of db.Store used by the
// production Packmon server.
type Store struct {
	pool      *pgxpool.Pool
	encryptor *auth.FieldEncryptor
}

var _ db.Store = (*Store)(nil)

// PoolConfig holds optional connection pool tuning parameters.
// Zero values mean "use pgxpool defaults".
type PoolConfig struct {
	MaxConns int32
	MinConns int32
}

// New opens a PostgreSQL connection pool and verifies connectivity.
// The encryptor parameter encrypts sensitive fields (e.g. feed API keys)
// at rest. Pass nil to disable encryption (plaintext fallback).
// poolCfg may be nil to use pgxpool defaults.
func New(ctx context.Context, dsn string, encryptor *auth.FieldEncryptor, poolCfg *PoolConfig) (*Store, error) {
	pgCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}

	if poolCfg != nil {
		if poolCfg.MaxConns > 0 {
			pgCfg.MaxConns = poolCfg.MaxConns
		}
		if poolCfg.MinConns > 0 {
			pgCfg.MinConns = poolCfg.MinConns
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgCfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	if encryptor == nil {
		// Inactive encryptor: passthrough, no encryption.
		encryptor = &auth.FieldEncryptor{}
	}

	return &Store{pool: pool, encryptor: encryptor}, nil
}

// Ping satisfies health.Pinger.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases the pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// DBPoolStats returns current PostgreSQL connection-pool gauges.
func (s *Store) DBPoolStats() db.DBPoolStats {
	stats := s.pool.Stat()
	return db.DBPoolStats{
		MaxConns:          stats.MaxConns(),
		AcquiredConns:     stats.AcquiredConns(),
		IdleConns:         stats.IdleConns(),
		ConstructingConns: stats.ConstructingConns(),
	}
}

func withTx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func normalizeJSON(raw json.RawMessage, fallback []byte) any {
	if len(raw) == 0 {
		if fallback == nil {
			return nil
		}
		return fallback
	}
	return []byte(raw)
}

func nullableString(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func normalizeSeverity(severity string) string {
	normalized := strings.ToUpper(strings.TrimSpace(severity))
	if normalized == "" {
		return "UNKNOWN"
	}
	return normalized
}

func clampLimit(limit, fallback, max int) int {
	if limit <= 0 {
		limit = fallback
	}
	if limit > max {
		return max
	}
	return limit
}

func sortStrings(values []string) {
	slices.Sort(values)
}

func mergeCSV(current, incoming string) string {
	set := make(map[string]struct{})
	for _, part := range strings.Split(current, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			set[part] = struct{}{}
		}
	}
	for _, part := range strings.Split(incoming, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			set[part] = struct{}{}
		}
	}

	parts := make([]string, 0, len(set))
	for part := range set {
		parts = append(parts, part)
	}
	sortStrings(parts)
	return strings.Join(parts, ", ")
}

func joinSortedCSV(current string) string {
	if current == "" {
		return ""
	}
	parts := make([]string, 0)
	seen := make(map[string]struct{})
	for _, part := range strings.Split(current, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		parts = append(parts, part)
	}
	sortStrings(parts)
	return strings.Join(parts, ", ")
}

func sortSearchResults(results []db.PackageSearchResult) {
	slices.SortFunc(results, func(a, b db.PackageSearchResult) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.Ecosystem, b.Ecosystem)
	})
}

func scanAPIKey(row pgx.Row) (*db.APIKey, error) {
	var (
		item       db.APIKey
		revokedAt  *time.Time
		lastUsedAt *time.Time
	)

	if err := row.Scan(
		&item.ID,
		&item.Name,
		&item.KeyHash,
		&item.CreatedAt,
		&revokedAt,
		&lastUsedAt,
	); err != nil {
		return nil, err
	}

	item.RevokedAt = revokedAt
	item.LastUsedAt = lastUsedAt
	return &item, nil
}
