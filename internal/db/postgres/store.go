package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the PostgreSQL-backed implementation of db.Store used by the
// production Packmon server.
type Store struct {
	pool *pgxpool.Pool
}

var _ db.Store = (*Store)(nil)

// New opens a PostgreSQL connection pool and verifies connectivity.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	return &Store{pool: pool}, nil
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
	for i := 1; i < len(values); i++ {
		current := values[i]
		j := i - 1
		for j >= 0 && values[j] > current {
			values[j+1] = values[j]
			j--
		}
		values[j+1] = current
	}
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
	for i := 1; i < len(results); i++ {
		current := results[i]
		j := i - 1
		for j >= 0 && (results[j].Name > current.Name || (results[j].Name == current.Name && results[j].Ecosystem > current.Ecosystem)) {
			results[j+1] = results[j]
			j--
		}
		results[j+1] = current
	}
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
