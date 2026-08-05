package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/secret"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the PostgreSQL-backed implementation of db.Store used by the
// production Packmon server.
type Store struct {
	pool      *pgxpool.Pool
	encryptor *secret.FieldEncryptor
}

var _ db.Store = (*Store)(nil)

// PoolConfig holds optional connection pool tuning parameters.
// Zero values mean "use pgxpool defaults".
type PoolConfig struct {
	MaxConns       int32
	MinConns       int32
	ConnectTimeout time.Duration
}

// New opens a PostgreSQL connection pool and verifies connectivity.
// The encryptor parameter encrypts sensitive fields (e.g. feed API keys)
// at rest. Pass nil to disable encryption (plaintext fallback).
// poolCfg may be nil to use pgxpool defaults.
func New(ctx context.Context, dsn string, encryptor *secret.FieldEncryptor, poolCfg *PoolConfig) (*Store, error) {
	pgCfg, err := newPgxPoolConfig(dsn, poolCfg)
	if err != nil {
		return nil, err
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
		encryptor = &secret.FieldEncryptor{}
	}

	return &Store{pool: pool, encryptor: encryptor}, nil
}

func newPgxPoolConfig(dsn string, poolCfg *PoolConfig) (*pgxpool.Config, error) {
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
		if poolCfg.ConnectTimeout > 0 {
			pgCfg.ConnConfig.ConnectTimeout = poolCfg.ConnectTimeout
		}
	}
	return pgCfg, nil
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
		AcquireCount:      stats.AcquireCount(),
		AcquireDuration:   stats.AcquireDuration(),
		CanceledAcquires:  stats.CanceledAcquireCount(),
		EmptyAcquires:     stats.EmptyAcquireCount(),
		EmptyAcquireWait:  stats.EmptyAcquireWaitTime(),
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

func normalizeVulnerabilitySeverity(severity string) (string, error) {
	normalized := normalizeSeverity(severity)
	if normalized == "UNKNOWN" {
		return "LOW", nil
	}
	if !storedSeverityValid(normalized, false) {
		return "", fmt.Errorf("unsupported vulnerability severity %q", severity)
	}
	return normalized, nil
}

func normalizeMaliciousSeverity(severity string) (string, error) {
	normalized := normalizeSeverity(severity)
	if !storedSeverityValid(normalized, true) {
		return "", fmt.Errorf("unsupported malicious severity %q", severity)
	}
	return normalized, nil
}

func storedSeverityValid(severity string, allowUnknown bool) bool {
	switch severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return true
	case "UNKNOWN":
		return allowUnknown
	default:
		return false
	}
}

func normalizeStoredEcosystem(ecosystem string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(ecosystem))
	if !domain.Ecosystem(normalized).Valid() {
		return "", fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
	return normalized, nil
}

func normalizeMaliciousRiskType(riskType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(riskType)) {
	case "":
		return "malware", nil
	case "malware":
		return "malware", nil
	case "supply_chain", "supply-chain", "supply chain":
		return "supply_chain", nil
	case "typosquatting", "typosquat", "typo-squatting":
		return "typosquatting", nil
	default:
		return "", fmt.Errorf("unsupported malicious risk type %q", riskType)
	}
}

func normalizeManualAdvisoryID(id string) (string, error) {
	normalized, ok := domain.NormalizeManualAdvisoryID(id)
	if !ok {
		return "", fmt.Errorf("manual advisory id must use %s namespace", domain.ManualAdvisoryIDPrefix)
	}
	return normalized, nil
}

func normalizeRefreshQueuePriority(priority int) (int, error) {
	if !db.ValidRefreshPriority(priority) {
		return 0, fmt.Errorf("unsupported refresh queue priority %d", priority)
	}
	return priority, nil
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
		if a.Ecosystem != b.Ecosystem {
			return strings.Compare(a.Ecosystem, b.Ecosystem)
		}
		return strings.Compare(a.Version, b.Version)
	})
}

func scanAPIKey(row pgx.Row) (*db.APIKey, error) {
	var (
		item       db.APIKey
		revokedAt  *time.Time
		lastUsedAt *time.Time
		expiresAt  *time.Time
		deletedAt  *time.Time
	)

	if err := row.Scan(
		&item.ID,
		&item.Name,
		&item.KeyHash,
		&item.CreatedAt,
		&revokedAt,
		&lastUsedAt,
		&expiresAt,
		&deletedAt,
	); err != nil {
		return nil, err
	}

	item.RevokedAt = revokedAt
	item.LastUsedAt = lastUsedAt
	item.ExpiresAt = expiresAt
	item.DeletedAt = deletedAt
	return &item, nil
}
