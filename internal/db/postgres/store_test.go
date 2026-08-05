package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
)

type capturingExecer struct {
	sql  string
	args []any
}

func (e *capturingExecer) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	e.sql = sql
	e.args = append([]any(nil), args...)
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func TestNewPgxPoolConfigAppliesPoolConfigWithoutDatabase(t *testing.T) {
	t.Parallel()

	pgCfg, err := newPgxPoolConfig("postgres://packmon:packmon@localhost:5432/packmon?sslmode=disable", &PoolConfig{
		MaxConns:       7,
		MinConns:       2,
		ConnectTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("newPgxPoolConfig() error = %v", err)
	}
	if pgCfg.MaxConns != 7 {
		t.Fatalf("MaxConns = %d, want 7", pgCfg.MaxConns)
	}
	if pgCfg.MinConns != 2 {
		t.Fatalf("MinConns = %d, want 2", pgCfg.MinConns)
	}
	if pgCfg.ConnConfig.ConnectTimeout != 3*time.Second {
		t.Fatalf("ConnConfig.ConnectTimeout = %s, want 3s", pgCfg.ConnConfig.ConnectTimeout)
	}
}

func TestNewPgxPoolConfigKeepsDSNConnectTimeoutWhenPoolConfigZero(t *testing.T) {
	t.Parallel()

	pgCfg, err := newPgxPoolConfig("postgres://packmon:packmon@localhost:5432/packmon?sslmode=disable&connect_timeout=4", &PoolConfig{})
	if err != nil {
		t.Fatalf("newPgxPoolConfig() error = %v", err)
	}
	if pgCfg.ConnConfig.ConnectTimeout != 4*time.Second {
		t.Fatalf("ConnConfig.ConnectTimeout = %s, want DSN timeout 4s", pgCfg.ConnConfig.ConnectTimeout)
	}
}

func TestDeleteAPIKeyTxPermanentlyRemovesRevokedKeyRow(t *testing.T) {
	t.Parallel()

	execer := &capturingExecer{}
	if err := deleteAPIKeyTx(context.Background(), execer, 42); err != nil {
		t.Fatalf("deleteAPIKeyTx() error = %v", err)
	}

	normalizedSQL := strings.Join(strings.Fields(execer.sql), " ")
	for _, want := range []string{
		"DELETE FROM api_keys",
		"WHERE id = $1",
		"revoked_at IS NOT NULL",
	} {
		if !strings.Contains(normalizedSQL, want) {
			t.Fatalf("deleteAPIKeyTx SQL = %q, want %q", normalizedSQL, want)
		}
	}
	if strings.Contains(normalizedSQL, "UPDATE") || strings.Contains(normalizedSQL, "deleted_at") {
		t.Fatalf("deleteAPIKeyTx SQL = %q, want a permanent delete without soft-delete tombstones", normalizedSQL)
	}
	if len(execer.args) != 1 || execer.args[0] != 42 {
		t.Fatalf("deleteAPIKeyTx args = %#v, want key id only", execer.args)
	}
}

func TestListAPIKeysPageUsesBoundedQuery(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("api_keys.go")
	if err != nil {
		t.Fatalf("read api_keys.go: %v", err)
	}
	source := string(data)
	start := strings.Index(source, "func (s *Store) ListAPIKeysPage")
	if start < 0 {
		t.Fatal("ListAPIKeysPage is missing")
	}
	body := source[start:]
	for _, want := range []string{
		"LIMIT $1 OFFSET $2",
		"ORDER BY created_at DESC, id DESC",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("ListAPIKeysPage missing %q\n%s", want, body)
		}
	}
}

func TestNormalizeSeverityUsesLowForUnresolvedVulnerabilitySeverity(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", " ", "UNKNOWN", "unknown"} {
		got, err := normalizeVulnerabilitySeverity(raw)
		if err != nil {
			t.Fatalf("normalizeVulnerabilitySeverity(%q) error = %v", raw, err)
		}
		if got != "LOW" {
			t.Fatalf("normalizeVulnerabilitySeverity(%q) = %q, want LOW", raw, got)
		}
	}
}

func TestNormalizeSeverityRejectsUnsupportedStoreValues(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"INFO", "NONE", "advisory"} {
		if _, err := normalizeVulnerabilitySeverity(raw); err == nil {
			t.Fatalf("normalizeVulnerabilitySeverity(%q) error = nil, want rejection", raw)
		}
		if _, err := normalizeMaliciousSeverity(raw); err == nil {
			t.Fatalf("normalizeMaliciousSeverity(%q) error = nil, want rejection", raw)
		}
		if _, err := normalizeStoredReputationSeverity(raw); err == nil {
			t.Fatalf("normalizeStoredReputationSeverity(%q) error = nil, want rejection", raw)
		}
	}
}

func TestNormalizeStoredReputationSeverityMapsUnknownToCritical(t *testing.T) {
	t.Parallel()

	got, err := normalizeStoredReputationSeverity("unknown")
	if err != nil {
		t.Fatalf("normalizeStoredReputationSeverity() error = %v", err)
	}
	if got != "CRITICAL" {
		t.Fatalf("normalizeStoredReputationSeverity() = %q, want CRITICAL", got)
	}
}

func TestNormalizeMaliciousSeverityAllowsUnknown(t *testing.T) {
	t.Parallel()

	got, err := normalizeMaliciousSeverity("unknown")
	if err != nil {
		t.Fatalf("normalizeMaliciousSeverity() error = %v", err)
	}
	if got != "UNKNOWN" {
		t.Fatalf("normalizeMaliciousSeverity() = %q, want UNKNOWN", got)
	}
}

func TestNormalizeStoredEcosystemRejectsNoncanonicalValues(t *testing.T) {
	t.Parallel()

	got, err := normalizeStoredEcosystem(" NPM ")
	if err != nil {
		t.Fatalf("normalizeStoredEcosystem(valid) error = %v", err)
	}
	if got != "npm" {
		t.Fatalf("normalizeStoredEcosystem(valid) = %q, want npm", got)
	}

	for _, raw := range []string{"", "npmm", "javascript"} {
		if _, err := normalizeStoredEcosystem(raw); err == nil {
			t.Fatalf("normalizeStoredEcosystem(%q) error = nil, want rejection", raw)
		}
	}
}

func TestNormalizeMaliciousRiskTypeRejectsUnsupportedValues(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		raw  string
		want string
	}{
		{raw: "", want: "malware"},
		{raw: " Malware ", want: "malware"},
		{raw: "supply-chain", want: "supply_chain"},
		{raw: "typo-squatting", want: "typosquatting"},
	} {
		got, err := normalizeMaliciousRiskType(tc.raw)
		if err != nil {
			t.Fatalf("normalizeMaliciousRiskType(%q) error = %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeMaliciousRiskType(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	for _, raw := range []string{"other", "unknown", "removed_package"} {
		if _, err := normalizeMaliciousRiskType(raw); err == nil {
			t.Fatalf("normalizeMaliciousRiskType(%q) error = nil, want rejection", raw)
		}
	}
}

func TestNormalizeManualAdvisoryIDRequiresManualNamespace(t *testing.T) {
	t.Parallel()

	got, err := normalizeManualAdvisoryID(" " + domain.ManualAdvisoryIDPrefix + "operator-1 ")
	if err != nil {
		t.Fatalf("normalizeManualAdvisoryID(valid) error = %v", err)
	}
	if got != domain.ManualAdvisoryIDPrefix+"operator-1" {
		t.Fatalf("normalizeManualAdvisoryID(valid) = %q", got)
	}

	for _, raw := range []string{"", "CVE-2026-0001", "GHSA-xxxx-yyyy-zzzz", "osv:1234"} {
		if _, err := normalizeManualAdvisoryID(raw); err == nil {
			t.Fatalf("normalizeManualAdvisoryID(%q) error = nil, want rejection", raw)
		}
	}
}

func TestNormalizeRefreshQueuePriorityRejectsOutOfRangeValues(t *testing.T) {
	t.Parallel()

	for _, priority := range []int{0, 1, 2, 3} {
		if got, err := normalizeRefreshQueuePriority(priority); err != nil || got != priority {
			t.Fatalf("normalizeRefreshQueuePriority(%d) = %d, %v; want same priority", priority, got, err)
		}
	}
	for _, priority := range []int{-1, 4, 99} {
		if _, err := normalizeRefreshQueuePriority(priority); err == nil {
			t.Fatalf("normalizeRefreshQueuePriority(%d) error = nil, want rejection", priority)
		}
	}
}
