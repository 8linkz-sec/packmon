//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

const maliciousSearchScaleRows = 250_000

type explainPlanEnvelope struct {
	Plan explainPlanNode `json:"Plan"`
}

type explainPlanNode struct {
	NodeType          string            `json:"Node Type"`
	RelationName      string            `json:"Relation Name"`
	IndexName         string            `json:"Index Name"`
	HeapFetches       int64             `json:"Heap Fetches"`
	TempReadBlocks    int64             `json:"Temp Read Blocks"`
	TempWrittenBlocks int64             `json:"Temp Written Blocks"`
	Plans             []explainPlanNode `json:"Plans"`
}

func TestDBPERF001MaliciousSearchScaleContract(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, err := store.pool.Exec(ctx, `
		INSERT INTO malicious_findings (
			id, ecosystem, name, source, risk_type, severity, summary, description, removed_at
		)
		SELECT
			'dbperf-scale-' || item::text,
			'npm',
			'pkg-' || lpad(item::text, 7, '0'),
			CASE item % 2 WHEN 0 THEN 'openssf' ELSE 'socket' END,
			'malware',
			CASE item % 4 WHEN 0 THEN 'CRITICAL' WHEN 1 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' ELSE 'LOW' END,
			'scale finding',
			repeat('x', 1024),
			NULL
		FROM generate_series(1, $1) AS item`, maliciousSearchScaleRows); err != nil {
		t.Fatalf("insert malicious scale fixture: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO malicious_findings (
			id, ecosystem, name, source, risk_type, severity, summary, removed_at
		) VALUES
			('dbperf-exact-1', 'npm', 'aaa-overlap', 'openssf', 'malware', 'CRITICAL', 'one', NULL),
			('dbperf-exact-2', 'npm', 'aaa-overlap', 'socket', 'malware', 'CRITICAL', 'two', NULL),
			('manual:dbperf-exact-removed', 'npm', 'aaa-overlap', 'manual', 'malware', 'CRITICAL', 'removed', NOW()),
			('dbperf-exact-3', 'npm', 'aab-next', 'openssf', 'malware', 'HIGH', 'three', NULL)`); err != nil {
		t.Fatalf("insert exact-result fixture: %v", err)
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem: "npm",
		Name:      "aaa-overlap",
		Version:   "1.0.0",
		Source:    db.ReputationSourceReversingLabs,
		Status:    "malicious",
		Severity:  "CRITICAL",
		Summary:   "reputation overlap",
	}); err != nil {
		t.Fatalf("insert reputation overlap: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `VACUUM (ANALYZE) malicious_findings`); err != nil {
		t.Fatalf("vacuum malicious scale fixture: %v", err)
	}

	assertMaliciousSearchExactResults(t, store, ctx)
	assertMaliciousSearchPlan(t, store, ctx, "unfiltered", maliciousPackageSearchUnfilteredSQL,
		[]any{201}, "idx_malicious_active_search_order", true)
	assertMaliciousSearchPlan(t, store, ctx, "name", maliciousPackageSearchNameSQL,
		[]any{"%aaa-overlap%", 201}, "idx_malicious_findings_name_trgm", false)
	assertMaliciousSearchPlan(t, store, ctx, "severity", maliciousPackageSearchSeveritySQL,
		[]any{"CRITICAL", 201}, "idx_malicious_active_severity_search", true)
	assertMaliciousSearchPlan(t, store, ctx, "name and severity", maliciousPackageSearchNameSeveritySQL,
		[]any{"%aaa-overlap%", "CRITICAL", 201}, "idx_malicious_findings_name_trgm", false)

	for _, index := range []string{"idx_malicious_active_search_order", "idx_malicious_active_severity_search"} {
		var size int64
		if err := store.pool.QueryRow(ctx, `SELECT pg_relation_size($1::regclass)`, index).Scan(&size); err != nil {
			t.Fatalf("read %s size: %v", index, err)
		}
		t.Logf("%s size at %d active rows: %d bytes", index, maliciousSearchScaleRows+3, size)
	}
}

func assertMaliciousSearchExactResults(t *testing.T, store *Store, ctx context.Context) {
	t.Helper()

	firstPage, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "malicious", Limit: 2})
	if err != nil {
		t.Fatalf("SearchPackages first page: %v", err)
	}
	if len(firstPage) != 2 {
		t.Fatalf("first page length = %d, want 2: %+v", len(firstPage), firstPage)
	}
	if got := firstPage[0]; got.Name != "aaa-overlap" || got.Version != "" || got.FindingsCount != 2 || got.Sources != "openssf, socket" || got.FindingTypes != "malicious" {
		t.Fatalf("first aggregate row = %+v, want exact active malicious aggregate", got)
	}
	if got := firstPage[1]; got.Name != "aaa-overlap" || got.Version != "1.0.0" || got.FindingsCount != 1 || got.Sources != db.ReputationSourceReversingLabs || got.FindingTypes != "malicious" {
		t.Fatalf("second aggregate row = %+v, want versioned reputation overlap", got)
	}

	secondPage, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "malicious", Limit: 2, Offset: 1})
	if err != nil {
		t.Fatalf("SearchPackages second page: %v", err)
	}
	if len(secondPage) != 2 || secondPage[0].Version != "1.0.0" || secondPage[1].Name != "aab-next" {
		t.Fatalf("offset page = %+v, want reputation overlap then aab-next", secondPage)
	}

	critical, err := store.SearchPackages(ctx, db.PackageSearchParams{Severity: "CRITICAL", FindingType: "malicious", Limit: 2})
	if err != nil {
		t.Fatalf("SearchPackages critical: %v", err)
	}
	if len(critical) != 2 || critical[0].Name != "aaa-overlap" || critical[0].FindingsCount != 2 || critical[1].Version != "1.0.0" {
		t.Fatalf("critical results = %+v, want exact severity-filtered overlap rows", critical)
	}
}

func assertMaliciousSearchPlan(t *testing.T, store *Store, ctx context.Context, name, query string, args []any, wantIndex string, wantIndexOnly bool) {
	t.Helper()

	var raw []byte
	if err := store.pool.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&raw); err != nil {
		t.Fatalf("explain %s malicious search: %v", name, err)
	}
	var envelopes []explainPlanEnvelope
	if err := json.Unmarshal(raw, &envelopes); err != nil || len(envelopes) != 1 {
		t.Fatalf("decode %s explain JSON: %v raw=%s", name, err, raw)
	}

	var (
		usedWantedIndex bool
		violations      []string
	)
	walkExplainPlan(envelopes[0].Plan, func(node explainPlanNode) {
		if node.RelationName == "malicious_findings" && node.NodeType == "Seq Scan" {
			violations = append(violations, "sequential scan on malicious_findings")
		}
		if node.IndexName == wantIndex {
			usedWantedIndex = true
			if wantIndexOnly && node.NodeType != "Index Only Scan" {
				violations = append(violations, fmt.Sprintf("%s used as %s instead of Index Only Scan", wantIndex, node.NodeType))
			}
			if wantIndexOnly && node.HeapFetches != 0 {
				violations = append(violations, fmt.Sprintf("%s heap fetches = %d, want 0 after VACUUM", wantIndex, node.HeapFetches))
			}
		}
		if node.TempReadBlocks != 0 || node.TempWrittenBlocks != 0 {
			violations = append(violations, fmt.Sprintf("%s temp blocks read=%d written=%d", node.NodeType, node.TempReadBlocks, node.TempWrittenBlocks))
		}
	})
	if !usedWantedIndex {
		violations = append(violations, "expected index not used: "+wantIndex)
	}
	if len(violations) != 0 {
		t.Fatalf("%s malicious search plan contract failed: %s\nplan=%s", name, strings.Join(violations, "; "), raw)
	}
}

func walkExplainPlan(node explainPlanNode, visit func(explainPlanNode)) {
	visit(node)
	for _, child := range node.Plans {
		walkExplainPlan(child, visit)
	}
}
