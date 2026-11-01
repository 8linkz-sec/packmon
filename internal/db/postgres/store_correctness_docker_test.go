//go:build integration

package postgres

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestPostgresStoreCorrectnessAgainstDocker groups store-correctness
// regressions behind one PostgreSQL container. The subtests run sequentially
// and use disjoint fixtures; dashboard assertions compare deltas.
func TestPostgresStoreCorrectnessAgainstDocker(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	t.Run("dashboard buckets historical reputation risk as LOW", func(t *testing.T) {
		testDashboardBucketsHistoricalReputationRiskAsLow(ctx, t, store)
	})
	t.Run("scan totals above int32 are not narrowed", func(t *testing.T) {
		testScanTotalsAboveInt32AreNotNarrowed(ctx, t, store)
	})
}

func testScanTotalsAboveInt32AreNotNarrowed(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	now := time.Now().UTC()
	for i, scanID := range []string{"scan-bigint-1", "scan-bigint-2"} {
		if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
			ScanID:         scanID,
			ScannedAt:      now.Add(time.Duration(i) * time.Millisecond),
			BlockThreshold: "CRITICAL",
			FeedStatus:     "healthy",
			PackagesCount:  math.MaxInt32,
			FindingsCount:  math.MaxInt32,
		}); err != nil {
			t.Fatalf("InsertScanLog(%s) error = %v", scanID, err)
		}
	}
	const want = int64(2 * math.MaxInt32)

	totals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals() error = %v, want BIGINT totals above int32", err)
	}
	if totals.PackagesScanned < want || totals.Findings < want {
		t.Fatalf("ScanTotals() = %+v, want both totals >= %d", totals, want)
	}

	daily, err := store.CountScansByDay(ctx, 1)
	if err != nil {
		t.Fatalf("CountScansByDay(1) error = %v, want BIGINT daily findings sum", err)
	}
	if len(daily) != 1 || int64(daily[0].FindingsCount) < want || daily[0].ScanCount < 2 {
		t.Fatalf("CountScansByDay(1) = %+v, want today's findings sum >= %d over >= 2 scans", daily, want)
	}
}

func testDashboardBucketsHistoricalReputationRiskAsLow(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	before, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats(before) error = %v", err)
	}

	now := time.Now().UTC()
	rep := db.PackageReputation{
		Ecosystem:     "pypi",
		Name:          "polars-runtime-32",
		Version:       "1.40.1",
		Source:        db.ReputationSourceReversingLabs,
		Status:        "risk",
		Severity:      "HIGH",
		Summary:       "ReversingLabs: malware incident history",
		LastCheckedAt: &now,
	}
	if err := store.UpsertPackageReputation(ctx, &rep); err != nil {
		t.Fatalf("UpsertPackageReputation(risk/HIGH) error = %v", err)
	}

	// The stored provider severity stays HIGH; only the finding (and so the
	// dashboard bucket) is informational LOW.
	var storedSeverity string
	if err := store.pool.QueryRow(ctx, `
		SELECT severity FROM package_reputation_cache
		WHERE ecosystem = 'pypi' AND name = 'polars-runtime-32' AND version = '1.40.1'`).Scan(&storedSeverity); err != nil {
		t.Fatalf("read stored reputation severity: %v", err)
	}
	if storedSeverity != "HIGH" {
		t.Fatalf("stored reputation severity = %q, want HIGH preserved", storedSeverity)
	}

	findings, err := store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{
		Ecosystem: "pypi", Name: "polars-runtime-32", Version: "1.40.1",
	}}, db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindingsBatch() error = %v", err)
	}
	if len(findings) != 1 || findings[0].RiskType != domain.RiskTypeMalwareHistory || findings[0].Severity != domain.SeverityLow {
		t.Fatalf("FindReputationFindingsBatch() = %+v, want one LOW malware_history finding", findings)
	}

	after, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats(after) error = %v", err)
	}
	if delta := after.BySeverity["HIGH"] - before.BySeverity["HIGH"]; delta != 0 {
		t.Fatalf("dashboard HIGH bucket delta = %d, want 0 for informational malware_history", delta)
	}
	if delta := after.BySeverity[string(findings[0].Severity)] - before.BySeverity[string(findings[0].Severity)]; delta != 1 {
		t.Fatalf("dashboard %s bucket delta = %d, want 1 matching the emitted finding severity", findings[0].Severity, delta)
	}
	if delta := after.TotalSupplyChainRisk - before.TotalSupplyChainRisk; delta != 1 {
		t.Fatalf("dashboard supply-chain total delta = %d, want 1", delta)
	}
}
