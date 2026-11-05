package postgres

import (
	"math"
	"regexp"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestDashboardReputationSeverityMatchesFindingContract pins the dashboard
// severity bucket of a cached reputation row to the severity of the finding
// reputationToFinding emits for it, so a historical malware_history row stored
// as HIGH is counted as LOW, exactly as TestReputationToFindingMapsHistoricalRisk
// requires for the finding itself.
func TestDashboardReputationSeverityMatchesFindingContract(t *testing.T) {
	t.Parallel()

	statuses := []string{reputationStatusMalicious, reputationStatusRemoved, reputationStatusRisk}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "", "unknown", " high "}
	for _, status := range statuses {
		for _, severity := range severities {
			finding, ok := reputationToFinding(db.PackageReputation{
				Ecosystem: "pypi",
				Name:      "polars-runtime-32",
				Version:   "1.40.1",
				Source:    db.ReputationSourceReversingLabs,
				Status:    status,
				Severity:  severity,
			})
			if !ok {
				t.Fatalf("reputationToFinding(status=%q) returned !ok", status)
			}
			if got := dashboardReputationSeverity(status, severity); got != string(finding.Severity) {
				t.Fatalf("dashboardReputationSeverity(%q, %q) = %q, want finding severity %q", status, severity, got, finding.Severity)
			}
		}
	}

	if got := dashboardReputationSeverity(reputationStatusRisk, "HIGH"); got != string(domain.SeverityLow) {
		t.Fatalf("dashboardReputationSeverity(risk, HIGH) = %q, want LOW for informational malware_history", got)
	}
}

// TestScanTotalQueriesKeepBigintTotals guards the cumulative and daily scan
// totals against narrowing to PostgreSQL int: scan_log_totals exposes BIGINT
// sums (migration 043), and a ::int cast fails once a retained sum exceeds
// 2147483647.
func TestScanTotalQueriesKeepBigintTotals(t *testing.T) {
	t.Parallel()

	narrowingCast := regexp.MustCompile(`(?i)::\s*(?:int|int4|integer)\b`)
	for _, cast := range []string{"::int", "::int4", "::integer", ":: INTEGER"} {
		if !narrowingCast.MatchString(cast) {
			t.Fatalf("narrowing-cast guard does not recognize %q", cast)
		}
	}
	if narrowingCast.MatchString(scanTotalsSQL) {
		t.Fatalf("scanTotalsSQL narrows BIGINT totals to a 32-bit integer:\n%s", scanTotalsSQL)
	}
	if !strings.Contains(countScansByDaySQL, "COALESCE(SUM(scan_log.findings_count), 0)::bigint") {
		t.Fatalf("countScansByDaySQL must keep the daily findings sum as bigint:\n%s", countScansByDaySQL)
	}

	// Compile-time contract: the Go side of the cumulative totals is int64.
	asInt64 := func(value int64) int64 { return value }
	totals := db.ScanTotals{PackagesScanned: math.MaxInt32 + 1, Findings: math.MaxInt32 + 1}
	if asInt64(totals.PackagesScanned) != math.MaxInt32+1 || asInt64(totals.Findings) != math.MaxInt32+1 {
		t.Fatalf("ScanTotals = %+v, want values above int32 preserved", totals)
	}
}

func TestDashboardReputationSeverityKeepsUnmappedStatusRaw(t *testing.T) {
	t.Parallel()

	if got := dashboardReputationSeverity("clean", "high"); got != "HIGH" {
		t.Fatalf("dashboardReputationSeverity(clean, high) = %q, want normalized raw severity HIGH", got)
	}
}
