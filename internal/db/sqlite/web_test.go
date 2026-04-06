package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

func TestHistoryQueriesAndClear(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeSilently(store)

	ctx := context.Background()
	baseDay := time.Now().UTC().Truncate(24 * time.Hour)

	entries := []ScanEntry{
		{
			RepoName:          "repo-a",
			Branch:            "main",
			ScannedAt:         baseDay.Add(-48 * time.Hour),
			PackagesCount:     10,
			FindingsCount:     3,
			FindingIDs:        []string{"A-1"},
			FindingSeverities: []string{"HIGH"},
		},
		{
			RepoName:          "repo-a",
			Branch:            "main",
			ScannedAt:         baseDay.Add(-24 * time.Hour),
			PackagesCount:     8,
			FindingsCount:     1,
			FindingIDs:        []string{"A-2"},
			FindingSeverities: []string{"LOW"},
		},
		{
			RepoName:          "repo-b",
			Branch:            "release",
			ScannedAt:         baseDay,
			PackagesCount:     12,
			FindingsCount:     0,
			FindingIDs:        []string{},
			FindingSeverities: []string{},
		},
	}

	for _, entry := range entries {
		if err := store.InsertScan(ctx, entry); err != nil {
			t.Fatalf("InsertScan() error = %v", err)
		}
	}

	recent, err := store.ListRecentScans(ctx, 2)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("ListRecentScans() len = %d, want 2", len(recent))
	}
	if recent[0].RepoName != "repo-b" || recent[1].RepoName != "repo-a" {
		t.Fatalf("ListRecentScans() order = [%s, %s], want [repo-b, repo-a]", recent[0].RepoName, recent[1].RepoName)
	}

	daily, err := store.CountScansByDay(ctx, 3)
	if err != nil {
		t.Fatalf("CountScansByDay() error = %v", err)
	}
	if len(daily) != 3 {
		t.Fatalf("CountScansByDay() len = %d, want 3", len(daily))
	}
	if daily[0].ScanCount != 1 || daily[0].FindingsCount != 3 {
		t.Fatalf("day 0 = %+v, want 1 scan / 3 findings", daily[0])
	}
	if daily[1].ScanCount != 1 || daily[1].FindingsCount != 1 {
		t.Fatalf("day 1 = %+v, want 1 scan / 1 finding", daily[1])
	}
	if daily[2].ScanCount != 1 || daily[2].FindingsCount != 0 {
		t.Fatalf("day 2 = %+v, want 1 scan / 0 findings", daily[2])
	}

	before := baseDay.Add(-24 * time.Hour)
	deleted, err := store.ClearHistory(ctx, &before, "repo-a")
	if err != nil {
		t.Fatalf("ClearHistory() error = %v", err)
	}
	if deleted != 1 {
		t.Fatalf("ClearHistory() deleted = %d, want 1", deleted)
	}

	remaining, err := store.GetRecentScans(ctx, "", 10)
	if err != nil {
		t.Fatalf("GetRecentScans() error = %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("remaining scans = %d, want 2", len(remaining))
	}
}

func TestDashboardStatsAndSearchPackages(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeSilently(store)

	ctx := context.Background()

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
		VALUES
			('V-1|npm|lodash', 'V-1', 'npm', 'lodash', '[]', 'HIGH', 'lodash vuln 1'),
			('V-2|npm|lodash', 'V-2', 'npm', 'lodash', '[]', 'MEDIUM', 'lodash vuln 2'),
			('V-3|go|golang.org/x/text', 'V-3', 'go', 'golang.org/x/text', '[]', 'LOW', 'text vuln')`); err != nil {
		t.Fatalf("insert vulnerabilities: %v", err)
	}

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary)
		VALUES
			('M-1', 'npm', 'lodash', NULL, 'malware', 'CRITICAL', 'lodash malware'),
			('M-2', 'pypi', 'requests-evil', NULL, 'typosquatting', 'HIGH', 'requests clone')`); err != nil {
		t.Fatalf("insert malicious rows: %v", err)
	}

	hasData, err := store.HasAdvisoryData(ctx)
	if err != nil {
		t.Fatalf("HasAdvisoryData() error = %v", err)
	}
	if !hasData {
		t.Fatal("HasAdvisoryData() = false, want true")
	}

	results, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "lod", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchPackages() len = %d, want 1", len(results))
	}
	if results[0].Name != "lodash" || results[0].FindingsCount != 3 {
		t.Fatalf("SearchPackages() result = %+v, want lodash with 3 findings", results[0])
	}
	if results[0].VulnerabilityCount != 2 || results[0].VulnerabilityIDs != "V-1, V-2" {
		t.Fatalf("SearchPackages() vulnerabilities = (%d, %q), want (2, %q)", results[0].VulnerabilityCount, results[0].VulnerabilityIDs, "V-1, V-2")
	}

	highResults, err := store.SearchPackages(ctx, db.PackageSearchParams{Severity: "HIGH", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() with severity error = %v", err)
	}
	if len(highResults) != 2 {
		t.Fatalf("SearchPackages() with severity len = %d, want 2", len(highResults))
	}

	maliciousResults, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "malicious", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() with malicious finding filter error = %v", err)
	}
	if len(maliciousResults) != 2 {
		t.Fatalf("SearchPackages() with malicious finding filter len = %d, want 2", len(maliciousResults))
	}
	for _, result := range maliciousResults {
		if result.Name == "requests-evil" && result.VulnerabilityCount != 0 {
			t.Fatalf("SearchPackages() malicious-only result has vulnerability count %d, want 0", result.VulnerabilityCount)
		}
	}

	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if stats.TotalPackages != 3 {
		t.Fatalf("TotalPackages = %d, want 3", stats.TotalPackages)
	}
	if stats.TotalVulnerabilities != 3 {
		t.Fatalf("TotalVulnerabilities = %d, want 3", stats.TotalVulnerabilities)
	}
	if stats.TotalMalicious != 2 {
		t.Fatalf("TotalMalicious = %d, want 2", stats.TotalMalicious)
	}
	if stats.BySeverity["CRITICAL"] != 1 || stats.BySeverity["HIGH"] != 2 || stats.BySeverity["MEDIUM"] != 1 || stats.BySeverity["LOW"] != 1 {
		t.Fatalf("BySeverity = %#v, want CRITICAL=1 HIGH=2 MEDIUM=1 LOW=1", stats.BySeverity)
	}
}
