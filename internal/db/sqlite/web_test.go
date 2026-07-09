package sqlite

import (
	"context"
	"fmt"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestHistoryQueriesAndClear(t *testing.T) {
	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer ioutils.CloseSilently(store)

	ctx := context.Background()
	fixedNow := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	originalNowUTC := nowUTC
	nowUTC = func() time.Time { return fixedNow }
	t.Cleanup(func() { nowUTC = originalNowUTC })
	baseDay := fixedNow.Truncate(24 * time.Hour)

	entries := []ScanEntry{
		{
			RepoName:          "repo-a",
			Branch:            "main",
			Commit:            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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

	recent, err := store.ListRecentScans(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("ListRecentScans() len = %d, want 2", len(recent))
	}
	if recent[0].RepoName != "repo-b" || recent[1].RepoName != "repo-a" {
		t.Fatalf("ListRecentScans() order = [%s, %s], want [repo-b, repo-a]", recent[0].RepoName, recent[1].RepoName)
	}
	stored, err := store.GetRecentScans(ctx, "repo-a", 10)
	if err != nil {
		t.Fatalf("GetRecentScans(repo-a) error = %v", err)
	}
	if stored[1].Commit != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("stored commit = %q, want commit SHA", stored[1].Commit)
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

func TestGetRecentScansReturnsDecodeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		column      string
		value       string
		wantSnippet string
	}{
		{name: "scanned_at", column: "scanned_at", value: "not-a-time", wantSnippet: "scan history row 1 scanned_at"},
		{name: "finding_ids", column: "finding_ids", value: "{", wantSnippet: "scan history row 1 finding_ids"},
		{name: "finding_severities", column: "finding_severities", value: "{", wantSnippet: "scan history row 1 finding_severities"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, err := New(t.TempDir() + "/packmon.db")
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer ioutils.CloseSilently(store)

			scannedAt := "2026-05-30T12:00:00Z"
			findingIDs := `["GHSA-test"]`
			findingSeverities := `["HIGH"]`
			switch tt.column {
			case "scanned_at":
				scannedAt = tt.value
			case "finding_ids":
				findingIDs = tt.value
			case "finding_severities":
				findingSeverities = tt.value
			}

			_, err = store.DB().ExecContext(context.Background(), `
				INSERT INTO scan_history(repo_name, branch, scanned_at, packages_count, findings_count, finding_ids, finding_severities)
				VALUES('repo', 'main', ?, 1, 1, ?, ?)`, scannedAt, findingIDs, findingSeverities)
			if err != nil {
				t.Fatalf("seed corrupt history: %v", err)
			}

			_, err = store.GetRecentScans(context.Background(), "", 10)
			if err == nil {
				t.Fatal("GetRecentScans() error = nil, want decode error")
			}
			if !strings.Contains(err.Error(), tt.wantSnippet) {
				t.Fatalf("GetRecentScans() error = %v, want %q", err, tt.wantSnippet)
			}
		})
	}
}

func TestScanHistorySchemaIncludesCommitAndIndexes(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer ioutils.CloseSilently(store)

	if ok, err := tableHasColumn(store.DB(), "scan_history", "commit"); err != nil {
		t.Fatalf("inspect scan_history commit column: %v", err)
	} else if !ok {
		t.Fatal("scan_history.commit column missing")
	}

	rows, err := store.DB().QueryContext(context.Background(), `
		SELECT name FROM sqlite_master
		WHERE type = 'index' AND tbl_name = 'scan_history'`)
	if err != nil {
		t.Fatalf("query scan_history indexes: %v", err)
	}
	defer ioutils.CloseSilently(rows)

	indexes := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		indexes[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate indexes: %v", err)
	}
	for _, want := range []string{"idx_scan_history_scanned_at", "idx_scan_history_repo_scanned_at", "idx_scan_history_repo_retention"} {
		if !indexes[want] {
			t.Fatalf("scan_history index %q missing; have %#v", want, indexes)
		}
	}
}

func TestDashboardStatsAndSearchPackages(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer ioutils.CloseSilently(store)

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
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES
			('REP-1', 'npm', 'supply-only', '1.0.0', 'supply_chain_risk', 'removed_package', 'MEDIUM', 'removed package'),
			('REP-2', 'npm', 'rep-malware', '1.0.0', 'malicious', 'malware', 'CRITICAL', 'reputation malware')`); err != nil {
		t.Fatalf("insert reputation rows: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO lifecycle_releases_local(
			id, ecosystem, name, product_slug, product_label, cycle, latest, is_eoas, eoas_from, is_eol, eol_from
		) VALUES
			('LIFE-1', 'pypi', 'django', 'django', 'Django', '4.2', '4.2.11', 1, '2020-01-01', 0, NULL),
			('LIFE-2', 'pypi', 'django-eol', 'django', 'Django', '3.2', '3.2.25', 0, NULL, 1, '2020-01-01')`); err != nil {
		t.Fatalf("insert lifecycle rows: %v", err)
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
	if results[0].FindingTypes != "malicious, vulnerability" {
		t.Fatalf("SearchPackages() finding types = %q, want malicious and vulnerability", results[0].FindingTypes)
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
	if len(maliciousResults) != 3 {
		t.Fatalf("SearchPackages() with malicious finding filter len = %d, want 3", len(maliciousResults))
	}
	sawReputationMalicious := false
	for _, result := range maliciousResults {
		if result.Name == "requests-evil" && result.VulnerabilityCount != 0 {
			t.Fatalf("SearchPackages() malicious-only result has vulnerability count %d, want 0", result.VulnerabilityCount)
		}
		if result.FindingTypes != "malicious" {
			t.Fatalf("SearchPackages() malicious-only finding types = %q, want malicious", result.FindingTypes)
		}
		if result.Name == "rep-malware" && result.FindingsCount == 1 {
			sawReputationMalicious = true
		}
	}
	if !sawReputationMalicious {
		t.Fatalf("SearchPackages() malicious-only results = %+v, want reputation-backed malware", maliciousResults)
	}
	supplyResults, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "supply_chain_risk", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() with supply-chain finding filter error = %v", err)
	}
	sawSupplyOnly := false
	sawEOLEntry := false
	for _, result := range supplyResults {
		if result.Name == "supply-only" && result.FindingsCount == 1 {
			if result.FindingTypes != "supply_chain_risk" {
				t.Fatalf("SearchPackages() supply-only finding types = %q, want supply_chain_risk", result.FindingTypes)
			}
			sawSupplyOnly = true
		}
		if result.Name == "django-eol" && result.Version == "3.2.25" && result.FindingsCount == 1 {
			if result.FindingTypes != "supply_chain_risk" {
				t.Fatalf("SearchPackages() EOL supply-chain finding types = %q, want supply_chain_risk", result.FindingTypes)
			}
			sawEOLEntry = true
		}
	}
	if !sawSupplyOnly || !sawEOLEntry {
		t.Fatalf("SearchPackages() supply-chain results = %+v, want reputation risk and EOL lifecycle risk", supplyResults)
	}
	eolResults, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "supply_chain_risk", Query: "django-eol", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() with supply-chain EOL finding filter error = %v", err)
	}
	if len(eolResults) != 1 || eolResults[0].Name != "django-eol" || eolResults[0].Version != "3.2.25" {
		t.Fatalf("SearchPackages() supply-chain EOL results = %+v, want django-eol with version 3.2.25", eolResults)
	}
	lifecycleResults, err := store.SearchPackages(ctx, db.PackageSearchParams{FindingType: "lifecycle", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() with lifecycle finding filter error = %v", err)
	}
	if len(lifecycleResults) != 1 || lifecycleResults[0].Name != "django" || lifecycleResults[0].Version != "4.2.11" || lifecycleResults[0].FindingsCount != 1 {
		t.Fatalf("SearchPackages() lifecycle results = %+v, want django with version 4.2.11", lifecycleResults)
	}
	if lifecycleResults[0].FindingTypes != "lifecycle" {
		t.Fatalf("SearchPackages() lifecycle finding types = %q, want lifecycle", lifecycleResults[0].FindingTypes)
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
	if stats.TotalMalicious != 3 {
		t.Fatalf("TotalMalicious = %d, want 3 including reputation-backed malware", stats.TotalMalicious)
	}
	if stats.TotalSupplyChainRisk != 2 {
		t.Fatalf("TotalSupplyChainRisk = %d, want 2", stats.TotalSupplyChainRisk)
	}
	if stats.TotalLifecycle != 1 {
		t.Fatalf("TotalLifecycle = %d, want 1", stats.TotalLifecycle)
	}
	if stats.BySeverity["CRITICAL"] != 2 || stats.BySeverity["HIGH"] != 2 || stats.BySeverity["MEDIUM"] != 2 || stats.BySeverity["LOW"] != 1 {
		t.Fatalf("BySeverity = %#v, want vulnerability plus malicious/reputation severities", stats.BySeverity)
	}
}

func TestHasAdvisoryDataIncludesReputationAndLifecycle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "reputation only",
			sql: `INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
				VALUES ('REP-only', 'npm', 'removed-pkg', '1.0.0', 'supply_chain_risk', 'removed_package', 'MEDIUM', 'removed package')`,
		},
		{
			name: "lifecycle only",
			sql: `INSERT INTO lifecycle_releases_local(id, ecosystem, name, product_slug, product_label, cycle, is_eol, eol_from)
				VALUES ('LIFE-only', 'pypi', 'django', 'django', 'Django', '3.2', 1, '2020-01-01')`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, err := New(t.TempDir() + "/packmon.db")
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer ioutils.CloseSilently(store)

			ctx := context.Background()
			if _, err := store.DB().ExecContext(ctx, tt.sql); err != nil {
				t.Fatalf("seed %s: %v", tt.name, err)
			}

			hasData, err := store.HasAdvisoryData(ctx)
			if err != nil {
				t.Fatalf("HasAdvisoryData() error = %v", err)
			}
			if !hasData {
				t.Fatal("HasAdvisoryData() = false, want true")
			}
		})
	}
}

func TestSearchPackagesCapsVulnerabilityIDPreview(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer ioutils.CloseSilently(store)

	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		id := fmt.Sprintf("ADV-%03d", i)
		if _, err := store.DB().ExecContext(ctx, `
			INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
			VALUES(?, ?, 'npm', 'wide-advisory-package', '[]', 'HIGH', 'preview cap')`, id+"|npm|wide-advisory-package", id); err != nil {
			t.Fatalf("insert vulnerability %s: %v", id, err)
		}
	}

	results, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "wide-advisory", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchPackages() len = %d, want 1", len(results))
	}
	if results[0].VulnerabilityCount != 7 {
		t.Fatalf("SearchPackages() vulnerability count = %d, want 7", results[0].VulnerabilityCount)
	}
	wantIDs := "ADV-001, ADV-002, ADV-003, ADV-004, ADV-005, +2 more"
	if results[0].VulnerabilityIDs != wantIDs {
		t.Fatalf("SearchPackages() vulnerability IDs = %q, want %q", results[0].VulnerabilityIDs, wantIDs)
	}
	if strings.Contains(results[0].VulnerabilityIDs, "ADV-006") || strings.Contains(results[0].VulnerabilityIDs, "ADV-007") {
		t.Fatalf("SearchPackages() included IDs beyond cap: %q", results[0].VulnerabilityIDs)
	}
}

func TestLimitLocalSearchResultsSortsByNameEcosystemVersion(t *testing.T) {
	t.Parallel()

	results := []db.PackageSearchResult{
		{Ecosystem: "npm", Name: "zeta", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "alpha", Version: "2.0.0"},
		{Ecosystem: "go", Name: "alpha", Version: "1.0.0"},
		{Ecosystem: "go", Name: "alpha", Version: "0.9.0"},
	}

	got := limitLocalSearchResults(results, 3, 0)

	want := []db.PackageSearchResult{
		{Ecosystem: "go", Name: "alpha", Version: "0.9.0"},
		{Ecosystem: "go", Name: "alpha", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "alpha", Version: "2.0.0"},
	}
	if len(got) != len(want) {
		t.Fatalf("limitLocalSearchResults() len = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("limitLocalSearchResults()[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	got = limitLocalSearchResults(results, 2, 1)
	want = []db.PackageSearchResult{
		{Ecosystem: "go", Name: "alpha", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "alpha", Version: "2.0.0"},
	}
	if len(got) != len(want) {
		t.Fatalf("limitLocalSearchResults(offset) len = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("limitLocalSearchResults(offset)[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSearchPackagesWithoutFiltersReturnsEmptyWithoutQuerying(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	results, err := store.SearchPackages(context.Background(), db.PackageSearchParams{})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("SearchPackages() len = %d, want 0", len(results))
	}
}

func TestSearchPackagesUsesUnicodeAwareQueryMatching(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer ioutils.CloseSilently(store)

	ctx := context.Background()
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
		VALUES ('V-unicode|npm|ÜberPkg', 'V-unicode', 'npm', 'ÜberPkg', '[]', 'HIGH', 'unicode package')`); err != nil {
		t.Fatalf("insert unicode package: %v", err)
	}

	results, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "über", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if len(results) != 1 || results[0].Name != "ÜberPkg" {
		t.Fatalf("SearchPackages() results = %+v, want Unicode case-insensitive match", results)
	}
}

func TestDashboardStatsNormalizesBlankSeverity(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer ioutils.CloseSilently(store)

	ctx := context.Background()
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
		VALUES
			('V-blank|npm|blank', 'V-blank', 'npm', 'blank', '[]', '', 'blank severity'),
			('V-spaced|npm|spaced', 'V-spaced', 'npm', 'spaced', '[]', ' high ', 'spaced severity')`); err != nil {
		t.Fatalf("insert vulnerabilities: %v", err)
	}

	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if stats.BySeverity["UNKNOWN"] != 1 {
		t.Fatalf("UNKNOWN severity count = %d, want 1 in %#v", stats.BySeverity["UNKNOWN"], stats.BySeverity)
	}
	if stats.BySeverity["HIGH"] != 1 {
		t.Fatalf("HIGH severity count = %d, want 1 in %#v", stats.BySeverity["HIGH"], stats.BySeverity)
	}
}

func TestClosedStoreReturnsQueryErrors(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	ctx := context.Background()
	checks := []struct {
		name string
		run  func() error
	}{
		{name: "HasAdvisoryData", run: func() error {
			_, err := store.HasAdvisoryData(ctx)
			return err
		}},
		{name: "ListRecentScans", run: func() error {
			_, err := store.ListRecentScans(ctx, 1, 0)
			return err
		}},
		{name: "CountScansByDay", run: func() error {
			_, err := store.CountScansByDay(ctx, 1)
			return err
		}},
		{name: "SearchPackages", run: func() error {
			_, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "lodash"})
			return err
		}},
		{name: "DashboardStats", run: func() error {
			_, err := store.DashboardStats(ctx)
			return err
		}},
		{name: "FindVulnerabilities", run: func() error {
			_, err := store.FindVulnerabilities(ctx, "npm", "lodash", "")
			return err
		}},
		{name: "FindMalicious", run: func() error {
			_, err := store.FindMalicious(ctx, "npm", "evil", "")
			return err
		}},
		{name: "FindReputationFindings", run: func() error {
			_, err := store.FindReputationFindings(ctx, "npm", "evil", db.ReputationSourceReversingLabs)
			return err
		}},
		{name: "GetSyncMeta", run: func() error {
			_, err := store.GetSyncMeta(ctx, "last_sync")
			return err
		}},
		{name: "SetSyncMeta", run: func() error {
			return store.SetSyncMeta(ctx, "last_sync", "now")
		}},
		{name: "InsertScan", run: func() error {
			return store.InsertScan(ctx, ScanEntry{ScannedAt: time.Now().UTC()})
		}},
		{name: "ClearHistory", run: func() error {
			_, err := store.ClearHistory(ctx, nil, "")
			return err
		}},
		{name: "EnforceRetention", run: func() error {
			return store.EnforceRetention(ctx, 1)
		}},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err == nil {
				t.Fatal("error = nil, want closed database error")
			}
		})
	}
}
