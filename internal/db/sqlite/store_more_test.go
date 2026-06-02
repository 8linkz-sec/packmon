package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

func newSQLiteTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	return store
}

func TestStorePathCloseAndFeedConfigNoops(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	if store.Path() == "" {
		t.Fatal("Path() = empty, want database path")
	}

	ctx := context.Background()
	if cfg, err := store.GetFeedConfig(ctx, "osv"); err != nil || cfg != nil {
		t.Fatalf("GetFeedConfig() = %+v, %v; want nil nil", cfg, err)
	}
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: "osv"}); err != nil {
		t.Fatalf("UpsertFeedConfig() error = %v", err)
	}
	if err := store.DeleteFeedConfig(ctx, "osv"); err != nil {
		t.Fatalf("DeleteFeedConfig() error = %v", err)
	}
	configs, err := store.ListFeedConfigs(ctx)
	if err != nil {
		t.Fatalf("ListFeedConfigs() error = %v", err)
	}
	if len(configs) != 0 {
		t.Fatalf("ListFeedConfigs() len = %d, want 0", len(configs))
	}
}

func TestNewReturnsDirectoryCreationError(t *testing.T) {
	t.Parallel()

	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	if _, err := New(filepath.Join(parentFile, "packmon.db")); err == nil {
		t.Fatal("New() error = nil, want directory creation error")
	}
}

func TestMigrateSchemaAddsRowKeyToOldVulnerabilityTable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "old.db")
	rawDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer closeSilently(rawDB)

	if _, err := rawDB.Exec(`
		CREATE TABLE vulnerabilities_local (
			id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			name TEXT NOT NULL,
			version_ranges TEXT,
			severity TEXT NOT NULL,
			cvss_score REAL,
			epss_score REAL,
			cisa_kev INTEGER DEFAULT 0,
			summary TEXT
		);
		INSERT INTO vulnerabilities_local(id, ecosystem, name, version_ranges, severity)
		VALUES('GHSA-old', 'npm', 'left-pad', '[]', 'LOW');
	`); err != nil {
		t.Fatalf("create old schema: %v", err)
	}

	if hasRowKey, err := tableHasColumn(rawDB, "vulnerabilities_local", "row_key"); err != nil || hasRowKey {
		t.Fatalf("tableHasColumn(before) = %v, %v; want false nil", hasRowKey, err)
	}
	if err := migrateSchema(rawDB); err != nil {
		t.Fatalf("migrateSchema() error = %v", err)
	}
	if hasRowKey, err := tableHasColumn(rawDB, "vulnerabilities_local", "row_key"); err != nil || !hasRowKey {
		t.Fatalf("tableHasColumn(after) = %v, %v; want true nil", hasRowKey, err)
	}

	var rowKey string
	if err := rawDB.QueryRow(`SELECT row_key FROM vulnerabilities_local WHERE id = 'GHSA-old'`).Scan(&rowKey); err != nil {
		t.Fatalf("read migrated row key: %v", err)
	}
	if rowKey != "GHSA-old|npm|left-pad" {
		t.Fatalf("row_key = %q", rowKey)
	}

	if err := migrateSchema(rawDB); err != nil {
		t.Fatalf("migrateSchema(idempotent) error = %v", err)
	}
}

func TestFindVulnerabilitiesMatchesRangesAndFailsSafeOnInvalidJSON(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
		VALUES
			('V-1|npm|lodash', 'V-1', 'npm', 'lodash', '[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]', 'HIGH', 'affected range'),
			('V-2|npm|lodash', 'V-2', 'npm', 'lodash', '[{"type":"SEMVER","events":[{"introduced":"3.0.0"},{"fixed":"4.0.0"}]}]', 'LOW', 'unaffected range'),
			('V-3|npm|lodash', 'V-3', 'npm', 'lodash', '{broken', 'MEDIUM', NULL)`); err != nil {
		t.Fatalf("insert vulnerabilities: %v", err)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "lodash", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("FindVulnerabilities() len = %d, want affected + fail-safe invalid JSON", len(findings))
	}
	byID := map[string]domain.Finding{}
	for _, finding := range findings {
		byID[finding.AdvisoryID] = finding
	}
	if byID["V-1"].FixedVersion != ">= 2.0.0" {
		t.Fatalf("V-1 FixedVersion = %q, want >= 2.0.0", byID["V-1"].FixedVersion)
	}
	if byID["V-3"].Title != "V-3" {
		t.Fatalf("V-3 title = %q, want advisory ID fallback", byID["V-3"].Title)
	}

	findings, err = store.FindVulnerabilities(ctx, "npm", "lodash", "2.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(unaffected) error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "V-3" {
		t.Fatalf("FindVulnerabilities(unaffected) = %+v, want only fail-safe invalid JSON finding", findings)
	}
}

func TestFindLocalSecurityRowsNormalizeNuGetNames(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
		VALUES ('V-NUGET|nuget|newtonsoft.json', 'V-NUGET', 'nuget', 'newtonsoft.json', NULL, 'HIGH', 'nuget vuln');
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary)
		VALUES ('M-NUGET', 'nuget', 'newtonsoft.json', '["13.0.3"]', 'malware', 'CRITICAL', 'nuget malicious');
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES ('R-NUGET', 'nuget', 'newtonsoft.json', '13.0.3', 'supply_chain_risk', 'removed_package', 'LOW', 'nuget reputation')`); err != nil {
		t.Fatalf("insert nuget rows: %v", err)
	}

	vulns, err := store.FindVulnerabilities(ctx, "nuget", "Newtonsoft.Json", "13.0.3")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "V-NUGET" || vulns[0].Name != "newtonsoft.json" {
		t.Fatalf("FindVulnerabilities() = %+v, want normalized NuGet hit", vulns)
	}

	malicious, err := store.FindMalicious(ctx, "nuget", "Newtonsoft.Json", "13.0.3")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	byID := make(map[string]domain.Finding, len(malicious))
	sawMalicious := false
	for _, finding := range malicious {
		byID[finding.AdvisoryID] = finding
		if finding.Type == domain.FindingTypeMalicious && finding.RiskType == "malware" && finding.Name == "newtonsoft.json" {
			sawMalicious = true
		}
	}
	if !sawMalicious {
		t.Fatalf("FindMalicious() = %+v, want normalized malicious hit", malicious)
	}
	if byID["R-NUGET"].Name != "newtonsoft.json" {
		t.Fatalf("FindMalicious() = %+v, want normalized reputation hit", malicious)
	}

	reputation, err := store.FindReputationFindings(ctx, "nuget", "Newtonsoft.Json", "reversinglabs")
	if err != nil {
		t.Fatalf("FindReputationFindings() error = %v", err)
	}
	if len(reputation) != 1 || reputation[0].AdvisoryID != "R-NUGET" || reputation[0].Name != "newtonsoft.json" {
		t.Fatalf("FindReputationFindings() = %+v, want normalized NuGet hit", reputation)
	}
}

func TestFindMaliciousFiltersVersionsAndIncludesReputation(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary)
		VALUES
			('M-1', 'npm', 'evil', '["1.0.0"]', 'malware', 'CRITICAL', 'known bad'),
			('M-2', 'npm', 'evil', '["2.0.0"]', 'typosquatting', 'HIGH', ''),
			('M-3', 'npm', 'evil', NULL, 'malware', 'CRITICAL', 'all versions')`); err != nil {
		t.Fatalf("insert malicious: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES ('R-1', 'npm', 'evil', '1.0.0', 'supply_chain_risk', 'removed_package', 'LOW', 'removed')`); err != nil {
		t.Fatalf("insert reputation: %v", err)
	}

	findings, err := store.FindMalicious(ctx, "npm", "evil", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	byID := map[string]domain.Finding{}
	var matchingMalicious int
	for _, finding := range findings {
		byID[finding.AdvisoryID] = finding
		if finding.Type == domain.FindingTypeMalicious && finding.RiskType == "malware" {
			matchingMalicious++
		}
	}
	if matchingMalicious != 2 {
		t.Fatalf("FindMalicious() matching malicious findings = %d, want version-specific + all-versions rows: %+v", matchingMalicious, findings)
	}
	for _, finding := range findings {
		if finding.RiskType == "typosquatting" {
			t.Fatalf("FindMalicious() included non-matching version row: %+v", findings)
		}
	}
	if byID["R-1"].Type != domain.FindingTypeSupplyChainRisk {
		t.Fatalf("reputation finding = %+v, want supply_chain_risk", byID["R-1"])
	}

	allReputation, err := store.FindReputationFindings(ctx, "npm", "evil", "reversinglabs")
	if err != nil {
		t.Fatalf("FindReputationFindings() error = %v", err)
	}
	if len(allReputation) != 1 || allReputation[0].Version != "1.0.0" {
		t.Fatalf("FindReputationFindings() = %+v, want exact reputation row", allReputation)
	}
	otherSource, err := store.FindReputationFindings(ctx, "npm", "evil", "socket")
	if err != nil {
		t.Fatalf("FindReputationFindings(other source) error = %v", err)
	}
	if len(otherSource) != 0 {
		t.Fatalf("FindReputationFindings(other source) len = %d, want 0", len(otherSource))
	}
}

func TestEnforceRetentionKeepsNewestPerRepo(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 4; i++ {
		if err := store.InsertScan(ctx, ScanEntry{
			RepoName:      "repo-a",
			ScannedAt:     now.Add(time.Duration(i) * time.Minute),
			PackagesCount: i,
			FindingsCount: i,
		}); err != nil {
			t.Fatalf("InsertScan(repo-a %d) error = %v", i, err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := store.InsertScan(ctx, ScanEntry{
			RepoName:  "repo-b",
			ScannedAt: now.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("InsertScan(repo-b %d) error = %v", i, err)
		}
	}

	if err := store.EnforceRetention(ctx, 2); err != nil {
		t.Fatalf("EnforceRetention() error = %v", err)
	}
	repoA, err := store.GetRecentScans(ctx, "repo-a", 10)
	if err != nil {
		t.Fatalf("GetRecentScans(repo-a) error = %v", err)
	}
	if len(repoA) != 2 {
		t.Fatalf("repo-a scans = %d, want newest 2", len(repoA))
	}
	if repoA[0].PackagesCount != 3 || repoA[1].PackagesCount != 2 {
		t.Fatalf("repo-a retained scans = %+v, want newest entries", repoA)
	}
	repoB, err := store.GetRecentScans(ctx, "repo-b", 10)
	if err != nil {
		t.Fatalf("GetRecentScans(repo-b) error = %v", err)
	}
	if len(repoB) != 2 {
		t.Fatalf("repo-b scans = %d, want unchanged 2", len(repoB))
	}

	if err := store.EnforceRetention(ctx, 0); err != nil {
		t.Fatalf("EnforceRetention(no-op) error = %v", err)
	}
}
