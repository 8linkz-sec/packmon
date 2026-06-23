package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
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

func TestNewRestrictsSQLiteDatabaseFilePermissions(t *testing.T) {
	requirePOSIXFileModeSupport(t)

	dbPath := filepath.Join(t.TempDir(), "packmon.db")
	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeSilently(store)

	if _, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO sync_meta(key, value) VALUES('permission-probe', '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`); err != nil {
		t.Fatalf("force sqlite write: %v", err)
	}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := dbPath + suffix
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s permissions = %o, want 0600", path, got)
		}
	}
}

func requirePOSIXFileModeSupport(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX file permission bits reliably")
	}
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatalf("write permission probe: %v", err)
	}
	if err := os.Chmod(probe, 0o600); err != nil {
		t.Fatalf("chmod permission probe: %v", err)
	}
	info, err := os.Stat(probe)
	if err != nil {
		t.Fatalf("stat permission probe: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Skipf("filesystem does not preserve POSIX file mode bits: got %o after chmod 0600", got)
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
		CREATE TABLE malicious_local (
			id TEXT PRIMARY KEY,
			ecosystem TEXT NOT NULL,
			name TEXT NOT NULL,
			versions TEXT,
			risk_type TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'CRITICAL',
			summary TEXT
		);
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity)
		VALUES('MAL-old', 'npm', 'evil', '["1.0.0"]', 'malware', 'CRITICAL');
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
	if hasVersionsAffected, err := tableHasColumn(rawDB, "vulnerabilities_local", "versions_affected"); err != nil || !hasVersionsAffected {
		t.Fatalf("tableHasColumn(versions_affected) = %v, %v; want true nil", hasVersionsAffected, err)
	}
	if hasReferences, err := tableHasColumn(rawDB, "vulnerabilities_local", "references_json"); err != nil || !hasReferences {
		t.Fatalf("tableHasColumn(references_json) = %v, %v; want true nil", hasReferences, err)
	}
	if hasVulnSource, err := tableHasColumn(rawDB, "vulnerabilities_local", "source"); err != nil || !hasVulnSource {
		t.Fatalf("tableHasColumn(vulnerability source) = %v, %v; want true nil", hasVulnSource, err)
	}
	if hasMaliciousSource, err := tableHasColumn(rawDB, "malicious_local", "source"); err != nil || !hasMaliciousSource {
		t.Fatalf("tableHasColumn(malicious source) = %v, %v; want true nil", hasMaliciousSource, err)
	}

	var rowKey, versionsAffected, referencesJSON, source string
	if err := rawDB.QueryRow(`SELECT row_key, versions_affected, references_json, source FROM vulnerabilities_local WHERE id = 'GHSA-old'`).Scan(&rowKey, &versionsAffected, &referencesJSON, &source); err != nil {
		t.Fatalf("read migrated row key: %v", err)
	}
	if rowKey != "GHSA-old|npm|left-pad" {
		t.Fatalf("row_key = %q", rowKey)
	}
	if versionsAffected != "[]" {
		t.Fatalf("versions_affected = %q, want []", versionsAffected)
	}
	if referencesJSON != "[]" {
		t.Fatalf("references_json = %q, want []", referencesJSON)
	}
	if source != "local" {
		t.Fatalf("vulnerability source = %q, want local", source)
	}
	if err := rawDB.QueryRow(`SELECT source FROM malicious_local WHERE id = 'MAL-old'`).Scan(&source); err != nil {
		t.Fatalf("read migrated malicious source: %v", err)
	}
	if source != "local" {
		t.Fatalf("malicious source = %q, want local", source)
	}

	if err := migrateSchema(rawDB); err != nil {
		t.Fatalf("migrateSchema(idempotent) error = %v", err)
	}
}

func TestAcquireSQLiteMigrationLockSerializesLocalMigrations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "packmon.db")
	unlock, err := acquireSQLiteMigrationLock(dbPath)
	if err != nil {
		t.Fatalf("acquire first migration lock: %v", err)
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()

	originalTimeout := sqliteMigrationLockTimeout
	originalPoll := sqliteMigrationLockPollInterval
	sqliteMigrationLockTimeout = 50 * time.Millisecond
	sqliteMigrationLockPollInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		sqliteMigrationLockTimeout = originalTimeout
		sqliteMigrationLockPollInterval = originalPoll
	})

	_, err = acquireSQLiteMigrationLock(dbPath)
	if err == nil {
		t.Fatal("second migration lock error = nil, want timeout while first lock is held")
	}
	if !strings.Contains(err.Error(), "migration lock") {
		t.Fatalf("second migration lock error = %v, want migration lock context", err)
	}

	unlock()
	unlock = nil
	unlockAgain, err := acquireSQLiteMigrationLock(dbPath)
	if err != nil {
		t.Fatalf("acquire after unlock: %v", err)
	}
	unlockAgain()
}

func TestMigrateSchemaNormalizesExistingCaseInsensitivePackageNames(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "mixed-case.db")
	store, err := New(path)
	if err != nil {
		t.Fatalf("New(initial) error = %v", err)
	}
	ctx := context.Background()
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, versions_affected, severity)
		VALUES('PYSEC-old|pypi|My.Pkg_Name', 'PYSEC-old', 'pypi', 'My.Pkg_Name', '[]', '["1.0.0"]', 'HIGH');
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity)
		VALUES('MAL-old', 'pypi', 'Django', '["4.2.11"]', 'malware', 'CRITICAL');
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity)
		VALUES('REP-old', 'pypi', 'Other_Pkg', '1.0.0', 'malicious', 'malware', 'CRITICAL');
		INSERT INTO lifecycle_releases_local(id, ecosystem, name, product_slug, product_label, cycle)
		VALUES('LIFE-old', 'nuget', 'Newtonsoft.Json', 'newtonsoft-json', 'Newtonsoft.Json', '13');
	`); err != nil {
		t.Fatalf("insert mixed case rows: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close(initial) error = %v", err)
	}

	store, err = New(path)
	if err != nil {
		t.Fatalf("New(reopen) error = %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Fatalf("Close(reopen) error = %v", err)
		}
	})

	vulns, err := store.FindVulnerabilities(ctx, "pypi", "my-pkg-name", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(normalized existing) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].Name != "my-pkg-name" {
		t.Fatalf("vulnerabilities after migration = %+v, want normalized local row", vulns)
	}
	malicious, err := store.FindMalicious(ctx, "pypi", "django", "4.2.11")
	if err != nil {
		t.Fatalf("FindMalicious(normalized existing) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].Name != "django" {
		t.Fatalf("malicious after migration = %+v, want normalized local row", malicious)
	}
	reputation, err := store.FindReputationFindings(ctx, "pypi", "other-pkg", "reversinglabs")
	if err != nil {
		t.Fatalf("FindReputationFindings(normalized existing) error = %v", err)
	}
	if len(reputation) != 1 || reputation[0].Name != "other-pkg" {
		t.Fatalf("reputation after migration = %+v, want normalized local row", reputation)
	}
	var storedLifecycleName string
	if err := store.DB().QueryRowContext(ctx, `SELECT name FROM lifecycle_releases_local WHERE id = 'LIFE-old'`).Scan(&storedLifecycleName); err != nil {
		t.Fatalf("read lifecycle name: %v", err)
	}
	if storedLifecycleName != "newtonsoft.json" {
		t.Fatalf("stored lifecycle name = %q, want normalized name", storedLifecycleName)
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
	if _, ok := byID["R-NUGET"]; ok {
		t.Fatalf("FindMalicious() included reputation hit: %+v", malicious)
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
	if _, ok := byID["R-1"]; ok {
		t.Fatalf("FindMalicious() included reputation finding: %+v", findings)
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

func TestFindMaliciousErrorsOnMalformedStoredVersions(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary)
		VALUES ('M-BAD', 'npm', 'evil', '{"introduced":"1.0.0"}', 'malware', 'CRITICAL', 'bad versions')`); err != nil {
		t.Fatalf("insert malicious: %v", err)
	}

	_, err := store.FindMalicious(ctx, "npm", "evil", "2.0.0")
	if err == nil {
		t.Fatal("FindMalicious() error = nil, want malformed versions error")
	}
	if !strings.Contains(err.Error(), "M-BAD") {
		t.Fatalf("FindMalicious() error = %q, want finding ID", err)
	}

	_, err = store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "evil", Version: "2.0.0"}})
	if err == nil {
		t.Fatal("FindMaliciousBatch() error = nil, want malformed versions error")
	}
	if !strings.Contains(err.Error(), "M-BAD") {
		t.Fatalf("FindMaliciousBatch() error = %q, want finding ID", err)
	}
}

func TestFindLocalSecurityRowsBatchMatchesVersionsAndReputation(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
		VALUES
			('V-B1|npm|lodash', 'V-B1', 'npm', 'lodash', '[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]', 'HIGH', 'affected'),
			('V-B2|npm|lodash', 'V-B2', 'npm', 'lodash', '[{"type":"SEMVER","events":[{"introduced":"3.0.0"},{"fixed":"4.0.0"}]}]', 'LOW', 'unaffected');
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary)
		VALUES
			('M-B1', 'npm', 'evil', '["1.0.0"]', 'malware', 'CRITICAL', 'known bad'),
			('M-B2', 'npm', 'evil', '["2.0.0"]', 'typosquatting', 'HIGH', 'other version');
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES ('R-B1', 'npm', 'evil', '1.0.0', 'supply_chain_risk', 'removed_package', 'LOW', 'removed')`); err != nil {
		t.Fatalf("insert batch rows: %v", err)
	}

	vulns, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "lodash", Version: "1.5.0"}})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "V-B1" {
		t.Fatalf("FindVulnerabilitiesBatch() = %+v, want only affected range", vulns)
	}

	malicious, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	byID := make(map[string]domain.Finding, len(malicious))
	for _, finding := range malicious {
		byID[finding.AdvisoryID] = finding
	}
	if byID["M-B1"].Type != domain.FindingTypeMalicious {
		t.Fatalf("FindMaliciousBatch() = %+v, want malicious hit", malicious)
	}
	if _, ok := byID["M-B2"]; ok {
		t.Fatalf("FindMaliciousBatch() included non-matching version row: %+v", malicious)
	}
	reputation, err := store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}}, db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindingsBatch() error = %v", err)
	}
	if len(reputation) != 1 || reputation[0].AdvisoryID != "R-B1" || reputation[0].Type != domain.FindingTypeSupplyChainRisk {
		t.Fatalf("FindReputationFindingsBatch() = %+v, want reputation hit", reputation)
	}
}

func TestBatchLookupsChunkLargePackageSets(t *testing.T) {
	store := newSQLiteTestStore(t)
	ctx := context.Background()

	const packageCount = 1200
	packages := make([]db.PackageQuery, 0, packageCount)
	for i := 0; i < packageCount; i++ {
		packages = append(packages, db.PackageQuery{
			Ecosystem: "npm",
			Name:      fmt.Sprintf("pkg-%04d", i),
			Version:   "1.0.0",
		})
	}

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
		VALUES('GHSA-large|npm|pkg-1199', 'GHSA-large', 'npm', 'pkg-1199', '[{"events":[{"introduced":"0"}]}]', 'HIGH', 'large vuln');
		INSERT INTO malicious_local(id, ecosystem, name, risk_type, severity, summary)
		VALUES('MAL-large', 'npm', 'pkg-1198', 'malware', 'CRITICAL', 'large malicious');
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES('REP-large', 'npm', 'pkg-1196', '1.0.0', 'supply_chain_risk', 'removed_package', 'LOW', 'large reputation');
		INSERT INTO lifecycle_releases_local(id, ecosystem, name, product_slug, product_label, cycle, is_eol, eol_from)
		VALUES('LIFE-large', 'npm', 'pkg-1197', 'pkg-1197', 'pkg-1197', '1.0', 1, '2025-01-01T00:00:00Z');
	`); err != nil {
		t.Fatalf("seed local db: %v", err)
	}

	vulnerabilities, err := store.FindVulnerabilitiesBatch(ctx, packages)
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(vulnerabilities) != 1 || vulnerabilities[0].AdvisoryID != "GHSA-large" {
		t.Fatalf("FindVulnerabilitiesBatch() = %+v, want GHSA-large", vulnerabilities)
	}

	malicious, err := store.FindMaliciousBatch(ctx, packages)
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	ids := map[string]bool{}
	for _, finding := range malicious {
		ids[finding.AdvisoryID] = true
	}
	if !ids["MAL-large"] || ids["REP-large"] {
		t.Fatalf("FindMaliciousBatch() = %+v, want only malicious findings", malicious)
	}

	reputation, err := store.FindReputationFindingsBatch(ctx, packages, db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindingsBatch() error = %v", err)
	}
	if len(reputation) != 1 || reputation[0].AdvisoryID != "REP-large" {
		t.Fatalf("FindReputationFindingsBatch() = %+v, want reputation finding", reputation)
	}

	lifecycle, err := store.FindLifecycleFindingsBatch(ctx, packages, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v", err)
	}
	if len(lifecycle) != 1 || lifecycle[0].AdvisoryID != "endoflife:pkg-1197:1.0:eol" {
		t.Fatalf("FindLifecycleFindingsBatch() = %+v, want lifecycle finding", lifecycle)
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
