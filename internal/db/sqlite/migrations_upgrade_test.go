package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// openLegacyLocalDB creates a database shaped like an older Packmon CLI cache:
// the tables exist, but without the columns later releases added. This is the
// state migrateSchema has to upgrade in place on a user's machine.
func openLegacyLocalDB(t *testing.T, statements ...string) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("seed legacy schema: %v\n%s", err, statement)
		}
	}
	return db
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()

	has, err := tableHasColumn(db, table, column)
	if err != nil {
		t.Fatalf("tableHasColumn(%s, %s): %v", table, column, err)
	}
	return has
}

// legacyVulnerabilitiesTable is the pre-upgrade shape: it already has row_key
// (so the table rebuild is skipped) but none of the columns added later.
const legacyVulnerabilitiesTable = `CREATE TABLE vulnerabilities_local (
	row_key   TEXT PRIMARY KEY,
	id        TEXT NOT NULL,
	ecosystem TEXT NOT NULL,
	name      TEXT NOT NULL,
	severity  TEXT NOT NULL
)`

// TestEnsureVulnerabilityLocalColumnsUpgradesALegacyTable covers the in-place
// upgrade of an older local cache. Without it the CLI would query columns that
// do not exist and every local scan would fail on a database that merely
// predates the current release.
func TestEnsureVulnerabilityLocalColumnsUpgradesALegacyTable(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t, legacyVulnerabilitiesTable)

	for _, column := range []string{"versions_affected", "references_json", "epss_percentile", "source"} {
		if columnExists(t, db, "vulnerabilities_local", column) {
			t.Fatalf("fixture already has %s; the test would prove nothing", column)
		}
	}

	if err := ensureVulnerabilityLocalColumns(db); err != nil {
		t.Fatalf("ensureVulnerabilityLocalColumns: %v", err)
	}
	for _, column := range []string{"versions_affected", "references_json", "epss_percentile", "source"} {
		if !columnExists(t, db, "vulnerabilities_local", column) {
			t.Errorf("column %s was not added", column)
		}
	}

	// Running again on an already-upgraded database must be a no-op, because
	// migrateSchema runs on every CLI start.
	if err := ensureVulnerabilityLocalColumns(db); err != nil {
		t.Fatalf("second ensureVulnerabilityLocalColumns: %v", err)
	}
}

// TestEnsureVulnerabilityLocalColumnsDefaultsTheSourceColumn pins the default on
// the added source column. Existing rows have no source, and a NULL there would
// break the source-scoped queries the sync uses.
func TestEnsureVulnerabilityLocalColumnsDefaultsTheSourceColumn(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t, legacyVulnerabilitiesTable,
		`INSERT INTO vulnerabilities_local (row_key, id, ecosystem, name, severity)
		 VALUES ('k1', 'GHSA-1', 'npm', 'left-pad', 'HIGH')`)

	if err := ensureVulnerabilityLocalColumns(db); err != nil {
		t.Fatalf("ensureVulnerabilityLocalColumns: %v", err)
	}

	var source string
	if err := db.QueryRow(`SELECT source FROM vulnerabilities_local WHERE row_key = 'k1'`).Scan(&source); err != nil {
		t.Fatalf("read back source: %v", err)
	}
	if source != "local" {
		t.Fatalf("source = %q, want the existing row defaulted to local", source)
	}
}

// TestEnsureMaliciousLocalColumnsUpgradesALegacyTable is the same upgrade for the
// malicious table.
func TestEnsureMaliciousLocalColumnsUpgradesALegacyTable(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t, `CREATE TABLE malicious_local (
		id        TEXT PRIMARY KEY,
		ecosystem TEXT NOT NULL,
		name      TEXT NOT NULL,
		severity  TEXT NOT NULL
	)`)

	if err := ensureMaliciousLocalColumns(db); err != nil {
		t.Fatalf("ensureMaliciousLocalColumns: %v", err)
	}
	if !columnExists(t, db, "malicious_local", "source") {
		t.Error("the malicious source column was not added")
	}
	if err := ensureMaliciousLocalColumns(db); err != nil {
		t.Fatalf("second ensureMaliciousLocalColumns: %v", err)
	}
}

// TestEnsureMaliciousLocalColumnsSkipsAMissingTable covers a fresh database,
// where the table does not exist yet and the schema creation will make it.
// Treating that as an error would break first-run initialisation.
func TestEnsureMaliciousLocalColumnsSkipsAMissingTable(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t)
	if err := ensureMaliciousLocalColumns(db); err != nil {
		t.Fatalf("ensureMaliciousLocalColumns(no table) = %v, want a no-op", err)
	}
}

// TestEnsureScanHistorySchemaAddsTheCommitColumnAndIndexes covers the history
// upgrade. The commit column is a reserved word in SQL and has to stay quoted;
// the indexes back the retention and per-repo queries.
func TestEnsureScanHistorySchemaAddsTheCommitColumnAndIndexes(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t, `CREATE TABLE scan_history (
		id         INTEGER PRIMARY KEY,
		repo_name  TEXT,
		scanned_at TEXT NOT NULL
	)`)

	if err := ensureScanHistorySchema(db); err != nil {
		t.Fatalf("ensureScanHistorySchema: %v", err)
	}
	if !columnExists(t, db, "scan_history", "commit") {
		t.Error("the commit column was not added")
	}

	var indexes int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
		WHERE type = 'index' AND name LIKE 'idx_scan_history_%'`).Scan(&indexes); err != nil {
		t.Fatalf("count indexes: %v", err)
	}
	if indexes != 3 {
		t.Errorf("created %d scan-history indexes, want 3", indexes)
	}

	if err := ensureScanHistorySchema(db); err != nil {
		t.Fatalf("second ensureScanHistorySchema: %v", err)
	}
}

// TestEnsureScanHistorySchemaSkipsAMissingTable covers the fresh-database path.
func TestEnsureScanHistorySchemaSkipsAMissingTable(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t)
	if err := ensureScanHistorySchema(db); err != nil {
		t.Fatalf("ensureScanHistorySchema(no table) = %v, want a no-op", err)
	}
}

// TestNormalizeExistingVulnerabilityPackageNamesRewritesLegacyRows covers the
// case-folding backfill. PyPI and NuGet names are matched case-insensitively, so
// a row stored under its original casing by an older release would never match a
// scanned package again.
func TestNormalizeExistingVulnerabilityPackageNamesRewritesLegacyRows(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t, legacyVulnerabilitiesTable,
		`INSERT INTO vulnerabilities_local (row_key, id, ecosystem, name, severity) VALUES
			('legacy-1', 'GHSA-1', 'PyPI', 'Django', 'HIGH'),
			('legacy-2', 'GHSA-2', 'npm', 'Left-Pad', 'HIGH')`)

	if err := normalizeExistingVulnerabilityPackageNames(db); err != nil {
		t.Fatalf("normalizeExistingVulnerabilityPackageNames: %v", err)
	}

	var pypiName string
	if err := db.QueryRow(`SELECT name FROM vulnerabilities_local WHERE id = 'GHSA-1'`).Scan(&pypiName); err != nil {
		t.Fatalf("read back the PyPI row: %v", err)
	}
	if pypiName != normalizePackageName("PyPI", "Django") {
		t.Errorf("PyPI name = %q, want it normalised", pypiName)
	}

	// npm is case-sensitive and must be left exactly as it was.
	var npmName string
	if err := db.QueryRow(`SELECT name FROM vulnerabilities_local WHERE id = 'GHSA-2'`).Scan(&npmName); err != nil {
		t.Fatalf("read back the npm row: %v", err)
	}
	if npmName != "Left-Pad" {
		t.Errorf("npm name = %q, want it untouched", npmName)
	}
}

// TestNormalizeExistingVulnerabilityPackageNamesDropsDuplicateRows covers the
// collision case: if both the original and the already-normalised row exist,
// rewriting the key would violate the primary key. The stale duplicate has to go
// first, otherwise the migration fails and the CLI cannot start.
func TestNormalizeExistingVulnerabilityPackageNamesDropsDuplicateRows(t *testing.T) {
	t.Parallel()

	normalized := normalizePackageName("PyPI", "Django")
	normalizedKey := syncVulnerabilityRowKey("GHSA-1", "PyPI", normalized)

	db := openLegacyLocalDB(t, legacyVulnerabilitiesTable)
	if _, err := db.Exec(
		`INSERT INTO vulnerabilities_local (row_key, id, ecosystem, name, severity) VALUES (?, ?, ?, ?, ?)`,
		"legacy-1", "GHSA-1", "PyPI", "Django", "HIGH",
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO vulnerabilities_local (row_key, id, ecosystem, name, severity) VALUES (?, ?, ?, ?, ?)`,
		normalizedKey, "GHSA-1", "PyPI", normalized, "HIGH",
	); err != nil {
		t.Fatalf("seed normalised row: %v", err)
	}

	if err := normalizeExistingVulnerabilityPackageNames(db); err != nil {
		t.Fatalf("normalizeExistingVulnerabilityPackageNames: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities_local WHERE id = 'GHSA-1'`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("advisory GHSA-1 has %d rows, want the duplicate collapsed into one", count)
	}
}

// TestNormalizeExistingNamedRowsCoversTheSecondaryTables walks the same backfill
// for the tables keyed by id rather than row_key, and pins that a missing table
// is skipped rather than reported as an error.
func TestNormalizeExistingNamedRowsCoversTheSecondaryTables(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t, `CREATE TABLE malicious_local (
		id        TEXT PRIMARY KEY,
		ecosystem TEXT NOT NULL,
		name      TEXT NOT NULL
	)`, `INSERT INTO malicious_local (id, ecosystem, name) VALUES
			('MAL-1', 'PyPI', 'Evil_Package'),
			('MAL-2', 'npm', 'Evil-Package')`)

	if err := normalizeExistingNamedRows(db, "malicious_local"); err != nil {
		t.Fatalf("normalizeExistingNamedRows: %v", err)
	}

	var pypiName string
	if err := db.QueryRow(`SELECT name FROM malicious_local WHERE id = 'MAL-1'`).Scan(&pypiName); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if pypiName != normalizePackageName("PyPI", "Evil_Package") {
		t.Errorf("PyPI name = %q, want it normalised", pypiName)
	}

	var npmName string
	if err := db.QueryRow(`SELECT name FROM malicious_local WHERE id = 'MAL-2'`).Scan(&npmName); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if npmName != "Evil-Package" {
		t.Errorf("npm name = %q, want it untouched", npmName)
	}

	if err := normalizeExistingNamedRows(db, "reputation_findings_local"); err != nil {
		t.Fatalf("normalizeExistingNamedRows(missing table) = %v, want a no-op", err)
	}
}

// TestMigrateSchemaUpgradesALegacyDatabaseEndToEnd runs the whole sequence the
// CLI runs at startup against a legacy cache, which is the scenario a user
// upgrading Packmon actually hits.
func TestMigrateSchemaUpgradesALegacyDatabaseEndToEnd(t *testing.T) {
	t.Parallel()

	db := openLegacyLocalDB(t, legacyVulnerabilitiesTable,
		`CREATE TABLE malicious_local (
			id        TEXT PRIMARY KEY,
			ecosystem TEXT NOT NULL,
			name      TEXT NOT NULL
		)`,
		`CREATE TABLE scan_history (
			id         INTEGER PRIMARY KEY,
			repo_name  TEXT,
			scanned_at TEXT NOT NULL
		)`,
		`INSERT INTO vulnerabilities_local (row_key, id, ecosystem, name, severity)
		 VALUES ('legacy-1', 'GHSA-1', 'PyPI', 'Django', 'HIGH')`)

	if err := migrateSchema(db); err != nil {
		t.Fatalf("migrateSchema: %v", err)
	}

	for _, column := range []string{"versions_affected", "references_json", "epss_percentile", "source"} {
		if !columnExists(t, db, "vulnerabilities_local", column) {
			t.Errorf("vulnerabilities_local.%s missing after the upgrade", column)
		}
	}
	if !columnExists(t, db, "malicious_local", "source") {
		t.Error("malicious_local.source missing after the upgrade")
	}
	if !columnExists(t, db, "scan_history", "commit") {
		t.Error("scan_history.commit missing after the upgrade")
	}

	var name string
	if err := db.QueryRow(`SELECT name FROM vulnerabilities_local WHERE id = 'GHSA-1'`).Scan(&name); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if name != normalizePackageName("PyPI", "Django") {
		t.Errorf("name = %q, want the backfill applied", name)
	}

	// The upgrade must be idempotent -- it runs on every CLI start.
	if err := migrateSchema(db); err != nil {
		t.Fatalf("second migrateSchema: %v", err)
	}
}
