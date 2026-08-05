package sqlite

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// closedTestDB returns a handle whose connection pool is already closed, so
// every statement issued through it fails. That is the cheapest faithful stand-in
// for a local cache file that has become unusable mid-run -- a locked, deleted or
// corrupted `~/.packmon/db/packmon.db`.
func closedTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close test database: %v", err)
	}
	return db
}

// TestMigrateSchemaPropagatesInspectionFailures makes sure a broken local cache
// surfaces as an error instead of a silently half-migrated schema. Without this,
// a failure inside migrateSchema would leave the caller believing the local
// database is ready to answer scans.
func TestMigrateSchemaPropagatesInspectionFailures(t *testing.T) {
	t.Parallel()

	err := migrateSchema(closedTestDB(t))
	if err == nil {
		t.Fatal("migrateSchema(closed database) error = nil, want a propagated failure")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Fatalf("migrateSchema() error = %v, want the underlying database failure", err)
	}
}

// TestSchemaHelpersReportFailures covers the two inspection helpers every
// migration step funnels through. They must report an error rather than
// answering "column absent", which would make a migration re-run destructive
// statements against a live table.
func TestSchemaHelpersReportFailures(t *testing.T) {
	t.Parallel()

	db := closedTestDB(t)

	if _, err := tableExists(db, "vulnerabilities_local"); err == nil {
		t.Fatal("tableExists(closed database) error = nil, want a failure")
	}
	if _, err := tableHasColumn(db, "vulnerabilities_local", "row_key"); err == nil {
		t.Fatal("tableHasColumn(closed database) error = nil, want a failure")
	}
}

// TestTableExistsReportsAbsentTable pins the non-error negative case, so a
// missing table is never confused with an inspection failure.
func TestTableExistsReportsAbsentTable(t *testing.T) {
	t.Parallel()

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	exists, err := tableExists(db, "no_such_table")
	if err != nil {
		t.Fatalf("tableExists(absent) error = %v, want nil", err)
	}
	if exists {
		t.Fatal("tableExists(absent) = true, want false")
	}
}

// TestColumnEnsurersPropagateFailures covers the individual ensure* steps. Each
// one runs independently during startup, so each has to fail loudly on its own.
func TestColumnEnsurersPropagateFailures(t *testing.T) {
	t.Parallel()

	for name, ensure := range map[string]func(*sql.DB) error{
		"vulnerability columns": ensureVulnerabilityLocalColumns,
		"malicious columns":     ensureMaliciousLocalColumns,
		"scan history schema":   ensureScanHistorySchema,
		"vulnerability row key": migrateVulnerabilityRowKeys,
		"package name casing":   normalizeExistingCaseInsensitivePackageNames,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ensure(closedTestDB(t)); err == nil {
				t.Fatalf("%s on a closed database returned nil, want a failure", name)
			}
		})
	}
}
