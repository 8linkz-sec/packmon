package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

// The fault-injecting driver below exists for one specific class of branch that
// no amount of state manipulation can reach: the per-statement error arms inside
// the schema-migration helpers. Closing the database fails the *first*
// statement, so every later one stays unreachable; dropping a table changes what
// the statements do rather than making one of them fail. Only a driver that can
// fail the n-th matching statement gets there.
//
// It is deliberately minimal: it wraps the real driver and fails a statement
// whose SQL contains a configured substring, after a configured number of
// successes. Everything else is delegated.

var errInjectedFault = errors.New("injected driver fault")

type faultRule struct {
	mu       sync.Mutex
	contains string
	skip     int
	fired    bool
}

// shouldFail reports whether this statement is the one to fail, consuming one
// skip if it matches but is not yet due.
func (r *faultRule) shouldFail(query string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.contains == "" || !strings.Contains(strings.ToUpper(query), strings.ToUpper(r.contains)) {
		return false
	}
	if r.skip > 0 {
		r.skip--
		return false
	}
	r.fired = true
	return true
}

func (r *faultRule) didFire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fired
}

type faultDriver struct {
	inner driver.Driver
	rule  *faultRule
}

func (d *faultDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &faultConn{Conn: conn, rule: d.rule}, nil
}

type faultConn struct {
	driver.Conn
	rule *faultRule
}

func (c *faultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.rule.shouldFail(query) {
		return nil, fmt.Errorf("%w on %q", errInjectedFault, query)
	}
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (c *faultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.rule.shouldFail(query) {
		return nil, fmt.Errorf("%w on %q", errInjectedFault, query)
	}
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return queryer.QueryContext(ctx, query, args)
}

var (
	faultDriverOnce sync.Once
	realDriverName  = "sqlite"
	faultDriverSeq  int
	faultDriverMu   sync.Mutex
)

// openFaultyDB opens a real SQLite database through the fault-injecting driver.
// The returned rule reports afterwards whether the fault actually fired, so a
// test cannot silently pass because its match string was wrong.
func openFaultyDB(t *testing.T, contains string, skip int) (*sql.DB, *faultRule) {
	t.Helper()

	var inner driver.Driver
	faultDriverOnce.Do(func() {
		probe, err := sql.Open(realDriverName, ":memory:")
		if err != nil {
			t.Fatalf("open probe connection: %v", err)
		}
		inner = probe.Driver()
		_ = probe.Close()
	})
	if inner == nil {
		probe, err := sql.Open(realDriverName, ":memory:")
		if err != nil {
			t.Fatalf("open probe connection: %v", err)
		}
		inner = probe.Driver()
		_ = probe.Close()
	}

	rule := &faultRule{contains: contains, skip: skip}

	faultDriverMu.Lock()
	faultDriverSeq++
	name := fmt.Sprintf("sqlite-fault-%d", faultDriverSeq)
	faultDriverMu.Unlock()
	sql.Register(name, &faultDriver{inner: inner, rule: rule})

	db, err := sql.Open(name, filepath.Join(t.TempDir(), "faulty.db"))
	if err != nil {
		t.Fatalf("open faulty database: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db, rule
}

// seedLegacySchemaOn creates the pre-upgrade tables on an already-open database,
// so a migration helper has something to alter.
func seedLegacySchemaOn(t *testing.T, db *sql.DB, statements ...string) {
	t.Helper()

	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("seed schema: %v\n%s", err, statement)
		}
	}
}

// TestEnsureVulnerabilityLocalColumnsReportsEachColumnFailure covers the
// per-column error arms. The helper adds four columns in sequence; a failure on
// any one of them must abort the migration and name the column, because a
// partially migrated cache would then be queried for a column that does not
// exist.
func TestEnsureVulnerabilityLocalColumnsReportsEachColumnFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		skip    int
		wantFor string
	}{
		{name: "versions_affected", skip: 0, wantFor: "versions_affected"},
		{name: "references_json", skip: 1, wantFor: "references_json"},
		{name: "epss_percentile", skip: 2, wantFor: "epss_percentile"},
		{name: "source", skip: 3, wantFor: "source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, rule := openFaultyDB(t, "ALTER TABLE vulnerabilities_local ADD COLUMN", tc.skip)
			seedLegacySchemaOn(t, db, legacyVulnerabilitiesTable)

			err := ensureVulnerabilityLocalColumns(db)
			if err == nil {
				t.Fatalf("the migration succeeded although the %s column failed", tc.wantFor)
			}
			if !rule.didFire() {
				t.Fatal("the injected fault never fired; the match string is wrong")
			}
			if !errors.Is(err, errInjectedFault) {
				t.Fatalf("error = %v, want the injected fault wrapped", err)
			}
			if !strings.Contains(err.Error(), tc.wantFor) {
				t.Errorf("error = %v, want it to name the %s column", err, tc.wantFor)
			}
		})
	}
}

// TestEnsureVulnerabilityLocalColumnsReportsAnInspectionFailure covers the other
// arm in the same helper: the column probe itself failing. Treating that as
// "column missing" would issue an ALTER for a column that already exists.
func TestEnsureVulnerabilityLocalColumnsReportsAnInspectionFailure(t *testing.T) {
	db, rule := openFaultyDB(t, "PRAGMA table_info", 0)
	seedLegacySchemaOn(t, db, legacyVulnerabilitiesTable)

	err := ensureVulnerabilityLocalColumns(db)
	if err == nil {
		t.Fatal("the migration succeeded although the column probe failed")
	}
	if !rule.didFire() {
		t.Fatal("the injected fault never fired")
	}
	if !errors.Is(err, errInjectedFault) {
		t.Fatalf("error = %v, want the injected fault wrapped", err)
	}
}

// TestEnsureMaliciousLocalColumnsReportsEachColumnFailure is the same guarantee
// for the malicious table, which adds three columns in sequence.
func TestEnsureMaliciousLocalColumnsReportsEachColumnFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		skip int
	}{
		{name: "reference_urls", skip: 0},
		{name: "version_ranges", skip: 1},
		{name: "source", skip: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, rule := openFaultyDB(t, "ALTER TABLE malicious_local ADD COLUMN", tc.skip)
			seedLegacySchemaOn(t, db, `CREATE TABLE malicious_local (
				id        TEXT PRIMARY KEY,
				ecosystem TEXT NOT NULL,
				name      TEXT NOT NULL
			)`)

			err := ensureMaliciousLocalColumns(db)
			if err == nil {
				t.Fatalf("the migration succeeded although the %s column failed", tc.name)
			}
			if !rule.didFire() {
				t.Fatal("the injected fault never fired; the match string is wrong")
			}
			if !errors.Is(err, errInjectedFault) {
				t.Fatalf("error = %v, want the injected fault wrapped", err)
			}
			if !strings.Contains(err.Error(), tc.name) {
				t.Errorf("error = %v, want it to name the %s column", err, tc.name)
			}
		})
	}
}

// TestEnsureScanHistorySchemaReportsAFailedIndex covers the index creation that
// follows the column migration. The indexes back the retention query, so a
// silently skipped index turns into a full table scan on every scan.
func TestEnsureScanHistorySchemaReportsAFailedIndex(t *testing.T) {
	db, rule := openFaultyDB(t, "CREATE INDEX IF NOT EXISTS idx_scan_history", 0)
	seedLegacySchemaOn(t, db, `CREATE TABLE scan_history (
		id         INTEGER PRIMARY KEY,
		repo_name  TEXT,
		scanned_at TEXT NOT NULL,
		"commit"   TEXT
	)`)

	err := ensureScanHistorySchema(db)
	if err == nil {
		t.Fatal("the migration succeeded although an index failed")
	}
	if !rule.didFire() {
		t.Fatal("the injected fault never fired")
	}
	if !strings.Contains(err.Error(), "index") {
		t.Errorf("error = %v, want it to name the index", err)
	}
}

// TestNormalizeExistingVulnerabilityPackageNamesReportsAFailedRewrite covers the
// backfill's write arm. A failure there must abort rather than leave half the
// rows normalised, because the un-normalised half would stop matching scans.
func TestNormalizeExistingVulnerabilityPackageNamesReportsAFailedRewrite(t *testing.T) {
	db, rule := openFaultyDB(t, "UPDATE vulnerabilities_local SET row_key", 0)
	seedLegacySchemaOn(t, db, legacyVulnerabilitiesTable,
		`INSERT INTO vulnerabilities_local (row_key, id, ecosystem, name, severity)
		 VALUES ('legacy-1', 'GHSA-1', 'PyPI', 'Django', 'HIGH')`)

	err := normalizeExistingVulnerabilityPackageNames(db)
	if err == nil {
		t.Fatal("the backfill succeeded although the rewrite failed")
	}
	if !rule.didFire() {
		t.Fatal("the injected fault never fired")
	}
	if !errors.Is(err, errInjectedFault) {
		t.Fatalf("error = %v, want the injected fault wrapped", err)
	}
}

// TestNormalizeExistingNamedRowsReportsAFailedRewrite is the same for the tables
// keyed by id rather than row_key.
func TestNormalizeExistingNamedRowsReportsAFailedRewrite(t *testing.T) {
	db, rule := openFaultyDB(t, "UPDATE malicious_local SET name", 0)
	seedLegacySchemaOn(t, db, `CREATE TABLE malicious_local (
		id        TEXT PRIMARY KEY,
		ecosystem TEXT NOT NULL,
		name      TEXT NOT NULL
	)`, `INSERT INTO malicious_local (id, ecosystem, name)
		 VALUES ('MAL-1', 'PyPI', 'Evil_Package')`)

	err := normalizeExistingNamedRows(db, "malicious_local")
	if err == nil {
		t.Fatal("the backfill succeeded although the rewrite failed")
	}
	if !rule.didFire() {
		t.Fatal("the injected fault never fired")
	}
}

// TestMigrateSchemaStopsAtTheFirstFailure covers the sequencing in the top-level
// migration. Later steps must not run after an earlier one failed, or they would
// operate on a schema that is not in the state they expect.
func TestMigrateSchemaStopsAtTheFirstFailure(t *testing.T) {
	db, rule := openFaultyDB(t, "ALTER TABLE vulnerabilities_local ADD COLUMN", 0)
	seedLegacySchemaOn(t, db, legacyVulnerabilitiesTable, `CREATE TABLE malicious_local (
		id        TEXT PRIMARY KEY,
		ecosystem TEXT NOT NULL,
		name      TEXT NOT NULL
	)`)

	if err := migrateSchema(db); err == nil {
		t.Fatal("migrateSchema succeeded although a column migration failed")
	}
	if !rule.didFire() {
		t.Fatal("the injected fault never fired")
	}

	// The later step must not have run: malicious_local still has no source
	// column.
	has, err := tableHasColumn(db, "malicious_local", "source")
	if err != nil {
		t.Fatalf("tableHasColumn: %v", err)
	}
	if has {
		t.Fatal("a later migration step ran after an earlier one failed")
	}
}

// TestFaultDriverStaysOutOfTheWayWhenItDoesNotMatch is the control for the
// harness itself: with a match string that never fires, the migration must
// succeed exactly as it does on the real driver. Without this, a test could pass
// because the fault silently broke something unrelated.
func TestFaultDriverStaysOutOfTheWayWhenItDoesNotMatch(t *testing.T) {
	db, rule := openFaultyDB(t, "ALTER TABLE a_table_that_does_not_exist", 0)
	seedLegacySchemaOn(t, db, legacyVulnerabilitiesTable)

	if err := ensureVulnerabilityLocalColumns(db); err != nil {
		t.Fatalf("the migration failed with an inert fault rule: %v", err)
	}
	if rule.didFire() {
		t.Fatal("the fault fired although its match string should never occur")
	}
	for _, column := range []string{"versions_affected", "references_json", "epss_percentile", "source"} {
		has, err := tableHasColumn(db, "vulnerabilities_local", column)
		if err != nil {
			t.Fatalf("tableHasColumn(%s): %v", column, err)
		}
		if !has {
			t.Errorf("column %s was not added", column)
		}
	}
}
