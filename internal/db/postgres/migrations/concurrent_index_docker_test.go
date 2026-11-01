//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

// createInvalidIndex leaves an INVALID index named name behind the way an
// interrupted concurrent build does: a concurrent unique build over duplicate
// rows fails after the catalog entry is committed. The index sits on a scratch
// table, so a rebuild that lands on the migration's own table is observable.
func createInvalidIndex(t *testing.T, ctx context.Context, db *sql.DB, name string) {
	t.Helper()

	seed := "invalid_index_seed_" + name
	for _, statement := range []string{
		`CREATE TABLE ` + seed + ` (v integer)`,
		`INSERT INTO ` + seed + ` (v) VALUES (1), (1)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("seed invalid index %s (%s): %v", name, statement, err)
		}
	}
	if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX CONCURRENTLY `+name+` ON `+seed+` (v)`); err == nil {
		t.Fatalf("concurrent unique build of %s over duplicate rows succeeded, want a failed build", name)
	}
	if state := catalogIndexState(t, ctx, db, name); state != indexInvalid {
		t.Fatalf("index %s state after failed concurrent build = %s, want INVALID", name, state)
	}
}

func catalogIndexState(t *testing.T, ctx context.Context, db *sql.DB, name string) indexState {
	t.Helper()
	state, err := (catalogStatementConn{db: db}).indexState(ctx, name)
	if err != nil {
		t.Fatalf("read index state %s: %v", name, err)
	}
	return state
}

func assertValidIndexOnTable(t *testing.T, ctx context.Context, db *sql.DB, name, table string) {
	t.Helper()
	if state := catalogIndexState(t, ctx, db, name); state != indexValid {
		t.Fatalf("index %s state = %s, want valid", name, state)
	}
	var got string
	if err := db.QueryRowContext(ctx, `
		SELECT indrelid::regclass::text
		FROM pg_index
		WHERE indexrelid = to_regclass($1::text)`, name).Scan(&got); err != nil {
		t.Fatalf("read table of index %s: %v", name, err)
	}
	if got != table {
		t.Fatalf("index %s is on table %s, want %s", name, got, table)
	}
}

func applyEmbeddedMigrationsBefore(t *testing.T, dsn string, version int) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations() error = %v", err)
	}
	for _, migration := range migrations {
		if migration.version >= version {
			continue
		}
		if err := applyMigration(ctx, db, migration); err != nil {
			t.Fatalf("apply migration %s: %v", migration.name, err)
		}
	}
}

// TestRunRebuildsInvalidConcurrentIndexesOfAppliedMigrations covers a database
// that is already clean at the latest version but kept an INVALID index from
// an interrupted concurrent build: migrate rebuilds it on the migration's own
// table, for 049 and for older concurrent index migrations alike.
func TestRunRebuildsInvalidConcurrentIndexesOfAppliedMigrations(t *testing.T) {
	dsn := startMigrationPostgres(t)
	if err := Run(dsn); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx := context.Background()

	for _, name := range []string{"idx_malicious_active_search_order", "idx_malicious_findings_name_trgm"} {
		if _, err := db.ExecContext(ctx, `DROP INDEX CONCURRENTLY `+name); err != nil {
			t.Fatalf("drop %s: %v", name, err)
		}
		createInvalidIndex(t, ctx, db, name)
	}

	if err := Run(dsn); err != nil {
		t.Fatalf("Run() with INVALID indexes error = %v", err)
	}
	assertValidIndexOnTable(t, ctx, db, "idx_malicious_active_search_order", "malicious_findings")
	assertValidIndexOnTable(t, ctx, db, "idx_malicious_findings_name_trgm", "malicious_findings")
	assertMaliciousActiveSearchIndexes(t, ctx, db, true)

	version, dirty, err := Version(dsn)
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if version != ExpectedVersion || dirty {
		t.Fatalf("Version() = %d dirty=%v, want %d clean", version, dirty, ExpectedVersion)
	}
}

// TestInterruptedConcurrentIndexMigrationRetriesAfterClearingDirtyMarker walks
// the documented recovery path for an interrupted 049: the dirty database is
// refused with the retry instructions, and once the dirty marker is cleared the
// retried migration replaces the INVALID index instead of keeping it because of
// IF NOT EXISTS.
func TestInterruptedConcurrentIndexMigrationRetriesAfterClearingDirtyMarker(t *testing.T) {
	dsn := startMigrationPostgres(t)
	applyEmbeddedMigrationsBefore(t, dsn, 49)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx := context.Background()

	migration049, err := ReadEmbeddedMigration(49, MigrationDirectionUp)
	if err != nil {
		t.Fatalf("read migration 49: %v", err)
	}
	statements, err := splitSQLStatements(migration049.SQL)
	if err != nil {
		t.Fatalf("split migration 49: %v", err)
	}
	// The interrupted run finished the first build and left the second INVALID.
	if _, err := db.ExecContext(ctx, statements[0]); err != nil {
		t.Fatalf("apply first 049 statement: %v", err)
	}
	createInvalidIndex(t, ctx, db, "idx_malicious_active_severity_search")
	if err := markDirtyWithChecksum(ctx, db, 49, migration049.Name, migrationChecksum(migration049.SQL)); err != nil {
		t.Fatalf("mark 049 dirty: %v", err)
	}

	err = Run(dsn)
	if err == nil || !strings.Contains(err.Error(), "dirty at version 49") || !strings.Contains(err.Error(), "safe to retry") {
		t.Fatalf("Run(dirty 49) error = %v, want dirty error with retry instructions", err)
	}
	if state := catalogIndexState(t, ctx, db, "idx_malicious_active_severity_search"); state != indexInvalid {
		t.Fatalf("dirty run changed the INVALID index: state = %s", state)
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = 49 AND dirty`); err != nil {
		t.Fatalf("clear 049 dirty marker: %v", err)
	}
	if err := Run(dsn); err != nil {
		t.Fatalf("Run() retry error = %v", err)
	}
	assertValidIndexOnTable(t, ctx, db, "idx_malicious_active_search_order", "malicious_findings")
	assertValidIndexOnTable(t, ctx, db, "idx_malicious_active_severity_search", "malicious_findings")

	version, dirty, err := Version(dsn)
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if version != ExpectedVersion || dirty {
		t.Fatalf("Version() = %d dirty=%v, want %d clean", version, dirty, ExpectedVersion)
	}
	var succeeded int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM schema_migration_events
		WHERE version = 49 AND success AND NOT dirty`).Scan(&succeeded); err != nil {
		t.Fatalf("count 049 success events: %v", err)
	}
	if succeeded != 1 {
		t.Fatalf("049 success events = %d, want 1", succeeded)
	}
}

// TestConcurrentIndexMigrationFailsWhenBuildLeavesNoValidIndex covers the
// post-build check: IF NOT EXISTS skips the build when a non-index relation
// already holds the name, and the migration must fail dirty instead of
// recording a schema without the index.
func TestConcurrentIndexMigrationFailsWhenBuildLeavesNoValidIndex(t *testing.T) {
	dsn := startMigrationPostgres(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	for _, statement := range []string{
		`CREATE TABLE concurrent_index_target (v integer)`,
		`CREATE TABLE idx_concurrent_index_conflict (v integer)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("prepare name conflict (%s): %v", statement, err)
		}
	}

	err = applyMigration(ctx, db, migrationFile{
		version: 77,
		name:    "077_conflicting_index.up.sql",
		sql: `-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_concurrent_index_conflict ON concurrent_index_target (v);`,
	})
	if err == nil || !strings.Contains(err.Error(), "index idx_concurrent_index_conflict is missing or not an index") {
		t.Fatalf("applyMigration() error = %v, want post-build index check failure", err)
	}
	version, dirty, ok, err := currentVersion(ctx, db)
	if err != nil {
		t.Fatalf("currentVersion() error = %v", err)
	}
	if !ok || version != 77 || !dirty {
		t.Fatalf("currentVersion() = %d dirty=%v ok=%v, want 77 dirty", version, dirty, ok)
	}
}
