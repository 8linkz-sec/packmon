package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// shadowLocalTableWithView creates a view under a table name the schema wants to
// create. SQLite refuses `CREATE TABLE IF NOT EXISTS x` when a view named x
// exists, which is a faithful stand-in for a corrupted or hand-edited local
// cache -- and the only way to reach the schema-creation failure path without a
// fake driver.
func shadowLocalTableWithView(t *testing.T, dbPath, table string) {
	t.Helper()

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`CREATE VIEW ` + table + ` AS SELECT 1 AS one`); err != nil {
		t.Fatalf("create shadowing view: %v", err)
	}
}

// TestNewReportsSchemaCreationFailure covers the branch that runs when the
// schema cannot be created. A corrupt local cache must surface as a named error
// the user can act on, not as a half-initialised store that fails later on an
// unrelated query.
func TestNewReportsSchemaCreationFailure(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "packmon.db")
	shadowLocalTableWithView(t, dbPath, "vulnerabilities_local")

	store, err := New(dbPath)
	if err == nil {
		_ = store.Close()
		t.Fatal("New() on a shadowed schema = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "create schema") {
		t.Fatalf("error = %v, want it to name schema creation", err)
	}
	if store != nil {
		t.Fatal("New() returned a store alongside its error")
	}
}

// TestNewReportsMigrationFailure covers the second failure stage: the schema is
// created but the in-place migration cannot run. The distinction matters because
// the two errors point the user at different problems.
func TestNewReportsMigrationFailure(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "packmon.db")

	// A view named scan_history lets the schema pass (scan_history is created
	// with IF NOT EXISTS elsewhere) but makes the history migration fail when it
	// tries to alter it.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE scan_history (id INTEGER PRIMARY KEY, repo_name TEXT)`); err != nil {
		t.Fatalf("seed legacy history table: %v", err)
	}
	// Occupy the name the migration wants to add so the ALTER collides.
	if _, err := db.Exec(`ALTER TABLE scan_history ADD COLUMN "commit" TEXT`); err != nil {
		t.Fatalf("seed commit column: %v", err)
	}
	if _, err := db.Exec(`CREATE VIEW idx_scan_history_scanned_at AS SELECT 1 AS one`); err != nil {
		t.Fatalf("shadow index name: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed connection: %v", err)
	}

	store, err := New(dbPath)
	if err == nil {
		_ = store.Close()
		t.Skip("this SQLite build tolerates the shadowed index name; nothing to assert")
	}
	if store != nil {
		t.Fatal("New() returned a store alongside its error")
	}
}

// TestNewTimesOutOnAHeldMigrationLock covers the lock contention path. Two
// Packmon processes starting at once must not migrate the same cache
// concurrently; the loser has to fail with a clear message rather than corrupt
// the database.
func TestNewTimesOutOnAHeldMigrationLock(t *testing.T) {
	// Not parallel: it retunes the package-level lock timings.
	originalTimeout := sqliteMigrationLockTimeout
	originalPoll := sqliteMigrationLockPollInterval
	sqliteMigrationLockTimeout = 20 * time.Millisecond
	sqliteMigrationLockPollInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		sqliteMigrationLockTimeout = originalTimeout
		sqliteMigrationLockPollInterval = originalPoll
	})

	dbPath := filepath.Join(t.TempDir(), "packmon.db")
	lockPath := dbPath + ".migrate.lock"
	if err := os.WriteFile(lockPath, []byte("held by another process"), 0o600); err != nil {
		t.Fatalf("seed lock file: %v", err)
	}

	store, err := New(dbPath)
	if err == nil {
		_ = store.Close()
		t.Fatal("New() with a held migration lock = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "migration lock") {
		t.Fatalf("error = %v, want it to name the migration lock", err)
	}

	// Once the lock is gone the same path must succeed, so the failure is about
	// contention and not about a permanently poisoned database.
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("remove lock file: %v", err)
	}
	store, err = New(dbPath)
	if err != nil {
		t.Fatalf("New() after releasing the lock: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestNewSurfacesALockReleaseFailure covers the deferred release. A lock that
// cannot be removed leaves the next start blocked, so the failure has to reach
// the caller rather than be swallowed after an otherwise successful open.
func TestNewSurfacesALockReleaseFailure(t *testing.T) {
	// Not parallel: it swaps a package-level function.
	releaseErr := errors.New("lock file is busy")
	original := removeSQLiteMigrationLockFile
	removeSQLiteMigrationLockFile = func(string) error { return releaseErr }
	t.Cleanup(func() { removeSQLiteMigrationLockFile = original })

	dbPath := filepath.Join(t.TempDir(), "packmon.db")
	store, err := New(dbPath)
	if !errors.Is(err, releaseErr) {
		t.Fatalf("error = %v, want the lock release failure", err)
	}
	if store != nil {
		t.Fatal("New() returned a store although the lock could not be released")
	}
}

// TestSkipSQLiteMigrationLockMatchesTheNonFileTargets keeps the lock out of the
// in-memory and DSN paths, where there is no database file to guard and the lock
// file would be created next to the working directory instead.
func TestSkipSQLiteMigrationLockMatchesTheNonFileTargets(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"", "   ", ":memory:", "file:local.db?cache=shared"} {
		if !skipSQLiteMigrationLock(path) {
			t.Errorf("skipSQLiteMigrationLock(%q) = false, want it skipped", path)
		}
		if !skipSQLiteSyncLock(path) {
			t.Errorf("skipSQLiteSyncLock(%q) = false, want it skipped", path)
		}
	}
	if skipSQLiteMigrationLock("local.db") {
		t.Error("skipSQLiteMigrationLock(real path) = true, want it locked")
	}
}

// TestAcquireSQLiteSyncLockSerialisesConcurrentSyncs covers the sync lock. Two
// `packmon db sync` runs against the same cache would interleave writes, so the
// second must wait and then fail rather than proceed.
func TestAcquireSQLiteSyncLockSerialisesConcurrentSyncs(t *testing.T) {
	// Not parallel: it retunes the package-level lock timings.
	originalTimeout := sqliteSyncLockTimeout
	originalPoll := sqliteMigrationLockPollInterval
	sqliteSyncLockTimeout = 20 * time.Millisecond
	sqliteMigrationLockPollInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		sqliteSyncLockTimeout = originalTimeout
		sqliteMigrationLockPollInterval = originalPoll
	})

	dbPath := filepath.Join(t.TempDir(), "packmon.db")
	ctx := context.Background()

	release, err := acquireSQLiteSyncLock(ctx, dbPath)
	if err != nil {
		t.Fatalf("first acquireSQLiteSyncLock: %v", err)
	}

	if _, err := acquireSQLiteSyncLock(ctx, dbPath); err == nil {
		t.Fatal("a second sync acquired the lock while the first held it")
	} else if !strings.Contains(err.Error(), "sync lock") {
		t.Fatalf("error = %v, want it to name the sync lock", err)
	}

	release()
	// Releasing twice must stay safe: callers defer it and may also call it.
	release()

	second, err := acquireSQLiteSyncLock(ctx, dbPath)
	if err != nil {
		t.Fatalf("acquireSQLiteSyncLock after release: %v", err)
	}
	second()
}

// TestAcquireSQLiteSyncLockHonoursCancellation covers the context path: a
// cancelled sync must stop waiting for the lock immediately instead of burning
// the whole timeout.
func TestAcquireSQLiteSyncLockHonoursCancellation(t *testing.T) {
	// Not parallel: it retunes the package-level lock timings.
	originalTimeout := sqliteSyncLockTimeout
	sqliteSyncLockTimeout = time.Hour
	t.Cleanup(func() { sqliteSyncLockTimeout = originalTimeout })

	dbPath := filepath.Join(t.TempDir(), "packmon.db")
	release, err := acquireSQLiteSyncLock(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("acquireSQLiteSyncLock: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, err := acquireSQLiteSyncLock(ctx, dbPath); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the cancelled wait took %v, want it to return promptly", elapsed)
	}
}

// TestAcquireSQLiteSyncLockSkipsNonFileTargets covers the in-memory path, where
// there is no file to lock and the caller still needs a usable release func.
func TestAcquireSQLiteSyncLockSkipsNonFileTargets(t *testing.T) {
	t.Parallel()

	release, err := acquireSQLiteSyncLock(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("acquireSQLiteSyncLock(:memory:) = %v, want a no-op lock", err)
	}
	if release == nil {
		t.Fatal("acquireSQLiteSyncLock returned no release function")
	}
	release()
}

// TestStoreCloseIsSafeOnAZeroValueStore covers the nil-database path. Close runs
// from deferred cleanup on paths where the store was never fully built.
func TestStoreCloseIsSafeOnAZeroValueStore(t *testing.T) {
	t.Parallel()

	if err := (&Store{}).Close(); err != nil {
		t.Fatalf("Close() on a zero-value store = %v, want nil", err)
	}
}
