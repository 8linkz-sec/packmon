//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestCancelledMigrationRecordsFailureAndReleasesLockOnPostgres cancels a
// running migration statement on a real PostgreSQL session opened the way
// RunContextWithOptions opens it, and checks that the session survives the
// cancel so the failure bookkeeping and the advisory-lock release still run.
func TestCancelledMigrationRecordsFailureAndReleasesLockOnPostgres(t *testing.T) {
	dsn := startMigrationPostgresInstance(t, false).dsn

	for _, tt := range []struct {
		name string
		sql  string
	}{
		{name: "transactional", sql: "SELECT pg_sleep(30)"},
		{name: "no-transaction", sql: "-- " + noTransactionDirective + "\nSELECT pg_sleep(30);"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db, err := openMigrationDB(dsn)
			if err != nil {
				t.Fatalf("openMigrationDB() error = %v", err)
			}
			defer ioutils.CloseSilently(db)

			conn, err := connectAndLockMigrations(context.Background(), db, 10*time.Second)
			if err != nil {
				t.Fatalf("connectAndLockMigrations() error = %v", err)
			}
			defer ioutils.CloseSilently(conn)
			if err := ensureVersionTable(context.Background(), conn); err != nil {
				t.Fatalf("ensureVersionTable() error = %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			started := time.Now()
			err = applyMigration(ctx, conn, migrationFile{version: 901, name: "901_slow.up.sql", sql: tt.sql})
			// PostgreSQL cancels the statement (SQLSTATE 57014) instead of the
			// client dropping the session.
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
				t.Fatalf("applyMigration() error = %v, want the server-side cancel (SQLSTATE 57014)", err)
			}
			if elapsed := time.Since(started); elapsed > 15*time.Second {
				t.Fatalf("cancelled migration took %s, want the server-side cancel to stop it promptly", elapsed)
			}

			var finished sql.NullTime
			var success, dirty bool
			if err := conn.QueryRowContext(context.Background(), `
				SELECT finished_at, success, dirty
				FROM schema_migration_events
				WHERE version = 901
				ORDER BY id DESC
				LIMIT 1`).Scan(&finished, &success, &dirty); err != nil {
				t.Fatalf("read failure event on the migration session: %v", err)
			}
			if !finished.Valid || success || !dirty {
				t.Fatalf("failure event finished_at=%v success=%v dirty=%v, want finished, failed, dirty", finished, success, dirty)
			}
			version, versionDirty, ok, err := currentVersion(context.Background(), conn)
			if err != nil || !ok || version != 901 || !versionDirty {
				t.Fatalf("currentVersion() = %d dirty=%v ok=%v err=%v, want 901 dirty", version, versionDirty, ok, err)
			}

			cleanupCtx, cleanupCancel := migrationCleanupContext(ctx)
			defer cleanupCancel()
			if err := releaseMigrationLock(cleanupCtx, conn); err != nil {
				t.Fatalf("releaseMigrationLock() after cancel error = %v", err)
			}

			// Reset the dirty marker so the next subtest starts clean.
			if _, err := conn.ExecContext(context.Background(), `DELETE FROM schema_migrations WHERE version = 901`); err != nil {
				t.Fatalf("reset dirty marker: %v", err)
			}
		})
	}
}
