//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

func TestSystemSettingsMigration003ContractsAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	db, ctx, cancel := openFocusedMigrationDB(t, dsn)
	defer cancel()
	defer ioutils.CloseSilently(db)

	applyEmbeddedUpThrough(t, ctx, db, 2)
	mustExecMigrationTest(t, ctx, db, `CREATE TABLE migration_003_sentinel (id integer PRIMARY KEY, value text NOT NULL)`)
	mustExecMigrationTest(t, ctx, db, `INSERT INTO migration_003_sentinel VALUES (1, 'preserve-me')`)
	applyEmbeddedMigrationForTest(t, ctx, db, 3, MigrationDirectionUp)

	t.Run("defaults_and_valid_values", func(t *testing.T) {
		mustExecMigrationTest(t, ctx, db, `TRUNCATE system_settings`)
		mustExecMigrationTest(t, ctx, db, `INSERT INTO system_settings DEFAULT VALUES`)
		var id, perMinute, burst int
		var threshold string
		var updatedAt time.Time
		if err := db.QueryRowContext(ctx, `SELECT id, block_threshold, rate_limit_per_minute, rate_limit_burst, updated_at FROM system_settings`).Scan(
			&id, &threshold, &perMinute, &burst, &updatedAt,
		); err != nil {
			t.Fatalf("read default system settings: %v", err)
		}
		if id != 1 || threshold != "CRITICAL" || perMinute != 60 || burst != 60 || updatedAt.IsZero() {
			t.Fatalf("default system settings = (%d, %q, %d, %d, %v), want (1, CRITICAL, 60, 60, nonzero)", id, threshold, perMinute, burst, updatedAt)
		}
		if updatedAt.Before(time.Now().Add(-time.Minute)) || updatedAt.After(time.Now().Add(time.Minute)) {
			t.Fatalf("default updated_at = %v, want current timestamp", updatedAt)
		}

		for _, allowed := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"} {
			mustExecMigrationTest(t, ctx, db, `TRUNCATE system_settings`)
			if _, err := db.ExecContext(ctx, `INSERT INTO system_settings (block_threshold, rate_limit_per_minute, rate_limit_burst) VALUES ($1, 1, 1)`, allowed); err != nil {
				t.Fatalf("insert allowed threshold %q with minimum limits: %v", allowed, err)
			}
		}
	})

	t.Run("invalid_singleton_threshold_limits_and_nulls_are_rejected", func(t *testing.T) {
		mustExecMigrationTest(t, ctx, db, `TRUNCATE system_settings`)
		mustExecMigrationTest(t, ctx, db, `INSERT INTO system_settings DEFAULT VALUES`)
		cases := []struct {
			name string
			sql  string
			code string
		}{
			{name: "id_other_than_one", sql: `INSERT INTO system_settings (id) VALUES (2)`, code: "23514"},
			{name: "duplicate_singleton", sql: `INSERT INTO system_settings DEFAULT VALUES`, code: "23505"},
			{name: "unknown_threshold", sql: `UPDATE system_settings SET block_threshold = 'EXTREME'`, code: "23514"},
			{name: "lowercase_threshold", sql: `UPDATE system_settings SET block_threshold = 'critical'`, code: "23514"},
			{name: "zero_per_minute", sql: `UPDATE system_settings SET rate_limit_per_minute = 0`, code: "23514"},
			{name: "negative_per_minute", sql: `UPDATE system_settings SET rate_limit_per_minute = -1`, code: "23514"},
			{name: "zero_burst", sql: `UPDATE system_settings SET rate_limit_burst = 0`, code: "23514"},
			{name: "negative_burst", sql: `UPDATE system_settings SET rate_limit_burst = -1`, code: "23514"},
			{name: "null_id", sql: `UPDATE system_settings SET id = NULL`, code: "23502"},
			{name: "null_threshold", sql: `UPDATE system_settings SET block_threshold = NULL`, code: "23502"},
			{name: "null_per_minute", sql: `UPDATE system_settings SET rate_limit_per_minute = NULL`, code: "23502"},
			{name: "null_burst", sql: `UPDATE system_settings SET rate_limit_burst = NULL`, code: "23502"},
			{name: "null_updated_at", sql: `UPDATE system_settings SET updated_at = NULL`, code: "23502"},
		}
		for _, tc := range cases {
			_, err := db.ExecContext(ctx, tc.sql)
			assertPostgresErrorCodeWithLabel(t, err, tc.code, tc.name)
		}
	})

	t.Run("044_down_precedes_populated_003_down", func(t *testing.T) {
		mustExecMigrationTest(t, ctx, db, `TRUNCATE system_settings`)
		mustExecMigrationTest(t, ctx, db, `INSERT INTO system_settings (block_threshold, rate_limit_per_minute, rate_limit_burst) VALUES ('HIGH', 17, 23)`)
		applyEmbeddedMigrationForTest(t, ctx, db, 44, MigrationDirectionUp)
		mustExecMigrationTest(t, ctx, db, `UPDATE system_settings SET scan_log_retention_seconds = 7, admin_audit_retention_seconds = 11`)
		applyEmbeddedMigrationForTest(t, ctx, db, 44, MigrationDirectionDown)
		assertColumnExists(t, ctx, db, "system_settings", "scan_log_retention_seconds", false)
		assertColumnExists(t, ctx, db, "system_settings", "admin_audit_retention_seconds", false)
		var threshold string
		var perMinute, burst int
		if err := db.QueryRowContext(ctx, `SELECT block_threshold, rate_limit_per_minute, rate_limit_burst FROM system_settings`).Scan(&threshold, &perMinute, &burst); err != nil {
			t.Fatalf("read settings after 044 down: %v", err)
		}
		if threshold != "HIGH" || perMinute != 17 || burst != 23 {
			t.Fatalf("base settings after 044 down = (%q, %d, %d), want (HIGH, 17, 23)", threshold, perMinute, burst)
		}
		applyEmbeddedMigrationForTest(t, ctx, db, 3, MigrationDirectionDown)
		assertRelationExists(t, ctx, db, "system_settings", false)
		assertSentinelPreserved(t, ctx, db, "migration_003_sentinel")
	})

	t.Run("down_is_repeatable_and_up_recreates_an_empty_table", func(t *testing.T) {
		applyEmbeddedMigrationForTest(t, ctx, db, 3, MigrationDirectionDown)
		assertRelationExists(t, ctx, db, "system_settings", false)
		assertSentinelPreserved(t, ctx, db, "migration_003_sentinel")
		applyEmbeddedMigrationForTest(t, ctx, db, 3, MigrationDirectionUp)
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_settings`).Scan(&count); err != nil {
			t.Fatalf("count recreated system settings: %v", err)
		}
		if count != 0 {
			t.Fatalf("recreated system_settings row count = %d, want 0", count)
		}
	})

	t.Run("failed_down_rolls_back_and_records_dirty_metadata", func(t *testing.T) {
		mustExecMigrationTest(t, ctx, db, `INSERT INTO system_settings (block_threshold, rate_limit_per_minute, rate_limit_burst) VALUES ('LOW', 9, 10)`)
		down := embeddedMigrationFileForTest(t, 3, MigrationDirectionDown)
		failed := migrationFile{
			version:   903,
			name:      "903_system_settings_injected_failure.down.sql",
			direction: MigrationDirectionDown,
			sql:       down.sql + "\nSELECT * FROM packmon_injected_missing_relation;",
		}
		if err := applyMigration(ctx, db, failed); err == nil || !strings.Contains(err.Error(), "packmon_injected_missing_relation") {
			t.Fatalf("apply injected 003 down error = %v, want missing-relation failure", err)
		}
		assertRelationExists(t, ctx, db, "system_settings", true)
		var threshold string
		if err := db.QueryRowContext(ctx, `SELECT block_threshold FROM system_settings`).Scan(&threshold); err != nil {
			t.Fatalf("read row after failed 003 down: %v", err)
		}
		if threshold != "LOW" {
			t.Fatalf("threshold after failed 003 down = %q, want LOW", threshold)
		}
		assertDirtyMigration(t, ctx, db, failed)
	})
}

func openFocusedMigrationDB(t *testing.T, dsn string) (*sql.DB, context.Context, context.CancelFunc) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	if err := db.PingContext(ctx); err != nil {
		cancel()
		ioutils.CloseSilently(db)
		t.Fatalf("ping focused migration database: %v", err)
	}
	if err := ensureVersionTable(ctx, db); err != nil {
		cancel()
		ioutils.CloseSilently(db)
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	return db, ctx, cancel
}

func applyEmbeddedUpThrough(t *testing.T, ctx context.Context, db *sql.DB, last int) {
	t.Helper()
	applyEmbeddedMigrationsRangeForTest(t, ctx, db, 1, last)
}

func embeddedMigrationFileForTest(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("read migration %03d %s: %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func mustExecMigrationTest(t *testing.T, ctx context.Context, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, statement, args...); err != nil {
		t.Fatalf("execute migration test statement: %v\nSQL:\n%s", err, statement)
	}
}

func assertPostgresErrorCode(t *testing.T, err error, want string) {
	t.Helper()
	expectSQLState(t, want, err)
}

func assertPostgresErrorCodeWithLabel(t *testing.T, err error, want, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s PostgreSQL error = nil, want SQLSTATE %s", label, want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != want {
		t.Fatalf("%s PostgreSQL error = %v, want SQLSTATE %s", label, err, want)
	}
}

func assertRelationExists(t *testing.T, ctx context.Context, db *sql.DB, relation string, want bool) {
	t.Helper()
	var got bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, relation).Scan(&got); err != nil {
		t.Fatalf("inspect relation %s: %v", relation, err)
	}
	if got != want {
		t.Fatalf("relation %s exists = %t, want %t", relation, got, want)
	}
}

func assertColumnExists(t *testing.T, ctx context.Context, db *sql.DB, table, column string, want bool) {
	t.Helper()
	var got bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
		)`, table, column).Scan(&got); err != nil {
		t.Fatalf("inspect column %s.%s: %v", table, column, err)
	}
	if got != want {
		t.Fatalf("column %s.%s exists = %t, want %t", table, column, got, want)
	}
}

func assertSentinelPreserved(t *testing.T, ctx context.Context, db *sql.DB, table string) {
	t.Helper()
	var value string
	query := fmt.Sprintf(`SELECT value FROM %s WHERE id = 1`, table)
	if err := db.QueryRowContext(ctx, query).Scan(&value); err != nil {
		t.Fatalf("read sentinel %s: %v", table, err)
	}
	if value != "preserve-me" {
		t.Fatalf("sentinel %s value = %q, want preserve-me", table, value)
	}
}
