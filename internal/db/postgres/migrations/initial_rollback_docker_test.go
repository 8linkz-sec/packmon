//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"testing"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

// TestInitialMigrationRollsBackInIsolationAgainstPostgres applies only the
// baseline schema and then its down migration. The baseline creates foreign keys
// between its own tables (scan_log.api_key_id -> api_keys), so the down file has
// to drop referencing tables first; afterwards no baseline table or helper
// function may remain, and the baseline must apply cleanly again.
func TestInitialMigrationRollsBackInIsolationAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgresInstance(t, false).dsn

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)

	ctx := context.Background()
	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	apply := func(direction MigrationDirection) {
		t.Helper()
		migration, err := ReadEmbeddedMigration(1, direction)
		if err != nil {
			t.Fatalf("read migration 001 %s: %v", direction, err)
		}
		if err := applyMigration(ctx, db, migrationFile{
			version:   migration.Version,
			name:      migration.Name,
			direction: migration.Direction,
			sql:       migration.SQL,
		}); err != nil {
			t.Fatalf("apply migration 001 %s: %v", direction, err)
		}
	}

	apply(MigrationDirectionUp)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO api_keys (name, key_hash) VALUES ('rollback-fixture', 'sha256:rollback-fixture');
		INSERT INTO scan_log (scan_id, packages_count, findings_count, duration_ms, api_key_id)
		SELECT 'rollback-scan', 1, 0, 1, id FROM api_keys WHERE name = 'rollback-fixture';`); err != nil {
		t.Fatalf("seed scan_log row that references api_keys: %v", err)
	}

	apply(MigrationDirectionDown)

	var leftoverTables []string
	rows, err := db.QueryContext(ctx, `
		SELECT tablename
		FROM pg_tables
		WHERE schemaname = 'public'
		  AND tablename NOT IN ('schema_migrations', 'schema_migration_events')
		ORDER BY tablename`)
	if err != nil {
		t.Fatalf("list tables after rollback: %v", err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		leftoverTables = append(leftoverTables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate tables: %v", err)
	}
	ioutils.CloseSilently(rows)
	if len(leftoverTables) != 0 {
		t.Fatalf("tables left after 001 down = %v, want none", leftoverTables)
	}

	var leftoverFunctions int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND p.proname IN ('packmon_jsonb_string_array_valid', 'packmon_jsonb_version_ranges_valid')`).Scan(&leftoverFunctions); err != nil {
		t.Fatalf("count helper functions after rollback: %v", err)
	}
	if leftoverFunctions != 0 {
		t.Fatalf("baseline helper functions left after 001 down = %d, want 0", leftoverFunctions)
	}

	apply(MigrationDirectionUp)
}
