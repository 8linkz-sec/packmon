//go:build integration

package migrations

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

func TestReversingLabsReputationMigration004ContractsAgainstPostgres(t *testing.T) {
	dsn := startMigrationPostgres(t)
	db, ctx, cancel := openFocusedMigrationDB(t, dsn)
	defer cancel()
	defer ioutils.CloseSilently(db)

	applyEmbeddedUpThrough(t, ctx, db, 4)
	mustExecMigrationTest(t, ctx, db, `CREATE TABLE migration_004_sentinel (id integer PRIMARY KEY, value text NOT NULL)`)
	mustExecMigrationTest(t, ctx, db, `INSERT INTO migration_004_sentinel VALUES (1, 'preserve-me')`)

	t.Run("defaults_nullability_status_and_coordinate_constraints", func(t *testing.T) {
		mustExecMigrationTest(t, ctx, db, `TRUNCATE package_reputation_cache RESTART IDENTITY`)
		mustExecMigrationTest(t, ctx, db, `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'defaults', '1.0.0', 'reversinglabs', 'pending')`)
		var (
			id                      int
			severity, summary, desc string
			references, evidence    string
			lastChecked, nextCheck  sql.NullTime
			lastError               string
			createdAt, updatedAt    time.Time
		)
		if err := db.QueryRowContext(ctx, `
			SELECT id, severity, summary, description, reference_urls::text, evidence::text,
			       last_checked_at, next_check_at, last_error, created_at, updated_at
			FROM package_reputation_cache WHERE name = 'defaults'`).Scan(
			&id, &severity, &summary, &desc, &references, &evidence,
			&lastChecked, &nextCheck, &lastError, &createdAt, &updatedAt,
		); err != nil {
			t.Fatalf("read reputation defaults: %v", err)
		}
		if id != 1 || severity != "CRITICAL" || summary != "" || desc != "" || references != "[]" || evidence != "{}" || lastChecked.Valid || nextCheck.Valid || lastError != "" || createdAt.IsZero() || updatedAt.IsZero() {
			t.Fatalf("reputation defaults = id=%d severity=%q summary=%q description=%q refs=%s evidence=%s last_checked=%v next_check=%v last_error=%q created=%v updated=%v",
				id, severity, summary, desc, references, evidence, lastChecked, nextCheck, lastError, createdAt, updatedAt)
		}
		type columnContract struct {
			dataType, nullable, defaultValue string
		}
		wantColumns := map[string]columnContract{
			"id":              {dataType: "integer", nullable: "NO", defaultValue: "nextval('package_reputation_cache_id_seq'::regclass)"},
			"ecosystem":       {dataType: "text", nullable: "NO"},
			"name":            {dataType: "text", nullable: "NO"},
			"version":         {dataType: "text", nullable: "NO"},
			"source":          {dataType: "text", nullable: "NO"},
			"status":          {dataType: "text", nullable: "NO"},
			"severity":        {dataType: "text", nullable: "NO", defaultValue: "'CRITICAL'::text"},
			"summary":         {dataType: "text", nullable: "NO", defaultValue: "''::text"},
			"description":     {dataType: "text", nullable: "NO", defaultValue: "''::text"},
			"reference_urls":  {dataType: "jsonb", nullable: "NO", defaultValue: "'[]'::jsonb"},
			"evidence":        {dataType: "jsonb", nullable: "NO", defaultValue: "'{}'::jsonb"},
			"last_checked_at": {dataType: "timestamp with time zone", nullable: "YES"},
			"next_check_at":   {dataType: "timestamp with time zone", nullable: "YES"},
			"last_error":      {dataType: "text", nullable: "NO", defaultValue: "''::text"},
			"created_at":      {dataType: "timestamp with time zone", nullable: "NO", defaultValue: "now()"},
			"updated_at":      {dataType: "timestamp with time zone", nullable: "NO", defaultValue: "now()"},
		}
		rows, err := db.QueryContext(ctx, `
			SELECT column_name, data_type, is_nullable, COALESCE(column_default, '')
			FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'package_reputation_cache'
			ORDER BY ordinal_position`)
		if err != nil {
			t.Fatalf("query reputation column catalog: %v", err)
		}
		gotColumns := make(map[string]columnContract, len(wantColumns))
		for rows.Next() {
			var name string
			var contract columnContract
			if err := rows.Scan(&name, &contract.dataType, &contract.nullable, &contract.defaultValue); err != nil {
				ioutils.CloseSilently(rows)
				t.Fatalf("scan reputation column catalog: %v", err)
			}
			gotColumns[name] = contract
		}
		if err := rows.Err(); err != nil {
			ioutils.CloseSilently(rows)
			t.Fatalf("iterate reputation column catalog: %v", err)
		}
		ioutils.CloseSilently(rows)
		if len(gotColumns) != len(wantColumns) {
			t.Fatalf("reputation column count = %d, want %d: %#v", len(gotColumns), len(wantColumns), gotColumns)
		}
		for name, want := range wantColumns {
			if got, ok := gotColumns[name]; !ok || got != want {
				t.Fatalf("reputation column %s = %#v present=%t, want %#v", name, got, ok, want)
			}
		}

		statuses := []string{"pending", "malicious", "removed", "clean", "not_found", "unsupported", "error"}
		for _, status := range statuses {
			if _, err := db.ExecContext(ctx, `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', $1, '1.0.0', 'reversinglabs', $2)`, "status-"+status, status); err != nil {
				t.Fatalf("insert allowed status %q: %v", status, err)
			}
		}
		cases := []struct {
			name string
			sql  string
			code string
		}{
			{name: "invalid_status", sql: `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'bad-status', '1', 'rl', 'risk')`, code: "23514"},
			{name: "null_status", sql: `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'null-status', '1', 'rl', NULL)`, code: "23502"},
			{name: "null_ecosystem", sql: `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES (NULL, 'n', '1', 'rl', 'clean')`, code: "23502"},
			{name: "null_name", sql: `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', NULL, '1', 'rl', 'clean')`, code: "23502"},
			{name: "null_version", sql: `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'n', NULL, 'rl', 'clean')`, code: "23502"},
			{name: "null_source", sql: `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'n', '1', NULL, 'clean')`, code: "23502"},
		}
		for _, tc := range cases {
			_, err := db.ExecContext(ctx, tc.sql)
			assertPostgresErrorCodeWithLabel(t, err, tc.code, tc.name)
		}
	})

	t.Run("coordinate_uniqueness_and_distinct_dimensions", func(t *testing.T) {
		mustExecMigrationTest(t, ctx, db, `TRUNCATE package_reputation_cache RESTART IDENTITY`)
		mustExecMigrationTest(t, ctx, db, `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'coordinate', '1.0.0', 'reversinglabs', 'clean')`)
		_, err := db.ExecContext(ctx, `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'coordinate', '1.0.0', 'reversinglabs', 'error')`)
		assertPostgresErrorCode(t, err, "23505")
		for _, coordinates := range []struct {
			ecosystem, name, version, source string
		}{
			{ecosystem: "pypi", name: "coordinate", version: "1.0.0", source: "reversinglabs"},
			{ecosystem: "npm", name: "other", version: "1.0.0", source: "reversinglabs"},
			{ecosystem: "npm", name: "coordinate", version: "2.0.0", source: "reversinglabs"},
			{ecosystem: "npm", name: "coordinate", version: "1.0.0", source: "other"},
		} {
			if _, err := db.ExecContext(ctx, `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ($1, $2, $3, $4, 'clean')`, coordinates.ecosystem, coordinates.name, coordinates.version, coordinates.source); err != nil {
				t.Fatalf("insert distinct coordinate %#v: %v", coordinates, err)
			}
		}
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_reputation_cache`).Scan(&count); err != nil {
			t.Fatalf("count coordinate rows: %v", err)
		}
		if count != 5 {
			t.Fatalf("distinct coordinate row count = %d, want 5", count)
		}
	})

	t.Run("due_index_has_exact_keys_and_predicate", func(t *testing.T) {
		var keys, predicate string
		var unique, valid, ready bool
		if err := db.QueryRowContext(ctx, `
			SELECT string_agg(a.attname, ',' ORDER BY key.ordinality),
			       pg_get_expr(i.indpred, i.indrelid), i.indisunique, i.indisvalid, i.indisready
			FROM pg_index i
			JOIN pg_class idx ON idx.oid = i.indexrelid
			JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS key(attnum, ordinality) ON key.attnum > 0
			JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = key.attnum
			WHERE idx.relname = 'idx_reputation_due'
			GROUP BY i.indpred, i.indrelid, i.indisunique, i.indisvalid, i.indisready`).Scan(&keys, &predicate, &unique, &valid, &ready); err != nil {
			t.Fatalf("inspect idx_reputation_due: %v", err)
		}
		if keys != "source,ecosystem,name,next_check_at" {
			t.Fatalf("idx_reputation_due keys = %q, want source,ecosystem,name,next_check_at", keys)
		}
		for _, status := range []string{"pending", "error", "malicious", "removed", "clean", "not_found"} {
			if !strings.Contains(predicate, "'"+status+"'::text") {
				t.Fatalf("idx_reputation_due predicate = %q, missing %q", predicate, status)
			}
		}
		if strings.Contains(predicate, "'unsupported'::text") || unique || !valid || !ready {
			t.Fatalf("idx_reputation_due predicate=%q unique=%t valid=%t ready=%t, want exact non-unsupported valid nonunique partial index", predicate, unique, valid, ready)
		}
	})

	t.Run("down_removes_owned_objects_preserves_sentinel_and_reapplies_empty", func(t *testing.T) {
		mustExecMigrationTest(t, ctx, db, `TRUNCATE package_reputation_cache RESTART IDENTITY`)
		mustExecMigrationTest(t, ctx, db, `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'remove-me', '1', 'rl', 'clean')`)
		applyEmbeddedMigrationForTest(t, ctx, db, 4, MigrationDirectionDown)
		for _, relation := range []string{"package_reputation_cache", "idx_reputation_due", "package_reputation_cache_id_seq"} {
			assertRelationExists(t, ctx, db, relation, false)
		}
		assertSentinelPreserved(t, ctx, db, "migration_004_sentinel")
		applyEmbeddedMigrationForTest(t, ctx, db, 4, MigrationDirectionDown)
		applyEmbeddedMigrationForTest(t, ctx, db, 4, MigrationDirectionUp)
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_reputation_cache`).Scan(&count); err != nil {
			t.Fatalf("count recreated reputation cache: %v", err)
		}
		if count != 0 {
			t.Fatalf("recreated reputation cache row count = %d, want 0", count)
		}
		mustExecMigrationTest(t, ctx, db, `INSERT INTO package_reputation_cache (ecosystem, name, version, source, status) VALUES ('npm', 'reapplied', '1', 'rl', 'pending')`)
		var id int
		if err := db.QueryRowContext(ctx, `SELECT id FROM package_reputation_cache WHERE name = 'reapplied'`).Scan(&id); err != nil {
			t.Fatalf("read id after 004 reapply: %v", err)
		}
		if id != 1 {
			t.Fatalf("first id after 004 reapply = %d, want 1", id)
		}
	})

	t.Run("failed_down_rolls_back_objects_rows_and_records_dirty_metadata", func(t *testing.T) {
		down := embeddedMigrationFileForTest(t, 4, MigrationDirectionDown)
		failed := migrationFile{
			version:   904,
			name:      "904_reputation_injected_failure.down.sql",
			direction: MigrationDirectionDown,
			sql:       down.sql + "\nSELECT * FROM packmon_injected_missing_relation;",
		}
		if err := applyMigration(ctx, db, failed); err == nil || !strings.Contains(err.Error(), "packmon_injected_missing_relation") {
			t.Fatalf("apply injected 004 down error = %v, want missing-relation failure", err)
		}
		assertRelationExists(t, ctx, db, "package_reputation_cache", true)
		assertRelationExists(t, ctx, db, "idx_reputation_due", true)
		assertRelationExists(t, ctx, db, "package_reputation_cache_id_seq", true)
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_reputation_cache WHERE name = 'reapplied' AND id = 1`).Scan(&count); err != nil {
			t.Fatalf("count row after failed 004 down: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count after failed 004 down = %d, want 1", count)
		}
		assertDirtyMigration(t, ctx, db, failed)
	})
}
