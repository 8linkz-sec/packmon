//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

func TestInitialMigrationRollsBackInIsolationAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	applyEmbeddedMigrationForTest(t, ctx, db, 1, MigrationDirectionUp)
	assertBaselineSchemaCatalog(t, ctx, db)
	seedBaselineTables(t, ctx, db, "isolated-before-down", true)

	down := applyEmbeddedMigrationForTest(t, ctx, db, 1, MigrationDirectionDown)
	assertCleanMigrationAndDelete(t, ctx, db, down)
	assertNoCurrentMigration(t, ctx, db)
	assertPackmonObjectsRemoved(t, ctx, db)

	// The down file is intentionally guarded. Reapplying it without any
	// baseline objects must still produce a complete clean migration record.
	down = applyEmbeddedMigrationForTest(t, ctx, db, 1, MigrationDirectionDown)
	assertCleanMigrationAndDelete(t, ctx, db, down)
	assertNoCurrentMigration(t, ctx, db)
	assertPackmonObjectsRemoved(t, ctx, db)

	applyEmbeddedMigrationForTest(t, ctx, db, 1, MigrationDirectionUp)
	assertBaselineSchemaCatalog(t, ctx, db)
	assertBaselineTablesEmpty(t, ctx, db)
	seedBaselineTables(t, ctx, db, "isolated-after-reapply", true)
}

func TestFullMigrationChainRollsBackToVersionZeroAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := RunContext(ctx, instance.dsn); err != nil {
		t.Fatalf("RunContext() error = %v", err)
	}

	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	assertValidatorResult(t, ctx, db, "packmon_jsonb_version_ranges_valid", `[{"events":[{"introduced":1}]}]`, false)
	assertValidatorResult(t, ctx, db, "packmon_jsonb_version_ranges_valid", `[{"events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`, true)
	seedBaselineTables(t, ctx, db, "full-chain", true)

	embeddedDown, err := EmbeddedMigrations(MigrationDirectionDown)
	if err != nil {
		t.Fatalf("EmbeddedMigrations(down): %v", err)
	}
	if len(embeddedDown) != ExpectedVersion {
		t.Fatalf("down migration count = %d, want %d", len(embeddedDown), ExpectedVersion)
	}
	for i, embedded := range embeddedDown {
		wantVersion := ExpectedVersion - i
		if embedded.Version != wantVersion {
			t.Fatalf("down migration[%d] version = %d, want %d", i, embedded.Version, wantVersion)
		}
		migration := migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
		if err := applyMigration(ctx, db, migration); err != nil {
			t.Fatalf("apply full-chain down %s: %v", migration.name, err)
		}
		assertCleanMigrationAndDelete(t, ctx, db, migration)
		if wantVersion == 1 {
			assertNoCurrentMigration(t, ctx, db)
		} else {
			assertCurrentMigration(t, ctx, db, wantVersion-1)
		}
	}
	assertPackmonObjectsRemoved(t, ctx, db)
	assertPGStatStatementsUsable(t, ctx, db)

	// The complete chain already applied 001 down once. A second isolated 001
	// down must remain harmless and must not remove operator-owned extensions.
	repeated := applyEmbeddedMigrationForTest(t, ctx, db, 1, MigrationDirectionDown)
	assertCleanMigrationAndDelete(t, ctx, db, repeated)
	assertNoCurrentMigration(t, ctx, db)
	assertPackmonObjectsRemoved(t, ctx, db)
	assertPGStatStatementsUsable(t, ctx, db)
}

func seedBaselineTables(t *testing.T, ctx context.Context, db *sql.DB, suffix string, wantFreshSequences bool) {
	t.Helper()
	vulnerabilityID := "baseline-vulnerability-" + suffix
	keyHash := "baseline-key-hash-" + suffix
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	execOK(t, ctx, db, `INSERT INTO vulnerabilities(id, summary, published, modified) VALUES($1, 'baseline fixture', $2, $2)`, vulnerabilityID, now)

	serialInserts := []struct {
		name      string
		statement string
		args      []any
	}{
		{"vulnerability_aliases", `INSERT INTO vulnerability_aliases(vulnerability_id, alias_id) VALUES($1, $2) RETURNING id`, []any{vulnerabilityID, "CVE-2026-" + suffix}},
		{"vulnerability_sources", `INSERT INTO vulnerability_sources(vulnerability_id, source, source_id, raw_json) VALUES($1, 'osv', $2, '{}'::jsonb) RETURNING id`, []any{vulnerabilityID, "OSV-" + suffix}},
		{"vulnerability_references", `INSERT INTO vulnerability_references(vulnerability_id, type, url, source) VALUES($1, 'ADVISORY', $2, 'osv') RETURNING id`, []any{vulnerabilityID, "https://example.test/" + suffix}},
		{"affected_packages", `INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected) VALUES($1, 'npm', $2, '[]'::jsonb, '[]'::jsonb) RETURNING id`, []any{vulnerabilityID, "affected-" + suffix}},
		{"package_check_status", `INSERT INTO package_check_status(ecosystem, name, source) VALUES('npm', $1, 'socket') RETURNING id`, []any{"status-" + suffix}},
		{"refresh_queue", `INSERT INTO refresh_queue(ecosystem, name, source, status) VALUES('npm', $1, 'socket', 'pending') RETURNING id`, []any{"queue-" + suffix}},
		{"admin_audit_log", `INSERT INTO admin_audit_log(action, details) VALUES($1, '{}'::jsonb) RETURNING id`, []any{"baseline-" + suffix}},
		{"api_keys", `INSERT INTO api_keys(name, key_hash) VALUES($1, $2) RETURNING id`, []any{"key-" + suffix, keyHash}},
	}
	ids := make(map[string]int)
	for _, insert := range serialInserts {
		var id int
		if err := db.QueryRowContext(ctx, insert.statement, insert.args...).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", insert.name, err)
		}
		ids[insert.name] = id
	}

	execOK(t, ctx, db, `INSERT INTO nvd_cvss_negative_cache(cve_id, vulnerability_updated_at) VALUES($1, $2)`, "CVE-NEGATIVE-"+suffix, now)
	execOK(t, ctx, db, `INSERT INTO malicious_findings(id, ecosystem, name, version_ranges, versions, source, risk_type, summary, reference_urls) VALUES($1, 'npm', $2, '[]'::jsonb, '[]'::jsonb, 'osv', 'malware', 'baseline', '[]'::jsonb)`, "malicious-"+suffix, "malicious-package-"+suffix)
	execOK(t, ctx, db, `INSERT INTO feed_sync_status(feed_name, last_sync_status, entries_synced, entries_total) VALUES($1, 'success', 1, 1)`, "feed-"+suffix)
	execOK(t, ctx, db, `INSERT INTO admin_auth(password_hash) VALUES($1)`, "hash-"+suffix)
	execOK(t, ctx, db, `INSERT INTO feed_configs(feed_name, enabled, mode, sync_interval) VALUES($1, true, 'self', interval '15 minutes')`, "config-"+suffix)

	var scanID int
	if err := db.QueryRowContext(ctx, `INSERT INTO scan_log(scan_id, packages_count, findings_count, duration_ms, api_key_id) VALUES($1, 1, 0, 1, $2) RETURNING id`, "scan-"+suffix, ids["api_keys"]).Scan(&scanID); err != nil {
		t.Fatalf("seed scan_log: %v", err)
	}
	ids["scan_log"] = scanID

	if wantFreshSequences {
		for table, id := range ids {
			if id != 1 {
				t.Fatalf("fresh %s sequence generated id %d, want 1", table, id)
			}
		}
	}
	assertBaselineTablesPopulated(t, ctx, db)
}

func assertBaselineTablesPopulated(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, table := range baselineApplicationTables {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count populated baseline table %s: %v", table, err)
		}
		if count == 0 {
			t.Fatalf("baseline table %s is empty after fixture seed", table)
		}
	}
}

func assertBaselineTablesEmpty(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, table := range baselineApplicationTables {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
			t.Fatalf("count empty baseline table %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("baseline table %s rows after reapply = %d, want 0", table, count)
		}
	}
}

func assertCurrentMigration(t *testing.T, ctx context.Context, db *sql.DB, wantVersion int) {
	t.Helper()
	version, dirty, ok, err := currentVersion(ctx, db)
	if err != nil {
		t.Fatalf("currentVersion(): %v", err)
	}
	if !ok || dirty || version != wantVersion {
		t.Fatalf("currentVersion() = version:%d dirty:%v ok:%v, want %d clean", version, dirty, ok, wantVersion)
	}
}

func assertNoCurrentMigration(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	version, dirty, ok, err := currentVersion(ctx, db)
	if err != nil {
		t.Fatalf("currentVersion(): %v", err)
	}
	if ok || dirty || version != 0 {
		t.Fatalf("currentVersion() = version:%d dirty:%v ok:%v, want no version", version, dirty, ok)
	}
}

func assertPackmonObjectsRemoved(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	unexpected := queryStrings(t, ctx, db, `
		SELECT class.relname
		FROM pg_class class
		JOIN pg_namespace namespace ON namespace.oid = class.relnamespace
		WHERE namespace.nspname = 'public'
		  AND class.relkind IN ('r', 'p', 'S', 'v', 'm')
		  AND class.relname NOT LIKE 'schema_migration%'
		  AND NOT EXISTS (
			SELECT 1 FROM pg_depend dependency
			WHERE dependency.classid = 'pg_class'::regclass
			  AND dependency.objid = class.oid
			  AND dependency.deptype = 'e'
		  )
		ORDER BY class.relname`)
	if len(unexpected) != 0 {
		t.Fatalf("non-extension Packmon relations after rollback = %v, want none", unexpected)
	}

	for _, name := range append(slices.Clone(baselineApplicationTables), "packmon_jsonb_string_array_valid", "packmon_jsonb_version_ranges_valid") {
		var exists bool
		if err := db.QueryRowContext(ctx, `
			SELECT to_regclass('public.' || $1) IS NOT NULL
			    OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname = $1)`, name).Scan(&exists); err != nil {
			t.Fatalf("inspect removed object %s: %v", name, err)
		}
		if exists {
			t.Fatalf("Packmon object %s still exists after rollback", name)
		}
	}
}

func assertPGStatStatementsUsable(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var installed bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&installed); err != nil {
		t.Fatalf("inspect pg_stat_statements extension: %v", err)
	}
	if !installed {
		t.Fatal("pg_stat_statements extension removed by Packmon rollback")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM public.pg_stat_statements(false)`).Scan(&count); err != nil {
		t.Fatalf("query retained pg_stat_statements(false): %v", err)
	}
	if count < 0 {
		t.Fatalf("pg_stat_statements(false) count = %d, want nonnegative", count)
	}
}
