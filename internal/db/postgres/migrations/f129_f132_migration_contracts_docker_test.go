//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f129F132Leaf struct {
	ctx    context.Context
	conn   *sql.Conn
	schema string
	dsn    string
}

type f129F132MigrationEvent struct {
	name     string
	checksum string
	success  bool
	dirty    bool
}

func TestMigration011SyncKeysetAndLifecycleTombstoneContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	db.SetMaxOpenConns(3)
	leafNumber := 0

	t.Run("populated_partial_failure_records_dirty_state", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_011_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 10)
		f129F132Seed011Sources(t, leaf)
		before := f129F132SourceSnapshot(t, leaf)
		f129F132Exec(t, leaf, `CREATE TABLE idx_lifecycle_products_updated_at(id integer)`)

		up := f129F132Embedded(t, 11, MigrationDirectionUp)
		err := applyMigration(leaf.ctx, leaf.conn, up)
		if err == nil || !strings.Contains(err.Error(), "idx_lifecycle_products_updated_at") {
			t.Fatalf("011 partial-up error = %v, want fourth-index relation collision", err)
		}
		for _, name := range []string{"idx_vulnerabilities_updated_at", "idx_malicious_findings_updated_at", "idx_package_reputation_cache_updated_at"} {
			f129F132AssertIndex(t, leaf, name, f129F132IndexTables()[name], "updated_at")
		}
		for _, name := range []string{"idx_lifecycle_releases_updated_at", "idx_lifecycle_package_map_updated_at", "idx_lifecycle_sync_tombstones_updated_at", "lifecycle_sync_tombstones"} {
			f129F132AssertRelationAbsent(t, leaf, name)
		}
		f129F132AssertRelationKind(t, leaf, "idx_lifecycle_products_updated_at", "r")
		f129F132AssertDirtyMetadata(t, leaf, up, 1)
		f129F132AssertRunRefusesDirty(t, leaf, 11)
		if got := f129F132SourceSnapshot(t, leaf); got != before {
			t.Fatalf("011 partial up changed source rows\ngot:  %s\nwant: %s", got, before)
		}
	})

	t.Run("isolated_fixture_cleanup_and_clean_rerun", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_011_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 10)
		f129F132Seed011Sources(t, leaf)
		before := f129F132SourceSnapshot(t, leaf)
		f129F132Exec(t, leaf, `CREATE TABLE idx_lifecycle_products_updated_at(id integer)`)
		up := f129F132Embedded(t, 11, MigrationDirectionUp)
		if err := applyMigration(leaf.ctx, leaf.conn, up); err == nil {
			t.Fatal("011 fixture collision error = nil")
		}
		f129F132FixtureOnlyResetFailed011Up(t, leaf)
		if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
			t.Fatalf("apply clean 011 after isolated fixture reset: %v", err)
		}
		f129F132AssertCleanMetadata(t, leaf, up)
		f129F132AssertAll011Objects(t, leaf, true)
		if got := f129F132SourceSnapshot(t, leaf); got != before {
			t.Fatalf("011 cleanup/rerun changed source rows\ngot:  %s\nwant: %s", got, before)
		}
		f129F132AssertEvents(t, leaf, 11, []f129F132MigrationEvent{
			{name: up.name, checksum: migrationChecksum(up.sql), success: false, dirty: true},
			{name: up.name, checksum: migrationChecksum(up.sql), success: true, dirty: false},
		})
	})

	t.Run("catalog_tombstone_keyset_xid_and_fk_semantics", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_011_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 10)
		f129F132Seed011Sources(t, leaf)
		before := f129F132SourceSnapshot(t, leaf)
		beforeXIDs := f129F132SourceXIDs(t, leaf)
		beforeFKs := f129F132LifecycleFKs(t, leaf)
		up := f129F132Apply(t, leaf, 11, MigrationDirectionUp)
		f129F132AssertCleanMetadata(t, leaf, up)
		f129F132AssertAll011Objects(t, leaf, true)
		f129F132AssertTombstoneCatalog(t, leaf)
		if got := f129F132SourceSnapshot(t, leaf); got != before {
			t.Fatalf("011 up changed source rows\ngot:  %s\nwant: %s", got, before)
		}
		if got := f129F132SourceXIDs(t, leaf); !reflect.DeepEqual(got, beforeXIDs) {
			t.Fatalf("011 up changed source xmin values\ngot:  %v\nwant: %v", got, beforeXIDs)
		}
		if got := f129F132LifecycleFKs(t, leaf); !reflect.DeepEqual(got, beforeFKs) {
			t.Fatalf("011 up replaced lifecycle foreign keys\ngot:  %v\nwant: %v", got, beforeFKs)
		}

		f129F132AssertTombstoneKeyset(t, leaf)
		f129F132AssertLifecycleCascade(t, leaf)
	})

	t.Run("all_seven_indexes_are_plan_eligible", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_011_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 10)
		f129F132Seed011Sources(t, leaf)
		f129F132Apply(t, leaf, 11, MigrationDirectionUp)
		f129F132Exec(t, leaf, `INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle,updated_at) VALUES('plan','npm','plan-package','plan-product','1','2026-07-01Z')`)
		f129F132Exec(t, leaf, `SET enable_seqscan = off`)
		for name, table := range f129F132IndexTables() {
			f129F132AssertJSONPlanUsesIndex(t, leaf, table, name)
		}
	})

	t.Run("guarded_reapplication_preserves_objects_and_rows", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_011_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 10)
		f129F132Seed011Sources(t, leaf)
		up := f129F132Apply(t, leaf, 11, MigrationDirectionUp)
		f129F132Exec(t, leaf, `INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle,updated_at) VALUES('reapply','npm','kept','product','1','2026-08-01Z')`)
		before := f129F132SourceAndTombstoneSnapshot(t, leaf)
		beforeOIDs := f129F132011ObjectOIDs(t, leaf)
		if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
			t.Fatalf("guarded 011 reapplication: %v", err)
		}
		if got := f129F132SourceAndTombstoneSnapshot(t, leaf); got != before {
			t.Fatalf("011 reapplication changed rows\ngot:  %s\nwant: %s", got, before)
		}
		if got := f129F132011ObjectOIDs(t, leaf); !reflect.DeepEqual(got, beforeOIDs) {
			t.Fatalf("011 reapplication replaced guarded objects\ngot:  %v\nwant: %v", got, beforeOIDs)
		}
		f129F132AssertEvents(t, leaf, 11, []f129F132MigrationEvent{
			{name: up.name, checksum: migrationChecksum(up.sql), success: true, dirty: false},
			{name: up.name, checksum: migrationChecksum(up.sql), success: true, dirty: false},
		})
	})

	t.Run("partial_down_then_repeated_down_preserves_sources", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_011_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 11)
		f129F132Seed011Sources(t, leaf)
		f129F132Exec(t, leaf, `INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle) VALUES('partial-down','npm','temporary','product','1')`)
		before := f129F132SourceSnapshot(t, leaf)
		f129F132Exec(t, leaf, `DROP INDEX CONCURRENTLY idx_lifecycle_releases_updated_at`)
		f129F132Exec(t, leaf, `CREATE TABLE idx_lifecycle_releases_updated_at(id integer)`)
		down := f129F132Embedded(t, 11, MigrationDirectionDown)
		if err := applyMigration(leaf.ctx, leaf.conn, down); err == nil || !strings.Contains(err.Error(), "idx_lifecycle_releases_updated_at") {
			t.Fatalf("011 partial-down error = %v, want non-index collision", err)
		}
		for _, name := range []string{"idx_lifecycle_sync_tombstones_updated_at", "lifecycle_sync_tombstones", "idx_lifecycle_package_map_updated_at"} {
			f129F132AssertRelationAbsent(t, leaf, name)
		}
		f129F132AssertRelationKind(t, leaf, "idx_lifecycle_releases_updated_at", "r")
		for _, name := range []string{"idx_lifecycle_products_updated_at", "idx_package_reputation_cache_updated_at", "idx_malicious_findings_updated_at", "idx_vulnerabilities_updated_at"} {
			f129F132AssertIndex(t, leaf, name, f129F132IndexTables()[name], "updated_at")
		}
		f129F132AssertDirtyMetadata(t, leaf, down, 2)
		f129F132AssertRunRefusesDirty(t, leaf, 11)
		f129F132ClearDirty(t, leaf, 11)
		f129F132Exec(t, leaf, `DROP TABLE idx_lifecycle_releases_updated_at`)
		if err := applyMigration(leaf.ctx, leaf.conn, down); err != nil {
			t.Fatalf("resume 011 down after fixture cleanup: %v", err)
		}
		if err := applyMigration(leaf.ctx, leaf.conn, down); err != nil {
			t.Fatalf("repeat guarded 011 down: %v", err)
		}
		f129F132AssertAll011Objects(t, leaf, false)
		if got := f129F132SourceSnapshot(t, leaf); got != before {
			t.Fatalf("011 partial/repeated down changed retained sources\ngot:  %s\nwant: %s", got, before)
		}
		for _, name := range []string{
			"idx_vulnerabilities_cisa_kev",
			"idx_malicious_eco_name",
			"idx_reputation_due",
			"lifecycle_products_pkey",
			"lifecycle_releases_pkey",
			"lifecycle_package_map_lookup_idx",
		} {
			f129F132AssertRelationExists(t, leaf, name)
		}
	})

	t.Run("fixture_metadata_reset_and_up_reapply", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_011_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 10)
		f129F132Seed011Sources(t, leaf)
		before := f129F132SourceSnapshot(t, leaf)
		up := f129F132Apply(t, leaf, 11, MigrationDirectionUp)
		down := f129F132Apply(t, leaf, 11, MigrationDirectionDown)
		f129F132AssertCleanMetadata(t, leaf, down)
		if err := applyMigration(leaf.ctx, leaf.conn, down); err != nil {
			t.Fatalf("repeat 011 down before metadata reset: %v", err)
		}
		f129F132AssertCleanMetadata(t, leaf, down)
		// Direct down application intentionally leaves version-011 metadata. This
		// deletion is fixture-only bookkeeping before reconstructing the up state.
		f129F132Exec(t, leaf, `DELETE FROM schema_migrations WHERE version=11`)
		if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
			t.Fatalf("011 up after fixture-only metadata reset: %v", err)
		}
		if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
			t.Fatalf("011 final guarded up reapply: %v", err)
		}
		f129F132AssertCleanMetadata(t, leaf, up)
		f129F132AssertAll011Objects(t, leaf, true)
		if got := f129F132SourceSnapshot(t, leaf); got != before {
			t.Fatalf("011 five-event cycle changed source rows\ngot:  %s\nwant: %s", got, before)
		}
		f129F132AssertEvents(t, leaf, 11, []f129F132MigrationEvent{
			{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			{name: down.name, checksum: migrationChecksum(down.sql), success: true},
			{name: down.name, checksum: migrationChecksum(down.sql), success: true},
			{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			{name: up.name, checksum: migrationChecksum(up.sql), success: true},
		})
	})
}

func TestMigration012ScanLogAPIKeyIdentityContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	db.SetMaxOpenConns(3)
	leafNumber := 0

	t.Run("absent_columns_null_backfill_down_and_replay", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_012_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 11)
		f129F132SeedScanLog(t, leaf, 1201, "absent", sql.NullInt64{}, sql.NullString{})
		f129F132FixtureDropIdentity(t, leaf, true, true)
		before := f129F132ScanSnapshot(t, leaf, false, false)
		up := f129F132Apply(t, leaf, 12, MigrationDirectionUp)
		f129F132AssertIdentityColumns(t, leaf, true, true)
		f129F132AssertScanIdentity(t, leaf, 1201, sql.NullInt64{}, sql.NullString{})
		if got := f129F132ScanSnapshot(t, leaf, true, true); !strings.Contains(got, `"api_key_id": null`) || !strings.Contains(got, `"api_key_name": null`) {
			t.Fatalf("012 absent-column backfill snapshot = %s, want NULL identities", got)
		}
		down := f129F132Apply(t, leaf, 12, MigrationDirectionDown)
		f129F132AssertVersion12Metadata(t, leaf, down)
		f129F132AssertScanIdentity(t, leaf, 1201, sql.NullInt64{}, sql.NullString{})
		if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
			t.Fatalf("replay 012 up: %v", err)
		}
		if got := f129F132ScanSnapshot(t, leaf, false, false); got != before {
			t.Fatalf("012 round trip changed legacy scan fields\ngot:  %s\nwant: %s", got, before)
		}
		f129F132AssertEvents(t, leaf, 12, []f129F132MigrationEvent{
			{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			{name: down.name, checksum: migrationChecksum(down.sql), success: true},
			{name: up.name, checksum: migrationChecksum(up.sql), success: true},
		})
	})

	t.Run("only_api_key_id_exists", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_012_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 11)
		f129F132SeedScanLog(t, leaf, 1202, "id-only", sql.NullInt64{Int64: 2202, Valid: true}, sql.NullString{String: "id-name", Valid: true})
		f129F132FixtureDropIdentity(t, leaf, false, true)
		f129F132Apply(t, leaf, 12, MigrationDirectionUp)
		f129F132AssertIdentityColumns(t, leaf, true, true)
		f129F132AssertScanIdentity(t, leaf, 1202, sql.NullInt64{Int64: 2202, Valid: true}, sql.NullString{})
		f129F132Apply(t, leaf, 12, MigrationDirectionDown)
		f129F132Apply(t, leaf, 12, MigrationDirectionUp)
		f129F132AssertScanIdentity(t, leaf, 1202, sql.NullInt64{Int64: 2202, Valid: true}, sql.NullString{})
	})

	t.Run("only_api_key_name_exists", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_012_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 11)
		f129F132SeedScanLog(t, leaf, 1203, "name-only", sql.NullInt64{Int64: 2203, Valid: true}, sql.NullString{String: "kept-name", Valid: true})
		f129F132FixtureDropIdentity(t, leaf, true, false)
		f129F132Apply(t, leaf, 12, MigrationDirectionUp)
		f129F132AssertIdentityColumns(t, leaf, true, true)
		f129F132AssertScanIdentity(t, leaf, 1203, sql.NullInt64{}, sql.NullString{String: "kept-name", Valid: true})
		f129F132Apply(t, leaf, 12, MigrationDirectionDown)
		f129F132Apply(t, leaf, 12, MigrationDirectionUp)
		f129F132AssertScanIdentity(t, leaf, 1203, sql.NullInt64{}, sql.NullString{String: "kept-name", Valid: true})
	})

	t.Run("baseline_owned_columns_and_fk_are_retained", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_012_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 11)
		f129F132SeedScanLog(t, leaf, 1204, "baseline", sql.NullInt64{Int64: 2204, Valid: true}, sql.NullString{String: "baseline-name", Valid: true})
		beforeColumns := f129F132IdentityAttnums(t, leaf)
		beforeFK := f129F132ScanLogFK(t, leaf)
		up := f129F132Apply(t, leaf, 12, MigrationDirectionUp)
		down := f129F132Apply(t, leaf, 12, MigrationDirectionDown)
		if got := f129F132IdentityAttnums(t, leaf); !reflect.DeepEqual(got, beforeColumns) {
			t.Fatalf("012 replaced baseline identity columns: got %v want %v", got, beforeColumns)
		}
		if got := f129F132ScanLogFK(t, leaf); got != beforeFK {
			t.Fatalf("012 replaced baseline scan-log FK: got %q want %q", got, beforeFK)
		}
		f129F132AssertScanIdentity(t, leaf, 1204, sql.NullInt64{Int64: 2204, Valid: true}, sql.NullString{String: "baseline-name", Valid: true})
		f129F132Exec(t, leaf, `DELETE FROM api_keys WHERE id=2204`)
		f129F132AssertScanIdentity(t, leaf, 1204, sql.NullInt64{}, sql.NullString{String: "baseline-name", Valid: true})
		f129F132AssertVersion12Metadata(t, leaf, down)
		f129F132AssertEvents(t, leaf, 12, []f129F132MigrationEvent{
			{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			{name: down.name, checksum: migrationChecksum(down.sql), success: true},
		})
	})

	t.Run("transaction_failure_rolls_back_and_fixture_recovers", func(t *testing.T) {
		leafNumber++
		leaf := f129F132PrepareLeaf(t, db, instance.dsn, fmt.Sprintf("f129_f132_012_%02d", leafNumber))
		f129F132ApplyThrough(t, leaf, 11)
		f129F132SeedScanLog(t, leaf, 1205, "failed", sql.NullInt64{}, sql.NullString{})
		f129F132FixtureDropIdentity(t, leaf, true, true)
		before := f129F132ScanSnapshot(t, leaf, false, false)
		up := f129F132Embedded(t, 12, MigrationDirectionUp)
		failed := up
		failed.sql += `

DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '42P01', MESSAGE = 'fixture-only migration 012 failure';
END $$;
`
		err := applyMigration(leaf.ctx, leaf.conn, failed)
		f129F132ExpectSQLState(t, err, "42P01")
		f129F132AssertIdentityColumns(t, leaf, false, false)
		if got := f129F132ScanSnapshot(t, leaf, false, false); got != before {
			t.Fatalf("failed transactional 012 changed scan rows\ngot:  %s\nwant: %s", got, before)
		}
		f129F132AssertDirtyMetadata(t, leaf, failed, 1)
		f129F132AssertRunRefusesDirty(t, leaf, 12)
		f129F132ClearDirty(t, leaf, 12)
		if err := applyMigration(leaf.ctx, leaf.conn, up); err != nil {
			t.Fatalf("012 up after fixture-only dirty cleanup: %v", err)
		}
		f129F132AssertIdentityColumns(t, leaf, true, true)
		f129F132AssertScanIdentity(t, leaf, 1205, sql.NullInt64{}, sql.NullString{})
		down := f129F132Apply(t, leaf, 12, MigrationDirectionDown)
		f129F132AssertVersion12Metadata(t, leaf, down)
		f129F132AssertEvents(t, leaf, 12, []f129F132MigrationEvent{
			{name: failed.name, checksum: migrationChecksum(failed.sql), success: false, dirty: true},
			{name: up.name, checksum: migrationChecksum(up.sql), success: true},
			{name: down.name, checksum: migrationChecksum(down.sql), success: true},
		})
	})
}

func f129F132PrepareLeaf(t *testing.T, db *sql.DB, dsn, schema string) f129F132Leaf {
	t.Helper()
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 20*time.Second)
	quoted := f129F132QuoteIdentifier(schema)
	if _, err := db.ExecContext(setupCtx, `CREATE SCHEMA `+quoted); err != nil {
		setupCancel()
		t.Fatalf("create isolated migration schema %s: %v", quoted, err)
	}
	setupCancel()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if _, err := db.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+quoted+` CASCADE`); err != nil {
			t.Errorf("drop isolated migration schema %s: %v", quoted, err)
		}
	})

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := db.Conn(connectCtx)
	connectCancel()
	if err != nil {
		t.Fatalf("pin isolated migration connection: %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(conn) })
	setCtx, setCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := conn.ExecContext(setCtx, `SET search_path TO `+quoted); err != nil {
		setCancel()
		t.Fatalf("set isolated migration search_path: %v", err)
	}
	setCancel()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse migration DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return f129F132Leaf{ctx: ctx, conn: conn, schema: schema, dsn: parsed.String()}
}

func f129F132QuoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func f129F132Embedded(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("ReadEmbeddedMigration(%d, %s): %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f129F132ApplyThrough(t *testing.T, leaf f129F132Leaf, version int) {
	t.Helper()
	if err := ensureVersionTable(leaf.ctx, leaf.conn); err != nil {
		t.Fatalf("ensure migration metadata in %s: %v", leaf.schema, err)
	}
	for current := 1; current <= version; current++ {
		f129F132Apply(t, leaf, current, MigrationDirectionUp)
	}
}

func f129F132Apply(t *testing.T, leaf f129F132Leaf, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	migration := f129F132Embedded(t, version, direction)
	if err := applyMigration(leaf.ctx, leaf.conn, migration); err != nil {
		t.Fatalf("apply %s in %s: %v", migration.name, leaf.schema, err)
	}
	return migration
}

func f129F132Exec(t *testing.T, leaf f129F132Leaf, statement string, args ...any) {
	t.Helper()
	if _, err := leaf.conn.ExecContext(leaf.ctx, statement, args...); err != nil {
		t.Fatalf("execute fixture SQL in %s: %v\nSQL:\n%s", leaf.schema, err, statement)
	}
}

func f129F132Seed011Sources(t *testing.T, leaf f129F132Leaf) {
	t.Helper()
	f129F132Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified,updated_at) VALUES('F129-VULN','fixture vulnerability','HIGH','2025-01-01Z','2025-01-02Z','2026-01-01Z')`)
	f129F132Exec(t, leaf, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary,reference_urls,updated_at) VALUES('F129-MAL','npm','fixture-malicious','fixture','malware','CRITICAL','fixture malicious','[]','2026-01-02Z')`)
	f129F132Exec(t, leaf, `INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,updated_at) VALUES('npm','fixture-reputation','1','fixture','clean','2026-01-03Z')`)
	f129F132Exec(t, leaf, `INSERT INTO lifecycle_products(product_slug,name,updated_at) VALUES('fixture-product','Fixture Product','2026-01-04Z')`)
	f129F132Exec(t, leaf, `INSERT INTO lifecycle_releases(product_slug,cycle,updated_at) VALUES('fixture-product','1','2026-01-05Z')`)
	f129F132Exec(t, leaf, `INSERT INTO lifecycle_package_map(ecosystem,name,product_slug,updated_at) VALUES('npm','fixture-package','fixture-product','2026-01-06Z')`)
}

func f129F132SourceSnapshot(t *testing.T, leaf f129F132Leaf) string {
	t.Helper()
	return f129F132Snapshot(t, leaf, `
		SELECT kind,identity,payload FROM (
			SELECT 'vulnerability' kind,id identity,to_jsonb(vulnerabilities)-'id' payload FROM vulnerabilities
			UNION ALL SELECT 'malicious',id,to_jsonb(malicious_findings)-'id' FROM malicious_findings
			UNION ALL SELECT 'reputation',ecosystem||'|'||name||'|'||version||'|'||source,to_jsonb(package_reputation_cache)-'id' FROM package_reputation_cache
			UNION ALL SELECT 'product',product_slug,to_jsonb(lifecycle_products)-'product_slug' FROM lifecycle_products
			UNION ALL SELECT 'release',product_slug||'|'||cycle,to_jsonb(lifecycle_releases)-'product_slug'-'cycle' FROM lifecycle_releases
			UNION ALL SELECT 'map',ecosystem||'|'||name||'|'||product_slug,to_jsonb(lifecycle_package_map)-'ecosystem'-'name'-'product_slug' FROM lifecycle_package_map
		) source_rows ORDER BY kind,identity`)
}

func f129F132SourceAndTombstoneSnapshot(t *testing.T, leaf f129F132Leaf) string {
	t.Helper()
	return f129F132Snapshot(t, leaf, `
		SELECT kind,identity,payload FROM (
			SELECT 'vulnerability' kind,id identity,to_jsonb(vulnerabilities)-'id' payload FROM vulnerabilities
			UNION ALL SELECT 'malicious',id,to_jsonb(malicious_findings)-'id' FROM malicious_findings
			UNION ALL SELECT 'reputation',ecosystem||'|'||name||'|'||version||'|'||source,to_jsonb(package_reputation_cache)-'id' FROM package_reputation_cache
			UNION ALL SELECT 'product',product_slug,to_jsonb(lifecycle_products)-'product_slug' FROM lifecycle_products
			UNION ALL SELECT 'release',product_slug||'|'||cycle,to_jsonb(lifecycle_releases)-'product_slug'-'cycle' FROM lifecycle_releases
			UNION ALL SELECT 'map',ecosystem||'|'||name||'|'||product_slug,to_jsonb(lifecycle_package_map)-'ecosystem'-'name'-'product_slug' FROM lifecycle_package_map
			UNION ALL SELECT 'tombstone',id,to_jsonb(lifecycle_sync_tombstones)-'id' FROM lifecycle_sync_tombstones
		) source_rows ORDER BY kind,identity`)
}

func f129F132Snapshot(t *testing.T, leaf f129F132Leaf, query string) string {
	t.Helper()
	var snapshot string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(snapshot_row)),'[]'::jsonb)::text FROM (`+query+`) snapshot_row`).Scan(&snapshot); err != nil {
		t.Fatalf("snapshot fixture rows: %v\nSQL:\n%s", err, query)
	}
	return snapshot
}

func f129F132IndexTables() map[string]string {
	return map[string]string{
		"idx_vulnerabilities_updated_at":           "vulnerabilities",
		"idx_malicious_findings_updated_at":        "malicious_findings",
		"idx_package_reputation_cache_updated_at":  "package_reputation_cache",
		"idx_lifecycle_products_updated_at":        "lifecycle_products",
		"idx_lifecycle_releases_updated_at":        "lifecycle_releases",
		"idx_lifecycle_package_map_updated_at":     "lifecycle_package_map",
		"idx_lifecycle_sync_tombstones_updated_at": "lifecycle_sync_tombstones",
	}
}

func f129F132AssertAll011Objects(t *testing.T, leaf f129F132Leaf, present bool) {
	t.Helper()
	for name, table := range f129F132IndexTables() {
		if present {
			f129F132AssertIndex(t, leaf, name, table, "updated_at")
		} else {
			f129F132AssertRelationAbsent(t, leaf, name)
		}
	}
	if present {
		f129F132AssertRelationKind(t, leaf, "lifecycle_sync_tombstones", "r")
	} else {
		f129F132AssertRelationAbsent(t, leaf, "lifecycle_sync_tombstones")
	}
}

func f129F132AssertIndex(t *testing.T, leaf f129F132Leaf, name, table, keys string) {
	t.Helper()
	var gotTable, gotKeys, predicate string
	var unique, valid, ready bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT tbl.relname,i.indisunique,
		       (SELECT string_agg(pg_get_indexdef(i.indexrelid,n,true),',' ORDER BY n) FROM generate_series(1,i.indnkeyatts) n),
		       COALESCE(pg_get_expr(i.indpred,i.indrelid),''),i.indisvalid,i.indisready
		FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid JOIN pg_class tbl ON tbl.oid=i.indrelid
		WHERE idx.oid=to_regclass($1)`, name).Scan(&gotTable, &unique, &gotKeys, &predicate, &valid, &ready); err != nil {
		t.Fatalf("inspect index %s: %v", name, err)
	}
	if gotTable != table || unique || gotKeys != keys || predicate != "" || !valid || !ready {
		t.Fatalf("index %s = table:%q unique:%t keys:%q predicate:%q valid:%t ready:%t, want %s nonunique (%s) valid/ready", name, gotTable, unique, gotKeys, predicate, valid, ready, table, keys)
	}
}

func f129F132AssertRelationAbsent(t *testing.T, leaf f129F132Leaf, name string) {
	t.Helper()
	var exists bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("inspect absent relation %s: %v", name, err)
	}
	if exists {
		t.Fatalf("relation %s exists, want absent", name)
	}
}

func f129F132AssertRelationExists(t *testing.T, leaf f129F132Leaf, name string) {
	t.Helper()
	var exists bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("inspect relation %s: %v", name, err)
	}
	if !exists {
		t.Fatalf("relation %s absent, want present", name)
	}
}

func f129F132AssertRelationKind(t *testing.T, leaf f129F132Leaf, name, want string) {
	t.Helper()
	var kind string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT relkind::text FROM pg_class WHERE oid=to_regclass($1)`, name).Scan(&kind); err != nil {
		t.Fatalf("inspect relation kind %s: %v", name, err)
	}
	if kind != want {
		t.Fatalf("relation %s kind = %q, want %q", name, kind, want)
	}
}

func f129F132FixtureOnlyResetFailed011Up(t *testing.T, leaf f129F132Leaf) {
	t.Helper()
	// Production recovery requires operator inspection. This inverse is limited
	// to the deliberately-created test schema and its known fixture objects.
	f129F132ClearDirty(t, leaf, 11)
	for _, name := range []string{"idx_vulnerabilities_updated_at", "idx_malicious_findings_updated_at", "idx_package_reputation_cache_updated_at"} {
		f129F132Exec(t, leaf, `DROP INDEX `+f129F132QuoteIdentifier(name))
	}
	f129F132Exec(t, leaf, `DROP TABLE idx_lifecycle_products_updated_at`)
}

func f129F132AssertTombstoneCatalog(t *testing.T, leaf f129F132Leaf) {
	t.Helper()
	type column struct{ name, dataType, nullable, defaultSQL string }
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT column_name,data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name='lifecycle_sync_tombstones' ORDER BY ordinal_position`, leaf.schema)
	if err != nil {
		t.Fatalf("read tombstone columns: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var got []column
	for rows.Next() {
		var c column
		if err := rows.Scan(&c.name, &c.dataType, &c.nullable, &c.defaultSQL); err != nil {
			t.Fatalf("scan tombstone column: %v", err)
		}
		got = append(got, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate tombstone columns: %v", err)
	}
	want := []column{{"id", "text", "NO", ""}, {"ecosystem", "text", "NO", ""}, {"name", "text", "NO", ""}, {"product_slug", "text", "NO", ""}, {"cycle", "text", "NO", ""}, {"updated_at", "timestamp with time zone", "NO", "now()"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tombstone columns = %#v, want %#v", got, want)
	}
	var primaryColumns string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT string_agg(a.attname,',' ORDER BY key.ordinality)
		FROM pg_constraint c CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY key(attnum,ordinality)
		JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=key.attnum
		WHERE c.conrelid='lifecycle_sync_tombstones'::regclass AND c.contype='p' GROUP BY c.oid`).Scan(&primaryColumns); err != nil {
		t.Fatalf("inspect tombstone primary key: %v", err)
	}
	if primaryColumns != "id" {
		t.Fatalf("tombstone primary key = %q, want id", primaryColumns)
	}
	var foreignKeys int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_constraint WHERE conrelid='lifecycle_sync_tombstones'::regclass AND contype='f'`).Scan(&foreignKeys); err != nil {
		t.Fatalf("count tombstone foreign keys: %v", err)
	}
	if foreignKeys != 0 {
		t.Fatalf("tombstone foreign-key count = %d, want 0", foreignKeys)
	}
	_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle) VALUES('null-test',NULL,'name','product','1')`)
	f129F132ExpectSQLState(t, err, "23502")
}

func f129F132AssertTombstoneKeyset(t *testing.T, leaf f129F132Leaf) {
	t.Helper()
	var lower time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT clock_timestamp()`).Scan(&lower); err != nil {
		t.Fatalf("read lower PostgreSQL clock bound for tombstone default: %v", err)
	}
	f129F132Exec(t, leaf, `
		INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle,updated_at) VALUES
		('key-a','npm','a','product','1','2026-06-01T00:00:00Z'),
		('key-b','npm','b','product','1','2026-06-01T00:00:00Z'),
		('key-c','npm','c','product','1','2026-06-02T00:00:00Z')`)
	f129F132Exec(t, leaf, `INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle) VALUES('default-time','npm','d','product','1')`)
	var upper time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT clock_timestamp()`).Scan(&upper); err != nil {
		t.Fatalf("read upper PostgreSQL clock bound for tombstone default: %v", err)
	}
	var defaultTime time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT updated_at FROM lifecycle_sync_tombstones WHERE id='default-time'`).Scan(&defaultTime); err != nil {
		t.Fatalf("read tombstone default updated_at: %v", err)
	}
	if defaultTime.Before(lower) || defaultTime.After(upper) {
		t.Fatalf("tombstone default updated_at = %v, want within [%v,%v]", defaultTime, lower, upper)
	}
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT id FROM lifecycle_sync_tombstones WHERE updated_at > $1 OR (updated_at=$1 AND id>$2) ORDER BY updated_at,id LIMIT 2`, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), "key-a")
	if err != nil {
		t.Fatalf("query tombstone keyset page: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var got []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan tombstone keyset: %v", err)
		}
		got = append(got, id)
	}
	if !reflect.DeepEqual(got, []string{"key-b", "key-c"}) {
		t.Fatalf("tombstone keyset page = %v, want [key-b key-c]", got)
	}
	_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle) VALUES('key-a','npm','duplicate','product','1')`)
	f129F132ExpectSQLState(t, err, "23505")
}

func f129F132SourceXIDs(t *testing.T, leaf f129F132Leaf) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for name, query := range map[string]string{
		"vulnerability": `SELECT xmin::text FROM vulnerabilities WHERE id='F129-VULN'`,
		"malicious":     `SELECT xmin::text FROM malicious_findings WHERE id='F129-MAL'`,
		"reputation":    `SELECT xmin::text FROM package_reputation_cache WHERE name='fixture-reputation'`,
		"product":       `SELECT xmin::text FROM lifecycle_products WHERE product_slug='fixture-product'`,
		"release":       `SELECT xmin::text FROM lifecycle_releases WHERE product_slug='fixture-product' AND cycle='1'`,
		"map":           `SELECT xmin::text FROM lifecycle_package_map WHERE ecosystem='npm' AND name='fixture-package' AND product_slug='fixture-product'`,
	} {
		var xid string
		if err := leaf.conn.QueryRowContext(leaf.ctx, query).Scan(&xid); err != nil {
			t.Fatalf("read %s xmin: %v", name, err)
		}
		result[name] = xid
	}
	return result
}

func f129F132LifecycleFKs(t *testing.T, leaf f129F132Leaf) []string {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `
		SELECT c.oid::text||'|'||c.conname||'|'||c.confdeltype::text
		FROM pg_constraint c
		WHERE c.conrelid IN ('lifecycle_releases'::regclass,'lifecycle_package_map'::regclass) AND c.contype='f'
		ORDER BY c.conname`)
	if err != nil {
		t.Fatalf("read lifecycle foreign keys: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scan lifecycle foreign key: %v", err)
		}
		result = append(result, value)
	}
	return result
}

func f129F132AssertLifecycleCascade(t *testing.T, leaf f129F132Leaf) {
	t.Helper()
	f129F132Exec(t, leaf, `INSERT INTO lifecycle_products(product_slug,name) VALUES('cascade-product','Cascade Product')`)
	f129F132Exec(t, leaf, `INSERT INTO lifecycle_releases(product_slug,cycle) VALUES('cascade-product','1')`)
	f129F132Exec(t, leaf, `INSERT INTO lifecycle_package_map(ecosystem,name,product_slug) VALUES('npm','cascade-package','cascade-product')`)
	f129F132Exec(t, leaf, `DELETE FROM lifecycle_products WHERE product_slug='cascade-product'`)
	var remaining int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT (SELECT COUNT(*) FROM lifecycle_releases WHERE product_slug='cascade-product')+(SELECT COUNT(*) FROM lifecycle_package_map WHERE product_slug='cascade-product')`).Scan(&remaining); err != nil {
		t.Fatalf("count cascaded lifecycle rows: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("lifecycle rows after parent delete = %d, want 0", remaining)
	}
}

func f129F132AssertJSONPlanUsesIndex(t *testing.T, leaf f129F132Leaf, table, index string) {
	t.Helper()
	query := `EXPLAIN (FORMAT JSON, COSTS OFF) SELECT * FROM ` + f129F132QuoteIdentifier(table) + ` WHERE updated_at >= '2020-01-01T00:00:00Z'::timestamptz`
	var raw []byte
	if err := leaf.conn.QueryRowContext(leaf.ctx, query).Scan(&raw); err != nil {
		t.Fatalf("JSON EXPLAIN %s: %v", table, err)
	}
	var plan any
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("decode JSON EXPLAIN for %s: %v\n%s", table, err, raw)
	}
	if !f129F132JSONPlanContainsIndex(plan, index) {
		t.Fatalf("JSON EXPLAIN for %s does not use %s: %s", table, index, raw)
	}
}

func f129F132JSONPlanContainsIndex(value any, index string) bool {
	switch value := value.(type) {
	case map[string]any:
		if value["Index Name"] == index {
			return true
		}
		for _, child := range value {
			if f129F132JSONPlanContainsIndex(child, index) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if f129F132JSONPlanContainsIndex(child, index) {
				return true
			}
		}
	}
	return false
}

func f129F132011ObjectOIDs(t *testing.T, leaf f129F132Leaf) map[string]uint32 {
	t.Helper()
	names := []string{"lifecycle_sync_tombstones"}
	for name := range f129F132IndexTables() {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make(map[string]uint32, len(names))
	for _, name := range names {
		var oid uint32
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT to_regclass($1)::oid`, name).Scan(&oid); err != nil {
			t.Fatalf("read OID for %s: %v", name, err)
		}
		result[name] = oid
	}
	return result
}

func f129F132SeedScanLog(t *testing.T, leaf f129F132Leaf, scanID int, repo string, keyID sql.NullInt64, keyName sql.NullString) {
	t.Helper()
	if keyID.Valid {
		f129F132Exec(t, leaf, `INSERT INTO api_keys(id,name,key_hash,created_at) VALUES($1,$2,$3,'2026-01-01Z')`, keyID.Int64, keyName.String, fmt.Sprintf("hash-%d", keyID.Int64))
	}
	f129F132Exec(t, leaf, `INSERT INTO scan_log(id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version,api_key_id,api_key_name) VALUES($1,$2,$3,'2026-02-03T04:05:06Z',7,2,123,'192.0.2.12','v-fixture',$4,$5)`, scanID, fmt.Sprintf("scan-%d", scanID), repo, keyID, keyName)
}

func f129F132FixtureDropIdentity(t *testing.T, leaf f129F132Leaf, dropID, dropName bool) {
	t.Helper()
	f129F132Exec(t, leaf, `ALTER TABLE scan_log DROP CONSTRAINT IF EXISTS scan_log_api_key_id_fkey`)
	if dropID {
		f129F132Exec(t, leaf, `ALTER TABLE scan_log DROP COLUMN api_key_id`)
	}
	if dropName {
		f129F132Exec(t, leaf, `ALTER TABLE scan_log DROP COLUMN api_key_name`)
	}
}

func f129F132AssertIdentityColumns(t *testing.T, leaf f129F132Leaf, wantID, wantName bool) {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT column_name,data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name='scan_log' AND column_name IN ('api_key_id','api_key_name') ORDER BY column_name`, leaf.schema)
	if err != nil {
		t.Fatalf("read scan identity columns: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	got := make(map[string]string)
	for rows.Next() {
		var name, dataType, nullable, defaultSQL string
		if err := rows.Scan(&name, &dataType, &nullable, &defaultSQL); err != nil {
			t.Fatalf("scan identity column: %v", err)
		}
		got[name] = dataType + "|" + nullable + "|" + defaultSQL
	}
	want := make(map[string]string)
	if wantID {
		want["api_key_id"] = "integer|YES|"
	}
	if wantName {
		want["api_key_name"] = "text|YES|"
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scan identity columns = %v, want %v", got, want)
	}
}

func f129F132AssertScanIdentity(t *testing.T, leaf f129F132Leaf, id int, wantID sql.NullInt64, wantName sql.NullString) {
	t.Helper()
	var gotID sql.NullInt64
	var gotName sql.NullString
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT api_key_id,api_key_name FROM scan_log WHERE id=$1`, id).Scan(&gotID, &gotName); err != nil {
		t.Fatalf("read scan identity %d: %v", id, err)
	}
	if gotID != wantID || gotName != wantName {
		t.Fatalf("scan identity %d = id:%#v name:%#v, want id:%#v name:%#v", id, gotID, gotName, wantID, wantName)
	}
}

func f129F132ScanSnapshot(t *testing.T, leaf f129F132Leaf, includeID, includeName bool) string {
	t.Helper()
	columns := "id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version"
	if includeID {
		columns += ",api_key_id"
	}
	if includeName {
		columns += ",api_key_name"
	}
	return f129F132Snapshot(t, leaf, `SELECT `+columns+` FROM scan_log ORDER BY id`)
}

func f129F132IdentityAttnums(t *testing.T, leaf f129F132Leaf) map[string]int16 {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT attname,attnum FROM pg_attribute WHERE attrelid='scan_log'::regclass AND attname IN ('api_key_id','api_key_name') AND NOT attisdropped ORDER BY attname`)
	if err != nil {
		t.Fatalf("read scan identity attnums: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	result := make(map[string]int16)
	for rows.Next() {
		var name string
		var number int16
		if err := rows.Scan(&name, &number); err != nil {
			t.Fatalf("scan identity attnum: %v", err)
		}
		result[name] = number
	}
	return result
}

func f129F132ScanLogFK(t *testing.T, leaf f129F132Leaf) string {
	t.Helper()
	var value string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT oid::text||'|'||conname||'|'||confdeltype::text||'|'||convalidated::text FROM pg_constraint WHERE conrelid='scan_log'::regclass AND conname='scan_log_api_key_id_fkey'`).Scan(&value); err != nil {
		t.Fatalf("read scan-log API-key FK: %v", err)
	}
	if !strings.HasSuffix(value, "|n|true") {
		t.Fatalf("scan-log API-key FK = %q, want ON DELETE SET NULL and validated", value)
	}
	return value
}

func f129F132AssertCleanMetadata(t *testing.T, leaf f129F132Leaf, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read clean metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || dirty || appliedAt.IsZero() {
		t.Fatalf("clean metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
}

func f129F132AssertDirtyMetadata(t *testing.T, leaf f129F132Leaf, migration migrationFile, eventCount int) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read dirty metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || !dirty || appliedAt.Valid {
		t.Fatalf("dirty metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
	var count, failedDirty, unfinished int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE NOT success AND dirty),COUNT(*) FILTER(WHERE finished_at IS NULL) FROM schema_migration_events WHERE version=$1`, migration.version).Scan(&count, &failedDirty, &unfinished); err != nil {
		t.Fatalf("count dirty events for %s: %v", migration.name, err)
	}
	if count != eventCount || failedDirty < 1 || unfinished != 0 {
		t.Fatalf("events for %s = count:%d failed-dirty:%d unfinished:%d, want count %d with completed dirty failure", migration.name, count, failedDirty, unfinished, eventCount)
	}
}

func f129F132AssertVersion12Metadata(t *testing.T, leaf f129F132Leaf, migration migrationFile) {
	t.Helper()
	f129F132AssertCleanMetadata(t, leaf, migration)
	version, dirty, ok, err := currentVersion(leaf.ctx, leaf.conn)
	if err != nil {
		t.Fatalf("currentVersion() after %s: %v", migration.name, err)
	}
	if !ok || dirty || version != 12 {
		t.Fatalf("currentVersion() after %s = version:%d dirty:%t ok:%t, want 12 clean", migration.name, version, dirty, ok)
	}
}

func f129F132AssertEvents(t *testing.T, leaf f129F132Leaf, version int, want []f129F132MigrationEvent) {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT name,checksum,success,dirty,finished_at IS NOT NULL FROM schema_migration_events WHERE version=$1 ORDER BY id`, version)
	if err != nil {
		t.Fatalf("read migration %03d events: %v", version, err)
	}
	defer ioutils.CloseSilently(rows)
	var got []f129F132MigrationEvent
	for rows.Next() {
		var event f129F132MigrationEvent
		var finished bool
		if err := rows.Scan(&event.name, &event.checksum, &event.success, &event.dirty, &finished); err != nil {
			t.Fatalf("scan migration %03d event: %v", version, err)
		}
		if !finished {
			t.Fatalf("migration %03d event %d unfinished", version, len(got)+1)
		}
		got = append(got, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migration %03d events: %v", version, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("migration %03d events = %#v, want %#v", version, got, want)
	}
}

func f129F132AssertRunRefusesDirty(t *testing.T, leaf f129F132Leaf, version int) {
	t.Helper()
	err := RunContext(leaf.ctx, leaf.dsn)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", version)) {
		t.Fatalf("RunContext() on dirty version %d error = %v, want dirty refusal", version, err)
	}
}

func f129F132ClearDirty(t *testing.T, leaf f129F132Leaf, version int) {
	t.Helper()
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND dirty`, version)
	if err != nil {
		t.Fatalf("fixture-only dirty cleanup for version %d: %v", version, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("fixture-only dirty cleanup for version %d affected=%d err=%v, want 1", version, affected, err)
	}
}

func f129F132ExpectSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("PostgreSQL error = nil, want SQLSTATE %s", want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != want {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, want)
	}
}
