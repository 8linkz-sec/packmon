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
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f143F148Leaf struct {
	ctx    context.Context
	conn   *sql.Conn
	dsn    string
	schema string
}

type f143F148Event struct {
	name     string
	checksum string
	success  bool
	dirty    bool
}

type f143F148Index struct {
	oid        int64
	valid      bool
	ready      bool
	live       bool
	unique     bool
	method     string
	keys       []string
	opclasses  []string
	predicate  string
	definition string
}

func TestF143F148MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	database, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(database)
	database.SetMaxOpenConns(6)

	t.Run("migration_018", func(t *testing.T) {
		t.Run("empty_backfill_catalog_defaults_and_rejections", func(t *testing.T) {
			leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f143_018_empty", 2*time.Minute)
			f143F148ApplyThrough(t, leaf, 17)
			before := f143F148DatabaseClock(t, leaf)
			up := f143F148Apply(t, leaf, 18, MigrationDirectionUp)
			after := f143F148DatabaseClock(t, leaf)
			f143F148AssertCleanMetadata(t, leaf, up)
			f143F148AssertTotals(t, leaf, 0, 0, before, after)
			f143F148AssertTotalsCatalog(t, leaf)
			f143F148Exec(t, leaf, `DELETE FROM scan_log_totals`)
			beforeDefault := f143F148DatabaseClock(t, leaf)
			f143F148Exec(t, leaf, `INSERT INTO scan_log_totals DEFAULT VALUES`)
			afterDefault := f143F148DatabaseClock(t, leaf)
			f143F148AssertTotals(t, leaf, 0, 0, beforeDefault, afterDefault)

			f143F148ExpectSQLState(t, f143F148ExecError(leaf, `INSERT INTO scan_log_totals(id) VALUES(FALSE)`), "23514")
			f143F148ExpectSQLState(t, f143F148ExecError(leaf, `INSERT INTO scan_log_totals(id) VALUES(NULL)`), "23502")
			f143F148ExpectSQLState(t, f143F148ExecError(leaf, `INSERT INTO scan_log_totals DEFAULT VALUES`), "23505")
			f143F148ExpectSQLState(t, f143F148ExecError(leaf, `UPDATE scan_log_totals SET packages_scanned=-1`), "23514")
			f143F148ExpectSQLState(t, f143F148ExecError(leaf, `UPDATE scan_log_totals SET findings=-1`), "23514")
			f143F148ExpectSQLState(t, f143F148ExecError(leaf, `UPDATE scan_log_totals SET packages_scanned=NULL`), "23502")
			f143F148ExpectSQLState(t, f143F148ExecError(leaf, `UPDATE scan_log_totals SET findings=NULL`), "23502")
			f143F148ExpectSQLState(t, f143F148ExecError(leaf, `UPDATE scan_log_totals SET updated_at=NULL`), "23502")
			f143F148AssertTotals(t, leaf, 0, 0, beforeDefault, afterDefault)
		})

		t.Run("populated_bigint_backfill_down_repeat_reapply_and_preservation", func(t *testing.T) {
			leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f144_018_populated", 2*time.Minute)
			f143F148ApplyThrough(t, leaf, 17)
			f143F148SeedScans(t, leaf)
			beforeRows := f143F148ScanSnapshot(t, leaf)
			beforeClock := f143F148DatabaseClock(t, leaf)
			f143F148Apply(t, leaf, 18, MigrationDirectionUp)
			afterClock := f143F148DatabaseClock(t, leaf)
			f143F148AssertTotals(t, leaf, 4294967417, 4294967335, beforeClock, afterClock)
			f143F148AssertEqual(t, "scan rows after 018 up", f143F148ScanSnapshot(t, leaf), beforeRows)

			f143F148Apply(t, leaf, 18, MigrationDirectionDown)
			f143F148AssertRelationAbsent(t, leaf, "scan_log_totals")
			f143F148AssertEqual(t, "scan rows after 018 down", f143F148ScanSnapshot(t, leaf), beforeRows)
			f143F148Apply(t, leaf, 18, MigrationDirectionDown)
			f143F148AssertRelationAbsent(t, leaf, "scan_log_totals")
			f143F148AssertEqual(t, "scan rows after repeated 018 down", f143F148ScanSnapshot(t, leaf), beforeRows)

			beforeClock = f143F148DatabaseClock(t, leaf)
			f143F148Apply(t, leaf, 18, MigrationDirectionUp)
			afterClock = f143F148DatabaseClock(t, leaf)
			f143F148AssertTotals(t, leaf, 4294967417, 4294967335, beforeClock, afterClock)
			f143F148AssertEqual(t, "scan rows after 018 reapply", f143F148ScanSnapshot(t, leaf), beforeRows)
		})

		t.Run("injected_up_and_down_failures_are_atomic_and_audited", func(t *testing.T) {
			leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f144_018_failure", 2*time.Minute)
			f143F148ApplyThrough(t, leaf, 17)
			f143F148SeedScans(t, leaf)
			beforeRows := f143F148ScanSnapshot(t, leaf)

			up := f143F148Embedded(t, 18, MigrationDirectionUp)
			failedUp := f143F148WithFailure(up, "")
			f143F148ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedUp), "P0001")
			f143F148AssertRelationAbsent(t, leaf, "scan_log_totals")
			f143F148AssertEqual(t, "scan rows after failed 018 up", f143F148ScanSnapshot(t, leaf), beforeRows)
			f143F148AssertDirtyAndRunRefusal(t, leaf, failedUp)
			f143F148ClearDirty(t, leaf, 18)
			f143F148Apply(t, leaf, 18, MigrationDirectionUp)
			beforeTotals := f143F148Snapshot(t, leaf, `SELECT * FROM scan_log_totals`)

			down := f143F148Embedded(t, 18, MigrationDirectionDown)
			failedDown := f143F148WithFailure(down, "")
			f143F148ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedDown), "P0001")
			f143F148AssertEqual(t, "totals after failed 018 down", f143F148Snapshot(t, leaf, `SELECT * FROM scan_log_totals`), beforeTotals)
			f143F148AssertEqual(t, "scan rows after failed 018 down", f143F148ScanSnapshot(t, leaf), beforeRows)
			f143F148AssertDirtyAndRunRefusal(t, leaf, failedDown)
			f143F148ClearDirty(t, leaf, 18)
			f143F148Apply(t, leaf, 18, MigrationDirectionDown)
			f143F148AssertRelationAbsent(t, leaf, "scan_log_totals")
			f143F148AssertEvents(t, leaf, 18, []f143F148Event{
				{failedUp.name, migrationChecksum(failedUp.sql), false, true},
				{up.name, migrationChecksum(up.sql), true, false},
				{failedDown.name, migrationChecksum(failedDown.sql), false, true},
				{down.name, migrationChecksum(down.sql), true, false},
			})
		})
	})

	t.Run("migration_019", func(t *testing.T) {
		t.Run("legacy_absent_index_create_repeat_plan_and_preserve", func(t *testing.T) {
			leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f146_019_create", 2*time.Minute)
			f143F148ApplyThrough(t, leaf, 18)
			f143F148SeedVulnerabilitySources(t, leaf)
			f143F148Exec(t, leaf, `DROP INDEX idx_vuln_sources_source_vuln_id`)
			beforeRows := f143F148VulnerabilitySourceSnapshot(t, leaf)
			f143F148Apply(t, leaf, 19, MigrationDirectionUp)
			first := f143F148AssertIndex(t, leaf, "idx_vuln_sources_source_vuln_id", "vulnerability_sources", []string{"source", "vulnerability_id"}, []string{"text_ops", "text_ops"}, "(raw_json IS NOT NULL)")
			f143F148AssertEqual(t, "vulnerability sources after 019 up", f143F148VulnerabilitySourceSnapshot(t, leaf), beforeRows)
			f143F148Apply(t, leaf, 19, MigrationDirectionUp)
			second := f143F148AssertIndex(t, leaf, "idx_vuln_sources_source_vuln_id", "vulnerability_sources", []string{"source", "vulnerability_id"}, []string{"text_ops", "text_ops"}, "(raw_json IS NOT NULL)")
			if first.oid != second.oid || first.definition != second.definition {
				t.Fatalf("019 repeated up replaced or changed index: first=%+v second=%+v", first, second)
			}
			f143F148AssertEqual(t, "vulnerability sources after repeated 019 up", f143F148VulnerabilitySourceSnapshot(t, leaf), beforeRows)
			f143F148Exec(t, leaf, `ANALYZE vulnerability_sources`)
			f143F148AssertPlanUsesIndex(t, leaf, `SELECT vulnerability_id FROM vulnerability_sources WHERE source='ghsa' AND raw_json IS NOT NULL`, "idx_vuln_sources_source_vuln_id")
			var ids []string
			rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT vulnerability_id FROM vulnerability_sources WHERE source='ghsa' AND raw_json IS NOT NULL ORDER BY vulnerability_id`)
			if err != nil {
				t.Fatalf("query representative GHSA sources: %v", err)
			}
			defer ioutils.CloseSilently(rows)
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					t.Fatalf("scan representative GHSA source: %v", err)
				}
				ids = append(ids, id)
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("iterate representative GHSA sources: %v", err)
			}
			if !reflect.DeepEqual(ids, []string{"GHSA-F143-0001", "GHSA-F143-0002"}) {
				t.Fatalf("representative GHSA IDs = %#v", ids)
			}
		})

		t.Run("baseline_and_legacy_down_repeat_reapply_preserve", func(t *testing.T) {
			for _, fixture := range []struct {
				name       string
				dropBefore bool
			}{
				{name: "baseline"},
				{name: "legacy_repaired", dropBefore: true},
			} {
				leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f145_019_"+fixture.name, 2*time.Minute)
				f143F148ApplyThrough(t, leaf, 18)
				f143F148SeedVulnerabilitySources(t, leaf)
				if fixture.dropBefore {
					f143F148Exec(t, leaf, `DROP INDEX idx_vuln_sources_source_vuln_id`)
				}
				f143F148Apply(t, leaf, 19, MigrationDirectionUp)
				beforeRows := f143F148VulnerabilitySourceSnapshot(t, leaf)
				beforeIndex := f143F148AssertIndex(t, leaf, "idx_vuln_sources_source_vuln_id", "vulnerability_sources", []string{"source", "vulnerability_id"}, []string{"text_ops", "text_ops"}, "(raw_json IS NOT NULL)")
				f143F148Apply(t, leaf, 19, MigrationDirectionDown)
				f143F148Apply(t, leaf, 19, MigrationDirectionDown)
				afterDown := f143F148AssertIndex(t, leaf, "idx_vuln_sources_source_vuln_id", "vulnerability_sources", []string{"source", "vulnerability_id"}, []string{"text_ops", "text_ops"}, "(raw_json IS NOT NULL)")
				f143F148AssertEqual(t, fixture.name+" vulnerability sources after 019 downs", f143F148VulnerabilitySourceSnapshot(t, leaf), beforeRows)
				f143F148Apply(t, leaf, 19, MigrationDirectionUp)
				afterUp := f143F148AssertIndex(t, leaf, "idx_vuln_sources_source_vuln_id", "vulnerability_sources", []string{"source", "vulnerability_id"}, []string{"text_ops", "text_ops"}, "(raw_json IS NOT NULL)")
				if beforeIndex.oid != afterDown.oid || beforeIndex.oid != afterUp.oid {
					t.Fatalf("%s 019 down/up replaced retained index: before=%d down=%d up=%d", fixture.name, beforeIndex.oid, afterDown.oid, afterUp.oid)
				}
			}
		})

		t.Run("injected_up_and_down_failures_are_atomic_and_audited", func(t *testing.T) {
			leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f146_019_failure", 2*time.Minute)
			f143F148ApplyThrough(t, leaf, 18)
			f143F148SeedVulnerabilitySources(t, leaf)
			f143F148Exec(t, leaf, `DROP INDEX idx_vuln_sources_source_vuln_id`)
			beforeRows := f143F148VulnerabilitySourceSnapshot(t, leaf)
			up := f143F148Embedded(t, 19, MigrationDirectionUp)
			failedUp := f143F148WithFailure(up, "")
			f143F148ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedUp), "P0001")
			f143F148AssertRelationAbsent(t, leaf, "idx_vuln_sources_source_vuln_id")
			f143F148AssertEqual(t, "vulnerability sources after failed 019 up", f143F148VulnerabilitySourceSnapshot(t, leaf), beforeRows)
			f143F148AssertDirtyAndRunRefusal(t, leaf, failedUp)
			f143F148ClearDirty(t, leaf, 19)
			f143F148Apply(t, leaf, 19, MigrationDirectionUp)
			beforeIndex := f143F148AssertIndex(t, leaf, "idx_vuln_sources_source_vuln_id", "vulnerability_sources", []string{"source", "vulnerability_id"}, []string{"text_ops", "text_ops"}, "(raw_json IS NOT NULL)")

			down := f143F148Embedded(t, 19, MigrationDirectionDown)
			failedDown := f143F148WithFailure(down, `DROP INDEX idx_vuln_sources_source_vuln_id;`)
			f143F148ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedDown), "P0001")
			afterFailure := f143F148AssertIndex(t, leaf, "idx_vuln_sources_source_vuln_id", "vulnerability_sources", []string{"source", "vulnerability_id"}, []string{"text_ops", "text_ops"}, "(raw_json IS NOT NULL)")
			if afterFailure.oid != beforeIndex.oid {
				t.Fatalf("failed 019 down replaced index OID: before=%d after=%d", beforeIndex.oid, afterFailure.oid)
			}
			f143F148AssertEqual(t, "vulnerability sources after failed 019 down", f143F148VulnerabilitySourceSnapshot(t, leaf), beforeRows)
			f143F148AssertDirtyAndRunRefusal(t, leaf, failedDown)
			f143F148ClearDirty(t, leaf, 19)
			f143F148Apply(t, leaf, 19, MigrationDirectionDown)
			f143F148AssertEvents(t, leaf, 19, []f143F148Event{
				{failedUp.name, migrationChecksum(failedUp.sql), false, true},
				{up.name, migrationChecksum(up.sql), true, false},
				{failedDown.name, migrationChecksum(failedDown.sql), false, true},
				{down.name, migrationChecksum(down.sql), true, false},
			})
		})
	})

	t.Run("migration_020", func(t *testing.T) {
		t.Run("legacy_absent_index_create_repeat_plan_and_preserve", func(t *testing.T) {
			leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f148_020_create", 2*time.Minute)
			f143F148ApplyThrough(t, leaf, 19)
			f143F148SeedLifecycleMap(t, leaf)
			f143F148Exec(t, leaf, `DROP INDEX idx_lifecycle_package_map_product_slug`)
			beforeRows := f143F148LifecycleSnapshot(t, leaf)
			f143F148Apply(t, leaf, 20, MigrationDirectionUp)
			first := f143F148AssertIndex(t, leaf, "idx_lifecycle_package_map_product_slug", "lifecycle_package_map", []string{"product_slug"}, []string{"text_ops"}, "")
			f143F148AssertEqual(t, "lifecycle mappings after 020 up", f143F148LifecycleSnapshot(t, leaf), beforeRows)
			f143F148Apply(t, leaf, 20, MigrationDirectionUp)
			second := f143F148AssertIndex(t, leaf, "idx_lifecycle_package_map_product_slug", "lifecycle_package_map", []string{"product_slug"}, []string{"text_ops"}, "")
			if first.oid != second.oid || first.definition != second.definition {
				t.Fatalf("020 repeated up replaced or changed index: first=%+v second=%+v", first, second)
			}
			f143F148AssertEqual(t, "lifecycle mappings after repeated 020 up", f143F148LifecycleSnapshot(t, leaf), beforeRows)
			f143F148AssertPlanUsesIndex(t, leaf, `DELETE FROM lifecycle_package_map WHERE product_slug='python'`, "idx_lifecycle_package_map_product_slug")
			var count int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM lifecycle_package_map WHERE product_slug='python'`).Scan(&count); err != nil {
				t.Fatalf("count representative lifecycle mappings: %v", err)
			}
			if count != 2 {
				t.Fatalf("representative lifecycle mapping count = %d, want 2", count)
			}
		})

		t.Run("baseline_and_legacy_down_repeat_reapply_preserve", func(t *testing.T) {
			for _, fixture := range []struct {
				name       string
				dropBefore bool
			}{
				{name: "baseline"},
				{name: "legacy_repaired", dropBefore: true},
			} {
				leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f147_020_"+fixture.name, 2*time.Minute)
				f143F148ApplyThrough(t, leaf, 19)
				f143F148SeedLifecycleMap(t, leaf)
				if fixture.dropBefore {
					f143F148Exec(t, leaf, `DROP INDEX idx_lifecycle_package_map_product_slug`)
				}
				f143F148Apply(t, leaf, 20, MigrationDirectionUp)
				beforeRows := f143F148LifecycleSnapshot(t, leaf)
				beforeIndex := f143F148AssertIndex(t, leaf, "idx_lifecycle_package_map_product_slug", "lifecycle_package_map", []string{"product_slug"}, []string{"text_ops"}, "")
				f143F148Apply(t, leaf, 20, MigrationDirectionDown)
				f143F148Apply(t, leaf, 20, MigrationDirectionDown)
				afterDown := f143F148AssertIndex(t, leaf, "idx_lifecycle_package_map_product_slug", "lifecycle_package_map", []string{"product_slug"}, []string{"text_ops"}, "")
				f143F148AssertEqual(t, fixture.name+" lifecycle mappings after 020 downs", f143F148LifecycleSnapshot(t, leaf), beforeRows)
				f143F148Apply(t, leaf, 20, MigrationDirectionUp)
				afterUp := f143F148AssertIndex(t, leaf, "idx_lifecycle_package_map_product_slug", "lifecycle_package_map", []string{"product_slug"}, []string{"text_ops"}, "")
				if beforeIndex.oid != afterDown.oid || beforeIndex.oid != afterUp.oid {
					t.Fatalf("%s 020 down/up replaced retained index: before=%d down=%d up=%d", fixture.name, beforeIndex.oid, afterDown.oid, afterUp.oid)
				}
			}
		})

		t.Run("injected_up_and_down_failures_are_atomic_and_audited", func(t *testing.T) {
			leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f148_020_failure", 2*time.Minute)
			f143F148ApplyThrough(t, leaf, 19)
			f143F148SeedLifecycleMap(t, leaf)
			f143F148Exec(t, leaf, `DROP INDEX idx_lifecycle_package_map_product_slug`)
			beforeRows := f143F148LifecycleSnapshot(t, leaf)
			up := f143F148Embedded(t, 20, MigrationDirectionUp)
			failedUp := f143F148WithFailure(up, "")
			f143F148ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedUp), "P0001")
			f143F148AssertRelationAbsent(t, leaf, "idx_lifecycle_package_map_product_slug")
			f143F148AssertEqual(t, "lifecycle mappings after failed 020 up", f143F148LifecycleSnapshot(t, leaf), beforeRows)
			f143F148AssertDirtyAndRunRefusal(t, leaf, failedUp)
			f143F148ClearDirty(t, leaf, 20)
			f143F148Apply(t, leaf, 20, MigrationDirectionUp)
			beforeIndex := f143F148AssertIndex(t, leaf, "idx_lifecycle_package_map_product_slug", "lifecycle_package_map", []string{"product_slug"}, []string{"text_ops"}, "")

			down := f143F148Embedded(t, 20, MigrationDirectionDown)
			failedDown := f143F148WithFailure(down, `DROP INDEX idx_lifecycle_package_map_product_slug;`)
			f143F148ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, failedDown), "P0001")
			afterFailure := f143F148AssertIndex(t, leaf, "idx_lifecycle_package_map_product_slug", "lifecycle_package_map", []string{"product_slug"}, []string{"text_ops"}, "")
			if afterFailure.oid != beforeIndex.oid {
				t.Fatalf("failed 020 down replaced index OID: before=%d after=%d", beforeIndex.oid, afterFailure.oid)
			}
			f143F148AssertEqual(t, "lifecycle mappings after failed 020 down", f143F148LifecycleSnapshot(t, leaf), beforeRows)
			f143F148AssertDirtyAndRunRefusal(t, leaf, failedDown)
			f143F148ClearDirty(t, leaf, 20)
			f143F148Apply(t, leaf, 20, MigrationDirectionDown)
			f143F148AssertEvents(t, leaf, 20, []f143F148Event{
				{failedUp.name, migrationChecksum(failedUp.sql), false, true},
				{up.name, migrationChecksum(up.sql), true, false},
				{failedDown.name, migrationChecksum(failedDown.sql), false, true},
				{down.name, migrationChecksum(down.sql), true, false},
			})
		})
	})

	t.Run("descending_043_through_018_and_reapply", func(t *testing.T) {
		leaf := f143F148PrepareLeaf(t, database, instance.dsn, "f143_148_descending", 4*time.Minute)
		f143F148ApplyThrough(t, leaf, 17)
		f143F148SeedScans(t, leaf)
		beforeRows := f143F148BaseScanSnapshot(t, leaf)
		for version := 18; version <= 43; version++ {
			f143F148Apply(t, leaf, version, MigrationDirectionUp)
		}
		f143F148AssertRelationKind(t, leaf, "scan_log_totals", "v")
		f143F148AssertTotalsValues(t, leaf, 4294967417, 4294967335)

		for version := 43; version >= 18; version-- {
			down := f143F148Apply(t, leaf, version, MigrationDirectionDown)
			f143F148DeleteSuccessfulVersion(t, leaf, down)
			if version == 43 {
				f143F148AssertRelationKind(t, leaf, "scan_log_totals", "r")
				f143F148AssertTotalsValues(t, leaf, 4294967417, 4294967335)
			}
		}
		f143F148AssertRelationAbsent(t, leaf, "scan_log_totals")
		f143F148AssertEqual(t, "scan rows after descending 043 through 018", f143F148BaseScanSnapshot(t, leaf), beforeRows)

		for version := 18; version <= 43; version++ {
			f143F148Apply(t, leaf, version, MigrationDirectionUp)
		}
		f143F148AssertRelationKind(t, leaf, "scan_log_totals", "v")
		f143F148AssertTotalsValues(t, leaf, 4294967417, 4294967335)
		f143F148AssertEqual(t, "scan rows after 018 through 043 reapply", f143F148BaseScanSnapshot(t, leaf), beforeRows)
		for _, version := range []int{18, 19, 20} {
			up := f143F148Embedded(t, version, MigrationDirectionUp)
			down := f143F148Embedded(t, version, MigrationDirectionDown)
			f143F148AssertEvents(t, leaf, version, []f143F148Event{
				{up.name, migrationChecksum(up.sql), true, false},
				{down.name, migrationChecksum(down.sql), true, false},
				{up.name, migrationChecksum(up.sql), true, false},
			})
		}
	})
}

func f143F148PrepareLeaf(t *testing.T, database *sql.DB, baseDSN, schema string, timeout time.Duration) f143F148Leaf {
	t.Helper()
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 20*time.Second)
	if _, err := database.ExecContext(setupCtx, `CREATE SCHEMA `+quoted); err != nil {
		setupCancel()
		t.Fatalf("create isolated schema %s: %v", schema, err)
	}
	setupCancel()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if _, err := database.ExecContext(cleanupCtx, `DROP SCHEMA IF EXISTS `+quoted+` CASCADE`); err != nil {
			t.Errorf("drop isolated schema %s: %v", schema, err)
		}
	})

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := database.Conn(connectCtx)
	connectCancel()
	if err != nil {
		t.Fatalf("pin connection for schema %s: %v", schema, err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(conn) })
	setCtx, setCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if _, err := conn.ExecContext(setCtx, `SET search_path TO `+quoted); err != nil {
		setCancel()
		t.Fatalf("set search_path for schema %s: %v", schema, err)
	}
	setCancel()

	parsed, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatalf("parse migration DSN: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	leaf := f143F148Leaf{ctx: ctx, conn: conn, dsn: parsed.String(), schema: schema}
	if err := ensureVersionTable(ctx, conn); err != nil {
		t.Fatalf("ensure migration metadata in schema %s: %v", schema, err)
	}
	return leaf
}

func f143F148ApplyThrough(t *testing.T, leaf f143F148Leaf, target int) {
	t.Helper()
	for version := 1; version <= target; version++ {
		f143F148Apply(t, leaf, version, MigrationDirectionUp)
	}
}

func f143F148Embedded(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("ReadEmbeddedMigration(%03d, %s): %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f143F148Apply(t *testing.T, leaf f143F148Leaf, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	migration := f143F148Embedded(t, version, direction)
	if err := applyMigration(leaf.ctx, leaf.conn, migration); err != nil {
		t.Fatalf("apply %s: %v", migration.name, err)
	}
	return migration
}

func f143F148WithFailure(migration migrationFile, mutation string) migrationFile {
	migration.sql += "\n" + mutation + `
DO $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'fixture-only migration failure';
END $$;
`
	return migration
}

func f143F148Exec(t *testing.T, leaf f143F148Leaf, statement string, args ...any) {
	t.Helper()
	if _, err := leaf.conn.ExecContext(leaf.ctx, statement, args...); err != nil {
		t.Fatalf("execute fixture SQL: %v\nSQL:\n%s", err, statement)
	}
}

func f143F148ExecError(leaf f143F148Leaf, statement string, args ...any) error {
	_, err := leaf.conn.ExecContext(leaf.ctx, statement, args...)
	return err
}

func f143F148SeedScans(t *testing.T, leaf f143F148Leaf) {
	t.Helper()
	f143F148Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version) VALUES
		('f143-zero','org/zero','2026-01-01T00:00:00Z',0,0,0,'192.0.2.1','packmon/f143'),
		('f143-max-one','org/max-one','2026-01-02T00:00:00Z',2147483647,2147483647,1,'192.0.2.2','packmon/f143'),
		('f143-max-two','org/max-two','2026-01-03T00:00:00Z',2147483647,2147483647,2,'192.0.2.3','packmon/f143'),
		('f143-tail','org/tail','2026-01-04T00:00:00Z',123,41,3,'192.0.2.4','packmon/f143')`)
}

func f143F148SeedVulnerabilitySources(t *testing.T, leaf f143F148Leaf) {
	t.Helper()
	f143F148Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES
		('GHSA-F143-0001','first','HIGH','2026-01-01Z','2026-01-02Z'),
		('GHSA-F143-0002','second','MEDIUM','2026-02-01Z','2026-02-02Z'),
		('CVE-2026-F143','third','LOW','2026-03-01Z','2026-03-02Z')`)
	f143F148Exec(t, leaf, `INSERT INTO vulnerability_sources(vulnerability_id,source,source_id,url,raw_json,updated_at) VALUES
		('GHSA-F143-0001','ghsa','GHSA-F143-0001','https://example.test/one','{"fixture":1}','2026-04-01Z'),
		('GHSA-F143-0002','ghsa','GHSA-F143-0002','https://example.test/two','{"fixture":2}','2026-04-02Z'),
		('CVE-2026-F143','osv','OSV-F143',NULL,NULL,'2026-04-03Z')`)
}

func f143F148SeedLifecycleMap(t *testing.T, leaf f143F148Leaf) {
	t.Helper()
	f143F148Exec(t, leaf, `INSERT INTO lifecycle_products(product_slug,name,category,source,identifiers,raw,updated_at) VALUES
		('python','Python','runtime','endoflife.date','[]','{}','2026-05-01Z'),
		('nodejs','Node.js','runtime','endoflife.date','[]','{}','2026-05-02Z')`)
	f143F148Exec(t, leaf, `INSERT INTO lifecycle_package_map(ecosystem,name,product_slug,purl_type,purl_namespace,purl_name,source,updated_at) VALUES
		('pypi','python','python','pypi','','python','endoflife.date','2026-05-03Z'),
		('docker','python','python','docker','library','python','endoflife.date','2026-05-04Z'),
		('npm','node','nodejs','npm','','node','endoflife.date','2026-05-05Z')`)
}

func f143F148Snapshot(t *testing.T, leaf f143F148Leaf, query string) string {
	t.Helper()
	var value string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(snapshot_row)),'[]'::jsonb)::text FROM (`+query+`) snapshot_row`).Scan(&value); err != nil {
		t.Fatalf("snapshot query: %v\nSQL:\n%s", err, query)
	}
	return value
}

func f143F148ScanSnapshot(t *testing.T, leaf f143F148Leaf) string {
	t.Helper()
	return f143F148Snapshot(t, leaf, `SELECT id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version,api_key_id,api_key_name,xmin::text AS xmin FROM scan_log ORDER BY id`)
}

func f143F148BaseScanSnapshot(t *testing.T, leaf f143F148Leaf) string {
	t.Helper()
	return f143F148Snapshot(t, leaf, `SELECT id,scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_ip,client_version,api_key_id,api_key_name FROM scan_log ORDER BY id`)
}

func f143F148VulnerabilitySourceSnapshot(t *testing.T, leaf f143F148Leaf) string {
	t.Helper()
	return f143F148Snapshot(t, leaf, `SELECT id,vulnerability_id,source,source_id,url,raw_json,updated_at,xmin::text AS xmin FROM vulnerability_sources ORDER BY id`)
}

func f143F148LifecycleSnapshot(t *testing.T, leaf f143F148Leaf) string {
	t.Helper()
	return f143F148Snapshot(t, leaf, `SELECT ecosystem,name,product_slug,purl_type,purl_namespace,purl_name,source,updated_at,xmin::text AS xmin FROM lifecycle_package_map ORDER BY ecosystem,name,product_slug`)
}

func f143F148DatabaseClock(t *testing.T, leaf f143F148Leaf) time.Time {
	t.Helper()
	var value time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT clock_timestamp()`).Scan(&value); err != nil {
		t.Fatalf("read database clock: %v", err)
	}
	return value
}

func f143F148AssertTotals(t *testing.T, leaf f143F148Leaf, packages, findings int64, earliest, latest time.Time) {
	t.Helper()
	var id bool
	var gotPackages, gotFindings int64
	var updated time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT id,packages_scanned,findings,updated_at FROM scan_log_totals`).Scan(&id, &gotPackages, &gotFindings, &updated); err != nil {
		t.Fatalf("read scan_log_totals: %v", err)
	}
	if !id || gotPackages != packages || gotFindings != findings || updated.Before(earliest) || updated.After(latest) {
		t.Fatalf("scan_log_totals = id:%t packages:%d findings:%d updated:%v, want true/%d/%d within [%v,%v]", id, gotPackages, gotFindings, updated, packages, findings, earliest, latest)
	}
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM scan_log_totals`).Scan(&count); err != nil {
		t.Fatalf("count scan_log_totals: %v", err)
	}
	if count != 1 {
		t.Fatalf("scan_log_totals row count = %d, want 1", count)
	}
}

func f143F148AssertTotalsValues(t *testing.T, leaf f143F148Leaf, packages, findings int64) {
	t.Helper()
	var id bool
	var gotPackages, gotFindings int64
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT id,packages_scanned,findings FROM scan_log_totals`).Scan(&id, &gotPackages, &gotFindings); err != nil {
		t.Fatalf("read scan_log_totals values: %v", err)
	}
	if !id || gotPackages != packages || gotFindings != findings {
		t.Fatalf("scan_log_totals values = id:%t packages:%d findings:%d, want true/%d/%d", id, gotPackages, gotFindings, packages, findings)
	}
}

func f143F148AssertTotalsCatalog(t *testing.T, leaf f143F148Leaf) {
	t.Helper()
	wantColumns := map[string][3]string{
		"id":               {"boolean", "NO", "true"},
		"packages_scanned": {"bigint", "NO", "0"},
		"findings":         {"bigint", "NO", "0"},
		"updated_at":       {"timestamp with time zone", "NO", "now()"},
	}
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT column_name,data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name='scan_log_totals' ORDER BY ordinal_position`, leaf.schema)
	if err != nil {
		t.Fatalf("read scan_log_totals columns: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	gotColumns := make(map[string][3]string)
	for rows.Next() {
		var name, dataType, nullable, defaultSQL string
		if err := rows.Scan(&name, &dataType, &nullable, &defaultSQL); err != nil {
			t.Fatalf("scan scan_log_totals column: %v", err)
		}
		gotColumns[name] = [3]string{dataType, nullable, defaultSQL}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate scan_log_totals columns: %v", err)
	}
	if !reflect.DeepEqual(gotColumns, wantColumns) {
		t.Fatalf("scan_log_totals columns = %#v, want %#v", gotColumns, wantColumns)
	}

	wantConstraints := map[string]string{
		"scan_log_totals_pkey":                      "PRIMARY KEY (id)",
		"scan_log_totals_packages_scanned_check":    "CHECK ((packages_scanned >= 0))",
		"scan_log_totals_findings_check":            "CHECK ((findings >= 0))",
		"scan_log_totals_singleton":                 "CHECK (id)",
		"scan_log_totals_id_not_null":               "NOT NULL id",
		"scan_log_totals_packages_scanned_not_null": "NOT NULL packages_scanned",
		"scan_log_totals_findings_not_null":         "NOT NULL findings",
		"scan_log_totals_updated_at_not_null":       "NOT NULL updated_at",
	}
	rows, err = leaf.conn.QueryContext(leaf.ctx, `SELECT conname,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='scan_log_totals'::regclass ORDER BY conname`)
	if err != nil {
		t.Fatalf("read scan_log_totals constraints: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	gotConstraints := make(map[string]string)
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			t.Fatalf("scan scan_log_totals constraint: %v", err)
		}
		gotConstraints[name] = strings.Join(strings.Fields(definition), " ")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate scan_log_totals constraints: %v", err)
	}
	if !reflect.DeepEqual(gotConstraints, wantConstraints) {
		t.Fatalf("scan_log_totals constraints = %#v, want %#v", gotConstraints, wantConstraints)
	}
}

func f143F148AssertIndex(t *testing.T, leaf f143F148Leaf, name, table string, wantKeys, wantOpclasses []string, wantPredicate string) f143F148Index {
	t.Helper()
	var got f143F148Index
	var keys, opclasses string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT i.indexrelid::bigint,i.indisvalid,i.indisready,i.indislive,i.indisunique,am.amname,
			array_to_string(ARRAY(SELECT pg_get_indexdef(i.indexrelid,key_position,true) FROM generate_series(1,i.indnkeyatts) key_position ORDER BY key_position),'|'),
			array_to_string(ARRAY(SELECT opc.opcname FROM unnest(i.indclass::oid[]) WITH ORDINALITY classes(opcoid,position) JOIN pg_opclass opc ON opc.oid=classes.opcoid ORDER BY classes.position),'|'),
			COALESCE(pg_get_expr(i.indpred,i.indrelid),''),pg_get_indexdef(i.indexrelid)
		FROM pg_index i
		JOIN pg_class index_relation ON index_relation.oid=i.indexrelid
		JOIN pg_class table_relation ON table_relation.oid=i.indrelid
		JOIN pg_namespace table_namespace ON table_namespace.oid=table_relation.relnamespace
		JOIN pg_am am ON am.oid=index_relation.relam
		WHERE table_namespace.nspname=$1 AND table_relation.relname=$2 AND index_relation.relname=$3`, leaf.schema, table, name).Scan(&got.oid, &got.valid, &got.ready, &got.live, &got.unique, &got.method, &keys, &opclasses, &got.predicate, &got.definition); err != nil {
		t.Fatalf("inspect index %s on %s: %v", name, table, err)
	}
	if keys != "" {
		got.keys = strings.Split(keys, "|")
	}
	if opclasses != "" {
		got.opclasses = strings.Split(opclasses, "|")
	}
	got.predicate = strings.Join(strings.Fields(got.predicate), " ")
	got.definition = strings.Join(strings.Fields(got.definition), " ")
	if !got.valid || !got.ready || !got.live || got.unique || got.method != "btree" || !reflect.DeepEqual(got.keys, wantKeys) || !reflect.DeepEqual(got.opclasses, wantOpclasses) || got.predicate != wantPredicate {
		t.Fatalf("index %s catalog = %+v, want valid/ready/live nonunique btree keys=%v opclasses=%v predicate=%q", name, got, wantKeys, wantOpclasses, wantPredicate)
	}
	wantDefinition := "CREATE INDEX " + name + " ON " + leaf.schema + "." + table + " USING btree (" + strings.Join(wantKeys, ", ") + ")"
	if wantPredicate != "" {
		wantDefinition += " WHERE " + wantPredicate
	}
	if got.definition != wantDefinition {
		t.Fatalf("index %s definition = %q, want %q", name, got.definition, wantDefinition)
	}
	return got
}

func f143F148AssertPlanUsesIndex(t *testing.T, leaf f143F148Leaf, query, indexName string) {
	t.Helper()
	f143F148Exec(t, leaf, `SET enable_seqscan TO off`)
	t.Cleanup(func() {
		resetCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = leaf.conn.ExecContext(resetCtx, `RESET enable_seqscan`)
	})
	var raw []byte
	if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON, COSTS OFF) `+query).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN representative query: %v", err)
	}
	var plan any
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("decode JSON EXPLAIN: %v", err)
	}
	if !f143F148JSONContainsIndex(plan, indexName) {
		t.Fatalf("JSON EXPLAIN does not use %s: %s", indexName, raw)
	}
}

func f143F148JSONContainsIndex(value any, indexName string) bool {
	switch typed := value.(type) {
	case map[string]any:
		if name, ok := typed["Index Name"].(string); ok && name == indexName {
			return true
		}
		for _, child := range typed {
			if f143F148JSONContainsIndex(child, indexName) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if f143F148JSONContainsIndex(child, indexName) {
				return true
			}
		}
	}
	return false
}

func f143F148AssertRelationAbsent(t *testing.T, leaf f143F148Leaf, name string) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace WHERE namespace.nspname=$1 AND relation.relname=$2`, leaf.schema, name).Scan(&count); err != nil {
		t.Fatalf("inspect absent relation %s: %v", name, err)
	}
	if count != 0 {
		t.Fatalf("relation %s count = %d, want 0", name, count)
	}
}

func f143F148AssertRelationKind(t *testing.T, leaf f143F148Leaf, name, want string) {
	t.Helper()
	var kind string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT relation.relkind::text FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace WHERE namespace.nspname=$1 AND relation.relname=$2`, leaf.schema, name).Scan(&kind); err != nil {
		t.Fatalf("inspect relation %s: %v", name, err)
	}
	if kind != want {
		t.Fatalf("relation %s kind = %q, want %q", name, kind, want)
	}
}

func f143F148AssertCleanMetadata(t *testing.T, leaf f143F148Leaf, migration migrationFile) {
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

func f143F148AssertDirtyAndRunRefusal(t *testing.T, leaf f143F148Leaf, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read dirty metadata for %s: %v", migration.name, err)
	}
	wantChecksum := migrationChecksum(migration.sql)
	if name != migration.name || checksum != wantChecksum || !dirty || appliedAt.Valid {
		t.Fatalf("dirty metadata for %s = name:%q checksum:%q dirty:%t applied:%v, want checksum %q", migration.name, name, checksum, dirty, appliedAt, wantChecksum)
	}
	var matching, unfinished int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FILTER(WHERE name=$2 AND checksum=$3 AND NOT success AND dirty),COUNT(*) FILTER(WHERE finished_at IS NULL) FROM schema_migration_events WHERE version=$1`, migration.version, migration.name, wantChecksum).Scan(&matching, &unfinished); err != nil {
		t.Fatalf("read dirty event for %s: %v", migration.name, err)
	}
	if matching != 1 || unfinished != 0 {
		t.Fatalf("dirty event for %s = matching:%d unfinished:%d, want 1/0", migration.name, matching, unfinished)
	}
	err := RunContext(leaf.ctx, leaf.dsn)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", migration.version)) {
		t.Fatalf("RunContext() dirty refusal for version %d = %v", migration.version, err)
	}
}

func f143F148ClearDirty(t *testing.T, leaf f143F148Leaf, version int) {
	t.Helper()
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND dirty`, version)
	if err != nil {
		t.Fatalf("clear dirty marker %d: %v", version, err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil || affected != 1 {
		t.Fatalf("clear dirty marker %d affected=%d error=%v, want 1", version, affected, rowsErr)
	}
}

func f143F148DeleteSuccessfulVersion(t *testing.T, leaf f143F148Leaf, migration migrationFile) {
	t.Helper()
	f143F148AssertCleanMetadata(t, leaf, migration)
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND name=$2 AND checksum=$3 AND NOT dirty`, migration.version, migration.name, migrationChecksum(migration.sql))
	if err != nil {
		t.Fatalf("delete successful metadata for %s: %v", migration.name, err)
	}
	affected, rowsErr := result.RowsAffected()
	if rowsErr != nil || affected != 1 {
		t.Fatalf("delete successful metadata for %s affected=%d error=%v, want 1", migration.name, affected, rowsErr)
	}
}

func f143F148AssertEvents(t *testing.T, leaf f143F148Leaf, version int, want []f143F148Event) {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT name,checksum,success,dirty,finished_at IS NOT NULL FROM schema_migration_events WHERE version=$1 ORDER BY id`, version)
	if err != nil {
		t.Fatalf("read migration %d events: %v", version, err)
	}
	defer ioutils.CloseSilently(rows)
	got := make([]f143F148Event, 0, len(want))
	for rows.Next() {
		var event f143F148Event
		var finished bool
		if err := rows.Scan(&event.name, &event.checksum, &event.success, &event.dirty, &finished); err != nil {
			t.Fatalf("scan migration %d event: %v", version, err)
		}
		if !finished {
			t.Fatalf("migration %d event %d is unfinished", version, len(got)+1)
		}
		got = append(got, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migration %d events: %v", version, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("migration %d events = %#v, want %#v", version, got, want)
	}
}

func f143F148ExpectSQLState(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("PostgreSQL error = nil, want SQLSTATE %s", want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) || state.SQLState() != want {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, want)
	}
}

func f143F148AssertEqual(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s changed\ngot:  %s\nwant: %s", label, got, want)
	}
}
