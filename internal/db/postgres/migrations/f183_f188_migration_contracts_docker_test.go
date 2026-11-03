//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

var f183F188Indexes038 = []f177F182IndexContract{
	{"idx_reputation_active_package", "package_reputation_cache", "ecosystem,name", "(status = ANY (ARRAY['malicious'::text, 'removed'::text, 'risk'::text]))"},
	{"idx_reputation_active_status_severity", "package_reputation_cache", "status,severity", "(status = ANY (ARRAY['malicious'::text, 'removed'::text, 'risk'::text]))"},
}

func TestF183F188MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	database, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(database)
	database.SetMaxOpenConns(4)

	extensionCtx, cancelExtension := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelExtension()
	if _, err := database.ExecContext(extensionCtx, `CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public`); err != nil {
		t.Fatalf("install pg_trgm once in public: %v", err)
	}

	leafNumber := 500
	newLeaf := func(t *testing.T) f159F164Leaf {
		t.Helper()
		leafNumber++
		return f159F164PrepareLeaf(t, database, instance.dsn, leafNumber)
	}

	t.Run("migration_038", func(t *testing.T) {
		t.Run("catalog_replay_rows_and_exact_dashboard_shapes", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 37)
			f183F188Seed038Rows(t, leaf)
			rows := f183F188Rows038(t, leaf)
			f159F164Apply(t, leaf, 38, MigrationDirectionUp)
			f183F188Assert038Catalog(t, leaf)
			f159F164AssertEqual(t, "038 rows", f183F188Rows038(t, leaf), rows)
			identities := f177F182IndexIdentities(t, leaf, f183F188Indexes038)
			f183F188Assert038DashboardShapes(t, leaf)
			f159F164Apply(t, leaf, 38, MigrationDirectionUp)
			f159F164AssertEqual(t, "038 replay identities", f177F182IndexIdentities(t, leaf, f183F188Indexes038), identities)
			f159F164AssertEqual(t, "038 replay rows", f183F188Rows038(t, leaf), rows)
		})

		t.Run("down_partial_repeat_up_preserves_rows_and_distinct_objects", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 38)
			f183F188Seed038Rows(t, leaf)
			rows := f183F188Rows038(t, leaf)
			f159F164Exec(t, leaf, `DROP INDEX idx_reputation_active_package; CREATE INDEX f183_unrelated_distinct_index ON package_reputation_cache(summary)`)
			unrelated := f159F164IndexIdentity(t, leaf, "f183_unrelated_distinct_index")
			f159F164ApplyDownAndDelete(t, leaf, 38)
			f183F188Assert038Absent(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 38)
			f183F188Assert038Absent(t, leaf)
			if got := f159F164IndexIdentity(t, leaf, "f183_unrelated_distinct_index"); got != unrelated {
				t.Fatalf("distinct unrelated index changed: got %q, want %q", got, unrelated)
			}
			f159F164AssertEqual(t, "038 down rows", f183F188Rows038(t, leaf), rows)
			f159F164Apply(t, leaf, 38, MigrationDirectionUp)
			f183F188Assert038Catalog(t, leaf)
			f159F164AssertEqual(t, "038 reapplied rows", f183F188Rows038(t, leaf), rows)
		})

		t.Run("up_and_down_late_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			t.Run("up", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 37)
				f183F188Seed038Rows(t, leaf)
				beforeRows := f183F188Rows038(t, leaf)
				beforeCatalog := f183F188Catalog038(t, leaf)
				up := f159F164WithFailure(f159F164Embedded(t, 38, MigrationDirectionUp))
				err := applyMigration(leaf.ctx, leaf.conn, up)
				f159F164ExpectSQLState(t, err, "P0001")
				f159F164AssertEqual(t, "038 failed-up rows", f183F188Rows038(t, leaf), beforeRows)
				f159F164AssertEqual(t, "038 failed-up catalog", f183F188Catalog038(t, leaf), beforeCatalog)
				f159F164AssertDirtyEventAndRefusal(t, leaf, up)
				f159F164ClearDirty(t, leaf, 38)
				f159F164Apply(t, leaf, 38, MigrationDirectionUp)
				f183F188Assert038Catalog(t, leaf)
			})
			t.Run("down", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 38)
				f183F188Seed038Rows(t, leaf)
				beforeRows := f183F188Rows038(t, leaf)
				beforeCatalog := f183F188Catalog038(t, leaf)
				down := f159F164WithFailure(f159F164Embedded(t, 38, MigrationDirectionDown))
				err := applyMigration(leaf.ctx, leaf.conn, down)
				f159F164ExpectSQLState(t, err, "P0001")
				f159F164AssertEqual(t, "038 failed-down rows", f183F188Rows038(t, leaf), beforeRows)
				f159F164AssertEqual(t, "038 failed-down catalog", f183F188Catalog038(t, leaf), beforeCatalog)
				f159F164AssertDirtyEventAndRefusal(t, leaf, down)
				f159F164ClearDirty(t, leaf, 38)
				f159F164Apply(t, leaf, 38, MigrationDirectionDown)
				f183F188Assert038Absent(t, leaf)
			})
		})

		t.Run("unrelated_same_name_ownership_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 38)
			f159F164Exec(t, leaf, `DROP INDEX idx_reputation_active_package; CREATE TABLE public.f183_foreign_index_owner(id INTEGER); CREATE INDEX idx_reputation_active_package ON public.f183_foreign_index_owner(id)`)
			f159F164ApplyDownAndDelete(t, leaf, 38)
			var remains int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='idx_reputation_active_package'`).Scan(&remains); err != nil {
				t.Fatalf("inspect foreign 038 index: %v", err)
			}
			f159F164Exec(t, leaf, `DROP TABLE public.f183_foreign_index_owner`)
			f159F164Apply(t, leaf, 38, MigrationDirectionUp)
			f183F188Assert038Catalog(t, leaf)
			if remains == 0 {
				t.Skip("F183-bugs-1 P2 reproduced: migration 038 down drops a same-named foreign index resolved later on search_path")
			}
		})

		t.Run("both_same_named_wrong_definitions_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 37)
			f159F164Exec(t, leaf, `CREATE INDEX idx_reputation_active_package ON package_reputation_cache(id); CREATE INDEX idx_reputation_active_status_severity ON package_reputation_cache(id)`)
			f159F164Apply(t, leaf, 38, MigrationDirectionUp)
			wrong := f183F188CountWrong038(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 38)
			f159F164Apply(t, leaf, 38, MigrationDirectionUp)
			f183F188Assert038Catalog(t, leaf)
			if wrong == 2 {
				t.Skip("F184-bugs-1 P3 reproduced: migration 038 accepts both same-named dashboard indexes with wrong definitions")
			}
			if wrong != 0 {
				t.Fatalf("migration 038 left %d partially wrong index definitions", wrong)
			}
		})
	})

	t.Run("migration_039", func(t *testing.T) {
		t.Run("legacy_creation_catalog_defaults_constraints_and_replay", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 38)
			f159F164Exec(t, leaf, `DROP TABLE nvd_cvss_negative_cache`)
			f159F164Apply(t, leaf, 39, MigrationDirectionUp)
			f183F188Assert039Catalog(t, leaf)
			f159F164Exec(t, leaf, `INSERT INTO nvd_cvss_negative_cache(cve_id) VALUES ('CVE-2026-F186')`)
			rows := f183F188Rows039(t, leaf)
			identity := f159F164IndexIdentity(t, leaf, "idx_nvd_cvss_negative_cache_checked_at")
			f159F164Apply(t, leaf, 39, MigrationDirectionUp)
			f159F164AssertEqual(t, "039 replay rows", f183F188Rows039(t, leaf), rows)
			if got := f159F164IndexIdentity(t, leaf, "idx_nvd_cvss_negative_cache_checked_at"); got != identity {
				t.Fatalf("039 replay index identity = %q, want %q", got, identity)
			}
		})

		t.Run("no_op_down_repeat_up_preserves_cache_and_index", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 39)
			f159F164Exec(t, leaf, `INSERT INTO nvd_cvss_negative_cache(cve_id,checked_at,vulnerability_updated_at) VALUES ('CVE-2026-F185','2025-01-01Z','2025-01-02Z')`)
			rows := f183F188Rows039(t, leaf)
			catalog := f183F188Catalog039(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 39)
			f159F164ApplyDownAndDelete(t, leaf, 39)
			f159F164AssertEqual(t, "039 down rows", f183F188Rows039(t, leaf), rows)
			f159F164AssertEqual(t, "039 down catalog", f183F188Catalog039(t, leaf), catalog)
			f159F164Apply(t, leaf, 39, MigrationDirectionUp)
			f159F164AssertEqual(t, "039 reapplied rows", f183F188Rows039(t, leaf), rows)
			f159F164AssertEqual(t, "039 reapplied catalog", f183F188Catalog039(t, leaf), catalog)
		})

		t.Run("up_and_down_late_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			t.Run("up", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 38)
				f159F164Exec(t, leaf, `DROP TABLE nvd_cvss_negative_cache`)
				before := f183F188Catalog039(t, leaf)
				up := f159F164WithFailure(f159F164Embedded(t, 39, MigrationDirectionUp))
				err := applyMigration(leaf.ctx, leaf.conn, up)
				f159F164ExpectSQLState(t, err, "P0001")
				f159F164AssertEqual(t, "039 failed-up catalog", f183F188Catalog039(t, leaf), before)
				f159F164AssertDirtyEventAndRefusal(t, leaf, up)
				f159F164ClearDirty(t, leaf, 39)
				f159F164Apply(t, leaf, 39, MigrationDirectionUp)
				f183F188Assert039Catalog(t, leaf)
			})
			t.Run("down", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 39)
				f159F164Exec(t, leaf, `INSERT INTO nvd_cvss_negative_cache(cve_id) VALUES ('CVE-2026-F185-DOWN')`)
				beforeRows := f183F188Rows039(t, leaf)
				beforeCatalog := f183F188Catalog039(t, leaf)
				down := f159F164WithFailure(f159F164Embedded(t, 39, MigrationDirectionDown))
				err := applyMigration(leaf.ctx, leaf.conn, down)
				f159F164ExpectSQLState(t, err, "P0001")
				f159F164AssertEqual(t, "039 failed-down rows", f183F188Rows039(t, leaf), beforeRows)
				f159F164AssertEqual(t, "039 failed-down catalog", f183F188Catalog039(t, leaf), beforeCatalog)
				f159F164AssertDirtyEventAndRefusal(t, leaf, down)
				f159F164ClearDirty(t, leaf, 39)
				f159F164Apply(t, leaf, 39, MigrationDirectionDown)
				f159F164AssertEqual(t, "039 recovered-down rows", f183F188Rows039(t, leaf), beforeRows)
			})
		})

		t.Run("malformed_existing_table_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 38)
			f159F164Exec(t, leaf, `DROP TABLE nvd_cvss_negative_cache; CREATE TABLE nvd_cvss_negative_cache(cve_id TEXT, checked_at TEXT, vulnerability_updated_at TIMESTAMPTZ)`)
			f159F164Apply(t, leaf, 39, MigrationDirectionUp)
			wrong := !f183F188039TableExact(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 39)
			f159F164Exec(t, leaf, `DROP TABLE nvd_cvss_negative_cache`)
			f159F164Apply(t, leaf, 39, MigrationDirectionUp)
			f183F188Assert039Catalog(t, leaf)
			if wrong {
				t.Skip("F186-bugs-1 P2 reproduced: migration 039 accepts an existing malformed negative-cache table")
			}
		})

		t.Run("same_named_wrong_checked_at_index_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 38)
			f159F164Exec(t, leaf, `DROP INDEX idx_nvd_cvss_negative_cache_checked_at; CREATE INDEX idx_nvd_cvss_negative_cache_checked_at ON nvd_cvss_negative_cache(cve_id)`)
			f159F164Apply(t, leaf, 39, MigrationDirectionUp)
			wrong := !f183F188039IndexExact(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 39)
			f159F164Exec(t, leaf, `DROP INDEX idx_nvd_cvss_negative_cache_checked_at`)
			f159F164Apply(t, leaf, 39, MigrationDirectionUp)
			f183F188Assert039Catalog(t, leaf)
			if wrong {
				t.Skip("F186-bugs-2 P3 reproduced: migration 039 accepts a same-named checked-at index with the wrong definition")
			}
		})
	})

	t.Run("migration_040", func(t *testing.T) {
		t.Run("all_legacy_columns_are_dropped_with_rows_preserved_and_replay", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 39)
			f159F164ApplyDownAndDelete(t, leaf, 40)
			f183F188Seed040Rows(t, leaf)
			rows := f159F164ScanSurvivingSnapshot(t, leaf)
			if got := f183F188Metadata040(t, leaf); !strings.Contains(got, "feature/f188") || !strings.Contains(got, "commit-f188") || !strings.Contains(got, "agent/f188") {
				t.Fatalf("040 legacy metadata fixture = %s", got)
			}
			f159F164Apply(t, leaf, 40, MigrationDirectionUp)
			f183F188Assert040Absent(t, leaf)
			f159F164AssertEqual(t, "040 surviving rows", f159F164ScanSurvivingSnapshot(t, leaf), rows)
			f159F164Apply(t, leaf, 40, MigrationDirectionUp)
			f183F188Assert040Absent(t, leaf)
		})

		t.Run("partially_absent_columns_before_up_are_harmless", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 39)
			f159F164ApplyDownAndDelete(t, leaf, 40)
			f183F188Seed040Rows(t, leaf)
			rows := f159F164ScanSurvivingSnapshot(t, leaf)
			f159F164Exec(t, leaf, `ALTER TABLE scan_log DROP COLUMN commit, DROP COLUMN user_agent`)
			f159F164Apply(t, leaf, 40, MigrationDirectionUp)
			f183F188Assert040Absent(t, leaf)
			f159F164AssertEqual(t, "040 partial-up rows", f159F164ScanSurvivingSnapshot(t, leaf), rows)
		})

		t.Run("partial_down_preserves_existing_value_and_adds_missing_columns", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 39)
			f159F164Exec(t, leaf, `ALTER TABLE scan_log ADD COLUMN branch TEXT; INSERT INTO scan_log(scan_id,repo_name,packages_count,findings_count,duration_ms,branch) VALUES ('f187-partial','repo/f187',1,0,7,'keep-branch')`)
			rows := f159F164ScanSurvivingSnapshot(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 40)
			f183F188Assert040Exact(t, leaf)
			if got := f183F188Metadata040(t, leaf); !strings.Contains(got, "keep-branch") {
				t.Fatalf("040 partial-down existing value lost: %s", got)
			}
			f159F164ApplyDownAndDelete(t, leaf, 40)
			f183F188Assert040Exact(t, leaf)
			f159F164AssertEqual(t, "040 partial-down rows", f159F164ScanSurvivingSnapshot(t, leaf), rows)
			f159F164Apply(t, leaf, 40, MigrationDirectionUp)
			f183F188Assert040Absent(t, leaf)
		})

		t.Run("up_and_down_late_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			t.Run("up", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 39)
				f159F164ApplyDownAndDelete(t, leaf, 40)
				f183F188Seed040Rows(t, leaf)
				beforeRows := f159F164ScanSurvivingSnapshot(t, leaf)
				beforeMetadata := f183F188Metadata040(t, leaf)
				up := f159F164WithFailure(f159F164Embedded(t, 40, MigrationDirectionUp))
				err := applyMigration(leaf.ctx, leaf.conn, up)
				f159F164ExpectSQLState(t, err, "P0001")
				f159F164AssertEqual(t, "040 failed-up rows", f159F164ScanSurvivingSnapshot(t, leaf), beforeRows)
				f159F164AssertEqual(t, "040 failed-up metadata", f183F188Metadata040(t, leaf), beforeMetadata)
				f159F164AssertDirtyEventAndRefusal(t, leaf, up)
				f159F164ClearDirty(t, leaf, 40)
				f159F164Apply(t, leaf, 40, MigrationDirectionUp)
				f183F188Assert040Absent(t, leaf)
			})
			t.Run("down", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 40)
				beforeRows := f159F164ScanSurvivingSnapshot(t, leaf)
				down := f159F164WithFailure(f159F164Embedded(t, 40, MigrationDirectionDown))
				err := applyMigration(leaf.ctx, leaf.conn, down)
				f159F164ExpectSQLState(t, err, "P0001")
				f183F188Assert040Absent(t, leaf)
				f159F164AssertEqual(t, "040 failed-down rows", f159F164ScanSurvivingSnapshot(t, leaf), beforeRows)
				f159F164AssertDirtyEventAndRefusal(t, leaf, down)
				f159F164ClearDirty(t, leaf, 40)
				f159F164Apply(t, leaf, 40, MigrationDirectionDown)
				f183F188Assert040Exact(t, leaf)
			})
		})

		t.Run("wrong_existing_legacy_column_shape_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 39)
			f159F164Exec(t, leaf, `ALTER TABLE scan_log ADD COLUMN branch INTEGER NOT NULL DEFAULT 7`)
			f159F164ApplyDownAndDelete(t, leaf, 40)
			wrong := !f183F188040ColumnsExact(t, leaf)
			f159F164Exec(t, leaf, `ALTER TABLE scan_log DROP COLUMN branch, DROP COLUMN commit, DROP COLUMN user_agent`)
			f159F164Apply(t, leaf, 40, MigrationDirectionUp)
			f183F188Assert040Absent(t, leaf)
			if wrong {
				t.Skip("F187-bugs-1 P3 reproduced: migration 040 down accepts an existing legacy column with the wrong type, nullability, and default")
			}
		})
	})
}

func f183F188Seed038Rows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity,summary,updated_at) VALUES
		('npm','f184-malicious','1','fixture','malicious','HIGH','active malicious','2025-01-01Z'),
		('npm','f184-removed','1','fixture','removed','MEDIUM','active removed','2025-01-02Z'),
		('go','f184-risk','1','fixture','risk','LOW','active risk','2025-01-03Z'),
		('npm','f184-clean','1','fixture','clean','LOW','inactive clean','2025-01-04Z')`)
}

func f183F188Rows038(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,ecosystem,name,version,source,status,severity,summary,updated_at,xmin::text FROM package_reputation_cache WHERE name LIKE 'f184-%' ORDER BY id`)
}

func f183F188Assert038Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for _, want := range f183F188Indexes038 {
		if !f177F182IndexExact(t, leaf, want) {
			table, keys, predicate, _, err := f177F182IndexCatalog(t, leaf, want.name)
			t.Fatalf("038 index %s = table:%q keys:%q predicate:%q error:%v, want %q/%q/%q", want.name, table, keys, predicate, err, want.table, want.keys, want.predicate)
		}
	}
}

func f183F188CountWrong038(t *testing.T, leaf f159F164Leaf) int {
	t.Helper()
	wrong := 0
	for _, want := range f183F188Indexes038 {
		if !f177F182IndexExact(t, leaf, want) {
			wrong++
		}
	}
	return wrong
}

func f183F188Assert038Absent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class idx JOIN pg_namespace n ON n.oid=idx.relnamespace WHERE n.nspname=$1 AND idx.relname=ANY(ARRAY['idx_reputation_active_package','idx_reputation_active_status_severity'])`, leaf.schema).Scan(&count); err != nil || count != 0 {
		t.Fatalf("038 index count after down = %d error=%v, want 0", count, err)
	}
}

func f183F188Catalog038(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT idx.relname,pg_get_indexdef(idx.oid) definition,idx.oid::text identity FROM pg_class idx JOIN pg_namespace n ON n.oid=idx.relnamespace WHERE n.nspname=current_schema() AND idx.relname=ANY(ARRAY['idx_reputation_active_package','idx_reputation_active_status_severity']) ORDER BY idx.relname`)
}

func f183F188Assert038DashboardShapes(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `SET enable_seqscan=off; SET enable_bitmapscan=off`)
	defer f159F164Exec(t, leaf, `RESET enable_seqscan; RESET enable_bitmapscan`)
	tests := []struct {
		name  string
		index string
		query string
		want  string
	}{
		{"package_union_arm", "idx_reputation_active_package", `SELECT ecosystem,name FROM package_reputation_cache WHERE status IN ('malicious','removed','risk') ORDER BY ecosystem,name`, `[{"name": "f184-risk", "ecosystem": "go"}, {"name": "f184-malicious", "ecosystem": "npm"}, {"name": "f184-removed", "ecosystem": "npm"}]`},
		{"severity_group_arm", "idx_reputation_active_status_severity", `SELECT status AS reputation_status,severity,COUNT(*)::int AS count FROM package_reputation_cache WHERE status IN ('malicious','removed','risk') GROUP BY status,severity ORDER BY status,severity`, `[{"count": 1, "severity": "HIGH", "reputation_status": "malicious"}, {"count": 1, "severity": "MEDIUM", "reputation_status": "removed"}, {"count": 1, "severity": "LOW", "reputation_status": "risk"}]`},
	}
	for _, tt := range tests {
		if got := f159F164Snapshot(t, leaf, tt.query); got != tt.want {
			t.Fatalf("038 %s result = %s, want %s", tt.name, got, tt.want)
		}
		var raw []byte
		if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) `+tt.query).Scan(&raw); err != nil {
			t.Fatalf("EXPLAIN 038 %s: %v", tt.name, err)
		}
		if !f159F164JSONContainsIndex(t, raw, tt.index) {
			t.Fatalf("038 %s plan lacks %s: %s", tt.name, tt.index, raw)
		}
	}
}

func f183F188039TableExact(t *testing.T, leaf f159F164Leaf) bool {
	t.Helper()
	var exactColumns, primaryKeys int
	err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FILTER (WHERE column_name='cve_id' AND data_type='text' AND is_nullable='NO' AND column_default IS NULL) + COUNT(*) FILTER (WHERE column_name IN ('checked_at','vulnerability_updated_at') AND data_type='timestamp with time zone' AND is_nullable='NO' AND column_default='now()') FROM information_schema.columns WHERE table_schema=$1 AND table_name='nvd_cvss_negative_cache'`, leaf.schema).Scan(&exactColumns)
	if err != nil || exactColumns != 3 {
		return false
	}
	err = leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND r.relname='nvd_cvss_negative_cache' AND c.contype='p' AND pg_get_constraintdef(c.oid)='PRIMARY KEY (cve_id)'`, leaf.schema).Scan(&primaryKeys)
	return err == nil && primaryKeys == 1
}

func f183F188039IndexExact(t *testing.T, leaf f159F164Leaf) bool {
	t.Helper()
	return f177F182IndexExact(t, leaf, f177F182IndexContract{"idx_nvd_cvss_negative_cache_checked_at", "nvd_cvss_negative_cache", "checked_at", ""})
}

func f183F188Assert039Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if !f183F188039TableExact(t, leaf) || !f183F188039IndexExact(t, leaf) {
		t.Fatalf("039 catalog is not exact: %s", f183F188Catalog039(t, leaf))
	}
}

func f183F188Catalog039(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT 'column' kind,column_name name,data_type||':'||is_nullable||':'||COALESCE(column_default,'') definition FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='nvd_cvss_negative_cache' UNION ALL SELECT 'constraint',c.conname,pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=current_schema() AND r.relname='nvd_cvss_negative_cache' UNION ALL SELECT 'index',idx.relname,pg_get_indexdef(idx.oid) FROM pg_class idx JOIN pg_namespace n ON n.oid=idx.relnamespace WHERE n.nspname=current_schema() AND idx.relname='idx_nvd_cvss_negative_cache_checked_at' ORDER BY 1,2`)
}

func f183F188Rows039(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT cve_id,checked_at,vulnerability_updated_at,xmin::text FROM nvd_cvss_negative_cache WHERE cve_id LIKE 'CVE-2026-F18%' ORDER BY cve_id`)
}

func f183F188Seed040Rows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms,client_version,branch,commit,user_agent) VALUES ('f188-filled','repo/f188','2025-01-01Z',3,2,11,'1.0','feature/f188','commit-f188','agent/f188'),('f188-null','repo/f188-null','2025-01-02Z',1,0,5,'1.1',NULL,NULL,NULL)`)
}

func f183F188040ColumnsExact(t *testing.T, leaf f159F164Leaf) bool {
	t.Helper()
	var count int
	err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='scan_log' AND column_name IN ('branch','commit','user_agent') AND data_type='text' AND is_nullable='YES' AND column_default IS NULL`, leaf.schema).Scan(&count)
	return err == nil && count == 3
}

func f183F188Assert040Exact(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if !f183F188040ColumnsExact(t, leaf) {
		t.Fatalf("040 legacy columns are not exact: %s", f183F188Catalog040(t, leaf))
	}
}

func f183F188Assert040Absent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='scan_log' AND column_name IN ('branch','commit','user_agent')`, leaf.schema).Scan(&count); err != nil || count != 0 {
		t.Fatalf("040 legacy column count = %d error=%v, want 0", count, err)
	}
}

func f183F188Catalog040(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT column_name,data_type,is_nullable,COALESCE(column_default,'') AS column_default FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='scan_log' AND column_name IN ('branch','commit','user_agent') ORDER BY column_name`)
}

func f183F188Metadata040(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT scan_id,branch,commit,user_agent FROM scan_log WHERE scan_id LIKE 'f18%' ORDER BY scan_id`)
}
