//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

var f171F176VersionConstraints = []string{
	"affected_packages_version_ranges_array_check",
	"affected_packages_versions_affected_array_check",
	"malicious_findings_version_ranges_array_check",
	"malicious_findings_versions_array_check",
}

var f171F176FeedConstraints = []string{
	"feed_sync_status_status_check",
	"feed_sync_status_entries_nonnegative_check",
	"feed_sync_status_entries_order_check",
	"feed_sync_status_duration_nonnegative_check",
}

func TestF171F176MigrationContractsAgainstPostgres(t *testing.T) {
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

	leafNumber := 300
	newLeaf := func(t *testing.T) f159F164Leaf {
		t.Helper()
		leafNumber++
		return f159F164PrepareLeaf(t, database, instance.dsn, leafNumber)
	}

	t.Run("migration_032", func(t *testing.T) {
		t.Run("dirty_repair_validator_truth_tables_catalog_enforcement_and_replay", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 31)
			f171F176Drop032Checks(t, leaf)
			f171F176Seed032Dirty(t, leaf)
			beforeVersions := f171F176032RowVersions(t, leaf)

			f159F164Apply(t, leaf, 32, MigrationDirectionUp)
			f171F176Assert032Catalog(t, leaf)
			f171F176Assert032Repairs(t, leaf)
			f171F176Assert032RepairVersions(t, beforeVersions, f171F176032RowVersions(t, leaf))
			f171F176Assert032TruthTables(t, leaf)
			f171F176Assert032Enforcement(t, leaf)
			stable := f159F164Snapshot(t, leaf, `SELECT 'a',id,version_ranges,versions_affected,updated_at,xmin::text FROM affected_packages UNION ALL SELECT 'm',0,version_ranges,versions,updated_at,xmin::text FROM malicious_findings WHERE id='f171-dirty' ORDER BY 1,2`)
			f159F164Apply(t, leaf, 32, MigrationDirectionUp)
			f159F164AssertEqual(t, "032 replay rows", f159F164Snapshot(t, leaf, `SELECT 'a',id,version_ranges,versions_affected,updated_at,xmin::text FROM affected_packages UNION ALL SELECT 'm',0,version_ranges,versions,updated_at,xmin::text FROM malicious_findings WHERE id='f171-dirty' ORDER BY 1,2`), stable)
		})

		t.Run("down_repeat_reapply_preserves_rows_and_dependency_order", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 32)
			f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('f172-round','round','LOW','2025-01-01Z','2025-01-01Z'); INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected) VALUES ('f172-round','npm','round','[{"events":[{"introduced":"0"}]}]','["1"]')`)
			rows := f159F164Snapshot(t, leaf, `SELECT vulnerability_id,ecosystem,name,version_ranges,versions_affected FROM affected_packages WHERE vulnerability_id='f172-round'`)
			f159F164ApplyDownAndDelete(t, leaf, 32)
			f171F176Assert032Absent(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 32)
			f171F176Assert032Absent(t, leaf)
			f159F164AssertEqual(t, "032 down rows", f159F164Snapshot(t, leaf, `SELECT vulnerability_id,ecosystem,name,version_ranges,versions_affected FROM affected_packages WHERE vulnerability_id='f172-round'`), rows)
			f159F164Apply(t, leaf, 32, MigrationDirectionUp)
			f171F176Assert032Catalog(t, leaf)
			f159F164AssertEqual(t, "032 reapplied rows", f159F164Snapshot(t, leaf, `SELECT vulnerability_id,ecosystem,name,version_ranges,versions_affected FROM affected_packages WHERE vulnerability_id='f172-round'`), rows)
		})

		t.Run("up_late_failure_is_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 31)
			f171F176Drop032Checks(t, leaf)
			f171F176Seed032Dirty(t, leaf)
			beforeRows := f171F176032Rows(t, leaf)
			beforeCatalog := f171F176032Catalog(t, leaf)
			up := f159F164Embedded(t, 32, MigrationDirectionUp)
			up.sql += `; INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected) VALUES ('f171-vuln','npm','late-failure','[]',NULL);`
			err := applyMigration(leaf.ctx, leaf.conn, up)
			f159F164ExpectSQLState(t, err, "23502")
			f159F164AssertEqual(t, "032 failed-up rows", f171F176032Rows(t, leaf), beforeRows)
			f159F164AssertEqual(t, "032 failed-up catalog", f171F176032Catalog(t, leaf), beforeCatalog)
			f159F164AssertDirtyEventAndRefusal(t, leaf, up)
			f159F164ClearDirty(t, leaf, 32)
			f159F164Apply(t, leaf, 32, MigrationDirectionUp)
			f171F176Assert032Catalog(t, leaf)
		})

		t.Run("down_extra_dependency_failure_is_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 32)
			f159F164Exec(t, leaf, `ALTER TABLE malicious_findings ADD CONSTRAINT f172_extra_validator_dependency CHECK (packmon_jsonb_string_array_valid(versions))`)
			before := f171F176032Catalog(t, leaf)
			down := f159F164Embedded(t, 32, MigrationDirectionDown)
			err := applyMigration(leaf.ctx, leaf.conn, down)
			f159F164ExpectSQLState(t, err, "2BP01")
			f159F164AssertEqual(t, "032 failed-down catalog", f171F176032Catalog(t, leaf), before)
			f159F164AssertDirtyEventAndRefusal(t, leaf, down)
			f159F164ClearDirty(t, leaf, 32)
			f159F164Exec(t, leaf, `ALTER TABLE malicious_findings DROP CONSTRAINT f172_extra_validator_dependency`)
			f159F164Apply(t, leaf, 32, MigrationDirectionDown)
			f171F176Assert032Absent(t, leaf)
		})
	})

	t.Run("migration_033", func(t *testing.T) {
		t.Run("legacy_upgrade_source_scoped_catalog_fk_index_and_replay", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 32)
			f171F176Make033Legacy(t, leaf)
			f159F164Exec(t, leaf, `
					INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES
						('f173-legacy','legacy','LOW','2025-01-01Z','2025-01-01Z'),
						('f173-independent','independent','LOW','2025-01-01Z','2025-01-01Z');
					INSERT INTO vulnerability_references(vulnerability_id,type,url,source) VALUES
						('f173-legacy','ADVISORY','https://example.test/legacy',NULL),
						('f173-legacy','REPORT','https://example.test/preserved','kept')`)
			fkIndex := f171F176033FKIndex(t, leaf)
			f159F164Apply(t, leaf, 33, MigrationDirectionUp)
			f171F176Assert033Catalog(t, leaf)
			if got := f171F176033FKIndex(t, leaf); got != fkIndex {
				t.Fatalf("033 FK/index changed: got %q, want %q", got, fkIndex)
			}
			if got := f159F164Snapshot(t, leaf, `SELECT vulnerability_id,type,url,source FROM vulnerability_references WHERE vulnerability_id='f173-legacy' ORDER BY url`); got != `[{"url": "https://example.test/legacy", "type": "ADVISORY", "source": "", "vulnerability_id": "f173-legacy"}, {"url": "https://example.test/preserved", "type": "REPORT", "source": "kept", "vulnerability_id": "f173-legacy"}]` {
				t.Fatalf("033 normalized and preserved legacy rows = %s", got)
			}
			f159F164Exec(t, leaf, `INSERT INTO vulnerability_references(vulnerability_id,type,url) VALUES ('f173-legacy','WEB','https://example.test/defaulted')`)
			if got := f159F164Snapshot(t, leaf, `SELECT type,url,source FROM vulnerability_references WHERE vulnerability_id='f173-legacy' AND url='https://example.test/defaulted'`); got != `[{"url": "https://example.test/defaulted", "type": "WEB", "source": ""}]` {
				t.Fatalf("033 omitted source default row = %s", got)
			}
			_, err := leaf.conn.ExecContext(leaf.ctx, `INSERT INTO vulnerability_references(vulnerability_id,type,url,source) VALUES ('f173-legacy','WEB','https://example.test/null-rejected',NULL)`)
			f159F164ExpectSQLState(t, err, "23502")
			_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO vulnerability_references(vulnerability_id,type,url,source) VALUES ('f173-legacy','OTHER','https://example.test/preserved','kept')`)
			f159F164ExpectSQLState(t, err, "23505")
			f159F164Exec(t, leaf, `
					INSERT INTO vulnerability_references(vulnerability_id,type,url,source) VALUES
						('f173-legacy','OTHER','https://example.test/legacy','other'),
						('f173-independent','WEB','https://example.test/preserved','kept')`)
			stableRows := f159F164Snapshot(t, leaf, `SELECT id,vulnerability_id,type,url,source,xmin::text FROM vulnerability_references WHERE vulnerability_id IN ('f173-legacy','f173-independent') ORDER BY vulnerability_id,id`)
			f159F164Apply(t, leaf, 33, MigrationDirectionUp)
			f171F176Assert033Catalog(t, leaf)
			f159F164AssertEqual(t, "033 replay reference rows", f159F164Snapshot(t, leaf, `SELECT id,vulnerability_id,type,url,source,xmin::text FROM vulnerability_references WHERE vulnerability_id IN ('f173-legacy','f173-independent') ORDER BY vulnerability_id,id`), stableRows)
		})

		t.Run("populated_down_repeat_up_round_trip_preserves_min_id_and_irreversible_loss", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 33)
			f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('f174-round','round','LOW','2025-01-01Z','2025-01-01Z'); INSERT INTO vulnerability_references(id,vulnerability_id,type,url,source) VALUES (3301,'f174-round','ADVISORY','https://example.test/same','a'),(3302,'f174-round','WEB','https://example.test/same','b'),(3303,'f174-round','REPORT','https://example.test/same','c'),(3304,'f174-round','PACKAGE','https://example.test/other','z')`)
			f159F164ApplyDownAndDelete(t, leaf, 33)
			f171F176Assert033Legacy(t, leaf)
			if got := f159F164Snapshot(t, leaf, `SELECT id,vulnerability_id,type,url,source FROM vulnerability_references WHERE vulnerability_id='f174-round' ORDER BY id`); got != `[{"id": 3301, "url": "https://example.test/same", "type": "ADVISORY", "source": "a", "vulnerability_id": "f174-round"}, {"id": 3304, "url": "https://example.test/other", "type": "PACKAGE", "source": "z", "vulnerability_id": "f174-round"}]` {
				t.Fatalf("033 down rows = %s", got)
			}
			f159F164Exec(t, leaf, `
					INSERT INTO vulnerability_references(vulnerability_id,type,url) VALUES ('f174-round','OMITTED','https://example.test/omitted');
					INSERT INTO vulnerability_references(vulnerability_id,type,url,source) VALUES ('f174-round','EXPLICIT_NULL','https://example.test/explicit-null',NULL)`)
			if got := f159F164Snapshot(t, leaf, `SELECT type,url,source FROM vulnerability_references WHERE vulnerability_id='f174-round' AND type IN ('OMITTED','EXPLICIT_NULL') ORDER BY type`); got != `[{"url": "https://example.test/explicit-null", "type": "EXPLICIT_NULL", "source": null}, {"url": "https://example.test/omitted", "type": "OMITTED", "source": null}]` {
				t.Fatalf("033 legacy NULL source inserts = %s", got)
			}
			_, err := leaf.conn.ExecContext(leaf.ctx, `INSERT INTO vulnerability_references(vulnerability_id,type,url,source) VALUES ('f174-round','CROSS_SOURCE','https://example.test/same','different')`)
			f159F164ExpectSQLState(t, err, "23505")
			f159F164ApplyDownAndDelete(t, leaf, 33)
			f159F164Apply(t, leaf, 33, MigrationDirectionUp)
			f171F176Assert033Catalog(t, leaf)
			if got := f159F164Snapshot(t, leaf, `SELECT type,url,source FROM vulnerability_references WHERE vulnerability_id='f174-round' AND type IN ('OMITTED','EXPLICIT_NULL') ORDER BY type`); got != `[{"url": "https://example.test/explicit-null", "type": "EXPLICIT_NULL", "source": ""}, {"url": "https://example.test/omitted", "type": "OMITTED", "source": ""}]` {
				t.Fatalf("033 re-up normalized legacy NULL sources = %s", got)
			}
			var lost int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM vulnerability_references WHERE id IN (3302,3303)`).Scan(&lost); err != nil || lost != 0 {
				t.Fatalf("irreversibly lost higher IDs count=%d error=%v, want 0", lost, err)
			}
		})

		t.Run("down_reference_dependency_failure_is_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 33)
			f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('f174-dep','dep','LOW','2025-01-01Z','2025-01-01Z'); INSERT INTO vulnerability_references(id,vulnerability_id,type,url,source) VALUES (3311,'f174-dep','WEB','https://example.test/dep','a'),(3312,'f174-dep','WEB','https://example.test/dep','b'); CREATE TABLE f174_reference_dependency(reference_id INTEGER NOT NULL REFERENCES vulnerability_references(id)); INSERT INTO f174_reference_dependency VALUES (3312)`)
			before := f159F164Snapshot(t, leaf, `SELECT id,url,source FROM vulnerability_references WHERE vulnerability_id='f174-dep' ORDER BY id`)
			down := f159F164Embedded(t, 33, MigrationDirectionDown)
			err := applyMigration(leaf.ctx, leaf.conn, down)
			f159F164ExpectSQLState(t, err, "23503")
			f159F164AssertEqual(t, "033 failed-down rows", f159F164Snapshot(t, leaf, `SELECT id,url,source FROM vulnerability_references WHERE vulnerability_id='f174-dep' ORDER BY id`), before)
			f171F176Assert033Catalog(t, leaf)
			f159F164AssertDirtyEventAndRefusal(t, leaf, down)
			f159F164ClearDirty(t, leaf, 33)
			f159F164Exec(t, leaf, `DROP TABLE f174_reference_dependency`)
			f159F164Apply(t, leaf, 33, MigrationDirectionDown)
			f171F176Assert033Legacy(t, leaf)
		})
	})

	t.Run("migration_034", func(t *testing.T) {
		t.Run("legacy_repairs_constraints_existing_objects_replay_export_and_plan_eligibility", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 33)
			f171F176Drop034Objects(t, leaf)
			f171F176Seed034Dirty(t, leaf)
			f159F164Exec(t, leaf, `ALTER TABLE feed_sync_status ADD CONSTRAINT feed_sync_status_status_check CHECK (last_sync_status IN ('pending','running','success','error','skipped','disabled','external','rejected','permanent_error')) NOT VALID; ALTER TABLE feed_sync_status ADD CONSTRAINT feed_sync_status_entries_nonnegative_check CHECK (entries_synced >= 0 AND entries_total >= 0) NOT VALID`)
			statusOID := f171F176ConstraintOID(t, leaf, "feed_sync_status_status_check")
			countOID := f171F176ConstraintOID(t, leaf, "feed_sync_status_entries_nonnegative_check")
			f159F164Apply(t, leaf, 34, MigrationDirectionUp)
			f171F176Assert034Repairs(t, leaf)
			f171F176Assert034Catalog(t, leaf)
			if got := f171F176ConstraintOID(t, leaf, "feed_sync_status_status_check"); got != statusOID {
				t.Fatalf("status constraint OID = %d, want retained %d", got, statusOID)
			}
			if got := f171F176ConstraintOID(t, leaf, "feed_sync_status_entries_nonnegative_check"); got != countOID {
				t.Fatalf("count constraint OID = %d, want retained %d", got, countOID)
			}
			f171F176Assert034Matrix(t, leaf)
			f171F176Assert034Plans(t, leaf)
			rows := f171F176034Rows(t, leaf)
			f159F164Apply(t, leaf, 34, MigrationDirectionUp)
			f159F164AssertEqual(t, "034 replay rows", f171F176034Rows(t, leaf), rows)
		})

		t.Run("down_partial_repeat_reapply_and_ownership_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 34)
			f159F164Exec(t, leaf, `INSERT INTO feed_sync_status(feed_name,last_sync_at,last_sync_duration,last_sync_status,last_error,entries_synced,entries_total,last_etag,last_commit_hash,metadata,updated_at) VALUES ('f175-sentinel','2024-01-02T03:04:05Z','2 seconds','success','sentinel error',2,3,'etag-sentinel','commit-sentinel','{"sentinel":true}','2024-01-03T04:05:06Z')`)
			sentinel := f171F176034Sentinel(t, leaf)
			f159F164Exec(t, leaf, `ALTER TABLE feed_sync_status DROP CONSTRAINT feed_sync_status_entries_order_check`)
			f159F164ApplyDownAndDelete(t, leaf, 34)
			f171F176Assert034Absent(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 34)
			f171F176Assert034Absent(t, leaf)
			f159F164AssertEqual(t, "034 sentinel after repeated down", f171F176034Sentinel(t, leaf), sentinel)
			f171F176Seed034InvalidWhileDown(t, leaf)
			f171F176Assert034InvalidAcceptedWhileDown(t, leaf)

			t.Run("known_bug_F175_bugs_1", func(t *testing.T) {
				f159F164Exec(t, leaf, `CREATE TABLE public.f175_unrelated_index_owner(id INTEGER, source TEXT, ecosystem TEXT, name TEXT, version TEXT, updated_at TIMESTAMPTZ, status TEXT); CREATE INDEX idx_reputation_reportable_sync ON public.f175_unrelated_index_owner(id)`)
				f159F164Apply(t, leaf, 34, MigrationDirectionDown)
				var remains int
				if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='idx_reputation_reportable_sync'`).Scan(&remains); err != nil {
					t.Fatalf("inspect unrelated index: %v", err)
				}
				f159F164Exec(t, leaf, `DROP TABLE public.f175_unrelated_index_owner`)
				if remains == 0 {
					t.Skip("F175-bugs-1 P2 reproduced: migration 034 down drops a same-named unrelated index resolved later on search_path")
				}
			})

			f159F164Apply(t, leaf, 34, MigrationDirectionUp)
			f171F176Assert034Catalog(t, leaf)
			f171F176Assert034DownRowsRepaired(t, leaf)
			f159F164AssertEqual(t, "034 sentinel after re-up", f171F176034Sentinel(t, leaf), sentinel)
			f159F164Exec(t, leaf, `DELETE FROM feed_sync_status WHERE feed_name LIKE 'f175-down-%'`)
		})

		t.Run("unrelated_constraint_name_collision_is_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 33)
			f171F176Drop034Objects(t, leaf)
			t.Run("known_bug_F176_bugs_1", func(t *testing.T) {
				f159F164Exec(t, leaf, `CREATE TABLE public.f176_unrelated_constraint_owner(status TEXT, CONSTRAINT feed_sync_status_status_check CHECK (status <> ''))`)
				up := f159F164Embedded(t, 34, MigrationDirectionUp)
				err := applyMigration(leaf.ctx, leaf.conn, up)
				if err == nil {
					f159F164Exec(t, leaf, `DROP TABLE public.f176_unrelated_constraint_owner`)
					f171F176Assert034Catalog(t, leaf)
					return
				}
				f159F164ExpectSQLState(t, err, "42704")
				f159F164AssertDirtyEventAndRefusal(t, leaf, up)
				f159F164ClearDirty(t, leaf, 34)
				f159F164Exec(t, leaf, `DROP TABLE public.f176_unrelated_constraint_owner`)
				f159F164Apply(t, leaf, 34, MigrationDirectionUp)
				f171F176Assert034Catalog(t, leaf)
				t.Skip("F176-bugs-1 P2 reproduced: migration 034 global constraint-name probe mistakes an unrelated table constraint for the target constraint")
			})
			f171F176Assert034Catalog(t, leaf)
		})

		t.Run("wrong_definition_index_probe_and_clean_recovery", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 33)
			f171F176Drop034Objects(t, leaf)
			t.Run("known_bug_F176_bugs_2", func(t *testing.T) {
				f159F164Exec(t, leaf, `CREATE INDEX idx_reputation_reportable_sync ON package_reputation_cache(updated_at)`)
				f159F164Apply(t, leaf, 34, MigrationDirectionUp)
				if f171F176034IndexIsExact(t, leaf) {
					return
				}
				f159F164ApplyDownAndDelete(t, leaf, 34)
				f159F164Apply(t, leaf, 34, MigrationDirectionUp)
				f171F176Assert034Catalog(t, leaf)
				t.Skip("F176-bugs-2 P3 reproduced: migration 034 accepts a same-named target index with the wrong definition")
			})
			f171F176Assert034Catalog(t, leaf)
		})
	})
}

func f171F176Drop032Checks(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for _, name := range f171F176VersionConstraints {
		table := "affected_packages"
		if strings.HasPrefix(name, "malicious") {
			table = "malicious_findings"
		}
		f159F164Exec(t, leaf, fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s`, table, name))
	}
}

func f171F176Seed032Dirty(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO vulnerabilities(id,summary,severity,published,modified)
		VALUES ('f171-vuln','dirty','LOW','2025-01-01Z','2025-01-01Z');
		INSERT INTO affected_packages(id,vulnerability_id,ecosystem,name,version_ranges,versions_affected,updated_at)
		VALUES
			(1,'f171-vuln','npm','invalid-range','{}','["1"]','2020-01-01Z'),
			(2,'f171-vuln','npm','invalid-versions','[]','{"bad":true}','2020-01-01Z'),
			(3,'f171-vuln','npm','valid','[{"events":[{"introduced":"0"}]}]','["1"]','2020-01-01Z');
		INSERT INTO malicious_findings(id,ecosystem,name,version_ranges,versions,source,risk_type,severity,summary,updated_at)
		VALUES
			('f171-dirty','npm','dirty','{}','{"bad":true}','fixture','malware','LOW','dirty','2020-01-01Z'),
			('f171-null','npm','nulls',NULL,NULL,'fixture','malware','LOW','preexisting SQL NULLs','2020-01-01Z')`)
}

func f171F176Assert032Repairs(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if got := f159F164Snapshot(t, leaf, `SELECT id,version_ranges,versions_affected FROM affected_packages WHERE id IN (1,2) ORDER BY id`); got != `[{"id": 1, "version_ranges": [], "versions_affected": ["1"]}, {"id": 2, "version_ranges": [], "versions_affected": []}]` {
		t.Fatalf("032 affected repairs = %s", got)
	}
	if got := f159F164Snapshot(t, leaf, `SELECT version_ranges,versions FROM malicious_findings WHERE id='f171-dirty'`); got != `[{"versions": null, "version_ranges": null}]` {
		t.Fatalf("032 malicious repairs = %s", got)
	}
	if got := f159F164Snapshot(t, leaf, `SELECT version_ranges,versions FROM malicious_findings WHERE id='f171-null'`); got != `[{"versions": null, "version_ranges": null}]` {
		t.Fatalf("032 preexisting malicious SQL NULLs = %s", got)
	}
}

type f171F176RowVersion struct {
	updatedAt time.Time
	xmin      string
}

func f171F176032RowVersions(t *testing.T, leaf f159F164Leaf) map[string]f171F176RowVersion {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `
		SELECT 'affected:'||id::text,updated_at,xmin::text
		FROM affected_packages WHERE id IN (1,2,3)
		UNION ALL
		SELECT 'malicious:'||id,updated_at,xmin::text
		FROM malicious_findings WHERE id IN ('f171-dirty','f171-null')`)
	if err != nil {
		t.Fatalf("query 032 row versions: %v", err)
	}
	defer ioutils.CloseSilently(rows)

	versions := make(map[string]f171F176RowVersion)
	for rows.Next() {
		var key string
		var version f171F176RowVersion
		if err := rows.Scan(&key, &version.updatedAt, &version.xmin); err != nil {
			t.Fatalf("scan 032 row version: %v", err)
		}
		versions[key] = version
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate 032 row versions: %v", err)
	}
	if len(versions) != 5 {
		t.Fatalf("032 versioned fixture rows = %d, want 5", len(versions))
	}
	return versions
}

func f171F176Assert032RepairVersions(t *testing.T, before, after map[string]f171F176RowVersion) {
	t.Helper()
	repaired := map[string]bool{
		"affected:1":           true,
		"affected:2":           true,
		"malicious:f171-dirty": true,
	}
	for key, beforeVersion := range before {
		afterVersion, ok := after[key]
		if !ok {
			t.Fatalf("032 row %s disappeared during repair", key)
		}
		if repaired[key] {
			if !afterVersion.updatedAt.After(beforeVersion.updatedAt) || afterVersion.xmin == beforeVersion.xmin {
				t.Fatalf("032 repaired row %s version before=%+v after=%+v, want advanced timestamp and xmin", key, beforeVersion, afterVersion)
			}
			continue
		}
		if !afterVersion.updatedAt.Equal(beforeVersion.updatedAt) || afterVersion.xmin != beforeVersion.xmin {
			t.Fatalf("032 untouched row %s version before=%+v after=%+v", key, beforeVersion, afterVersion)
		}
	}
}

func f171F176Assert032TruthTables(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	stringCases := []struct {
		value string
		want  bool
	}{{`[]`, true}, {`["1",""]`, true}, {`["1",2]`, false}, {`[1]`, false}, {`{}`, false}, {`null`, false}}
	for _, tt := range stringCases {
		var got bool
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT packmon_jsonb_string_array_valid($1::jsonb)`, tt.value).Scan(&got); err != nil || got != tt.want {
			t.Fatalf("string-array validator(%s)=%t error=%v, want %t", tt.value, got, err, tt.want)
		}
	}
	// Migration 032 historically checks only the container shape and presence of a recognized event key.
	// Null, numeric, and blank values are accepted, and a missing events member passes because the
	// PL/pgSQL IF condition evaluates to SQL NULL. Migration 050 tightens these boundaries later.
	rangeCases := []struct {
		value string
		want  bool
	}{
		{`[]`, true},
		{`[{"events":[{"introduced":null}]}]`, true},
		{`[{"events":[{"introduced":1}]}]`, true},
		{`[{"events":[{"introduced":""}]}]`, true},
		{`[{"events":[{"introduced":"0"}]}]`, true},
		{`[{"events":[{"fixed":null}]}]`, true},
		{`[{"events":[{"fixed":1}]}]`, true},
		{`[{"events":[{"fixed":""}]}]`, true},
		{`[{"events":[{"fixed":"1.0.0"}]}]`, true},
		{`[{"events":[{"last_affected":null}]}]`, true},
		{`[{"events":[{"last_affected":1}]}]`, true},
		{`[{"events":[{"last_affected":""}]}]`, true},
		{`[{"events":[{"last_affected":"1.0.0"}]}]`, true},
		{`[{"events":[{"limit":null}]}]`, true},
		{`[{"events":[{"limit":1}]}]`, true},
		{`[{"events":[{"limit":""}]}]`, true},
		{`[{"events":[{"limit":"2.0.0"}]}]`, true},
		{`[{"events":[]}]`, false},
		{`[{}]`, true},
		{`[{"events":{}}]`, false},
		{`[{"events":["introduced"]}]`, false},
		{`[{"events":[{"unknown":"0"}]}]`, false},
		{`{}`, false},
	}
	for _, tt := range rangeCases {
		var got bool
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT packmon_jsonb_version_ranges_valid($1::jsonb)`, tt.value).Scan(&got); err != nil || got != tt.want {
			t.Fatalf("version-range validator(%s)=%t error=%v, want %t", tt.value, got, err, tt.want)
		}
	}
	var stringNull, rangeNull sql.NullBool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT packmon_jsonb_string_array_valid(NULL),packmon_jsonb_version_ranges_valid(NULL)`).Scan(&stringNull, &rangeNull); err != nil || !stringNull.Valid || stringNull.Bool || !rangeNull.Valid || rangeNull.Bool {
		t.Fatalf("SQL NULL validator results = string:%v range:%v error:%v, want false/false", stringNull, rangeNull, err)
	}
}

func f171F176Assert032Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var functions, constraints, validated int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname IN ('packmon_jsonb_string_array_valid','packmon_jsonb_version_ranges_valid')`, leaf.schema).Scan(&functions); err != nil {
		t.Fatalf("inspect 032 functions: %v", err)
	}
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*),COUNT(*) FILTER (WHERE c.convalidated) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND c.conname=ANY($2)`, leaf.schema, f171F176VersionConstraints).Scan(&constraints, &validated); err != nil {
		t.Fatalf("inspect 032 constraints: %v", err)
	}
	if functions != 2 || constraints != 4 || validated != 4 {
		t.Fatalf("032 catalog = functions:%d constraints:%d validated:%d, want 2/4/4", functions, constraints, validated)
	}
}

func f171F176Assert032Enforcement(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	statements := []string{
		`INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected) VALUES ('f171-vuln','npm','bad-insert-range','{}','[]')`,
		`INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected) VALUES ('f171-vuln','npm','bad-insert-versions','[]','{}')`,
		`INSERT INTO malicious_findings(id,ecosystem,name,version_ranges,source,risk_type,severity,summary) VALUES ('f171-bad-range','npm','bad','{}','fixture','malware','LOW','bad')`,
		`INSERT INTO malicious_findings(id,ecosystem,name,versions,source,risk_type,severity,summary) VALUES ('f171-bad-versions','npm','bad','{}','fixture','malware','LOW','bad')`,
		`UPDATE affected_packages SET version_ranges='{}' WHERE id=3`, `UPDATE affected_packages SET versions_affected='{}' WHERE id=3`,
		`UPDATE malicious_findings SET version_ranges='{}' WHERE id='f171-dirty'`, `UPDATE malicious_findings SET versions='{}' WHERE id='f171-dirty'`,
	}
	for _, statement := range statements {
		_, err := leaf.conn.ExecContext(leaf.ctx, statement)
		f159F164ExpectSQLState(t, err, "23514")
	}
}

func f171F176Assert032Absent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var functions, constraints int
	_ = leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proname IN ('packmon_jsonb_string_array_valid','packmon_jsonb_version_ranges_valid')`, leaf.schema).Scan(&functions)
	_ = leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND c.conname=ANY($2)`, leaf.schema, f171F176VersionConstraints).Scan(&constraints)
	if functions != 0 || constraints != 0 {
		t.Fatalf("032 objects after down = functions:%d constraints:%d", functions, constraints)
	}
}

func f171F176032Rows(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT 'a' kind,id::text key,version_ranges,versions_affected value,updated_at,xmin::text FROM affected_packages UNION ALL SELECT 'm',id,version_ranges,versions,updated_at,xmin::text FROM malicious_findings ORDER BY 1,2`)
}

func f171F176032Catalog(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT 'function' kind,p.proname name,pg_get_functiondef(p.oid) definition FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=current_schema() AND p.proname LIKE 'packmon_jsonb_%_valid' UNION ALL SELECT 'constraint',c.conname,pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=current_schema() AND c.conname=ANY(ARRAY['affected_packages_version_ranges_array_check','affected_packages_versions_affected_array_check','malicious_findings_version_ranges_array_check','malicious_findings_versions_array_check']) ORDER BY 1,2`)
}

func f171F176Make033Legacy(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `ALTER TABLE vulnerability_references DROP CONSTRAINT IF EXISTS vulnerability_references_vulnerability_id_source_url_key; ALTER TABLE vulnerability_references ALTER COLUMN source DROP DEFAULT,ALTER COLUMN source DROP NOT NULL; ALTER TABLE vulnerability_references ADD CONSTRAINT vulnerability_references_vulnerability_id_url_key UNIQUE(vulnerability_id,url)`)
}

func f171F176Assert033Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var nullable, defaultSQL string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name='vulnerability_references' AND column_name='source'`, leaf.schema).Scan(&nullable, &defaultSQL); err != nil || nullable != "NO" || defaultSQL != "''::text" {
		t.Fatalf("033 source catalog = nullable:%q default:%q error:%v", nullable, defaultSQL, err)
	}
	var definition string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c WHERE c.conrelid='vulnerability_references'::regclass AND c.conname='vulnerability_references_vulnerability_id_source_url_key'`).Scan(&definition); err != nil || definition != "UNIQUE (vulnerability_id, source, url)" {
		t.Fatalf("033 scoped unique = %q error=%v", definition, err)
	}
}

func f171F176Assert033Legacy(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var nullable, defaultSQL, definition string
	_ = leaf.conn.QueryRowContext(leaf.ctx, `SELECT is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name='vulnerability_references' AND column_name='source'`, leaf.schema).Scan(&nullable, &defaultSQL)
	_ = leaf.conn.QueryRowContext(leaf.ctx, `SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c WHERE c.conrelid='vulnerability_references'::regclass AND c.conname='vulnerability_references_vulnerability_id_url_key'`).Scan(&definition)
	if nullable != "YES" || defaultSQL != "" || definition != "UNIQUE (vulnerability_id, url)" {
		t.Fatalf("033 legacy catalog = nullable:%q default:%q unique:%q", nullable, defaultSQL, definition)
	}
}

func f171F176033FKIndex(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT 'constraint' kind,c.conname name,c.oid::text identity,pg_get_constraintdef(c.oid) definition FROM pg_constraint c WHERE c.conrelid='vulnerability_references'::regclass AND c.contype='f' UNION ALL SELECT 'index',i.relname,i.oid::text,pg_get_indexdef(i.oid) FROM pg_class i JOIN pg_namespace n ON n.oid=i.relnamespace WHERE n.nspname=current_schema() AND i.relname='idx_vuln_refs_vuln_id' ORDER BY 1,2`)
}

func f171F176Drop034Objects(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `DROP INDEX IF EXISTS idx_reputation_reportable_sync`)
	for _, name := range f171F176FeedConstraints {
		f159F164Exec(t, leaf, `ALTER TABLE feed_sync_status DROP CONSTRAINT IF EXISTS `+name)
	}
}

func f171F176Seed034Dirty(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO feed_sync_status(feed_name,last_sync_status,last_error,entries_synced,entries_total,last_sync_duration) VALUES
			('f175-status',' SUCCESS ',NULL,1,1,'1 second'),
			('f175-empty-status',' ',NULL,1,1,'1 second'),
			('f175-invalid-existing','BOGUS','keep existing error',1,1,'1 second'),
			('f175-negative-synced','pending',NULL,-2,3,'1 second'),
			('f175-negative-total','pending',NULL,0,-3,'1 second'),
			('f175-order','pending',NULL,5,3,'1 second'),
			('f175-duration','pending',NULL,1,1,'-1 second'),
			('f175-zero-duration','pending',NULL,1,1,'0 seconds'),
			('f175-null-duration','pending',NULL,1,1,NULL)`)
}

func f171F176Assert034Repairs(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if got := f171F176034Rows(t, leaf); got != `[{"feed_name": "f175-duration", "last_error": null, "entries_total": 1, "entries_synced": 1, "last_sync_status": "pending", "last_sync_duration": null}, {"feed_name": "f175-empty-status", "last_error": "normalized invalid feed sync status during migration 034", "entries_total": 1, "entries_synced": 1, "last_sync_status": "error", "last_sync_duration": "00:00:01"}, {"feed_name": "f175-invalid-existing", "last_error": "keep existing error", "entries_total": 1, "entries_synced": 1, "last_sync_status": "error", "last_sync_duration": "00:00:01"}, {"feed_name": "f175-negative-synced", "last_error": null, "entries_total": 3, "entries_synced": 0, "last_sync_status": "pending", "last_sync_duration": "00:00:01"}, {"feed_name": "f175-negative-total", "last_error": null, "entries_total": 0, "entries_synced": 0, "last_sync_status": "pending", "last_sync_duration": "00:00:01"}, {"feed_name": "f175-null-duration", "last_error": null, "entries_total": 1, "entries_synced": 1, "last_sync_status": "pending", "last_sync_duration": null}, {"feed_name": "f175-order", "last_error": null, "entries_total": 5, "entries_synced": 5, "last_sync_status": "pending", "last_sync_duration": "00:00:01"}, {"feed_name": "f175-status", "last_error": null, "entries_total": 1, "entries_synced": 1, "last_sync_status": "success", "last_sync_duration": "00:00:01"}, {"feed_name": "f175-zero-duration", "last_error": null, "entries_total": 1, "entries_synced": 1, "last_sync_status": "pending", "last_sync_duration": "00:00:00"}]` {
		t.Fatalf("034 repaired rows = %s", got)
	}
}

func f171F176034Sentinel(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT feed_name,last_sync_at,last_sync_duration,last_sync_status,last_error,entries_synced,entries_total,last_etag,last_commit_hash,metadata,updated_at,xmin::text FROM feed_sync_status WHERE feed_name='f175-sentinel'`)
}

func f171F176Seed034InvalidWhileDown(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO feed_sync_status(feed_name,last_sync_status,entries_synced,entries_total,last_sync_duration) VALUES
			('f175-down-status','invalid',0,0,'0 seconds'),
			('f175-down-negative-synced','pending',-1,0,'0 seconds'),
			('f175-down-negative-total','pending',0,-1,'0 seconds'),
			('f175-down-order','pending',2,1,'0 seconds'),
			('f175-down-duration','pending',0,0,'-1 second')`)
}

func f171F176Assert034InvalidAcceptedWhileDown(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if got := f159F164Snapshot(t, leaf, `SELECT feed_name,last_sync_status,entries_synced,entries_total,last_sync_duration FROM feed_sync_status WHERE feed_name LIKE 'f175-down-%' ORDER BY feed_name`); got != `[{"feed_name": "f175-down-duration", "entries_total": 0, "entries_synced": 0, "last_sync_status": "pending", "last_sync_duration": "-00:00:01"}, {"feed_name": "f175-down-negative-synced", "entries_total": 0, "entries_synced": -1, "last_sync_status": "pending", "last_sync_duration": "00:00:00"}, {"feed_name": "f175-down-negative-total", "entries_total": -1, "entries_synced": 0, "last_sync_status": "pending", "last_sync_duration": "00:00:00"}, {"feed_name": "f175-down-order", "entries_total": 1, "entries_synced": 2, "last_sync_status": "pending", "last_sync_duration": "00:00:00"}, {"feed_name": "f175-down-status", "entries_total": 0, "entries_synced": 0, "last_sync_status": "invalid", "last_sync_duration": "00:00:00"}]` {
		t.Fatalf("034 invalid rows accepted while constraints are down = %s", got)
	}
}

func f171F176Assert034DownRowsRepaired(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if got := f159F164Snapshot(t, leaf, `SELECT feed_name,last_sync_status,last_error,entries_synced,entries_total,last_sync_duration FROM feed_sync_status WHERE feed_name LIKE 'f175-down-%' ORDER BY feed_name`); got != `[{"feed_name": "f175-down-duration", "last_error": null, "entries_total": 0, "entries_synced": 0, "last_sync_status": "pending", "last_sync_duration": null}, {"feed_name": "f175-down-negative-synced", "last_error": null, "entries_total": 0, "entries_synced": 0, "last_sync_status": "pending", "last_sync_duration": "00:00:00"}, {"feed_name": "f175-down-negative-total", "last_error": null, "entries_total": 0, "entries_synced": 0, "last_sync_status": "pending", "last_sync_duration": "00:00:00"}, {"feed_name": "f175-down-order", "last_error": null, "entries_total": 2, "entries_synced": 2, "last_sync_status": "pending", "last_sync_duration": "00:00:00"}, {"feed_name": "f175-down-status", "last_error": "normalized invalid feed sync status during migration 034", "entries_total": 0, "entries_synced": 0, "last_sync_status": "error", "last_sync_duration": "00:00:00"}]` {
		t.Fatalf("034 down-state rows after re-up repair = %s", got)
	}
}

func f171F176034Rows(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT feed_name,last_sync_status,last_error,entries_synced,entries_total,last_sync_duration FROM feed_sync_status WHERE feed_name LIKE 'f175-%' ORDER BY feed_name`)
}

func f171F176ConstraintOID(t *testing.T, leaf f159F164Leaf, name string) int64 {
	t.Helper()
	var oid int64
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT c.oid::bigint FROM pg_constraint c WHERE c.conrelid='feed_sync_status'::regclass AND c.conname=$1`, name).Scan(&oid); err != nil {
		t.Fatalf("inspect constraint %s OID: %v", name, err)
	}
	return oid
}

func f171F176Assert034Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var constraints, validated int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*),COUNT(*) FILTER (WHERE convalidated) FROM pg_constraint WHERE conrelid='feed_sync_status'::regclass AND conname=ANY($1)`, f171F176FeedConstraints).Scan(&constraints, &validated); err != nil || constraints != 4 || validated != 4 {
		t.Fatalf("034 constraints = %d validated=%d error=%v, want 4/4", constraints, validated, err)
	}
	if !f171F176034IndexIsExact(t, leaf) {
		t.Fatal("idx_reputation_reportable_sync does not have the exact partial covering definition")
	}
}

func f171F176034IndexIsExact(t *testing.T, leaf f159F164Leaf) bool {
	t.Helper()
	var keys, includes, predicate string
	err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT string_agg(pg_get_indexdef(x.indexrelid,k,true),',' ORDER BY k) FILTER (WHERE k<=x.indnkeyatts),string_agg(pg_get_indexdef(x.indexrelid,k,true),',' ORDER BY k) FILTER (WHERE k>x.indnkeyatts),pg_get_expr(x.indpred,x.indrelid) FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_namespace n ON n.oid=i.relnamespace CROSS JOIN LATERAL generate_series(1,x.indnatts) k WHERE n.nspname=$1 AND i.relname='idx_reputation_reportable_sync' GROUP BY x.indexrelid,x.indnkeyatts,x.indpred,x.indrelid`, leaf.schema).Scan(&keys, &includes, &predicate)
	if err != nil {
		return false
	}
	return keys == "source,ecosystem,name,version" && includes == "updated_at" && strings.Join(strings.Fields(predicate), " ") == "(status = ANY (ARRAY['malicious'::text, 'removed'::text, 'risk'::text]))"
}

func f171F176Assert034Matrix(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	valid := []string{"pending", "running", "success", "error", "skipped", "disabled", "external", "rejected", "permanent_error"}
	for i, status := range valid {
		f159F164Exec(t, leaf, `INSERT INTO feed_sync_status(feed_name,last_sync_status,entries_synced,entries_total,last_sync_duration) VALUES ($1,$2,0,0,'0 seconds')`, fmt.Sprintf("f175-valid-%d", i), status)
	}
	invalid := []string{
		`INSERT INTO feed_sync_status(feed_name,last_sync_status) VALUES ('f175-bad-status','invalid')`,
		`INSERT INTO feed_sync_status(feed_name,entries_synced,entries_total) VALUES ('f175-bad-negative-synced',-1,0)`,
		`INSERT INTO feed_sync_status(feed_name,entries_synced,entries_total) VALUES ('f175-bad-negative-total',0,-1)`,
		`INSERT INTO feed_sync_status(feed_name,entries_synced,entries_total) VALUES ('f175-bad-order',2,1)`,
		`INSERT INTO feed_sync_status(feed_name,last_sync_duration) VALUES ('f175-bad-duration','-1 second')`,
		`UPDATE feed_sync_status SET last_sync_status='invalid' WHERE feed_name='f175-status'`,
		`UPDATE feed_sync_status SET entries_synced=-1 WHERE feed_name='f175-status'`,
		`UPDATE feed_sync_status SET entries_total=-1 WHERE feed_name='f175-status'`,
		`UPDATE feed_sync_status SET entries_synced=3,entries_total=2 WHERE feed_name='f175-status'`,
		`UPDATE feed_sync_status SET last_sync_duration='-1 second' WHERE feed_name='f175-status'`,
	}
	for _, statement := range invalid {
		_, err := leaf.conn.ExecContext(leaf.ctx, statement)
		f159F164ExpectSQLState(t, err, "23514")
	}
}

func f171F176Assert034Plans(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `SET enable_seqscan=off; SET enable_bitmapscan=off`)
	defer f159F164Exec(t, leaf, `RESET enable_seqscan; RESET enable_bitmapscan`)
	queries := []string{
		`SELECT source,ecosystem,name,version,updated_at FROM package_reputation_cache WHERE status IN ('malicious','removed','risk') ORDER BY source,ecosystem,name,version`,
		`SELECT source,ecosystem,name,version,updated_at FROM package_reputation_cache WHERE status IN ('malicious','removed','risk') AND (source,ecosystem,name,version)>('a','npm','a','1') ORDER BY source,ecosystem,name,version LIMIT 10`,
	}
	for _, query := range queries {
		var raw []byte
		if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) `+query).Scan(&raw); err != nil {
			t.Fatalf("EXPLAIN representative export query: %v", err)
		}
		if !f159F164JSONContainsIndex(t, raw, "idx_reputation_reportable_sync") || f171F176JSONContainsNode(t, raw, "Sort") {
			t.Fatalf("representative export plan lacks target index or adds Sort: %s", raw)
		}
	}
}

func f171F176JSONContainsNode(t *testing.T, raw []byte, node string) bool {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch current := current.(type) {
		case map[string]any:
			if current["Node Type"] == node {
				return true
			}
			for _, child := range current {
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range current {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}

func f171F176Assert034Absent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var constraints, indexes int
	_ = leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_constraint WHERE conrelid='feed_sync_status'::regclass AND conname=ANY($1)`, f171F176FeedConstraints).Scan(&constraints)
	_ = leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname='idx_reputation_reportable_sync'`, leaf.schema).Scan(&indexes)
	if constraints != 0 || indexes != 0 {
		t.Fatalf("034 objects after down = constraints:%d indexes:%d", constraints, indexes)
	}
}
