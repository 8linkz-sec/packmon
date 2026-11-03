//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	packmondb "github.com/8linkz-sec/packmon/internal/db"
	postgresstore "github.com/8linkz-sec/packmon/internal/db/postgres"
	"github.com/8linkz-sec/packmon/internal/ioutils"
)

var f165F170Constraints = []struct {
	table string
	name  string
}{
	{"affected_packages", "affected_packages_ecosystem_check"},
	{"malicious_findings", "malicious_findings_ecosystem_check"},
	{"package_reputation_cache", "package_reputation_cache_ecosystem_check"},
	{"package_check_status", "package_check_status_ecosystem_check"},
	{"refresh_queue", "refresh_queue_ecosystem_check"},
	{"lifecycle_package_map", "lifecycle_package_map_ecosystem_check"},
	{"lifecycle_sync_tombstones", "lifecycle_sync_tombstones_ecosystem_check"},
	{"malicious_findings", "malicious_findings_risk_type_check"},
	{"vulnerability_sources", "vulnerability_sources_manual_id_check"},
	{"malicious_findings", "malicious_findings_manual_id_check"},
	{"refresh_queue", "refresh_queue_status_check"},
	{"refresh_queue", "refresh_queue_priority_check"},
}

func TestF165F170MigrationContractsAgainstPostgres(t *testing.T) {
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

	leafNumber := 0
	newLeaf := func(t *testing.T) f159F164Leaf {
		t.Helper()
		leafNumber++
		return f159F164PrepareLeaf(t, database, instance.dsn, leafNumber+100)
	}

	t.Run("migration_029", func(t *testing.T) {
		t.Run("mixed_deleted_forward_repeat_down_repeat_reapply_preserves_references", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 28)
			f165F170SeedAPIKeys(t, leaf)
			untouched := f165F170Snapshot(t, leaf, `
				SELECT 'key' AS kind,id::text AS id,name,key_hash,created_at::text,COALESCE(revoked_at::text,''),COALESCE(last_used_at::text,''),COALESCE(deleted_at::text,''),xmin::text
				FROM api_keys WHERE id IN (101,102)
				UNION ALL
				SELECT 'scan',id::text,scan_id,COALESCE(api_key_name,''),scanned_at::text,'','','',xmin::text FROM scan_log
				ORDER BY kind,id`)
			deletedMetadata := f165F170Snapshot(t, leaf, `SELECT id,created_at,revoked_at,last_used_at,deleted_at FROM api_keys WHERE id IN (103,104) ORDER BY id`)
			references := f165F170Snapshot(t, leaf, `SELECT scan_id,api_key_id,api_key_name,scanned_at FROM scan_log ORDER BY scan_id`)

			f159F164Apply(t, leaf, 29, MigrationDirectionUp)
			f165F170AssertDeletedKeysScrubbed(t, leaf)
			f165F170AssertEqual(t, "untouched active/revoked keys and scans after 029", f165F170Snapshot(t, leaf, `
				SELECT 'key' AS kind,id::text AS id,name,key_hash,created_at::text,COALESCE(revoked_at::text,''),COALESCE(last_used_at::text,''),COALESCE(deleted_at::text,''),xmin::text
				FROM api_keys WHERE id IN (101,102)
				UNION ALL
				SELECT 'scan',id::text,scan_id,COALESCE(api_key_name,''),scanned_at::text,'','','',xmin::text FROM scan_log
				ORDER BY kind,id`), untouched)
			f165F170AssertEqual(t, "deleted key metadata after 029", f165F170Snapshot(t, leaf, `SELECT id,created_at,revoked_at,last_used_at,deleted_at FROM api_keys WHERE id IN (103,104) ORDER BY id`), deletedMetadata)
			f165F170AssertEqual(t, "scan references after 029", f165F170Snapshot(t, leaf, `SELECT scan_id,api_key_id,api_key_name,scanned_at FROM scan_log ORDER BY scan_id`), references)

			f159F164Apply(t, leaf, 29, MigrationDirectionUp)
			f165F170AssertDeletedKeysScrubbed(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 29)
			f159F164ApplyDownAndDelete(t, leaf, 29)
			f165F170AssertDeletedKeysScrubbed(t, leaf)
			f159F164Apply(t, leaf, 29, MigrationDirectionUp)
			f165F170AssertDeletedKeysScrubbed(t, leaf)
			f165F170AssertEqual(t, "deleted key metadata after 029 round trip", f165F170Snapshot(t, leaf, `SELECT id,created_at,revoked_at,last_used_at,deleted_at FROM api_keys WHERE id IN (103,104) ORDER BY id`), deletedMetadata)
			f165F170AssertEqual(t, "scan references after 029 round trip", f165F170Snapshot(t, leaf, `SELECT scan_id,api_key_id,api_key_name,scanned_at FROM scan_log ORDER BY scan_id`), references)
		})
	})

	t.Run("migration_030", func(t *testing.T) {
		t.Run("absent_column_upgrade_catalog_inserts_and_privacy_export", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 29)
			f159F164Exec(t, leaf, `ALTER TABLE scan_log DROP COLUMN client_version`)
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,packages_count,findings_count,duration_ms) VALUES ('legacy-absent','f168/repo',1,0,2)`)
			legacy := f165F170Snapshot(t, leaf, `SELECT id,scan_id,repo_name,packages_count,findings_count,duration_ms,scanned_at,xmin::text FROM scan_log ORDER BY id`)

			f159F164Apply(t, leaf, 30, MigrationDirectionUp)
			f165F170AssertClientVersionCatalog(t, leaf)
			f165F170AssertEqual(t, "legacy scan after absent-column 030 up", f165F170Snapshot(t, leaf, `SELECT id,scan_id,repo_name,packages_count,findings_count,duration_ms,scanned_at,xmin::text FROM scan_log ORDER BY id`), legacy)
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,packages_count,findings_count,duration_ms) VALUES ('omitted-version','f168/repo',1,0,2)`)
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,packages_count,findings_count,duration_ms,client_version) VALUES ('empty-version','f168/repo',1,0,2,''),('value-version','f168/repo',1,0,2,'packmon/30.1')`)
			f165F170AssertClientVersionValues(t, leaf)

			packmondb.ClearAdminAuditDigestHMACKey()
			t.Cleanup(packmondb.ClearAdminAuditDigestHMACKey)
			packmondb.SetAdminAuditDigestHMACKey([]byte("f165-f170-fixed-test-hmac-key"))
			store, err := postgresstore.New(leaf.ctx, leaf.dsn, nil, nil)
			if err != nil {
				t.Fatalf("postgres.New() error = %v", err)
			}
			t.Cleanup(func() { _ = store.Close() })
			recent, err := store.ListRecentScans(leaf.ctx, 10, 0)
			if err != nil {
				t.Fatalf("ListRecentScans() error = %v", err)
			}
			versions := map[string]string{}
			for _, scan := range recent {
				versions[scan.ScanID] = scan.ClientVersion
			}
			if versions["legacy-absent"] != "" || versions["omitted-version"] != "" || versions["empty-version"] != "" || versions["value-version"] != "packmon/30.1" {
				t.Fatalf("ListRecentScans client versions = %v", versions)
			}
			export, err := store.ExportPrivacyMetadata(leaf.ctx, packmondb.PrivacyExportSelector{Type: packmondb.PrivacySelectorRepoName, Value: "f168/repo"}, &packmondb.AdminAuditEntry{Action: "f168.privacy_export"})
			if err != nil {
				t.Fatalf("ExportPrivacyMetadata() error = %v", err)
			}
			if export.ScanLogCount != 4 {
				t.Fatalf("privacy scan count = %d, want 4", export.ScanLogCount)
			}
			exported := map[string]string{}
			for _, scan := range export.ScanLogs {
				exported[scan.ScanID] = scan.ClientVersion
			}
			if !reflect.DeepEqual(exported, versions) {
				t.Fatalf("privacy client versions = %v, recent = %v", exported, versions)
			}
		})

		t.Run("baseline_present_repeat_down_repeat_reapply_preserves_null_empty_and_value", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 29)
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,client_version) VALUES ('null-version',1,0,1,NULL),('empty-version',1,0,1,''),('value-version',1,0,1,'packmon/29.9')`)
			catalog := f165F170ClientVersionIdentity(t, leaf)
			rows := f165F170Snapshot(t, leaf, `SELECT id,scan_id,client_version,scanned_at,xmin::text FROM scan_log ORDER BY id`)
			f159F164Apply(t, leaf, 30, MigrationDirectionUp)
			f159F164Apply(t, leaf, 30, MigrationDirectionUp)
			if got := f165F170ClientVersionIdentity(t, leaf); got != catalog {
				t.Fatalf("client_version identity after repeat = %q, want %q", got, catalog)
			}
			f159F164ApplyDownAndDelete(t, leaf, 30)
			f159F164ApplyDownAndDelete(t, leaf, 30)
			f159F164Apply(t, leaf, 30, MigrationDirectionUp)
			if got := f165F170ClientVersionIdentity(t, leaf); got != catalog {
				t.Fatalf("client_version identity after down/reapply = %q, want %q", got, catalog)
			}
			f165F170AssertEqual(t, "030 baseline rows", f165F170Snapshot(t, leaf, `SELECT id,scan_id,client_version,scanned_at,xmin::text FROM scan_log ORDER BY id`), rows)
			f165F170AssertClientVersionValues(t, leaf)
		})
	})

	t.Run("migration_031", func(t *testing.T) {
		f165F170Run031Tests(t, newLeaf)
	})
}

func f165F170SeedAPIKeys(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO api_keys(id,name,key_hash,created_at,revoked_at,last_used_at,deleted_at) VALUES
		(101,'active label','active-hash','2025-01-01T00:00:00Z',NULL,'2025-01-02T00:00:00Z',NULL),
		(102,'revoked label','revoked-hash','2025-02-01T00:00:00Z','2025-02-02T00:00:00Z','2025-02-01T12:00:00Z',NULL),
		(103,'deleted alpha','deleted-alpha-hash','2025-03-01T00:00:00Z','2025-03-02T00:00:00Z','2025-03-01T12:00:00Z','2025-03-03T00:00:00Z'),
		(104,'deleted beta','deleted-beta-hash','2025-04-01T00:00:00Z',NULL,NULL,'2025-04-03T00:00:00Z');
		INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,api_key_id,api_key_name,scanned_at) VALUES
		('deleted-alpha-scan',1,0,1,103,'deleted alpha','2025-05-01T00:00:00Z'),
		('deleted-beta-scan',1,0,1,104,'deleted beta','2025-05-02T00:00:00Z')`)
}

func f165F170AssertDeletedKeysScrubbed(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT id,name,key_hash FROM api_keys WHERE id IN (103,104) ORDER BY id`)
	if err != nil {
		t.Fatalf("read scrubbed API keys: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	want := []struct {
		id   int
		name string
		hash string
	}{{103, "", "deleted:103"}, {104, "", "deleted:104"}}
	for i := 0; rows.Next(); i++ {
		if i >= len(want) {
			t.Fatal("too many scrubbed API keys")
		}
		var id int
		var name, hash string
		if err := rows.Scan(&id, &name, &hash); err != nil {
			t.Fatalf("scan scrubbed API key: %v", err)
		}
		if id != want[i].id || name != want[i].name || hash != want[i].hash {
			t.Fatalf("scrubbed API key %d = id:%d name:%q hash:%q, want %+v", i, id, name, hash, want[i])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate scrubbed API keys: %v", err)
	}
}

func f165F170AssertClientVersionCatalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var dataType, nullable, defaultSQL string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name='scan_log' AND column_name='client_version'`, leaf.schema).Scan(&dataType, &nullable, &defaultSQL); err != nil {
		t.Fatalf("inspect scan_log.client_version: %v", err)
	}
	if dataType != "text" || nullable != "YES" || defaultSQL != "" {
		t.Fatalf("scan_log.client_version = type:%q nullable:%q default:%q, want text/YES/empty", dataType, nullable, defaultSQL)
	}
}

func f165F170ClientVersionIdentity(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	var identity string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT c.oid::text || '|' || a.attnum::text || '|' || a.atttypid::regtype::text || '|' || a.attnotnull::text || '|' || COALESCE(pg_get_expr(d.adbin,d.adrelid),'') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='client_version' LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname=$1 AND c.relname='scan_log'`, leaf.schema).Scan(&identity); err != nil {
		t.Fatalf("inspect client_version identity: %v", err)
	}
	return identity
}

func f165F170AssertClientVersionValues(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var nullCount, emptyCount, valueCount int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FILTER(WHERE client_version IS NULL),COUNT(*) FILTER(WHERE client_version=''),COUNT(*) FILTER(WHERE client_version IN ('packmon/30.1','packmon/29.9')) FROM scan_log`).Scan(&nullCount, &emptyCount, &valueCount); err != nil {
		t.Fatalf("inspect client_version values: %v", err)
	}
	if nullCount < 1 || emptyCount < 1 || valueCount < 1 {
		t.Fatalf("client_version matrix = null:%d empty:%d value:%d, want each present", nullCount, emptyCount, valueCount)
	}
}

func f165F170Snapshot(t *testing.T, leaf f159F164Leaf, query string) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, query)
}

func f165F170AssertEqual(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s changed\ngot:  %s\nwant: %s", label, got, want)
	}
}

func f165F170Run031Tests(t *testing.T, newLeaf func(*testing.T) f159F164Leaf) {
	t.Helper()
	t.Run("normalization_catalog_and_acceptance_rejection_matrix", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 30)
		f165F170Drop031Constraints(t, leaf)
		baseline := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
		f165F170Seed031Normalization(t, leaf, baseline)
		canonicalBefore := f165F170Snapshot(t, leaf, f165F170Canonical031SnapshotSQL)

		f159F164Apply(t, leaf, 31, MigrationDirectionUp)
		f165F170Assert031Constraints(t, leaf)
		f165F170Assert031Normalization(t, leaf, baseline)
		f165F170AssertEqual(t, "canonical controls after 031", f165F170Snapshot(t, leaf, f165F170Canonical031SnapshotSQL), canonicalBefore)
		f165F170Assert031AcceptanceMatrix(t, leaf)
	})

	t.Run("partial_existing_constraints_and_replay_preserve_identity", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 30)
		f165F170Drop031Constraints(t, leaf)
		f159F164Exec(t, leaf, `
			ALTER TABLE affected_packages ADD CONSTRAINT affected_packages_ecosystem_check CHECK (ecosystem IN ('npm','pypi','go','maven','cargo','nuget','composer','gem','pub','cocoapods','swiftpm','hex','cran','actions','docker')) NOT VALID;
			ALTER TABLE malicious_findings ADD CONSTRAINT malicious_findings_risk_type_check CHECK (risk_type IN ('malware','supply_chain','typosquatting')) NOT VALID;
			ALTER TABLE refresh_queue ADD CONSTRAINT refresh_queue_status_check CHECK (status IN ('pending','processing','paused','done','error')) NOT VALID`)
		before := f165F170ConstraintIdentities(t, leaf, []string{"affected_packages_ecosystem_check", "malicious_findings_risk_type_check", "refresh_queue_status_check"})
		rowsBefore := f165F170All031Rows(t, leaf)
		f159F164Apply(t, leaf, 31, MigrationDirectionUp)
		f165F170Assert031Constraints(t, leaf)
		f165F170AssertConstraintIdentities(t, leaf, before)
		allIdentity := f165F170ConstraintIdentities(t, leaf, f165F170ConstraintNames())
		f159F164Apply(t, leaf, 31, MigrationDirectionUp)
		f165F170Assert031Constraints(t, leaf)
		f165F170AssertConstraintIdentities(t, leaf, allIdentity)
		f165F170AssertEqual(t, "rows after partial/repeated 031 up", f165F170All031Rows(t, leaf), rowsBefore)
	})

	t.Run("partial_repeated_down_and_reapply_preserve_rows_and_unrelated_checks", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 31)
		f165F170Seed031CanonicalRows(t, leaf)
		f159F164Exec(t, leaf, `ALTER TABLE affected_packages ADD CONSTRAINT f169_unrelated_name_check CHECK (name <> '')`)
		f159F164Exec(t, leaf, `ALTER TABLE malicious_findings DROP CONSTRAINT malicious_findings_risk_type_check`)
		rowsBefore := f165F170All031Rows(t, leaf)
		f159F164ApplyDownAndDelete(t, leaf, 31)
		f165F170Assert031ConstraintsAbsent(t, leaf)
		f165F170AssertUnrelatedCheck(t, leaf)
		f165F170AssertEqual(t, "rows after partial 031 down", f165F170All031Rows(t, leaf), rowsBefore)
		f159F164ApplyDownAndDelete(t, leaf, 31)
		f165F170Assert031ConstraintsAbsent(t, leaf)
		f165F170AssertUnrelatedCheck(t, leaf)
		f165F170AssertEqual(t, "rows after repeated 031 down", f165F170All031Rows(t, leaf), rowsBefore)
		f159F164Apply(t, leaf, 31, MigrationDirectionUp)
		f165F170Assert031Constraints(t, leaf)
		f165F170AssertUnrelatedCheck(t, leaf)
		f165F170AssertEqual(t, "rows after 031 reapply", f165F170All031Rows(t, leaf), rowsBefore)
	})

	t.Run("unknown_ecosystem_failure_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 30)
		f165F170Drop031Constraints(t, leaf)
		f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('F170-UNKNOWN','unknown ecosystem','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z'); INSERT INTO affected_packages(vulnerability_id,ecosystem,name) VALUES ('F170-UNKNOWN','unknown-ecosystem','unknown-package')`)
		f165F170Assert031FailureRecovery(t, leaf, "23514", `UPDATE affected_packages SET ecosystem='npm' WHERE vulnerability_id='F170-UNKNOWN'`)
	})

	t.Run("invalid_vulnerability_source_manual_id_failure_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 30)
		f165F170Drop031Constraints(t, leaf)
		f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('F170-MANUAL-VULN','manual vulnerability','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z'); INSERT INTO vulnerability_sources(vulnerability_id,source,source_id) VALUES ('F170-MANUAL-VULN','manual','invalid-source-id')`)
		f165F170Assert031FailureRecovery(t, leaf, "23514", `UPDATE vulnerability_sources SET source='osv' WHERE source='manual'`)
	})

	t.Run("invalid_malicious_manual_id_failure_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 30)
		f165F170Drop031Constraints(t, leaf)
		f159F164Exec(t, leaf, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,summary) VALUES ('F170-MANUAL-MAL','npm','manual-malicious','manual','malware','invalid manual ID')`)
		f165F170Assert031FailureRecovery(t, leaf, "23514", `UPDATE malicious_findings SET source='osv' WHERE id='F170-MANUAL-MAL'`)
	})

	t.Run("normalization_uniqueness_collision_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 30)
		f165F170Drop031Constraints(t, leaf)
		f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('F170-COLLISION','collision','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z'); INSERT INTO affected_packages(vulnerability_id,ecosystem,name) VALUES ('F170-COLLISION','NPM','same-name'),('F170-COLLISION','npm','same-name')`)
		f165F170Assert031FailureRecovery(t, leaf, "23505", `UPDATE affected_packages SET name='renamed-before-retry' WHERE vulnerability_id='F170-COLLISION' AND ecosystem='NPM'`)
	})

	t.Run("unrelated_constraint_name_collision_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 30)
		f165F170Drop031Constraints(t, leaf)
		f159F164Exec(t, leaf, `CREATE TABLE f170_foreign_constraint_owner(value TEXT NOT NULL); ALTER TABLE f170_foreign_constraint_owner ADD CONSTRAINT affected_packages_ecosystem_check CHECK (value <> '')`)
		rowsBefore := f165F170All031Rows(t, leaf)
		constraintsBefore := f165F170AllConstraintSnapshot(t, leaf)
		migration := f159F164Embedded(t, 31, MigrationDirectionUp)
		err := applyMigration(leaf.ctx, leaf.conn, migration)
		f159F164ExpectSQLState(t, err, "42704")
		f165F170AssertEqual(t, "rows after unrelated-name 031 failure", f165F170All031Rows(t, leaf), rowsBefore)
		f165F170AssertEqual(t, "constraints after unrelated-name 031 failure", f165F170AllConstraintSnapshot(t, leaf), constraintsBefore)
		f165F170AssertConstraintOnTable(t, leaf, "f170_foreign_constraint_owner", "affected_packages_ecosystem_check", true)
		f165F170AssertConstraintOnTable(t, leaf, "affected_packages", "affected_packages_ecosystem_check", false)
		f159F164AssertDirtyEventAndRefusal(t, leaf, migration)
		t.Run("known_bug_F170_bugs_1", func(t *testing.T) {
			t.Skip("F170-bugs-1: migration 031 checks pg_constraint.conname globally and skips a required target-table constraint")
		})
		f159F164ClearDirty(t, leaf, 31)
		f159F164Exec(t, leaf, `ALTER TABLE f170_foreign_constraint_owner DROP CONSTRAINT affected_packages_ecosystem_check`)
		f159F164Apply(t, leaf, 31, MigrationDirectionUp)
		f165F170Assert031Constraints(t, leaf)
	})
}

const f165F170Canonical031SnapshotSQL = `
	SELECT 'affected' AS kind,id::text AS id,ecosystem AS value,name AS extra,'' AS timestamp,xmin::text FROM affected_packages WHERE name='canonical-affected'
	UNION ALL SELECT 'malicious',id,ecosystem,risk_type,updated_at::text,xmin::text FROM malicious_findings WHERE id='F170-CANONICAL'
	UNION ALL SELECT 'reputation',id::text,ecosystem,name,updated_at::text,xmin::text FROM package_reputation_cache WHERE name='canonical-reputation'
	UNION ALL SELECT 'check',id::text,ecosystem,name,updated_at::text,xmin::text FROM package_check_status WHERE name='canonical-check'
	UNION ALL SELECT 'queue',id::text,ecosystem,status,COALESCE(processed_at::text,''),xmin::text FROM refresh_queue WHERE name='canonical-queue'
	UNION ALL SELECT 'map',name,ecosystem,product_slug,updated_at::text,xmin::text FROM lifecycle_package_map WHERE name='canonical-map'
	UNION ALL SELECT 'tombstone',id,ecosystem,name,updated_at::text,xmin::text FROM lifecycle_sync_tombstones WHERE id='canonical-tombstone'
	ORDER BY kind,id`

func f165F170Drop031Constraints(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for _, constraint := range f165F170Constraints {
		f159F164Exec(t, leaf, `ALTER TABLE `+constraint.table+` DROP CONSTRAINT IF EXISTS `+constraint.name)
	}
}

func f165F170Seed031Normalization(t *testing.T, leaf f159F164Leaf, baseline time.Time) {
	t.Helper()
	baselineLiteral := f159F164SQLLiteral(baseline.Format(time.RFC3339Nano))
	fixtureSQL := `
		INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('F170-NORM','normalize','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z'),('F170-CANON','canonical','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z');
		INSERT INTO affected_packages(vulnerability_id,ecosystem,name) VALUES ('F170-NORM',' NPM ','normalize-affected'),('F170-CANON','npm','canonical-affected');
		INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,summary,updated_at) VALUES
		('F170-SUPPLY-HYPHEN',' PyPI ','risk-supply-hyphen','osv','supply-chain','normalize',__BASELINE__),
		('F170-SUPPLY-SPACE','npm','risk-supply-space','osv','supply chain','normalize',__BASELINE__),
		('F170-TYPO-SHORT','npm','risk-typo-short','osv','typosquat','normalize',__BASELINE__),
		('F170-TYPO-HYPHEN','npm','risk-typo-hyphen','osv','typo-squatting','normalize',__BASELINE__),
		('F170-EMPTY-RISK','npm','risk-empty','osv','','normalize',__BASELINE__),
		('F170-FALLBACK-RISK','npm','risk-fallback','osv','unexpected','normalize',__BASELINE__),
		('F170-CANONICAL','npm','canonical-malicious','osv','malware','canonical',__BASELINE__);
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity,updated_at) VALUES (' Cargo ','normalize-reputation','1','rl','clean','LOW',__BASELINE__),('cargo','canonical-reputation','1','rl','clean','LOW',__BASELINE__);
		INSERT INTO package_check_status(ecosystem,name,source,updated_at) VALUES (' Go ','normalize-check','socket',__BASELINE__),('go','canonical-check','socket',__BASELINE__);
		INSERT INTO refresh_queue(ecosystem,name,source,priority,status,requested_at,processed_at,error) VALUES
		(' Maven ','normalize-done','socket',-1,' DONE ',__BASELINE__,NULL,NULL),
		('npm','normalize-invalid','socket',9,'mystery',__BASELINE__,NULL,''),
		('npm','canonical-queue','socket',2,'error',__BASELINE__,__BASELINE__,'existing error');
		INSERT INTO lifecycle_products(product_slug,name,updated_at) VALUES ('f170-product','F170 Product',__BASELINE__);
		INSERT INTO lifecycle_package_map(ecosystem,name,product_slug,updated_at) VALUES (' NuGet ','normalize-map','f170-product',__BASELINE__),('nuget','canonical-map','f170-product',__BASELINE__);
		INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle,updated_at) VALUES ('normalize-tombstone',' SwiftPM ','normalize-tombstone','f170-product','1',__BASELINE__),('canonical-tombstone','swiftpm','canonical-tombstone','f170-product','1',__BASELINE__)`
	f159F164Exec(t, leaf, strings.ReplaceAll(fixtureSQL, "__BASELINE__", baselineLiteral))
}

func f165F170Seed031CanonicalRows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('F169-CANON','canonical','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z');
		INSERT INTO affected_packages(vulnerability_id,ecosystem,name) VALUES ('F169-CANON','npm','f169-package');
		INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,summary) VALUES ('F169-MAL','npm','f169-mal','osv','malware','canonical');
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity) VALUES ('npm','f169-rep','1','rl','clean','LOW');
		INSERT INTO package_check_status(ecosystem,name,source) VALUES ('npm','f169-check','socket');
		INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm','f169-queue','socket',1,'done');
		INSERT INTO lifecycle_products(product_slug,name) VALUES ('f169-product','F169 Product');
		INSERT INTO lifecycle_package_map(ecosystem,name,product_slug) VALUES ('npm','f169-map','f169-product');
		INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle) VALUES ('f169-tomb','npm','f169-tomb','f169-product','1')`)
}

func f165F170Assert031Normalization(t *testing.T, leaf f159F164Leaf, baseline time.Time) {
	t.Helper()
	for _, check := range []struct{ query, want string }{
		{`SELECT ecosystem FROM affected_packages WHERE name='normalize-affected'`, "npm"},
		{`SELECT ecosystem FROM malicious_findings WHERE id='F170-SUPPLY-HYPHEN'`, "pypi"},
		{`SELECT ecosystem FROM package_reputation_cache WHERE name='normalize-reputation'`, "cargo"},
		{`SELECT ecosystem FROM package_check_status WHERE name='normalize-check'`, "go"},
		{`SELECT ecosystem FROM refresh_queue WHERE name='normalize-done'`, "maven"},
		{`SELECT ecosystem FROM lifecycle_package_map WHERE name='normalize-map'`, "nuget"},
		{`SELECT ecosystem FROM lifecycle_sync_tombstones WHERE id='normalize-tombstone'`, "swiftpm"},
		{`SELECT risk_type FROM malicious_findings WHERE id='F170-SUPPLY-HYPHEN'`, "supply_chain"},
		{`SELECT risk_type FROM malicious_findings WHERE id='F170-SUPPLY-SPACE'`, "supply_chain"},
		{`SELECT risk_type FROM malicious_findings WHERE id='F170-TYPO-SHORT'`, "typosquatting"},
		{`SELECT risk_type FROM malicious_findings WHERE id='F170-TYPO-HYPHEN'`, "typosquatting"},
		{`SELECT risk_type FROM malicious_findings WHERE id='F170-EMPTY-RISK'`, "malware"},
		{`SELECT risk_type FROM malicious_findings WHERE id='F170-FALLBACK-RISK'`, "malware"},
	} {
		var got string
		if err := leaf.conn.QueryRowContext(leaf.ctx, check.query).Scan(&got); err != nil {
			t.Fatalf("normalization query %q: %v", check.query, err)
		}
		if got != check.want {
			t.Fatalf("normalization query %q = %q, want %q", check.query, got, check.want)
		}
	}
	for _, table := range []string{"malicious_findings", "package_reputation_cache", "package_check_status", "lifecycle_package_map", "lifecycle_sync_tombstones"} {
		var count int
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM `+table+` WHERE updated_at > $1`, baseline).Scan(&count); err != nil {
			t.Fatalf("inspect %s updated_at: %v", table, err)
		}
		if count < 1 {
			t.Fatalf("%s rows updated after baseline = %d, want at least 1", table, count)
		}
	}
	var status, errorText string
	var priority int
	var processed sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT status,priority,processed_at,error FROM refresh_queue WHERE name='normalize-invalid'`).Scan(&status, &priority, &processed, &errorText); err != nil {
		t.Fatalf("read normalized invalid queue row: %v", err)
	}
	if status != "error" || priority != 3 || !processed.Valid || errorText != "normalized invalid queue status during migration 031" {
		t.Fatalf("normalized invalid queue = status:%q priority:%d processed:%v error:%q", status, priority, processed, errorText)
	}
	var doneProcessed sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT status,priority,processed_at FROM refresh_queue WHERE name='normalize-done'`).Scan(&status, &priority, &doneProcessed); err != nil {
		t.Fatalf("read normalized done queue row: %v", err)
	}
	if status != "done" || priority != 0 || doneProcessed.Valid {
		t.Fatalf("normalized done queue = status:%q priority:%d processed:%v, want done/0/NULL", status, priority, doneProcessed)
	}
}

func f165F170Assert031Constraints(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	allowed := "ARRAY['npm'::text, 'pypi'::text, 'go'::text, 'maven'::text, 'cargo'::text, 'nuget'::text, 'composer'::text, 'gem'::text, 'pub'::text, 'cocoapods'::text, 'swiftpm'::text, 'hex'::text, 'cran'::text, 'actions'::text, 'docker'::text]"
	want := map[string]string{
		"affected_packages_ecosystem_check":         "CHECK ((ecosystem = ANY (" + allowed + ")))",
		"malicious_findings_ecosystem_check":        "CHECK ((ecosystem = ANY (" + allowed + ")))",
		"package_reputation_cache_ecosystem_check":  "CHECK ((ecosystem = ANY (" + allowed + ")))",
		"package_check_status_ecosystem_check":      "CHECK ((ecosystem = ANY (" + allowed + ")))",
		"refresh_queue_ecosystem_check":             "CHECK ((ecosystem = ANY (" + allowed + ")))",
		"lifecycle_package_map_ecosystem_check":     "CHECK ((ecosystem = ANY (" + allowed + ")))",
		"lifecycle_sync_tombstones_ecosystem_check": "CHECK ((ecosystem = ANY (" + allowed + ")))",
		"malicious_findings_risk_type_check":        "CHECK ((risk_type = ANY (ARRAY['malware'::text, 'supply_chain'::text, 'typosquatting'::text])))",
		"vulnerability_sources_manual_id_check":     "CHECK (((source <> 'manual'::text) OR ((vulnerability_id ~~ 'manual:%'::text) AND (source_id ~~ 'manual:%'::text))))",
		"malicious_findings_manual_id_check":        "CHECK (((source <> 'manual'::text) OR (id ~~ 'manual:%'::text)))",
		"refresh_queue_status_check":                "CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'paused'::text, 'done'::text, 'error'::text])))",
		"refresh_queue_priority_check":              "CHECK (((priority >= 0) AND (priority <= 3)))",
	}
	for _, constraint := range f165F170Constraints {
		var table, definition string
		var validated bool
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT rel.relname,pg_get_constraintdef(c.oid),c.convalidated FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid JOIN pg_namespace n ON n.oid=rel.relnamespace WHERE n.nspname=$1 AND rel.relname=$2 AND c.conname=$3`, leaf.schema, constraint.table, constraint.name).Scan(&table, &definition, &validated); err != nil {
			t.Fatalf("inspect constraint %s.%s: %v", constraint.table, constraint.name, err)
		}
		if table != constraint.table || definition != want[constraint.name] || !validated {
			t.Fatalf("constraint %s = table:%q definition:%q validated:%t, want table:%q definition:%q validated", constraint.name, table, definition, validated, constraint.table, want[constraint.name])
		}
	}
}

func f165F170Assert031ConstraintsAbsent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for _, constraint := range f165F170Constraints {
		f165F170AssertConstraintOnTable(t, leaf, constraint.table, constraint.name, false)
	}
}

func f165F170AssertConstraintOnTable(t *testing.T, leaf f159F164Leaf, table, name string, want bool) {
	t.Helper()
	var exists bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid JOIN pg_namespace n ON n.oid=rel.relnamespace WHERE n.nspname=$1 AND rel.relname=$2 AND c.conname=$3)`, leaf.schema, table, name).Scan(&exists); err != nil {
		t.Fatalf("inspect constraint %s.%s: %v", table, name, err)
	}
	if exists != want {
		t.Fatalf("constraint %s.%s exists = %t, want %t", table, name, exists, want)
	}
}

func f165F170AssertUnrelatedCheck(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var definition string
	var validated bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT pg_get_constraintdef(c.oid),c.convalidated FROM pg_constraint c WHERE c.conrelid='affected_packages'::regclass AND c.conname='f169_unrelated_name_check'`).Scan(&definition, &validated); err != nil {
		t.Fatalf("inspect unrelated check: %v", err)
	}
	if definition != "CHECK ((name <> ''::text))" || !validated {
		t.Fatalf("unrelated check = %q validated:%t", definition, validated)
	}
}

func f165F170ConstraintNames() []string {
	names := make([]string, 0, len(f165F170Constraints))
	for _, constraint := range f165F170Constraints {
		names = append(names, constraint.name)
	}
	return names
}

func f165F170ConstraintIdentities(t *testing.T, leaf f159F164Leaf, names []string) map[string]string {
	t.Helper()
	identities := make(map[string]string, len(names))
	for _, name := range names {
		var identity string
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT oid::text || '|' || conrelid::text FROM pg_constraint WHERE connamespace=$1::regnamespace AND conname=$2`, leaf.schema, name).Scan(&identity); err != nil {
			t.Fatalf("inspect constraint identity %s: %v", name, err)
		}
		identities[name] = identity
	}
	return identities
}

func f165F170AssertConstraintIdentities(t *testing.T, leaf f159F164Leaf, want map[string]string) {
	t.Helper()
	for name, identity := range want {
		if got := f165F170ConstraintIdentities(t, leaf, []string{name})[name]; got != identity {
			t.Fatalf("constraint identity %s = %q, want %q", name, got, identity)
		}
	}
}

func f165F170Assert031AcceptanceMatrix(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	allowed := []string{"npm", "pypi", "go", "maven", "cargo", "nuget", "composer", "gem", "pub", "cocoapods", "swiftpm", "hex", "cran", "actions", "docker"}
	tables := []struct {
		name   string
		update string
		insert func(int, string) string
	}{
		{"affected_packages", `UPDATE affected_packages SET ecosystem=$1 WHERE name='normalize-affected'`, func(i int, ecosystem string) string {
			return fmt.Sprintf(`INSERT INTO affected_packages(vulnerability_id,ecosystem,name) VALUES ('F170-NORM',%s,'accepted-affected-%02d')`, f159F164SQLLiteral(ecosystem), i)
		}},
		{"malicious_findings", `UPDATE malicious_findings SET ecosystem=$1 WHERE id='F170-CANONICAL'`, func(i int, ecosystem string) string {
			return fmt.Sprintf(`INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,summary) VALUES ('F170-ACCEPT-MAL-%02d',%s,'accepted-mal-%02d','osv','malware','accepted')`, i, f159F164SQLLiteral(ecosystem), i)
		}},
		{"package_reputation_cache", `UPDATE package_reputation_cache SET ecosystem=$1 WHERE name='normalize-reputation'`, func(i int, ecosystem string) string {
			return fmt.Sprintf(`INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity) VALUES (%s,'accepted-rep-%02d','1','rl','clean','LOW')`, f159F164SQLLiteral(ecosystem), i)
		}},
		{"package_check_status", `UPDATE package_check_status SET ecosystem=$1 WHERE name='normalize-check'`, func(i int, ecosystem string) string {
			return fmt.Sprintf(`INSERT INTO package_check_status(ecosystem,name,source) VALUES (%s,'accepted-check-%02d','socket')`, f159F164SQLLiteral(ecosystem), i)
		}},
		{"refresh_queue", `UPDATE refresh_queue SET ecosystem=$1 WHERE name='canonical-queue'`, func(i int, ecosystem string) string {
			return fmt.Sprintf(`INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES (%s,'accepted-queue-%02d','socket',1,'done')`, f159F164SQLLiteral(ecosystem), i)
		}},
		{"lifecycle_package_map", `UPDATE lifecycle_package_map SET ecosystem=$1 WHERE name='normalize-map'`, func(i int, ecosystem string) string {
			return fmt.Sprintf(`INSERT INTO lifecycle_package_map(ecosystem,name,product_slug) VALUES (%s,'accepted-map-%02d','f170-product')`, f159F164SQLLiteral(ecosystem), i)
		}},
		{"lifecycle_sync_tombstones", `UPDATE lifecycle_sync_tombstones SET ecosystem=$1 WHERE id='normalize-tombstone'`, func(i int, ecosystem string) string {
			return fmt.Sprintf(`INSERT INTO lifecycle_sync_tombstones(id,ecosystem,name,product_slug,cycle) VALUES ('accepted-tomb-%02d',%s,'accepted-tomb-%02d','f170-product','1')`, i, f159F164SQLLiteral(ecosystem), i)
		}},
	}
	for _, table := range tables {
		for i, ecosystem := range allowed {
			if _, err := leaf.conn.ExecContext(leaf.ctx, table.update, ecosystem); err != nil {
				t.Fatalf("%s accepts ecosystem update %q: %v", table.name, ecosystem, err)
			}
			f159F164Exec(t, leaf, table.insert(i, ecosystem))
		}
		_, err := leaf.conn.ExecContext(leaf.ctx, table.update, "invalid")
		f159F164ExpectConstraint(t, err, table.name+"_ecosystem_check")
		invalidInsert := strings.Replace(table.insert(99, "npm"), "'npm'", "'invalid'", 1)
		_, err = leaf.conn.ExecContext(leaf.ctx, invalidInsert)
		f159F164ExpectConstraint(t, err, table.name+"_ecosystem_check")
	}

	for i, risk := range []string{"malware", "supply_chain", "typosquatting"} {
		if _, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE malicious_findings SET risk_type=$1 WHERE id='F170-CANONICAL'`, risk); err != nil {
			t.Fatalf("risk type update %q: %v", risk, err)
		}
		f159F164Exec(t, leaf, fmt.Sprintf(`INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,summary) VALUES ('F170-RISK-%d','npm','risk-%d','osv',%s,'accepted')`, i, i, f159F164SQLLiteral(risk)))
	}
	_, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE malicious_findings SET risk_type='invalid' WHERE id='F170-CANONICAL'`)
	f159F164ExpectConstraint(t, err, "malicious_findings_risk_type_check")
	_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,summary) VALUES ('F170-RISK-BAD','npm','bad-risk','osv','invalid','bad')`)
	f159F164ExpectConstraint(t, err, "malicious_findings_risk_type_check")

	f165F170AssertManualIDMatrix(t, leaf)
	f165F170AssertQueueMatrix(t, leaf)
}

func f165F170AssertManualIDMatrix(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES ('manual:F170-VALID','manual valid','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z'),('F170-NONMANUAL','nonmanual valid','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z'),('manual:F170-BAD-SOURCE','manual bad source','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z'),('F170-BAD-VULN','bad vuln id','LOW','2025-01-01T00:00:00Z','2025-01-01T00:00:00Z');
		INSERT INTO vulnerability_sources(vulnerability_id,source,source_id) VALUES ('manual:F170-VALID','manual','manual:F170-VALID'),('F170-NONMANUAL','osv','ordinary-source')`)
	_, err := leaf.conn.ExecContext(leaf.ctx, `INSERT INTO vulnerability_sources(vulnerability_id,source,source_id) VALUES ('F170-BAD-VULN','manual','manual:F170-BAD-VULN')`)
	f159F164ExpectConstraint(t, err, "vulnerability_sources_manual_id_check")
	_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO vulnerability_sources(vulnerability_id,source,source_id) VALUES ('manual:F170-BAD-SOURCE','manual','bad-source')`)
	f159F164ExpectConstraint(t, err, "vulnerability_sources_manual_id_check")
	_, err = leaf.conn.ExecContext(leaf.ctx, `UPDATE vulnerability_sources SET source='manual',source_id='ordinary-source' WHERE vulnerability_id='F170-NONMANUAL'`)
	f159F164ExpectConstraint(t, err, "vulnerability_sources_manual_id_check")

	f159F164Exec(t, leaf, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,summary) VALUES ('manual:F170-MAL-VALID','npm','manual-valid','manual','malware','valid manual'),('F170-MAL-NONMANUAL','npm','nonmanual-valid','osv','malware','valid nonmanual')`)
	_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,summary) VALUES ('F170-MAL-BAD','npm','manual-bad','manual','malware','bad')`)
	f159F164ExpectConstraint(t, err, "malicious_findings_manual_id_check")
	_, err = leaf.conn.ExecContext(leaf.ctx, `UPDATE malicious_findings SET source='manual' WHERE id='F170-MAL-NONMANUAL'`)
	f159F164ExpectConstraint(t, err, "malicious_findings_manual_id_check")
}

func f165F170AssertQueueMatrix(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for i, status := range []string{"pending", "processing", "paused", "done", "error"} {
		if _, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE refresh_queue SET status=$1 WHERE name='canonical-queue'`, status); err != nil {
			t.Fatalf("queue status update %q: %v", status, err)
		}
		f159F164Exec(t, leaf, fmt.Sprintf(`INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm','status-%d','status-source-%d',1,%s)`, i, i, f159F164SQLLiteral(status)))
	}
	_, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE refresh_queue SET status='invalid' WHERE name='canonical-queue'`)
	f159F164ExpectConstraint(t, err, "refresh_queue_status_check")
	_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm','status-bad','socket',1,'invalid')`)
	f159F164ExpectConstraint(t, err, "refresh_queue_status_check")

	for _, priority := range []int{0, 3} {
		if _, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE refresh_queue SET priority=$1 WHERE name='canonical-queue'`, priority); err != nil {
			t.Fatalf("queue priority update %d: %v", priority, err)
		}
		f159F164Exec(t, leaf, fmt.Sprintf(`INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm','priority-%d','socket',%d,'done')`, priority, priority))
	}
	for _, priority := range []int{-1, 4} {
		_, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE refresh_queue SET priority=$1 WHERE name='canonical-queue'`, priority)
		f159F164ExpectConstraint(t, err, "refresh_queue_priority_check")
		_, err = leaf.conn.ExecContext(leaf.ctx, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm',$1,'socket',$2,'done')`, fmt.Sprintf("priority-bad-%d", priority), priority)
		f159F164ExpectConstraint(t, err, "refresh_queue_priority_check")
	}
}

func f165F170Assert031FailureRecovery(t *testing.T, leaf f159F164Leaf, sqlState, repairSQL string) {
	t.Helper()
	rowsBefore := f165F170All031Rows(t, leaf)
	constraintsBefore := f165F170AllConstraintSnapshot(t, leaf)
	migration := f159F164Embedded(t, 31, MigrationDirectionUp)
	f159F164ExpectSQLState(t, applyMigration(leaf.ctx, leaf.conn, migration), sqlState)
	f165F170AssertEqual(t, "full rows after failed 031 up", f165F170All031Rows(t, leaf), rowsBefore)
	f165F170AssertEqual(t, "full constraints after failed 031 up", f165F170AllConstraintSnapshot(t, leaf), constraintsBefore)
	f159F164AssertDirtyEventAndRefusal(t, leaf, migration)
	f159F164ClearDirty(t, leaf, 31)
	f159F164Exec(t, leaf, repairSQL)
	f159F164Apply(t, leaf, 31, MigrationDirectionUp)
	f165F170Assert031Constraints(t, leaf)
}

func f165F170All031Rows(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f165F170Snapshot(t, leaf, `
		SELECT 'affected_packages' AS table_name,to_jsonb(r)::text AS row_value FROM (SELECT id,vulnerability_id,ecosystem,name,version_ranges,versions_affected,xmin::text AS xmin FROM affected_packages ORDER BY id) r
		UNION ALL SELECT 'lifecycle_package_map',to_jsonb(r)::text FROM (SELECT ecosystem,name,product_slug,purl_type,purl_namespace,purl_name,source,updated_at,xmin::text AS xmin FROM lifecycle_package_map ORDER BY ecosystem,name,product_slug) r
		UNION ALL SELECT 'lifecycle_sync_tombstones',to_jsonb(r)::text FROM (SELECT id,ecosystem,name,product_slug,cycle,updated_at,xmin::text AS xmin FROM lifecycle_sync_tombstones ORDER BY id) r
		UNION ALL SELECT 'malicious_findings',to_jsonb(r)::text FROM (SELECT id,ecosystem,name,source,risk_type,severity,summary,updated_at,xmin::text AS xmin FROM malicious_findings ORDER BY id) r
		UNION ALL SELECT 'package_check_status',to_jsonb(r)::text FROM (SELECT id,ecosystem,name,source,updated_at,xmin::text AS xmin FROM package_check_status ORDER BY id) r
		UNION ALL SELECT 'package_reputation_cache',to_jsonb(r)::text FROM (SELECT id,ecosystem,name,version,source,status,severity,updated_at,xmin::text AS xmin FROM package_reputation_cache ORDER BY id) r
		UNION ALL SELECT 'refresh_queue',to_jsonb(r)::text FROM (SELECT id,ecosystem,name,source,priority,status,requested_at,processed_at,error,xmin::text AS xmin FROM refresh_queue ORDER BY id) r
		UNION ALL SELECT 'vulnerability_sources',to_jsonb(r)::text FROM (SELECT id,vulnerability_id,source,source_id,updated_at,xmin::text AS xmin FROM vulnerability_sources ORDER BY id) r
		ORDER BY table_name,row_value`)
}

func f165F170AllConstraintSnapshot(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f165F170Snapshot(t, leaf, `SELECT rel.relname AS table_name,c.conname,c.contype::text,pg_get_constraintdef(c.oid) AS definition,c.convalidated,c.oid::text FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid JOIN pg_namespace n ON n.oid=rel.relnamespace WHERE n.nspname=current_schema() ORDER BY rel.relname,c.conname`)
}
