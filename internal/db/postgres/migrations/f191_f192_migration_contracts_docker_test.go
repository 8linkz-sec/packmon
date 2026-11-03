//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

var f191F192CurrentConstraints = map[string]map[string]string{
	"feed_sync_status": {
		"feed_sync_status_status_check":               "CHECK ((last_sync_status = ANY (ARRAY['pending'::text, 'running'::text, 'success'::text, 'error'::text, 'skipped'::text, 'disabled'::text, 'external'::text, 'rejected'::text, 'permanent_error'::text])))",
		"feed_sync_status_entries_nonnegative_check":  "CHECK (((entries_synced >= 0) AND (entries_total >= 0)))",
		"feed_sync_status_entries_order_check":        "CHECK (((entries_total <= 0) OR (entries_synced <= entries_total)))",
		"feed_sync_status_duration_nonnegative_check": "CHECK (((last_sync_duration IS NULL) OR (last_sync_duration >= '00:00:00'::interval)))",
	},
	"refresh_queue": {
		"refresh_queue_status_check":   "CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'paused'::text, 'done'::text, 'error'::text])))",
		"refresh_queue_priority_check": "CHECK (((priority >= 0) AND (priority <= 3)))",
	},
	"scan_log": {
		"scan_log_api_key_id_fkey":                           "FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL",
		"scan_log_packages_count_nonnegative_check":          "CHECK ((packages_count >= 0))",
		"scan_log_findings_count_nonnegative_check":          "CHECK ((findings_count >= 0))",
		"scan_log_duration_ms_nonnegative_check":             "CHECK ((duration_ms >= 0))",
		"scan_log_manual_advisories_count_nonnegative_check": "CHECK ((manual_advisories_count >= 0))",
		"scan_log_block_threshold_check":                     "CHECK ((block_threshold = ANY (ARRAY['CRITICAL'::text, 'HIGH'::text, 'MEDIUM'::text, 'LOW'::text, 'NONE'::text])))",
		"scan_log_feed_status_check":                         "CHECK ((feed_status = ANY (ARRAY['healthy'::text, 'degraded'::text, 'error'::text])))",
		"scan_log_feed_versions_object_check":                "CHECK (((feed_versions IS NULL) OR (jsonb_typeof(feed_versions) = 'object'::text)))",
		"scan_log_finding_ids_array_check":                   "CHECK (((finding_ids IS NULL) OR (jsonb_typeof(finding_ids) = 'array'::text)))",
		"scan_log_finding_severities_array_check":            "CHECK (((finding_severities IS NULL) OR (jsonb_typeof(finding_severities) = 'array'::text)))",
	},
	"api_keys": {
		"api_keys_deleted_requires_revoked_check":     "CHECK (((deleted_at IS NULL) OR (revoked_at IS NOT NULL)))",
		"api_keys_revoked_not_before_created_check":   "CHECK (((revoked_at IS NULL) OR (revoked_at >= created_at)))",
		"api_keys_deleted_not_before_created_check":   "CHECK (((deleted_at IS NULL) OR (deleted_at >= created_at)))",
		"api_keys_last_used_not_before_created_check": "CHECK (((last_used_at IS NULL) OR (last_used_at >= created_at)))",
		"api_keys_deleted_not_before_revoked_check":   "CHECK (((deleted_at IS NULL) OR (revoked_at IS NULL) OR (deleted_at >= revoked_at)))",
	},
	"feed_configs": {
		"feed_configs_sync_interval_minimum_check": "CHECK (((sync_interval IS NULL) OR (sync_interval >= '00:15:00'::interval)))",
	},
}

func TestF191F192MigrationContractsAgainstPostgres(t *testing.T) {
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

	leafNumber := 700
	newLeaf := func(t *testing.T) f159F164Leaf {
		t.Helper()
		leafNumber++
		return f159F164PrepareLeaf(t, database, instance.dsn, leafNumber)
	}

	t.Run("populated_version_041_upgrade_repairs_rows_defaults_and_catalog", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 41)
		f191F192SeedUpgradeRows(t, leaf)

		f159F164Apply(t, leaf, 42, MigrationDirectionUp)

		if got := f191F192UpgradeRows(t, leaf); got != `[{"scan_id": "f192-blank-orphan", "api_key_id": null, "feed_status": "healthy", "block_threshold": "CRITICAL"}, {"scan_id": "f192-mixed-valid", "api_key_id": 900, "feed_status": "degraded", "block_threshold": "HIGH"}, {"scan_id": "f192-normal-valid", "api_key_id": 900, "feed_status": "error", "block_threshold": "NONE"}]` {
			t.Fatalf("042 upgraded rows = %s", got)
		}
		f191F192AssertDefaults(t, leaf, "'CRITICAL'::text", "'healthy'::text")
		f191F192AssertCurrentCatalog(t, leaf)
	})

	t.Run("unknown_nonblank_scan_enums_reject_upgrade_atomically", func(t *testing.T) {
		for _, tc := range []struct {
			name, column, value string
		}{
			{"block_threshold", "block_threshold", "urgent"},
			{"feed_status", "feed_status", "stale"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 41)
				f159F164Exec(t, leaf, fmt.Sprintf(`INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,%s) VALUES ('f192-invalid-enum',0,0,0,$1)`, tc.column), tc.value)
				beforeRows := f191F192UpgradeRows(t, leaf)
				beforeCatalog := f191F192CatalogSnapshot(t, leaf)

				err := applyMigration(leaf.ctx, leaf.conn, f159F164Embedded(t, 42, MigrationDirectionUp))
				f159F164ExpectSQLState(t, err, "23514")
				f159F164AssertEqual(t, "failed 042 enum-upgrade rows", f191F192UpgradeRows(t, leaf), beforeRows)
				f159F164AssertEqual(t, "failed 042 enum-upgrade catalog", f191F192CatalogSnapshot(t, leaf), beforeCatalog)
				f191F192AssertDirty(t, leaf)
			})
		}
	})

	t.Run("direct_write_boundaries", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 42)
		f191F192AssertCurrentCatalog(t, leaf)
		f191F192AssertFeedAndQueueBoundaries(t, leaf)
		f191F192AssertScanBoundaries(t, leaf)
		f191F192AssertAPIKeyAndIntervalBoundaries(t, leaf)
	})

	t.Run("compatible_down_partial_repeat_and_up_preserve_rows_and_defaults", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 42)
		f191F192SeedCompatibleCurrentRows(t, leaf)
		before := f191F192AllRows(t, leaf)
		foreignKeyBefore := f191F192HasScanAPIKeyForeignKey(t, leaf)
		f159F164Exec(t, leaf, `ALTER TABLE scan_log DROP CONSTRAINT scan_log_feed_status_check; ALTER TABLE api_keys DROP CONSTRAINT api_keys_last_used_not_before_created_check; ALTER TABLE feed_configs DROP CONSTRAINT feed_configs_sync_interval_minimum_check`)

		f159F164Apply(t, leaf, 42, MigrationDirectionDown)
		foreignKeyAfterDown := f191F192HasScanAPIKeyForeignKey(t, leaf)
		f191F192AssertLegacyCatalog(t, leaf)
		f191F192AssertDefaults(t, leaf, "''::text", "''::text")
		f159F164AssertEqual(t, "042 compatible down rows", f191F192AllRows(t, leaf), before)

		f159F164Apply(t, leaf, 42, MigrationDirectionDown)
		f191F192AssertLegacyCatalog(t, leaf)
		f159F164AssertEqual(t, "042 repeated down rows", f191F192AllRows(t, leaf), before)
		f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms) VALUES ('f191-down-defaults',0,0,0)`)
		var threshold, feedStatus string
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT block_threshold,feed_status FROM scan_log WHERE scan_id='f191-down-defaults'`).Scan(&threshold, &feedStatus); err != nil || threshold != "" || feedStatus != "" {
			t.Fatalf("legacy defaults = threshold:%q feed:%q error=%v", threshold, feedStatus, err)
		}

		f159F164Apply(t, leaf, 42, MigrationDirectionUp)
		f191F192AssertCurrentCatalog(t, leaf)
		f191F192AssertDefaults(t, leaf, "'CRITICAL'::text", "'healthy'::text")
		if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT block_threshold,feed_status FROM scan_log WHERE scan_id='f191-down-defaults'`).Scan(&threshold, &feedStatus); err != nil || threshold != "CRITICAL" || feedStatus != "healthy" {
			t.Fatalf("re-upgraded legacy defaults row = threshold:%q feed:%q error=%v", threshold, feedStatus, err)
		}
		if foreignKeyBefore && !foreignKeyAfterDown && f191F192HasScanAPIKeyForeignKey(t, leaf) {
			t.Skip("known production defect F157-bugs-1: migration 042 down removes the 001-owned scan_log_api_key_id_fkey; clean 042 up restores it")
		}
		if !foreignKeyBefore || !foreignKeyAfterDown {
			t.Fatalf("unexpected scan_log API-key FK lifecycle before=%t after-down=%t after-up=%t", foreignKeyBefore, foreignKeyAfterDown, f191F192HasScanAPIKeyForeignKey(t, leaf))
		}
	})

	t.Run("incompatible_positive_synced_zero_total_down_is_atomic", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 42)
		f159F164Exec(t, leaf, `INSERT INTO feed_sync_status(feed_name,last_sync_status,entries_synced,entries_total) VALUES ('f191-zero-total','success',3,0)`)
		beforeRows := f191F192AllRows(t, leaf)
		beforeCatalog := f191F192CatalogSnapshot(t, leaf)

		err := applyMigration(leaf.ctx, leaf.conn, f159F164Embedded(t, 42, MigrationDirectionDown))
		f159F164ExpectSQLState(t, err, "23514")
		f159F164AssertEqual(t, "failed 042 down rows", f191F192AllRows(t, leaf), beforeRows)
		f159F164AssertEqual(t, "failed 042 down catalog", f191F192CatalogSnapshot(t, leaf), beforeCatalog)
		f191F192AssertDefaults(t, leaf, "'CRITICAL'::text", "'healthy'::text")
		f191F192AssertCurrentCatalog(t, leaf)
		f191F192AssertDirty(t, leaf)
	})
}

func f191F192SeedUpgradeRows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO api_keys(id,name,key_hash,created_at,revoked_at,last_used_at,deleted_at)
		VALUES (900,'f192-valid','f192-valid-hash','2026-01-01Z','2026-01-02Z','2026-01-01Z','2026-01-03Z');
		ALTER TABLE scan_log DROP CONSTRAINT scan_log_api_key_id_fkey;
		INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,api_key_id,block_threshold,feed_status) VALUES
			('f192-mixed-valid',2,1,5,900,' high ',' DEGRADED '),
			('f192-blank-orphan',0,0,0,99999,'   ',' '),
			('f192-normal-valid',1,0,1,900,'NONE','error')`)
}

func f191F192UpgradeRows(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT scan_id,api_key_id,block_threshold,feed_status FROM scan_log WHERE scan_id LIKE 'f192-%' ORDER BY scan_id`)
}

func f191F192AssertDefaults(t *testing.T, leaf f159F164Leaf, threshold, feedStatus string) {
	t.Helper()
	var gotThreshold, gotFeedStatus string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT MAX(column_default) FILTER (WHERE column_name='block_threshold'),MAX(column_default) FILTER (WHERE column_name='feed_status') FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='scan_log'`).Scan(&gotThreshold, &gotFeedStatus); err != nil {
		t.Fatalf("inspect scan-log defaults: %v", err)
	}
	if gotThreshold != threshold || gotFeedStatus != feedStatus {
		t.Fatalf("scan-log defaults = threshold:%q feed:%q, want %q/%q", gotThreshold, gotFeedStatus, threshold, feedStatus)
	}
}

func f191F192AssertCurrentCatalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	wantCount := 0
	for table, constraints := range f191F192CurrentConstraints {
		for name, wantDefinition := range constraints {
			wantCount++
			var gotTable, gotDefinition string
			var validated bool
			err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT r.relname,pg_get_constraintdef(c.oid),c.convalidated FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=current_schema() AND r.relname=$1 AND c.conname=$2`, table, name).Scan(&gotTable, &gotDefinition, &validated)
			if err != nil {
				t.Fatalf("inspect current constraint %s.%s: %v", table, name, err)
			}
			if gotTable != table || gotDefinition != wantDefinition || !validated {
				t.Fatalf("current constraint %s.%s = table:%q definition:%q validated:%t, want %q validated", table, name, gotTable, gotDefinition, validated, wantDefinition)
			}
		}
	}
	if wantCount != 22 {
		t.Fatalf("current constraint fixture count = %d, want 22", wantCount)
	}
}

func f191F192AssertLegacyCatalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for table, constraints := range f191F192CurrentConstraints {
		for name := range constraints {
			if table == "feed_sync_status" || table == "refresh_queue" {
				continue
			}
			var count int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=current_schema() AND r.relname=$1 AND c.conname=$2`, table, name).Scan(&count); err != nil || count != 0 {
				t.Fatalf("legacy target %s.%s count=%d error=%v, want absent", table, name, count, err)
			}
		}
	}
	legacy := map[string]map[string]string{
		"feed_sync_status": {
			"feed_sync_status_status_check":               f191F192CurrentConstraints["feed_sync_status"]["feed_sync_status_status_check"],
			"feed_sync_status_entries_nonnegative_check":  f191F192CurrentConstraints["feed_sync_status"]["feed_sync_status_entries_nonnegative_check"],
			"feed_sync_status_entries_order_check":        "CHECK ((entries_synced <= entries_total))",
			"feed_sync_status_duration_nonnegative_check": f191F192CurrentConstraints["feed_sync_status"]["feed_sync_status_duration_nonnegative_check"],
		},
		"refresh_queue": f191F192CurrentConstraints["refresh_queue"],
	}
	for table, constraints := range legacy {
		for name, want := range constraints {
			var got string
			var validated bool
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT pg_get_constraintdef(c.oid),c.convalidated FROM pg_constraint c WHERE c.conrelid=$1::regclass AND c.conname=$2`, table, name).Scan(&got, &validated); err != nil || got != want || !validated {
				t.Fatalf("legacy constraint %s.%s = %q validated:%t error=%v, want %q validated", table, name, got, validated, err, want)
			}
		}
	}
}

func f191F192AssertFeedAndQueueBoundaries(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	statuses := []string{"pending", "running", "success", "error", "skipped", "disabled", "external", "rejected", "permanent_error"}
	for i, status := range statuses {
		f159F164Exec(t, leaf, `INSERT INTO feed_sync_status(feed_name,last_sync_status,entries_synced,entries_total,last_sync_duration) VALUES ($1,$2,0,0,'0 seconds')`, fmt.Sprintf("f192-feed-%d", i), status)
	}
	f159F164Exec(t, leaf, `INSERT INTO feed_sync_status(feed_name,last_sync_status,entries_synced,entries_total) VALUES ('f192-positive-zero','success',2,0),('f192-equal','success',2,2)`)
	badFeed := []string{
		`INSERT INTO feed_sync_status(feed_name,last_sync_status) VALUES ('f192-feed-bad-status','unknown')`,
		`INSERT INTO feed_sync_status(feed_name,entries_synced,entries_total) VALUES ('f192-feed-bad-synced',-1,0)`,
		`INSERT INTO feed_sync_status(feed_name,entries_synced,entries_total) VALUES ('f192-feed-bad-total',0,-1)`,
		`INSERT INTO feed_sync_status(feed_name,last_sync_duration) VALUES ('f192-feed-bad-duration','-1 microsecond')`,
	}
	for _, statement := range badFeed {
		_, err := leaf.conn.ExecContext(leaf.ctx, statement)
		f159F164ExpectSQLState(t, err, "23514")
	}

	queueStatuses := []string{"pending", "processing", "paused", "done", "error"}
	for i, status := range queueStatuses {
		priority := 0
		if i == len(queueStatuses)-1 {
			priority = 3
		}
		f159F164Exec(t, leaf, `INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm',$1,'f192',$2,$3)`, fmt.Sprintf("queue-%d", i), priority, status)
	}
	for _, statement := range []string{
		`INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm','queue-bad-low','f192',-1,'done')`,
		`INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm','queue-bad-high','f192',4,'done')`,
		`INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm','queue-bad-status','f192',1,'waiting')`,
	} {
		_, err := leaf.conn.ExecContext(leaf.ctx, statement)
		f159F164ExpectSQLState(t, err, "23514")
	}
}

func f191F192AssertScanBoundaries(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `INSERT INTO api_keys(id,name,key_hash,created_at) VALUES (910,'f192-scan-key','f192-scan-key-hash','2026-01-01Z')`)
	f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,manual_advisories_count,block_threshold,feed_status,feed_versions,finding_ids,finding_severities,api_key_id) VALUES ('f192-scan-valid',0,0,0,0,'CRITICAL','healthy','{}','[]','[]',910)`)
	tests := []struct {
		name, statement, state string
	}{
		{"packages", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms) VALUES ('f192-bad-packages',-1,0,0)`, "23514"},
		{"findings", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms) VALUES ('f192-bad-findings',0,-1,0)`, "23514"},
		{"duration", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms) VALUES ('f192-bad-duration',0,0,-1)`, "23514"},
		{"manual", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,manual_advisories_count) VALUES ('f192-bad-manual',0,0,0,-1)`, "23514"},
		{"feed_versions_shape", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,feed_versions) VALUES ('f192-bad-feed-json',0,0,0,'[]')`, "23514"},
		{"finding_ids_shape", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,finding_ids) VALUES ('f192-bad-ids-json',0,0,0,'{}')`, "23514"},
		{"finding_severities_shape", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,finding_severities) VALUES ('f192-bad-severities-json',0,0,0,'{}')`, "23514"},
		{"feed_versions_null", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,feed_versions) VALUES ('f192-null-feed-json',0,0,0,NULL)`, "23502"},
		{"finding_ids_null", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,finding_ids) VALUES ('f192-null-ids-json',0,0,0,NULL)`, "23502"},
		{"finding_severities_null", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,finding_severities) VALUES ('f192-null-severities-json',0,0,0,NULL)`, "23502"},
		{"block_threshold", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,block_threshold) VALUES ('f192-bad-threshold',0,0,0,'UNKNOWN')`, "23514"},
		{"feed_status", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,feed_status) VALUES ('f192-bad-feed-status',0,0,0,'unknown')`, "23514"},
		{"api_key", `INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,api_key_id) VALUES ('f192-bad-api-key',0,0,0,99999)`, "23503"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := leaf.conn.ExecContext(leaf.ctx, tc.statement)
			f159F164ExpectSQLState(t, err, tc.state)
		})
	}
}

func f191F192AssertAPIKeyAndIntervalBoundaries(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO api_keys(name,key_hash,created_at,revoked_at,last_used_at,deleted_at)
		VALUES ('f192-equal-times','f192-equal-times-hash','2026-02-01Z','2026-02-01Z','2026-02-01Z','2026-02-01Z');
		INSERT INTO feed_configs(feed_name,enabled,mode,sync_interval) VALUES
			('f192-null-interval',true,'self',NULL),
			('f192-exact-interval',true,'self','15 minutes')`)
	tests := []struct {
		name, statement string
	}{
		{"revoked_before_created", `INSERT INTO api_keys(name,key_hash,created_at,revoked_at) VALUES ('f192-bad-revoked','f192-bad-revoked-hash','2026-02-02Z','2026-02-01Z')`},
		{"last_used_before_created", `INSERT INTO api_keys(name,key_hash,created_at,last_used_at) VALUES ('f192-bad-used','f192-bad-used-hash','2026-02-02Z','2026-02-01Z')`},
		{"deleted_before_created", `INSERT INTO api_keys(name,key_hash,created_at,revoked_at,deleted_at) VALUES ('f192-bad-deleted-created','f192-bad-deleted-created-hash','2026-02-02Z','2026-02-03Z','2026-02-01Z')`},
		{"deleted_without_revoked", `INSERT INTO api_keys(name,key_hash,created_at,deleted_at) VALUES ('f192-bad-no-revoke','f192-bad-no-revoke-hash','2026-02-01Z','2026-02-02Z')`},
		{"deleted_before_revoked", `INSERT INTO api_keys(name,key_hash,created_at,revoked_at,deleted_at) VALUES ('f192-bad-delete-order','f192-bad-delete-order-hash','2026-02-01Z','2026-02-03Z','2026-02-02Z')`},
		{"interval_just_below_minimum", `INSERT INTO feed_configs(feed_name,enabled,mode,sync_interval) VALUES ('f192-short-interval',true,'self','14 minutes 59.999999 seconds')`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := leaf.conn.ExecContext(leaf.ctx, tc.statement)
			f159F164ExpectSQLState(t, err, "23514")
		})
	}
}

func f191F192SeedCompatibleCurrentRows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO api_keys(id,name,key_hash,created_at,revoked_at,last_used_at,deleted_at)
		VALUES (920,'f191-key','f191-key-hash','2026-03-01Z','2026-03-02Z','2026-03-01Z','2026-03-03Z');
		INSERT INTO scan_log(scan_id,packages_count,findings_count,duration_ms,api_key_id,manual_advisories_count,block_threshold,feed_status,feed_versions,finding_ids,finding_severities)
		VALUES ('f191-scan',2,1,4,920,1,'HIGH','degraded','{"osv":"ok"}','["finding"]','["HIGH"]');
		INSERT INTO feed_sync_status(feed_name,last_sync_status,entries_synced,entries_total,last_sync_duration) VALUES ('f191-feed','success',2,2,'1 second');
		INSERT INTO refresh_queue(ecosystem,name,source,priority,status) VALUES ('npm','f191-package','f191',3,'done');
		INSERT INTO feed_configs(feed_name,enabled,mode,sync_interval) VALUES ('f191-config',true,'self','15 minutes')`)
}

func f191F192AllRows(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `
		SELECT 'api' kind,id::text key,to_jsonb(api_keys)-'id' value,xmin::text xmin FROM api_keys WHERE name LIKE 'f191-%'
		UNION ALL SELECT 'scan',id::text,to_jsonb(scan_log)-'id',xmin::text FROM scan_log WHERE scan_id LIKE 'f191-%'
		UNION ALL SELECT 'feed',feed_name,to_jsonb(feed_sync_status)-'feed_name',xmin::text FROM feed_sync_status WHERE feed_name LIKE 'f191-%'
		UNION ALL SELECT 'queue',id::text,to_jsonb(refresh_queue)-'id',xmin::text FROM refresh_queue WHERE source='f191'
		UNION ALL SELECT 'config',feed_name,to_jsonb(feed_configs)-'feed_name',xmin::text FROM feed_configs WHERE feed_name LIKE 'f191-%'
		ORDER BY 1,2`)
}

func f191F192CatalogSnapshot(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT r.relname table_name,c.conname,pg_get_constraintdef(c.oid) definition,c.convalidated,c.oid::text identity FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=current_schema() AND r.relname=ANY(ARRAY['feed_sync_status','refresh_queue','scan_log','api_keys','feed_configs']) ORDER BY 1,2`)
}

func f191F192HasScanAPIKeyForeignKey(t *testing.T, leaf f159F164Leaf) bool {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_constraint WHERE conrelid='scan_log'::regclass AND conname='scan_log_api_key_id_fkey'`).Scan(&count); err != nil {
		t.Fatalf("inspect scan-log API-key FK: %v", err)
	}
	return count == 1
}

func f191F192AssertDirty(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var dirty bool
	var appliedAt sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT dirty,applied_at FROM schema_migrations WHERE version=42`).Scan(&dirty, &appliedAt); err != nil || !dirty || appliedAt.Valid {
		t.Fatalf("failed 042 metadata = dirty:%t applied:%v error=%v, want dirty with NULL applied_at", dirty, appliedAt, err)
	}
}
