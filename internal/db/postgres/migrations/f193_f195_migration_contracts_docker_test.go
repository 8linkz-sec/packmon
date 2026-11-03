//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

var f193F195OldIndexes043 = []f177F182IndexContract{
	{"idx_admin_audit_digest", "admin_audit_log", "row_digest", ""},
	{"idx_api_keys_hash", "api_keys", "key_hash", ""},
	{"idx_api_keys_expires_at", "api_keys", "expires_at", "(expires_at IS NOT NULL)"},
	{"idx_api_keys_deleted_at", "api_keys", "deleted_at", "(deleted_at IS NOT NULL)"},
	{"lifecycle_package_map_lookup_idx", "lifecycle_package_map", "ecosystem,name", ""},
	{"idx_malicious_eco_name", "malicious_findings", "ecosystem,name", ""},
	{"idx_check_status_next", "package_check_status", "source,next_check_at", ""},
	{"idx_scan_log_scan_id", "scan_log", "scan_id", ""},
	{"idx_vuln_aliases_vuln_id", "vulnerability_aliases", "vulnerability_id", ""},
	{"idx_vuln_sources_vuln_id", "vulnerability_sources", "vulnerability_id", ""},
	{"idx_vuln_refs_vuln_id", "vulnerability_references", "vulnerability_id", ""},
	{"idx_affected_eco_name", "affected_packages", "ecosystem,name", ""},
}

var f193F195ReplacementIndexes043 = []f177F182IndexContract{
	{"idx_malicious_sync_keyset", "malicious_findings", "ecosystem,name,id", ""},
	{"idx_affected_sync_keyset", "affected_packages", "ecosystem,name,vulnerability_id", ""},
}

func TestF193F195MigrationContractsAgainstPostgres(t *testing.T) {
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

	leafNumber := 600
	newLeaf := func(t *testing.T) f159F164Leaf {
		t.Helper()
		leafNumber++
		return f159F164PrepareLeaf(t, database, instance.dsn, leafNumber)
	}

	t.Run("migration_043", func(t *testing.T) {
		t.Run("populated_042_up_down_up_preserves_rows_catalog_and_rollup", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 42)
			f159F164Exec(t, leaf, `INSERT INTO scan_log(scan_id,repo_name,scanned_at,packages_count,findings_count,duration_ms) VALUES
				('f194-large-a','repo/a','2026-01-02T03:04:05Z',2000000000,1800000000,10),
				('f194-large-b','repo/b','2026-02-03T04:05:06Z',1500000000,1200000000,20)`)
			rows := f193F195ScanRows043(t, leaf)

			f159F164Apply(t, leaf, 43, MigrationDirectionUp)
			f193F195AssertRelationKind(t, leaf, "scan_log_totals", "v")
			f193F195AssertIndexes043(t, leaf, f193F195OldIndexes043, false)
			f193F195AssertIndexes043(t, leaf, f193F195ReplacementIndexes043, true)
			f193F195AssertViewTotals043(t, leaf, 3_500_000_000, 3_000_000_000, time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC))
			f159F164AssertEqual(t, "043 up scan rows", f193F195ScanRows043(t, leaf), rows)
			f193F195AssertViewRejectsWrites043(t, leaf)

			f159F164ApplyDownAndDelete(t, leaf, 43)
			f193F195AssertRelationKind(t, leaf, "scan_log_totals", "r")
			f193F195AssertIndexes043(t, leaf, f193F195ReplacementIndexes043, false)
			f193F195AssertIndexes043(t, leaf, f193F195OldIndexes043, true)
			f193F195AssertTableTotals043(t, leaf, 3_500_000_000, 3_000_000_000)
			f193F195AssertTableConstraints043(t, leaf)
			f159F164AssertEqual(t, "043 down scan rows", f193F195ScanRows043(t, leaf), rows)

			f159F164Apply(t, leaf, 43, MigrationDirectionUp)
			f193F195AssertRelationKind(t, leaf, "scan_log_totals", "v")
			f193F195AssertIndexes043(t, leaf, f193F195OldIndexes043, false)
			f193F195AssertIndexes043(t, leaf, f193F195ReplacementIndexes043, true)
			f193F195AssertViewTotals043(t, leaf, 3_500_000_000, 3_000_000_000, time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC))
			f159F164AssertEqual(t, "043 re-up scan rows", f193F195ScanRows043(t, leaf), rows)

			f159F164Exec(t, leaf, `DELETE FROM scan_log`)
			f193F195AssertEmptyViewTotals043(t, leaf)
		})

		t.Run("empty_view_and_rollback_table_are_singletons", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 43)
			f193F195AssertRelationKind(t, leaf, "scan_log_totals", "v")
			f193F195AssertEmptyViewTotals043(t, leaf)

			f159F164ApplyDownAndDelete(t, leaf, 43)
			f193F195AssertRelationKind(t, leaf, "scan_log_totals", "r")
			f193F195AssertTableTotals043(t, leaf, 0, 0)
			f193F195AssertTableConstraints043(t, leaf)
		})
	})

	t.Run("migration_044", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 43)
		f159F164Exec(t, leaf, `INSERT INTO system_settings(id,block_threshold,rate_limit_per_minute,rate_limit_burst,updated_at) VALUES (1,'MEDIUM',17,23,'2026-03-04T05:06:07Z')`)
		baseSettings := f193F195BaseSettings044(t, leaf)

		f159F164Apply(t, leaf, 44, MigrationDirectionUp)
		f193F195AssertRetentionCatalog044(t, leaf)
		f193F195AssertRetentionValues044(t, leaf, 2_592_000, 2_592_000)
		f159F164AssertEqual(t, "044 up base settings", f193F195BaseSettings044(t, leaf), baseSettings)
		f159F164Exec(t, leaf, `UPDATE system_settings SET scan_log_retention_seconds=86400,admin_audit_retention_seconds=172800 WHERE id=1`)

		f159F164ApplyDownAndDelete(t, leaf, 44)
		f193F195AssertRetentionAbsent044(t, leaf)
		f159F164AssertEqual(t, "044 down base settings", f193F195BaseSettings044(t, leaf), baseSettings)
		f159F164ApplyDownAndDelete(t, leaf, 44)
		f193F195AssertRetentionAbsent044(t, leaf)
		f159F164AssertEqual(t, "044 repeated down base settings", f193F195BaseSettings044(t, leaf), baseSettings)

		f159F164Apply(t, leaf, 44, MigrationDirectionUp)
		f193F195AssertRetentionCatalog044(t, leaf)
		f193F195AssertRetentionValues044(t, leaf, 2_592_000, 2_592_000)
		f159F164Exec(t, leaf, `ALTER TABLE system_settings DROP CONSTRAINT system_settings_scan_log_retention_nonnegative_check; ALTER TABLE system_settings DROP COLUMN admin_audit_retention_seconds`)
		f159F164ApplyDownAndDelete(t, leaf, 44)
		f193F195AssertRetentionAbsent044(t, leaf)
		f159F164AssertEqual(t, "044 partial down base settings", f193F195BaseSettings044(t, leaf), baseSettings)

		f159F164Apply(t, leaf, 44, MigrationDirectionUp)
		f193F195AssertRetentionCatalog044(t, leaf)
		f193F195AssertRetentionValues044(t, leaf, 2_592_000, 2_592_000)
		f193F195AssertRetentionChecks044(t, leaf)
		f159F164AssertEqual(t, "044 final base settings", f193F195BaseSettings044(t, leaf), baseSettings)
	})
}

func f193F195ScanRows043(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT scan_log.* FROM scan_log ORDER BY id`)
}

func f193F195AssertRelationKind(t *testing.T, leaf f159F164Leaf, relation, want string) {
	t.Helper()
	var got string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2`, leaf.schema, relation).Scan(&got); err != nil {
		t.Fatalf("inspect relation %s: %v", relation, err)
	}
	if got != want {
		t.Fatalf("relation %s kind = %q, want %q", relation, got, want)
	}
}

func f193F195AssertIndexes043(t *testing.T, leaf f159F164Leaf, contracts []f177F182IndexContract, want bool) {
	t.Helper()
	for _, contract := range contracts {
		exact := f177F182IndexExact(t, leaf, contract)
		if exact != want {
			table, keys, predicate, _, err := f177F182IndexCatalog(t, leaf, contract.name)
			t.Fatalf("043 index %s exact = %t, want %t (table:%q keys:%q predicate:%q error:%v)", contract.name, exact, want, table, keys, predicate, err)
		}
	}
}

func f193F195AssertViewTotals043(t *testing.T, leaf f159F164Leaf, packages, findings int64, updatedAt time.Time) {
	t.Helper()
	var id bool
	var gotPackages, gotFindings int64
	var gotUpdatedAt time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT id,packages_scanned,findings,updated_at FROM scan_log_totals`).Scan(&id, &gotPackages, &gotFindings, &gotUpdatedAt); err != nil {
		t.Fatalf("read 043 view totals: %v", err)
	}
	if !id || gotPackages != packages || gotFindings != findings || !gotUpdatedAt.Equal(updatedAt) {
		t.Fatalf("043 view totals = id:%t packages:%d findings:%d updated:%v, want true/%d/%d/%v", id, gotPackages, gotFindings, gotUpdatedAt, packages, findings, updatedAt)
	}
	var rows int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM scan_log_totals`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("043 view row count = %d error=%v, want 1", rows, err)
	}
}

func f193F195AssertEmptyViewTotals043(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	started := time.Now().UTC()
	var id bool
	var packages, findings int64
	var updatedAt time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT id,packages_scanned,findings,updated_at FROM scan_log_totals`).Scan(&id, &packages, &findings, &updatedAt); err != nil {
		t.Fatalf("read empty 043 view totals: %v", err)
	}
	finished := time.Now().UTC()
	if !id || packages != 0 || findings != 0 || updatedAt.Before(started.Add(-time.Second)) || updatedAt.After(finished.Add(time.Second)) {
		t.Fatalf("empty 043 view totals = id:%t packages:%d findings:%d updated:%v, want true/0/0 within [%v,%v]", id, packages, findings, updatedAt, started, finished)
	}
}

func f193F195AssertViewRejectsWrites043(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if _, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE scan_log_totals SET packages_scanned=1`); err == nil {
		t.Fatal("043 aggregate view accepted UPDATE")
	}
	if _, err := leaf.conn.ExecContext(leaf.ctx, `INSERT INTO scan_log_totals(id,packages_scanned,findings) VALUES(TRUE,1,1)`); err == nil {
		t.Fatal("043 aggregate view accepted INSERT")
	}
}

func f193F195AssertTableTotals043(t *testing.T, leaf f159F164Leaf, packages, findings int64) {
	t.Helper()
	var id bool
	var gotPackages, gotFindings int64
	var updatedAt time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT id,packages_scanned,findings,updated_at FROM scan_log_totals`).Scan(&id, &gotPackages, &gotFindings, &updatedAt); err != nil {
		t.Fatalf("read 043 rollback table totals: %v", err)
	}
	if !id || gotPackages != packages || gotFindings != findings || updatedAt.IsZero() {
		t.Fatalf("043 rollback table totals = id:%t packages:%d findings:%d updated:%v, want true/%d/%d/non-zero", id, gotPackages, gotFindings, updatedAt, packages, findings)
	}
	var rows int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM scan_log_totals`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("043 rollback table row count = %d error=%v, want 1", rows, err)
	}
}

func f193F195AssertTableConstraints043(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	tests := []struct {
		name      string
		statement string
		sqlState  string
	}{
		{"false_singleton", `INSERT INTO scan_log_totals(id) VALUES(FALSE)`, "23514"},
		{"second_singleton", `INSERT INTO scan_log_totals DEFAULT VALUES`, "23505"},
		{"negative_packages", `UPDATE scan_log_totals SET packages_scanned=-1`, "23514"},
		{"negative_findings", `UPDATE scan_log_totals SET findings=-1`, "23514"},
		{"null_packages", `UPDATE scan_log_totals SET packages_scanned=NULL`, "23502"},
		{"null_findings", `UPDATE scan_log_totals SET findings=NULL`, "23502"},
		{"null_updated_at", `UPDATE scan_log_totals SET updated_at=NULL`, "23502"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := leaf.conn.ExecContext(leaf.ctx, tt.statement)
			f159F164ExpectSQLState(t, err, tt.sqlState)
		})
	}
}

func f193F195BaseSettings044(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,block_threshold,rate_limit_per_minute,rate_limit_burst,updated_at FROM system_settings ORDER BY id`)
}

func f193F195AssertRetentionCatalog044(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var columns int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='system_settings' AND column_name=ANY(ARRAY['scan_log_retention_seconds','admin_audit_retention_seconds']) AND data_type='bigint' AND is_nullable='NO' AND column_default='2592000'`, leaf.schema).Scan(&columns); err != nil || columns != 2 {
		t.Fatalf("044 exact retention column count = %d error=%v, want 2", columns, err)
	}
	wantConstraints := map[string]string{
		"system_settings_scan_log_retention_nonnegative_check":    "CHECK ((scan_log_retention_seconds >= 0))",
		"system_settings_admin_audit_retention_nonnegative_check": "CHECK ((admin_audit_retention_seconds >= 0))",
	}
	rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT c.conname,pg_get_constraintdef(c.oid),c.convalidated FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND r.relname='system_settings' AND c.conname=ANY(ARRAY['system_settings_scan_log_retention_nonnegative_check','system_settings_admin_audit_retention_nonnegative_check'])`, leaf.schema)
	if err != nil {
		t.Fatalf("read 044 constraints: %v", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var name, definition string
		var validated bool
		if err := rows.Scan(&name, &definition, &validated); err != nil {
			t.Fatalf("scan 044 constraint: %v", err)
		}
		if definition != wantConstraints[name] || !validated {
			t.Fatalf("044 constraint %s = %q validated=%t, want %q validated", name, definition, validated, wantConstraints[name])
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate 044 constraints: %v", err)
	}
	if seen != len(wantConstraints) {
		t.Fatalf("044 retention constraint count = %d, want %d", seen, len(wantConstraints))
	}
}

func f193F195AssertRetentionValues044(t *testing.T, leaf f159F164Leaf, scanLog, adminAudit int64) {
	t.Helper()
	var gotScanLog, gotAdminAudit int64
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT scan_log_retention_seconds,admin_audit_retention_seconds FROM system_settings WHERE id=1`).Scan(&gotScanLog, &gotAdminAudit); err != nil {
		t.Fatalf("read 044 retention values: %v", err)
	}
	if gotScanLog != scanLog || gotAdminAudit != adminAudit {
		t.Fatalf("044 retention values = %d/%d, want %d/%d", gotScanLog, gotAdminAudit, scanLog, adminAudit)
	}
}

func f193F195AssertRetentionAbsent044(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var columns, constraints int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='system_settings' AND column_name=ANY(ARRAY['scan_log_retention_seconds','admin_audit_retention_seconds'])`, leaf.schema).Scan(&columns); err != nil {
		t.Fatalf("inspect absent 044 columns: %v", err)
	}
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND r.relname='system_settings' AND c.conname=ANY(ARRAY['system_settings_scan_log_retention_nonnegative_check','system_settings_admin_audit_retention_nonnegative_check'])`, leaf.schema).Scan(&constraints); err != nil {
		t.Fatalf("inspect absent 044 constraints: %v", err)
	}
	if columns != 0 || constraints != 0 {
		t.Fatalf("044 objects after down = columns:%d constraints:%d, want 0/0", columns, constraints)
	}
}

func f193F195AssertRetentionChecks044(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for _, column := range []string{"scan_log_retention_seconds", "admin_audit_retention_seconds"} {
		_, err := leaf.conn.ExecContext(leaf.ctx, `UPDATE system_settings SET `+f159F164QuoteIdentifier(column)+`=-1 WHERE id=1`)
		f159F164ExpectSQLState(t, err, "23514")
	}
	f193F195AssertRetentionValues044(t, leaf, 2_592_000, 2_592_000)
}
