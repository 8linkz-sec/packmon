//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

var baselineApplicationTables = []string{
	"admin_audit_log",
	"admin_auth",
	"affected_packages",
	"api_keys",
	"feed_configs",
	"feed_sync_status",
	"malicious_findings",
	"nvd_cvss_negative_cache",
	"package_check_status",
	"refresh_queue",
	"scan_log",
	"vulnerabilities",
	"vulnerability_aliases",
	"vulnerability_references",
	"vulnerability_sources",
}

var baselineOwnedSequences = map[string]string{
	"admin_audit_log_id_seq":          "admin_audit_log.id",
	"affected_packages_id_seq":        "affected_packages.id",
	"api_keys_id_seq":                 "api_keys.id",
	"package_check_status_id_seq":     "package_check_status.id",
	"refresh_queue_id_seq":            "refresh_queue.id",
	"scan_log_id_seq":                 "scan_log.id",
	"vulnerability_aliases_id_seq":    "vulnerability_aliases.id",
	"vulnerability_references_id_seq": "vulnerability_references.id",
	"vulnerability_sources_id_seq":    "vulnerability_sources.id",
}

type baselineIndexExpectation struct {
	table     string
	unique    bool
	keys      string
	opclasses string
	predicate string
}

var baselineIndexes = map[string]baselineIndexExpectation{
	"idx_admin_audit_correlation_id": {
		table: "admin_audit_log", keys: "correlation_id", opclasses: "text_ops", predicate: "correlation_id<>''",
	},
	"idx_admin_audit_time": {
		table: "admin_audit_log", keys: "created_at", opclasses: "timestamptz_ops",
	},
	"idx_affected_eco_name": {
		table: "affected_packages", keys: "ecosystem|name", opclasses: "text_ops|text_ops",
	},
	"idx_api_keys_hash": {
		table: "api_keys", keys: "key_hash", opclasses: "text_ops",
	},
	"idx_check_status_next": {
		table: "package_check_status", keys: "source|next_check_at", opclasses: "text_ops|timestamptz_ops",
	},
	"idx_malicious_eco_name": {
		table: "malicious_findings", keys: "ecosystem|name", opclasses: "text_ops|text_ops",
	},
	"idx_malicious_source": {
		table: "malicious_findings", keys: "source", opclasses: "text_ops",
	},
	"idx_nvd_cvss_negative_cache_checked_at": {
		table: "nvd_cvss_negative_cache", keys: "checked_at", opclasses: "timestamptz_ops",
	},
	"idx_package_check_status_socket_updated_at": {
		table: "package_check_status", keys: "updated_at", opclasses: "timestamptz_ops", predicate: "source='socket'",
	},
	"idx_queue_dedup": {
		table: "refresh_queue", unique: true, keys: "ecosystem|name|source", opclasses: "text_ops|text_ops|text_ops", predicate: "status=anyarray['pending','processing']",
	},
	"idx_queue_priority": {
		table: "refresh_queue", keys: "source|status|priority|requested_at", opclasses: "text_ops|text_ops|int4_ops|timestamptz_ops",
	},
	"idx_scan_log_scan_id": {
		table: "scan_log", keys: "scan_id", opclasses: "text_ops",
	},
	"idx_scan_log_time": {
		table: "scan_log", keys: "scanned_at", opclasses: "timestamptz_ops",
	},
	"idx_vuln_aliases_alias_id": {
		table: "vulnerability_aliases", keys: "alias_id", opclasses: "text_ops",
	},
	"idx_vuln_aliases_cve_alias": {
		table: "vulnerability_aliases", keys: "alias_id|vulnerability_id", opclasses: "text_pattern_ops|text_ops", predicate: "alias_id~~'cve-%'",
	},
	"idx_vuln_aliases_vuln_id": {
		table: "vulnerability_aliases", keys: "vulnerability_id", opclasses: "text_ops",
	},
	"idx_vuln_refs_vuln_id": {
		table: "vulnerability_references", keys: "vulnerability_id", opclasses: "text_ops",
	},
	"idx_vuln_sources_source_vuln_id": {
		table: "vulnerability_sources", keys: "source|vulnerability_id", opclasses: "text_ops|text_ops", predicate: "raw_jsonisnotnull",
	},
	"idx_vuln_sources_vuln_id": {
		table: "vulnerability_sources", keys: "vulnerability_id", opclasses: "text_ops",
	},
	"idx_vulnerabilities_cisa_kev": {
		table: "vulnerabilities", keys: "id", opclasses: "text_ops", predicate: "cisa_kev=true",
	},
	"idx_vulnerabilities_nvd_candidate": {
		table: "vulnerabilities", keys: "id", opclasses: "text_ops", predicate: "severity='unknown'orseverity='low'andcvss_scoreisnull",
	},
}

func TestInitialMigrationSchemaContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, true)
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

	t.Run("scalar_boundaries_and_defaults", func(t *testing.T) {
		assertInitialScalarBoundaries(t, ctx, db)
	})
	t.Run("foreign_keys_and_cascades", func(t *testing.T) {
		assertInitialForeignKeys(t, ctx, db)
	})
	t.Run("uniqueness_and_singletons", func(t *testing.T) {
		assertInitialUniqueness(t, ctx, db)
	})
	t.Run("catalog_objects", func(t *testing.T) {
		assertBaselineSchemaCatalog(t, ctx, db)
	})
	t.Run("validator_functions", func(t *testing.T) {
		assertInitialValidatorFunctions(t, ctx, db)
		applyEmbeddedMigrationsRangeForTest(t, ctx, db, 2, ExpectedVersion)
		assertCurrentVersionRangeValidator(t, ctx, db)
	})
}

func assertInitialScalarBoundaries(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	now := "2026-01-02T03:04:05Z"
	for i, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		execOK(t, ctx, db, `INSERT INTO vulnerabilities(id, summary, severity, cvss_score, epss_score, epss_percentile, published, modified) VALUES($1, 'boundary', $2, $3, $4, $5, $6, $6)`, fmt.Sprintf("scalar-vuln-%d", i), severity, []float64{0, 10}[i%2], []float64{0, 1}[i%2], []float64{1, 0}[i%2], now)
	}
	for name, args := range map[string][]any{
		"severity":         {"scalar-bad-severity", "UNKNOWN", nil, nil, nil, now},
		"cvss below":       {"scalar-bad-cvss-low", "LOW", -0.01, nil, nil, now},
		"cvss above":       {"scalar-bad-cvss-high", "LOW", 10.01, nil, nil, now},
		"epss below":       {"scalar-bad-epss-low", "LOW", nil, -0.01, nil, now},
		"epss above":       {"scalar-bad-epss-high", "LOW", nil, 1.01, nil, now},
		"percentile below": {"scalar-bad-pct-low", "LOW", nil, nil, -0.01, now},
		"percentile above": {"scalar-bad-pct-high", "LOW", nil, nil, 1.01, now},
	} {
		err := execSQL(ctx, db, `INSERT INTO vulnerabilities(id, summary, severity, cvss_score, epss_score, epss_percentile, published, modified) VALUES($1, 'invalid', $2, $3, $4, $5, $6, $6)`, args...)
		if err == nil {
			t.Fatalf("%s boundary insert succeeded, want CHECK violation", name)
		}
		expectSQLState(t, "23514", err)
	}

	for _, status := range []string{"pending", "running", "success", "error", "skipped", "disabled", "external", "rejected", "permanent_error"} {
		execOK(t, ctx, db, `INSERT INTO feed_sync_status(feed_name, last_sync_status, last_sync_duration, entries_synced, entries_total) VALUES($1, $2, interval '0', 0, 0)`, "scalar-feed-"+status, status)
	}
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO feed_sync_status(feed_name, last_sync_status) VALUES('scalar-feed-bad-status', 'unknown')`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO feed_sync_status(feed_name, entries_synced) VALUES('scalar-feed-negative-synced', -1)`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO feed_sync_status(feed_name, entries_total) VALUES('scalar-feed-negative-total', -1)`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO feed_sync_status(feed_name, entries_synced, entries_total) VALUES('scalar-feed-order', 2, 1)`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO feed_sync_status(feed_name, last_sync_duration) VALUES('scalar-feed-duration', interval '-1 microsecond')`))
	execOK(t, ctx, db, `INSERT INTO feed_sync_status(feed_name, entries_synced, entries_total) VALUES('scalar-feed-unbounded-total', 7, 0)`)

	execOK(t, ctx, db, `INSERT INTO scan_log(scan_id, packages_count, findings_count, duration_ms) VALUES('scalar-scan-zero', 0, 0, 0)`)
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO scan_log(scan_id, packages_count, findings_count, duration_ms) VALUES('scalar-scan-negative-packages', -1, 0, 0)`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO scan_log(scan_id, packages_count, findings_count, duration_ms) VALUES('scalar-scan-negative-findings', 0, -1, 0)`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO scan_log(scan_id, packages_count, findings_count, duration_ms) VALUES('scalar-scan-negative-duration', 0, 0, -1)`))

	for _, status := range []string{"pending", "processing", "paused", "done", "error"} {
		for _, priority := range []int{0, 3} {
			execOK(t, ctx, db, `INSERT INTO refresh_queue(ecosystem, name, source, status, priority) VALUES('npm', $1, 'scalar', $2, $3)`, fmt.Sprintf("queue-%s-%d", status, priority), status, priority)
		}
	}
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO refresh_queue(ecosystem, name, source, status) VALUES('npm', 'queue-bad-status', 'scalar', 'unknown')`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO refresh_queue(ecosystem, name, source, priority) VALUES('npm', 'queue-low-priority', 'scalar', -1)`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO refresh_queue(ecosystem, name, source, priority) VALUES('npm', 'queue-high-priority', 'scalar', 4)`))

	execOK(t, ctx, db, `INSERT INTO feed_configs(feed_name, enabled, mode, sync_interval) VALUES('scalar-config-self', true, 'self', NULL), ('scalar-config-external', false, 'external', interval '15 minutes')`)
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO feed_configs(feed_name, enabled, mode) VALUES('scalar-config-mode', true, 'hybrid')`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO feed_configs(feed_name, enabled, mode, sync_interval) VALUES('scalar-config-cadence', true, 'self', interval '14 minutes 59 seconds')`))

	var keyID int
	var created time.Time
	var revoked, lastUsed sql.NullTime
	if err := db.QueryRowContext(ctx, `INSERT INTO api_keys(name, key_hash) VALUES('scalar-default-key', 'scalar-default-hash') RETURNING id, created_at, revoked_at, last_used_at`).Scan(&keyID, &created, &revoked, &lastUsed); err != nil {
		t.Fatalf("insert API key with defaults: %v", err)
	}
	if keyID != 1 || created.IsZero() || revoked.Valid || lastUsed.Valid {
		t.Fatalf("API key defaults = id:%d created:%v revoked:%v last_used:%v", keyID, created, revoked, lastUsed)
	}
	execOK(t, ctx, db, `UPDATE api_keys SET revoked_at = created_at, last_used_at = created_at WHERE id = $1`, keyID)
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO api_keys(name, key_hash, created_at, revoked_at) VALUES('scalar-key-bad-revoked', 'scalar-key-bad-revoked', $1, $1::timestamptz - interval '1 microsecond')`, now))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO api_keys(name, key_hash, created_at, last_used_at) VALUES('scalar-key-bad-used', 'scalar-key-bad-used', $1, $1::timestamptz - interval '1 microsecond')`, now))

	var vulnSeverity, feedStatus, queueStatus string
	var cisa, exploit bool
	var queuePriority int
	if err := db.QueryRowContext(ctx, `
		WITH v AS (
			INSERT INTO vulnerabilities(id, summary, published, modified)
			VALUES('scalar-default-vulnerability', 'defaults', $1, $1)
			RETURNING severity, cisa_kev, exploit_exists
		), f AS (
			INSERT INTO feed_sync_status(feed_name) VALUES('scalar-default-feed')
			RETURNING last_sync_status
		), q AS (
			INSERT INTO refresh_queue(ecosystem, name, source) VALUES('npm', 'scalar-default-queue', 'scalar-default')
			RETURNING status, priority
		)
		SELECT v.severity, v.cisa_kev, v.exploit_exists, f.last_sync_status, q.status, q.priority FROM v, f, q`, now).Scan(&vulnSeverity, &cisa, &exploit, &feedStatus, &queueStatus, &queuePriority); err != nil {
		t.Fatalf("read baseline defaults: %v", err)
	}
	if vulnSeverity != "LOW" || cisa || exploit || feedStatus != "pending" || queueStatus != "pending" || queuePriority != 3 {
		t.Fatalf("baseline defaults = severity:%s cisa:%v exploit:%v feed:%s queue:%s/%d", vulnSeverity, cisa, exploit, feedStatus, queueStatus, queuePriority)
	}
}

func assertInitialForeignKeys(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	const vulnID = "fk-vulnerability"
	execOK(t, ctx, db, `INSERT INTO vulnerabilities(id, summary, published, modified) VALUES($1, 'fk', now(), now())`, vulnID)
	execOK(t, ctx, db, `INSERT INTO vulnerability_aliases(vulnerability_id, alias_id) VALUES($1, 'CVE-2026-FK')`, vulnID)
	execOK(t, ctx, db, `INSERT INTO vulnerability_sources(vulnerability_id, source, source_id) VALUES($1, 'osv', 'OSV-FK')`, vulnID)
	execOK(t, ctx, db, `INSERT INTO vulnerability_references(vulnerability_id, type, url, source) VALUES($1, 'ADVISORY', 'https://example.test/fk', 'osv')`, vulnID)
	execOK(t, ctx, db, `INSERT INTO affected_packages(vulnerability_id, ecosystem, name) VALUES($1, 'npm', 'fk-package')`, vulnID)
	execOK(t, ctx, db, `DELETE FROM vulnerabilities WHERE id = $1`, vulnID)
	for _, table := range []string{"vulnerability_aliases", "vulnerability_sources", "vulnerability_references", "affected_packages"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE vulnerability_id = $1`, vulnID).Scan(&count); err != nil {
			t.Fatalf("count cascaded %s rows: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s rows after parent delete = %d, want 0", table, count)
		}
	}

	var keyID int
	if err := db.QueryRowContext(ctx, `INSERT INTO api_keys(name, key_hash) VALUES('fk-key', 'fk-key-hash') RETURNING id`).Scan(&keyID); err != nil {
		t.Fatalf("insert FK API key: %v", err)
	}
	execOK(t, ctx, db, `INSERT INTO scan_log(scan_id, packages_count, findings_count, duration_ms, api_key_id) VALUES('fk-scan', 1, 0, 1, $1)`, keyID)
	execOK(t, ctx, db, `DELETE FROM api_keys WHERE id = $1`, keyID)
	var scanKey sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT api_key_id FROM scan_log WHERE scan_id = 'fk-scan'`).Scan(&scanKey); err != nil {
		t.Fatalf("read scan API key after delete: %v", err)
	}
	if scanKey.Valid {
		t.Fatalf("scan API key after parent delete = %d, want NULL", scanKey.Int64)
	}

	for name, statement := range map[string]string{
		"alias":     `INSERT INTO vulnerability_aliases(vulnerability_id, alias_id) VALUES('missing', 'missing')`,
		"source":    `INSERT INTO vulnerability_sources(vulnerability_id, source, source_id) VALUES('missing', 'osv', 'missing')`,
		"reference": `INSERT INTO vulnerability_references(vulnerability_id, url) VALUES('missing', 'https://example.test/missing')`,
		"affected":  `INSERT INTO affected_packages(vulnerability_id, ecosystem, name) VALUES('missing', 'npm', 'missing')`,
		"scan key":  `INSERT INTO scan_log(scan_id, packages_count, findings_count, duration_ms, api_key_id) VALUES('missing-key', 0, 0, 0, 999999)`,
	} {
		err := execSQL(ctx, db, statement)
		if err == nil {
			t.Fatalf("%s missing-parent insert succeeded, want FK violation", name)
		}
		expectSQLState(t, "23503", err)
	}

	execOK(t, ctx, db, `INSERT INTO vulnerabilities(id, summary, published, modified) VALUES('manual:valid', 'manual', now(), now())`)
	execOK(t, ctx, db, `INSERT INTO vulnerability_sources(vulnerability_id, source, source_id) VALUES('manual:valid', 'manual', 'manual:valid')`)
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO vulnerability_sources(vulnerability_id, source, source_id) VALUES('scalar-default-vulnerability', 'manual', 'manual:wrong')`))
	execOK(t, ctx, db, `INSERT INTO malicious_findings(id, ecosystem, name, source, risk_type, summary) VALUES('manual:valid-malicious', 'npm', 'manual-valid', 'manual', 'malware', 'manual')`)
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO malicious_findings(id, ecosystem, name, source, risk_type, summary) VALUES('invalid-manual', 'npm', 'manual-invalid', 'manual', 'malware', 'manual')`))
}

func assertInitialUniqueness(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	execOK(t, ctx, db, `INSERT INTO vulnerabilities(id, summary, published, modified) VALUES('unique-vuln', 'unique', now(), now())`)
	fixtures := []struct {
		name      string
		seed      string
		duplicate string
	}{
		{"alias", `INSERT INTO vulnerability_aliases(vulnerability_id, alias_id) VALUES('unique-vuln', 'CVE-2026-UNIQUE')`, `INSERT INTO vulnerability_aliases(vulnerability_id, alias_id) VALUES('unique-vuln', 'CVE-2026-UNIQUE')`},
		{"source", `INSERT INTO vulnerability_sources(vulnerability_id, source, source_id) VALUES('unique-vuln', 'osv', 'unique-1')`, `INSERT INTO vulnerability_sources(vulnerability_id, source, source_id) VALUES('unique-vuln', 'osv', 'unique-2')`},
		{"reference", `INSERT INTO vulnerability_references(vulnerability_id, source, url) VALUES('unique-vuln', 'osv', 'https://example.test/unique')`, `INSERT INTO vulnerability_references(vulnerability_id, source, url) VALUES('unique-vuln', 'osv', 'https://example.test/unique')`},
		{"affected", `INSERT INTO affected_packages(vulnerability_id, ecosystem, name) VALUES('unique-vuln', 'npm', 'unique-package')`, `INSERT INTO affected_packages(vulnerability_id, ecosystem, name) VALUES('unique-vuln', 'npm', 'unique-package')`},
		{"status", `INSERT INTO package_check_status(ecosystem, name, source) VALUES('npm', 'unique-package', 'socket')`, `INSERT INTO package_check_status(ecosystem, name, source) VALUES('npm', 'unique-package', 'socket')`},
		{"API key hash", `INSERT INTO api_keys(name, key_hash) VALUES('unique-key-1', 'unique-key-hash')`, `INSERT INTO api_keys(name, key_hash) VALUES('unique-key-2', 'unique-key-hash')`},
		{"active queue", `INSERT INTO refresh_queue(ecosystem, name, source, status) VALUES('npm', 'unique-queue', 'socket', 'pending')`, `INSERT INTO refresh_queue(ecosystem, name, source, status) VALUES('npm', 'unique-queue', 'socket', 'processing')`},
	}
	for _, fixture := range fixtures {
		execOK(t, ctx, db, fixture.seed)
		err := execSQL(ctx, db, fixture.duplicate)
		if err == nil {
			t.Fatalf("duplicate %s insert succeeded, want uniqueness violation", fixture.name)
		}
		expectSQLState(t, "23505", err)
	}

	execOK(t, ctx, db, `INSERT INTO admin_auth(password_hash) VALUES('hash')`)
	expectSQLState(t, "23505", execSQL(ctx, db, `INSERT INTO admin_auth(id, username, password_hash) VALUES(1, 'admin', 'duplicate')`))
	expectSQLState(t, "23514", execSQL(ctx, db, `INSERT INTO admin_auth(id, username, password_hash) VALUES(2, 'admin', 'second')`))
}

func assertInitialValidatorFunctions(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	stringArrays := []struct {
		name  string
		value any
		want  bool
	}{
		{"null SQL", nil, false},
		{"object", `{}`, false},
		{"empty", `[]`, true},
		{"strings", `["", "value"]`, true},
		{"mixed", `["value", 1]`, false},
	}
	for _, tc := range stringArrays {
		assertValidatorResult(t, ctx, db, "packmon_jsonb_string_array_valid", tc.value, tc.want)
	}

	legacyRanges := []struct {
		name  string
		value any
		want  bool
	}{
		{"null SQL", nil, false},
		{"not array", `{}`, false},
		{"empty ranges", `[]`, true},
		// The legacy function treats a missing events key as SQL NULL, so the
		// IF expression does not fire and the empty loop returns true. Migration
		// 050 below proves that the current function rejects the same payload.
		{"missing events", `[{}]`, true},
		{"empty events", `[{"events":[]}]`, false},
		{"null events", `[{"events":null}]`, false},
		{"numeric events", `[{"events":1}]`, false},
		{"string event", `[{"events":["introduced"]}]`, false},
		{"empty event", `[{"events":[{}]}]`, false},
		{"introduced null", `[{"events":[{"introduced":null}]}]`, true},
		{"introduced numeric", `[{"events":[{"introduced":1}]}]`, true},
		{"introduced blank", `[{"events":[{"introduced":" "}]}]`, true},
		{"mixed values", `[{"events":[{"introduced":"0","fixed":7}]}]`, true},
		{"valid introduced fixed", `[{"events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`, true},
	}
	for _, tc := range legacyRanges {
		assertValidatorResult(t, ctx, db, "packmon_jsonb_version_ranges_valid", tc.value, tc.want)
	}
}

func assertCurrentVersionRangeValidator(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{"empty ranges", `[]`, true},
		{"introduced", `[{"events":[{"introduced":"0"}]}]`, true},
		{"fixed", `[{"events":[{"fixed":"1.2.3"}]}]`, true},
		{"missing events", `[{}]`, false},
		{"empty events", `[{"events":[]}]`, false},
		{"null boundary", `[{"events":[{"introduced":null}]}]`, false},
		{"numeric boundary", `[{"events":[{"introduced":1}]}]`, false},
		{"blank boundary", `[{"events":[{"introduced":" \t"}]}]`, false},
		{"mixed boundary", `[{"events":[{"introduced":"0","fixed":7}]}]`, false},
	} {
		assertValidatorResult(t, ctx, db, "packmon_jsonb_version_ranges_valid", tc.value, tc.want)
	}
}

func assertValidatorResult(t *testing.T, ctx context.Context, db *sql.DB, function string, value any, want bool) {
	t.Helper()
	var got bool
	if err := db.QueryRowContext(ctx, `SELECT `+function+`($1::jsonb)`, value).Scan(&got); err != nil {
		t.Fatalf("%s(%v): %v", function, value, err)
	}
	if got != want {
		t.Fatalf("%s(%v) = %v, want %v", function, value, got, want)
	}
}

func assertBaselineSchemaCatalog(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	gotTables := queryStrings(t, ctx, db, `
		SELECT tablename FROM pg_tables
		WHERE schemaname = 'public' AND tablename <> ALL($1::text[])
		ORDER BY tablename`, []string{"schema_migrations", "schema_migration_events"})
	if !slices.Equal(gotTables, baselineApplicationTables) {
		t.Fatalf("baseline tables = %v, want %v", gotTables, baselineApplicationTables)
	}

	gotSequences := make(map[string]string)
	rows, err := db.QueryContext(ctx, `
		SELECT seq.relname, tbl.relname || '.' || attr.attname
		FROM pg_class seq
		JOIN pg_namespace ns ON ns.oid = seq.relnamespace
		JOIN pg_depend dep ON dep.classid = 'pg_class'::regclass AND dep.objid = seq.oid AND dep.deptype = 'a'
		JOIN pg_class tbl ON tbl.oid = dep.refobjid
		JOIN pg_attribute attr ON attr.attrelid = tbl.oid AND attr.attnum = dep.refobjsubid
		WHERE ns.nspname = 'public' AND seq.relkind = 'S' AND tbl.relname = ANY($1::text[])
		ORDER BY seq.relname`, baselineApplicationTables)
	if err != nil {
		t.Fatalf("query baseline sequences: %v", err)
	}
	for rows.Next() {
		var name, owner string
		if err := rows.Scan(&name, &owner); err != nil {
			t.Fatalf("scan baseline sequence: %v", err)
		}
		gotSequences[name] = owner
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate baseline sequences: %v", err)
	}
	ioutils.CloseSilently(rows)
	if !maps.Equal(gotSequences, baselineOwnedSequences) {
		t.Fatalf("baseline owned sequences = %v, want %v", gotSequences, baselineOwnedSequences)
	}

	gotIndexes := make(map[string]baselineIndexExpectation)
	rows, err = db.QueryContext(ctx, `
		SELECT idx.relname, tbl.relname, i.indisunique,
			(SELECT string_agg(pg_get_indexdef(i.indexrelid, key_no, true), '|' ORDER BY key_no)
			 FROM generate_series(1, i.indnkeyatts) key_no),
			(SELECT string_agg(opc.opcname, '|' ORDER BY classes.ordinality)
			 FROM unnest(i.indclass::oid[]) WITH ORDINALITY classes(opclass_oid, ordinality)
			 JOIN pg_opclass opc ON opc.oid = classes.opclass_oid),
			COALESCE(pg_get_expr(i.indpred, i.indrelid), ''), i.indisvalid, i.indisready
		FROM pg_index i
		JOIN pg_class idx ON idx.oid = i.indexrelid
		JOIN pg_class tbl ON tbl.oid = i.indrelid
		JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
		WHERE ns.nspname = 'public'
		  AND tbl.relname = ANY($1::text[])
		  AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = i.indexrelid)
		ORDER BY idx.relname`, baselineApplicationTables)
	if err != nil {
		t.Fatalf("query baseline indexes: %v", err)
	}
	for rows.Next() {
		var name, table, keys, opclasses, predicate string
		var unique, valid, ready bool
		if err := rows.Scan(&name, &table, &unique, &keys, &opclasses, &predicate, &valid, &ready); err != nil {
			t.Fatalf("scan baseline index: %v", err)
		}
		if !valid || !ready {
			t.Fatalf("baseline index %s valid=%v ready=%v, want both true", name, valid, ready)
		}
		gotIndexes[name] = baselineIndexExpectation{table: table, unique: unique, keys: keys, opclasses: opclasses, predicate: normalizeCatalogPredicate(predicate)}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate baseline indexes: %v", err)
	}
	ioutils.CloseSilently(rows)
	if !maps.Equal(gotIndexes, baselineIndexes) {
		t.Fatalf("baseline indexes = %#v, want %#v", gotIndexes, baselineIndexes)
	}

	functions := make(map[string]string)
	rows, err = db.QueryContext(ctx, `
		SELECT p.proname, oidvectortypes(p.proargtypes), pg_get_function_result(p.oid), l.lanname, p.provolatile
		FROM pg_proc p
		JOIN pg_namespace ns ON ns.oid = p.pronamespace
		JOIN pg_language l ON l.oid = p.prolang
		WHERE ns.nspname = 'public' AND p.proname = ANY($1::text[])
		ORDER BY p.proname`, []string{"packmon_jsonb_string_array_valid", "packmon_jsonb_version_ranges_valid"})
	if err != nil {
		t.Fatalf("query baseline functions: %v", err)
	}
	for rows.Next() {
		var name, args, result, language, volatility string
		if err := rows.Scan(&name, &args, &result, &language, &volatility); err != nil {
			t.Fatalf("scan baseline function: %v", err)
		}
		functions[name] = strings.Join([]string{args, result, language, volatility}, "|")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate baseline functions: %v", err)
	}
	ioutils.CloseSilently(rows)
	wantFunctions := map[string]string{
		"packmon_jsonb_string_array_valid":   "jsonb|boolean|plpgsql|i",
		"packmon_jsonb_version_ranges_valid": "jsonb|boolean|plpgsql|i",
	}
	if !maps.Equal(functions, wantFunctions) {
		t.Fatalf("baseline functions = %v, want %v", functions, wantFunctions)
	}

	var triggerCount int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM pg_trigger trigger
		JOIN pg_class tbl ON tbl.oid = trigger.tgrelid
		JOIN pg_namespace ns ON ns.oid = tbl.relnamespace
		WHERE ns.nspname = 'public' AND tbl.relname = ANY($1::text[]) AND NOT trigger.tgisinternal`, baselineApplicationTables).Scan(&triggerCount); err != nil {
		t.Fatalf("count baseline triggers: %v", err)
	}
	if triggerCount != 0 {
		t.Fatalf("non-internal triggers on baseline tables = %d, want 0", triggerCount)
	}
}

func normalizeCatalogPredicate(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "::text", "")
	value = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", "(", "", ")", "").Replace(value)
	return value
}

func applyEmbeddedMigrationForTest(t *testing.T, ctx context.Context, db migrationConn, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("read migration %03d %s: %v", version, direction, err)
	}
	migration := migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
	if err := applyMigration(ctx, db, migration); err != nil {
		t.Fatalf("apply migration %s: %v", migration.name, err)
	}
	return migration
}

func applyEmbeddedMigrationsRangeForTest(t *testing.T, ctx context.Context, db migrationConn, first, last int) {
	t.Helper()
	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations(): %v", err)
	}
	for _, migration := range migrations {
		if migration.version < first || migration.version > last {
			continue
		}
		if err := applyMigration(ctx, db, migration); err != nil {
			t.Fatalf("apply migration %s: %v", migration.name, err)
		}
	}
}

func assertCleanMigrationAndDelete(t *testing.T, ctx context.Context, db *sql.DB, migration migrationFile) {
	t.Helper()
	assertCleanMigration(t, ctx, db, migration)

	result, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version = $1`, migration.version)
	if err != nil {
		t.Fatalf("delete metadata for %s: %v", migration.name, err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		t.Fatalf("delete metadata for %s affected=%d err=%v, want 1", migration.name, affected, err)
	}
}

func assertCleanMigration(t *testing.T, ctx context.Context, db *sql.DB, migration migrationFile) {
	t.Helper()
	wantChecksum := migrationChecksum(migration.sql)
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT name, checksum, dirty, applied_at FROM schema_migrations WHERE version = $1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != wantChecksum || dirty || !appliedAt.Valid {
		t.Fatalf("metadata for %s = name:%q checksum:%q dirty:%v applied:%v", migration.name, name, checksum, dirty, appliedAt.Valid)
	}

	var eventName, eventChecksum string
	var finished sql.NullTime
	var success, eventDirty bool
	if err := db.QueryRowContext(ctx, `
		SELECT name, checksum, finished_at, success, dirty
		FROM schema_migration_events WHERE version = $1 ORDER BY id DESC LIMIT 1`, migration.version).Scan(&eventName, &eventChecksum, &finished, &success, &eventDirty); err != nil {
		t.Fatalf("read latest event for %s: %v", migration.name, err)
	}
	if eventName != migration.name || eventChecksum != wantChecksum || !finished.Valid || !success || eventDirty {
		t.Fatalf("event for %s = name:%q checksum:%q finished:%v success:%v dirty:%v", migration.name, eventName, eventChecksum, finished.Valid, success, eventDirty)
	}
}

func expectSQLState(t *testing.T, want string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("SQL error = nil, want SQLSTATE %s", want)
	}
	var state interface{ SQLState() string }
	if !errors.As(err, &state) {
		t.Fatalf("SQL error %T %v does not expose SQLSTATE %s", err, err, want)
	}
	if got := state.SQLState(); got != want {
		t.Fatalf("SQLSTATE = %s, want %s: %v", got, want, err)
	}
}

func execSQL(ctx context.Context, db *sql.DB, statement string, args ...any) error {
	_, err := db.ExecContext(ctx, statement, args...)
	return err
}

func execOK(t *testing.T, ctx context.Context, db *sql.DB, statement string, args ...any) {
	t.Helper()
	if err := execSQL(ctx, db, statement, args...); err != nil {
		t.Fatalf("execute %q: %v", statement, err)
	}
}

func queryStrings(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		t.Fatalf("query strings: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scan string: %v", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate strings: %v", err)
	}
	return values
}
