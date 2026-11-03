//go:build integration

package postgres

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF211ScanLogContractsAgainstPostgres(t *testing.T) {
	store, dsn := startDockerPostgresStore(t)
	ctx := context.Background()

	t.Run("insert commits normalized nullable fields and rollup exactly once", func(t *testing.T) {
		before := f211ScanTotals(t, store)
		entry := db.ScanLogEntry{
			ScanID:                "f211-insert",
			RepoName:              "  ",
			ScannedAt:             time.Date(2026, 11, 3, 8, 30, 0, 0, time.UTC),
			PackagesCount:         17,
			FindingsCount:         3,
			DurationMs:            211,
			CorrelationID:         "corr-f211",
			IdempotencyKey:        "f211-idempotency",
			RequestDigest:         "sha256:f211-request",
			ResultDigest:          "sha256:f211-result",
			FindingsBlocking:      true,
			BlockThreshold:        "HIGH",
			FeedStatus:            "healthy",
			ManualAdvisoriesCount: 2,
		}
		if err := store.InsertScanLog(ctx, &entry); err != nil {
			t.Fatalf("InsertScanLog() error = %v", err)
		}

		got, err := store.ListRecentScans(ctx, 1, -10)
		if err != nil || len(got) != 1 {
			t.Fatalf("ListRecentScans() = %+v, %v; want one row", got, err)
		}
		want := entry
		want.RepoName = ""
		want.FeedVersions = map[string]string{}
		want.FindingIDs = []string{}
		want.FindingSeverities = []string{}
		got[0].ScannedAt = got[0].ScannedAt.UTC()
		if !reflect.DeepEqual(got[0], want) {
			t.Fatalf("ListRecentScans()[0] = %+v, want %+v", got[0], want)
		}

		after := f211ScanTotals(t, store)
		if after.PackagesScanned-before.PackagesScanned != int64(entry.PackagesCount) ||
			after.Findings-before.Findings != int64(entry.FindingsCount) {
			t.Fatalf("scan totals delta = %+v -> %+v, want packages=%d findings=%d",
				before, after, entry.PackagesCount, entry.FindingsCount)
		}

		duplicate := entry
		duplicate.ScanID = "f211-duplicate-must-not-win"
		duplicate.PackagesCount = 999
		duplicate.FindingsCount = 999
		duplicate.RequestDigest = "sha256:duplicate"
		if err := store.InsertScanLog(ctx, &duplicate); err != nil {
			t.Fatalf("InsertScanLog(duplicate) error = %v", err)
		}
		if totals := f211ScanTotals(t, store); totals != after {
			t.Fatalf("scan totals after idempotent duplicate = %+v, want %+v", totals, after)
		}
		lookup, err := store.GetScanLogByIdempotencyKey(ctx, "  f211-idempotency \t")
		if err != nil || lookup == nil {
			t.Fatalf("GetScanLogByIdempotencyKey() = %+v, %v", lookup, err)
		}
		if lookup.ScanID != entry.ScanID || lookup.IdempotencyKey != entry.IdempotencyKey ||
			lookup.RequestDigest != entry.RequestDigest || lookup.ResultDigest != entry.ResultDigest {
			t.Fatalf("idempotency lookup = %+v, want original committed metadata", lookup)
		}
	})

	t.Run("missing idempotency key is not an error", func(t *testing.T) {
		got, err := store.GetScanLogByIdempotencyKey(ctx, "f211-absent")
		if err != nil || got != nil {
			t.Fatalf("GetScanLogByIdempotencyKey(absent) = %+v, %v; want nil, nil", got, err)
		}
	})

	t.Run("insert execution error rolls back row and rollup", func(t *testing.T) {
		before := f211ScanTotals(t, store)
		err := store.InsertScanLog(ctx, &db.ScanLogEntry{
			ScanID:        "f211-invalid-ip",
			ScannedAt:     time.Now().UTC(),
			PackagesCount: 5,
			FindingsCount: 2,
			ClientIP:      "not an inet address",
		})
		if err == nil || !strings.Contains(err.Error(), "postgres: insert scan log:") {
			t.Fatalf("InsertScanLog(invalid IP) error = %v, want wrapped execution error", err)
		}
		f211RequireScanAbsent(t, store, "f211-invalid-ip")
		if after := f211ScanTotals(t, store); after != before {
			t.Fatalf("scan totals after execution rollback = %+v, want %+v", after, before)
		}
	})

	t.Run("deferred commit failure rolls back row and rollup", func(t *testing.T) {
		before := f211ScanTotals(t, store)
		if _, err := store.pool.Exec(ctx, `
			CREATE FUNCTION f211_fail_scan_log_commit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				RAISE EXCEPTION 'forced f211 deferred commit failure';
			END $$;
			CREATE CONSTRAINT TRIGGER f211_fail_scan_log_commit
			AFTER INSERT ON scan_log
			DEFERRABLE INITIALLY DEFERRED
			FOR EACH ROW
			WHEN (NEW.scan_id = 'f211-commit-failure')
			EXECUTE FUNCTION f211_fail_scan_log_commit()`); err != nil {
			t.Fatalf("install deferred commit fault: %v", err)
		}
		t.Cleanup(func() {
			_, _ = store.pool.Exec(context.Background(), `
				DROP TRIGGER IF EXISTS f211_fail_scan_log_commit ON scan_log;
				DROP FUNCTION IF EXISTS f211_fail_scan_log_commit()`)
		})

		err := store.InsertScanLog(ctx, &db.ScanLogEntry{
			ScanID:         "f211-commit-failure",
			ScannedAt:      time.Now().UTC(),
			PackagesCount:  7,
			FindingsCount:  4,
			BlockThreshold: "NONE",
			FeedStatus:     "healthy",
		})
		if err == nil || !strings.Contains(err.Error(), "commit tx:") ||
			!strings.Contains(err.Error(), "forced f211 deferred commit failure") {
			t.Fatalf("InsertScanLog(deferred failure) error = %v, want wrapped commit error", err)
		}
		f211RequireScanAbsent(t, store, "f211-commit-failure")
		if after := f211ScanTotals(t, store); after != before {
			t.Fatalf("scan totals after commit rollback = %+v, want %+v", after, before)
		}

		if _, err := store.pool.Exec(ctx, `
			DROP TRIGGER f211_fail_scan_log_commit ON scan_log;
			DROP FUNCTION f211_fail_scan_log_commit()`); err != nil {
			t.Fatalf("remove deferred commit fault: %v", err)
		}
	})

	t.Run("recent scan paging clamps limit and offset", func(t *testing.T) {
		if _, err := store.pool.Exec(ctx, `DELETE FROM scan_log`); err != nil {
			t.Fatalf("reset scan log: %v", err)
		}
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO scan_log(scan_id, scanned_at, packages_count, findings_count, duration_ms)
			SELECT 'f211-page-' || lpad(g::text, 3, '0'),
			       TIMESTAMPTZ '2026-11-03 10:00:00+00' + (g * INTERVAL '1 second'),
			       g, g % 3, g
			FROM generate_series(1, 105) AS g`); err != nil {
			t.Fatalf("seed paging rows: %v", err)
		}
		page, err := store.ListRecentScans(ctx, 1000, -5)
		if err != nil || len(page) != 100 {
			t.Fatalf("ListRecentScans(clamped) len=%d, error=%v; want 100", len(page), err)
		}
		if page[0].ScanID != "f211-page-105" || page[99].ScanID != "f211-page-006" {
			t.Fatalf("clamped page bounds = %q .. %q", page[0].ScanID, page[99].ScanID)
		}
		next, err := store.ListRecentScans(ctx, 2, 100)
		if err != nil || len(next) != 2 || next[0].ScanID != "f211-page-005" || next[1].ScanID != "f211-page-004" {
			t.Fatalf("ListRecentScans(offset) = %+v, %v", next, err)
		}
	})

	t.Run("pruning is strict transactional and preserves rollup", func(t *testing.T) {
		if _, err := store.pool.Exec(ctx, `DELETE FROM scan_log`); err != nil {
			t.Fatalf("reset scan log: %v", err)
		}
		now := time.Now().UTC()
		for _, entry := range []db.ScanLogEntry{
			{ScanID: "f211-prune-old", ScannedAt: now.Add(-2 * time.Hour), PackagesCount: 1, BlockThreshold: "NONE", FeedStatus: "healthy"},
			{ScanID: "f211-prune-recent", ScannedAt: now.Add(time.Hour), PackagesCount: 1, BlockThreshold: "NONE", FeedStatus: "healthy"},
		} {
			entry := entry
			if err := store.InsertScanLog(ctx, &entry); err != nil {
				t.Fatalf("InsertScanLog(%s) error = %v", entry.ScanID, err)
			}
		}
		before := f211ScanTotals(t, store)
		removed, err := store.PruneScanLogs(ctx, time.Hour)
		if err != nil || removed != 1 {
			t.Fatalf("PruneScanLogs() = %d, %v; want 1, nil", removed, err)
		}
		f211RequireScanAbsent(t, store, "f211-prune-old")
		f211RequireScanPresent(t, store, "f211-prune-recent")
		after := f211ScanTotals(t, store)
		if after.PackagesScanned != before.PackagesScanned-1 || after.Findings != before.Findings {
			t.Fatalf("scan totals after committed pruning = %+v, want packages=%d findings=%d",
				after, before.PackagesScanned-1, before.Findings)
		}
	})

	t.Run("prune error rolls back every candidate", func(t *testing.T) {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO scan_log(scan_id, scanned_at, packages_count, findings_count, duration_ms)
			VALUES
				('f211-prune-rollback-a', NOW() - INTERVAL '3 hours', 1, 0, 1),
				('f211-prune-rollback-b', NOW() - INTERVAL '4 hours', 1, 0, 1);
			CREATE FUNCTION f211_fail_scan_log_prune() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF OLD.scan_id = 'f211-prune-rollback-b' THEN
					RAISE EXCEPTION 'forced f211 prune failure';
				END IF;
				RETURN OLD;
			END $$;
			CREATE TRIGGER f211_fail_scan_log_prune
			BEFORE DELETE ON scan_log
			FOR EACH ROW EXECUTE FUNCTION f211_fail_scan_log_prune()`); err != nil {
			t.Fatalf("install prune fault: %v", err)
		}
		t.Cleanup(func() {
			_, _ = store.pool.Exec(context.Background(), `
				DROP TRIGGER IF EXISTS f211_fail_scan_log_prune ON scan_log;
				DROP FUNCTION IF EXISTS f211_fail_scan_log_prune()`)
		})

		before := f211ScanTotals(t, store)
		removed, err := store.PruneScanLogs(ctx, time.Hour)
		if removed != 0 || err == nil || !strings.Contains(err.Error(), "postgres: prune scan logs:") {
			t.Fatalf("PruneScanLogs(fault) = %d, %v; want 0 and wrapped error", removed, err)
		}
		f211RequireScanPresent(t, store, "f211-prune-rollback-a")
		f211RequireScanPresent(t, store, "f211-prune-rollback-b")
		if after := f211ScanTotals(t, store); after != before {
			t.Fatalf("scan totals after prune rollback = %+v, want %+v", after, before)
		}

		if _, err := store.pool.Exec(ctx, `
			DROP TRIGGER f211_fail_scan_log_prune ON scan_log;
			DROP FUNCTION f211_fail_scan_log_prune()`); err != nil {
			t.Fatalf("remove prune fault: %v", err)
		}
	})

	t.Run("closed pool errors are wrapped with nil or zero results", func(t *testing.T) {
		closed, err := New(ctx, dsn, nil, &PoolConfig{MaxConns: 1, MinConns: 1})
		if err != nil {
			t.Fatalf("New(closed fault store) error = %v", err)
		}
		if err := closed.Close(); err != nil {
			t.Fatalf("Close(closed fault store) error = %v", err)
		}

		if got, err := closed.GetScanLogByIdempotencyKey(ctx, "f211-idempotency"); got != nil || err == nil ||
			!strings.Contains(err.Error(), "postgres: get scan log by idempotency key:") {
			t.Fatalf("GetScanLogByIdempotencyKey(closed) = %+v, %v", got, err)
		}
		if got, err := closed.ListRecentScans(ctx, 10, 0); got != nil || err == nil ||
			!strings.Contains(err.Error(), "postgres: list recent scans:") {
			t.Fatalf("ListRecentScans(closed) = %+v, %v", got, err)
		}
		if got, err := closed.PruneScanLogs(ctx, time.Hour); got != 0 || err == nil {
			t.Fatalf("PruneScanLogs(closed) = %d, %v", got, err)
		}
	})

	for _, tc := range []struct {
		name       string
		row        string
		wantPrefix string
	}{
		{
			name: "row scan failure returns no partial page",
			row: f211ScanLogViewRow(
				"1", "'f211-scan-fault'::text", "'infinity'::timestamptz",
				`'{}'::jsonb`, `'[]'::jsonb`, `'[]'::jsonb`, "0::int",
			),
			wantPrefix: "postgres: scan recent scan row:",
		},
		{
			name: "feed versions decode failure returns no partial page",
			row: f211ScanLogViewRow(
				"1", "'f211-feed-json-fault'::text", "NOW()",
				`'[]'::jsonb`, `'[]'::jsonb`, `'[]'::jsonb`, "0::int",
			),
			wantPrefix: "postgres: decode scan log feed versions:",
		},
		{
			name: "finding ids decode failure returns no partial page",
			row: f211ScanLogViewRow(
				"1", "'f211-id-json-fault'::text", "NOW()",
				`'{}'::jsonb`, `'{}'::jsonb`, `'[]'::jsonb`, "0::int",
			),
			wantPrefix: "postgres: decode scan log finding ids:",
		},
		{
			name: "finding severities decode failure returns no partial page",
			row: f211ScanLogViewRow(
				"1", "'f211-severity-json-fault'::text", "NOW()",
				`'{}'::jsonb`, `'[]'::jsonb`, `'{}'::jsonb`, "0::int",
			),
			wantPrefix: "postgres: decode scan log finding severities:",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := f099SwapTableForFaultView(t, store, "scan_log", "scan_log_f211_fault_base", nil,
				"CREATE VIEW scan_log AS "+tc.row)
			got, err := store.ListRecentScans(ctx, 10, 0)
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.wantPrefix) {
				t.Fatalf("ListRecentScans(fault) = %+v, %v; want nil and %q", got, err, tc.wantPrefix)
			}
			restore()
		})
	}

	t.Run("iteration failure discards an already scanned row", func(t *testing.T) {
		valid := f211ScanLogViewRow(
			"2", "'f211-iteration-valid'::text", "TIMESTAMPTZ '2026-11-03 12:00:00+00'",
			`'{}'::jsonb`, `'[]'::jsonb`, `'[]'::jsonb`, "1::int",
		)
		fault := f211ScanLogViewRow(
			"1", "'f211-iteration-fault'::text", "TIMESTAMPTZ '2026-11-03 11:00:00+00'",
			`'{}'::jsonb`, `'[]'::jsonb`, `'[]'::jsonb`, "f211_fail_scan_log_int(2)",
		)
		restore := f099SwapTableForFaultView(t, store, "scan_log", "scan_log_f211_iteration_base",
			[]string{`DROP FUNCTION IF EXISTS f211_fail_scan_log_int(integer)`},
			`CREATE FUNCTION f211_fail_scan_log_int(value integer) RETURNS integer LANGUAGE plpgsql STABLE AS $$ BEGIN RAISE EXCEPTION 'forced f211 iteration failure'; END $$`,
			"CREATE VIEW scan_log AS "+valid+" UNION ALL "+fault)
		got, err := store.ListRecentScans(ctx, 10, 0)
		if got != nil || err == nil || !strings.Contains(err.Error(), "postgres: iterate recent scans:") ||
			!strings.Contains(err.Error(), "forced f211 iteration failure") {
			t.Fatalf("ListRecentScans(iteration fault) = %+v, %v; want nil iteration error", got, err)
		}
		restore()
	})
}

func f211ScanLogViewRow(id, scanID, scannedAt, feedVersions, findingIDs, findingSeverities, manualCount string) string {
	return fmt.Sprintf(`SELECT
		%s::int AS id,
		%s AS scan_id,
		NULL::text AS repo_name,
		%s AS scanned_at,
		1::int AS packages_count,
		1::int AS findings_count,
		1::int AS duration_ms,
		NULL::inet AS client_ip,
		NULL::text AS client_version,
		NULL::int AS api_key_id,
		NULL::text AS api_key_name,
		''::text AS correlation_id,
		NULL::text AS idempotency_key,
		''::text AS request_digest,
		''::text AS result_digest,
		FALSE AS findings_blocking,
		''::text AS block_threshold,
		''::text AS feed_status,
		%s AS feed_versions,
		%s AS finding_ids,
		%s AS finding_severities,
		%s AS manual_advisories_count`,
		id, scanID, scannedAt, feedVersions, findingIDs, findingSeverities, manualCount)
}

func f211ScanTotals(t *testing.T, store *Store) db.ScanTotals {
	t.Helper()
	totals, err := store.ScanTotals(context.Background())
	if err != nil {
		t.Fatalf("ScanTotals() error = %v", err)
	}
	return *totals
}

func f211RequireScanAbsent(t *testing.T, store *Store, scanID string) {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(context.Background(), `SELECT COUNT(*)::int FROM scan_log WHERE scan_id=$1`, scanID).Scan(&count); err != nil {
		t.Fatalf("count scan %q: %v", scanID, err)
	}
	if count != 0 {
		t.Fatalf("scan %q count = %d, want absent", scanID, count)
	}
}

func f211RequireScanPresent(t *testing.T, store *Store, scanID string) {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(context.Background(), `SELECT COUNT(*)::int FROM scan_log WHERE scan_id=$1`, scanID).Scan(&count); err != nil {
		t.Fatalf("count scan %q: %v", scanID, err)
	}
	if count != 1 {
		t.Fatalf("scan %q count = %d, want 1", scanID, count)
	}
}
