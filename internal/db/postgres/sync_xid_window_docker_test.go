//go:build integration

package postgres

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// testSyncXIDConditionsMatchTheirModel evaluates syncXIDAtOrAfterSQL and
// syncXIDBeforeSQL on PostgreSQL for 32-bit xmin values around the
// database's next transaction ID and for watermarks inside, at the edge of,
// and outside the 2^31 window (including one from the future), and checks
// each result against the Go model the unit tests verify across the
// wraparound and past the first epoch. This pins PostgreSQL's integer
// semantics, the once-per-statement window subquery, and the binding of the
// 64-bit watermark as text.
func testSyncXIDConditionsMatchTheirModel(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	var next int64
	if err := store.pool.QueryRow(ctx, `SELECT txid_snapshot_xmax(txid_current_snapshot())`).Scan(&next); err != nil {
		t.Fatalf("read next transaction ID: %v", err)
	}
	low := func(xid int64) string { return strconv.FormatInt(((xid%4294967296)+4294967296)%4294967296, 10) }
	xmins := []string{"2", "3000000000", low(next - 200), low(next - 101), low(next - 100), low(next - 50), low(next - 1), low(next), low(next + 1000)}
	watermarks := []int64{next - 100, next - 1, next, next + 1, next - 2147483647, next - 2147483648, syncTestEpoch5 + 1000}

	for _, watermark := range watermarks {
		rows, err := store.pool.Query(ctx, `
			SELECT txid_snapshot_xmax(txid_current_snapshot()), x.row_xid::text::bigint,
				`+syncXIDAtOrAfterSQL("x.row_xid", "$1")+`,
				`+syncXIDBeforeSQL("x.row_xid", "$1")+`
			FROM unnest($2::text[]) AS raw(value)
			CROSS JOIN LATERAL (SELECT raw.value::xid AS row_xid) x`,
			strconv.FormatInt(watermark, 10), xmins)
		if err != nil {
			t.Fatalf("evaluate xid conditions for watermark %d: %v", watermark, err)
		}
		count := 0
		for rows.Next() {
			var (
				stmtNext          int64
				xmin              uint32
				atOrAfter, before bool
			)
			if err := rows.Scan(&stmtNext, &xmin, &atOrAfter, &before); err != nil {
				rows.Close()
				t.Fatalf("scan xid conditions: %v", err)
			}
			count++
			if want := syncTestXIDAtOrAfter(xmin, watermark, stmtNext); atOrAfter != want {
				t.Errorf("at or after(xmin %d, watermark %d, next %d) = %v on PostgreSQL, want %v", xmin, watermark, stmtNext, atOrAfter, want)
			}
			if want := syncTestXIDBefore(xmin, watermark, stmtNext); before != want {
				t.Errorf("before(xmin %d, watermark %d, next %d) = %v on PostgreSQL, want %v", xmin, watermark, stmtNext, before, want)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate xid conditions: %v", err)
		}
		if count != len(xmins) {
			t.Fatalf("evaluated %d xmin values for watermark %d, want %d", count, watermark, len(xmins))
		}
	}
}

// testDeltaDeliversRowCommittedAfterTheSnapshot reproduces the change the
// since_xid leg exists for: a transaction that started before a sync's
// snapshot (so its updated_at predates the snapshot) and commits after it.
// The sync cannot see the row, and the next delta must deliver it through
// since_xid; by timestamp alone it is missed.
func testDeltaDeliversRowCommittedAfterTheSnapshot(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const id = "MAL-xid-late-commit"
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin late transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO malicious_findings(id, ecosystem, name, source, risk_type, severity, summary, updated_at)
		VALUES ($1, 'npm', 'xid-late-commit', 'openssf', 'malware', 'CRITICAL', 'late commit', clock_timestamp() - interval '1 hour')`, id); err != nil {
		t.Fatalf("insert late malicious finding: %v", err)
	}

	since := syncDeltaBoundary(ctx, t, store).Add(-2 * time.Hour)
	first, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since})
	if err != nil {
		t.Fatalf("ExportSync(while the late transaction runs) error = %v", err)
	}
	if syncMaliciousExportContains(first.Malicious, id) {
		t.Fatalf("ExportSync(while the late transaction runs) delivered uncommitted %s", id)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit late transaction: %v", err)
	}

	timestampOnly, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &first.SyncedAt})
	if err != nil {
		t.Fatalf("ExportSync(next delta by timestamp) error = %v", err)
	}
	if syncMaliciousExportContains(timestampOnly.Malicious, id) {
		t.Fatalf("ExportSync(next delta by timestamp) delivered %s, want the fixture to depend on since_xid", id)
	}
	next, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &first.SyncedAt, SinceXID: first.SyncedXID})
	if err != nil {
		t.Fatalf("ExportSync(next delta) error = %v", err)
	}
	if !syncMaliciousExportContains(next.Malicious, id) {
		t.Fatalf("ExportSync(next delta since xid %d) missed %s committed after the previous snapshot", first.SyncedXID, id)
	}
}

func syncMaliciousExportContains(rows []db.SyncMalicious, id string) bool {
	for _, row := range rows {
		if row.ID == id {
			return true
		}
	}
	return false
}
