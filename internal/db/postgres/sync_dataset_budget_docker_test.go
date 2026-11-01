//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/synccontract"
)

// testOtherDatasetPagesStayWithinTheirByteBudgets syncs a delta of malicious
// and reputation rows whose summaries each encode to about 3.5 MiB of JSON
// ('<' is escaped to six bytes), so a page bounded by rows only would carry
// all of them -- more than the 32 MiB a client accepts. Every page stays
// within the byte budgets: at most two malicious rows (8 MiB) and one
// reputation row (4 MiB) per page, each dataset advances on every page until
// it is exhausted, and every row arrives exactly once.
func testOtherDatasetPagesStayWithinTheirByteBudgets(ctx context.Context, t *testing.T, store *Store) {
	t.Helper()

	const (
		rows = 5
		pad  = 600 << 10
	)
	since := syncDeltaBoundary(ctx, t, store)
	now := time.Now().UTC()
	for i := range rows {
		suffix := strconv.Itoa(i)
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO malicious_findings(id, ecosystem, name, source, risk_type, severity, summary)
			VALUES ($1, 'npm', $2, 'openssf', 'malware', 'CRITICAL', repeat('<', $3::int))`,
			"MAL-budget-"+suffix, "budget-mal-"+suffix, pad); err != nil {
			t.Fatalf("insert oversized malicious finding %d: %v", i, err)
		}
		if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
			Ecosystem: "npm", Name: "budget-rep-" + suffix, Version: "1.0.0",
			Source: db.ReputationSourceReversingLabs, Status: "malicious", Severity: "CRITICAL",
			Summary: "budget fixture", LastCheckedAt: &now,
		}); err != nil {
			t.Fatalf("UpsertPackageReputation(%d) error = %v", i, err)
		}
		if _, err := store.pool.Exec(ctx, `
			UPDATE package_reputation_cache SET summary = repeat('<', $1::int)
			WHERE source = $2 AND ecosystem = 'npm' AND name = $3`,
			pad, db.ReputationSourceReversingLabs, "budget-rep-"+suffix); err != nil {
			t.Fatalf("pad reputation summary %d: %v", i, err)
		}
	}

	malicious := make(map[string]int, rows)
	reputation := make(map[string]int, rows)
	opts := db.SyncExportOptions{Since: &since, Limit: synccontract.MaxLimit}
	for pages := 1; ; pages++ {
		page, err := store.ExportSync(ctx, opts)
		if err != nil {
			t.Fatalf("ExportSync(page %d) error = %v", pages, err)
		}
		encoded, err := json.Marshal(synccontract.ResponseFromExport(page, "healthy", nil))
		if err != nil {
			t.Fatalf("encode page %d: %v", pages, err)
		}
		if len(encoded) > synccontract.MaxResponseBytes {
			t.Fatalf("page %d encodes to %d bytes, more than the %d-byte client cap", pages, len(encoded), synccontract.MaxResponseBytes)
		}
		if len(page.Malicious) > 2 || len(page.Reputation) > 1 {
			t.Fatalf("page %d holds %d malicious and %d reputation rows, want at most 2 and 1 within the byte budgets", pages, len(page.Malicious), len(page.Reputation))
		}
		for _, row := range page.Malicious {
			malicious[row.ID]++
		}
		for _, row := range page.Reputation {
			reputation[row.Name]++
		}
		if !page.Truncated {
			break
		}
		if pages > 3*rows {
			t.Fatalf("delta did not finish after %d pages", pages)
		}
		if (len(page.Malicious) == 0 && !page.NextCursor.MaliciousDone) || (len(page.Reputation) == 0 && !page.NextCursor.ReputationDone) {
			t.Fatalf("page %d made no progress on a dataset it continues: %+v", pages, page.NextCursor)
		}
		opts.SnapshotAt, opts.SnapshotXID, opts.Cursor = page.SyncedAt, page.SyncedXID, *page.NextCursor
	}
	for i := range rows {
		suffix := strconv.Itoa(i)
		if got := malicious["MAL-budget-"+suffix]; got != 1 {
			t.Fatalf("malicious row %d delivered %d times, want once (%v)", i, got, malicious)
		}
		if got := reputation["budget-rep-"+suffix]; got != 1 {
			t.Fatalf("reputation row %d delivered %d times, want once (%v)", i, got, reputation)
		}
	}
}
