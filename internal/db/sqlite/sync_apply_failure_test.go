package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/synccontract"
)

// syncPageWithEveryTable returns a response that touches all four local tables,
// so a test can drop one table and be sure the failure comes from that table
// rather than from an empty payload.
func syncPageWithEveryTable() *synccontract.Response {
	return &synccontract.Response{
		SyncedAt: "2026-08-04T12:00:00Z",
		Vulnerabilities: []synccontract.Vulnerability{{
			ID:        "GHSA-sync-1",
			Ecosystem: "npm",
			Name:      "left-pad",
			Severity:  "HIGH",
			Source:    "osv",
		}},
		Malicious: []synccontract.Malicious{{
			ID:        "MAL-sync-1",
			Ecosystem: "npm",
			Name:      "evil-pkg",
			RiskType:  "malware",
			Severity:  "CRITICAL",
			Source:    "socket",
		}},
	}
}

// newStoreWithDroppedTable opens a store and removes one local table, standing
// in for a partially corrupted or hand-edited cache.
func newStoreWithDroppedTable(t *testing.T, table string) *Store {
	t.Helper()

	store, err := New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.DB().Exec(`DROP TABLE ` + table); err != nil {
		t.Fatalf("drop %s: %v", table, err)
	}
	return store
}

// TestApplySyncReportsAnUnusableDatabase covers the outermost failure: the
// transaction cannot even be opened. A sync that swallowed this would mark the
// cache as freshly synced while writing nothing.
func TestApplySyncReportsAnUnusableDatabase(t *testing.T) {
	t.Parallel()

	store := newClosedStore(t)

	stats, err := applySync(context.Background(), store, false, syncPageWithEveryTable())
	if err == nil {
		t.Fatal("applySync on a closed database = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "begin transaction") {
		t.Fatalf("error = %v, want it to name the transaction", err)
	}
	if stats != (SyncStats{}) {
		t.Fatalf("stats = %+v, want the zero value on failure", stats)
	}
}

// TestApplySyncReportsAFailedFullClear covers the full-sync path, which drops
// existing rows before inserting. If the clear fails the import must abort:
// continuing would merge a full snapshot into stale data.
func TestApplySyncReportsAFailedFullClear(t *testing.T) {
	t.Parallel()

	store := newStoreWithDroppedTable(t, "reputation_findings_local")

	if _, err := applySync(context.Background(), store, true, syncPageWithEveryTable()); err == nil {
		t.Fatal("a full sync over a broken cache = nil error, want a refusal")
	}
}

// TestApplySyncRollsBackWhenOneTableFails is the transactional guarantee. A page
// that fails part-way must leave nothing behind, or the next incremental sync
// would build on a half-written snapshot.
func TestApplySyncRollsBackWhenOneTableFails(t *testing.T) {
	t.Parallel()

	store := newStoreWithDroppedTable(t, "malicious_local")
	ctx := context.Background()

	if _, err := applySync(ctx, store, false, syncPageWithEveryTable()); err == nil {
		t.Fatal("applySync with a missing table = nil error, want a refusal")
	}

	// The vulnerability from the same page was applied before the failure and
	// must have been rolled back with it.
	var count int
	if err := store.DB().QueryRow(
		`SELECT COUNT(*) FROM vulnerabilities_local WHERE id = 'GHSA-sync-1'`,
	).Scan(&count); err != nil {
		t.Fatalf("count vulnerabilities: %v", err)
	}
	if count != 0 {
		t.Fatalf("the failed page committed %d vulnerability rows, want 0", count)
	}
}

// TestApplySyncSucceedsOnAHealthyCache is the control: without a broken table the
// same page applies cleanly, which is what makes the failure tests meaningful.
func TestApplySyncSucceedsOnAHealthyCache(t *testing.T) {
	t.Parallel()

	store, err := New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := applySync(context.Background(), store, false, syncPageWithEveryTable()); err != nil {
		t.Fatalf("applySync on a healthy cache: %v", err)
	}

	var vulnerabilities, malicious int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM vulnerabilities_local`).Scan(&vulnerabilities); err != nil {
		t.Fatalf("count vulnerabilities: %v", err)
	}
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM malicious_local`).Scan(&malicious); err != nil {
		t.Fatalf("count malicious: %v", err)
	}
	if vulnerabilities != 1 || malicious != 1 {
		t.Fatalf("applied %d vulnerabilities and %d malicious rows, want 1 each", vulnerabilities, malicious)
	}
}

// TestApplySyncFullClearsBeforeInserting pins the full-sync semantics: rows that
// are no longer in the snapshot must disappear. Merging instead would keep a
// withdrawn advisory blocking a package forever.
func TestApplySyncFullClearsBeforeInserting(t *testing.T) {
	t.Parallel()

	store, err := New(filepath.Join(t.TempDir(), "packmon.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	stale := &synccontract.Response{
		SyncedAt: "2026-08-03T12:00:00Z",
		Vulnerabilities: []synccontract.Vulnerability{{
			ID: "GHSA-stale", Ecosystem: "npm", Name: "stale-pkg", Severity: "HIGH", Source: "osv",
		}},
	}
	if _, err := applySync(ctx, store, true, stale); err != nil {
		t.Fatalf("seed sync: %v", err)
	}

	stats, err := applySync(ctx, store, true, syncPageWithEveryTable())
	if err != nil {
		t.Fatalf("second full sync: %v", err)
	}
	if stats.FullCleared.Vulnerabilities == 0 {
		t.Error("the full sync reported no cleared vulnerability rows")
	}

	var stalePresent int
	if err := store.DB().QueryRow(
		`SELECT COUNT(*) FROM vulnerabilities_local WHERE id = 'GHSA-stale'`,
	).Scan(&stalePresent); err != nil {
		t.Fatalf("count stale rows: %v", err)
	}
	if stalePresent != 0 {
		t.Fatal("a full sync kept an advisory that left the snapshot")
	}
}
