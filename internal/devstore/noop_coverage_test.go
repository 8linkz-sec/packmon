package devstore

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestNoopStoreRemainingStubAndPruneBranches(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if deleted, err := store.ReplaceLifecycleProducts(ctx, []db.LifecycleProduct{{ProductSlug: "nodejs"}}); err != nil || deleted != 0 {
		t.Fatalf("ReplaceLifecycleProducts() = %d, %v; want 0 nil", deleted, err)
	}
	if findings, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "node"}}, time.Now()); err != nil || findings != nil {
		t.Fatalf("FindLifecycleFindingsBatch() = %+v, %v; want nil nil", findings, err)
	}

	for _, finding := range []db.MaliciousFinding{
		{ID: "keep", Ecosystem: "npm", Name: "keep", Source: "openssf", Severity: "CRITICAL", ReferenceURLs: json.RawMessage(`["https://example.test/keep"]`)},
		{ID: "drop", Ecosystem: "npm", Name: "drop", Source: "openssf", Severity: "HIGH", Versions: json.RawMessage(`["1.0.0"]`)},
		{ID: "other-source", Ecosystem: "npm", Name: "other", Source: "manual", Severity: "LOW"},
	} {
		if err := store.UpsertMaliciousFinding(ctx, &finding); err != nil {
			t.Fatalf("UpsertMaliciousFinding(%s) error = %v", finding.ID, err)
		}
	}
	pruned, err := store.DeleteMaliciousFindingsNotInSource(ctx, "openssf", []string{"keep"})
	if err != nil {
		t.Fatalf("DeleteMaliciousFindingsNotInSource() error = %v", err)
	}
	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}
	listed, err := store.ListMaliciousFindings(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListMaliciousFindings() error = %v", err)
	}
	for _, finding := range listed {
		if finding.ID == "drop" {
			t.Fatalf("drop finding was not pruned: %+v", listed)
		}
	}

	since := time.Now().Add(-time.Minute)
	exported, err := store.ExportSync(ctx, db.SyncExportOptions{Since: &since, Ecosystems: []string{"npm"}})
	if err != nil {
		t.Fatalf("ExportSync() error = %v", err)
	}
	var sawDropTombstone bool
	for _, row := range exported.Malicious {
		if row.ID == "drop" && row.Withdrawn && row.Versions == `["1.0.0"]` {
			sawDropTombstone = true
		}
	}
	if !sawDropTombstone {
		t.Fatalf("ExportSync() missing pruned tombstone: %+v", exported.Malicious)
	}
}
