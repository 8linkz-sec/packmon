package devstore

import (
	"context"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestNoopStoreAPIKeyTimestampsAreDefensiveCopies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	expiresAt := time.Now().UTC().Add(time.Hour)
	originalExpiresAt := expiresAt
	keyID, err := store.CreateAPIKey(ctx, "ci", "hash", &expiresAt)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	expiresAt = expiresAt.Add(-2 * time.Hour)

	found, err := store.FindAPIKeyByHash(ctx, "hash")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash() error = %v", err)
	}
	if found == nil || found.ExpiresAt == nil || !found.ExpiresAt.Equal(originalExpiresAt) {
		t.Fatalf("FindAPIKeyByHash() expires = %+v, want %s", found, originalExpiresAt)
	}
	*found.ExpiresAt = time.Now().UTC().Add(-time.Hour)

	foundAgain, err := store.FindAPIKeyByHash(ctx, "hash")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash() after caller mutation error = %v", err)
	}
	if foundAgain == nil {
		t.Fatal("FindAPIKeyByHash() after caller mutation = nil, want stored key")
	}

	if err := store.TouchAPIKeyLastUsed(ctx, keyID); err != nil {
		t.Fatalf("TouchAPIKeyLastUsed() error = %v", err)
	}
	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0].LastUsedAt == nil {
		t.Fatalf("ListAPIKeys() = %+v, want touched key", keys)
	}
	*keys[0].LastUsedAt = time.Time{}

	keysAgain, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys() after caller mutation error = %v", err)
	}
	if keysAgain[0].LastUsedAt == nil || keysAgain[0].LastUsedAt.IsZero() {
		t.Fatalf("ListAPIKeys() LastUsedAt was mutated through returned pointer: %+v", keysAgain[0])
	}
}

func TestNoopStoreRefreshJobsUseDefensiveProcessedAtCopies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	processedAt := time.Now().UTC().Add(-time.Minute)
	created, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem:   "npm",
		Name:        "left-pad",
		Source:      "socket",
		Priority:    1,
		ProcessedAt: &processedAt,
	})
	if err != nil || !created {
		t.Fatalf("EnqueueRefresh() = %v, %v; want created nil", created, err)
	}
	processedAt = time.Time{}

	claimed, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh() error = %v", err)
	}
	if claimed == nil || claimed.ProcessedAt == nil {
		t.Fatalf("DequeueRefresh() = %+v, want claimed job", claimed)
	}
	claimedAt := *claimed.ProcessedAt
	*claimed.ProcessedAt = time.Time{}

	jobs, err := store.ListQueueJobsPage(ctx, db.RefreshStatusProcessing, 10, 0)
	if err != nil {
		t.Fatalf("ListQueueJobsPage() error = %v", err)
	}
	if len(jobs) != 1 || jobs[0].ProcessedAt == nil || !jobs[0].ProcessedAt.Equal(claimedAt) {
		t.Fatalf("ListQueueJobsPage() = %+v, want stored processed timestamp %s", jobs, claimedAt)
	}
	*jobs[0].ProcessedAt = time.Time{}

	jobsAgain, err := store.ListQueueJobsPage(ctx, db.RefreshStatusProcessing, 10, 0)
	if err != nil {
		t.Fatalf("ListQueueJobsPage() after caller mutation error = %v", err)
	}
	if jobsAgain[0].ProcessedAt == nil || jobsAgain[0].ProcessedAt.IsZero() {
		t.Fatalf("ListQueueJobsPage() ProcessedAt was mutated through returned pointer: %+v", jobsAgain[0])
	}
}

func TestNoopStoreScanLogsUseDefensiveCopies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	entry := &db.ScanLogEntry{
		ScanID:            "scan-1",
		ScannedAt:         time.Now().UTC(),
		IdempotencyKey:    "idem-1",
		FeedVersions:      map[string]string{"osv": "one"},
		FindingIDs:        []string{"CVE-1"},
		FindingSeverities: []string{"HIGH"},
	}
	if err := store.InsertScanLog(ctx, entry); err != nil {
		t.Fatalf("InsertScanLog() error = %v", err)
	}
	entry.FeedVersions["osv"] = "caller-mutated"
	entry.FindingIDs[0] = "caller-mutated"
	entry.FindingSeverities[0] = "caller-mutated"

	got, err := store.GetScanLogByIdempotencyKey(ctx, "idem-1")
	if err != nil {
		t.Fatalf("GetScanLogByIdempotencyKey() error = %v", err)
	}
	if got == nil ||
		got.FeedVersions["osv"] != "one" ||
		got.FindingIDs[0] != "CVE-1" ||
		got.FindingSeverities[0] != "HIGH" {
		t.Fatalf("GetScanLogByIdempotencyKey() = %+v, want stored immutable values", got)
	}

	got.FeedVersions["osv"] = "returned-mutated"
	got.FindingIDs[0] = "returned-mutated"
	got.FindingSeverities[0] = "returned-mutated"
	recent, err := store.ListRecentScans(ctx, 1, 0)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(recent) != 1 ||
		recent[0].FeedVersions["osv"] != "one" ||
		recent[0].FindingIDs[0] != "CVE-1" ||
		recent[0].FindingSeverities[0] != "HIGH" {
		t.Fatalf("ListRecentScans() = %+v, want stored immutable values", recent)
	}

	recent[0].FeedVersions["osv"] = "recent-mutated"
	recent[0].FindingIDs[0] = "recent-mutated"
	recent[0].FindingSeverities[0] = "recent-mutated"
	gotAgain, err := store.GetScanLogByIdempotencyKey(ctx, "idem-1")
	if err != nil {
		t.Fatalf("GetScanLogByIdempotencyKey() after caller mutation error = %v", err)
	}
	if gotAgain.FeedVersions["osv"] != "one" ||
		gotAgain.FindingIDs[0] != "CVE-1" ||
		gotAgain.FindingSeverities[0] != "HIGH" {
		t.Fatalf("stored scan log was mutated through returned fields: %+v", gotAgain)
	}
}
