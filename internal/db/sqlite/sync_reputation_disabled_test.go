package sqlite

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
)

// The tests in this file pin the reputation parity rule: when the server does
// not serve ReversingLabs reputation rows (not enabled in self mode), it says
// so with reputation_disabled and the local database drops previously synced
// reputation rows, so local scans match /api/v1/check. When the server serves
// reputation again, the client refetches the whole reputation dataset because
// a delta sync would never resend rows that did not change in the meantime.

const leftoverReputationID = "reversinglabs:npm/left-pad@1.3.0"

func leftoverMaliciousReputation() syncReputation {
	return syncReputation{
		ID:        leftoverReputationID,
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		Type:      "malicious",
		RiskType:  "malware",
		Severity:  "CRITICAL",
		Summary:   "ReversingLabs: malicious package version",
	}
}

func newReputationParityStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(store) })
	return store
}

func seedSyncedReputation(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := applySync(ctx, store, false, &syncResponse{Reputation: []syncReputation{leftoverMaliciousReputation()}}); err != nil {
		t.Fatalf("seed reputation: %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatalf("seed last sync: %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, "500"); err != nil {
		t.Fatalf("seed last sync xid: %v", err)
	}
	if got := countLocalReputation(t, store); got != 1 {
		t.Fatalf("seeded reputation rows = %d, want 1", got)
	}
}

func countLocalReputation(t *testing.T, store *Store) int {
	t.Helper()
	findings, err := store.FindReputationFindingsBatch(context.Background(), []db.PackageQuery{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
	}}, db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindingsBatch() error = %v", err)
	}
	return len(findings)
}

func reputationResyncMeta(t *testing.T, store *Store) string {
	t.Helper()
	value, err := store.GetSyncMeta(context.Background(), syncMetaKeyReputationResync)
	if err != nil {
		t.Fatalf("GetSyncMeta(reputation resync) error = %v", err)
	}
	return value
}

// scriptedSyncServer answers the n-th sync request with pages[n] and records
// every request query.
type scriptedSyncServer struct {
	mu      sync.Mutex
	queries []url.Values
}

func (s *scriptedSyncServer) start(t *testing.T, pages ...syncResponse) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		index := len(s.queries)
		s.queries = append(s.queries, r.URL.Query())
		s.mu.Unlock()
		if index >= len(pages) {
			t.Errorf("unexpected extra sync request %d: %s", index+1, r.URL.RawQuery)
			http.Error(w, "unexpected request", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(pages[index]); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func (s *scriptedSyncServer) requests() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.queries...)
}

func TestSyncDropsSyncedReputationWhenServerReportsDisabled(t *testing.T) {
	t.Parallel()

	store := newReputationParityStore(t)
	seedSyncedReputation(t, store)

	recorder := &scriptedSyncServer{}
	server := recorder.start(t, syncResponse{
		SyncedAt:           "2026-11-01T10:00:00Z",
		SyncedXID:          700,
		FeedStatus:         "healthy",
		ReputationDisabled: true,
		// A disabled response must never re-add reputation rows, even if a
		// misbehaving server sends some.
		Reputation: []syncReputation{leftoverMaliciousReputation()},
	})

	var stats SyncStats
	if err := Sync(context.Background(), store, SyncConfig{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Stats:             &stats,
	}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	requests := recorder.requests()
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1 delta page", len(requests))
	}
	if requests[0].Get("since") != "2026-10-01T00:00:00Z" {
		t.Fatalf("since = %q, want incremental sync", requests[0].Get("since"))
	}
	if got := countLocalReputation(t, store); got != 0 {
		t.Fatalf("local reputation rows after disabled delta sync = %d, want 0", got)
	}
	if stats.ReputationDisabled.Reputation != 1 || !stats.AnyRemoved() {
		t.Fatalf("stats = %+v, want one reputation row cleared because reputation is disabled", stats)
	}
	if got := reputationResyncMeta(t, store); got != "true" {
		t.Fatalf("reputation resync meta = %q, want true so a later re-enable refetches reputation", got)
	}
	lastSync, err := store.GetSyncMeta(context.Background(), syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta(last sync) error = %v", err)
	}
	if lastSync != "2026-11-01T10:00:00Z" {
		t.Fatalf("last sync = %q, want advanced freshness marker", lastSync)
	}
}

func TestSyncKeepsReputationTablesUntouchedWhenServerServesReputation(t *testing.T) {
	t.Parallel()

	store := newReputationParityStore(t)
	seedSyncedReputation(t, store)

	recorder := &scriptedSyncServer{}
	server := recorder.start(t, syncResponse{
		SyncedAt:   "2026-11-01T10:00:00Z",
		SyncedXID:  700,
		FeedStatus: "healthy",
	})

	if err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := len(recorder.requests()); got != 1 {
		t.Fatalf("requests = %d, want one delta page without a reputation refetch", got)
	}
	if got := countLocalReputation(t, store); got != 1 {
		t.Fatalf("local reputation rows = %d, want delta sync to keep unchanged rows", got)
	}
	if got := reputationResyncMeta(t, store); got != "" {
		t.Fatalf("reputation resync meta = %q, want unset", got)
	}
}

func TestSyncRefetchesReputationAfterServerReenablesIt(t *testing.T) {
	t.Parallel()

	store := newReputationParityStore(t)
	ctx := context.Background()
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatalf("seed last sync: %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyReputationResync, "true"); err != nil {
		t.Fatalf("seed reputation resync: %v", err)
	}

	recorder := &scriptedSyncServer{}
	server := recorder.start(t,
		// Delta page: reputation is served again, but the unchanged leftover
		// row is older than since and is therefore not part of the delta.
		syncResponse{SyncedAt: "2026-11-01T10:00:00Z", SyncedXID: 700, FeedStatus: "healthy"},
		// Reputation-only refetch, first page.
		syncResponse{
			SyncedAt:   "2026-11-01T10:00:05Z",
			SyncedXID:  710,
			FeedStatus: "healthy",
			Reputation: []syncReputation{leftoverMaliciousReputation()},
			Truncated:  true,
			NextCursor: &syncCursor{VulnerabilitiesDone: true, MaliciousDone: true, LifecycleDone: true, ReputationCursor: "after-left-pad"},
		},
		// Reputation-only refetch, last page.
		syncResponse{SyncedAt: "2026-11-01T10:00:05Z", SyncedXID: 710, FeedStatus: "healthy"},
	)

	var stats SyncStats
	if err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true, Stats: &stats}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	requests := recorder.requests()
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want delta page plus two reputation refetch pages", len(requests))
	}
	if requests[0].Get("since") == "" {
		t.Fatalf("first request = %v, want incremental delta", requests[0])
	}
	for i, q := range requests[1:] {
		if q.Get("since") != "" || q.Get("since_xid") != "" {
			t.Fatalf("refetch request %d = %v, want no since window", i+1, q)
		}
		if q.Get("vulnerabilities_done") != "true" || q.Get("malicious_done") != "true" || q.Get("lifecycle_done") != "true" || q.Get("reputation_done") != "" {
			t.Fatalf("refetch request %d = %v, want reputation-only done markers", i+1, q)
		}
	}
	if requests[1].Get("snapshot") != "" || requests[1].Get("reputation_cursor") != "" {
		t.Fatalf("first refetch request = %v, want fresh snapshot from the first reputation row", requests[1])
	}
	if requests[2].Get("snapshot") != "2026-11-01T10:00:05Z" || requests[2].Get("snapshot_xid") != "710" || requests[2].Get("reputation_cursor") != "after-left-pad" {
		t.Fatalf("second refetch request = %v, want pinned snapshot and reputation keyset cursor", requests[2])
	}
	if got := countLocalReputation(t, store); got != 1 {
		t.Fatalf("local reputation rows after re-enable = %d, want refetched row", got)
	}
	if got := reputationResyncMeta(t, store); got != "" {
		t.Fatalf("reputation resync meta = %q, want cleared after complete refetch", got)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta(last sync) error = %v", err)
	}
	if lastSync != "2026-11-01T10:00:00Z" {
		t.Fatalf("last sync = %q, want the delta snapshot, not the reputation refetch snapshot", lastSync)
	}
}

func TestSyncKeepsReputationResyncPendingWhileServerStillDisabled(t *testing.T) {
	t.Parallel()

	store := newReputationParityStore(t)
	ctx := context.Background()
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatalf("seed last sync: %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyReputationResync, "true"); err != nil {
		t.Fatalf("seed reputation resync: %v", err)
	}

	recorder := &scriptedSyncServer{}
	server := recorder.start(t, syncResponse{
		SyncedAt:           "2026-11-01T10:00:00Z",
		FeedStatus:         "healthy",
		ReputationDisabled: true,
	})
	if err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := len(recorder.requests()); got != 1 {
		t.Fatalf("requests = %d, want no reputation refetch while disabled", got)
	}
	if got := reputationResyncMeta(t, store); got != "true" {
		t.Fatalf("reputation resync meta = %q, want still pending", got)
	}
}

func TestSyncFilteredReputationRefetchKeepsResyncPending(t *testing.T) {
	t.Parallel()

	store := newReputationParityStore(t)
	ctx := context.Background()
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-10-01T00:00:00Z"); err != nil {
		t.Fatalf("seed last sync: %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyReputationResync, "true"); err != nil {
		t.Fatalf("seed reputation resync: %v", err)
	}

	recorder := &scriptedSyncServer{}
	server := recorder.start(t,
		syncResponse{SyncedAt: "2026-11-01T10:00:00Z", FeedStatus: "healthy"},
		syncResponse{SyncedAt: "2026-11-01T10:00:05Z", FeedStatus: "healthy", Reputation: []syncReputation{leftoverMaliciousReputation()}},
	)
	if err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true, Ecosystems: []string{"npm"}}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	requests := recorder.requests()
	if len(requests) != 2 {
		t.Fatalf("requests = %d, want delta plus filtered reputation refetch", len(requests))
	}
	if requests[1].Get("ecosystem") != "npm" {
		t.Fatalf("refetch request = %v, want the same ecosystem filter", requests[1])
	}
	if got := countLocalReputation(t, store); got != 1 {
		t.Fatalf("local reputation rows = %d, want filtered refetch applied", got)
	}
	if got := reputationResyncMeta(t, store); got != "true" {
		t.Fatalf("reputation resync meta = %q, want pending until an unfiltered refetch completes", got)
	}
}

func TestFullSyncClearsReputationResyncWithoutExtraRefetch(t *testing.T) {
	t.Parallel()

	store := newReputationParityStore(t)
	ctx := context.Background()
	if err := store.SetSyncMeta(ctx, syncMetaKeyReputationResync, "true"); err != nil {
		t.Fatalf("seed reputation resync: %v", err)
	}

	recorder := &scriptedSyncServer{}
	server := recorder.start(t, syncResponse{
		SyncedAt:   "2026-11-01T10:00:00Z",
		FeedStatus: "healthy",
		Reputation: []syncReputation{leftoverMaliciousReputation()},
	})
	if err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true, Full: true}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := len(recorder.requests()); got != 1 {
		t.Fatalf("requests = %d, want the full sync alone to restore reputation", got)
	}
	if got := countLocalReputation(t, store); got != 1 {
		t.Fatalf("local reputation rows = %d, want 1", got)
	}
	if got := reputationResyncMeta(t, store); got != "" {
		t.Fatalf("reputation resync meta = %q, want cleared by the full sync", got)
	}
}

func TestFullSyncWhileReputationDisabledKeepsResyncPending(t *testing.T) {
	t.Parallel()

	store := newReputationParityStore(t)
	seedSyncedReputation(t, store)

	recorder := &scriptedSyncServer{}
	server := recorder.start(t, syncResponse{
		SyncedAt:           "2026-11-01T10:00:00Z",
		FeedStatus:         "healthy",
		ReputationDisabled: true,
	})
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true, Full: true}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got := countLocalReputation(t, store); got != 0 {
		t.Fatalf("local reputation rows = %d, want 0", got)
	}
	if got := reputationResyncMeta(t, store); got != "true" {
		t.Fatalf("reputation resync meta = %q, want pending", got)
	}
}
