package telemetry

import (
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// Prometheus label values become time-series identities. An empty or nonsensical
// label therefore does not just look untidy -- it creates a series that never
// resolves and, when it comes from user-supplied data, lets the cardinality grow
// without bound. These tests cover the guards that keep such labels out.

// TestOldestQueueJobsIgnoresUnusableJobs covers the queue-age gauge. Only
// pending and processing jobs have a meaningful age; a completed job would keep
// reporting a growing age forever, and a job without a source has no label to
// report under.
func TestOldestQueueJobsIgnoresUnusableJobs(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	oldest, sources := oldestQueueJobs([]db.RefreshJob{
		{Source: "", Status: "pending", RequestedAt: base},
		{Source: "scan", Status: "done", RequestedAt: base.Add(-time.Hour)},
		{Source: "scan", Status: "error", RequestedAt: base.Add(-2 * time.Hour)},
		{Source: "scan", Status: "pending", RequestedAt: base},
		{Source: "scan", Status: "processing", RequestedAt: base.Add(-30 * time.Minute)},
		{Source: "admin", Status: "pending", RequestedAt: base.Add(-10 * time.Minute)},
	})

	if len(sources) != 2 {
		t.Fatalf("sources = %v, want only scan and admin", sources)
	}
	if sources[0] != "admin" || sources[1] != "scan" {
		t.Fatalf("sources = %v, want them sorted", sources)
	}
	// The oldest *active* job wins, and the older completed ones are ignored.
	if got := oldest["scan"]; !got.Equal(base.Add(-30 * time.Minute)) {
		t.Fatalf("oldest scan job = %v, want the oldest active one", got)
	}
	if _, ok := oldest[""]; ok {
		t.Error("a job without a source produced a metric label")
	}
}

// TestOldestQueueJobsHandlesAnEmptyQueue keeps the metric writer from ranging
// over a nil map on a freshly started server.
func TestOldestQueueJobsHandlesAnEmptyQueue(t *testing.T) {
	t.Parallel()

	oldest, sources := oldestQueueJobs(nil)
	if oldest == nil {
		t.Error("oldestQueueJobs(nil) returned a nil map")
	}
	if len(sources) != 0 {
		t.Errorf("sources = %v, want none", sources)
	}
}

// TestQueueJobsFromOldestSkipsIncompleteEntries covers the reverse mapping used
// when rebuilding jobs from the recorded gauge. An entry missing either half
// cannot produce a usable job.
func TestQueueJobsFromOldestSkipsIncompleteEntries(t *testing.T) {
	t.Parallel()

	requestedAt := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	jobs := queueJobsFromOldest(map[string]time.Time{
		"scan": requestedAt,
		"":     requestedAt,
		"zero": {},
	})

	if len(jobs) != 1 {
		t.Fatalf("jobs = %+v, want only the complete entry", jobs)
	}
	if jobs[0].Source != "scan" || !jobs[0].RequestedAt.Equal(requestedAt) {
		t.Fatalf("job = %+v, want the scan entry", jobs[0])
	}
}

// TestSortedQueueJobCompletedKeysDropsIncompleteLabels covers the completion
// counter, whose series is keyed by both source and result. A key missing either
// would emit a metric with an empty label.
func TestSortedQueueJobCompletedKeysDropsIncompleteLabels(t *testing.T) {
	t.Parallel()

	keys := sortedQueueJobCompletedKeys(map[QueueJobCompletedKey]uint64{
		{Source: "scan", Result: QueueJobResultSuccess}:  3,
		{Source: "scan", Result: QueueJobResultError}:    1,
		{Source: "admin", Result: QueueJobResultSuccess}: 2,
		{Source: "", Result: QueueJobResultSuccess}:      9,
		{Source: "scan", Result: ""}:                     9,
	})

	if len(keys) != 3 {
		t.Fatalf("keys = %+v, want the three complete ones", keys)
	}
	for _, key := range keys {
		if key.Source == "" || key.Result == "" {
			t.Errorf("key %+v has an empty label", key)
		}
	}
	// The order has to be deterministic, or the metrics output churns between
	// scrapes and diffs become useless.
	if keys[0].Source != "admin" {
		t.Errorf("keys = %+v, want them sorted by source first", keys)
	}
	if keys[1].Result != QueueJobResultError || keys[2].Result != QueueJobResultSuccess {
		t.Errorf("keys = %+v, want them sorted by result within a source", keys)
	}
}

// TestSortedQueueJobCompletedKeysIsStable pins the determinism directly, since
// Go map iteration order is randomised and a wrong comparator would only show up
// intermittently.
func TestSortedQueueJobCompletedKeysIsStable(t *testing.T) {
	t.Parallel()

	metrics := map[QueueJobCompletedKey]uint64{
		{Source: "scan", Result: QueueJobResultSuccess}:  1,
		{Source: "scan", Result: QueueJobResultError}:    1,
		{Source: "admin", Result: QueueJobResultSuccess}: 1,
		{Source: "admin", Result: QueueJobResultError}:   1,
		{Source: "feed", Result: QueueJobResultSuccess}:  1,
	}

	first := sortedQueueJobCompletedKeys(metrics)
	for range 20 {
		next := sortedQueueJobCompletedKeys(metrics)
		if len(next) != len(first) {
			t.Fatalf("key count changed between calls: %d vs %d", len(next), len(first))
		}
		for i := range first {
			if next[i] != first[i] {
				t.Fatalf("key order changed at %d: %+v vs %+v", i, next[i], first[i])
			}
		}
	}
}

// TestSnapshotCountersRecordAndReadBack covers the recorder methods behind the
// metrics endpoint. Each counter drives an operational alert, so a value that
// never advances would silently disable it.
func TestSnapshotCountersRecordAndReadBack(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()

	registry.AddQueueStuckRecovered(3)
	registry.AddQueueStuckRecovered(2)
	registry.IncFeedSyncTimeout("osv")
	registry.IncFeedSyncTimeout("osv")
	registry.IncFeedSyncTimeout("ghsa")
	registry.IncQueueError("scan")
	registry.IncQueueJobCompleted("scan", QueueJobResultSuccess)
	registry.IncQueueJobCompleted("scan", "  SUCCESS  ")
	registry.IncQueueJobCompleted("scan", QueueJobResultError)
	// Anything outside the fixed vocabulary is dropped: the result label is what
	// bounds this metric's cardinality.
	registry.IncQueueJobCompleted("scan", "done")
	registry.IncQueueJobCompleted("scan", "")
	registry.IncQueueJobCompleted("", QueueJobResultSuccess)

	snapshot := registry.Snapshot()
	if snapshot.QueueStuckRecovered != 5 {
		t.Errorf("QueueStuckRecovered = %d, want the additions summed", snapshot.QueueStuckRecovered)
	}
	if snapshot.FeedSyncTimeouts["osv"] != 2 || snapshot.FeedSyncTimeouts["ghsa"] != 1 {
		t.Errorf("FeedSyncTimeouts = %v, want per-feed counts", snapshot.FeedSyncTimeouts)
	}
	if snapshot.QueueErrors["scan"] != 1 {
		t.Errorf("QueueErrors = %v, want the scan source counted", snapshot.QueueErrors)
	}
	if got := snapshot.QueueJobsCompleted[QueueJobCompletedKey{Source: "scan", Result: QueueJobResultSuccess}]; got != 2 {
		t.Errorf("completed success = %d, want 2 (the padded spelling normalises)", got)
	}
	if got := snapshot.QueueJobsCompleted[QueueJobCompletedKey{Source: "scan", Result: QueueJobResultError}]; got != 1 {
		t.Errorf("completed error = %d, want 1", got)
	}
	if len(snapshot.QueueJobsCompleted) != 2 {
		t.Errorf("QueueJobsCompleted = %v, want only the two valid label pairs", snapshot.QueueJobsCompleted)
	}
}
