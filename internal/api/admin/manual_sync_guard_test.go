package admin

import (
	"errors"
	"sync"
	"testing"
)

// TestBeginManualFeedSyncAfterAuditAdmitsOnlyOneSyncPerFeed covers the guard
// behind the admin "sync now" button. Two concurrent manual syncs of the same
// feed would double the load on an upstream that is often rate-limited, and the
// second run's status write would race the first.
func TestBeginManualFeedSyncAfterAuditAdmitsOnlyOneSyncPerFeed(t *testing.T) {
	t.Parallel()

	handler := &AdminHandler{}

	started, err := handler.beginManualFeedSyncAfterAudit("osv", nil)
	if err != nil || !started {
		t.Fatalf("first sync = %v, %v; want it started", started, err)
	}

	started, err = handler.beginManualFeedSyncAfterAudit("osv", nil)
	if err != nil {
		t.Fatalf("second sync error = %v, want none", err)
	}
	if started {
		t.Fatal("a second manual sync of the same feed was admitted")
	}

	// A different feed is unaffected.
	if started, err := handler.beginManualFeedSyncAfterAudit("ghsa", nil); err != nil || !started {
		t.Fatalf("second feed = %v, %v; want it started", started, err)
	}

	// After the run finishes the feed can be synced again.
	handler.endManualFeedSync("osv")
	if started, err := handler.beginManualFeedSyncAfterAudit("osv", nil); err != nil || !started {
		t.Fatalf("sync after release = %v, %v; want it started", started, err)
	}
}

// TestBeginManualFeedSyncNormalisesTheFeedName keeps two spellings of one feed
// from each starting their own sync.
func TestBeginManualFeedSyncNormalisesTheFeedName(t *testing.T) {
	t.Parallel()

	handler := &AdminHandler{}
	if !handler.beginManualFeedSync("osv") {
		t.Fatal("the first sync was not admitted")
	}
	if handler.beginManualFeedSync("  OSV  ") {
		t.Fatal("a differently spelled name started a second sync of the same feed")
	}

	handler.endManualFeedSync("  OSV  ")
	if !handler.beginManualFeedSync("osv") {
		t.Fatal("releasing under a different spelling did not free the feed")
	}
}

// TestBeginManualFeedSyncAfterAuditDoesNotClaimTheFeedOnAuditFailure is the
// important ordering property. The audit entry is written before the feed is
// claimed, so a failed audit must leave the feed free -- otherwise a sync that
// never ran would block every later attempt until the process restarts.
func TestBeginManualFeedSyncAfterAuditDoesNotClaimTheFeedOnAuditFailure(t *testing.T) {
	t.Parallel()

	handler := &AdminHandler{}
	auditErr := errors.New("audit log write failed")

	started, err := handler.beginManualFeedSyncAfterAudit("osv", func() error { return auditErr })
	if !errors.Is(err, auditErr) {
		t.Fatalf("error = %v, want the audit failure", err)
	}
	if started {
		t.Fatal("the sync started although its audit entry failed")
	}

	// The feed must still be claimable.
	if started, err := handler.beginManualFeedSyncAfterAudit("osv", nil); err != nil || !started {
		t.Fatalf("after a failed audit = %v, %v; want the feed still free", started, err)
	}
}

// TestBeginManualFeedSyncAfterAuditRunsTheAuditBeforeClaiming pins the order
// itself: the audit callback must observe the feed as not yet claimed, which is
// what lets a failed audit abort cleanly.
func TestBeginManualFeedSyncAfterAuditRunsTheAuditBeforeClaiming(t *testing.T) {
	t.Parallel()

	handler := &AdminHandler{}
	var claimedDuringAudit bool

	started, err := handler.beginManualFeedSyncAfterAudit("osv", func() error {
		handler.manualSyncMu.Lock()
		_, claimedDuringAudit = handler.manualSyncs["osv"]
		handler.manualSyncMu.Unlock()
		return nil
	})
	if err != nil || !started {
		t.Fatalf("sync = %v, %v; want it started", started, err)
	}
	if claimedDuringAudit {
		t.Fatal("the feed was already claimed while its audit entry was being written")
	}
}

// TestBeginManualFeedSyncAfterAuditIsRaceFree drives the guard concurrently.
// Exactly one caller may win, because the audit window between the two checks is
// where a naive implementation would let a second sync slip through.
func TestBeginManualFeedSyncAfterAuditIsRaceFree(t *testing.T) {
	t.Parallel()

	handler := &AdminHandler{}
	const goroutines = 16

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(goroutines)

	results := make([]bool, goroutines)
	for i := range goroutines {
		go func() {
			defer done.Done()
			start.Wait()
			started, err := handler.beginManualFeedSyncAfterAudit("osv", func() error { return nil })
			if err == nil {
				results[i] = started
			}
		}()
	}
	start.Done()
	done.Wait()

	admitted := 0
	for _, started := range results {
		if started {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("%d of %d concurrent callers were admitted, want exactly 1", admitted, goroutines)
	}
}

// TestManualFeedSyncHelpersToleratePartialState covers the nil paths. The
// helpers run from request handlers and from a deferred release in a background
// goroutine, so neither may panic on a half-built handler.
func TestManualFeedSyncHelpersToleratePartialState(t *testing.T) {
	t.Parallel()

	var nilHandler *AdminHandler
	if started, err := nilHandler.beginManualFeedSyncAfterAudit("osv", nil); started || err != nil {
		t.Errorf("nil handler = %v, %v; want false, nil", started, err)
	}
	nilHandler.endManualFeedSync("osv")

	// Releasing a feed that was never claimed is a no-op, not a panic.
	handler := &AdminHandler{}
	handler.endManualFeedSync("never-started")
}
