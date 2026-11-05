package feed

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestManagerRegistrationGuardAndLockBranches(t *testing.T) {
	t.Parallel()

	manager := NewManager(&managerStoreStub{}, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour)
	manager.feedLocks = nil
	first := manager.feedLockForNameLocked("osv")
	if first == nil || manager.feedLockForNameLocked("osv") != first {
		t.Fatal("feedLockForNameLocked did not initialize and reuse the lock")
	}

	rf := &registeredFeed{config: FeedConfig{Syncer: &successSyncerStub{name: "osv"}, Enabled: true, Mode: FeedModeSelf}}
	manager.startFeedLocked(rf, time.Hour, nil, feedStartOptions{})
	if rf.cancel != nil {
		t.Fatal("startFeedLocked without manager context started a loop")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager.ctx = ctx
	manager.startFeedLocked(rf, time.Hour, nil, feedStartOptions{})
	if rf.cancel != nil {
		t.Fatal("startFeedLocked with canceled context started a loop")
	}

	manager.ctx = nil
	manager.startFeedAfterPreviousStopsLocked("osv", make(chan struct{}), rf, time.Hour, feedStartOptions{})
	manager.ctx = ctx
	manager.startFeedAfterPreviousStopsLocked("osv", make(chan struct{}), rf, time.Hour, feedStartOptions{})
	manager.Wait()
}

func TestAcquireSyncLockImmediateWaitAndTryBranches(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	locked, err := acquireSyncLock(context.Background(), &mu, true)
	if err != nil || !locked {
		t.Fatalf("acquireSyncLock(wait immediate) = %v, %v", locked, err)
	}
	mu.Unlock()
	mu.Lock()
	locked, err = acquireSyncLock(context.Background(), &mu, false)
	if err != nil || locked {
		t.Fatalf("acquireSyncLock(try held) = %v, %v", locked, err)
	}
	mu.Unlock()
}

func TestManagerStatusHelperEarlyAndFailureBranches(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &managerStoreStub{getErr: errors.New("read failed")}
	manager := NewManager(store, logger, time.Hour)
	if err := manager.recordStatus(context.Background(), "osv", db.FeedSyncStatusError, "failed", 0, nil); err == nil {
		t.Fatal("recordStatus(read error) error = nil")
	}

	if err := manager.recordStatusForFeed(context.Background(), nil, db.FeedSyncStatusError, "", 0, nil); err != nil {
		t.Fatalf("recordStatusForFeed(nil) error = %v", err)
	}
	if err := manager.recordRunningStatusForFeed(context.Background(), nil); err != nil {
		t.Fatalf("recordRunningStatusForFeed(nil) error = %v", err)
	}

	store.getErr = nil
	current := &registeredFeed{config: FeedConfig{Syncer: &successSyncerStub{name: "osv"}}}
	stale := &registeredFeed{config: FeedConfig{Syncer: &successSyncerStub{name: "osv"}}}
	manager.feeds["osv"] = current
	if err := manager.recordStatusForFeed(context.Background(), stale, db.FeedSyncStatusError, "", 0, nil); err != nil {
		t.Fatalf("recordStatusForFeed(stale) error = %v", err)
	}
	if err := manager.recordRunningStatusForFeed(context.Background(), stale); err != nil {
		t.Fatalf("recordRunningStatusForFeed(stale) error = %v", err)
	}
	if !manager.isCurrentRegisteredFeed(nil) {
		t.Fatal("isCurrentRegisteredFeed(nil) = false")
	}
	unknown := &registeredFeed{config: FeedConfig{Syncer: &successSyncerStub{name: "unknown"}}}
	if !manager.isCurrentRegisteredFeed(unknown) {
		t.Fatal("isCurrentRegisteredFeed(unregistered) = false")
	}
}

func TestManagerPendingAndInterruptedRecoveryBranches(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &managerStoreStub{getErr: errors.New("read failed")}
	manager := NewManager(store, logger, time.Hour)
	manager.recordPendingStatusIfMissing(context.Background(), "osv")
	manager.recoverInterruptedRunningStatus("osv")
	if len(store.statuses) != 0 {
		t.Fatalf("statuses after read errors = %+v", store.statuses)
	}

	store.getErr = nil
	store.status = &db.FeedSyncStatus{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusSuccess}
	manager.recordPendingStatusIfMissing(context.Background(), "osv")
	manager.recoverInterruptedRunningStatus("osv")
	if len(store.statuses) != 0 {
		t.Fatalf("statuses after existing success = %+v", store.statuses)
	}

	future := time.Now().UTC().Add(time.Hour)
	store.status = &db.FeedSyncStatus{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusRunning, UpdatedAt: future}
	manager.recoverInterruptedRunningStatus("osv")
	if store.status == nil || store.status.LastSyncDuration == nil || *store.status.LastSyncDuration != 0 {
		t.Fatalf("future interrupted status = %+v", store.status)
	}

	failingStore := &managerStoreStub{
		status:    &db.FeedSyncStatus{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusRunning},
		upsertErr: errors.New("write failed"),
	}
	NewManager(failingStore, logger, time.Hour).recoverInterruptedRunningStatus("osv")
}

func TestManagerPhaseReleasePreviousCancellationAndStatusFallbacks(t *testing.T) {
	t.Parallel()

	logHandler, logSink := newManagerLogHandler()
	logger := slog.New(logHandler)
	ctx, cancel := context.WithCancel(context.Background())
	manager := NewManager(&managerStoreStub{}, logger, time.Hour)
	manager.ctx = ctx
	manager.phase1Done = make(chan struct{})
	rf := &registeredFeed{config: FeedConfig{Syncer: &successSyncerStub{name: "epss"}, Enabled: true, Mode: FeedModeSelf}}
	manager.feeds["epss"] = rf
	manager.startFeedLocked(rf, time.Hour, nil, feedStartOptions{waitForPhase1: true, syncOnStartup: false})
	close(manager.phase1Done)
	deadline := time.After(time.Second)
	for logSink.count("phase 1 complete, starting enrichment feed", "epss") == 0 || logSink.count("starting feed sync loop", "epss") == 0 {
		select {
		case <-logSink.ch:
		case <-deadline:
			t.Fatal("enrichment feed did not enter its loop after phase 1 completed")
		}
	}
	cancel()
	manager.Wait()

	ctx, cancel = context.WithCancel(context.Background())
	manager = NewManager(&managerStoreStub{}, logger, time.Hour)
	manager.ctx = ctx
	rf = &registeredFeed{config: FeedConfig{Syncer: &successSyncerStub{name: "osv"}, Enabled: true, Mode: FeedModeSelf}}
	manager.feeds["osv"] = rf
	manager.startFeedAfterPreviousStopsLocked("osv", make(chan struct{}), rf, time.Hour, feedStartOptions{})
	cancel()
	manager.Wait()

	store := &managerStoreStub{getErr: errors.New("read failed")}
	manager = NewManager(store, logger, time.Hour)
	if err := manager.recordRunningStatus(context.Background(), "osv"); err == nil {
		t.Fatal("recordRunningStatus(read error) error = nil")
	}

	lastSync := time.Now().UTC().Add(-time.Hour)
	store.getErr = nil
	store.status = &db.FeedSyncStatus{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusRunning, LastSyncAt: &lastSync}
	manager.recoverInterruptedRunningStatus("osv")
	if store.status.LastSyncDuration == nil {
		t.Fatalf("recovered status = %+v, want duration from LastSyncAt", store.status)
	}

	manager.feedStatusReadTimeout = 0
	store.status = nil
	if manager.lastSyncFresh(context.Background(), "osv", time.Hour) {
		t.Fatal("lastSyncFresh(missing with default timeout) = true")
	}
}
