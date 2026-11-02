package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

type triggerSyncer struct {
	name  string
	calls atomic.Int32
}

func (s *triggerSyncer) Name() string { return s.name }

func (s *triggerSyncer) Sync(context.Context, db.Store) (*feed.SyncResult, error) {
	s.calls.Add(1)
	// Windows' wall-clock resolution can otherwise make this successful sync
	// appear to take exactly zero time, which intentionally omits the duration.
	time.Sleep(time.Millisecond)
	return &feed.SyncResult{EntriesSynced: 1, EntriesTotal: 1}, nil
}

type blockingTriggerSyncer struct {
	name    string
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (s *blockingTriggerSyncer) Name() string { return s.name }

func (s *blockingTriggerSyncer) Sync(ctx context.Context, _ db.Store) (*feed.SyncResult, error) {
	if s.calls.Add(1) > 1 {
		return &feed.SyncResult{}, nil
	}
	close(s.started)
	select {
	case <-s.release:
		return &feed.SyncResult{EntriesSynced: 1, EntriesTotal: 1}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestNewFeedSyncTriggerUsesBackgroundManagerWhenAvailable(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := newNoopStore()
	manager := feed.NewManager(store, logger, time.Hour)
	syncer := &triggerSyncer{name: "test-feed"}
	if err := manager.Register(feed.FeedConfig{
		Syncer:  syncer,
		Mode:    feed.FeedModeSelf,
		Enabled: true,
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	trigger := newFeedSyncTrigger(&config.Config{}, store, logger, &backgroundServices{manager: manager})
	if err := trigger(context.Background(), "test-feed"); err != nil {
		t.Fatalf("trigger background manager error = %v", err)
	}
	if calls := syncer.calls.Load(); calls != 1 {
		t.Fatalf("syncer calls = %d, want 1", calls)
	}

	status, err := store.GetFeedSyncStatus(context.Background(), "test-feed")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil {
		t.Fatal("GetFeedSyncStatus() = nil, want successful callback status")
	}
	if status.FeedName != "test-feed" || status.LastSyncStatus != db.FeedSyncStatusSuccess || status.LastError != "" {
		t.Fatalf("feed status identity/result = %+v, want test-feed success without error", status)
	}
	if status.EntriesSynced != 1 || status.EntriesTotal != 1 {
		t.Fatalf("feed status entries = %d/%d, want 1/1", status.EntriesSynced, status.EntriesTotal)
	}
	if status.LastSyncAt == nil || status.UpdatedAt.IsZero() || !status.LastSyncAt.Equal(status.UpdatedAt) {
		t.Fatalf("feed status timestamps = last_sync_at %v, updated_at %v; want equal non-zero values", status.LastSyncAt, status.UpdatedAt)
	}
	if status.LastSyncDuration == nil || *status.LastSyncDuration <= 0 {
		t.Fatalf("feed status duration = %v, want a positive recorded duration", status.LastSyncDuration)
	}
}

func TestBackgroundWaitTracksManualFeedSync(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := newNoopStore()
	manager := feed.NewManager(store, logger, time.Hour)
	syncer := &blockingTriggerSyncer{
		name:    "test-feed",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	if err := manager.Register(feed.FeedConfig{
		Syncer:  syncer,
		Mode:    feed.FeedModeSelf,
		Enabled: true,
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	background := &backgroundServices{
		manager:      manager,
		logger:       logger,
		shutdownWait: time.Second,
	}
	trigger := newFeedSyncTrigger(&config.Config{}, store, logger, background)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- trigger(ctx, "test-feed")
	}()
	select {
	case <-syncer.started:
	case <-time.After(time.Second):
		t.Fatal("manual sync did not start")
	}

	waitDone := make(chan bool, 1)
	go func() {
		waitDone <- background.Wait()
	}()
	select {
	case result := <-waitDone:
		t.Fatalf("Wait returned %t while manual sync was still running", result)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case result := <-waitDone:
		if !result {
			t.Fatal("Wait() = false after the manual sync observed cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("Wait did not observe manual sync completion")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("manual sync error = %v, want context.Canceled", err)
	}
	if err := trigger(context.Background(), "test-feed"); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-Wait trigger error = %v, want context.Canceled", err)
	}
	if calls := syncer.calls.Load(); calls != 1 {
		t.Fatalf("syncer calls after rejected post-Wait trigger = %d, want 1", calls)
	}
}

func TestNewFeedSyncTriggerBuildsManagerWhenBackgroundUnavailable(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
		Feeds:    config.FeedsConfig{DataDir: t.TempDir()},
	}
	trigger := newFeedSyncTrigger(cfg, newNoopStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	err := trigger(context.Background(), "not-registered")
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("trigger unknown feed error = %v, want not registered", err)
	}
}
