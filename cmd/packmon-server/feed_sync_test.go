package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

type triggerSyncer struct {
	name string
}

func (s triggerSyncer) Name() string { return s.name }

func (s triggerSyncer) Sync(context.Context, db.Store) (*feed.SyncResult, error) {
	return &feed.SyncResult{EntriesSynced: 1, EntriesTotal: 1}, nil
}

type blockingTriggerSyncer struct {
	name    string
	started chan struct{}
	release chan struct{}
}

func (s *blockingTriggerSyncer) Name() string { return s.name }

func (s *blockingTriggerSyncer) Sync(ctx context.Context, _ db.Store) (*feed.SyncResult, error) {
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
	manager.Register(feed.FeedConfig{
		Syncer:  triggerSyncer{name: "test-feed"},
		Mode:    feed.FeedModeSelf,
		Enabled: true,
	})

	trigger := newFeedSyncTrigger(&config.Config{}, store, logger, &backgroundServices{manager: manager})
	if err := trigger(context.Background(), "test-feed"); err != nil {
		t.Fatalf("trigger background manager error = %v", err)
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
	manager.Register(feed.FeedConfig{
		Syncer:  syncer,
		Mode:    feed.FeedModeSelf,
		Enabled: true,
	})
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

	waitDone := make(chan struct{})
	go func() {
		background.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("Wait returned while manual sync was still running")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("Wait did not observe manual sync completion")
	}
	if err := <-done; err == nil {
		t.Fatal("manual sync error = nil, want cancellation")
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
