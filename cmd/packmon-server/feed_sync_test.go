package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

type triggerSyncer struct {
	name string
}

func (s triggerSyncer) Name() string { return s.name }

func (s triggerSyncer) Sync(context.Context, db.Store) (*feed.SyncResult, error) {
	return &feed.SyncResult{EntriesSynced: 1, EntriesTotal: 1}, nil
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
