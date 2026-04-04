package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
)

func TestApplyStoredFeedConfigOverrides(t *testing.T) {
	store := newNoopStore()
	interval := 90 * time.Minute
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName:     "ghsa",
		Enabled:      false,
		Mode:         "external",
		SyncInterval: &interval,
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(ghsa) error = %v", err)
	}
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName: "socket",
		Enabled:  true,
		Mode:     "self",
		APIKey:   "socket-live-key",
	}); err != nil {
		t.Fatalf("UpsertFeedConfig(socket) error = %v", err)
	}

	cfg := testAdminConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, logger); err != nil {
		t.Fatalf("applyStoredFeedConfigOverrides() error = %v", err)
	}

	ghsa, ok := cfg.FeedSettings("ghsa")
	if !ok {
		t.Fatal("cfg.FeedSettings(ghsa) = !ok")
	}
	if ghsa.Enabled {
		t.Fatal("ghsa.Enabled = true, want false")
	}
	if ghsa.Mode != config.FeedModeExternal {
		t.Fatalf("ghsa.Mode = %q, want external", ghsa.Mode)
	}
	if ghsa.SyncInterval != interval {
		t.Fatalf("ghsa.SyncInterval = %s, want %s", ghsa.SyncInterval, interval)
	}

	socket, ok := cfg.FeedSettings("socket")
	if !ok {
		t.Fatal("cfg.FeedSettings(socket) = !ok")
	}
	if !socket.Enabled {
		t.Fatal("socket.Enabled = false, want true")
	}
	if socket.APIKey != "socket-live-key" {
		t.Fatalf("socket.APIKey = %q, want socket-live-key", socket.APIKey)
	}
}
