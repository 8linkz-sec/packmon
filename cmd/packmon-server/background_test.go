package main

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/feed"
)

func TestFeedPhaseForNameSeparatesEnrichmentFeeds(t *testing.T) {
	t.Parallel()

	tests := map[string]feed.FeedPhase{
		"osv":       feed.FeedPhaseVulnerability,
		"ghsa":      feed.FeedPhaseVulnerability,
		"openssf":   feed.FeedPhaseVulnerability,
		"malicious": feed.FeedPhaseVulnerability,
		"vulncheck": feed.FeedPhaseEnrichment,
		"cisakev":   feed.FeedPhaseEnrichment,
		"epss":      feed.FeedPhaseEnrichment,
		"nvd":       feed.FeedPhaseEnrichment,
	}
	for name, want := range tests {
		if got := feedPhaseForName(name); got != want {
			t.Fatalf("feedPhaseForName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNewFeedSyncerRecognizesKnownFeeds(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Feeds: config.FeedsConfig{DataDir: t.TempDir()}}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := newNoopStore()

	for _, name := range []string{"osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "nvd"} {
		if syncer := newFeedSyncer(name, cfg, store, logger); syncer == nil {
			t.Fatalf("newFeedSyncer(%q) = nil", name)
		}
	}
	if syncer := newFeedSyncer("unknown", cfg, store, logger); syncer != nil {
		t.Fatalf("newFeedSyncer(unknown) = %T, want nil", syncer)
	}
}

func TestNewQueueProcessorHonorsFeedEnablementAndMode(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := newNoopStore()

	disabled := &config.Config{Feeds: config.FeedsConfig{
		SocketMode:        config.FeedModeSelf,
		ReversingLabsMode: config.FeedModeSelf,
	}}
	if processor := newQueueProcessor(disabled, store, logger); processor != nil {
		t.Fatalf("newQueueProcessor(disabled) = %T, want nil", processor)
	}

	external := &config.Config{Feeds: config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeExternal,
	}}
	if processor := newQueueProcessor(external, store, logger); processor != nil {
		t.Fatalf("newQueueProcessor(external socket) = %T, want nil", processor)
	}

	enabled := &config.Config{Feeds: config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-secret",
	}}
	if processor := newQueueProcessor(enabled, store, logger); processor == nil {
		t.Fatal("newQueueProcessor(enabled socket) = nil, want processor")
	}
}

func TestStartBackgroundServicesSkipsWorkersInDevelopment(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	services := startBackgroundServices(context.Background(), cfg, cfg.Feeds, newNoopStore(), logger)
	if services == nil {
		t.Fatal("startBackgroundServices returned nil")
	}
	if services.manager != nil || services.queueCancel != nil || services.queueDone != nil {
		t.Fatalf("development services unexpectedly started workers: %+v", services)
	}
	services.Wait()
}

func TestApplyAndResetFeedConfigMutateRuntimeConfig(t *testing.T) {
	t.Parallel()

	defaultFeeds := config.FeedsConfig{
		OSVEnabled: true,
		OSVMode:    config.FeedModeSelf,
	}
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeDevelopment},
		Feeds:  defaultFeeds,
	}
	services := &backgroundServices{cfg: cfg, defaultFeeds: defaultFeeds}

	if err := services.ApplyFeedConfig(context.Background(), config.FeedSettings{
		Name:                 "osv",
		Enabled:              false,
		Mode:                 config.FeedModeExternal,
		SyncInterval:         5 * time.Minute,
		SupportsSyncInterval: true,
	}); err != nil {
		t.Fatalf("ApplyFeedConfig: %v", err)
	}
	settings, _ := cfg.FeedSettings("osv")
	if settings.Enabled || settings.Mode != config.FeedModeExternal || settings.SyncInterval != 5*time.Minute {
		t.Fatalf("settings after apply = %+v", settings)
	}

	if err := services.ResetFeedConfig(context.Background(), "osv"); err != nil {
		t.Fatalf("ResetFeedConfig: %v", err)
	}
	settings, _ = cfg.FeedSettings("osv")
	if !settings.Enabled || settings.Mode != config.FeedModeSelf || settings.SyncInterval != 0 {
		t.Fatalf("settings after reset = %+v", settings)
	}
}

func TestBackgroundServicesApplyProductionConfigRestartsQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defaultFeeds := config.FeedsConfig{
		OSVEnabled:        true,
		OSVMode:           config.FeedModeSelf,
		OSVInterval:       time.Hour,
		SocketMode:        config.FeedModeExternal,
		ReversingLabsMode: config.FeedModeSelf,
		DataDir:           t.TempDir(),
	}
	cfg := &config.Config{
		Server:   config.ServerConfig{Mode: config.ModeProduction},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
		Feeds:    defaultFeeds,
	}
	services := startBackgroundServices(ctx, cfg, defaultFeeds, newNoopStore(), slog.Default())
	if services.manager == nil {
		t.Fatal("manager = nil, want production manager")
	}

	if err := services.ApplyFeedConfig(ctx, config.FeedSettings{
		Name:                 "osv",
		Enabled:              true,
		Mode:                 config.FeedModeSelf,
		SyncInterval:         30 * time.Minute,
		SupportsSyncInterval: true,
	}); err != nil {
		t.Fatalf("ApplyFeedConfig(osv) error = %v", err)
	}
	if err := services.ApplyFeedConfig(ctx, config.FeedSettings{
		Name:    "socket",
		Enabled: true,
		Mode:    config.FeedModeSelf,
	}); err != nil {
		t.Fatalf("ApplyFeedConfig(socket) error = %v", err)
	}
	if services.queueDone == nil {
		t.Fatal("queueDone = nil, want queue processor after socket self config")
	}
	if err := services.ResetFeedConfig(ctx, "unknown"); err != nil {
		t.Fatalf("ResetFeedConfig(unknown) error = %v", err)
	}

	cancel()
	services.Wait()
}
