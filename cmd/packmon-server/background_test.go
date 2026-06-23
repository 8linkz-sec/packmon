package main

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
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
		"endoflife": feed.FeedPhaseEnrichment,
	}
	for name, want := range tests {
		if got := feedPhaseForName(name); got != want {
			t.Fatalf("feedPhaseForName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNewFeedManagerHonorsSyncOnStartupConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		FeedSync: config.FeedSyncConfig{
			Interval:  time.Hour,
			OnStartup: false,
		},
		Feeds: config.FeedsConfig{
			DataDir: t.TempDir(),
		},
	}
	manager := newFeedManager(cfg, newNoopStore(), slog.New(slog.NewTextHandler(os.Stdout, nil)))
	if manager.SyncOnStartup() {
		t.Fatal("manager SyncOnStartup = true, want false from config")
	}
}

func TestNewFeedSyncerRecognizesKnownFeeds(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Feeds: config.FeedsConfig{DataDir: t.TempDir()}}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := newNoopStore()

	for _, name := range []string{"osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "nvd", "endoflife"} {
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

func TestNewQueueProcessorRecordsMissingKeyStatus(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := newNoopStore()
	cfg := &config.Config{Feeds: config.FeedsConfig{
		SocketEnabled:        true,
		SocketMode:           config.FeedModeSelf,
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
	}}

	if processor := newQueueProcessor(cfg, store, logger); processor != nil {
		t.Fatalf("newQueueProcessor(missing keys) = %T, want nil", processor)
	}
	socketStatus, err := store.GetFeedSyncStatus(context.Background(), "socket")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(socket) error = %v", err)
	}
	if socketStatus == nil || socketStatus.LastSyncStatus != "skipped" || socketStatus.LastError != "Socket.dev API key not configured" {
		t.Fatalf("socket status = %+v, want skipped missing-key row", socketStatus)
	}
	rlStatus, err := store.GetFeedSyncStatus(context.Background(), "reversinglabs")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(reversinglabs) error = %v", err)
	}
	if rlStatus == nil || rlStatus.LastSyncStatus != "skipped" || rlStatus.LastError != "ReversingLabs API key not configured" {
		t.Fatalf("reversinglabs status = %+v, want skipped missing-key row", rlStatus)
	}
}

func TestRecordQueueWorkerSkippedPreservesExistingFeedData(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := newNoopStore()
	lastSuccessfulSync := time.Now().UTC().Add(-6 * time.Hour)
	if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{
		FeedName:       "socket",
		LastSyncAt:     &lastSuccessfulSync,
		LastSyncStatus: "success",
		EntriesSynced:  11,
		EntriesTotal:   13,
		LastEtag:       "etag-old",
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}

	recordQueueWorkerSkipped(store, logger, "socket", "Socket.dev API key not configured")

	status, err := store.GetFeedSyncStatus(context.Background(), "socket")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(socket) error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "skipped" {
		t.Fatalf("socket status = %+v, want skipped", status)
	}
	if status.LastSyncAt == nil || !status.LastSyncAt.Equal(lastSuccessfulSync) {
		t.Fatalf("LastSyncAt = %v, want preserved %v", status.LastSyncAt, lastSuccessfulSync)
	}
	if status.EntriesSynced != 11 || status.EntriesTotal != 13 || status.LastEtag != "etag-old" {
		t.Fatalf("status lost feed data: %+v", status)
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

func TestBackgroundServicesWaitReportsStopped(t *testing.T) {
	t.Parallel()

	services := &backgroundServices{shutdownWait: time.Second}
	if !services.Wait() {
		t.Fatal("Wait() = false, want true when no background work is running")
	}
}

func TestBackgroundServicesWaitReportsAbandonedOnTimeout(t *testing.T) {
	t.Parallel()

	services := &backgroundServices{shutdownWait: 10 * time.Millisecond}
	if !services.beginManualSyncTask() {
		t.Fatal("beginManualSyncTask() = false, want running manual task")
	}

	if services.Wait() {
		t.Fatal("Wait() = true, want false while manual task is still running after deadline")
	}

	services.endManualSyncTask()
}

func TestRunAuditRetentionOncePrunesConfiguredLogs(t *testing.T) {
	t.Parallel()

	store := &auditRetentionTestStore{}
	retention := config.RetentionConfig{
		ScanLog:       48 * time.Hour,
		AdminAuditLog: 72 * time.Hour,
		RefreshQueue:  96 * time.Hour,
	}

	runAuditRetentionOnce(context.Background(), retention, store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	if store.scanCalls != 1 || store.scanRetention != 48*time.Hour {
		t.Fatalf("scan retention calls = %d/%s, want 1/48h", store.scanCalls, store.scanRetention)
	}
	if store.adminCalls != 1 || store.adminRetention != 72*time.Hour {
		t.Fatalf("admin retention calls = %d/%s, want 1/72h", store.adminCalls, store.adminRetention)
	}
	if store.queueCalls != 1 || store.queueRetention != 96*time.Hour {
		t.Fatalf("queue retention calls = %d/%s, want 1/96h", store.queueCalls, store.queueRetention)
	}
}

func TestRunAuditRetentionOnceSkipsDisabledDurations(t *testing.T) {
	t.Parallel()

	store := &auditRetentionTestStore{}
	runAuditRetentionOnce(context.Background(), config.RetentionConfig{}, store, slog.New(slog.NewTextHandler(os.Stdout, nil)))

	if store.scanCalls != 0 || store.adminCalls != 0 || store.queueCalls != 0 {
		t.Fatalf("retention calls = scan:%d admin:%d queue:%d, want none when durations are disabled", store.scanCalls, store.adminCalls, store.queueCalls)
	}
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

type auditRetentionTestStore struct {
	scanCalls      int
	scanRetention  time.Duration
	adminCalls     int
	adminRetention time.Duration
	queueCalls     int
	queueRetention time.Duration
}

func (s *auditRetentionTestStore) PruneScanLogs(_ context.Context, retention time.Duration) (int, error) {
	s.scanCalls++
	s.scanRetention = retention
	return 3, nil
}

func (s *auditRetentionTestStore) PruneAdminAuditLogs(_ context.Context, retention time.Duration) (int, error) {
	s.adminCalls++
	s.adminRetention = retention
	return 4, nil
}

func (s *auditRetentionTestStore) PruneRefreshQueue(_ context.Context, retention time.Duration) (int, error) {
	s.queueCalls++
	s.queueRetention = retention
	return 5, nil
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
		APIKey:  "socket-secret",
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

func TestRestartQueueProcessorDoesNotOverlapGenerations(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	oldDone := make(chan error, 1)
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		Feeds: config.FeedsConfig{
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
			SocketAPIKey:  "socket-secret",
		},
	}
	services := &backgroundServices{
		logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
		cfg:          cfg,
		store:        newNoopStore(),
		rootCtx:      context.Background(),
		shutdownWait: 10 * time.Millisecond,
		queueCancel:  oldCancel,
		queueDone:    oldDone,
		queueDones:   []chan error{oldDone},
	}

	services.restartQueueProcessor()

	if oldCtx.Err() == nil {
		t.Fatal("old queue context was not cancelled")
	}
	if services.queueDone != nil {
		t.Fatal("queueDone is non-nil, want no replacement while old generation is stuck")
	}
	if len(services.queueDones) != 0 {
		t.Fatalf("queueDones length = %d, want consumed old generation removed", len(services.queueDones))
	}
}

func TestRestartQueueProcessorStartsReplacementAfterOldStops(t *testing.T) {
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oldDone := make(chan error, 1)
	oldDone <- context.Canceled
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		Feeds: config.FeedsConfig{
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
			SocketAPIKey:  "socket-secret",
		},
	}
	services := &backgroundServices{
		logger:       slog.New(slog.NewTextHandler(os.Stdout, nil)),
		cfg:          cfg,
		store:        newNoopStore(),
		rootCtx:      rootCtx,
		shutdownWait: time.Second,
		queueCancel:  func() {},
		queueDone:    oldDone,
		queueDones:   []chan error{oldDone},
	}

	services.restartQueueProcessor()

	if services.queueDone == nil {
		t.Fatal("queueDone = nil, want replacement queue processor")
	}
	if services.queueDone == oldDone {
		t.Fatal("queueDone still points at old generation")
	}
	cancel()
	services.Wait()
}
