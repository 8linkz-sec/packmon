package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/feed/cisakev"
	"github.com/8linkz-sec/packmon/internal/feed/endoflife"
	"github.com/8linkz-sec/packmon/internal/feed/epss"
	"github.com/8linkz-sec/packmon/internal/feed/ghsa"
	"github.com/8linkz-sec/packmon/internal/feed/malicious"
	"github.com/8linkz-sec/packmon/internal/feed/nvd"
	"github.com/8linkz-sec/packmon/internal/feed/osv"
	"github.com/8linkz-sec/packmon/internal/feed/reversinglabs"
	"github.com/8linkz-sec/packmon/internal/feed/socket"
	"github.com/8linkz-sec/packmon/internal/feed/vulncheck"
)

type backgroundServices struct {
	logger        *slog.Logger
	cfg           *config.Config
	defaultFeeds  config.FeedsConfig
	store         db.Store
	rootCtx       context.Context
	manager       *feed.Manager
	shutdownWait  time.Duration
	manualMu      sync.Mutex
	manualCond    *sync.Cond
	manualRunning int
	manualClosed  bool
	queueMu       sync.Mutex
	queueCancel   context.CancelFunc
	queueDone     chan error
	queueDones    []chan error
	retentionDone chan error

	socketRateLimiter        *socket.RateLimiter
	reversingLabsRateLimiter *reversinglabs.RateLimiter
}

func startBackgroundServices(ctx context.Context, cfg *config.Config, defaultFeeds config.FeedsConfig, store db.Store, logger *slog.Logger) *backgroundServices {
	services := &backgroundServices{
		logger:                   logger,
		cfg:                      cfg,
		defaultFeeds:             defaultFeeds,
		store:                    store,
		rootCtx:                  ctx,
		shutdownWait:             cfg.Server.ShutdownTimeout,
		socketRateLimiter:        socket.NewRateLimiter(0),
		reversingLabsRateLimiter: reversinglabs.NewRateLimiter(0),
	}
	if cfg.IsDevelopment() {
		return services
	}

	services.manager = newFeedManager(cfg, store, logger)
	services.manager.Start(ctx)

	services.queueMu.Lock()
	services.startQueueProcessorLocked()
	services.queueMu.Unlock()
	services.startAuditRetentionWorker()

	return services
}

func (b *backgroundServices) ApplyFeedConfig(ctx context.Context, settings config.FeedSettings) error {
	if b == nil || b.cfg == nil {
		return nil
	}

	if err := b.cfg.SetFeedSettings(settings); err != nil {
		return err
	}

	feedName := config.NormalizeFeedName(settings.Name)
	if b.manager != nil {
		if syncer := newFeedSyncer(feedName, b.cfg, b.store, b.logger); syncer != nil {
			feedCfg := feed.FeedConfig{
				Syncer:  syncer,
				Mode:    feed.FeedMode(settings.Mode),
				Enabled: settings.Enabled,
				Phase:   feedPhaseForName(feedName),
			}

			interval := time.Duration(0)
			if settings.SupportsSyncInterval {
				interval = b.cfg.EffectiveFeedInterval(feedName)
			}
			b.manager.ApplyConfig(ctx, feedCfg, interval)
		}
	}

	if feedName == "socket" || feedName == "reversinglabs" {
		b.restartQueueProcessor()
	}

	return nil
}

func (b *backgroundServices) ResetFeedConfig(ctx context.Context, feedName string) error {
	if b == nil || b.cfg == nil {
		return nil
	}
	defaultCfg := &config.Config{
		Feeds:    b.defaultFeeds,
		FeedSync: b.cfg.FeedSync,
	}
	settings, ok := defaultCfg.FeedSettings(feedName)
	if !ok {
		return nil
	}
	return b.ApplyFeedConfig(ctx, settings)
}

func (b *backgroundServices) RunManualFeedSync(ctx context.Context, feedName string) error {
	if b == nil {
		return context.Canceled
	}
	if !b.beginManualSyncTask() {
		return context.Canceled
	}
	defer b.endManualSyncTask()

	if b.manager != nil {
		return b.manager.SyncOne(ctx, feedName)
	}

	manager := newFeedManager(b.cfg, b.store, b.logger)
	return manager.SyncOne(ctx, feedName)
}

func (b *backgroundServices) beginManualSyncTask() bool {
	b.manualMu.Lock()
	defer b.manualMu.Unlock()
	if b.manualClosed {
		return false
	}
	if b.manualCond == nil {
		b.manualCond = sync.NewCond(&b.manualMu)
	}
	b.manualRunning++
	return true
}

func (b *backgroundServices) endManualSyncTask() {
	b.manualMu.Lock()
	defer b.manualMu.Unlock()
	if b.manualRunning > 0 {
		b.manualRunning--
	}
	if b.manualCond != nil {
		b.manualCond.Broadcast()
	}
}

func (b *backgroundServices) waitManualSyncTasks() {
	b.manualMu.Lock()
	defer b.manualMu.Unlock()
	b.manualClosed = true
	if b.manualCond == nil {
		b.manualCond = sync.NewCond(&b.manualMu)
	}
	for b.manualRunning > 0 {
		b.manualCond.Wait()
	}
}

func (b *backgroundServices) restartQueueProcessor() {
	if b == nil || b.cfg == nil || b.cfg.IsDevelopment() {
		return
	}

	b.queueMu.Lock()
	defer b.queueMu.Unlock()

	oldDone := b.stopQueueProcessorLocked()
	b.removeQueueDoneLocked(oldDone)
	if oldDone != nil && !b.waitForQueueProcessor(oldDone, "restart") {
		return
	}
	b.startQueueProcessorLocked()
}

func (b *backgroundServices) stopQueueProcessorLocked() chan error {
	done := b.queueDone
	if b.queueCancel != nil {
		b.queueCancel()
	}
	b.queueCancel = nil
	b.queueDone = nil
	return done
}

func (b *backgroundServices) removeQueueDoneLocked(done chan error) {
	if done == nil {
		return
	}
	for i, candidate := range b.queueDones {
		if candidate == done {
			b.queueDones = append(b.queueDones[:i], b.queueDones[i+1:]...)
			return
		}
	}
}

func (b *backgroundServices) waitForQueueProcessor(done chan error, reason string) bool {
	wait := b.shutdownWait
	if wait <= 0 {
		wait = 3 * time.Second
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) && b.logger != nil {
			b.logger.Error("queue processor stopped with error", "reason", reason, "error", err)
		}
		if b.logger != nil {
			b.logger.Info("queue processor stopped", "reason", reason)
		}
		return true
	case <-time.After(wait):
		if b.logger != nil {
			b.logger.Warn("queue processor did not stop before deadline; replacement not started",
				"reason", reason,
				"timeout", wait.String())
		}
		return false
	}
}

func (b *backgroundServices) startQueueProcessorLocked() {
	if b.rootCtx == nil || b.rootCtx.Err() != nil {
		return
	}

	if b.socketRateLimiter == nil {
		b.socketRateLimiter = socket.NewRateLimiter(0)
	}
	if b.reversingLabsRateLimiter == nil {
		b.reversingLabsRateLimiter = reversinglabs.NewRateLimiter(0)
	}
	processor := newQueueProcessorWithRateLimiters(b.cfg, b.store, b.logger, b.socketRateLimiter, b.reversingLabsRateLimiter)
	if processor == nil {
		b.queueDone = nil
		return
	}

	queueCtx, cancel := context.WithCancel(b.rootCtx)
	done := make(chan error, 1)
	b.queueCancel = cancel
	b.queueDone = done
	b.queueDones = append(b.queueDones, done)
	go func() {
		done <- processor.Run(queueCtx)
	}()
}

// Wait blocks until all background services have stopped or the configured
// shutdown wait is reached. This prevents the container from hanging when a
// feed syncer is stuck mid-download while still respecting the operator's
// graceful-shutdown budget.
func (b *backgroundServices) Wait() bool {
	if b == nil {
		return true
	}

	start := time.Now()
	done := make(chan struct{})
	go func() {
		if b.manager != nil {
			if b.logger != nil {
				b.logger.Info("shutdown: waiting for feed manager")
			}
			b.manager.Wait()
			if b.logger != nil {
				b.logger.Info("shutdown: feed manager stopped", "elapsed", time.Since(start).String())
			}
		}
		b.queueMu.Lock()
		b.stopQueueProcessorLocked()
		queueDones := append([]chan error(nil), b.queueDones...)
		b.queueMu.Unlock()

		for _, queueDone := range queueDones {
			if b.logger != nil {
				b.logger.Info("shutdown: waiting for queue processor")
			}
			err := <-queueDone
			if err != nil && !errors.Is(err, context.Canceled) && b.logger != nil {
				b.logger.Error("queue processor stopped with error", "error", err)
			}
			if b.logger != nil {
				b.logger.Info("shutdown: queue processor stopped", "elapsed", time.Since(start).String())
			}
		}
		if b.retentionDone != nil {
			if b.logger != nil {
				b.logger.Info("shutdown: waiting for audit retention worker")
			}
			err := <-b.retentionDone
			if err != nil && !errors.Is(err, context.Canceled) && b.logger != nil {
				b.logger.Error("audit retention worker stopped with error", "error", err)
			}
			if b.logger != nil {
				b.logger.Info("shutdown: audit retention worker stopped", "elapsed", time.Since(start).String())
			}
		}
		if b.logger != nil {
			b.logger.Info("shutdown: waiting for manual feed syncs")
		}
		b.waitManualSyncTasks()
		if b.logger != nil {
			b.logger.Info("shutdown: manual feed syncs stopped", "elapsed", time.Since(start).String())
		}
		close(done)
	}()

	wait := b.shutdownWait
	if wait <= 0 {
		wait = 3 * time.Second
	}
	select {
	case <-done:
		if b.logger != nil {
			b.logger.Info("shutdown: all background services stopped", "elapsed", time.Since(start).String())
		}
		return true
	case <-time.After(wait):
		if b.logger != nil {
			b.logger.Warn("shutdown: background services did not stop before deadline, abandoning",
				"timeout", wait.String(),
				"elapsed", time.Since(start).String())
		}
		return false
	}
}

func newFeedManager(cfg *config.Config, store db.Store, logger *slog.Logger) *feed.Manager {
	manager := feed.NewManager(store, logger.With("component", "feed_manager"), cfg.FeedSync.Interval)
	manager.SetSyncOnStartup(cfg.FeedSync.OnStartup)

	registerFeedSyncer(manager, cfg, "osv", newFeedSyncer("osv", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "ghsa", newFeedSyncer("ghsa", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "openssf", newFeedSyncer("openssf", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "vulncheck", newFeedSyncer("vulncheck", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "cisakev", newFeedSyncer("cisakev", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "epss", newFeedSyncer("epss", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "nvd", newFeedSyncer("nvd", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "endoflife", newFeedSyncer("endoflife", cfg, store, logger))

	return manager
}

func newFeedSyncer(name string, cfg *config.Config, store db.Store, logger *slog.Logger) feed.FeedSyncer {
	feeds := cfg.FeedsSnapshot()
	switch config.NormalizeFeedName(name) {
	case "osv":
		return osv.NewSyncer(store, logger)
	case "ghsa":
		return ghsa.NewSyncer(store, logger, feeds.DataDir)
	case "openssf":
		return malicious.NewSyncer(store, logger, feeds.DataDir)
	case "vulncheck":
		return vulncheck.NewSyncer(feeds.VulnCheckAPIKey, logger)
	case "cisakev":
		return cisakev.NewSyncer(logger)
	case "epss":
		return epss.NewSyncer(logger)
	case "nvd":
		return newNVDSyncer(cfg, logger)
	case "endoflife":
		return endoflife.NewSyncer(logger, endoflife.WithBaseURL(feeds.EndOfLifeBaseURL))
	default:
		return nil
	}
}

func newQueueProcessor(cfg *config.Config, store db.Store, logger *slog.Logger) *feed.QueueProcessor {
	return newQueueProcessorWithRateLimiters(cfg, store, logger, nil, nil)
}

func newQueueProcessorWithRateLimiters(cfg *config.Config, store db.Store, logger *slog.Logger, socketRateLimiter *socket.RateLimiter, reversingLabsRateLimiter *reversinglabs.RateLimiter) *feed.QueueProcessor {
	feeds := cfg.FeedsSnapshot()
	workers := make([]feed.AsyncWorker, 0, 2)
	if feeds.SocketEnabled && feeds.SocketMode == config.FeedModeSelf {
		if strings.TrimSpace(feeds.SocketAPIKey) != "" {
			var opts []socket.Option
			if socketRateLimiter != nil {
				opts = append(opts, socket.WithRateLimiter(socketRateLimiter))
			}
			workers = append(workers, socket.NewWorker(store, feeds.SocketAPIKey, logger, opts...))
		} else {
			recordQueueWorkerSkipped(store, logger, socket.FeedName, "Socket.dev API key not configured")
		}
	}
	if feeds.ReversingLabsEnabled && feeds.ReversingLabsMode == config.FeedModeSelf {
		if strings.TrimSpace(feeds.ReversingLabsAPIKey) != "" {
			opts := []reversinglabs.Option{
				reversinglabs.WithBaseURL(feeds.ReversingLabsBaseURL),
				reversinglabs.WithLookupTTL(feeds.ReversingLabsLookupTTL),
				reversinglabs.WithCacheRetention(feeds.ReversingLabsCacheRetention),
				reversinglabs.WithBatchSize(feeds.ReversingLabsBatchSize),
				reversinglabs.WithExcludedNamespaces(feeds.ReversingLabsExcludedNamespaces),
			}
			if reversingLabsRateLimiter != nil {
				opts = append(opts, reversinglabs.WithRateLimiter(reversingLabsRateLimiter))
			}
			workers = append(workers, reversinglabs.NewWorker(
				store,
				feeds.ReversingLabsAPIKey,
				logger,
				opts...,
			))
		} else {
			recordQueueWorkerSkipped(store, logger, reversinglabs.FeedName, "ReversingLabs API key not configured")
		}
	}
	if len(workers) == 0 {
		return nil
	}
	return feed.NewQueueProcessor(store, logger, workers)
}

func recordQueueWorkerSkipped(store db.Store, logger *slog.Logger, feedName, message string) {
	now := time.Now().UTC()
	status := &db.FeedSyncStatus{
		FeedName:       feedName,
		LastSyncStatus: "skipped",
		LastError:      message,
		UpdatedAt:      now,
	}
	if current, err := feed.GetFeedSyncStatusBounded(store, feedName); err != nil {
		logger.Warn("failed to load current queue worker feed status",
			slog.String("feed", feedName),
			slog.String("error", err.Error()),
		)
	} else {
		feed.PreserveFeedStatusData(status, current)
	}
	if err := feed.UpsertFeedSyncStatusBounded(store, status); err != nil {
		logger.Warn("failed to record queue worker skipped status",
			slog.String("feed", feedName),
			slog.String("error", err.Error()),
		)
	}
}

func newNVDSyncer(cfg *config.Config, logger *slog.Logger) *nvd.Syncer {
	feeds := cfg.FeedsSnapshot()
	var opts []nvd.Option
	if feeds.NVDAPIKey != "" {
		opts = append(opts, nvd.WithAPIKey(feeds.NVDAPIKey))
	}
	return nvd.NewSyncer(logger, opts...)
}

// enrichmentFeeds are feeds that enrich existing vulnerability data
// and must wait for Phase 1 (vulnerability data) to complete first.
var enrichmentFeeds = map[string]bool{
	"vulncheck": true,
	"cisakev":   true,
	"epss":      true,
	"nvd":       true,
	"endoflife": true,
}

func feedPhaseForName(name string) feed.FeedPhase {
	if enrichmentFeeds[config.NormalizeFeedName(name)] {
		return feed.FeedPhaseEnrichment
	}
	return feed.FeedPhaseVulnerability
}

func registerFeedSyncer(manager *feed.Manager, cfg *config.Config, name string, syncer feed.FeedSyncer) {
	settings, ok := cfg.FeedSettings(name)
	if !ok {
		return
	}

	feedCfg := feed.FeedConfig{
		Syncer:  syncer,
		Mode:    feed.FeedMode(settings.Mode),
		Enabled: settings.Enabled,
		Phase:   feedPhaseForName(name),
	}

	if interval := cfg.EffectiveFeedInterval(name); interval > 0 && settings.SupportsSyncInterval {
		manager.RegisterWithInterval(feedCfg, interval)
		return
	}
	manager.Register(feedCfg)
}
