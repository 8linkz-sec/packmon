package main

import (
	"context"
	"errors"
	"log/slog"
	"slices"
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
	"github.com/8linkz-sec/packmon/internal/telemetry"
)

type backgroundServices struct {
	logger           *slog.Logger
	cfg              *config.Config
	runtime          *config.RuntimeSettings
	defaultFeeds     config.FeedsConfig
	store            db.Store
	rootCtx          context.Context
	manager          *feed.Manager
	shutdownWait     time.Duration
	manualMu         sync.Mutex
	manualCond       *sync.Cond
	manualRunning    int
	manualClosed     bool
	queueMu          sync.Mutex
	queueCancel      context.CancelFunc
	queueDone        chan error
	queueDones       []chan error
	retentionDone    chan error
	managerStartDone chan struct{}
	backgroundTasks  sync.WaitGroup

	socketRateLimiter        *socket.RateLimiter
	reversingLabsRateLimiter *reversinglabs.RateLimiter
}

type asyncWorkerRateLimiters struct {
	socket        *socket.RateLimiter
	reversingLabs *reversinglabs.RateLimiter
}

type asyncWorkerRuntime struct {
	store        db.Store
	logger       *slog.Logger
	feeds        config.FeedsConfig
	metrics      feed.MetricsRecorder
	rateLimiters asyncWorkerRateLimiters
}

type asyncWorkerDescriptor struct {
	feedName             string
	enabled              func(config.FeedsConfig) bool
	mode                 func(config.FeedsConfig) config.FeedMode
	apiKey               func(config.FeedsConfig) string
	skippedStatusMessage string
	newWorker            func(asyncWorkerRuntime) feed.AsyncWorker
}

func (d asyncWorkerDescriptor) configured(feeds config.FeedsConfig) bool {
	return d.enabled != nil &&
		d.mode != nil &&
		d.enabled(feeds) &&
		d.mode(feeds) == config.FeedModeSelf
}

func (d asyncWorkerDescriptor) apiKeyConfigured(feeds config.FeedsConfig) bool {
	if d.apiKey == nil {
		return true
	}
	return strings.TrimSpace(d.apiKey(feeds)) != ""
}

var asyncWorkerDescriptors = []asyncWorkerDescriptor{
	{
		feedName:             socket.FeedName,
		enabled:              func(feeds config.FeedsConfig) bool { return feeds.SocketEnabled },
		mode:                 func(feeds config.FeedsConfig) config.FeedMode { return feeds.SocketMode },
		apiKey:               func(feeds config.FeedsConfig) string { return feeds.SocketAPIKey },
		skippedStatusMessage: "Socket.dev API key not configured",
		newWorker: func(runtime asyncWorkerRuntime) feed.AsyncWorker {
			opts := []socket.Option{socket.WithMetricsRecorder(runtime.metrics)}
			if strings.TrimSpace(runtime.feeds.SocketBaseURL) != "" {
				opts = append(opts, socket.WithBaseURL(runtime.feeds.SocketBaseURL))
			}
			if runtime.rateLimiters.socket != nil {
				opts = append(opts, socket.WithRateLimiter(runtime.rateLimiters.socket))
			}
			opts = append(opts, socket.WithExcludedNamespaces(runtime.feeds.SocketExcludedNamespaces))
			return socket.NewWorker(runtime.store, runtime.feeds.SocketAPIKey, runtime.logger, opts...)
		},
	},
	{
		feedName:             reversinglabs.FeedName,
		enabled:              func(feeds config.FeedsConfig) bool { return feeds.ReversingLabsEnabled },
		mode:                 func(feeds config.FeedsConfig) config.FeedMode { return feeds.ReversingLabsMode },
		apiKey:               func(feeds config.FeedsConfig) string { return feeds.ReversingLabsAPIKey },
		skippedStatusMessage: "ReversingLabs API key not configured",
		newWorker: func(runtime asyncWorkerRuntime) feed.AsyncWorker {
			opts := []reversinglabs.Option{
				reversinglabs.WithMetricsRecorder(runtime.metrics),
				reversinglabs.WithBaseURL(runtime.feeds.ReversingLabsBaseURL),
				reversinglabs.WithLookupTTL(runtime.feeds.ReversingLabsLookupTTL),
				reversinglabs.WithCacheRetention(runtime.feeds.ReversingLabsCacheRetention),
				reversinglabs.WithBatchSize(runtime.feeds.ReversingLabsBatchSize),
				reversinglabs.WithExcludedNamespaces(runtime.feeds.ReversingLabsExcludedNamespaces),
			}
			if runtime.rateLimiters.reversingLabs != nil {
				opts = append(opts, reversinglabs.WithRateLimiter(runtime.rateLimiters.reversingLabs))
			}
			return reversinglabs.NewWorker(
				runtime.store,
				runtime.feeds.ReversingLabsAPIKey,
				runtime.logger,
				opts...,
			)
		},
	},
}

var asyncWorkerDescriptorsByFeedName = func() map[string]asyncWorkerDescriptor {
	out := make(map[string]asyncWorkerDescriptor, len(asyncWorkerDescriptors))
	for _, descriptor := range asyncWorkerDescriptors {
		out[config.NormalizeFeedName(descriptor.feedName)] = descriptor
	}
	return out
}()

func asyncWorkerDescriptorForFeed(feedName string) (asyncWorkerDescriptor, bool) {
	descriptor, ok := asyncWorkerDescriptorsByFeedName[config.NormalizeFeedName(feedName)]
	return descriptor, ok
}

type feedRuntime struct {
	cfg    *config.Config
	feeds  config.FeedsConfig
	logger *slog.Logger
}

type feedRuntimeDescriptor struct {
	name      string
	phase     feed.FeedPhase
	newSyncer func(feedRuntime) feed.FeedSyncer
}

func (d feedRuntimeDescriptor) syncer(runtime feedRuntime) feed.FeedSyncer {
	if d.newSyncer == nil {
		return nil
	}
	return d.newSyncer(runtime)
}

var feedRuntimeDescriptors = []feedRuntimeDescriptor{
	{
		name:  osv.FeedName,
		phase: feed.FeedPhaseVulnerability,
		newSyncer: func(runtime feedRuntime) feed.FeedSyncer {
			return osv.NewSyncer(runtime.logger, osv.WithBaseURL(runtime.feeds.OSVBaseURL))
		},
	},
	{
		name:  ghsa.FeedName,
		phase: feed.FeedPhaseVulnerability,
		newSyncer: func(runtime feedRuntime) feed.FeedSyncer {
			return ghsa.NewSyncerWithOptions(runtime.logger, runtime.feeds.DataDir, ghsa.WithRepoURL(runtime.feeds.GHSARepoURL))
		},
	},
	{
		name:  malicious.FeedName,
		phase: feed.FeedPhaseVulnerability,
		newSyncer: func(runtime feedRuntime) feed.FeedSyncer {
			return malicious.NewSyncerWithOptions(runtime.logger, runtime.feeds.DataDir, malicious.WithRepoURL(runtime.feeds.OpenSSFRepoURL))
		},
	},
	{
		name:  "vulncheck",
		phase: feed.FeedPhaseEnrichment,
		newSyncer: func(runtime feedRuntime) feed.FeedSyncer {
			opts := []vulncheck.Option{}
			if strings.TrimSpace(runtime.feeds.VulnCheckBaseURL) != "" {
				opts = append(opts, vulncheck.WithBaseURL(runtime.feeds.VulnCheckBaseURL))
			}
			return vulncheck.NewSyncer(runtime.feeds.VulnCheckAPIKey, runtime.logger, opts...)
		},
	},
	{
		name:  "cisakev",
		phase: feed.FeedPhaseEnrichment,
		newSyncer: func(runtime feedRuntime) feed.FeedSyncer {
			return cisakev.NewSyncer(runtime.logger, cisakev.WithCatalogURL(runtime.feeds.CISAKEVCatalogURL))
		},
	},
	{
		name:  "epss",
		phase: feed.FeedPhaseEnrichment,
		newSyncer: func(runtime feedRuntime) feed.FeedSyncer {
			return epss.NewSyncer(runtime.logger, epss.WithScoresURL(runtime.feeds.EPSSScoresURL))
		},
	},
	{
		name:  "nvd",
		phase: feed.FeedPhaseEnrichment,
		newSyncer: func(runtime feedRuntime) feed.FeedSyncer {
			return newNVDSyncer(runtime.cfg, runtime.logger)
		},
	},
	{
		name:  endoflife.FeedName,
		phase: feed.FeedPhaseEnrichment,
		newSyncer: func(runtime feedRuntime) feed.FeedSyncer {
			return endoflife.NewSyncer(runtime.logger, endoflife.WithBaseURL(runtime.feeds.EndOfLifeBaseURL))
		},
	},
}

var feedRuntimeDescriptorsByName = func() map[string]feedRuntimeDescriptor {
	out := make(map[string]feedRuntimeDescriptor, len(feedRuntimeDescriptors))
	for _, descriptor := range feedRuntimeDescriptors {
		out[config.NormalizeFeedName(descriptor.name)] = descriptor
	}
	return out
}()

func feedRuntimeDescriptorForName(name string) (feedRuntimeDescriptor, bool) {
	descriptor, ok := feedRuntimeDescriptorsByName[config.NormalizeFeedName(name)]
	return descriptor, ok
}

func newFeedRuntime(cfg *config.Config, logger *slog.Logger) feedRuntime {
	runtime := feedRuntime{
		cfg:    cfg,
		logger: logger,
	}
	if cfg != nil {
		runtime.feeds = cfg.FeedsSnapshot()
	}
	return runtime
}

func startBackgroundServices(ctx context.Context, cfg *config.Config, runtime *config.RuntimeSettings, defaultFeeds config.FeedsConfig, store db.Store, logger *slog.Logger) (*backgroundServices, error) {
	services := &backgroundServices{
		logger:                   logger,
		cfg:                      cfg,
		runtime:                  runtime,
		defaultFeeds:             defaultFeeds,
		store:                    store,
		rootCtx:                  ctx,
		shutdownWait:             cfg.Server.ShutdownTimeout,
		socketRateLimiter:        socket.NewRateLimiter(0),
		reversingLabsRateLimiter: reversinglabs.NewRateLimiter(0),
	}
	if cfg.IsDevelopment() {
		return services, nil
	}

	services.manager = newFeedManager(cfg, store, logger)
	services.managerStartDone = make(chan struct{})
	go func() {
		defer close(services.managerStartDone)
		services.manager.Start(ctx)
	}()

	services.queueMu.Lock()
	err := services.startQueueProcessorLocked()
	services.queueMu.Unlock()
	if err != nil {
		return services, err
	}
	services.startAuditRetentionWorker()

	return services, nil
}

func (b *backgroundServices) startBackgroundTask(name string, fn func(context.Context) error) {
	if b == nil || fn == nil {
		return
	}
	ctx := b.rootCtx
	if ctx == nil {
		ctx = context.Background()
	}
	b.backgroundTasks.Add(1)
	go func() {
		defer b.backgroundTasks.Done()
		if err := fn(ctx); err != nil {
			if b.logger != nil && !errors.Is(err, context.Canceled) {
				b.logger.Warn("background startup task failed",
					slog.String("task", name),
					slog.String("error", err.Error()),
				)
			}
			return
		}
		if b.logger != nil {
			b.logger.Info("background startup task completed",
				slog.String("task", name),
			)
		}
	}()
}

func (b *backgroundServices) ApplyFeedConfig(ctx context.Context, settings config.FeedSettings) error {
	if b == nil || b.cfg == nil {
		return nil
	}

	feedName := config.NormalizeFeedName(settings.Name)
	beforeSettings, hadBeforeSettings := b.cfg.FeedSettings(feedName)
	beforeFeeds := b.cfg.FeedsSnapshot()
	beforeRuntime := runtimeFeedConfigSignature(b.cfg, beforeFeeds, beforeSettings)

	if err := b.cfg.SetFeedSettings(settings); err != nil {
		return err
	}

	afterSettings, hadAfterSettings := b.cfg.FeedSettings(feedName)
	afterFeeds := b.cfg.FeedsSnapshot()
	if hadBeforeSettings && hadAfterSettings && beforeRuntime.equal(runtimeFeedConfigSignature(b.cfg, afterFeeds, afterSettings)) {
		return nil
	}

	if b.manager != nil {
		if descriptor, ok := feedRuntimeDescriptorForName(feedName); ok {
			syncer := descriptor.syncer(newFeedRuntime(b.cfg, b.logger))
			feedCfg := feed.FeedConfig{
				Syncer:  syncer,
				Mode:    feed.FeedMode(settings.Mode),
				Enabled: settings.Enabled,
				Phase:   descriptor.phase,
			}

			interval := time.Duration(0)
			if settings.SupportsSyncInterval {
				interval = b.cfg.EffectiveFeedInterval(feedName)
			}
			b.manager.ApplyConfig(ctx, feedCfg, interval)
		}
	}

	if _, ok := asyncWorkerDescriptorForFeed(feedName); ok {
		if err := b.restartQueueProcessor(); err != nil {
			return err
		}
	}

	return nil
}

func (b *backgroundServices) ResetFeedConfig(ctx context.Context, feedName string) (config.FeedSettings, bool, error) {
	if b == nil || b.cfg == nil {
		return config.FeedSettings{}, false, nil
	}
	defaultCfg := &config.Config{
		Feeds:    b.defaultFeeds,
		FeedSync: b.cfg.FeedSync,
	}
	settings, ok := defaultCfg.FeedSettings(feedName)
	if !ok {
		return config.FeedSettings{}, false, nil
	}
	return settings, true, b.ApplyFeedConfig(ctx, settings)
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

func (b *backgroundServices) restartQueueProcessor() error {
	if b == nil || b.cfg == nil || b.cfg.IsDevelopment() {
		return nil
	}

	b.queueMu.Lock()
	defer b.queueMu.Unlock()

	oldDone := b.stopQueueProcessorLocked()
	if oldDone != nil && !b.waitForQueueProcessor(oldDone, "restart") {
		b.queueDone = oldDone
		return nil
	}
	b.removeQueueDoneLocked(oldDone)
	return b.startQueueProcessorLocked()
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
				slog.Duration("timeout", wait))
		}
		return false
	}
}

func (b *backgroundServices) startQueueProcessorLocked() error {
	if b.rootCtx == nil || b.rootCtx.Err() != nil {
		return nil
	}

	if b.socketRateLimiter == nil {
		b.socketRateLimiter = socket.NewRateLimiter(0)
	}
	if b.reversingLabsRateLimiter == nil {
		b.reversingLabsRateLimiter = reversinglabs.NewRateLimiter(0)
	}
	processor, err := newQueueProcessorWithRateLimitersAndRecorder(b.cfg, b.store, b.logger, b.socketRateLimiter, b.reversingLabsRateLimiter, b.recordQueueWorkerSkippedAsync)
	if err != nil {
		return err
	}
	if processor == nil {
		b.queueDone = nil
		return nil
	}

	queueCtx, cancel := context.WithCancel(b.rootCtx)
	done := make(chan error, 1)
	b.queueCancel = cancel
	b.queueDone = done
	b.queueDones = append(b.queueDones, done)
	go func() {
		done <- processor.Run(queueCtx)
	}()
	return nil
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
		b.waitFeedManager(start)
		b.stopAndWaitQueueProcessors(start)
		b.waitRetentionWorker(start)
		b.waitManualSyncs(start)
		b.waitBackgroundStartupTasks(start)
		close(done)
	}()

	wait := b.shutdownWait
	if wait <= 0 {
		wait = 3 * time.Second
	}
	select {
	case <-done:
		if b.logger != nil {
			b.logger.Info("shutdown: all background services stopped", slog.Duration("elapsed", time.Since(start)))
		}
		return true
	case <-time.After(wait):
		if b.logger != nil {
			b.logger.Warn("shutdown: background services did not stop before deadline, abandoning",
				slog.Duration("timeout", wait),
				slog.Duration("elapsed", time.Since(start)))
		}
		return false
	}
}

func (b *backgroundServices) waitFeedManager(start time.Time) {
	if b.managerStartDone != nil {
		if b.logger != nil {
			b.logger.Info("shutdown: waiting for feed manager startup")
		}
		<-b.managerStartDone
	}
	if b.manager != nil {
		if b.logger != nil {
			b.logger.Info("shutdown: waiting for feed manager")
		}
		b.manager.Wait()
		if b.logger != nil {
			b.logger.Info("shutdown: feed manager stopped", slog.Duration("elapsed", time.Since(start)))
		}
	}
}

func (b *backgroundServices) stopAndWaitQueueProcessors(start time.Time) {
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
			b.logger.Info("shutdown: queue processor stopped", slog.Duration("elapsed", time.Since(start)))
		}
	}
}

func (b *backgroundServices) waitRetentionWorker(start time.Time) {
	if b.retentionDone != nil {
		if b.logger != nil {
			b.logger.Info("shutdown: waiting for audit retention worker")
		}
		err := <-b.retentionDone
		if err != nil && !errors.Is(err, context.Canceled) && b.logger != nil {
			b.logger.Error("audit retention worker stopped with error", "error", err)
		}
		if b.logger != nil {
			b.logger.Info("shutdown: audit retention worker stopped", slog.Duration("elapsed", time.Since(start)))
		}
	}
}

func (b *backgroundServices) waitManualSyncs(start time.Time) {
	if b.logger != nil {
		b.logger.Info("shutdown: waiting for manual feed syncs")
	}
	b.waitManualSyncTasks()
	if b.logger != nil {
		b.logger.Info("shutdown: manual feed syncs stopped", slog.Duration("elapsed", time.Since(start)))
	}
}

func (b *backgroundServices) waitBackgroundStartupTasks(start time.Time) {
	if b.logger != nil {
		b.logger.Info("shutdown: waiting for background startup tasks")
	}
	b.backgroundTasks.Wait()
	if b.logger != nil {
		b.logger.Info("shutdown: background startup tasks stopped", slog.Duration("elapsed", time.Since(start)))
	}
}

func newFeedManager(cfg *config.Config, store db.Store, logger *slog.Logger) *feed.Manager {
	manager := feed.NewManager(store, logger.With("component", "feed_manager"), cfg.FeedSync.Interval, feed.WithMetricsRecorder(telemetry.Default()))
	manager.SetSyncOnStartup(cfg.FeedSync.OnStartup)

	for _, descriptor := range feedRuntimeDescriptors {
		registerFeedSyncer(manager, cfg, logger, descriptor)
	}

	return manager
}

func newFeedSyncer(name string, cfg *config.Config, logger *slog.Logger) feed.FeedSyncer {
	descriptor, ok := feedRuntimeDescriptorForName(name)
	if !ok {
		return nil
	}
	return descriptor.syncer(newFeedRuntime(cfg, logger))
}

func newQueueProcessorWithRateLimiters(cfg *config.Config, store db.Store, logger *slog.Logger, socketRateLimiter *socket.RateLimiter, reversingLabsRateLimiter *reversinglabs.RateLimiter) (*feed.QueueProcessor, error) {
	return newQueueProcessorWithRateLimitersAndRecorder(cfg, store, logger, socketRateLimiter, reversingLabsRateLimiter, func(feedName, message string) error {
		return recordQueueWorkerSkipped(context.Background(), store, logger, feedName, message)
	})
}

func newQueueProcessorWithRateLimitersAndRecorder(cfg *config.Config, store db.Store, logger *slog.Logger, socketRateLimiter *socket.RateLimiter, reversingLabsRateLimiter *reversinglabs.RateLimiter, recordSkipped func(feedName, message string) error) (*feed.QueueProcessor, error) {
	if recordSkipped == nil {
		recordSkipped = func(feedName, message string) error {
			return recordQueueWorkerSkipped(context.Background(), store, logger, feedName, message)
		}
	}
	feeds := cfg.FeedsSnapshot()
	metrics := telemetry.Default()
	runtime := asyncWorkerRuntime{
		store:   store,
		logger:  logger,
		feeds:   feeds,
		metrics: metrics,
		rateLimiters: asyncWorkerRateLimiters{
			socket:        socketRateLimiter,
			reversingLabs: reversingLabsRateLimiter,
		},
	}
	workers := make([]feed.AsyncWorker, 0, len(asyncWorkerDescriptors))
	for _, descriptor := range asyncWorkerDescriptors {
		if !descriptor.configured(feeds) {
			continue
		}
		if !descriptor.apiKeyConfigured(feeds) {
			if err := recordSkipped(descriptor.feedName, descriptor.skippedStatusMessage); err != nil {
				return nil, err
			}
			continue
		}
		workers = append(workers, descriptor.newWorker(runtime))
	}
	if len(workers) == 0 {
		return nil, nil
	}
	return feed.NewQueueProcessor(store, logger, workers, feed.WithMetricsRecorder(metrics)), nil
}

func (b *backgroundServices) recordQueueWorkerSkippedAsync(feedName, message string) error {
	b.startBackgroundTask("queue worker skipped status "+feedName, func(ctx context.Context) error {
		return recordQueueWorkerSkipped(ctx, b.store, b.logger, feedName, message)
	})
	return nil
}

func recordQueueWorkerSkipped(ctx context.Context, store db.Store, logger *slog.Logger, feedName, message string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now().UTC()
	status := &db.FeedSyncStatus{
		FeedName:       feedName,
		LastSyncStatus: db.FeedSyncStatusSkipped,
		LastError:      message,
		UpdatedAt:      now,
	}
	readCtx, readCancel := context.WithTimeout(ctx, feed.FeedStatusReadTimeout)
	current, err := store.GetFeedSyncStatus(readCtx, feedName)
	readCancel()
	if err != nil {
		if logger != nil {
			logger.Warn("failed to load current queue worker feed status",
				slog.String("feed", feedName),
				slog.String("error", err.Error()),
			)
		}
		return err
	} else {
		feed.PreserveFeedStatusData(status, current)
	}

	writeCtx, writeCancel := context.WithTimeout(ctx, feed.FeedStatusWriteTimeout)
	err = store.UpsertFeedSyncStatus(writeCtx, status)
	writeCancel()
	if err != nil {
		if logger != nil {
			logger.Warn("failed to record queue worker skipped status",
				slog.String("feed", feedName),
				slog.String("error", err.Error()),
			)
		}
		return err
	}
	return nil
}

func newNVDSyncer(cfg *config.Config, logger *slog.Logger) *nvd.Syncer {
	feeds := cfg.FeedsSnapshot()
	var opts []nvd.Option
	if feeds.NVDAPIKey != "" {
		opts = append(opts, nvd.WithAPIKey(feeds.NVDAPIKey))
	}
	opts = append(opts, nvd.WithAPIURL(feeds.NVDAPIURL))
	return nvd.NewSyncer(logger, opts...)
}

func feedPhaseForName(name string) feed.FeedPhase {
	descriptor, ok := feedRuntimeDescriptorForName(name)
	if !ok {
		return feed.FeedPhaseVulnerability
	}
	return descriptor.phase
}

func registerFeedSyncer(manager *feed.Manager, cfg *config.Config, logger *slog.Logger, descriptor feedRuntimeDescriptor) {
	name := descriptor.name
	settings, ok := cfg.FeedSettings(name)
	if !ok {
		return
	}

	syncer := descriptor.syncer(newFeedRuntime(cfg, logger))
	feedCfg := feed.FeedConfig{
		Syncer:  syncer,
		Mode:    feed.FeedMode(settings.Mode),
		Enabled: settings.Enabled,
		Phase:   descriptor.phase,
	}

	if interval := cfg.EffectiveFeedInterval(name); interval > 0 && settings.SupportsSyncInterval {
		if err := manager.RegisterWithInterval(feedCfg, interval); err != nil {
			logger.Error("failed to register feed syncer", "feed", name, "error", err)
		}
		return
	}
	if err := manager.Register(feedCfg); err != nil {
		logger.Error("failed to register feed syncer", "feed", name, "error", err)
	}
}

type runtimeFeedConfig struct {
	name                        string
	enabled                     bool
	mode                        config.FeedMode
	syncInterval                time.Duration
	apiKey                      string
	reversingLabsBaseURL        string
	reversingLabsLookupTTL      time.Duration
	reversingLabsBatchSize      int
	reversingLabsCacheRetention time.Duration
	reversingLabsExcludedNS     []string
	socketExcludedNS            []string
}

func runtimeFeedConfigSignature(cfg *config.Config, feeds config.FeedsConfig, settings config.FeedSettings) runtimeFeedConfig {
	signature := runtimeFeedConfig{
		name:    config.NormalizeFeedName(settings.Name),
		enabled: settings.Enabled,
		mode:    settings.Mode,
		apiKey:  strings.TrimSpace(settings.APIKey),
	}
	if settings.SupportsSyncInterval {
		signature.syncInterval = settings.SyncInterval
		if signature.syncInterval <= 0 && cfg != nil {
			signature.syncInterval = cfg.FeedSync.Interval
		}
	}
	switch signature.name {
	case "socket":
		signature.socketExcludedNS = append([]string(nil), feeds.SocketExcludedNamespaces...)
	case "reversinglabs":
		signature.reversingLabsBaseURL = strings.TrimSpace(feeds.ReversingLabsBaseURL)
		signature.reversingLabsLookupTTL = feeds.ReversingLabsLookupTTL
		signature.reversingLabsBatchSize = feeds.ReversingLabsBatchSize
		signature.reversingLabsCacheRetention = feeds.ReversingLabsCacheRetention
		signature.reversingLabsExcludedNS = append([]string(nil), feeds.ReversingLabsExcludedNamespaces...)
	}
	return signature
}

func (c runtimeFeedConfig) equal(other runtimeFeedConfig) bool {
	return c.name == other.name &&
		c.enabled == other.enabled &&
		c.mode == other.mode &&
		c.syncInterval == other.syncInterval &&
		c.apiKey == other.apiKey &&
		c.reversingLabsBaseURL == other.reversingLabsBaseURL &&
		c.reversingLabsLookupTTL == other.reversingLabsLookupTTL &&
		c.reversingLabsBatchSize == other.reversingLabsBatchSize &&
		c.reversingLabsCacheRetention == other.reversingLabsCacheRetention &&
		slices.Equal(c.reversingLabsExcludedNS, other.reversingLabsExcludedNS) &&
		slices.Equal(c.socketExcludedNS, other.socketExcludedNS)
}
