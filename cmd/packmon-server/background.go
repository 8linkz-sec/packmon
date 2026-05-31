package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
	"github.com/8linkz/packmon/internal/feed/cisakev"
	"github.com/8linkz/packmon/internal/feed/epss"
	"github.com/8linkz/packmon/internal/feed/ghsa"
	"github.com/8linkz/packmon/internal/feed/malicious"
	"github.com/8linkz/packmon/internal/feed/nvd"
	"github.com/8linkz/packmon/internal/feed/osv"
	"github.com/8linkz/packmon/internal/feed/reversinglabs"
	"github.com/8linkz/packmon/internal/feed/socket"
	"github.com/8linkz/packmon/internal/feed/vulncheck"
)

type backgroundServices struct {
	logger       *slog.Logger
	cfg          *config.Config
	defaultFeeds config.FeedsConfig
	store        db.Store
	rootCtx      context.Context
	manager      *feed.Manager
	queueMu      sync.Mutex
	queueCancel  context.CancelFunc
	queueDone    chan error
	queueDones   []chan error
}

func startBackgroundServices(ctx context.Context, cfg *config.Config, defaultFeeds config.FeedsConfig, store db.Store, logger *slog.Logger) *backgroundServices {
	services := &backgroundServices{logger: logger, cfg: cfg, defaultFeeds: defaultFeeds, store: store, rootCtx: ctx}
	if cfg.IsDevelopment() {
		return services
	}

	services.manager = newFeedManager(cfg, store, logger)
	services.manager.Start(ctx)

	services.queueMu.Lock()
	services.startQueueProcessorLocked()
	services.queueMu.Unlock()

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
	defaultCfg := *b.cfg
	defaultCfg.Feeds = b.defaultFeeds
	settings, ok := defaultCfg.FeedSettings(feedName)
	if !ok {
		return nil
	}
	return b.ApplyFeedConfig(ctx, settings)
}

func (b *backgroundServices) restartQueueProcessor() {
	if b == nil || b.cfg == nil || b.cfg.IsDevelopment() {
		return
	}

	b.queueMu.Lock()
	defer b.queueMu.Unlock()

	if b.queueCancel != nil {
		b.queueCancel()
		b.queueCancel = nil
	}
	b.startQueueProcessorLocked()
}

func (b *backgroundServices) startQueueProcessorLocked() {
	if b.rootCtx == nil || b.rootCtx.Err() != nil {
		return
	}

	processor := newQueueProcessor(b.cfg, b.store, b.logger)
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

// Wait blocks until all background services have stopped or the hard
// shutdown deadline (3 seconds) is reached. This prevents the container
// from hanging when a feed syncer is stuck mid-download.
func (b *backgroundServices) Wait() {
	if b == nil {
		return
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
		if b.queueCancel != nil {
			b.queueCancel()
		}
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
		close(done)
	}()

	select {
	case <-done:
		if b.logger != nil {
			b.logger.Info("shutdown: all background services stopped", "elapsed", time.Since(start).String())
		}
	case <-time.After(3 * time.Second):
		if b.logger != nil {
			b.logger.Warn("shutdown: background services did not stop within 3s, abandoning",
				"elapsed", time.Since(start).String())
		}
	}
}

func newFeedManager(cfg *config.Config, store db.Store, logger *slog.Logger) *feed.Manager {
	manager := feed.NewManager(store, logger.With("component", "feed_manager"), cfg.FeedSync.Interval)

	registerFeedSyncer(manager, cfg, "osv", newFeedSyncer("osv", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "ghsa", newFeedSyncer("ghsa", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "openssf", newFeedSyncer("openssf", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "vulncheck", newFeedSyncer("vulncheck", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "cisakev", newFeedSyncer("cisakev", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "epss", newFeedSyncer("epss", cfg, store, logger))
	registerFeedSyncer(manager, cfg, "nvd", newFeedSyncer("nvd", cfg, store, logger))

	return manager
}

func newFeedSyncer(name string, cfg *config.Config, store db.Store, logger *slog.Logger) feed.FeedSyncer {
	switch config.NormalizeFeedName(name) {
	case "osv":
		return osv.NewSyncer(store, logger)
	case "ghsa":
		return ghsa.NewSyncer(store, logger, cfg.Feeds.DataDir)
	case "openssf":
		return malicious.NewSyncer(store, logger, cfg.Feeds.DataDir)
	case "vulncheck":
		return vulncheck.NewSyncer(cfg.Feeds.VulnCheckAPIKey, logger)
	case "cisakev":
		return cisakev.NewSyncer(logger)
	case "epss":
		return epss.NewSyncer(logger)
	case "nvd":
		return newNVDSyncer(cfg, logger)
	default:
		return nil
	}
}

func newQueueProcessor(cfg *config.Config, store db.Store, logger *slog.Logger) *feed.QueueProcessor {
	workers := make([]feed.AsyncWorker, 0, 2)
	if cfg.Feeds.SocketEnabled && cfg.Feeds.SocketMode == config.FeedModeSelf {
		workers = append(workers, socket.NewWorker(store, cfg.Feeds.SocketAPIKey, logger))
	}
	if cfg.Feeds.ReversingLabsEnabled && cfg.Feeds.ReversingLabsMode == config.FeedModeSelf {
		workers = append(workers, reversinglabs.NewWorker(
			store,
			cfg.Feeds.ReversingLabsAPIKey,
			logger,
			reversinglabs.WithBaseURL(cfg.Feeds.ReversingLabsBaseURL),
			reversinglabs.WithLookupTTL(cfg.Feeds.ReversingLabsLookupTTL),
			reversinglabs.WithBatchSize(cfg.Feeds.ReversingLabsBatchSize),
		))
	}
	if len(workers) == 0 {
		return nil
	}
	return feed.NewQueueProcessor(store, logger, workers)
}

func newNVDSyncer(cfg *config.Config, logger *slog.Logger) *nvd.Syncer {
	var opts []nvd.Option
	if cfg.Feeds.NVDAPIKey != "" {
		opts = append(opts, nvd.WithAPIKey(cfg.Feeds.NVDAPIKey))
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
