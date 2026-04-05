package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
	"github.com/8linkz/packmon/internal/feed/cisakev"
	"github.com/8linkz/packmon/internal/feed/epss"
	"github.com/8linkz/packmon/internal/feed/ghsa"
	"github.com/8linkz/packmon/internal/feed/malicious"
	"github.com/8linkz/packmon/internal/feed/osv"
	"github.com/8linkz/packmon/internal/feed/socket"
	"github.com/8linkz/packmon/internal/feed/vulncheck"
)

type backgroundServices struct {
	logger    *slog.Logger
	manager   *feed.Manager
	queueDone chan error
}

func startBackgroundServices(ctx context.Context, cfg *config.Config, store db.Store, logger *slog.Logger) *backgroundServices {
	services := &backgroundServices{logger: logger}
	if cfg.IsDevelopment() {
		return services
	}

	services.manager = newFeedManager(cfg, store, logger)
	services.manager.Start(ctx)

	if processor := newQueueProcessor(cfg, store, logger); processor != nil {
		services.queueDone = make(chan error, 1)
		go func() {
			services.queueDone <- processor.Run(ctx)
		}()
	}

	return services
}

// Wait blocks until all background services have stopped or the hard
// shutdown deadline (5 seconds) is reached. This prevents the container
// from hanging when a feed syncer is stuck mid-download.
func (b *backgroundServices) Wait() {
	if b == nil {
		return
	}

	done := make(chan struct{})
	go func() {
		if b.manager != nil {
			b.manager.Wait()
		}
		if b.queueDone != nil {
			err := <-b.queueDone
			if err != nil && !errors.Is(err, context.Canceled) && b.logger != nil {
				b.logger.Error("queue processor stopped with error", "error", err)
			}
		}
		close(done)
	}()

	select {
	case <-done:
		if b.logger != nil {
			b.logger.Info("all background services stopped")
		}
	case <-time.After(5 * time.Second):
		if b.logger != nil {
			b.logger.Warn("background services did not stop within 5s, forcing exit")
		}
	}
}

func newFeedManager(cfg *config.Config, store db.Store, logger *slog.Logger) *feed.Manager {
	manager := feed.NewManager(store, logger.With("component", "feed_manager"), cfg.FeedSync.Interval)

	registerFeedSyncer(manager, cfg, "osv", osv.NewSyncer(store, logger))
	registerFeedSyncer(manager, cfg, "ghsa", ghsa.NewSyncer(store, logger, cfg.Feeds.DataDir))
	registerFeedSyncer(manager, cfg, "openssf", malicious.NewSyncer(store, logger, cfg.Feeds.DataDir))
	registerFeedSyncer(manager, cfg, "vulncheck", vulncheck.NewSyncer(cfg.Feeds.VulnCheckAPIKey, logger))
	registerFeedSyncer(manager, cfg, "cisakev", cisakev.NewSyncer(logger))
	registerFeedSyncer(manager, cfg, "epss", epss.NewSyncer(logger))

	return manager
}

func newQueueProcessor(cfg *config.Config, store db.Store, logger *slog.Logger) *feed.QueueProcessor {
	workers := make([]feed.AsyncWorker, 0, 1)
	if cfg.Feeds.SocketEnabled && cfg.Feeds.SocketMode == config.FeedModeSelf {
		workers = append(workers, socket.NewWorker(store, cfg.Feeds.SocketAPIKey, logger))
	}
	if len(workers) == 0 {
		return nil
	}
	return feed.NewQueueProcessor(store, logger, workers)
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
	}

	if interval := cfg.EffectiveFeedInterval(name); interval > 0 && settings.SupportsSyncInterval {
		manager.RegisterWithInterval(feedCfg, interval)
		return
	}
	manager.Register(feedCfg)
}
