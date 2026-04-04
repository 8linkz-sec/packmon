package main

import (
	"context"
	"errors"
	"log/slog"

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

func (b *backgroundServices) Wait() {
	if b == nil {
		return
	}
	if b.manager != nil {
		b.manager.Wait()
	}
	if b.queueDone != nil {
		err := <-b.queueDone
		if err != nil && !errors.Is(err, context.Canceled) && b.logger != nil {
			b.logger.Error("queue processor stopped with error", "error", err)
		}
	}
}

func newFeedManager(cfg *config.Config, store db.Store, logger *slog.Logger) *feed.Manager {
	manager := feed.NewManager(store, logger.With("component", "feed_manager"), cfg.FeedSync.Interval)

	manager.Register(feed.FeedConfig{
		Syncer:  osv.NewSyncer(store, logger),
		Mode:    feed.FeedMode(cfg.Feeds.OSVMode),
		Enabled: cfg.Feeds.OSVEnabled,
	})
	manager.Register(feed.FeedConfig{
		Syncer:  ghsa.NewSyncer(store, logger, cfg.Feeds.DataDir),
		Mode:    feed.FeedMode(cfg.Feeds.GHSAMode),
		Enabled: cfg.Feeds.GHSAEnabled,
	})
	manager.Register(feed.FeedConfig{
		Syncer:  malicious.NewSyncer(store, logger, cfg.Feeds.DataDir),
		Mode:    feed.FeedMode(cfg.Feeds.MaliciousMode),
		Enabled: cfg.Feeds.MaliciousEnabled,
	})
	manager.Register(feed.FeedConfig{
		Syncer:  vulncheck.NewSyncer(cfg.Feeds.VulnCheckAPIKey, logger),
		Mode:    feed.FeedMode(cfg.Feeds.VulnCheckMode),
		Enabled: cfg.Feeds.VulnCheckEnabled,
	})
	manager.Register(feed.FeedConfig{
		Syncer:  cisakev.NewSyncer(logger),
		Mode:    feed.FeedMode(cfg.Feeds.CISAKEVMode),
		Enabled: cfg.Feeds.CISAKEVEnabled,
	})
	manager.Register(feed.FeedConfig{
		Syncer:  epss.NewSyncer(logger),
		Mode:    feed.FeedMode(cfg.Feeds.EPSSMode),
		Enabled: cfg.Feeds.EPSSEnabled,
	})

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
