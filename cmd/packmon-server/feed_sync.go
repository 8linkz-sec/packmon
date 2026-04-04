package main

import (
	"context"
	"log/slog"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
)

func newFeedSyncTrigger(cfg *config.Config, store db.Store, logger *slog.Logger, background *backgroundServices) func(context.Context, string) error {
	return func(ctx context.Context, feedName string) error {
		if background != nil && background.manager != nil {
			return background.manager.SyncOne(ctx, feedName)
		}

		manager := newFeedManager(cfg, store, logger)
		return manager.SyncOne(ctx, feedName)
	}
}
