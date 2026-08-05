package main

import (
	"context"
	"log/slog"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

func newFeedSyncTrigger(cfg *config.Config, store db.Store, logger *slog.Logger, background *backgroundServices) func(context.Context, string) error {
	return func(ctx context.Context, feedName string) error {
		if background != nil {
			return background.RunManualFeedSync(ctx, feedName)
		}

		manager := newFeedManager(cfg, store, logger)
		return manager.SyncOne(ctx, feedName)
	}
}
