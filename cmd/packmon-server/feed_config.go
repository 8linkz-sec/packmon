package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
)

func applyStoredFeedConfigOverrides(ctx context.Context, cfg *config.Config, store db.Store, logger *slog.Logger) error {
	overrides, err := store.ListFeedConfigs(ctx)
	if err != nil {
		return fmt.Errorf("list feed config overrides: %w", err)
	}
	if len(overrides) == 0 {
		return nil
	}

	applied := 0
	for _, override := range overrides {
		current, ok := cfg.FeedSettings(override.FeedName)
		if !ok {
			if logger != nil {
				logger.Warn("ignoring unknown persisted feed override", "feed", override.FeedName)
			}
			continue
		}

		mode, err := config.ParseFeedMode(override.Mode)
		if err != nil {
			if logger != nil {
				logger.Warn("ignoring invalid persisted feed mode", "feed", override.FeedName, "mode", override.Mode, "error", err)
			}
			continue
		}

		current.Enabled = override.Enabled
		current.Mode = mode
		if override.SyncInterval != nil {
			current.SyncInterval = *override.SyncInterval
		} else {
			current.SyncInterval = 0
		}
		if current.RequiresAPIKey || strings.TrimSpace(override.APIKey) != "" {
			current.APIKey = strings.TrimSpace(override.APIKey)
		}

		if err := cfg.SetFeedSettings(current); err != nil {
			return fmt.Errorf("apply feed config override for %s: %w", override.FeedName, err)
		}
		applied++
	}

	if logger != nil && applied > 0 {
		logger.Info("applied persisted feed configuration overrides", "count", applied)
	}
	return nil
}
