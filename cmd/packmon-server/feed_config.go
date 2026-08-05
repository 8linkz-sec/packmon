package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
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
		if err := rejectProductionPlaintextFeedAPIKey(cfg, override); err != nil {
			return err
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
		if current.SupportsAPIKey || strings.TrimSpace(override.APIKey) != "" {
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

func rejectProductionPlaintextFeedAPIKey(cfg *config.Config, override db.FeedConfig) error {
	if cfg == nil || cfg.IsDevelopment() {
		return nil
	}
	if strings.TrimSpace(cfg.Admin.EncryptionKey) == "" || strings.TrimSpace(override.APIKey) == "" || override.APIKeyEncrypted {
		return nil
	}
	return fmt.Errorf("plaintext feed API key stored for feed %q; re-save or clear this feed API key through the admin feed settings so it is encrypted at rest before production startup", override.FeedName)
}
