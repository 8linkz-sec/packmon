package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
)

func applyStoredSystemSettings(ctx context.Context, cfg *config.Config, store db.Store, logger *slog.Logger) error {
	settings, err := store.GetSystemSettings(ctx)
	if err != nil {
		return fmt.Errorf("get system settings: %w", err)
	}
	if settings == nil {
		return nil
	}

	applied := 0
	if threshold, ok := normalizeStoredBlockThreshold(settings.BlockThreshold); ok {
		cfg.Server.BlockThreshold = threshold
		applied++
	} else if logger != nil {
		logger.Warn("ignoring invalid persisted block threshold", "block_threshold", settings.BlockThreshold)
	}

	if settings.RateLimitPerMinute > 0 {
		cfg.Server.RateLimitPerMinute = settings.RateLimitPerMinute
		applied++
	} else if logger != nil {
		logger.Warn("ignoring invalid persisted rate limit per minute", "rate_limit_per_minute", settings.RateLimitPerMinute)
	}

	if settings.RateLimitBurst > 0 {
		cfg.Server.RateLimitBurst = settings.RateLimitBurst
		applied++
	} else if logger != nil {
		logger.Warn("ignoring invalid persisted rate limit burst", "rate_limit_burst", settings.RateLimitBurst)
	}

	if logger != nil && applied > 0 {
		logger.Info("applied persisted system settings", "count", applied)
	}
	return nil
}

func normalizeStoredBlockThreshold(raw string) (string, bool) {
	switch normalized := strings.ToUpper(strings.TrimSpace(raw)); normalized {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return normalized, true
	default:
		return "", false
	}
}
