package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/8linkz/packmon/internal/db"
)

func TestApplyStoredSystemSettingsOverridesRuntimeConfig(t *testing.T) {
	store := newNoopStore()
	if err := store.UpsertSystemSettings(context.Background(), &db.SystemSettings{
		BlockThreshold:     "HIGH",
		RateLimitPerMinute: 120,
		RateLimitBurst:     25,
	}); err != nil {
		t.Fatalf("UpsertSystemSettings() error = %v", err)
	}

	cfg := testAdminConfig()
	cfg.Server.BlockThreshold = "CRITICAL"
	cfg.Server.RateLimitPerMinute = 60
	cfg.Server.RateLimitBurst = 60

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := applyStoredSystemSettings(context.Background(), cfg, store, logger); err != nil {
		t.Fatalf("applyStoredSystemSettings() error = %v", err)
	}

	if cfg.Server.BlockThreshold != "HIGH" {
		t.Fatalf("Server.BlockThreshold = %q, want HIGH", cfg.Server.BlockThreshold)
	}
	if cfg.Server.RateLimitPerMinute != 120 {
		t.Fatalf("Server.RateLimitPerMinute = %d, want 120", cfg.Server.RateLimitPerMinute)
	}
	if cfg.Server.RateLimitBurst != 25 {
		t.Fatalf("Server.RateLimitBurst = %d, want 25", cfg.Server.RateLimitBurst)
	}
}
