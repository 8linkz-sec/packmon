package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
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

type systemSettingsErrorStore struct {
	db.Store
}

func (*systemSettingsErrorStore) GetSystemSettings(context.Context) (*db.SystemSettings, error) {
	return nil, errors.New("settings unavailable")
}

func TestApplyStoredSystemSettingsErrorAndInvalidBranches(t *testing.T) {
	t.Parallel()

	cfg := testAdminConfig()
	if err := applyStoredSystemSettings(context.Background(), cfg, &systemSettingsErrorStore{}, nil); err == nil || !strings.Contains(err.Error(), "get system settings") {
		t.Fatalf("applyStoredSystemSettings(error store) = %v", err)
	}

	store := newNoopStore()
	if err := store.UpsertSystemSettings(context.Background(), &db.SystemSettings{
		BlockThreshold:     " invalid ",
		RateLimitPerMinute: 0,
		RateLimitBurst:     -1,
	}); err != nil {
		t.Fatalf("UpsertSystemSettings(invalid) error = %v", err)
	}
	cfg.Server.BlockThreshold = "CRITICAL"
	cfg.Server.RateLimitPerMinute = 60
	cfg.Server.RateLimitBurst = 10
	if err := applyStoredSystemSettings(context.Background(), cfg, store, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("applyStoredSystemSettings(invalid settings) error = %v", err)
	}
	if cfg.Server.BlockThreshold != "CRITICAL" || cfg.Server.RateLimitPerMinute != 60 || cfg.Server.RateLimitBurst != 10 {
		t.Fatalf("invalid persisted settings should be ignored: %+v", cfg.Server)
	}

	if value, ok := normalizeStoredBlockThreshold(" none "); !ok || value != "NONE" {
		t.Fatalf("normalizeStoredBlockThreshold(none) = %q/%v", value, ok)
	}
	if _, ok := normalizeStoredBlockThreshold("bad"); ok {
		t.Fatal("normalizeStoredBlockThreshold(bad) ok = true")
	}
}
