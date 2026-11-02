package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestApplyStoredSystemSettingsOverridesRuntimeConfig(t *testing.T) {
	store := newNoopStore()
	if err := store.UpsertSystemSettings(context.Background(), &db.SystemSettings{
		BlockThreshold:      "HIGH",
		RateLimitPerMinute:  120,
		RateLimitBurst:      25,
		ScanLogRetention:    45 * 24 * time.Hour,
		AdminAuditRetention: 14 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("UpsertSystemSettings() error = %v", err)
	}

	cfg := testAdminConfig()
	cfg.Server.BlockThreshold = "CRITICAL"
	cfg.Server.RateLimitPerMinute = 60
	cfg.Server.RateLimitBurst = 60
	cfg.Retention.ScanLog = 30 * 24 * time.Hour
	cfg.Retention.AdminAuditLog = 30 * 24 * time.Hour

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
	if cfg.Retention.ScanLog != 45*24*time.Hour {
		t.Fatalf("Retention.ScanLog = %s, want 1080h", cfg.Retention.ScanLog)
	}
	if cfg.Retention.AdminAuditLog != 14*24*time.Hour {
		t.Fatalf("Retention.AdminAuditLog = %s, want 336h", cfg.Retention.AdminAuditLog)
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

func TestApplyStoredSystemSettingsAbsentLeavesConfigUnchanged(t *testing.T) {
	t.Parallel()

	cfg := testAdminConfig()
	before := *cfg
	if err := applyStoredSystemSettings(context.Background(), cfg, newNoopStore(), nil); err != nil {
		t.Fatalf("applyStoredSystemSettings() error = %v", err)
	}
	if !reflect.DeepEqual(*cfg, before) {
		t.Fatalf("config changed for absent settings:\ngot  %+v\nwant %+v", *cfg, before)
	}
}

func TestApplyStoredSystemSettingsRetentionSemantics(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		settings db.SystemSettings
		want     db.SystemSettings
	}{
		{
			name: "zero retention clears while valid server fields apply",
			settings: db.SystemSettings{
				BlockThreshold:      " medium ",
				RateLimitPerMinute:  240,
				RateLimitBurst:      40,
				ScanLogRetention:    0,
				AdminAuditRetention: 0,
			},
			want: db.SystemSettings{
				BlockThreshold:      "MEDIUM",
				RateLimitPerMinute:  240,
				RateLimitBurst:      40,
				ScanLogRetention:    0,
				AdminAuditRetention: 0,
			},
		},
		{
			name: "negative retention and invalid rate preserve while valid fields apply",
			settings: db.SystemSettings{
				BlockThreshold:      " low ",
				RateLimitPerMinute:  0,
				RateLimitBurst:      80,
				ScanLogRetention:    -time.Second,
				AdminAuditRetention: -time.Second,
			},
			want: db.SystemSettings{
				BlockThreshold:      "LOW",
				RateLimitPerMinute:  60,
				RateLimitBurst:      80,
				ScanLogRetention:    30 * 24 * time.Hour,
				AdminAuditRetention: 30 * 24 * time.Hour,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newNoopStore()
			if err := store.UpsertSystemSettings(context.Background(), &tt.settings); err != nil {
				t.Fatalf("UpsertSystemSettings() error = %v", err)
			}
			cfg := testAdminConfig()
			cfg.Server.BlockThreshold = "CRITICAL"
			cfg.Server.RateLimitPerMinute = 60
			cfg.Server.RateLimitBurst = 10
			cfg.Retention.ScanLog = 30 * 24 * time.Hour
			cfg.Retention.AdminAuditLog = 30 * 24 * time.Hour

			if err := applyStoredSystemSettings(context.Background(), cfg, store, nil); err != nil {
				t.Fatalf("applyStoredSystemSettings() error = %v", err)
			}
			got := db.SystemSettings{
				BlockThreshold:      cfg.Server.BlockThreshold,
				RateLimitPerMinute:  cfg.Server.RateLimitPerMinute,
				RateLimitBurst:      cfg.Server.RateLimitBurst,
				ScanLogRetention:    cfg.Retention.ScanLog,
				AdminAuditRetention: cfg.Retention.AdminAuditLog,
			}
			if got != tt.want {
				t.Fatalf("effective settings = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestApplyStoredSystemSettingsStructuredLogs(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	if err := store.UpsertSystemSettings(context.Background(), &db.SystemSettings{
		BlockThreshold:      "invalid",
		RateLimitPerMinute:  0,
		RateLimitBurst:      -1,
		ScanLogRetention:    0,
		AdminAuditRetention: 14 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("UpsertSystemSettings() error = %v", err)
	}
	var logs bytes.Buffer
	if err := applyStoredSystemSettings(context.Background(), testAdminConfig(), store, slog.New(slog.NewJSONHandler(&logs, nil))); err != nil {
		t.Fatalf("applyStoredSystemSettings() error = %v", err)
	}

	wantLogs := map[string]map[string]any{
		"ignoring invalid persisted block threshold": {
			"level":           "WARN",
			"msg":             "ignoring invalid persisted block threshold",
			"block_threshold": "invalid",
		},
		"ignoring invalid persisted rate limit per minute": {
			"level":                 "WARN",
			"msg":                   "ignoring invalid persisted rate limit per minute",
			"rate_limit_per_minute": float64(0),
		},
		"ignoring invalid persisted rate limit burst": {
			"level":            "WARN",
			"msg":              "ignoring invalid persisted rate limit burst",
			"rate_limit_burst": float64(-1),
		},
		"applied persisted system settings": {
			"level": "INFO",
			"msg":   "applied persisted system settings",
			"count": float64(2),
		},
	}
	if got := decodeJSONLogRecords(t, logs.String()); !reflect.DeepEqual(got, wantLogs) {
		t.Fatalf("structured system-setting logs = %#v, want %#v", got, wantLogs)
	}
}
