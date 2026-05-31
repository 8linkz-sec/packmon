package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/config"
)

func TestNewLoggerHonorsConfiguredLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level     string
		wantDebug bool
		wantInfo  bool
		wantWarn  bool
	}{
		{level: "debug", wantDebug: true, wantInfo: true, wantWarn: true},
		{level: "info", wantInfo: true, wantWarn: true},
		{level: "warn", wantWarn: true},
		{level: "error"},
		{level: "unknown", wantInfo: true, wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			logger := newLogger(config.LogConfig{Level: tt.level, Format: "json"})
			if got := logger.Enabled(context.Background(), slog.LevelDebug); got != tt.wantDebug {
				t.Fatalf("debug enabled = %v, want %v", got, tt.wantDebug)
			}
			if got := logger.Enabled(context.Background(), slog.LevelInfo); got != tt.wantInfo {
				t.Fatalf("info enabled = %v, want %v", got, tt.wantInfo)
			}
			if got := logger.Enabled(context.Background(), slog.LevelWarn); got != tt.wantWarn {
				t.Fatalf("warn enabled = %v, want %v", got, tt.wantWarn)
			}
		})
	}

	if logger := newLogger(config.LogConfig{Level: "debug", Format: "console"}); !logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("console debug logger should enable debug")
	}
}

func TestStartBackgroundServicesWiresProductionManagerWithoutEnabledFeeds(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		FeedSync: config.FeedSyncConfig{
			Interval: time.Hour,
		},
		Feeds: config.FeedsConfig{
			OSVMode:           config.FeedModeSelf,
			GHSAMode:          config.FeedModeSelf,
			OpenSSFMode:       config.FeedModeSelf,
			VulnCheckMode:     config.FeedModeSelf,
			CISAKEVMode:       config.FeedModeSelf,
			EPSSMode:          config.FeedModeSelf,
			NVDMode:           config.FeedModeSelf,
			SocketMode:        config.FeedModeSelf,
			ReversingLabsMode: config.FeedModeSelf,
			DataDir:           t.TempDir(),
		},
	}

	services := startBackgroundServices(ctx, cfg, cfg.Feeds, newNoopStore(), slog.Default())
	if services == nil {
		t.Fatal("services = nil")
	}
	if services.manager == nil {
		t.Fatal("manager = nil, want production manager")
	}
	if services.queueDone != nil {
		t.Fatalf("queueDone = %#v, want nil without async workers", services.queueDone)
	}
	cancel()
	services.Wait()
}

func TestBackgroundServicesNoopGuards(t *testing.T) {
	t.Parallel()

	var services *backgroundServices
	if err := services.ApplyFeedConfig(context.Background(), config.FeedSettings{Name: "osv", Mode: config.FeedModeSelf}); err != nil {
		t.Fatalf("nil ApplyFeedConfig error = %v", err)
	}
	if err := services.ResetFeedConfig(context.Background(), "osv"); err != nil {
		t.Fatalf("nil ResetFeedConfig error = %v", err)
	}
	services.restartQueueProcessor()
	services.Wait()

	services = &backgroundServices{cfg: &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}}
	services.restartQueueProcessor()
}
