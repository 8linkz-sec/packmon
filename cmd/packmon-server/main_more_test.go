package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/secret"
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

func TestEffectiveHardExitDelayExceedsConfiguredShutdownTimeout(t *testing.T) {
	saved := hardExitDelay
	hardExitDelay = defaultHardExitDelay
	t.Cleanup(func() { hardExitDelay = saved })

	cfg := &config.Config{Server: config.ServerConfig{ShutdownTimeout: 30 * time.Second}}
	got := effectiveHardExitDelay(cfg)
	if got <= cfg.Server.ShutdownTimeout {
		t.Fatalf("effectiveHardExitDelay() = %s, want greater than shutdown timeout %s", got, cfg.Server.ShutdownTimeout)
	}
}

func TestRequireProductionFieldEncryption(t *testing.T) {
	t.Parallel()

	inactive, err := secret.NewFieldEncryptor("")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(inactive) error = %v", err)
	}
	active, err := secret.NewFieldEncryptor("test-encryption-key")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(active) error = %v", err)
	}

	production := &config.Config{Server: config.ServerConfig{Mode: config.ModeProduction}}
	if err := requireProductionFieldEncryption(production, inactive); err == nil {
		t.Fatal("requireProductionFieldEncryption(production inactive) error = nil")
	}
	if err := requireProductionFieldEncryption(production, active); err != nil {
		t.Fatalf("requireProductionFieldEncryption(production active) error = %v", err)
	}
	development := &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}
	if err := requireProductionFieldEncryption(development, inactive); err != nil {
		t.Fatalf("requireProductionFieldEncryption(development inactive) error = %v", err)
	}
}

func TestDatabaseStartupContextUsesConfiguredDeadline(t *testing.T) {
	t.Parallel()

	parent := context.Background()
	cfg := &config.Config{DB: config.DBConfig{ConnectTimeout: 250 * time.Millisecond}}
	ctx, cancel := databaseStartupContext(parent, cfg)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("databaseStartupContext() has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > cfg.DB.ConnectTimeout {
		t.Fatalf("databaseStartupContext() deadline remaining = %s, want within configured %s", remaining, cfg.DB.ConnectTimeout)
	}
}

func TestDatabaseStartupContextFallsBackToDefaultDeadline(t *testing.T) {
	t.Parallel()

	ctx, cancel := databaseStartupContext(context.Background(), &config.Config{})
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("databaseStartupContext(default) has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > defaultDatabaseStartupTimeout {
		t.Fatalf("databaseStartupContext(default) deadline remaining = %s, want within default %s", remaining, defaultDatabaseStartupTimeout)
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
