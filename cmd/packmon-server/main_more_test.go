package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	pgstore "github.com/8linkz-sec/packmon/internal/db/postgres"
	migrations "github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
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

func TestNewLoggerIncludesStableServiceField(t *testing.T) {
	jsonOutput := captureServerStdout(t, func() {
		logger := newLogger(config.LogConfig{Level: "info", Format: "json"})
		logger.Info("ordinary record")
	})
	var record map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonOutput)), &record); err != nil {
		t.Fatalf("JSON log record is not valid JSON: %v; output=%q", err, jsonOutput)
	}
	if got := record["service"]; got != "packmon-server" {
		t.Fatalf("JSON log service = %#v, want packmon-server; record=%v", got, record)
	}

	consoleOutput := captureServerStdout(t, func() {
		logger := newLogger(config.LogConfig{Level: "info", Format: "console"})
		logger.Info("ordinary record")
	})
	if !strings.Contains(consoleOutput, "service=packmon-server") {
		t.Fatalf("console log output = %q, want service=packmon-server", consoleOutput)
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
	weakActive, err := secret.NewFieldEncryptor("test-encryption-key")
	if err != nil {
		t.Fatalf("NewFieldEncryptor(weak active) error = %v", err)
	}
	helperStyleKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	helperStyleActive, err := secret.NewFieldEncryptor(helperStyleKey)
	if err != nil {
		t.Fatalf("NewFieldEncryptor(helper-style active) error = %v", err)
	}

	production := &config.Config{Server: config.ServerConfig{Mode: config.ModeProduction}}
	if err := requireProductionFieldEncryption(production, inactive); err == nil {
		t.Fatal("requireProductionFieldEncryption(production inactive) error = nil")
	}
	production.Admin.EncryptionKey = "test-encryption-key"
	if err := requireProductionFieldEncryption(production, weakActive); err == nil {
		t.Fatal("requireProductionFieldEncryption(production weak active) error = nil")
	}

	for _, tt := range []struct {
		name   string
		rawKey string
	}{
		{name: "non-base64", rawKey: "not-base64!"},
		{name: "short", rawKey: base64.StdEncoding.EncodeToString([]byte("short"))},
		{name: "31-bytes", rawKey: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcde"))},
		{name: "33-bytes", rawKey: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef0"))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{Mode: config.ModeProduction},
				Admin:  config.AdminConfig{EncryptionKey: tt.rawKey},
			}
			active, err := secret.NewFieldEncryptor(tt.rawKey)
			if err != nil {
				t.Fatalf("NewFieldEncryptor(%q) error = %v", tt.rawKey, err)
			}
			if err := requireProductionFieldEncryption(cfg, active); err == nil {
				t.Fatalf("requireProductionFieldEncryption(%q) error = nil", tt.rawKey)
			}
		})
	}

	production.Admin.EncryptionKey = helperStyleKey
	if err := requireProductionFieldEncryption(production, helperStyleActive); err != nil {
		t.Fatalf("requireProductionFieldEncryption(production helper-style active) error = %v", err)
	}
	development := &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}
	if err := requireProductionFieldEncryption(development, inactive); err != nil {
		t.Fatalf("requireProductionFieldEncryption(development inactive) error = %v", err)
	}
	if err := requireProductionFieldEncryption(development, weakActive); err != nil {
		t.Fatalf("requireProductionFieldEncryption(development weak active) error = %v", err)
	}
}

func TestRequireProductionAdminAuditHMACKey(t *testing.T) {
	t.Parallel()

	production := &config.Config{Server: config.ServerConfig{Mode: config.ModeProduction}}
	if err := requireProductionAdminAuditHMACKey(production); err == nil {
		t.Fatal("requireProductionAdminAuditHMACKey(production empty) error = nil")
	}

	for _, tt := range []struct {
		name   string
		rawKey string
	}{
		{name: "non-base64", rawKey: "not-base64!"},
		{name: "short", rawKey: base64.StdEncoding.EncodeToString([]byte("short"))},
		{name: "31-bytes", rawKey: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcde"))},
		{name: "33-bytes", rawKey: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef0"))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{Mode: config.ModeProduction},
				Admin:  config.AdminConfig{AdminAuditHMACKey: tt.rawKey},
			}
			if err := requireProductionAdminAuditHMACKey(cfg); err == nil {
				t.Fatalf("requireProductionAdminAuditHMACKey(%q) error = nil", tt.rawKey)
			}
		})
	}

	production.Admin.AdminAuditHMACKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if err := requireProductionAdminAuditHMACKey(production); err != nil {
		t.Fatalf("requireProductionAdminAuditHMACKey(production valid) error = %v", err)
	}

	development := &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}
	if err := requireProductionAdminAuditHMACKey(development); err != nil {
		t.Fatalf("requireProductionAdminAuditHMACKey(development empty) error = %v", err)
	}
}

func TestLoadAndValidateRuntimeConfigRejectsInsecureProduction(t *testing.T) {
	t.Setenv("PACKMON_SERVER_MODE", "production")
	t.Setenv("PACKMON_TRUSTED_PROXIES", "")
	t.Setenv("PACKMON_TLS_CERT_FILE", "")
	t.Setenv("PACKMON_TLS_KEY_FILE", "")
	t.Setenv("PACKMON_ALLOW_INSECURE_LOCAL_HTTP", "false")

	runtime, err := loadAndValidateRuntimeConfig()
	if err == nil || !strings.Contains(err.Error(), "refusing to start in production without transport security") {
		t.Fatalf("loadAndValidateRuntimeConfig() error = %v", err)
	}
	if runtime != nil {
		t.Fatalf("loadAndValidateRuntimeConfig() runtime = %#v, want nil on validation error", runtime)
	}
}

func TestLoadAndValidateRuntimeConfigRejectsProductionOffLoopbackMetrics(t *testing.T) {
	originalDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(originalDefault) })

	t.Setenv("PACKMON_SERVER_MODE", "production")
	t.Setenv("PACKMON_TLS_CERT_FILE", "server.crt")
	t.Setenv("PACKMON_TLS_KEY_FILE", "server.key")
	t.Setenv("PACKMON_METRICS_HOST", "0.0.0.0")
	t.Setenv("PACKMON_METRICS_PORT", "9090")

	runtime, err := loadAndValidateRuntimeConfig()
	if err == nil || !strings.Contains(err.Error(), "PACKMON_METRICS_HOST must bind to a loopback address in production") {
		t.Fatalf("loadAndValidateRuntimeConfig() error = %v, want production metrics bind rejection", err)
	}
	if runtime != nil {
		t.Fatalf("loadAndValidateRuntimeConfig() runtime = %#v, want nil on validation error", runtime)
	}
}

func TestLoadAndValidateRuntimeConfigAllowsProductionLoopbackMetrics(t *testing.T) {
	originalDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(originalDefault) })

	t.Setenv("PACKMON_SERVER_MODE", "production")
	t.Setenv("PACKMON_TLS_CERT_FILE", "server.crt")
	t.Setenv("PACKMON_TLS_KEY_FILE", "server.key")
	t.Setenv("PACKMON_METRICS_HOST", "127.0.0.1")
	t.Setenv("PACKMON_METRICS_PORT", "9090")

	runtime, err := loadAndValidateRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndValidateRuntimeConfig() error = %v", err)
	}
	if runtime == nil {
		t.Fatal("loadAndValidateRuntimeConfig() runtime = nil")
	}
}

func TestLoadAndValidateRuntimeConfigInstallsConfiguredDefaultLogger(t *testing.T) {
	originalDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(originalDefault) })

	t.Setenv("PACKMON_SERVER_MODE", "development")
	t.Setenv("PACKMON_LOG_LEVEL", "warn")
	t.Setenv("PACKMON_LOG_FORMAT", "json")

	runtime, err := loadAndValidateRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndValidateRuntimeConfig() error = %v", err)
	}
	if slog.Default() != runtime.logger {
		t.Fatal("configured server logger was not installed as slog default")
	}
	if slog.Default().Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("default logger enabled info, want configured warn level")
	}
	if !slog.Default().Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("default logger disabled warn, want configured warn level")
	}
}

func TestVerifyProductionSchemaUsesVersionContextAndFailsClosed(t *testing.T) {
	originalVersion := readDatabaseMigrationVersionContext
	t.Cleanup(func() {
		readDatabaseMigrationVersionContext = originalVersion
	})

	versionErr := errors.New("version unavailable")
	tests := []struct {
		name        string
		version     uint
		dirty       bool
		versionErr  error
		wantVersion uint
		wantErrPart string
	}{
		{
			name:        "version read error",
			versionErr:  versionErr,
			wantErrPart: "schema version check failed: version unavailable",
		},
		{
			name:        "dirty schema",
			version:     7,
			dirty:       true,
			wantErrPart: "database schema is dirty at version 7",
		},
		{
			name:        "version mismatch",
			version:     uint(migrations.ExpectedVersion) - 1,
			wantErrPart: "schema version mismatch",
		},
		{
			name:        "expected schema",
			version:     uint(migrations.ExpectedVersion),
			wantVersion: uint(migrations.ExpectedVersion),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			readDatabaseMigrationVersionContext = func(ctx context.Context, dsn string) (uint, bool, error) {
				called = true
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("schema check context has no deadline")
				}
				return tt.version, tt.dirty, tt.versionErr
			}

			cfg := &config.Config{Server: config.ServerConfig{Mode: config.ModeProduction}}
			got, err := verifyProductionSchema(context.Background(), cfg, slog.Default())
			if !called {
				t.Fatal("readDatabaseMigrationVersionContext was not called")
			}
			if tt.wantErrPart == "" {
				if err != nil {
					t.Fatalf("verifyProductionSchema() error = %v", err)
				}
				if got != tt.wantVersion {
					t.Fatalf("verifyProductionSchema() version = %d, want %d", got, tt.wantVersion)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErrPart) {
				t.Fatalf("verifyProductionSchema() error = %v, want containing %q", err, tt.wantErrPart)
			}
		})
	}
}

func TestOpenRuntimeStoreDevelopmentUsesNoopStore(t *testing.T) {
	cfg := &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}
	opened, err := openRuntimeStore(context.Background(), cfg, slog.Default())
	if err != nil {
		t.Fatalf("openRuntimeStore(development) error = %v", err)
	}
	if _, ok := opened.store.(*noopStore); !ok {
		t.Fatalf("openRuntimeStore(development) store = %T, want *noopStore", opened.store)
	}
	if _, ok := opened.pinger.(*noopPinger); !ok {
		t.Fatalf("openRuntimeStore(development) pinger = %T, want *noopPinger", opened.pinger)
	}
}

func TestRuntimePostgresPoolConfigIncludesConnectTimeout(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{DB: config.DBConfig{
		MaxConns:       8,
		MinConns:       3,
		ConnectTimeout: 2 * time.Second,
	}}

	got := runtimePostgresPoolConfig(cfg)
	want := &pgstore.PoolConfig{
		MaxConns:       8,
		MinConns:       3,
		ConnectTimeout: 2 * time.Second,
	}
	if *got != *want {
		t.Fatalf("runtimePostgresPoolConfig() = %#v, want %#v", got, want)
	}
}

func TestBootstrapRuntimeDatabaseUsesStartupTimeoutForStoredState(t *testing.T) {
	store := &blockingAdminBootstrapStore{
		noopStore: newNoopStore(),
		ctxErr:    make(chan error, 1),
	}
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		DB:     config.DBConfig{ConnectTimeout: 25 * time.Millisecond},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime := &runtimeConfig{cfg: cfg, logger: logger}
	deadlineChecks := 0
	hooks := runtimeDatabaseBootstrapHooks{
		verifySchema: func(ctx context.Context, _ *config.Config, _ *slog.Logger) (uint, error) {
			assertStartupDeadline(t, ctx, cfg.DB.ConnectTimeout)
			deadlineChecks++
			return uint(migrations.ExpectedVersion), nil
		},
		openStore: func(ctx context.Context, _ *config.Config, _ *slog.Logger) (*runtimeStore, error) {
			assertStartupDeadline(t, ctx, cfg.DB.ConnectTimeout)
			deadlineChecks++
			return &runtimeStore{store: store, pinger: &noopPinger{}}, nil
		},
		applyState: applyStoredRuntimeState,
	}

	opened, _, err := bootstrapRuntimeDatabase(context.Background(), runtime, hooks)
	if opened != nil {
		t.Fatalf("bootstrapRuntimeDatabase() opened store = %#v, want nil on bootstrap timeout", opened)
	}
	if err == nil || !strings.Contains(err.Error(), "bootstrap admin auth") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrapRuntimeDatabase() error = %v, want bootstrap deadline exceeded", err)
	}
	if deadlineChecks != 2 {
		t.Fatalf("startup deadline checks = %d, want 2", deadlineChecks)
	}
	if err := <-store.ctxErr; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrap context error = %v, want deadline exceeded", err)
	}
}

func TestBootstrapRuntimeDatabaseUsesStartupTimeoutForFeedConfig(t *testing.T) {
	store := &blockingFeedConfigStore{
		noopStore: newNoopStore(),
		ctxErr:    make(chan error, 1),
	}
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		DB:     config.DBConfig{ConnectTimeout: 25 * time.Millisecond},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime := &runtimeConfig{cfg: cfg, logger: logger}
	hooks := runtimeDatabaseBootstrapHooks{
		verifySchema: func(context.Context, *config.Config, *slog.Logger) (uint, error) {
			return uint(migrations.ExpectedVersion), nil
		},
		openStore: func(context.Context, *config.Config, *slog.Logger) (*runtimeStore, error) {
			return &runtimeStore{store: store, pinger: &noopPinger{}}, nil
		},
		applyState: applyStoredRuntimeState,
	}

	opened, _, err := bootstrapRuntimeDatabase(context.Background(), runtime, hooks)
	if opened != nil {
		t.Fatalf("bootstrapRuntimeDatabase() opened store = %#v, want nil on feed config timeout", opened)
	}
	if err == nil || !strings.Contains(err.Error(), "apply stored feed config overrides") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrapRuntimeDatabase() error = %v, want feed config deadline exceeded", err)
	}
	if err := <-store.ctxErr; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("feed config context error = %v, want deadline exceeded", err)
	}
}

func TestBootstrapRuntimeDatabaseUsesStartupTimeoutForSystemSettings(t *testing.T) {
	store := &blockingSystemSettingsStore{
		noopStore: newNoopStore(),
		ctxErr:    make(chan error, 1),
	}
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		DB:     config.DBConfig{ConnectTimeout: 25 * time.Millisecond},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime := &runtimeConfig{cfg: cfg, logger: logger}
	hooks := runtimeDatabaseBootstrapHooks{
		verifySchema: func(context.Context, *config.Config, *slog.Logger) (uint, error) {
			return uint(migrations.ExpectedVersion), nil
		},
		openStore: func(context.Context, *config.Config, *slog.Logger) (*runtimeStore, error) {
			return &runtimeStore{store: store, pinger: &noopPinger{}}, nil
		},
		applyState: applyStoredRuntimeState,
	}

	opened, _, err := bootstrapRuntimeDatabase(context.Background(), runtime, hooks)
	if opened != nil {
		t.Fatalf("bootstrapRuntimeDatabase() opened store = %#v, want nil on system settings timeout", opened)
	}
	if err == nil || !strings.Contains(err.Error(), "apply stored system settings") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrapRuntimeDatabase() error = %v, want system settings deadline exceeded", err)
	}
	if err := <-store.ctxErr; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("system settings context error = %v, want deadline exceeded", err)
	}
}

func TestBootstrapRuntimeDatabaseDefersStartupRepairs(t *testing.T) {
	store := &blockingCriticalPathRepairStore{
		noopStore: newNoopStore(),
		started:   make(chan struct{}, 1),
		release:   make(chan struct{}),
		ctxErr:    make(chan error, 1),
	}
	t.Cleanup(func() { close(store.release) })

	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeProduction},
		DB:     config.DBConfig{ConnectTimeout: time.Second},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime := &runtimeConfig{cfg: cfg, logger: logger}
	hooks := runtimeDatabaseBootstrapHooks{
		verifySchema: func(context.Context, *config.Config, *slog.Logger) (uint, error) {
			return uint(migrations.ExpectedVersion), nil
		},
		openStore: func(context.Context, *config.Config, *slog.Logger) (*runtimeStore, error) {
			return &runtimeStore{store: store, pinger: &noopPinger{}}, nil
		},
		applyState: applyStoredRuntimeState,
	}

	done := make(chan error, 1)
	go func() {
		opened, _, err := bootstrapRuntimeDatabase(context.Background(), runtime, hooks)
		if opened != nil {
			_ = opened.store.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bootstrapRuntimeDatabase() error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("bootstrapRuntimeDatabase() blocked on best-effort startup repair")
	}

	select {
	case <-store.started:
		t.Fatal("startup repair ran on the bootstrap critical path")
	default:
	}
}

func TestBuildRuntimeServerRunsStartupRepairsWithRootContext(t *testing.T) {
	store := &blockingCriticalPathRepairStore{
		noopStore: newNoopStore(),
		started:   make(chan struct{}, 1),
		release:   make(chan struct{}),
		ctxErr:    make(chan error, 1),
	}
	t.Cleanup(func() { close(store.release) })

	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:            config.ModeDevelopment,
			ShutdownTimeout: time.Second,
		},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime := &runtimeConfig{cfg: cfg, logger: logger, devMode: true}

	runtimeServer, err := buildRuntimeServer(runtime, &runtimeStore{store: store, pinger: &noopPinger{}}, cfg.Feeds)
	if err != nil {
		t.Fatalf("buildRuntimeServer() error = %v", err)
	}

	select {
	case <-store.started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("startup repair did not start in the runtime background context")
	}

	runtimeServer.stop()
	if !runtimeServer.background.Wait() {
		t.Fatal("background services did not stop after root context cancellation")
	}
	if err := <-store.ctxErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("startup repair context error = %v, want root context cancellation", err)
	}
}

type blockingAdminBootstrapStore struct {
	*noopStore
	ctxErr chan error
}

func (s *blockingAdminBootstrapStore) GetAdminAuth(ctx context.Context) (*db.AdminAuth, error) {
	err := startupDeadlineError(ctx)
	s.ctxErr <- err
	return nil, err
}

type blockingFeedConfigStore struct {
	*noopStore
	ctxErr chan error
}

func (s *blockingFeedConfigStore) ListFeedConfigs(ctx context.Context) ([]db.FeedConfig, error) {
	err := startupDeadlineError(ctx)
	s.ctxErr <- err
	return nil, err
}

type blockingSystemSettingsStore struct {
	*noopStore
	ctxErr chan error
}

func (s *blockingSystemSettingsStore) GetSystemSettings(ctx context.Context) (*db.SystemSettings, error) {
	err := startupDeadlineError(ctx)
	s.ctxErr <- err
	return nil, err
}

type blockingCriticalPathRepairStore struct {
	*noopStore
	started chan struct{}
	release chan struct{}
	ctxErr  chan error
}

func (s *blockingCriticalPathRepairStore) RepairCaseInsensitivePackageNames(ctx context.Context) (int, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}

	select {
	case <-s.release:
		s.ctxErr <- nil
		return 0, nil
	case <-ctx.Done():
		err := ctx.Err()
		s.ctxErr <- err
		return 0, err
	}
}

func startupDeadlineError(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("startup context has no deadline")
	}
	return context.DeadlineExceeded
}

func assertStartupDeadline(t *testing.T, ctx context.Context, timeout time.Duration) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("startup context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > timeout {
		t.Fatalf("startup deadline remaining = %s, want within configured %s", remaining, timeout)
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

func TestRunMigrateUsesStartupTimeoutForMigration(t *testing.T) {
	originalRun := runDatabaseMigrationsContext
	originalVersion := readDatabaseMigrationVersionContext
	t.Cleanup(func() {
		runDatabaseMigrationsContext = originalRun
		readDatabaseMigrationVersionContext = originalVersion
	})

	t.Setenv("PACKMON_DB_CONNECT_TIMEOUT", "25ms")
	t.Setenv("PACKMON_LOG_LEVEL", "error")

	configuredTimeout := 25 * time.Millisecond
	deadlineSeen := make(chan time.Duration, 1)
	runDatabaseMigrationsContext = func(ctx context.Context, _ string) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("migration context has no deadline")
		}
		deadlineSeen <- time.Until(deadline)
		return context.DeadlineExceeded
	}

	versionCalled := false
	readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
		versionCalled = true
		return 0, false, nil
	}

	err := runMigrate()
	if err == nil || !strings.Contains(err.Error(), "migrations failed: context deadline exceeded") {
		t.Fatalf("runMigrate() error = %v, want context deadline exceeded migration failure", err)
	}
	if versionCalled {
		t.Fatal("readDatabaseMigrationVersionContext called after migration timeout")
	}
	if remaining := <-deadlineSeen; remaining <= 0 || remaining > configuredTimeout {
		t.Fatalf("migration context deadline remaining = %s, want within configured timeout %s", remaining, configuredTimeout)
	}
}

func TestRunMigrateAddsDriverConnectTimeoutFromConfiguredStartupTimeout(t *testing.T) {
	originalRun := runDatabaseMigrationsContext
	originalVersion := readDatabaseMigrationVersionContext
	t.Cleanup(func() {
		runDatabaseMigrationsContext = originalRun
		readDatabaseMigrationVersionContext = originalVersion
	})

	t.Setenv("PACKMON_DB_CONNECT_TIMEOUT", "1500ms")
	t.Setenv("PACKMON_LOG_LEVEL", "error")

	var migrationDSN string
	runDatabaseMigrationsContext = func(_ context.Context, dsn string) error {
		migrationDSN = dsn
		return errors.New("stop after dsn capture")
	}
	readDatabaseMigrationVersionContext = func(_ context.Context, _ string) (uint, bool, error) {
		t.Fatal("readDatabaseMigrationVersionContext called after migration failure")
		return 0, false, nil
	}

	err := runMigrate()
	if err == nil || !strings.Contains(err.Error(), "stop after dsn capture") {
		t.Fatalf("runMigrate() error = %v, want captured migration error", err)
	}
	if !strings.Contains(migrationDSN, "connect_timeout=2") {
		t.Fatalf("migration DSN = %q, want connect_timeout rounded up from configured DB timeout", migrationDSN)
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

	services, err := startBackgroundServices(ctx, cfg, config.NewRuntimeSettingsFromConfig(cfg), cfg.Feeds, newNoopStore(), slog.Default())
	if err != nil {
		t.Fatalf("startBackgroundServices() error = %v", err)
	}
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
	if _, _, err := services.ResetFeedConfig(context.Background(), "osv"); err != nil {
		t.Fatalf("nil ResetFeedConfig error = %v", err)
	}
	if err := services.restartQueueProcessor(); err != nil {
		t.Fatalf("nil restartQueueProcessor error = %v", err)
	}
	services.Wait()

	services = &backgroundServices{cfg: &config.Config{Server: config.ServerConfig{Mode: config.ModeDevelopment}}}
	if err := services.restartQueueProcessor(); err != nil {
		t.Fatalf("development restartQueueProcessor error = %v", err)
	}
}
