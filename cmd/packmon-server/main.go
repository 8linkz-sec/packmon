package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	pgstore "github.com/8linkz-sec/packmon/internal/db/postgres"
	migrations "github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
	"github.com/8linkz-sec/packmon/internal/health"
	"github.com/8linkz-sec/packmon/internal/secret"
	"github.com/8linkz-sec/packmon/internal/server"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	serverSignalContext = func(parent context.Context) (context.Context, context.CancelFunc) {
		return signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
	}
	hardExit = os.Exit

	defaultHardExitDelay = 8 * time.Second
	hardExitDelay        = defaultHardExitDelay

	defaultDatabaseStartupTimeout = 10 * time.Second
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("packmon-server %s (%s) built %s %s/%s\n",
				version, commit, date, runtime.GOOS, runtime.GOARCH)
			return
		case "migrate":
			if err := runMigrate(); err != nil {
				fmt.Fprintf(os.Stderr, "packmon-server migrate: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "packmon-server: %v\n", err)
		os.Exit(1)
	}
}

var (
	runDatabaseMigrations        = migrations.Run
	readDatabaseMigrationVersion = migrations.Version
)

// runMigrate loads config, runs all pending migrations, and exits.
func runMigrate() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := newLogger(cfg.Log)
	dsn := cfg.DB.DSN()

	logger.Info("running database migrations",
		slog.Uint64("expected_version", uint64(migrations.ExpectedVersion)),
	)

	if err := runDatabaseMigrations(dsn); err != nil {
		return fmt.Errorf("migrations failed: %w", err)
	}

	ver, dirty, err := readDatabaseMigrationVersion(dsn)
	if err != nil {
		return fmt.Errorf("failed to read schema version after migration: %w", err)
	}

	if dirty {
		return fmt.Errorf("schema is in dirty state after migration (version %d)", ver)
	}

	logger.Info("migrations completed successfully",
		slog.Uint64("schema_version", uint64(ver)),
	)

	return nil
}

func run() error {
	// Load configuration from environment.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Set up structured logger.
	logger := newLogger(cfg.Log)

	// Fail closed: refuse to start in production without transport security
	// (in-app TLS or a trusted reverse proxy), so bearer tokens never travel
	// over cleartext on the network.
	if err := cfg.ValidateTransportSecurity(); err != nil {
		return err
	}

	devMode := cfg.IsDevelopment()
	ver := uint(migrations.ExpectedVersion)
	if devMode {
		logger.Warn("running in DEVELOPMENT mode -- API authentication is relaxed and an in-memory store is used; never expose this mode on an untrusted network")
	}
	if !devMode && cfg.Server.AllowInsecureLocalHTTP {
		logger.Warn("production transport security relaxed for local-only HTTP -- keep the Docker port bound to loopback and do not expose this server on a network")
	}
	if !devMode && strings.TrimSpace(cfg.Server.PublicHost) == "" {
		logger.Warn("PACKMON_SERVER_PUBLIC_HOST is not set -- HTTPS redirect is disabled for non-loopback hosts")
	}
	if !devMode {
		// Verify database schema version before starting the server.
		// Migrations must be run separately via "packmon-server migrate" (DE-27).
		dsn := cfg.DB.DSN()
		dbCtx, cancel := databaseStartupContext(context.Background(), cfg)
		ver, dirty, err := migrations.VersionContext(dbCtx, dsn)
		cancel()
		if err != nil {
			logger.Error("failed to read database schema version -- run 'packmon-server migrate' first",
				slog.String("error", err.Error()),
			)
			return fmt.Errorf("schema version check failed: %w", err)
		}
		if dirty {
			logger.Error("database schema is in dirty state -- manual intervention required",
				slog.Uint64("schema_version", uint64(ver)),
			)
			return fmt.Errorf("database schema is dirty at version %d", ver)
		}
		if ver != uint(migrations.ExpectedVersion) {
			logger.Error("database schema version mismatch -- run 'packmon-server migrate'",
				slog.Uint64("current_version", uint64(ver)),
				slog.Uint64("expected_version", uint64(migrations.ExpectedVersion)),
			)
			return fmt.Errorf("schema version mismatch: database is at %d, binary expects %d", ver, migrations.ExpectedVersion)
		}
	}

	// Warn if the metrics endpoint is bound to a non-localhost address,
	// which could expose operational intelligence to untrusted networks.
	metricsHost := strings.ToLower(strings.TrimSpace(cfg.Metrics.Host))
	if metricsHost != "127.0.0.1" && metricsHost != "::1" && metricsHost != "localhost" && metricsHost != "" {
		logger.Warn("metrics endpoint bound to non-localhost address, consider restricting access",
			slog.String("metrics_host", cfg.Metrics.Host),
			slog.String("metrics_addr", cfg.Metrics.Addr()),
		)
	}

	logger.Info("packmon-server starting",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("mode", string(cfg.Server.Mode)),
		slog.Uint64("schema_version", uint64(ver)),
	)

	var (
		store  db.Store
		pinger health.Pinger
	)

	// Create field encryptor for sensitive at-rest data (feed API keys).
	encryptor, err := secret.NewFieldEncryptor(cfg.Admin.EncryptionKey)
	if err != nil {
		return fmt.Errorf("create field encryptor: %w", err)
	}
	if err := requireProductionFieldEncryption(cfg, encryptor); err != nil {
		logger.Error("feed API-key encryption is required in production")
		return err
	}
	if devMode && !encryptor.Active() {
		logger.Warn("PACKMON_ENCRYPTION_KEY is not set -- development feed API keys use plaintext in-memory storage")
	}

	if devMode {
		store = newNoopStore()
		pinger = &noopPinger{}
	} else {
		dbCtx, cancel := databaseStartupContext(context.Background(), cfg)
		pg, err := pgstore.New(dbCtx, cfg.DB.DSN(), encryptor, &pgstore.PoolConfig{
			MaxConns: cfg.DB.MaxConns,
			MinConns: cfg.DB.MinConns,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("open postgres store: %w", err)
		}
		store = pg
		pinger = pg
	}
	// NOTE: store.Close() is called explicitly during shutdown, not via defer,
	// to prevent blocking when orphaned goroutines hold DB connections.

	if err := auth.BootstrapAdmin(context.Background(), store, cfg.Admin.InitialPassword, logger); err != nil {
		return fmt.Errorf("bootstrap admin auth: %w", err)
	}

	defaultFeeds := cfg.Feeds
	if err := applyStoredFeedConfigOverrides(context.Background(), cfg, store, logger); err != nil {
		return fmt.Errorf("apply stored feed config overrides: %w", err)
	}
	if err := applyStoredSystemSettings(context.Background(), cfg, store, logger); err != nil {
		return fmt.Errorf("apply stored system settings: %w", err)
	}
	runStartupRepairs(context.Background(), store, logger)

	build := server.BuildInfo{
		Version:       version,
		Commit:        commit,
		Date:          date,
		SchemaVersion: ver,
	}

	// Use signal.NotifyContext so SIGTERM/SIGINT cancels the root context
	// immediately. This lets feed syncers, queue workers, and the HTTP
	// server all observe ctx.Done() at the same time.
	rootCtx, stop := serverSignalContext(context.Background())
	defer stop()

	// Hard exit deadline: if the process is STILL alive 8 seconds after
	// SIGTERM, force-exit. This is a safety net for any goroutine that
	// ignores context cancellation (e.g. stuck git clone, blocked DB write).
	go func() {
		<-rootCtx.Done()
		delay := effectiveHardExitDelay(cfg)
		logger.Info("shutdown: hard exit deadline set", slog.String("timeout", delay.String()))
		time.Sleep(delay)
		logger.Error("shutdown: hard exit deadline exceeded, forcing os.Exit(1)")
		hardExit(1) //nolint:revive // intentional hard exit
	}()

	background := startBackgroundServices(rootCtx, cfg, defaultFeeds, store, logger)
	syncFeed := newFeedSyncTrigger(cfg, store, logger, background)
	applyFeedConfig := background.ApplyFeedConfig
	resetFeedConfig := background.ResetFeedConfig

	srv := server.New(rootCtx, cfg, store, pinger, logger, build, syncFeed, applyFeedConfig, resetFeedConfig)

	logger.Info("server running, waiting for shutdown signal")
	err = srv.Run(rootCtx)
	logger.Info("shutdown: HTTP servers stopped")

	stop() // ensure context is cancelled if Run returned due to error

	logger.Info("shutdown: waiting for background services")
	if background.Wait() {
		logger.Info("shutdown: background services done")
	} else {
		logger.Warn("shutdown: background services abandoned")
	}

	logger.Info("shutdown: closing database pool")
	// pool.Close() does not accept a context, so there is no way to
	// enforce a timeout here. The hard exit deadline goroutine above
	// already provides a safety net if Close blocks indefinitely.
	_ = store.Close()
	logger.Info("shutdown: complete")

	return err
}

func requireProductionFieldEncryption(cfg *config.Config, encryptor *secret.FieldEncryptor) error {
	if cfg == nil || cfg.IsDevelopment() {
		return nil
	}
	if encryptor == nil || !encryptor.Active() {
		return fmt.Errorf("PACKMON_ENCRYPTION_KEY is required in production to protect feed API keys at rest")
	}
	return nil
}

func databaseStartupContext(parent context.Context, cfg *config.Config) (context.Context, context.CancelFunc) {
	timeout := defaultDatabaseStartupTimeout
	if cfg != nil && cfg.DB.ConnectTimeout > 0 {
		timeout = cfg.DB.ConnectTimeout
	}
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, timeout)
}

func effectiveHardExitDelay(cfg *config.Config) time.Duration {
	// Tests may override hardExitDelay to a short duration. Preserve explicit
	// overrides while making the production default exceed graceful shutdown.
	if hardExitDelay != defaultHardExitDelay {
		return hardExitDelay
	}
	if cfg == nil || cfg.Server.ShutdownTimeout <= 0 {
		return defaultHardExitDelay
	}
	minimum := cfg.Server.ShutdownTimeout + 5*time.Second
	if minimum > defaultHardExitDelay {
		return minimum
	}
	return defaultHardExitDelay
}

// newLogger creates an slog.Logger based on the log configuration.
func newLogger(lc config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(lc.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if strings.ToLower(lc.Format) == "console" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
