package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	pgstore "github.com/8linkz-sec/packmon/internal/db/postgres"
	migrations "github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
	"github.com/8linkz-sec/packmon/internal/devstore"
	"github.com/8linkz-sec/packmon/internal/health"
	"github.com/8linkz-sec/packmon/internal/logsafe"
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

const productionFieldEncryptionKeyBytes = 32

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("packmon-server %s (%s) built %s %s/%s\n",
				version, commit, date, runtime.GOOS, runtime.GOARCH)
			return
		case "migrate":
			if err := runMigrate(); err != nil {
				logFatalError("packmon-server migrate", "packmon-server migrate failed", err)
				os.Exit(1)
			}
			return
		case "privacy":
			if err := runPrivacy(os.Args[2:]); err != nil {
				logFatalError("packmon-server privacy", "packmon-server privacy command failed", err)
				os.Exit(1)
			}
			return
		}
	}

	if err := run(); err != nil {
		logFatalError("packmon-server", "packmon-server startup failed", err)
		os.Exit(1)
	}
}

type configuredFatalError struct {
	err    error
	logger *slog.Logger
}

func (e *configuredFatalError) Error() string {
	return e.err.Error()
}

func (e *configuredFatalError) Unwrap() error {
	return e.err
}

func withConfiguredFatalLogger(err error, logger *slog.Logger) error {
	if err == nil || logger == nil {
		return err
	}
	var existing *configuredFatalError
	if errors.As(err, &existing) {
		return err
	}
	return &configuredFatalError{err: err, logger: logger}
}

func logFatalError(stderrPrefix, message string, err error) {
	var fatalErr *configuredFatalError
	if errors.As(err, &fatalErr) && fatalErr.logger != nil {
		fatalErr.logger.Error(message,
			slog.String("error", logsafe.BoundedDiagnosticValue(fatalErr.err.Error(), 512)),
		)
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", stderrPrefix, err)
}

var (
	runDatabaseMigrationsContext        = migrations.RunContext
	readDatabaseMigrationVersionContext = migrations.VersionContext
)

// runMigrate loads config, runs all pending migrations, and exits.
func runMigrate() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := newLogger(cfg.Log)
	timeout := databaseStartupTimeout(cfg)
	dsn, err := dsnWithConnectTimeout(cfg.DB.DSN(), timeout)
	if err != nil {
		return withConfiguredFatalLogger(fmt.Errorf("prepare migration DSN: %w", err), logger)
	}

	logger.Info("running database migrations",
		slog.Uint64("expected_version", uint64(migrations.ExpectedVersion)),
	)

	dbCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := runDatabaseMigrationsContext(dbCtx, dsn); err != nil {
		return withConfiguredFatalLogger(fmt.Errorf("migrations failed: %w", err), logger)
	}

	ver, dirty, err := readDatabaseMigrationVersionContext(dbCtx, dsn)
	if err != nil {
		return withConfiguredFatalLogger(fmt.Errorf("failed to read schema version after migration: %w", err), logger)
	}

	if dirty {
		return withConfiguredFatalLogger(fmt.Errorf("schema is in dirty state after migration (version %d)", ver), logger)
	}

	logger.Info("migrations completed successfully",
		slog.Uint64("schema_version", uint64(ver)),
	)

	return nil
}

func run() error {
	runtimeCfg, err := loadAndValidateRuntimeConfig()
	if err != nil {
		return err
	}
	cfg := runtimeCfg.cfg
	logger := runtimeCfg.logger

	logRuntimeConfigWarnings(runtimeCfg)

	runtimeStore, defaultFeeds, err := bootstrapRuntimeDatabase(context.Background(), runtimeCfg, runtimeDatabaseBootstrapHooks{})
	if err != nil {
		return withConfiguredFatalLogger(err, logger)
	}

	warnIfMetricsEndpointExposed(cfg, logger)
	logRuntimeStarting(runtimeCfg)

	runtime, err := buildRuntimeServer(runtimeCfg, runtimeStore, defaultFeeds)
	if err != nil {
		return withConfiguredFatalLogger(err, logger)
	}
	logger.Info("server running, waiting for shutdown signal")
	err = runtime.srv.Run(runtime.rootCtx)
	if err := shutdownRuntime(runtime, err); err != nil {
		return withConfiguredFatalLogger(err, logger)
	}
	return nil
}

type runtimeConfig struct {
	cfg           *config.Config
	logger        *slog.Logger
	devMode       bool
	schemaVersion uint
}

type runtimeStore struct {
	store  server.Store
	pinger health.Pinger
}

type runtimeServer struct {
	rootCtx    context.Context
	stop       context.CancelFunc
	logger     *slog.Logger
	store      db.Store
	background *backgroundServices
	srv        *server.Server
}

type runtimeDatabaseBootstrapHooks struct {
	verifySchema func(context.Context, *config.Config, *slog.Logger) (uint, error)
	openStore    func(context.Context, *config.Config, *slog.Logger) (*runtimeStore, error)
	applyState   func(context.Context, *config.Config, db.Store, *slog.Logger) (config.FeedsConfig, error)
}

func (h runtimeDatabaseBootstrapHooks) withDefaults() runtimeDatabaseBootstrapHooks {
	if h.verifySchema == nil {
		h.verifySchema = verifyProductionSchema
	}
	if h.openStore == nil {
		h.openStore = openRuntimeStore
	}
	if h.applyState == nil {
		h.applyState = applyStoredRuntimeState
	}
	return h
}

func bootstrapRuntimeDatabase(parent context.Context, runtime *runtimeConfig, hooks runtimeDatabaseBootstrapHooks) (*runtimeStore, config.FeedsConfig, error) {
	hooks = hooks.withDefaults()
	dbCtx, cancel := databaseStartupContext(parent, runtime.cfg)
	defer cancel()

	ver, err := hooks.verifySchema(dbCtx, runtime.cfg, runtime.logger)
	if err != nil {
		return nil, config.FeedsConfig{}, err
	}
	runtime.schemaVersion = ver

	opened, err := hooks.openStore(dbCtx, runtime.cfg, runtime.logger)
	if err != nil {
		return nil, config.FeedsConfig{}, err
	}

	defaultFeeds, err := hooks.applyState(dbCtx, runtime.cfg, opened.store, runtime.logger)
	if err != nil {
		_ = opened.store.Close()
		return nil, config.FeedsConfig{}, err
	}
	return opened, defaultFeeds, nil
}

func loadAndValidateRuntimeConfig() (*runtimeConfig, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	logger := newLogger(cfg.Log)
	slog.SetDefault(logger)
	if err := cfg.ValidateTransportSecurity(); err != nil {
		return nil, withConfiguredFatalLogger(err, logger)
	}
	if err := cfg.ValidateMetricsExposure(); err != nil {
		return nil, withConfiguredFatalLogger(err, logger)
	}

	return &runtimeConfig{
		cfg:           cfg,
		logger:        logger,
		devMode:       cfg.IsDevelopment(),
		schemaVersion: uint(migrations.ExpectedVersion),
	}, nil
}

func logRuntimeConfigWarnings(runtime *runtimeConfig) {
	cfg := runtime.cfg
	logger := runtime.logger
	if runtime.devMode {
		logger.Warn("running in DEVELOPMENT mode -- API authentication is relaxed and an in-memory store is used; never expose this mode on an untrusted network")
	}
	if !runtime.devMode && cfg.Server.AllowInsecureLocalHTTP {
		logger.Warn("production transport security relaxed for local-only HTTP -- keep the Docker port bound to loopback and do not expose this server on a network")
	}
	if !runtime.devMode && strings.TrimSpace(cfg.Server.PublicHost) == "" {
		logger.Warn("PACKMON_SERVER_PUBLIC_HOST is not set -- HTTPS redirect is disabled for non-loopback hosts")
	}
}

func verifyProductionSchema(parent context.Context, cfg *config.Config, logger *slog.Logger) (uint, error) {
	ver := uint(migrations.ExpectedVersion)
	if cfg.IsDevelopment() {
		return ver, nil
	}

	// Migrations are an explicit operational step; normal startup only verifies
	// the schema version before opening listeners.
	dsn := cfg.DB.DSN()
	dbCtx, cancel := databaseStartupContext(parent, cfg)
	ver, dirty, err := readDatabaseMigrationVersionContext(dbCtx, dsn)
	cancel()
	if err != nil {
		logger.Error("failed to read database schema version -- run 'packmon-server migrate' first",
			slog.String("error", err.Error()),
		)
		return ver, fmt.Errorf("schema version check failed: %w", err)
	}
	if dirty {
		logger.Error("database schema is in dirty state -- manual intervention required",
			slog.Uint64("schema_version", uint64(ver)),
		)
		return ver, fmt.Errorf("database schema is dirty at version %d", ver)
	}
	if ver != uint(migrations.ExpectedVersion) {
		logger.Error("database schema version mismatch -- run 'packmon-server migrate'",
			slog.Uint64("current_version", uint64(ver)),
			slog.Uint64("expected_version", uint64(migrations.ExpectedVersion)),
		)
		return ver, fmt.Errorf("schema version mismatch: database is at %d, binary expects %d", ver, migrations.ExpectedVersion)
	}
	return ver, nil
}

func warnIfMetricsEndpointExposed(cfg *config.Config, logger *slog.Logger) {
	metricsHost := strings.ToLower(strings.TrimSpace(cfg.Metrics.Host))
	if metricsHost != "127.0.0.1" && metricsHost != "::1" && metricsHost != "localhost" && metricsHost != "" {
		logger.Warn("metrics endpoint bound to non-localhost address, consider restricting access",
			slog.String("metrics_host", cfg.Metrics.Host),
			slog.String("metrics_addr", cfg.Metrics.Addr()),
		)
	}
}

func logRuntimeStarting(runtime *runtimeConfig) {
	runtime.logger.Info("packmon-server starting",
		slog.String("version", version),
		slog.String("commit", commit),
		slog.String("mode", string(runtime.cfg.Server.Mode)),
		slog.Uint64("schema_version", uint64(runtime.schemaVersion)),
	)
}

func openRuntimeStore(parent context.Context, cfg *config.Config, logger *slog.Logger) (*runtimeStore, error) {
	encryptor, err := secret.NewFieldEncryptor(cfg.Admin.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create field encryptor: %w", err)
	}
	if err := requireProductionFieldEncryption(cfg, encryptor); err != nil {
		logger.Error("feed API-key encryption is required in production")
		return nil, err
	}
	if err := requireProductionAdminAuditHMACKey(cfg); err != nil {
		logger.Error("admin audit HMAC key is required in production")
		return nil, err
	}
	if err := configureAdminAuditDigestHMACKey(cfg); err != nil {
		return nil, err
	}
	if cfg.IsDevelopment() && !encryptor.Active() {
		logger.Warn("PACKMON_ENCRYPTION_KEY is not set -- development feed API keys use plaintext in-memory storage")
	}

	if cfg.IsDevelopment() {
		return &runtimeStore{
			store:  devstore.NewStore(),
			pinger: &devstore.Pinger{},
		}, nil
	}

	dbCtx, cancel := databaseStartupContext(parent, cfg)
	pg, err := pgstore.New(dbCtx, cfg.DB.DSN(), encryptor, runtimePostgresPoolConfig(cfg))
	cancel()
	if err != nil {
		return nil, fmt.Errorf("open postgres store: %w", err)
	}
	return &runtimeStore{store: pg, pinger: pg}, nil
}

func runtimePostgresPoolConfig(cfg *config.Config) *pgstore.PoolConfig {
	if cfg == nil {
		return &pgstore.PoolConfig{}
	}
	return &pgstore.PoolConfig{
		MaxConns:       cfg.DB.MaxConns,
		MinConns:       cfg.DB.MinConns,
		ConnectTimeout: cfg.DB.ConnectTimeout,
	}
}

func applyStoredRuntimeState(ctx context.Context, cfg *config.Config, store db.Store, logger *slog.Logger) (config.FeedsConfig, error) {
	if err := auth.BootstrapAdmin(ctx, newAdminBootstrapStore(store), cfg.Admin.InitialPassword, logger); err != nil {
		return config.FeedsConfig{}, fmt.Errorf("bootstrap admin auth: %w", err)
	}

	defaultFeeds := cfg.Feeds
	if err := applyStoredFeedConfigOverrides(ctx, cfg, store, logger); err != nil {
		return config.FeedsConfig{}, fmt.Errorf("apply stored feed config overrides: %w", err)
	}
	if err := applyStoredSystemSettings(ctx, cfg, store, logger); err != nil {
		return config.FeedsConfig{}, fmt.Errorf("apply stored system settings: %w", err)
	}

	return defaultFeeds, nil
}

func buildRuntimeServer(runtime *runtimeConfig, opened *runtimeStore, defaultFeeds config.FeedsConfig) (*runtimeServer, error) {
	cfg := runtime.cfg
	logger := runtime.logger

	// Use signal.NotifyContext so SIGTERM/SIGINT cancels the root context
	// immediately. This lets feed syncers, queue workers, and the HTTP
	// server all observe ctx.Done() at the same time.
	rootCtx, stop := serverSignalContext(context.Background())

	armHardExitDeadline(rootCtx, cfg, logger)

	runtimeSettings := config.NewRuntimeSettingsFromConfig(cfg)
	background, err := startBackgroundServices(rootCtx, cfg, runtimeSettings, defaultFeeds, opened.store, logger)
	if err != nil {
		stop()
		return nil, err
	}
	background.startStartupRepairs(opened.store)
	syncFeed := newFeedSyncTrigger(cfg, opened.store, logger, background)
	applyFeedConfig := background.ApplyFeedConfig
	resetFeedConfig := background.ResetFeedConfig

	build := server.BuildInfo{
		Version:       version,
		Commit:        commit,
		Date:          date,
		SchemaVersion: runtime.schemaVersion,
	}

	srv := server.NewWithRuntime(rootCtx, cfg, opened.store, opened.pinger, logger, build, runtimeSettings, syncFeed, applyFeedConfig, resetFeedConfig)
	return &runtimeServer{
		rootCtx:    rootCtx,
		stop:       stop,
		logger:     logger,
		store:      opened.store,
		background: background,
		srv:        srv,
	}, nil
}

func armHardExitDeadline(rootCtx context.Context, cfg *config.Config, logger *slog.Logger) {
	// Hard exit deadline: if the process is STILL alive 8 seconds after
	// SIGTERM, force-exit. This is a safety net for any goroutine that
	// ignores context cancellation (e.g. stuck git clone, blocked DB write).
	go func() {
		<-rootCtx.Done()
		delay := effectiveHardExitDelay(cfg)
		logger.Info("shutdown: hard exit deadline set", slog.Duration("timeout", delay))
		time.Sleep(delay)
		logger.Error("shutdown: hard exit deadline exceeded, forcing os.Exit(1)")
		hardExit(1) //nolint:revive // intentional hard exit
	}()
}

func shutdownRuntime(runtime *runtimeServer, runErr error) error {
	logger := runtime.logger
	logger.Info("shutdown: HTTP servers stopped")

	runtime.stop() // ensure context is cancelled if Run returned due to error

	logger.Info("shutdown: waiting for background services")
	if runtime.background.Wait() {
		logger.Info("shutdown: background services done")
	} else {
		logger.Warn("shutdown: background services abandoned")
	}

	logger.Info("shutdown: closing database pool")
	// pool.Close() does not accept a context, so there is no way to
	// enforce a timeout here. The hard exit deadline goroutine above
	// already provides a safety net if Close blocks indefinitely.
	_ = runtime.store.Close()
	logger.Info("shutdown: complete")

	return runErr
}

func requireProductionFieldEncryption(cfg *config.Config, encryptor *secret.FieldEncryptor) error {
	if cfg == nil || cfg.IsDevelopment() {
		return nil
	}
	if encryptor == nil || !encryptor.Active() || strings.TrimSpace(cfg.Admin.EncryptionKey) == "" {
		return fmt.Errorf("PACKMON_ENCRYPTION_KEY is required in production to protect feed API keys at rest")
	}
	rawKey, err := base64.StdEncoding.DecodeString(cfg.Admin.EncryptionKey)
	if err != nil {
		return fmt.Errorf("PACKMON_ENCRYPTION_KEY must be base64-encoded %d random bytes in production: %w", productionFieldEncryptionKeyBytes, err)
	}
	if len(rawKey) != productionFieldEncryptionKeyBytes {
		return fmt.Errorf("PACKMON_ENCRYPTION_KEY must decode to %d bytes in production (got %d)", productionFieldEncryptionKeyBytes, len(rawKey))
	}
	return nil
}

func requireProductionAdminAuditHMACKey(cfg *config.Config) error {
	if cfg == nil || cfg.IsDevelopment() {
		return nil
	}
	if strings.TrimSpace(cfg.Admin.AdminAuditHMACKey) == "" {
		return fmt.Errorf("PACKMON_ADMIN_AUDIT_HMAC_KEY is required in production to protect admin audit digests")
	}
	rawKey, err := base64.StdEncoding.DecodeString(cfg.Admin.AdminAuditHMACKey)
	if err != nil {
		return fmt.Errorf("PACKMON_ADMIN_AUDIT_HMAC_KEY must be base64-encoded %d random bytes in production: %w", productionFieldEncryptionKeyBytes, err)
	}
	if len(rawKey) != productionFieldEncryptionKeyBytes {
		return fmt.Errorf("PACKMON_ADMIN_AUDIT_HMAC_KEY must decode to %d bytes in production (got %d)", productionFieldEncryptionKeyBytes, len(rawKey))
	}
	return nil
}

func configureAdminAuditDigestHMACKey(cfg *config.Config) error {
	if cfg == nil || strings.TrimSpace(cfg.Admin.AdminAuditHMACKey) == "" {
		db.ClearAdminAuditDigestHMACKey()
		return nil
	}
	rawKey, err := base64.StdEncoding.DecodeString(cfg.Admin.AdminAuditHMACKey)
	if err != nil {
		return fmt.Errorf("configure admin audit HMAC key: %w", err)
	}
	if len(rawKey) != productionFieldEncryptionKeyBytes {
		return fmt.Errorf("configure admin audit HMAC key: key must decode to %d bytes", productionFieldEncryptionKeyBytes)
	}
	db.SetAdminAuditDigestHMACKey(rawKey)
	return nil
}

func databaseStartupContext(parent context.Context, cfg *config.Config) (context.Context, context.CancelFunc) {
	timeout := databaseStartupTimeout(cfg)
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, timeout)
}

func databaseStartupTimeout(cfg *config.Config) time.Duration {
	timeout := defaultDatabaseStartupTimeout
	if cfg != nil && cfg.DB.ConnectTimeout > 0 {
		timeout = cfg.DB.ConnectTimeout
	}
	return timeout
}

func dsnWithConnectTimeout(dsn string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		return dsn, nil
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	if strings.TrimSpace(query.Get("connect_timeout")) != "" {
		return dsn, nil
	}
	seconds := timeout / time.Second
	if timeout%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	query.Set("connect_timeout", strconv.FormatInt(int64(seconds), 10))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
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

	return slog.New(handler).With("service", "packmon-server")
}
