// Package server provides the HTTP server for the Packmon feed server.
// It wires middleware, routes, and a separate metrics server, and handles
// graceful shutdown on SIGTERM/SIGINT.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/8linkz-sec/packmon/internal/api/admin"
	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/health"
	"github.com/8linkz-sec/packmon/internal/httpsecurity"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/server/middleware"
	"github.com/8linkz-sec/packmon/internal/telemetry"
)

// Server is the top-level HTTP server for Packmon. It manages two
// listeners: the main API server and a separate metrics server.
type Server struct {
	cfg     *config.Config
	store   db.Store
	pinger  health.Pinger
	logger  *slog.Logger
	build   BuildInfo
	main    *http.Server
	metrics *http.Server
	health  *health.Checker
}

// Store is the full server persistence boundary required by route wiring and
// the metrics endpoint.
type Store interface {
	db.Store
	telemetry.MetricsStore
}

// New creates a Server with all middleware and routes wired up.
// The caller must provide a Store implementation and a Pinger for
// health checks (typically the same pgxpool.Pool satisfies both).
func New(
	ctx context.Context,
	cfg *config.Config,
	store Store,
	pinger health.Pinger,
	logger *slog.Logger,
	build BuildInfo,
	syncFeed admin.FeedSyncFunc,
	applyFeedConfig admin.FeedConfigApplyFunc,
	resetFeedConfig admin.FeedConfigResetFunc,
) *Server {
	return NewWithRuntime(ctx, cfg, store, pinger, logger, build, config.NewRuntimeSettingsFromConfig(cfg), syncFeed, applyFeedConfig, resetFeedConfig)
}

// NewWithRuntime creates a Server that shares the supplied runtime settings
// holder with other process components such as background services.
func NewWithRuntime(
	ctx context.Context,
	cfg *config.Config,
	store Store,
	pinger health.Pinger,
	logger *slog.Logger,
	build BuildInfo,
	runtime *config.RuntimeSettings,
	syncFeed admin.FeedSyncFunc,
	applyFeedConfig admin.FeedConfigApplyFunc,
	resetFeedConfig admin.FeedConfigResetFunc,
) *Server {
	devMode := cfg.IsDevelopment()

	if runtime == nil {
		runtime = config.NewRuntimeSettingsFromConfig(cfg)
	}

	// Session manager for admin authentication. The context controls the
	// lifetime of the session cleanup goroutine.
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, cfg.Admin.SessionTimeout, cfg.Admin.IdleTimeout, sessionCookieSecure(cfg))

	// -- Build middleware chain ------------------------------------------------
	// Order matters: outermost middleware runs first.
	// TrustedClientIP -> Telemetry -> SecurityHeaders -> Correlation -> Recovery -> Logging -> RateLimit -> UserAgent -> Auth -> APIKeyRateLimit -> Session -> Handler
	registry := telemetry.Default()
	registry.SetBuildInfo(telemetry.BuildInfo{
		Service: "packmon-server",
		Version: build.Version,
		Commit:  build.Commit,
		Date:    build.Date,
	})
	apiKeyAuth := newAPIKeyAuthStore(store)
	chain := func(h http.Handler) http.Handler {
		h = middleware.RequireAdminSession(sm, logger)(h)
		h = middleware.AuthenticatedAPIKeyRateLimitWithSource(ctx, logger, rateLimitConfig(cfg), runtime)(h)
		h = middleware.Auth(ctx, logger, apiKeyAuth, devMode)(h)
		h = middleware.UserAgent(logger, devMode)(h)
		h = middleware.RateLimitWithSource(ctx, logger, rateLimitConfig(cfg), runtime)(h)
		h = middleware.Logging(logger)(h)
		h = middleware.Recovery(logger)(h)
		h = middleware.Correlation(h)
		h = httpsecurity.SecurityHeaders(!devMode, cfg.Server.PublicHost, cfg.Server.TrustedProxies)(h)
		h = telemetry.HTTPMiddleware(registry)(h)
		h = middleware.TrustedClientIP(cfg.Server.TrustedProxies)(h)
		return h
	}

	// -- Register routes ------------------------------------------------------
	mux := http.NewServeMux()
	hc := health.NewChecker(pinger)
	registerRoutes(routeDependencies{
		ctx:             ctx,
		mux:             mux,
		healthChecker:   hc,
		cfg:             cfg,
		runtime:         runtime,
		store:           store,
		sessionManager:  sm,
		logger:          logger,
		buildInfo:       build,
		syncFeed:        syncFeed,
		applyFeedConfig: applyFeedConfig,
		resetFeedConfig: resetFeedConfig,
	})

	mainAddr := cfg.Server.Addr()
	mainServer := &http.Server{
		Addr:         mainAddr,
		Handler:      chain(mux),
		ErrorLog:     newHTTPServerErrorLog(logger),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// -- Metrics server (plain, no middleware chain) ---------------------------
	metricsMux := http.NewServeMux()
	metricsMux.HandleFunc("GET /metrics", telemetry.MetricsHandlerWithRegistry(registry, store, build.SchemaVersion, logger))
	metricsAddr := cfg.Metrics.Addr()
	metricsServer := &http.Server{
		Addr:              metricsAddr,
		Handler:           httpsecurity.SecurityHeaders(false, "", nil)(metricsMux),
		ErrorLog:          newHTTPServerErrorLog(logger),
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadTimeout,
	}

	return &Server{
		cfg:     cfg,
		store:   store,
		pinger:  pinger,
		logger:  logger,
		build:   build,
		main:    mainServer,
		metrics: metricsServer,
		health:  hc,
	}
}

func sessionCookieSecure(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	if cfg.IsDevelopment() || cfg.Server.InsecureLocalHTTPOverrideActive() {
		return false
	}
	return true
}

func newHTTPServerErrorLog(logger *slog.Logger) *log.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return slog.NewLogLogger(logger.Handler(), slog.LevelError)
}

// buildServerTLSConfig constructs the *tls.Config used for in-app TLS
// termination from the validated TLS settings. It is a pure helper so the
// minimum-version wiring can be unit-tested without binding a listener.
func buildServerTLSConfig(tlsCfg config.TLSConfig) *tls.Config {
	// #nosec G402 -- TLS minimum is validated config: Packmon supports TLS 1.2 or 1.3 by policy.
	return &tls.Config{MinVersion: tlsCfg.MinVersionTLS()}
}

// resolveRateLimit returns the effective per-minute rate and burst, applying
// defaults when the config values are unset.
func resolveRateLimit(cfg *config.Config) (perMinute, burst int) {
	perMinute = 60
	burst = 60
	if cfg != nil {
		if cfg.Server.RateLimitPerMinute > 0 {
			perMinute = cfg.Server.RateLimitPerMinute
		}
		if cfg.Server.RateLimitBurst > 0 {
			burst = cfg.Server.RateLimitBurst
		}
	}
	return perMinute, burst
}

func rateLimitConfig(cfg *config.Config) middleware.RateLimitConfig {
	perMinute, burst := resolveRateLimit(cfg)
	return middleware.RateLimitConfig{
		Rate:  float64(perMinute) / 60,
		Burst: burst,
	}
}

// SetShuttingDown marks the server as shutting down so that the
// /readyz endpoint immediately returns 503. This should be called
// as the first step after receiving SIGTERM, before stopping the
// HTTP listener, to give the load balancer time to drain traffic.
func (s *Server) SetShuttingDown() {
	s.health.SetShuttingDown()
}

// Run starts both HTTP servers and blocks until the context is
// cancelled or a fatal server error occurs. Signal handling is the
// caller's responsibility (e.g. via signal.NotifyContext).
func (s *Server) Run(ctx context.Context) error {
	// Channel for fatal main server errors.
	errCh := make(chan error, 1)

	// Start metrics server.
	go func() {
		listener, err := net.Listen("tcp", s.metrics.Addr)
		if err != nil {
			s.logger.Warn("metrics server unavailable, continuing without metrics",
				slog.String("error", fmt.Errorf("metrics server listen: %w", err).Error()),
			)
			return
		}
		boundAddr := listener.Addr().String()
		s.logger.Info("metrics server listening", slog.String("addr", boundAddr))
		if err := s.metrics.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("metrics server stopped unexpectedly, continuing without metrics",
				slog.String("error", fmt.Errorf("metrics server: %w", err).Error()),
			)
		}
	}()

	// Start main server. When a TLS cert+key are configured, terminate TLS
	// in-app (no reverse proxy required); otherwise serve cleartext HTTP.
	tlsCfg := s.cfg.Server.TLS
	go func() {
		listener, err := net.Listen("tcp", s.main.Addr)
		if err != nil {
			errCh <- fmt.Errorf("main server listen: %w", err)
			return
		}
		boundAddr := listener.Addr().String()
		dashboard := dashboardURL(s.cfg, boundAddr)

		// Print a plain-text banner to stdout so the URL is unmissable even when
		// the structured JSON ready-line below scrolls past among the feed-sync
		// startup lines.
		fmt.Fprint(os.Stdout, dashboardBanner(dashboard))

		if tlsCfg.Enabled() {
			s.main.TLSConfig = buildServerTLSConfig(tlsCfg)
			s.logger.Info(mainServerReadyMessage(dashboard),
				slog.String("addr", boundAddr),
				slog.String("mode", string(s.cfg.Server.Mode)),
				slog.String("transport", "https"),
				slog.String("dashboard_url", dashboard),
				slog.String("tls_min_version", tlsCfg.MinVersion),
				slog.String("version", s.build.Version),
			)
			if err := s.main.ServeTLS(listener, tlsCfg.CertFile, tlsCfg.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("main server (tls): %w", err)
			}
			return
		}
		s.logger.Info(mainServerReadyMessage(dashboard),
			slog.String("addr", boundAddr),
			slog.String("mode", string(s.cfg.Server.Mode)),
			slog.String("transport", "http"),
			slog.String("dashboard_url", dashboard),
			slog.String("version", s.build.Version),
		)
		if err := s.main.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("main server: %w", err)
		}
	}()

	// Wait for context cancellation or fatal error.
	select {
	case err := <-errCh:
		s.logger.Error("server error, shutting down", slog.String("error", logsafe.BoundedDiagnosticValue(err.Error(), 512)))
		s.SetShuttingDown()
		return errors.Join(err, s.shutdown())
	case <-ctx.Done():
		s.logger.Info("context cancelled, shutting down")
	}

	// Mark as shutting down so /readyz returns 503 immediately for any
	// in-flight health probes during the graceful shutdown window.
	s.SetShuttingDown()

	return s.shutdown()
}

// shutdown performs an orderly shutdown of both HTTP servers.
func (s *Server) shutdown() error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownTimeout)
	defer cancel()

	var mainErr, metricsErr error

	s.logger.Info("shutdown: stopping main HTTP server",
		slog.Duration("timeout", s.cfg.Server.ShutdownTimeout))
	mainErr = s.main.Shutdown(ctx)
	logHTTPServerStopped(s.logger, "main HTTP server", start, mainErr)

	s.logger.Info("shutdown: stopping metrics server")
	metricsErr = s.metrics.Shutdown(ctx)
	logHTTPServerStopped(s.logger, "metrics server", start, metricsErr)

	return errors.Join(mainErr, metricsErr)
}

func logHTTPServerStopped(logger *slog.Logger, name string, start time.Time, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	attrs := []slog.Attr{
		slog.Duration("elapsed", time.Since(start)),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "shutdown: "+name+" stopped", attrs...)
}
