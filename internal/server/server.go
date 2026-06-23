// Package server provides the HTTP server for the Packmon feed server.
// It wires middleware, routes, and a separate metrics server, and handles
// graceful shutdown on SIGTERM/SIGINT.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/8linkz-sec/packmon/internal/api/admin"
	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/health"
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

// New creates a Server with all middleware and routes wired up.
// The caller must provide a Store implementation and a Pinger for
// health checks (typically the same pgxpool.Pool satisfies both).
func New(ctx context.Context, cfg *config.Config, store db.Store, pinger health.Pinger, logger *slog.Logger, build BuildInfo, syncFeed admin.FeedSyncFunc, applyFeedConfig admin.FeedConfigApplyFunc, resetFeedConfig admin.FeedConfigResetFunc) *Server {
	devMode := cfg.IsDevelopment()

	// Shared runtime settings (block threshold + rate limit) that the admin UI
	// can change without a restart. Seeded from the (already startup-applied)
	// config so the live handlers and rate limiter read current values.
	perMinute, burst := resolveRateLimit(cfg)
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, perMinute, burst)

	// Session manager for admin authentication. The context controls the
	// lifetime of the session cleanup goroutine.
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, cfg.Admin.SessionTimeout, cfg.Admin.IdleTimeout, sessionCookieSecure(cfg))

	// -- Build middleware chain ------------------------------------------------
	// Order matters: outermost middleware runs first.
	// TrustedClientIP -> Telemetry -> SecurityHeaders -> Correlation -> Recovery -> Logging -> RateLimit -> UserAgent -> Auth -> Session -> Handler
	registry := telemetry.Default()
	chain := func(h http.Handler) http.Handler {
		h = middleware.RequireAdminSession(sm, logger)(h)
		h = middleware.Auth(ctx, logger, store, devMode)(h)
		h = middleware.UserAgent(logger, devMode)(h)
		h = middleware.RateLimitWithSource(ctx, logger, rateLimitConfig(cfg), runtime)(h)
		h = middleware.Logging(logger)(h)
		h = middleware.Recovery(logger)(h)
		h = middleware.Correlation(h)
		h = middleware.SecurityHeaders(!devMode, cfg.Server.PublicHost, cfg.Server.TrustedProxies)(h)
		h = telemetry.HTTPMiddleware(registry)(h)
		h = middleware.TrustedClientIP(cfg.Server.TrustedProxies)(h)
		return h
	}

	// -- Register routes ------------------------------------------------------
	mux := http.NewServeMux()
	hc := health.NewChecker(pinger)
	registerRoutes(ctx, mux, hc, cfg, runtime, store, sm, logger, build, syncFeed, applyFeedConfig, resetFeedConfig)

	mainAddr := cfg.Server.Addr()
	mainServer := &http.Server{
		Addr:         mainAddr,
		Handler:      chain(mux),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// -- Metrics server (plain, no middleware chain) ---------------------------
	metricsMux := http.NewServeMux()
	metricsMux.HandleFunc("GET /metrics", telemetry.MetricsHandlerWithRegistry(registry, store, build.SchemaVersion, logger))
	metricsAddr := cfg.Metrics.Addr()
	metricsServer := &http.Server{
		Addr:              metricsAddr,
		Handler:           middleware.SecurityHeaders(false, "", nil)(metricsMux),
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
	if cfg == nil || cfg.IsDevelopment() {
		return false
	}
	if cfg.Server.AllowInsecureLocalHTTP {
		return false
	}
	return true
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
	// Channel for fatal server errors.
	errCh := make(chan error, 2)

	// Start metrics server.
	go func() {
		listener, err := net.Listen("tcp", s.metrics.Addr)
		if err != nil {
			errCh <- fmt.Errorf("metrics server listen: %w", err)
			return
		}
		boundAddr := listener.Addr().String()
		s.logger.Info("metrics server listening", slog.String("addr", boundAddr))
		if err := s.metrics.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("metrics server: %w", err)
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

		if tlsCfg.Enabled() {
			s.main.TLSConfig = buildServerTLSConfig(tlsCfg)
			s.logger.Info("main server listening",
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
		s.logger.Info("main server listening",
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
		s.logger.Error("server error, shutting down", slog.String("error", err.Error()))
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
		slog.String("timeout", s.cfg.Server.ShutdownTimeout.String()))
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
		slog.String("elapsed", time.Since(start).String()),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	logger.LogAttrs(context.Background(), slog.LevelInfo, "shutdown: "+name+" stopped", attrs...)
}
