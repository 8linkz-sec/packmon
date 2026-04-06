// Package server provides the HTTP server for the Packmon feed server.
// It wires middleware, routes, and a separate metrics server, and handles
// graceful shutdown on SIGTERM/SIGINT.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/8linkz/packmon/internal/api/admin"
	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/health"
	"github.com/8linkz/packmon/internal/server/middleware"
	"github.com/8linkz/packmon/internal/telemetry"
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
func New(ctx context.Context, cfg *config.Config, store db.Store, pinger health.Pinger, logger *slog.Logger, build BuildInfo, syncFeed admin.FeedSyncFunc) *Server {
	devMode := cfg.IsDevelopment()

	// Session manager for admin authentication.
	// In production mode, session cookies require HTTPS (Secure flag).
	// The context controls the lifetime of the session cleanup goroutine.
	sm := auth.NewSessionManager(ctx, cfg.Admin.SessionTimeout, !devMode)

	// -- Build middleware chain ------------------------------------------------
	// Order matters: outermost middleware runs first.
	// SecurityHeaders -> Correlation -> Recovery -> Logging -> UserAgent -> Auth -> Session -> RateLimit -> Handler
	chain := func(h http.Handler) http.Handler {
		h = middleware.RateLimit(ctx, logger, middleware.RateLimitConfig{
			Rate:  1.0, // 1 token/sec refill = 60/min sustained
			Burst: 60,  // allow bursts up to 60 requests
		})(h)
		h = middleware.RequireAdminSession(sm, logger)(h)
		h = middleware.Auth(logger, store, devMode)(h)
		h = middleware.UserAgent(logger, devMode)(h)
		h = middleware.Logging(logger)(h)
		h = middleware.Recovery(logger)(h)
		h = middleware.Correlation(h)
		h = middleware.SecurityHeaders(!devMode, cfg.Server.PublicHost)(h)
		return h
	}

	// -- Register routes ------------------------------------------------------
	mux := http.NewServeMux()
	hc := health.NewChecker(pinger)
	registerRoutes(ctx, mux, hc, cfg, store, sm, logger, build, syncFeed)

	mainAddr := fmt.Sprintf(":%d", cfg.Server.Port)
	mainServer := &http.Server{
		Addr:         mainAddr,
		Handler:      chain(mux),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// -- Metrics server (plain, no middleware chain) ---------------------------
	metricsMux := http.NewServeMux()
	metricsMux.HandleFunc("GET /metrics", telemetry.MetricsHandler(store, build.SchemaVersion))
	metricsAddr := cfg.Metrics.Addr()
	metricsServer := &http.Server{
		Addr:              metricsAddr,
		Handler:           metricsMux,
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
		s.logger.Info("metrics server starting", slog.String("addr", s.metrics.Addr))
		if err := s.metrics.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("metrics server: %w", err)
		}
	}()

	// Start main server.
	go func() {
		s.logger.Info("main server starting",
			slog.String("addr", s.main.Addr),
			slog.String("mode", string(s.cfg.Server.Mode)),
			slog.String("version", s.build.Version),
		)
		if err := s.main.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("main server: %w", err)
		}
	}()

	// Wait for context cancellation or fatal error.
	select {
	case err := <-errCh:
		s.logger.Error("server error, shutting down", slog.String("error", err.Error()))
		return err
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
	s.logger.Info("shutdown: main HTTP server stopped",
		slog.String("elapsed", time.Since(start).String()),
		slog.Bool("error", mainErr != nil))

	s.logger.Info("shutdown: stopping metrics server")
	metricsErr = s.metrics.Shutdown(ctx)
	s.logger.Info("shutdown: metrics server stopped",
		slog.String("elapsed", time.Since(start).String()),
		slog.Bool("error", metricsErr != nil))

	return errors.Join(mainErr, metricsErr)
}
