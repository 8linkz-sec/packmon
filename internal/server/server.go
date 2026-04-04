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
	"os"
	"os/signal"
	"syscall"

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
}

// New creates a Server with all middleware and routes wired up.
// The caller must provide a Store implementation and a Pinger for
// health checks (typically the same pgxpool.Pool satisfies both).
func New(cfg *config.Config, store db.Store, pinger health.Pinger, logger *slog.Logger, build BuildInfo) *Server {
	devMode := cfg.IsDevelopment()

	// Session manager for admin authentication.
	// In production mode, session cookies require HTTPS (Secure flag).
	sm := auth.NewSessionManager(cfg.Admin.SessionTimeout, !devMode)

	// -- Build middleware chain ------------------------------------------------
	// Order matters: outermost middleware runs first.
	// Correlation -> Recovery -> Logging -> UserAgent -> Auth -> Session -> RateLimit -> Handler
	chain := func(h http.Handler) http.Handler {
		h = middleware.RateLimit(logger, middleware.RateLimitConfig{
			Rate:  1.0, // 1 token/sec refill = 60/min sustained
			Burst: 60,  // allow bursts up to 60 requests
		})(h)
		h = middleware.RequireAdminSession(sm, logger)(h)
		h = middleware.Auth(logger, store, devMode)(h)
		h = middleware.UserAgent(logger, devMode)(h)
		h = middleware.Logging(logger)(h)
		h = middleware.Recovery(logger)(h)
		h = middleware.Correlation(h)
		return h
	}

	// -- Register routes ------------------------------------------------------
	mux := http.NewServeMux()
	hc := health.NewChecker(pinger)
	registerRoutes(mux, hc, store, sm, logger, build)

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
		Addr:    metricsAddr,
		Handler: metricsMux,
	}

	return &Server{
		cfg:     cfg,
		store:   store,
		pinger:  pinger,
		logger:  logger,
		build:   build,
		main:    mainServer,
		metrics: metricsServer,
	}
}

// Run starts both HTTP servers and blocks until a termination signal
// is received. It then performs a graceful shutdown within the
// configured timeout.
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

	// Wait for termination signal or fatal error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		s.logger.Info("received signal, shutting down", slog.String("signal", sig.String()))
	case err := <-errCh:
		s.logger.Error("server error, shutting down", slog.String("error", err.Error()))
		return err
	case <-ctx.Done():
		s.logger.Info("context cancelled, shutting down")
	}

	return s.shutdown()
}

// shutdown performs an orderly shutdown of both HTTP servers.
func (s *Server) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownTimeout)
	defer cancel()

	// Shut down main server first (stops accepting new requests).
	var mainErr, metricsErr error

	s.logger.Info("shutting down main server")
	mainErr = s.main.Shutdown(ctx)

	s.logger.Info("shutting down metrics server")
	metricsErr = s.metrics.Shutdown(ctx)

	return errors.Join(mainErr, metricsErr)
}
