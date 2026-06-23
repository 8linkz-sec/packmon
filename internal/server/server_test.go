package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

func TestRateLimitConfigUsesServerSettings(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			RateLimitPerMinute: 120,
			RateLimitBurst:     25,
		},
	}

	got := rateLimitConfig(cfg)

	if got.Rate != 2 {
		t.Fatalf("Rate = %v, want 2", got.Rate)
	}
	if got.Burst != 25 {
		t.Fatalf("Burst = %d, want 25", got.Burst)
	}
}

func TestRateLimitConfigFallsBackToDefaults(t *testing.T) {
	got := rateLimitConfig(&config.Config{})

	if got.Rate != 1 {
		t.Fatalf("Rate = %v, want 1", got.Rate)
	}
	if got.Burst != 60 {
		t.Fatalf("Burst = %d, want 60", got.Burst)
	}
}

func TestNewWiresServersAndRoutes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "HIGH",
			RateLimitPerMinute: 120,
			RateLimitBurst:     10,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{Version: "v-new"}, nil, nil, nil)

	if srv.main == nil || srv.metrics == nil || srv.health == nil {
		t.Fatal("New did not initialize server components")
	}
	if srv.main.Addr != ":0" {
		t.Fatalf("main addr = %q, want :0", srv.main.Addr)
	}
	if srv.metrics.Addr != "127.0.0.1:0" {
		t.Fatalf("metrics addr = %q, want 127.0.0.1:0", srv.metrics.Addr)
	}
	if srv.metrics.ReadTimeout != cfg.Server.ReadTimeout {
		t.Fatalf("metrics ReadTimeout = %s, want %s", srv.metrics.ReadTimeout, cfg.Server.ReadTimeout)
	}
	if srv.metrics.WriteTimeout != cfg.Server.WriteTimeout {
		t.Fatalf("metrics WriteTimeout = %s, want %s", srv.metrics.WriteTimeout, cfg.Server.WriteTimeout)
	}
	if srv.metrics.IdleTimeout != cfg.Server.ReadTimeout {
		t.Fatalf("metrics IdleTimeout = %s, want %s", srv.metrics.IdleTimeout, cfg.Server.ReadTimeout)
	}

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	req.Header.Set("User-Agent", "packmon-test")
	rec := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/version through New handler status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestNewWiresMetricsSecurityHeaders(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:            0,
			Mode:            config.ModeDevelopment,
			ReadTimeout:     time.Second,
			WriteTimeout:    time.Second,
			ShutdownTimeout: time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, metricsHeaderStore{}, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	rec := httptest.NewRecorder()
	srv.metrics.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	headers := rec.Result().Header
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=()",
	} {
		if got := headers.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if got := headers.Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("Content-Security-Policy = %q, want self baseline", got)
	}
}

func TestNewBindsLocalHTTPOverrideToLoopback(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:                   8080,
			Mode:                   config.ModeProduction,
			PublicHost:             "localhost:8080",
			AllowInsecureLocalHTTP: true,
			BlockThreshold:         "HIGH",
			RateLimitPerMinute:     120,
			RateLimitBurst:         10,
			ReadTimeout:            time.Second,
			WriteTimeout:           time.Second,
			ShutdownTimeout:        time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{Version: "v-new"}, nil, nil, nil)
	if srv.main.Addr != "127.0.0.1:8080" {
		t.Fatalf("main addr = %q, want loopback bind", srv.main.Addr)
	}
}

func TestRateLimitRunsBeforeAuthForInvalidAPIKeys(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &rateLimitAuthStore{}
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeProduction,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 1,
			RateLimitBurst:     1,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, store, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req1.Header.Set("User-Agent", "packmon-cli/test")
	req1.Header.Set("Authorization", "Bearer invalid-one")
	req1.RemoteAddr = "203.0.113.10:12345"
	rec1 := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("first invalid-key request status = %d, want 401; body=%s", rec1.Code, rec1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req2.Header.Set("User-Agent", "packmon-cli/test")
	req2.Header.Set("Authorization", "Bearer invalid-two")
	req2.RemoteAddr = "203.0.113.10:12345"
	rec2 := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second invalid-key request status = %d, want 429; body=%s", rec2.Code, rec2.Body.String())
	}
	if got := store.lookups.Load(); got != 1 {
		t.Fatalf("FindAPIKeyByHash calls = %d, want 1", got)
	}
}

func TestRunShutsDownOnContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    2 * time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	if err := srv.Run(ctx); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRunFatalServerErrorMarksShuttingDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)
	srv.metrics.Addr = "127.0.0.1:bad-port"

	if err := srv.Run(ctx); err == nil {
		t.Fatal("Run returned nil, want fatal metrics server error")
	}

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("User-Agent", "packmon-test")
	rec := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz after fatal server error status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestLogHTTPServerStoppedIncludesConcreteError(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))

	logHTTPServerStopped(logger, "main HTTP server", time.Now(), errors.New("context deadline exceeded"))

	output := logs.String()
	if !strings.Contains(output, `"error":"context deadline exceeded"`) {
		t.Fatalf("shutdown log missing concrete error: %s", output)
	}
	if strings.Contains(output, `"error":true`) {
		t.Fatalf("shutdown log still uses boolean-only error field: %s", output)
	}
}

type rateLimitAuthStore struct {
	db.Store
	lookups atomic.Int64
}

func (s *rateLimitAuthStore) FindAPIKeyByHash(context.Context, string) (*db.APIKey, error) {
	s.lookups.Add(1)
	return nil, nil
}

type metricsHeaderStore struct {
	db.Store
}

func (metricsHeaderStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return nil, nil
}

func (metricsHeaderStore) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return nil, nil
}

func (metricsHeaderStore) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	return nil, nil
}

func (metricsHeaderStore) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	return nil, nil
}

func TestSetShuttingDownMakesReadyEndpointUnavailable(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:               0,
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
			ReadTimeout:        time.Second,
			WriteTimeout:       time.Second,
			ShutdownTimeout:    time.Second,
		},
		Metrics:  config.MetricsConfig{Port: 0},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ctx, cfg, nil, routePinger{}, logger, BuildInfo{}, nil, nil, nil)

	srv.SetShuttingDown()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("User-Agent", "packmon-test")
	rec := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}
