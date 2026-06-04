package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
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

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	req.Header.Set("User-Agent", "packmon-test")
	rec := httptest.NewRecorder()
	srv.main.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/version through New handler status = %d, want 200; body=%s", rec.Code, rec.Body.String())
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

type rateLimitAuthStore struct {
	db.Store
	lookups atomic.Int64
}

func (s *rateLimitAuthStore) FindAPIKeyByHash(context.Context, string) (*db.APIKey, error) {
	s.lookups.Add(1)
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
