package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/health"
)

type routePinger struct{}

func (routePinger) Ping(context.Context) error { return nil }

func TestRegisterRoutesServesOperationalEndpoints(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := http.NewServeMux()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
		},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	runtime := config.NewRuntimeSettings("CRITICAL", 60, 60)
	sm := auth.NewSessionManager(ctx, time.Hour, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	registerRoutes(ctx, mux, health.NewChecker(routePinger{}), cfg, runtime, db.Store(nil), sm, logger, BuildInfo{
		Version: "v-test",
		Commit:  "c-test",
		Date:    "d-test",
	}, nil, nil, nil)

	for _, target := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200; body=%s", target, rec.Code, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/version status = %d, want 200", rec.Code)
	}
	var version map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&version); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if version["version"] != "v-test" || version["commit"] != "c-test" || version["date"] != "d-test" {
		t.Fatalf("version payload = %+v", version)
	}
}

func TestRegisterRoutesAcceptsFeedConfigCallbacks(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mux := http.NewServeMux()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
		},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	runtime := config.NewRuntimeSettings("CRITICAL", 60, 60)
	sm := auth.NewSessionManager(ctx, time.Hour, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	apply := func(context.Context, config.FeedSettings) error { return nil }
	reset := func(context.Context, string) error { return nil }

	registerRoutes(ctx, mux, health.NewChecker(routePinger{}), cfg, runtime, db.Store(nil), sm, logger, BuildInfo{}, nil, apply, reset)

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/version status = %d, want 200", rec.Code)
	}
}
