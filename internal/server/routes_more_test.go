package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/health"
	"github.com/8linkz-sec/packmon/internal/server/middleware"
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
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	registerRoutes(routeDependencies{
		ctx:            ctx,
		mux:            mux,
		healthChecker:  health.NewChecker(routePinger{}),
		cfg:            cfg,
		runtime:        runtime,
		store:          db.Store(nil),
		sessionManager: sm,
		logger:         logger,
		buildInfo: BuildInfo{
			Version: "v-test",
			Commit:  "c-test",
			Date:    "d-test",
		},
	})

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

func TestRegisterRoutesAPIErrorFallbacksUseJSONEnvelope(t *testing.T) {
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
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	registerRoutes(routeDependencies{
		ctx:            ctx,
		mux:            mux,
		healthChecker:  health.NewChecker(routePinger{}),
		cfg:            cfg,
		runtime:        runtime,
		store:          db.Store(nil),
		sessionManager: sm,
		logger:         logger,
	})

	for _, tt := range []struct {
		name   string
		method string
		target string
		status int
		code   string
	}{
		{
			name:   "unknown api route",
			method: http.MethodGet,
			target: "/api/v1/not-a-route",
			status: http.StatusNotFound,
			code:   "not_found",
		},
		{
			name:   "known route wrong method",
			method: http.MethodGet,
			target: "/api/v1/check",
			status: http.StatusMethodNotAllowed,
			code:   "unsupported",
		},
		{
			name:   "package route unsupported method",
			method: http.MethodDelete,
			target: "/api/v1/packages/npm/lodash",
			status: http.StatusMethodNotAllowed,
			code:   "unsupported",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, tt.target, nil)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.status, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Fatalf("Content-Type = %q, want application/json; charset=utf-8", got)
			}
			var body struct {
				Error string `json:"error"`
				Code  string `json:"code"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("error response body is not JSON: %v; body=%q", err, rec.Body.String())
			}
			if body.Code != tt.code {
				t.Fatalf("code = %q, want %q; body=%+v", body.Code, tt.code, body)
			}
			if strings.TrimSpace(body.Error) == "" {
				t.Fatalf("error message is empty: %+v", body)
			}
		})
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
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	apply := func(context.Context, config.FeedSettings) error { return nil }
	reset := func(context.Context, string) (config.FeedSettings, bool, error) {
		return config.FeedSettings{}, false, nil
	}

	registerRoutes(routeDependencies{
		ctx:             ctx,
		mux:             mux,
		healthChecker:   health.NewChecker(routePinger{}),
		cfg:             cfg,
		runtime:         runtime,
		store:           db.Store(nil),
		sessionManager:  sm,
		logger:          logger,
		applyFeedConfig: apply,
		resetFeedConfig: reset,
	})

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/version status = %d, want 200", rec.Code)
	}
}

func TestRegisterRoutesRequiresProductionFeedImportSecret(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mux := http.NewServeMux()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Mode:               config.ModeProduction,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
		},
		Admin:    config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
	runtime := config.NewRuntimeSettings("CRITICAL", 60, 60)
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	registerRoutes(routeDependencies{
		ctx:            ctx,
		mux:            mux,
		healthChecker:  health.NewChecker(routePinger{}),
		cfg:            cfg,
		runtime:        runtime,
		store:          db.Store(nil),
		sessionManager: sm,
		logger:         logger,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(`{"malicious":[{"id":"MAL-route","ecosystem":"npm","name":"evil"}]}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("feed import without production import secret status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRegisterRoutesRejectsPublicPackageRefresh(t *testing.T) {
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
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &routeRefreshStore{}

	registerRoutes(routeDependencies{
		ctx:            ctx,
		mux:            mux,
		healthChecker:  health.NewChecker(routePinger{}),
		cfg:            cfg,
		runtime:        runtime,
		store:          store,
		sessionManager: sm,
		logger:         logger,
	})

	req := httptest.NewRequest(http.MethodPost, "/package/npm/refresh/lodash", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("public package refresh status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
	if len(store.enqueued) != 0 {
		t.Fatalf("public package refresh enqueued jobs = %+v, want none", store.enqueued)
	}
}

func TestRegisterRoutesServesAdminScansBehindAdminSession(t *testing.T) {
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
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := routeScansStore{
		daily: []db.DailyScanStats{{
			Date:          time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC),
			ScanCount:     1,
			FindingsCount: 3,
		}},
		scans: []db.ScanLogEntry{{
			ScanID:        "scan-server-route",
			ScannedAt:     time.Date(2026, 6, 27, 12, 30, 0, 0, time.UTC),
			PackagesCount: 10,
			FindingsCount: 3,
			DurationMs:    42,
		}},
	}

	registerRoutes(routeDependencies{
		ctx:            ctx,
		mux:            mux,
		healthChecker:  health.NewChecker(routePinger{}),
		cfg:            cfg,
		runtime:        runtime,
		store:          store,
		sessionManager: sm,
		logger:         logger,
	})
	handler := middleware.RequireAdminSession(sm, logger)(mux)

	unauthReq := httptest.NewRequest(http.MethodGet, "/admin/scans", nil)
	unauthRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated /admin/scans status = %d, want 303; body=%s", unauthRec.Code, unauthRec.Body.String())
	}
	if got := unauthRec.Header().Get("Location"); got != "/admin/login?next=%2Fadmin%2Fscans" {
		t.Fatalf("unauthenticated /admin/scans Location = %q, want login redirect", got)
	}

	sessionRec := httptest.NewRecorder()
	if _, err := sm.CreateAdmin(sessionRec, false); err != nil {
		t.Fatalf("CreateAdmin session: %v", err)
	}
	authReq := httptest.NewRequest(http.MethodGet, "/admin/scans", nil)
	for _, cookie := range sessionRec.Result().Cookies() {
		authReq.AddCookie(cookie)
	}
	authRec := httptest.NewRecorder()
	handler.ServeHTTP(authRec, authReq)

	if authRec.Code != http.StatusOK {
		t.Fatalf("authenticated /admin/scans status = %d, want 200; body=%s", authRec.Code, authRec.Body.String())
	}
	body := authRec.Body.String()
	for _, want := range []string{
		"Scan Activity",
		"Recent Scans",
		"scan-server-route",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("authenticated /admin/scans missing %q:\n%s", want, body)
		}
	}
	if !regexp.MustCompile(`(?s)<a\b[^>]*href="/admin/scans"[^>]*aria-current="page"`).MatchString(body) {
		t.Fatalf("authenticated /admin/scans missing active admin nav link:\n%s", body)
	}
	if strings.Contains(body, `href="/scans"`) {
		t.Fatalf("authenticated /admin/scans linked unprotected /scans route:\n%s", body)
	}

	publicReq := httptest.NewRequest(http.MethodGet, "/scans", nil)
	publicRec := httptest.NewRecorder()
	handler.ServeHTTP(publicRec, publicReq)
	if publicRec.Code != http.StatusNotFound {
		t.Fatalf("public /scans status = %d, want 404; body=%s", publicRec.Code, publicRec.Body.String())
	}
}

type routeRefreshStore struct {
	db.Store
	enqueued []db.RefreshJob
}

func (s *routeRefreshStore) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	s.enqueued = append(s.enqueued, *job)
	return true, len(s.enqueued), nil
}

type routeScansStore struct {
	db.Store
	daily []db.DailyScanStats
	scans []db.ScanLogEntry
}

func (s routeScansStore) CountScansByDay(context.Context, int) ([]db.DailyScanStats, error) {
	return append([]db.DailyScanStats(nil), s.daily...), nil
}

func (s routeScansStore) ListRecentScans(context.Context, int, int) ([]db.ScanLogEntry, error) {
	return append([]db.ScanLogEntry(nil), s.scans...), nil
}
