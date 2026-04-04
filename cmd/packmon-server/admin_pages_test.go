package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/api/admin"
	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/web"
)

func TestAdminFeedsPageShowsRuntimeConfig(t *testing.T) {
	store := newNoopStore()
	now := time.Now().UTC()
	duration := 2 * time.Second
	if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{
		FeedName:         "ghsa",
		LastSyncAt:       &now,
		LastSyncDuration: &duration,
		LastSyncStatus:   "success",
		EntriesSynced:    12,
		EntriesTotal:     42,
	}); err != nil {
		t.Fatalf("upsert feed sync status: %v", err)
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds")
	rec := httptest.NewRecorder()

	handler.HandleAdminFeeds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/feeds status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"Current Runtime",
		"Saved Configuration",
		"GHSA",
		"ghsa",
		"external",
		"15m (default)",
		"success",
		"VulnCheck",
		"configured",
		"Socket.dev",
		"disabled",
		"not configured",
		"PACKMON_FEED_*",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/feeds body missing %q\nbody=%s", want, body)
		}
	}
}

func TestAdminSettingsPageShowsRuntimeValues(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings")
	rec := httptest.NewRecorder()

	handler.HandleAdminSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/settings status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"development",
		"15m",
		"45m",
		"127.0.0.1:9100",
		"db.internal",
		"packmon_test",
		"disable",
		"never",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/settings body missing %q\nbody=%s", want, body)
		}
	}
	if strings.Contains(body, "0001-01-01") {
		t.Fatalf("GET /admin/settings body contains zero timestamp: %s", body)
	}
}

func TestHandleFeedConfigSavePersistsOverride(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"socket"},
		"enabled":       {"on"},
		"mode":          {"external"},
		"api_key":       {"socket-test-key"},
		"clear_api_key": {""},
	})
	rec := httptest.NewRecorder()

	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/feeds/save status = %d, want 303", rec.Code)
	}

	override, err := store.GetFeedConfig(context.Background(), "socket")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override == nil {
		t.Fatal("GetFeedConfig() = nil, want override")
	}
	if !override.Enabled || override.Mode != "external" || override.APIKey != "socket-test-key" {
		t.Fatalf("unexpected override = %+v", *override)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "feed_config_save" {
		t.Fatalf("audit entries = %+v, want feed_config_save", audit)
	}
}

func TestHandleFeedConfigSaveParsesSyncInterval(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"ghsa"},
		"enabled":       {"on"},
		"mode":          {"self"},
		"sync_interval": {"2h30m"},
	})
	rec := httptest.NewRecorder()

	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/feeds/save status = %d, want 303", rec.Code)
	}

	override, err := store.GetFeedConfig(context.Background(), "ghsa")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override == nil || override.SyncInterval == nil {
		t.Fatalf("GetFeedConfig() = %+v, want sync interval override", override)
	}
	if *override.SyncInterval != 150*time.Minute {
		t.Fatalf("override.SyncInterval = %s, want 2h30m", *override.SyncInterval)
	}
}

func TestHandleFeedConfigResetDeletesOverride(t *testing.T) {
	store := newNoopStore()
	interval := 30 * time.Minute
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName:     "ghsa",
		Enabled:      true,
		Mode:         "external",
		SyncInterval: &interval,
	}); err != nil {
		t.Fatalf("UpsertFeedConfig() error = %v", err)
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
		"feed_name": {"ghsa"},
	})
	rec := httptest.NewRecorder()

	handler.HandleFeedConfigReset(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/feeds/reset status = %d, want 303", rec.Code)
	}

	override, err := store.GetFeedConfig(context.Background(), "ghsa")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override != nil {
		t.Fatalf("GetFeedConfig() = %+v, want nil after reset", *override)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "feed_config_reset" {
		t.Fatalf("audit entries = %+v, want feed_config_reset", audit)
	}
}

func newAdminTestHandler(t *testing.T, store *noopStore, cfg *config.Config) (*admin.AdminHandler, *auth.SessionManager) {
	t.Helper()

	renderer := web.NewRenderer(web.TemplateFS(), false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sm := auth.NewSessionManager(time.Hour, false)
	return admin.NewAdminHandler(store, sm, renderer, logger, cfg), sm
}

func newAuthenticatedAdminRequest(t *testing.T, sm *auth.SessionManager, method, target string) *http.Request {
	t.Helper()

	cookieRec := httptest.NewRecorder()
	sess, err := sm.Create(cookieRec)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sess.Admin = true

	req := httptest.NewRequest(method, target, nil)
	for _, cookie := range cookieRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func newAuthenticatedAdminFormRequest(t *testing.T, sm *auth.SessionManager, target string, values url.Values) *http.Request {
	t.Helper()

	cookieRec := httptest.NewRecorder()
	sess, err := sm.Create(cookieRec)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sess.Admin = true

	csrfToken, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("csrf token: %v", err)
	}
	values.Set(auth.CSRFFieldName, csrfToken)

	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookieRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func testAdminConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Mode: config.ModeDevelopment,
		},
		DB: config.DBConfig{
			Host:    "db.internal",
			Name:    "packmon_test",
			SSLMode: "disable",
		},
		Metrics: config.MetricsConfig{
			Host: "127.0.0.1",
			Port: 9100,
		},
		Admin: config.AdminConfig{
			SessionTimeout: 45 * time.Minute,
		},
		FeedSync: config.FeedSyncConfig{
			Interval:  15 * time.Minute,
			OnStartup: false,
		},
		Feeds: config.FeedsConfig{
			OSVEnabled:       true,
			OSVMode:          config.FeedModeSelf,
			GHSAEnabled:      true,
			GHSAMode:         config.FeedModeExternal,
			MaliciousEnabled: true,
			MaliciousMode:    config.FeedModeSelf,
			VulnCheckEnabled: true,
			VulnCheckMode:    config.FeedModeExternal,
			VulnCheckAPIKey:  "test-vulncheck-key",
			SocketEnabled:    false,
			SocketMode:       config.FeedModeSelf,
			CISAKEVEnabled:   true,
			CISAKEVMode:      config.FeedModeSelf,
			EPSSEnabled:      true,
			EPSSMode:         config.FeedModeExternal,
		},
	}
}
