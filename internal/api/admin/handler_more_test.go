package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

func TestRegisterRoutesIncludesWellKnownPasswordRedirect(t *testing.T) {
	store := newAdminStoreStub()
	cfg := adminFlowConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	mux := http.NewServeMux()

	RegisterRoutes(ctx, mux, store, sm, nil, cfg, config.NewRuntimeSettings("CRITICAL", 60, 60), nil, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/change-password", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("well-known status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/admin/settings" {
		t.Fatalf("Location = %q, want /admin/settings", got)
	}
}

func TestAdminAuditEntryIncludesRequestCorrelationID(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/admin/queue/purge", nil)
	req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), "corr-admin-audit-entry"))

	entry := (&AdminHandler{}).adminAuditEntry(req, "queue_purge", map[string]string{"scope": "queue"})
	if entry.CorrelationID != "corr-admin-audit-entry" {
		t.Fatalf("admin audit correlation ID = %q, want request correlation ID", entry.CorrelationID)
	}
}

func TestAdminWriteRejectsMissingCSRF(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/feeds/save")
	req.Body = http.NoBody
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = url.Values{"feed_name": {"osv"}, "mode": {"self"}}

	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.HasPrefix(got, "/admin/feeds?") || !strings.Contains(got, "err=") {
		t.Fatalf("Location = %q, want admin feeds error redirect", got)
	}
}

func TestAdminWriteCSRFRejectionIsAuditedAndLogged(t *testing.T) {
	var logs bytes.Buffer
	store := newAdminStoreStub()
	handler, sm, cancel := newAdminFlowHandler(t, store, adminFlowConfig())
	defer cancel()
	handler.logger = slog.New(slog.NewJSONHandler(&logs, nil))

	req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/feeds/save")
	req.RemoteAddr = "203.0.113.55:44444"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = url.Values{"feed_name": {"osv"}, "mode": {"self"}, "_csrf": {"invalid"}}

	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.HasPrefix(got, "/admin/feeds?") || !strings.Contains(got, "err=") {
		t.Fatalf("Location = %q, want admin feeds error redirect", got)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(audit))
	}
	if audit[0].Action != "admin_csrf_rejected" {
		t.Fatalf("audit action = %q, want admin_csrf_rejected", audit[0].Action)
	}
	if audit[0].IP != "203.0.113.55" {
		t.Fatalf("audit IP = %q, want client IP", audit[0].IP)
	}
	var details map[string]string
	if err := json.Unmarshal(audit[0].Details, &details); err != nil {
		t.Fatalf("audit details JSON = %q: %v", string(audit[0].Details), err)
	}
	if details["target_action"] != "feed_config_save" || details["path"] != "/admin/feeds/save" {
		t.Fatalf("audit details = %+v, want target action and path", details)
	}

	logLine := logs.String()
	for _, want := range []string{`"level":"WARN"`, `"msg":"admin CSRF validation failed"`, `"target_action":"feed_config_save"`, `"client_ip":"203.0.113.55"`, `"path":"/admin/feeds/save"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("CSRF rejection log missing %s: %s", want, logLine)
		}
	}
}

func TestAdminFeedConfigValidationBranches(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	cases := []struct {
		name   string
		values url.Values
		want   string
	}{
		{"unknown feed", url.Values{"feed_name": {"unknown"}, "mode": {"self"}}, "Unknown+feed"},
		{"invalid mode", url.Values{"feed_name": {"osv"}, "mode": {"bad"}}, "Invalid+feed+mode"},
		{"invalid interval", url.Values{"feed_name": {"osv"}, "mode": {"self"}, "sync_interval": {"0s"}}, "Invalid+sync+interval"},
		{"unsafe interval", url.Values{"feed_name": {"vulncheck"}, "mode": {"self"}, "sync_interval": {"1s"}}, "at+least+15m0s"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", tt.values)
			rec := httptest.NewRecorder()
			handler.HandleFeedConfigSave(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, tt.want) {
				t.Fatalf("Location = %q, want containing %q", got, tt.want)
			}
		})
	}

	store.feedConfigs["osv"] = db.FeedConfig{FeedName: "osv", Enabled: true, Mode: "broken"}
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{"feed_name": {"osv"}, "mode": {"self"}})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "invalid+persisted+mode") {
		t.Fatalf("Location = %q, want persisted mode error", got)
	}

	handler.SetFeedConfigApplyFunc(func(context.Context, config.FeedSettings) error {
		return context.Canceled
	})
	delete(store.feedConfigs, "osv")
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{"feed_name": {"osv"}, "mode": {"self"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "applying+it+failed") {
		t.Fatalf("Location = %q, want apply failure", got)
	}
	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after apply failure = %+v, want none", audit)
	}

	handler.SetFeedConfigResetFunc(func(context.Context, string) (config.FeedSettings, bool, error) {
		return config.FeedSettings{}, false, context.Canceled
	})
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"osv"}, "confirm_reset": {"on"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "applying+it+failed") {
		t.Fatalf("reset Location = %q, want apply failure", got)
	}
	audit, err = store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after reset apply failure = %+v, want none", audit)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"unknown"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Unknown+feed") {
		t.Fatalf("reset unknown Location = %q", got)
	}
}

func TestAdminFeedConfigErrorsRedirectToAffectedFeedEditor(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"vulncheck"},
		"mode":          {"self"},
		"sync_interval": {"0s"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	location := rec.Header().Get("Location")
	for _, want := range []string{
		"err=Invalid+sync+interval",
		"feed=vulncheck",
		"#feed-vulncheck",
	} {
		if !strings.Contains(location, want) {
			t.Fatalf("Location = %q, want scoped feed editor marker %q", location, want)
		}
	}
}

func TestAdminFeedConfigSaveRejectsUnsupportedModeBeforePersisting(t *testing.T) {
	for _, feedName := range []string{"endoflife", "nvd"} {
		t.Run(feedName, func(t *testing.T) {
			store := newAdminStoreStub()
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
			applyCalled := false
			handler.SetFeedConfigApplyFunc(func(context.Context, config.FeedSettings) error {
				applyCalled = true
				return nil
			})

			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
				"feed_name": {feedName},
				"enabled":   {"on"},
				"mode":      {"external"},
			})
			rec := httptest.NewRecorder()
			handler.HandleFeedConfigSave(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, "does+not+support+external+mode") {
				t.Fatalf("Location = %q, want unsupported mode error", got)
			}
			if applyCalled {
				t.Fatal("applyFeedConfig called for unsupported feed mode")
			}
			if override, err := store.GetFeedConfig(context.Background(), feedName); err != nil || override != nil {
				t.Fatalf("GetFeedConfig(%s) = %+v, %v; want nil nil", feedName, override, err)
			}
			audit, err := store.ListAdminAuditLog(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if len(audit) != 0 {
				t.Fatalf("audit entries = %+v, want none", audit)
			}
		})
	}
}

func TestAdminFeedConfigSaveRequiresAPIKeyClearConfirmation(t *testing.T) {
	store := newAdminStoreStub()
	store.feedConfigs["vulncheck"] = db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: "self", APIKey: "old-key"}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"vulncheck"},
		"enabled":       {"on"},
		"mode":          {"self"},
		"clear_api_key": {"on"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Confirm+API+key+removal") {
		t.Fatalf("Location = %q, want clear confirmation error", got)
	}
	override, err := store.GetFeedConfig(context.Background(), "vulncheck")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override == nil || override.APIKey != "old-key" {
		t.Fatalf("override after rejected clear = %+v, want old key", override)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":             {"vulncheck"},
		"enabled":               {"on"},
		"mode":                  {"self"},
		"api_key":               {"new-key"},
		"clear_api_key":         {"on"},
		"confirm_clear_api_key": {"on"},
	})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Choose+either+a+new+API+key+or+clear") {
		t.Fatalf("Location = %q, want ambiguous key error", got)
	}
	override, _ = store.GetFeedConfig(context.Background(), "vulncheck")
	if override == nil || override.APIKey != "old-key" {
		t.Fatalf("override after ambiguous clear = %+v, want old key", override)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":             {"vulncheck"},
		"enabled":               {"on"},
		"mode":                  {"self"},
		"clear_api_key":         {"on"},
		"confirm_clear_api_key": {"on"},
	})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigSave status = %d, want 303", rec.Code)
	}
	override, _ = store.GetFeedConfig(context.Background(), "vulncheck")
	if override == nil || override.APIKey != "" {
		t.Fatalf("override after confirmed clear = %+v, want empty API key", override)
	}
}

func TestAdminFeedConfigResetRequiresConfirmation(t *testing.T) {
	store := newAdminStoreStub()
	store.feedConfigs["vulncheck"] = db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: "self", APIKey: "old-key"}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"vulncheck"}})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Confirm+feed+configuration+reset") {
		t.Fatalf("Location = %q, want reset confirmation error", got)
	}
	if override, _ := store.GetFeedConfig(context.Background(), "vulncheck"); override == nil {
		t.Fatal("override was deleted without reset confirmation")
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
		"feed_name":     {"vulncheck"},
		"confirm_reset": {"on"},
	})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigReset status = %d, want 303", rec.Code)
	}
	if override, _ := store.GetFeedConfig(context.Background(), "vulncheck"); override != nil {
		t.Fatalf("override after confirmed reset = %+v, want nil", override)
	}
}

func TestAdminFeedConfigSaveDoesNotPersistWithoutAuditOrApply(t *testing.T) {
	t.Run("missing apply callback", func(t *testing.T) {
		store := newAdminStoreStub()
		handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		handler.SetFeedConfigApplyFunc(nil)
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
			"feed_name": {"osv"},
			"enabled":   {"on"},
			"mode":      {"self"},
		})
		rec := httptest.NewRecorder()
		handler.HandleFeedConfigSave(rec, req)
		if got := rec.Header().Get("Location"); !strings.Contains(got, "runtime+apply+is+unavailable") {
			t.Fatalf("Location = %q, want missing runtime apply error", got)
		}
		if override, _ := store.GetFeedConfig(context.Background(), "osv"); override != nil {
			t.Fatalf("override after missing apply callback = %+v, want nil", override)
		}
		audit, err := store.ListAdminAuditLog(context.Background(), 10)
		if err != nil {
			t.Fatalf("ListAdminAuditLog() error = %v", err)
		}
		if len(audit) != 0 {
			t.Fatalf("audit after missing apply callback = %+v, want none", audit)
		}
	})

	t.Run("audit failure", func(t *testing.T) {
		store := failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}
		handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
			"feed_name": {"osv"},
			"enabled":   {"on"},
			"mode":      {"self"},
		})
		rec := httptest.NewRecorder()
		handler.HandleFeedConfigSave(rec, req)
		if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+record+audit+log") {
			t.Fatalf("Location = %q, want audit failure", got)
		}
		if override, _ := store.GetFeedConfig(context.Background(), "osv"); override != nil {
			t.Fatalf("override after audit failure = %+v, want nil", override)
		}
	})

	t.Run("apply failure rolls back new override", func(t *testing.T) {
		store := newAdminStoreStub()
		handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		handler.SetFeedConfigApplyFunc(func(context.Context, config.FeedSettings) error {
			return context.Canceled
		})
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
			"feed_name": {"osv"},
			"enabled":   {"on"},
			"mode":      {"self"},
		})
		rec := httptest.NewRecorder()
		handler.HandleFeedConfigSave(rec, req)
		if got := rec.Header().Get("Location"); !strings.Contains(got, "applying+it+failed") {
			t.Fatalf("Location = %q, want apply failure", got)
		}
		if override, _ := store.GetFeedConfig(context.Background(), "osv"); override != nil {
			t.Fatalf("override after apply failure = %+v, want nil rollback", override)
		}
		audit, err := store.ListAdminAuditLog(context.Background(), 10)
		if err != nil {
			t.Fatalf("ListAdminAuditLog() error = %v", err)
		}
		if len(audit) != 0 {
			t.Fatalf("audit after apply failure = %+v, want none", audit)
		}
	})

	t.Run("missing reset callback", func(t *testing.T) {
		store := newAdminStoreStub()
		store.feedConfigs["vulncheck"] = db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: "self", APIKey: "old-key"}
		handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		handler.SetFeedConfigResetFunc(nil)
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
			"feed_name":     {"vulncheck"},
			"confirm_reset": {"on"},
		})
		rec := httptest.NewRecorder()
		handler.HandleFeedConfigReset(rec, req)
		if got := rec.Header().Get("Location"); !strings.Contains(got, "runtime+reset+is+unavailable") {
			t.Fatalf("Location = %q, want missing runtime reset error", got)
		}
		override, _ := store.GetFeedConfig(context.Background(), "vulncheck")
		if override == nil || override.APIKey != "old-key" {
			t.Fatalf("override after missing reset callback = %+v, want unchanged old key", override)
		}
		audit, err := store.ListAdminAuditLog(context.Background(), 10)
		if err != nil {
			t.Fatalf("ListAdminAuditLog() error = %v", err)
		}
		if len(audit) != 0 {
			t.Fatalf("audit after missing reset callback = %+v, want none", audit)
		}
	})

	t.Run("reset apply failure restores override", func(t *testing.T) {
		store := newAdminStoreStub()
		store.feedConfigs["vulncheck"] = db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: "self", APIKey: "old-key"}
		handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		handler.SetFeedConfigResetFunc(func(context.Context, string) (config.FeedSettings, bool, error) {
			return config.FeedSettings{}, false, context.Canceled
		})
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
			"feed_name":     {"vulncheck"},
			"confirm_reset": {"on"},
		})
		rec := httptest.NewRecorder()
		handler.HandleFeedConfigReset(rec, req)
		if got := rec.Header().Get("Location"); !strings.Contains(got, "applying+it+failed") {
			t.Fatalf("Location = %q, want reset apply failure", got)
		}
		override, _ := store.GetFeedConfig(context.Background(), "vulncheck")
		if override == nil || override.APIKey != "old-key" {
			t.Fatalf("override after reset rollback = %+v, want restored old key", override)
		}
		audit, err := store.ListAdminAuditLog(context.Background(), 10)
		if err != nil {
			t.Fatalf("ListAdminAuditLog() error = %v", err)
		}
		if len(audit) != 0 {
			t.Fatalf("audit after reset apply failure = %+v, want none", audit)
		}
	})
}

type failingFeedConfigUpsertWithAuditStore struct {
	*adminFlowStoreStub
	err error
}

func (s failingFeedConfigUpsertWithAuditStore) UpsertFeedConfigWithAudit(context.Context, *db.FeedConfig, *db.AdminAuditEntry) error {
	return s.err
}

type failingFeedConfigDeleteWithAuditStore struct {
	*adminFlowStoreStub
	err error
}

func (s failingFeedConfigDeleteWithAuditStore) DeleteFeedConfigWithAudit(context.Context, string, *time.Time, *db.AdminAuditEntry) error {
	return s.err
}

type conflictingFeedConfigUpsertStore struct {
	*adminFlowStoreStub
	cfg    *config.Config
	newer  config.FeedSettings
	t      *testing.T
	called bool
}

func (s *conflictingFeedConfigUpsertStore) UpsertFeedConfigWithAudit(context.Context, *db.FeedConfig, *db.AdminAuditEntry) error {
	s.called = true
	s.mu.Lock()
	record := db.FeedConfig{
		FeedName:  s.newer.Name,
		Enabled:   s.newer.Enabled,
		Mode:      string(s.newer.Mode),
		UpdatedAt: time.Now().UTC(),
	}
	if s.newer.SupportsSyncInterval && s.newer.SyncInterval > 0 {
		interval := s.newer.SyncInterval
		record.SyncInterval = &interval
	}
	s.feedConfigs[config.NormalizeFeedName(s.newer.Name)] = record
	s.mu.Unlock()
	if err := s.cfg.SetFeedSettings(s.newer); err != nil {
		s.t.Fatalf("SetFeedSettings(newer) error = %v", err)
	}
	return db.ErrConflict
}

type conflictingFeedConfigDeleteStore struct {
	*adminFlowStoreStub
	cfg    *config.Config
	newer  config.FeedSettings
	t      *testing.T
	called bool
}

func (s *conflictingFeedConfigDeleteStore) DeleteFeedConfigWithAudit(context.Context, string, *time.Time, *db.AdminAuditEntry) error {
	s.called = true
	s.mu.Lock()
	record := db.FeedConfig{
		FeedName:  s.newer.Name,
		Enabled:   s.newer.Enabled,
		Mode:      string(s.newer.Mode),
		APIKey:    s.newer.APIKey,
		UpdatedAt: time.Now().UTC(),
	}
	s.feedConfigs[config.NormalizeFeedName(s.newer.Name)] = record
	s.mu.Unlock()
	if err := s.cfg.SetFeedSettings(s.newer); err != nil {
		s.t.Fatalf("SetFeedSettings(newer reset) error = %v", err)
	}
	return db.ErrConflict
}

func TestAdminFeedConfigSaveRollsBackRuntimeWhenPersistFailsAfterApply(t *testing.T) {
	baseStore := newAdminStoreStub()
	store := failingFeedConfigUpsertWithAuditStore{
		adminFlowStoreStub: baseStore,
		err:                errors.New("database down"),
	}
	cfg := adminFlowConfig()
	handler, sm := newAdminHandlerForStore(t, store, cfg)
	applies := 0
	handler.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		applies++
		return cfg.SetFeedSettings(feed)
	})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name": {"osv"},
		"mode":      {"self"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)

	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+save+feed+configuration") {
		t.Fatalf("Location = %q, want save failure", got)
	}
	if applies != 2 {
		t.Fatalf("apply calls = %d, want desired apply plus rollback", applies)
	}
	runtimeFeed, _ := cfg.FeedSettings("osv")
	if !runtimeFeed.Enabled || runtimeFeed.Mode != config.FeedModeSelf {
		t.Fatalf("runtime feed after rollback = %+v, want original enabled self config", runtimeFeed)
	}
	if override, _ := baseStore.GetFeedConfig(context.Background(), "osv"); override != nil {
		t.Fatalf("override after failed save = %+v, want none", override)
	}
	audit, err := baseStore.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after failed save = %+v, want none", audit)
	}
}

func TestAdminFeedConfigSaveDoesNotRollbackNewerRuntimeAfterConflict(t *testing.T) {
	baseStore := newAdminStoreStub()
	cfg := adminFlowConfig()
	newer, ok := cfg.FeedSettings("osv")
	if !ok {
		t.Fatal("missing osv runtime config")
	}
	newer.Enabled = false
	newer.Mode = config.FeedModeSelf
	store := &conflictingFeedConfigUpsertStore{
		adminFlowStoreStub: baseStore,
		cfg:                cfg,
		newer:              newer,
		t:                  t,
	}
	handler, sm := newAdminHandlerForStore(t, store, cfg)
	handler.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		return cfg.SetFeedSettings(feed)
	})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name": {"osv"},
		"mode":      {"external"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigSave status = %d, want 303", rec.Code)
	}
	if !store.called {
		t.Fatal("UpsertFeedConfigWithAudit was not called")
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "changed+while+you+were+editing") {
		t.Fatalf("Location = %q, want conflict message", got)
	}
	runtimeFeed, _ := cfg.FeedSettings("osv")
	if runtimeFeed.Enabled != newer.Enabled || runtimeFeed.Mode != newer.Mode {
		t.Fatalf("runtime feed after stale save = %+v, want newer runtime %+v", runtimeFeed, newer)
	}
	override, _ := baseStore.GetFeedConfig(context.Background(), "osv")
	if override == nil || override.Enabled != newer.Enabled || override.Mode != string(newer.Mode) {
		t.Fatalf("persisted feed after stale save = %+v, want newer override", override)
	}
	audit, err := baseStore.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after stale save = %+v, want none", audit)
	}
}

func TestAdminFeedConfigResetDoesNotRollbackNewerRuntimeAfterConflict(t *testing.T) {
	baseStore := newAdminStoreStub()
	baseStore.feedConfigs["vulncheck"] = db.FeedConfig{
		FeedName: "vulncheck",
		Enabled:  true,
		Mode:     string(config.FeedModeSelf),
		APIKey:   "old-key",
	}
	cfg := adminFlowConfig()
	previous, ok := cfg.FeedSettings("vulncheck")
	if !ok {
		t.Fatal("missing vulncheck runtime config")
	}
	previous.Enabled = true
	previous.Mode = config.FeedModeSelf
	previous.APIKey = "old-key"
	if err := cfg.SetFeedSettings(previous); err != nil {
		t.Fatalf("SetFeedSettings(previous) error = %v", err)
	}
	newer := previous
	newer.APIKey = "newer-key"
	store := &conflictingFeedConfigDeleteStore{
		adminFlowStoreStub: baseStore,
		cfg:                cfg,
		newer:              newer,
		t:                  t,
	}
	handler, sm := newAdminHandlerForStore(t, store, cfg)
	handler.SetFeedConfigResetFunc(func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
		reset, ok := cfg.FeedSettings(feedName)
		if !ok {
			return config.FeedSettings{}, false, errors.New("missing feed")
		}
		reset.Enabled = false
		reset.APIKey = ""
		return reset, true, cfg.SetFeedSettings(reset)
	})
	handler.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		return cfg.SetFeedSettings(feed)
	})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
		"feed_name":     {"vulncheck"},
		"confirm_reset": {"on"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigReset status = %d, want 303", rec.Code)
	}
	if !store.called {
		t.Fatal("DeleteFeedConfigWithAudit was not called")
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "changed+while+you+were+editing") {
		t.Fatalf("Location = %q, want conflict message", got)
	}
	runtimeFeed, _ := cfg.FeedSettings("vulncheck")
	if runtimeFeed.APIKey != "newer-key" || !runtimeFeed.Enabled || runtimeFeed.Mode != config.FeedModeSelf {
		t.Fatalf("runtime feed after stale reset = %+v, want newer runtime %+v", runtimeFeed, newer)
	}
	override, _ := baseStore.GetFeedConfig(context.Background(), "vulncheck")
	if override == nil || override.APIKey != "newer-key" {
		t.Fatalf("persisted feed after stale reset = %+v, want newer override", override)
	}
	audit, err := baseStore.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after stale reset = %+v, want none", audit)
	}
}

func TestAdminFeedConfigResetRollsBackRuntimeWhenPersistFailsAfterApply(t *testing.T) {
	baseStore := newAdminStoreStub()
	baseStore.feedConfigs["vulncheck"] = db.FeedConfig{
		FeedName: "vulncheck",
		Enabled:  true,
		Mode:     string(config.FeedModeSelf),
		APIKey:   "old-key",
	}
	store := failingFeedConfigDeleteWithAuditStore{
		adminFlowStoreStub: baseStore,
		err:                errors.New("database down"),
	}
	cfg := adminFlowConfig()
	previousRuntime, ok := cfg.FeedSettings("vulncheck")
	if !ok {
		t.Fatal("missing vulncheck runtime config")
	}
	previousRuntime.Enabled = true
	previousRuntime.Mode = config.FeedModeSelf
	previousRuntime.APIKey = "old-key"
	if err := cfg.SetFeedSettings(previousRuntime); err != nil {
		t.Fatalf("SetFeedSettings(previous) error = %v", err)
	}
	handler, sm := newAdminHandlerForStore(t, store, cfg)
	handler.SetFeedConfigResetFunc(func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
		defaultRuntime, ok := cfg.FeedSettings(feedName)
		if !ok {
			return config.FeedSettings{}, false, errors.New("missing feed")
		}
		defaultRuntime.Enabled = false
		defaultRuntime.APIKey = ""
		return defaultRuntime, true, cfg.SetFeedSettings(defaultRuntime)
	})
	handler.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		return cfg.SetFeedSettings(feed)
	})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
		"feed_name":     {"vulncheck"},
		"confirm_reset": {"on"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)

	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+reset+feed+configuration") {
		t.Fatalf("Location = %q, want reset failure", got)
	}
	runtimeFeed, _ := cfg.FeedSettings("vulncheck")
	if !runtimeFeed.Enabled || runtimeFeed.Mode != config.FeedModeSelf || runtimeFeed.APIKey != "old-key" {
		t.Fatalf("runtime feed after rollback = %+v, want previous override", runtimeFeed)
	}
	override, _ := baseStore.GetFeedConfig(context.Background(), "vulncheck")
	if override == nil || override.APIKey != "old-key" {
		t.Fatalf("override after failed reset = %+v, want old override", override)
	}
	audit, err := baseStore.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit after failed reset = %+v, want none", audit)
	}
}

func TestParseAdminFormRejectsMalformedAndOversizedBodies(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/feeds/save", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if parseAdminForm(rec, req) {
		t.Fatal("parseAdminForm(malformed) = true, want false")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed status = %d, want 400", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/feeds/save", strings.NewReader("x="+strings.Repeat("a", maxAdminFormBytes+1)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if parseAdminForm(rec, req) {
		t.Fatal("parseAdminForm(oversized) = true, want false")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d, want 413", rec.Code)
	}
}

func TestAdminFeedSyncNowHTMXAndUnavailableBranches(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"unknown"}})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Unknown feed") {
		t.Fatalf("unknown feed response = %d %q", rec.Code, rec.Body.String())
	}
	for _, want := range []string{
		`role="alert"`,
		`aria-live="assertive"`,
		`aria-atomic="true"`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("unknown feed HTMX response missing accessible error marker %q: %s", want, rec.Body.String())
		}
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"socket"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Manual+sync+is+not+available") {
		t.Fatalf("Location = %q, want unavailable sync", got)
	}

	disabledCfg := adminFlowConfig()
	disabledCfg.Feeds.OSVEnabled = false
	handler, sm, _ = newAdminFlowHandler(t, store, disabledCfg, func(context.Context, string) error {
		t.Fatal("syncFeed called for disabled feed")
		return nil
	})
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "enabled self-managed") {
		t.Fatalf("disabled feed sync response = %d %q", rec.Code, rec.Body.String())
	}

	externalCfg := adminFlowConfig()
	externalCfg.Feeds.OSVMode = config.FeedModeExternal
	handler, sm, _ = newAdminFlowHandler(t, store, externalCfg, func(context.Context, string) error {
		t.Fatal("syncFeed called for external feed")
		return nil
	})
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "enabled self-managed") {
		t.Fatalf("external feed sync response = %d %q", rec.Code, rec.Body.String())
	}

	called := make(chan string, 1)
	handler, sm, _ = newAdminFlowHandler(t, store, adminFlowConfig(), func(_ context.Context, feedName string) error {
		called <- feedName
		return nil
	})
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sync status = %d, want 200", rec.Code)
	}
	for _, want := range []string{
		`role="status"`,
		`aria-live="polite"`,
		`OSV sync started with current runtime settings.`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("successful HTMX sync response missing %q: %s", want, rec.Body.String())
		}
	}
	if trigger := rec.Header().Get("HX-Trigger"); !strings.Contains(trigger, "feed-runtime-refresh") {
		t.Fatalf("HX-Trigger = %q, want runtime refresh", trigger)
	}
	select {
	case got := <-called:
		if got != "osv" {
			t.Fatalf("sync feed = %q, want osv", got)
		}
	case <-time.After(time.Second):
		t.Fatal("syncFeed was not called")
	}
}

func TestAdminFeedSyncNowRejectsOverlappingManualSync(t *testing.T) {
	store := newAdminStoreStub()
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig(), func(ctx context.Context, _ string) error {
		started <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	defer close(release)

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first sync status = %d, want 200", rec.Code)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first manual sync did not start")
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("overlapping sync status = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "already running") {
		t.Fatalf("overlapping sync body = %q, want already running message", rec.Body.String())
	}
	select {
	case <-started:
		t.Fatal("overlapping manual sync started a second goroutine")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestAdminFeedSyncNowDoesNotStartWhenAuditFails(t *testing.T) {
	baseStore := newAdminStoreStub()
	called := make(chan string, 1)
	handler, sm, _ := newAdminFlowHandler(t, baseStore, adminFlowConfig(), func(_ context.Context, feedName string) error {
		called <- feedName
		return nil
	})
	handler.store = adaptAdminStore(failingAuditStore{adminFlowStoreStub: baseStore})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("sync audit failure status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Failed to record audit log") {
		t.Fatalf("sync audit failure body = %q, want audit error", rec.Body.String())
	}
	select {
	case got := <-called:
		t.Fatalf("syncFeed called despite audit failure for %q", got)
	case <-time.After(50 * time.Millisecond):
	}
	status, err := baseStore.GetFeedSyncStatus(context.Background(), "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status != nil {
		t.Fatalf("feed status = %+v, want no running status when audit fails", status)
	}
	if !handler.beginManualFeedSync("osv") {
		t.Fatal("manual sync slot remained reserved after audit failure")
	}
	handler.endManualFeedSync("osv")
}

type blockingAuditStore struct {
	*adminFlowStoreStub
	started chan<- struct{}
	release <-chan struct{}
	err     error
}

func (s blockingAuditStore) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.err != nil {
		return s.err
	}
	return s.adminFlowStoreStub.InsertAdminAuditLog(ctx, entry)
}

func TestAdminFeedSyncNowDoesNotReserveSlotBeforeAuditSucceeds(t *testing.T) {
	baseStore := newAdminStoreStub()
	called := make(chan string, 1)
	handler, sm, _ := newAdminFlowHandler(t, baseStore, adminFlowConfig(), func(_ context.Context, feedName string) error {
		called <- feedName
		return nil
	})
	auditStarted := make(chan struct{}, 1)
	releaseAudit := make(chan struct{})
	handler.store = adaptAdminStore(blockingAuditStore{
		adminFlowStoreStub: baseStore,
		started:            auditStarted,
		release:            releaseAudit,
		err:                errors.New("audit down"),
	})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.HandleFeedSyncNow(rec, req)
		close(done)
	}()

	select {
	case <-auditStarted:
	case <-time.After(time.Second):
		close(releaseAudit)
		t.Fatal("manual sync audit did not start")
	}

	releasedAudit := false
	releaseBlockedAudit := func() {
		if !releasedAudit {
			close(releaseAudit)
			releasedAudit = true
		}
	}

	reserved := make(chan bool, 1)
	go func() {
		reserved <- handler.beginManualFeedSync("osv")
	}()
	select {
	case ok := <-reserved:
		if !ok {
			releaseBlockedAudit()
			t.Fatal("manual sync slot was reserved before audit succeeded")
		}
	case <-time.After(250 * time.Millisecond):
		releaseBlockedAudit()
		select {
		case ok := <-reserved:
			if ok {
				handler.endManualFeedSync("osv")
			}
		case <-time.After(time.Second):
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("manual sync slot check blocked before audit succeeded")
	}
	handler.endManualFeedSync("osv")

	releaseBlockedAudit()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HandleFeedSyncNow did not return after releasing audit")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("sync audit failure status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	select {
	case got := <-called:
		t.Fatalf("syncFeed called despite audit failure for %q", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMarkFeedSyncRunningPreservesStatusMetadataAndHandlesErrors(t *testing.T) {
	store := newAdminErrorStore()
	handler, _ := newAdminHandlerForStore(t, store, adminFlowConfig())

	if err := handler.markFeedSyncRunning(context.Background(), "", "osv"); err != nil {
		t.Fatalf("initial markFeedSyncRunning() error = %v", err)
	}
	status, err := store.GetFeedSyncStatus(context.Background(), "osv")
	if err != nil {
		t.Fatalf("initial GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "running" {
		t.Fatalf("initial status = %+v, want running", status)
	}
	if status.LastSyncAt != nil {
		t.Fatalf("initial LastSyncAt = %v, want nil before usable feed data exists", status.LastSyncAt)
	}

	store = newAdminErrorStore()
	metadata := []byte(`{"cursor":"old"}`)
	lastSuccessfulSync := time.Now().UTC().Add(-72 * time.Hour)
	store.feedStatuses["osv"] = db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: "success",
		LastSyncAt:     &lastSuccessfulSync,
		EntriesSynced:  12,
		EntriesTotal:   15,
		LastCommitHash: "commit-old",
		LastETag:       "etag-old",
		Metadata:       metadata,
	}
	handler, _ = newAdminHandlerForStore(t, store, adminFlowConfig())

	if err := handler.markFeedSyncRunning(context.Background(), "", "osv"); err != nil {
		t.Fatalf("markFeedSyncRunning() error = %v", err)
	}
	metadata[0] = '['

	status, err = store.GetFeedSyncStatus(context.Background(), "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "running" {
		t.Fatalf("status = %+v, want running", status)
	}
	if status.LastSyncAt == nil || !status.LastSyncAt.Equal(lastSuccessfulSync) {
		t.Fatalf("LastSyncAt = %v, want preserved successful sync time %v", status.LastSyncAt, lastSuccessfulSync)
	}
	if status.EntriesSynced != 12 || status.EntriesTotal != 15 || status.LastCommitHash != "commit-old" || status.LastETag != "etag-old" {
		t.Fatalf("status lost previous metadata: %+v", status)
	}
	if string(status.Metadata) != `{"cursor":"old"}` {
		t.Fatalf("metadata = %s, want copied metadata", string(status.Metadata))
	}

	before := store.feedStatuses["osv"]
	store.fail = map[string]error{"GetFeedSyncStatus": context.Canceled}
	if err := handler.markFeedSyncRunning(context.Background(), "", "osv"); !errors.Is(err, context.Canceled) {
		t.Fatalf("markFeedSyncRunning() error = %v, want load failure", err)
	}
	after := store.feedStatuses["osv"]
	if after.LastSyncStatus != before.LastSyncStatus ||
		after.LastSyncAt == nil ||
		!after.LastSyncAt.Equal(lastSuccessfulSync) ||
		after.EntriesSynced != before.EntriesSynced ||
		after.EntriesTotal != before.EntriesTotal ||
		after.LastCommitHash != before.LastCommitHash ||
		after.LastETag != before.LastETag ||
		string(after.Metadata) != string(before.Metadata) {
		t.Fatalf("status after failed preservation load = %+v, want unchanged %+v", after, before)
	}
}

func TestAdminQueueValidationBranches(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/queue/priority", url.Values{"job_id": {"bad"}, "priority": {"1"}})
	rec := httptest.NewRecorder()
	handler.HandleQueuePriorityUpdate(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Invalid+queue+job+ID") {
		t.Fatalf("Location = %q, want invalid job id", got)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/queue/priority", url.Values{"job_id": {"1"}, "priority": {"99"}})
	rec = httptest.NewRecorder()
	handler.HandleQueuePriorityUpdate(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Invalid+priority") {
		t.Fatalf("Location = %q, want invalid priority", got)
	}

	store.addQueueJob("pending")
	store.addQueueJob("paused")
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/queue/clear", url.Values{"status": {"all"}})
	rec = httptest.NewRecorder()
	handler.HandleQueueClear(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Cleared+2+queue+jobs") {
		t.Fatalf("Location = %q, want clear all message", got)
	}
}

func TestAdminQueuePriorityRejectsUndocumentedLevelsWithoutAudit(t *testing.T) {
	for _, priority := range []string{"4", "9"} {
		t.Run(priority, func(t *testing.T) {
			store := newAdminStoreStub()
			jobID := store.addQueueJob("pending")
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/queue/priority", url.Values{
				"job_id":   {strconv.Itoa(jobID)},
				"priority": {priority},
			})
			rec := httptest.NewRecorder()
			handler.HandleQueuePriorityUpdate(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("HandleQueuePriorityUpdate status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, "Invalid+priority") {
				t.Fatalf("Location = %q, want invalid priority redirect", got)
			}
			jobs, err := store.ListQueueJobs(context.Background(), "", 10)
			if err != nil {
				t.Fatalf("ListQueueJobs() error = %v", err)
			}
			if len(jobs) != 1 || jobs[0].Priority != 3 {
				t.Fatalf("jobs after rejected priority = %+v, want priority 3", jobs)
			}
			audit, err := store.ListAdminAuditLog(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if adminFlowAuditContains(audit, "queue_priority_update") {
				t.Fatalf("audit log contains queue_priority_update after rejected priority: %+v", audit)
			}
		})
	}
}

func TestAdminQueueClearRejectsInvalidStatusesWithoutAudit(t *testing.T) {
	for _, tt := range []struct {
		name   string
		values url.Values
	}{
		{name: "empty", values: url.Values{}},
		{name: "processing", values: url.Values{"status": {"processing"}}},
		{name: "bogus", values: url.Values{"status": {"bogus"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newAdminStoreStub()
			store.addQueueJob("pending")
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/queue/clear", tt.values)
			rec := httptest.NewRecorder()
			handler.HandleQueueClear(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("HandleQueueClear status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, "Invalid+queue+status") {
				t.Fatalf("Location = %q, want invalid status redirect", got)
			}
			jobs, err := store.ListQueueJobs(context.Background(), "", 10)
			if err != nil {
				t.Fatalf("ListQueueJobs() error = %v", err)
			}
			if len(jobs) != 1 || jobs[0].Status != "pending" {
				t.Fatalf("jobs after rejected clear = %+v, want one pending job", jobs)
			}
			audit, err := store.ListAdminAuditLog(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if adminFlowAuditContains(audit, "queue_clear") {
				t.Fatalf("audit log contains queue_clear after rejected clear: %+v", audit)
			}
		})
	}
}

func TestAdminAdvisoryValidationBranches(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	cases := []struct {
		name   string
		values url.Values
		want   string
	}{
		{"required", url.Values{"ecosystem": {"npm"}}, "required"},
		{"severity", url.Values{"ecosystem": {"npm"}, "name": {"left-pad"}, "severity": {"INFO"}, "summary": {"sum"}}, "Invalid severity"},
		{"ecosystem", url.Values{"ecosystem": {"unknown"}, "name": {"left-pad"}, "severity": {"HIGH"}, "summary": {"sum"}}, "Unknown ecosystem"},
		{"length", url.Values{"ecosystem": {"npm"}, "name": {strings.Repeat("a", 257)}, "severity": {"HIGH"}, "summary": {"sum"}}, "maximum length"},
		{"feed id", url.Values{"id": {"GHSA-feed-id"}, "ecosystem": {"npm"}, "name": {"left-pad"}, "severity": {"HIGH"}, "summary": {"sum"}}, "must start with manual"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", tt.values)
			rec := httptest.NewRecorder()
			handler.HandleAdvisoryCreate(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
			}
			if got := rec.Header().Get("Location"); got != "" {
				t.Fatalf("validation error redirected to %q", got)
			}
			if body := rec.Body.String(); !strings.Contains(body, tt.want) {
				t.Fatalf("body missing %q:\n%s", tt.want, body)
			}
		})
	}

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryDelete(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Missing+advisory+ID") {
		t.Fatalf("Location = %q, want missing advisory ID", got)
	}
}

func TestAdminPasswordChangeValidationBranches(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, CreatedAt: time.Now().UTC()}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	cases := []struct {
		name   string
		values url.Values
		want   string
	}{
		{"mismatch", url.Values{"current_password": {"current-password"}, "new_password": {"new-password-123"}, "confirm_password": {"different"}}, "do+not+match"},
		{"short", url.Values{"current_password": {"current-password"}, "new_password": {"short"}, "confirm_password": {"short"}}, "at+least"},
		{"wrong current", url.Values{"current_password": {"wrong"}, "new_password": {"new-password-123"}, "confirm_password": {"new-password-123"}}, "incorrect"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", tt.values)
			rec := httptest.NewRecorder()
			handler.HandlePasswordChange(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, tt.want) {
				t.Fatalf("Location = %q, want %q", got, tt.want)
			}
		})
	}

	store.adminAuth = nil
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {"current-password"},
		"new_password":     {"new-password-123"},
		"confirm_password": {"new-password-123"},
	})
	rec := httptest.NewRecorder()
	handler.HandlePasswordChange(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+verify") {
		t.Fatalf("Location = %q, want verify failure", got)
	}
}
