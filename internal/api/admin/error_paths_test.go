package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/web"
)

type adminErrorStore struct {
	*adminFlowStoreStub
	fail map[string]error
}

func newAdminErrorStore() *adminErrorStore {
	return &adminErrorStore{
		adminFlowStoreStub: newAdminStoreStub(),
		fail:               map[string]error{},
	}
}

func (s *adminErrorStore) err(name string) error {
	if err := s.fail[name]; err != nil {
		return err
	}
	return nil
}

func (s *adminErrorStore) GetAdminAuth(ctx context.Context) (*db.AdminAuth, error) {
	if err := s.err("GetAdminAuth"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.GetAdminAuth(ctx)
}

func (s *adminErrorStore) UpsertAdminAuth(ctx context.Context, passwordHash string, isBootstrap bool) error {
	if err := s.err("UpsertAdminAuth"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.UpsertAdminAuth(ctx, passwordHash, isBootstrap)
}

func (s *adminErrorStore) ListAPIKeys(ctx context.Context) ([]db.APIKey, error) {
	if err := s.err("ListAPIKeys"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.ListAPIKeys(ctx)
}

func (s *adminErrorStore) CreateAPIKey(ctx context.Context, name, keyHash string, expiresAt *time.Time) (int, error) {
	if err := s.err("CreateAPIKey"); err != nil {
		return 0, err
	}
	return s.adminFlowStoreStub.CreateAPIKey(ctx, name, keyHash, expiresAt)
}

func (s *adminErrorStore) RevokeAPIKey(ctx context.Context, keyID int) error {
	if err := s.err("RevokeAPIKey"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.RevokeAPIKey(ctx, keyID)
}

func (s *adminErrorStore) DeleteAPIKey(ctx context.Context, keyID int) error {
	if err := s.err("DeleteAPIKey"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.DeleteAPIKey(ctx, keyID)
}

func (s *adminErrorStore) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	if err := s.err("ListFeedSyncStatuses"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.ListFeedSyncStatuses(ctx)
}

func (s *adminErrorStore) GetFeedSyncStatus(ctx context.Context, feedName string) (*db.FeedSyncStatus, error) {
	if err := s.err("GetFeedSyncStatus"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.GetFeedSyncStatus(ctx, feedName)
}

func (s *adminErrorStore) UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error {
	if err := s.err("UpsertFeedSyncStatus"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.UpsertFeedSyncStatus(ctx, status)
}

func (s *adminErrorStore) GetFeedConfig(ctx context.Context, feedName string) (*db.FeedConfig, error) {
	if err := s.err("GetFeedConfig"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.GetFeedConfig(ctx, feedName)
}

func (s *adminErrorStore) UpsertFeedConfig(ctx context.Context, cfg *db.FeedConfig) error {
	if err := s.err("UpsertFeedConfig"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.UpsertFeedConfig(ctx, cfg)
}

func (s *adminErrorStore) DeleteFeedConfig(ctx context.Context, feedName string) error {
	if err := s.err("DeleteFeedConfig"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.DeleteFeedConfig(ctx, feedName)
}

func (s *adminErrorStore) ListFeedConfigs(ctx context.Context) ([]db.FeedConfig, error) {
	if err := s.err("ListFeedConfigs"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.ListFeedConfigs(ctx)
}

func (s *adminErrorStore) GetSystemSettings(ctx context.Context) (*db.SystemSettings, error) {
	if err := s.err("GetSystemSettings"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.GetSystemSettings(ctx)
}

func (s *adminErrorStore) UpsertSystemSettings(ctx context.Context, settings *db.SystemSettings) error {
	if err := s.err("UpsertSystemSettings"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.UpsertSystemSettings(ctx, settings)
}

func (s *adminErrorStore) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	if err := s.err("DashboardStats"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.DashboardStats(ctx)
}

func (s *adminErrorStore) ListManualAdvisories(ctx context.Context, limit int) ([]db.ManualAdvisory, error) {
	if err := s.err("ListManualAdvisories"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.ListManualAdvisories(ctx, limit)
}

func (s *adminErrorStore) UpsertManualAdvisory(ctx context.Context, advisory *db.ManualAdvisory) error {
	if err := s.err("UpsertManualAdvisory"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.UpsertManualAdvisory(ctx, advisory)
}

func (s *adminErrorStore) DeleteManualAdvisory(ctx context.Context, id string) error {
	if err := s.err("DeleteManualAdvisory"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.DeleteManualAdvisory(ctx, id)
}

func (s *adminErrorStore) ListAdminAuditLog(ctx context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	if err := s.err("ListAdminAuditLog"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.ListAdminAuditLog(ctx, limit)
}

func (s *adminErrorStore) QueueStats(ctx context.Context) (*db.QueueStatsResult, error) {
	if err := s.err("QueueStats"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.QueueStats(ctx)
}

func (s *adminErrorStore) ListQueueJobs(ctx context.Context, status string, limit int) ([]db.RefreshJob, error) {
	if err := s.err("ListQueueJobs"); err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.ListQueueJobs(ctx, status, limit)
}

func (s *adminErrorStore) PurgeQueue(ctx context.Context) (int, error) {
	if err := s.err("PurgeQueue"); err != nil {
		return 0, err
	}
	return s.adminFlowStoreStub.PurgeQueue(ctx)
}

func (s *adminErrorStore) UpdateQueueJobPriority(ctx context.Context, jobID, priority int) error {
	if err := s.err("UpdateQueueJobPriority"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.UpdateQueueJobPriority(ctx, jobID, priority)
}

func (s *adminErrorStore) PauseQueueJob(ctx context.Context, jobID int) error {
	if err := s.err("PauseQueueJob"); err != nil {
		return err
	}
	return s.adminFlowStoreStub.PauseQueueJob(ctx, jobID)
}

func (s *adminErrorStore) ClearQueue(ctx context.Context, statuses []string) (int, error) {
	if err := s.err("ClearQueue"); err != nil {
		return 0, err
	}
	return s.adminFlowStoreStub.ClearQueue(ctx, statuses)
}

func newAdminHandlerForStore(t *testing.T, store db.Store, cfg *config.Config) (*AdminHandler, *auth.SessionManager) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sm := auth.NewSessionManager(ctx, time.Hour, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var runtime *config.RuntimeSettings
	if cfg != nil {
		runtime = config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	} else {
		runtime = config.NewRuntimeSettings("CRITICAL", 60, 60)
	}
	return NewAdminHandler(ctx, store, sm, web.NewRenderer(web.TemplateFS(), false), logger, cfg, runtime, nil), sm
}

func TestAdminUnauthenticatedRedirectsIncludeHTMXBranch(t *testing.T) {
	store := newAdminStoreStub()
	handler, _, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	rec := httptest.NewRecorder()
	handler.HandleAdminKeys(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
		t.Fatalf("unauthenticated redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.HandleAdminKeys(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("HX-Redirect") != "/admin/login" {
		t.Fatalf("unauthenticated HTMX redirect = %d %q", rec.Code, rec.Header().Get("HX-Redirect"))
	}
}

func TestAdminPagesRenderFallbacksWhenStoreReadsFail(t *testing.T) {
	store := newAdminErrorStore()
	for _, name := range []string{
		"GetAdminAuth",
		"DashboardStats",
		"ListFeedSyncStatuses",
		"ListFeedConfigs",
		"QueueStats",
		"ListQueueJobs",
		"ListAPIKeys",
		"ListManualAdvisories",
		"ListAdminAuditLog",
		"GetSystemSettings",
	} {
		store.fail[name] = errors.New("db down")
	}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	for _, tt := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{name: "dashboard", target: "/admin/", call: handler.HandleDashboard},
		{name: "feeds", target: "/admin/feeds", call: handler.HandleAdminFeeds},
		{name: "feeds-runtime-partial", target: "/admin/feeds?partial=runtime", call: handler.HandleAdminFeeds},
		{name: "feeds-flash-partial", target: "/admin/feeds?partial=flash", call: handler.HandleAdminFeeds},
		{name: "queue", target: "/admin/queue", call: handler.HandleAdminQueue},
		{name: "keys", target: "/admin/keys", call: handler.HandleAdminKeys},
		{name: "advisories", target: "/admin/advisories", call: handler.HandleAdminAdvisories},
		{name: "audit", target: "/admin/audit", call: handler.HandleAdminAudit},
		{name: "settings", target: "/admin/settings", call: handler.HandleAdminSettings},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, tt.target)
			rec := httptest.NewRecorder()
			tt.call(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d body=%s", tt.target, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAdminWriteHandlersRedirectOnStoreFailures(t *testing.T) {
	store := newAdminErrorStore()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, CreatedAt: time.Now().UTC()}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	cases := []struct {
		name   string
		fail   string
		target string
		values url.Values
		call   func(http.ResponseWriter, *http.Request)
		want   string
	}{
		{name: "feed save", fail: "UpsertFeedConfig", target: "/admin/feeds/save", values: url.Values{"feed_name": {"osv"}, "mode": {"self"}}, call: handler.HandleFeedConfigSave, want: "Failed+to+save"},
		{name: "feed reset", fail: "DeleteFeedConfig", target: "/admin/feeds/reset", values: url.Values{"feed_name": {"osv"}}, call: handler.HandleFeedConfigReset, want: "Failed+to+reset"},
		{name: "key create", fail: "CreateAPIKey", target: "/admin/keys/create", values: url.Values{"name": {"ci"}}, call: handler.HandleKeyCreate, want: "Failed+to+create"},
		{name: "key revoke", fail: "RevokeAPIKey", target: "/admin/keys/revoke", values: url.Values{"key_id": {"1"}}, call: handler.HandleKeyRevoke, want: "Failed+to+revoke"},
		{name: "key delete", fail: "DeleteAPIKey", target: "/admin/keys/delete", values: url.Values{"key_id": {"1"}}, call: handler.HandleKeyDelete, want: "Failed+to+delete"},
		{name: "queue purge", fail: "PurgeQueue", target: "/admin/queue/purge", values: url.Values{}, call: handler.HandleQueuePurge, want: "err=Purge+failed"},
		{name: "queue priority", fail: "UpdateQueueJobPriority", target: "/admin/queue/priority", values: url.Values{"job_id": {"1"}, "priority": {"1"}}, call: handler.HandleQueuePriorityUpdate, want: "Priority+update+failed"},
		{name: "queue pause", fail: "PauseQueueJob", target: "/admin/queue/pause", values: url.Values{"job_id": {"1"}}, call: handler.HandleQueuePause, want: "Job+paused+failed"},
		{name: "queue clear", fail: "ClearQueue", target: "/admin/queue/clear", values: url.Values{"status": {"pending"}}, call: handler.HandleQueueClear, want: "Queue+clear+failed"},
		{name: "advisory create", fail: "UpsertManualAdvisory", target: "/admin/advisories/create", values: url.Values{"id": {"manual:one"}, "ecosystem": {"npm"}, "name": {"left-pad"}, "severity": {"HIGH"}, "summary": {"summary"}}, call: handler.HandleAdvisoryCreate, want: "Failed+to+create"},
		{name: "advisory delete", fail: "DeleteManualAdvisory", target: "/admin/advisories/delete", values: url.Values{"id": {"manual:one"}}, call: handler.HandleAdvisoryDelete, want: "Failed+to+delete"},
		{name: "system settings", fail: "UpsertSystemSettings", target: "/admin/settings/system", values: url.Values{"block_threshold": {"HIGH"}, "rate_limit_per_minute": {"120"}, "rate_limit_burst": {"30"}}, call: handler.HandleSystemSettingsSave, want: "Failed+to+save"},
		{name: "password change", fail: "UpsertAdminAuth", target: "/admin/settings/password", values: url.Values{"current_password": {"current-password"}, "new_password": {"new-password-123"}, "confirm_password": {"new-password-123"}}, call: handler.HandlePasswordChange, want: "Failed+to+update"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			store.fail = map[string]error{tt.fail: errors.New("db down")}
			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, tt.values)
			rec := httptest.NewRecorder()
			tt.call(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, tt.want) {
				t.Fatalf("Location = %q, want containing %q", got, tt.want)
			}
		})
	}
}

func TestAdminAdditionalValidationAndRenderBranches(t *testing.T) {
	store := newAdminErrorStore()
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req := httptest.NewRequest(http.MethodPost, "/admin/", nil)
	rec := httptest.NewRecorder()
	handler.HandleDashboard(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HandleDashboard(POST) status = %d, want 405", rec.Code)
	}

	req, _ = authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/login")
	rec = httptest.NewRecorder()
	handler.HandleLogin(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/" {
		t.Fatalf("HandleLogin(GET authenticated) = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	req = httptest.NewRequest(http.MethodGet, "/admin/logout", nil)
	rec = httptest.NewRecorder()
	handler.HandleLogout(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HandleLogout(GET) status = %d, want 405", rec.Code)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{})
	rec = httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Key+name+is+required") {
		t.Fatalf("key create missing name Location = %q", got)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{"name": {"ci"}, "expires_at": {"yesterday"}})
	rec = httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "invalid+expiration") {
		t.Fatalf("key create invalid expiry Location = %q", got)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/revoke", url.Values{"key_id": {"bad"}})
	rec = httptest.NewRecorder()
	handler.HandleKeyRevoke(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Invalid+key+ID") {
		t.Fatalf("key revoke invalid Location = %q", got)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/delete", url.Values{"key_id": {"bad"}})
	rec = httptest.NewRecorder()
	handler.HandleKeyDelete(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Invalid+key+ID") {
		t.Fatalf("key delete invalid Location = %q", got)
	}

	rec = httptest.NewRecorder()
	handler.renderAdmin(rec, "admin/does-not-exist.html", map[string]any{})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("renderAdmin(missing template) status = %d, want 500", rec.Code)
	}
}

func TestAdminAdvisoryCreateValidationBranches(t *testing.T) {
	store := newAdminErrorStore()
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	base := url.Values{
		"id":           {"manual:one"},
		"finding_type": {"vulnerability"},
		"ecosystem":    {"npm"},
		"name":         {"left-pad"},
		"severity":     {"HIGH"},
		"summary":      {"summary"},
	}
	cases := []struct {
		name   string
		mutate func(url.Values)
		want   string
	}{
		{name: "invalid finding type", mutate: func(v url.Values) { v.Set("finding_type", "other") }, want: "Invalid+finding+type"},
		{name: "missing required", mutate: func(v url.Values) { v.Set("summary", "") }, want: "required+fields"},
		{name: "invalid severity", mutate: func(v url.Values) { v.Set("severity", "INFO") }, want: "Invalid+severity"},
		{name: "unknown ecosystem", mutate: func(v url.Values) { v.Set("ecosystem", "unknown") }, want: "Unknown+ecosystem"},
		{name: "too long", mutate: func(v url.Values) { v.Set("name", strings.Repeat("x", 257)) }, want: "maximum+length"},
		{name: "non manual id", mutate: func(v url.Values) { v.Set("id", "GHSA-real") }, want: "manual%3A"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			values := url.Values{}
			for key, vals := range base {
				values[key] = append([]string(nil), vals...)
			}
			tt.mutate(values)
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", values)
			rec := httptest.NewRecorder()
			handler.HandleAdvisoryCreate(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, tt.want) {
				t.Fatalf("Location = %q, want containing %q", got, tt.want)
			}
		})
	}
}

func TestAdminFeedSyncResponseBranches(t *testing.T) {
	store := newAdminErrorStore()
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"missing"}})
	rec := httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "Unknown+feed") {
		t.Fatalf("unknown feed response = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"reversinglabs"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "Manual+sync") {
		t.Fatalf("unsupported sync response = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Manual sync") {
		t.Fatalf("htmx unavailable response = %d %q", rec.Code, rec.Body.String())
	}
}

func TestDesiredFeedSettingsStoredBranches(t *testing.T) {
	store := newAdminErrorStore()
	handler, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
	interval := 2 * time.Hour
	store.feedConfigs["vulncheck"] = db.FeedConfig{
		FeedName:     "vulncheck",
		Enabled:      true,
		Mode:         "self",
		APIKey:       "stored-key",
		SyncInterval: &interval,
	}
	feed, err := handler.desiredFeedSettings(context.Background(), "vulncheck")
	if err != nil {
		t.Fatalf("desiredFeedSettings: %v", err)
	}
	if feed.Mode != config.FeedModeSelf || feed.APIKey != "stored-key" || feed.SyncInterval != interval {
		t.Fatalf("feed = %+v, want stored mode/api key/interval", feed)
	}

	store.feedConfigs["vulncheck"] = db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: "bad"}
	if _, err := handler.desiredFeedSettings(context.Background(), "vulncheck"); err == nil || !strings.Contains(err.Error(), "invalid persisted mode") {
		t.Fatalf("desiredFeedSettings(invalid mode) = %v", err)
	}

	store.fail = map[string]error{"GetFeedConfig": errors.New("db down")}
	if _, err := handler.desiredFeedSettings(context.Background(), "vulncheck"); err == nil || !strings.Contains(err.Error(), "load persisted") {
		t.Fatalf("desiredFeedSettings(load error) = %v", err)
	}
}
