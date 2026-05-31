package admin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
)

func TestAdminHandlerNilFeedConfigSetters(t *testing.T) {
	t.Parallel()

	var handler *AdminHandler
	handler.SetFeedConfigApplyFunc(func(context.Context, config.FeedSettings) error { return nil })
	handler.SetFeedConfigResetFunc(func(context.Context, string) error { return nil })
}

func TestHandleLoginInvalidCSRFAndMissingAdminBranches(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	badSess, err := sm.CreatePreAuth(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("CreatePreAuth(bad) error = %v", err)
	}
	badForm := url.Values{
		"username": {"admin"},
		"password": {"secret"},
		"_csrf":    {"bad-token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(badForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: badSess.ID})
	rec := httptest.NewRecorder()
	handler.HandleLogin(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/" {
		t.Fatalf("invalid CSRF login response = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	sess, err := sm.CreatePreAuth(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("CreatePreAuth() error = %v", err)
	}
	csrfToken, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken() error = %v", err)
	}
	form := url.Values{
		"username": {"admin"},
		"password": {"secret"},
		"_csrf":    {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.ID})
	rec = httptest.NewRecorder()
	handler.HandleLogin(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Admin account has not been configured") {
		t.Fatalf("missing admin login response = %d %q", rec.Code, rec.Body.String())
	}
}

func TestHandleLogoutSuccessAuditsAndRedirects(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/logout", url.Values{})
	rec := httptest.NewRecorder()
	handler.HandleLogout(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
		t.Fatalf("logout response = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "logout" {
		t.Fatalf("audit = %+v, want logout", audit)
	}
}

func TestAdminWriteHandlersRejectUnauthenticatedAndBadCSRF(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, CreatedAt: time.Now().UTC()}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	cases := []struct {
		name   string
		target string
		values url.Values
		call   func(http.ResponseWriter, *http.Request)
	}{
		{name: "feed save", target: "/admin/feeds/save", values: url.Values{"feed_name": {"osv"}, "mode": {"self"}}, call: handler.HandleFeedConfigSave},
		{name: "feed reset", target: "/admin/feeds/reset", values: url.Values{"feed_name": {"osv"}}, call: handler.HandleFeedConfigReset},
		{name: "feed sync", target: "/admin/feeds/sync", values: url.Values{"feed_name": {"osv"}}, call: handler.HandleFeedSyncNow},
		{name: "queue purge", target: "/admin/queue/purge", values: url.Values{}, call: handler.HandleQueuePurge},
		{name: "queue priority", target: "/admin/queue/priority", values: url.Values{"job_id": {"1"}, "priority": {"1"}}, call: handler.HandleQueuePriorityUpdate},
		{name: "queue pause", target: "/admin/queue/pause", values: url.Values{"job_id": {"1"}}, call: handler.HandleQueuePause},
		{name: "queue clear", target: "/admin/queue/clear", values: url.Values{"status": {"pending"}}, call: handler.HandleQueueClear},
		{name: "key create", target: "/admin/keys/create", values: url.Values{"name": {"ci"}}, call: handler.HandleKeyCreate},
		{name: "key revoke", target: "/admin/keys/revoke", values: url.Values{"key_id": {"1"}}, call: handler.HandleKeyRevoke},
		{name: "key delete", target: "/admin/keys/delete", values: url.Values{"key_id": {"1"}}, call: handler.HandleKeyDelete},
		{name: "advisory create", target: "/admin/advisories/create", values: url.Values{"id": {"manual:one"}, "ecosystem": {"npm"}, "name": {"pkg"}, "severity": {"HIGH"}, "summary": {"sum"}}, call: handler.HandleAdvisoryCreate},
		{name: "advisory delete", target: "/admin/advisories/delete", values: url.Values{"id": {"manual:one"}}, call: handler.HandleAdvisoryDelete},
		{name: "password change", target: "/admin/settings/password", values: url.Values{"current_password": {"current-password"}, "new_password": {"new-password-123"}, "confirm_password": {"new-password-123"}}, call: handler.HandlePasswordChange},
	}

	for _, tt := range cases {
		t.Run(tt.name+" unauthenticated", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(tt.values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			tt.call(rec, req)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
				t.Fatalf("unauthenticated response = %d %q", rec.Code, rec.Header().Get("Location"))
			}
		})

		t.Run(tt.name+" bad csrf", func(t *testing.T) {
			req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, tt.target)
			req.Body = io.NopCloser(strings.NewReader(tt.values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			tt.call(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("bad CSRF response = %d, want 403", rec.Code)
			}
		})
	}
}

func TestAdminPagesRenderOptionalDataBranches(t *testing.T) {
	now := time.Now().UTC()
	store := newAdminStoreStub()
	store.adminAuth = &db.AdminAuth{
		PasswordHash:        "hash",
		LastLoginAt:         &now,
		PasswordChangedAt:   &now,
		PasswordIsBootstrap: true,
		CreatedAt:           now,
	}
	store.systemSettings = &db.SystemSettings{
		BlockThreshold:     "MEDIUM",
		RateLimitPerMinute: 120,
		RateLimitBurst:     40,
		UpdatedAt:          now,
	}
	store.apiKeys = []db.APIKey{{ID: 1, Name: "ci", CreatedAt: now}}
	store.manual["manual:one"] = db.ManualAdvisory{
		ID:          "manual:one",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "summary",
	}
	if err := store.InsertAdminAuditLog(context.Background(), &db.AdminAuditEntry{Action: "null_details"}); err != nil {
		t.Fatalf("InsertAdminAuditLog() error = %v", err)
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	for _, tt := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{name: "keys", target: "/admin/keys", call: handler.HandleAdminKeys},
		{name: "advisories edit", target: "/admin/advisories?edit=manual:one", call: handler.HandleAdminAdvisories},
		{name: "audit null details", target: "/admin/audit", call: handler.HandleAdminAudit},
		{name: "settings stored", target: "/admin/settings", call: handler.HandleAdminSettings},
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

func TestAdminFeedHealthBranches(t *testing.T) {
	old := time.Now().Add(-72 * time.Hour)
	recent := time.Now().Add(-time.Hour)
	cases := []struct {
		name   string
		feed   config.FeedSettings
		status *db.FeedSyncStatus
		want   string
	}{
		{name: "external no sync", feed: config.FeedSettings{Enabled: true, Mode: config.FeedModeExternal}, want: "configured"},
		{name: "no interval support", feed: config.FeedSettings{Enabled: true}, want: "configured"},
		{name: "error", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "error", EntriesTotal: 1}, want: "error"},
		{name: "running", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "running", EntriesTotal: 1}, want: "running"},
		{name: "skipped", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "skipped", EntriesTotal: 1}, want: "warning"},
		{name: "stale", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &old, LastSyncStatus: "success", EntriesTotal: 1}, want: "warning"},
		{name: "zero entries", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "success"}, want: "warning"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := adminFeedHealth(tt.feed, tt.status); got != tt.want {
				t.Fatalf("adminFeedHealth() = %q, want %q", got, tt.want)
			}
		})
	}
}

type failingAuditStore struct {
	*adminFlowStoreStub
}

func (s failingAuditStore) InsertAdminAuditLog(context.Context, *db.AdminAuditEntry) error {
	return errors.New("audit down")
}

func TestAuditLogIgnoresStoreFailure(t *testing.T) {
	handler, sm := newAdminHandlerForStore(t, failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")

	handler.auditLog(req, "test_action", map[string]string{"ok": "true"})
}
