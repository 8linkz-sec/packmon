package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
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
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: badSess.ID}) //nolint:gosec // test injects an in-memory pre-auth session cookie.
	rec := httptest.NewRecorder()
	handler.HandleLogin(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "Invalid request") {
		t.Fatalf("invalid CSRF login response = %d location=%q body=%q", rec.Code, rec.Header().Get("Location"), rec.Body.String())
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
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.ID}) //nolint:gosec // test injects an in-memory pre-auth session cookie.
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
	if audit[0].IP == "" {
		t.Fatalf("logout audit IP = %q, want source IP column populated", audit[0].IP)
	}
	var details map[string]string
	if err := json.Unmarshal(audit[0].Details, &details); err != nil {
		t.Fatalf("logout audit details JSON = %q: %v", string(audit[0].Details), err)
	}
	if _, ok := details["ip"]; ok {
		t.Fatalf("logout audit details duplicate IP: %v", details)
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

func TestAdminAuditPaginationRendersReachableHistory(t *testing.T) {
	store := newAdminStoreStub()
	for i := 1; i <= 105; i++ {
		action := fmt.Sprintf("audit_%03d", i)
		if err := store.InsertAdminAuditLog(context.Background(), &db.AdminAuditEntry{Action: action}); err != nil {
			t.Fatalf("InsertAdminAuditLog(%s) error = %v", action, err)
		}
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/audit")
	rec := httptest.NewRecorder()
	handler.HandleAdminAudit(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "audit_105") || strings.Contains(body, "audit_005") {
		t.Fatalf("first audit page did not show newest 100 only\nbody=%s", body)
	}
	if !strings.Contains(body, `/admin/audit?offset=100`) {
		t.Fatalf("first audit page missing next-page link\nbody=%s", body)
	}

	req, _ = authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/audit?offset=100")
	rec = httptest.NewRecorder()
	handler.HandleAdminAudit(rec, req)
	body = rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("page 2 status = %d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "audit_005") || strings.Contains(body, "audit_105") {
		t.Fatalf("second audit page did not show older entries\nbody=%s", body)
	}
	if !strings.Contains(body, `/admin/audit?offset=0`) {
		t.Fatalf("second audit page missing previous-page link\nbody=%s", body)
	}
}

func TestAdminQueuePaginationAndStatusFilterRenderReachableJobs(t *testing.T) {
	store := newAdminStoreStub()
	now := time.Now().UTC()
	for i := 1; i <= 55; i++ {
		store.queueJobs = append(store.queueJobs, db.RefreshJob{
			ID:          i,
			Ecosystem:   "npm",
			Name:        fmt.Sprintf("pkg-%03d", i),
			Source:      "socket",
			Priority:    3,
			Status:      "pending",
			RequestedAt: now.Add(time.Duration(i) * time.Second),
		})
	}
	store.queueJobs = append(store.queueJobs, db.RefreshJob{
		ID:          56,
		Ecosystem:   "npm",
		Name:        "error-only",
		Source:      "socket",
		Priority:    3,
		Status:      "error",
		RequestedAt: now.Add(56 * time.Second),
	})
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/queue?status=pending")
	rec := httptest.NewRecorder()
	handler.HandleAdminQueue(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "pkg-055") || strings.Contains(body, "pkg-005") || strings.Contains(body, "error-only") {
		t.Fatalf("first pending queue page did not show newest pending jobs only\nbody=%s", body)
	}
	if !strings.Contains(body, `/admin/queue?status=pending&amp;offset=50`) {
		t.Fatalf("first pending queue page missing next-page link\nbody=%s", body)
	}
	if !strings.Contains(body, `/admin/queue?status=error`) {
		t.Fatalf("queue status filter missing error link\nbody=%s", body)
	}

	req, _ = authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/queue?status=pending&offset=50")
	rec = httptest.NewRecorder()
	handler.HandleAdminQueue(rec, req)
	body = rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("page 2 status = %d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "pkg-005") || strings.Contains(body, "pkg-055") {
		t.Fatalf("second pending queue page did not show older pending jobs\nbody=%s", body)
	}
	if !strings.Contains(body, `/admin/queue?status=pending&amp;offset=0`) {
		t.Fatalf("second pending queue page missing previous-page link\nbody=%s", body)
	}
}

func TestAdminAuditHighlightsLockoutAndExposesFullDetails(t *testing.T) {
	store := newAdminStoreStub()
	longDetails := `{"event":"lockout","note":"` + strings.Repeat("a", 100) + `unique-tail-marker"}`
	if err := store.InsertAdminAuditLog(context.Background(), &db.AdminAuditEntry{
		Action:  "login_lockout",
		Details: json.RawMessage(longDetails),
		IP:      "127.0.0.1",
	}); err != nil {
		t.Fatalf("InsertAdminAuditLog() error = %v", err)
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/audit")
	rec := httptest.NewRecorder()
	handler.HandleAdminAudit(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "bg-amber-100 text-amber-800") {
		t.Fatalf("lockout audit action was not highlighted as warning\nbody=%s", body)
	}
	if !strings.Contains(body, "unique-tail-marker") {
		t.Fatalf("full audit details tail was not reachable in rendered page\nbody=%s", body)
	}
	if !strings.Contains(body, "Verified") {
		t.Fatalf("audit integrity status was not rendered\nbody=%s", body)
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
		{name: "feed disabled", feed: config.FeedSettings{Enabled: false, SupportsSyncInterval: true}, want: "disabled"},
		{name: "status disabled without timestamp", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncStatus: "disabled"}, want: "disabled"},
		{name: "external no sync", feed: config.FeedSettings{Enabled: true, Mode: config.FeedModeExternal}, want: "configured"},
		{name: "no interval support", feed: config.FeedSettings{Enabled: true}, want: "configured"},
		{name: "error without timestamp", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncStatus: "error", LastError: "boom"}, want: "error"},
		{name: "permanent error", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "permanent_error", EntriesTotal: 1}, want: "error"},
		{name: "error", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "error", EntriesTotal: 1}, want: "error"},
		{name: "running", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "running", EntriesTotal: 1}, want: "running"},
		{name: "skipped", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "skipped", EntriesTotal: 1}, want: "warning"},
		{name: "unknown status", feed: config.FeedSettings{Enabled: true, SupportsSyncInterval: true}, status: &db.FeedSyncStatus{LastSyncAt: &recent, LastSyncStatus: "failed", EntriesTotal: 1}, want: "error"},
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

func (s failingAuditStore) CreateAPIKeyWithAudit(context.Context, string, string, *time.Time, *db.AdminAuditEntry) (int, error) {
	return 0, errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) RevokeAPIKeyWithAudit(context.Context, int, *db.AdminAuditEntry) error {
	return errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) DeleteAPIKeyWithAudit(context.Context, int, *db.AdminAuditEntry) error {
	return errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) UpsertAdminAuthWithAudit(context.Context, string, bool, *db.AdminAuditEntry) error {
	return errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) PurgeQueueWithAudit(context.Context, *db.AdminAuditEntry) (int, error) {
	return 0, errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) UpdateQueueJobPriorityWithAudit(context.Context, int, int, *db.AdminAuditEntry) error {
	return errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) PauseQueueJobWithAudit(context.Context, int, *db.AdminAuditEntry) error {
	return errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) ResumeQueueJobWithAudit(context.Context, int, *db.AdminAuditEntry) error {
	return errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) RetryQueueJobWithAudit(context.Context, int, *db.AdminAuditEntry) error {
	return errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func (s failingAuditStore) ClearQueueWithAudit(context.Context, []string, *db.AdminAuditEntry) (int, error) {
	return 0, errors.Join(db.ErrAdminAuditLog, errors.New("audit down"))
}

func TestAuditLogReturnsStoreFailure(t *testing.T) {
	handler, sm := newAdminHandlerForStore(t, failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")

	if err := handler.auditLog(req, "test_action", map[string]string{"ok": "true"}); err == nil {
		t.Fatal("auditLog() error = nil, want store failure")
	}
}

type cancelAwareAuditStore struct {
	*adminFlowStoreStub
}

func (s cancelAwareAuditStore) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.adminFlowStoreStub.InsertAdminAuditLog(ctx, entry)
}

func TestAuditLogUsesIndependentContext(t *testing.T) {
	handler, sm := newAdminHandlerForStore(t, cancelAwareAuditStore{adminFlowStoreStub: newAdminStoreStub()}, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	if err := handler.auditLog(req, "test_action", map[string]string{"ok": "true"}); err != nil {
		t.Fatalf("auditLog() error = %v, want independent context", err)
	}
}
