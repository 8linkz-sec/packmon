package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/requestctx"
	"github.com/8linkz-sec/packmon/internal/web"
)

type f067QueueReadStore struct {
	*adminFlowStoreStub
	mu         sync.Mutex
	statsCalls int
	listCalls  int
	pageCalls  int
}

func (s *f067QueueReadStore) QueueStats(ctx context.Context) (*db.QueueStatsResult, error) {
	s.mu.Lock()
	s.statsCalls++
	s.mu.Unlock()
	return s.adminFlowStoreStub.QueueStats(ctx)
}

func (s *f067QueueReadStore) ListQueueJobs(ctx context.Context, status string, limit int) ([]db.RefreshJob, error) {
	s.mu.Lock()
	s.listCalls++
	s.mu.Unlock()
	return s.adminFlowStoreStub.ListQueueJobs(ctx, status, limit)
}

func (s *f067QueueReadStore) ListQueueJobsPage(ctx context.Context, status string, limit, offset int) ([]db.RefreshJob, error) {
	s.mu.Lock()
	s.pageCalls++
	s.mu.Unlock()
	return s.adminFlowStoreStub.ListQueueJobsPage(ctx, status, limit, offset)
}

func (s *f067QueueReadStore) calls() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statsCalls, s.listCalls, s.pageCalls
}

type f067NonPagingStore struct {
	Store
	jobs       []adminQueueJob
	calls      int
	lastStatus string
	lastLimit  int
}

func (s *f067NonPagingStore) ListQueueJobs(_ context.Context, status string, limit int) ([]adminQueueJob, error) {
	s.calls++
	s.lastStatus = status
	s.lastLimit = limit
	return append([]adminQueueJob(nil), s.jobs...), nil
}

func TestF067UnauthenticatedQueueReturnsBeforeStoreReads(t *testing.T) {
	store := &f067QueueReadStore{adminFlowStoreStub: newAdminStoreStub()}
	h, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
	req := httptest.NewRequest(http.MethodGet, "/admin/queue", nil)
	rec := httptest.NewRecorder()

	h.HandleAdminQueue(rec, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login?next=%2Fadmin%2Fqueue" {
		t.Fatalf("unauthenticated queue response = %d %q, want 303 login redirect", rec.Code, rec.Header().Get("Location"))
	}
	stats, list, page := store.calls()
	if stats != 0 || list != 0 || page != 0 {
		t.Fatalf("unauthenticated queue store reads = stats %d/list %d/page %d, want zero", stats, list, page)
	}
}

func TestF067ListQueueJobsPageFallsBackForNonPagingStores(t *testing.T) {
	jobs := make([]adminQueueJob, adminQueuePageSize+1)
	for i := range jobs {
		jobs[i] = adminQueueJob{ID: i + 1, Status: db.RefreshStatusError}
	}
	store := &f067NonPagingStore{jobs: jobs}
	h := &AdminHandler{store: store}

	got, hasNext, err := h.listQueueJobsPage(context.Background(), db.RefreshStatusError, 0)
	if err != nil {
		t.Fatalf("listQueueJobsPage fallback: %v", err)
	}
	if len(got) != adminQueuePageSize || !hasNext {
		t.Fatalf("fallback page = %d jobs/hasNext %t, want %d/true", len(got), hasNext, adminQueuePageSize)
	}
	if store.calls != 1 || store.lastStatus != db.RefreshStatusError || store.lastLimit != adminQueuePageSize+1 {
		t.Fatalf("fallback call = count %d/status %q/limit %d, want 1/error/51", store.calls, store.lastStatus, store.lastLimit)
	}
	if got[0].ID != 1 || got[len(got)-1].ID != adminQueuePageSize {
		t.Fatalf("fallback truncation IDs = %d..%d, want 1..%d", got[0].ID, got[len(got)-1].ID, adminQueuePageSize)
	}

	got, hasNext, err = h.listQueueJobsPage(context.Background(), db.RefreshStatusError, 1)
	if err == nil || !strings.Contains(err.Error(), "pagination is not available") {
		t.Fatalf("positive-offset fallback error = %v, want unsupported pagination", err)
	}
	if got != nil || hasNext || store.calls != 1 {
		t.Fatalf("positive-offset fallback = jobs %#v/hasNext %t/calls %d, want nil/false/no store read", got, hasNext, store.calls)
	}
}

func TestF067QueueJobActionsRejectInvalidIDsWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		target     string
		action     string
		startState string
		call       func(*AdminHandler, http.ResponseWriter, *http.Request)
	}{
		{name: "pause", target: "/admin/queue/pause", action: "queue_pause", startState: db.RefreshStatusPending, call: (*AdminHandler).HandleQueuePause},
		{name: "resume", target: "/admin/queue/resume", action: "queue_resume", startState: db.RefreshStatusPaused, call: (*AdminHandler).HandleQueueResume},
		{name: "retry", target: "/admin/queue/retry", action: "queue_retry", startState: db.RefreshStatusError, call: (*AdminHandler).HandleQueueRetry},
	} {
		for _, invalidID := range []string{"not-an-id", "0", "-1"} {
			t.Run(tc.name+"/"+invalidID, func(t *testing.T) {
				store := newAdminStoreStub()
				jobID := store.addQueueJob(tc.startState)
				h, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
				req, _ := authenticatedAdminFormRequest(t, sm, tc.target, url.Values{"job_id": {invalidID}})
				rec := httptest.NewRecorder()

				tc.call(h, rec, req)

				if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "Invalid+queue+job+ID") {
					t.Fatalf("invalid %s ID %q response = %d %q, want invalid-ID redirect", tc.name, invalidID, rec.Code, rec.Header().Get("Location"))
				}
				jobs, err := store.ListQueueJobs(context.Background(), "", 10)
				if err != nil {
					t.Fatalf("ListQueueJobs: %v", err)
				}
				if len(jobs) != 1 || jobs[0].ID != jobID || jobs[0].Status != tc.startState {
					t.Fatalf("jobs after invalid %s ID %q = %+v, want unchanged %s job %d", tc.name, invalidID, jobs, tc.startState, jobID)
				}
				audit, err := store.ListAdminAuditLog(context.Background(), 10)
				if err != nil {
					t.Fatalf("ListAdminAuditLog: %v", err)
				}
				if adminFlowAuditContains(audit, tc.action) {
					t.Fatalf("invalid %s ID %q recorded %s audit: %+v", tc.name, invalidID, tc.action, audit)
				}
			})
		}
	}
}

func TestF067QueueHelpersRecoverFromNilUnknownAndUnfilteredInputs(t *testing.T) {
	t.Parallel()

	if got := adminQueueFilterCount("", nil); got != 0 {
		t.Fatalf("adminQueueFilterCount(empty,nil) = %d, want 0", got)
	}
	if got := adminQueuePurgeCount(nil); got != 0 {
		t.Fatalf("adminQueuePurgeCount(nil) = %d, want 0", got)
	}
	stats := &adminQueueStats{Pending: 1, Processing: 2, Paused: 3, Error: 4, Done: 5}
	if got := adminQueueFilterCount("unknown", stats); got != 0 {
		t.Fatalf("adminQueueFilterCount(unknown) = %d, want 0", got)
	}
	if got := adminQueueFilterCount("", stats); got != 15 {
		t.Fatalf("adminQueueFilterCount(unfiltered) = %d, want 15", got)
	}
	if status, warning := adminQueueStatusFilter(" \t "); status != "" || warning != "" {
		t.Fatalf("blank status filter = %q/%q, want unfiltered", status, warning)
	}

	views := adminQueueJobViews([]adminQueueJob{{ID: 7, Status: "future-status"}})
	if len(views) != 1 || views[0].Status != "future-status" || views[0].StatusClass != "pm-badge-status-error" || views[0].CanPause || views[0].CanResume || views[0].CanRetry {
		t.Fatalf("unknown-status view = %+v, want preserved safe fallback", views)
	}
	state := buildAdminQueueEmptyState("", adminQueuePageSize)
	if state.PrimaryURL != "/admin/queue" || state.SecondaryURL != "" || state.SecondaryLabel != "" {
		t.Fatalf("unfiltered empty-page recovery = %+v, want one all-queue recovery action", state)
	}
}

func TestF068AdminRootMethodsUseExactRedirectAndAllowContracts(t *testing.T) {
	mux, _, cancel := f068RegisteredMux(t, newAdminStoreStub(), adminFlowConfig(), nil)
	defer cancel()

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		req := httptest.NewRequest(method, "/admin", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/" {
			t.Fatalf("%s /admin = %d %q, want 303 /admin/", method, rec.Code, rec.Header().Get("Location"))
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/admin", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /admin status = %d, want 405", rec.Code)
	}
	allow := strings.Split(rec.Header().Get("Allow"), ", ")
	if len(allow) != 2 || allow[0] != http.MethodGet || allow[1] != http.MethodHead {
		t.Fatalf("POST /admin Allow tokens = %#v, want [GET HEAD]", allow)
	}
}

func TestF068AdminLayoutLinksHandleNilAndConfiguredValues(t *testing.T) {
	t.Parallel()

	if got := adminLayoutLinks(nil); got.PrivacyURL != "" || got.LegalURL != "" || got.TermsURL != "" {
		t.Fatalf("adminLayoutLinks(nil) = %+v, want zero links", got)
	}
	cfg := &config.Config{Web: config.WebConfig{
		PrivacyURL: "/privacy",
		LegalURL:   "https://legal.example.invalid",
		TermsURL:   "/terms",
	}}
	got := adminLayoutLinks(cfg)
	if got.PrivacyURL != cfg.Web.PrivacyURL || got.LegalURL != cfg.Web.LegalURL || got.TermsURL != cfg.Web.TermsURL {
		t.Fatalf("adminLayoutLinks(configured) = %+v, want %+v", got, cfg.Web)
	}
}

type f068RouteCase struct {
	name         string
	path         string
	auditAction  string
	targetAction string
	wantLocation string
	setup        func(*testing.T, *adminFlowStoreStub) url.Values
	assertState  func(*testing.T, *adminFlowStoreStub, *auth.SessionManager, *http.Request, *httptest.ResponseRecorder)
	login        bool
}

type f068CallbackCounts struct {
	mu    sync.Mutex
	apply int
	reset int
	sync  int
}

func (c *f068CallbackCounts) values() (int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.apply, c.reset, c.sync
}

func TestF068RegisterRoutesDispatchesEveryPOSTMutation(t *testing.T) {
	passwordHash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cases := []f068RouteCase{
		{
			name: "login", path: "/admin/login", auditAction: "login_success", wantLocation: "/admin/", login: true,
			setup: func(*testing.T, *adminFlowStoreStub) url.Values {
				return url.Values{"username": {"admin"}, "password": {"current-password"}}
			},
			assertState: func(t *testing.T, _ *adminFlowStoreStub, sm *auth.SessionManager, _ *http.Request, rec *httptest.ResponseRecorder) {
				cookie := f068AdminSessionCookie(rec)
				if cookie == nil {
					t.Fatal("login did not issue an admin session cookie")
				}
				lookup := httptest.NewRequest(http.MethodGet, "/admin/", nil)
				lookup.AddCookie(cookie)
				if sess := sm.Get(lookup); sess == nil || !sess.Admin {
					t.Fatalf("login session = %+v, want authenticated admin", sess)
				}
			},
		},
		{
			name: "logout", path: "/admin/logout", auditAction: "logout", targetAction: "logout", wantLocation: "/admin/login",
			setup: func(*testing.T, *adminFlowStoreStub) url.Values { return url.Values{} },
			assertState: func(t *testing.T, _ *adminFlowStoreStub, sm *auth.SessionManager, req *http.Request, _ *httptest.ResponseRecorder) {
				if sess := sm.Get(req); sess != nil {
					t.Fatalf("logout retained session %+v", sess)
				}
			},
		},
		{
			name: "feed save", path: "/admin/feeds/save", auditAction: "feed_config_save", targetAction: "feed_config_save", wantLocation: "/admin/feeds?msg=" + url.QueryEscape(web.Message("admin.feeds.flash.saved_applied")),
			setup: func(*testing.T, *adminFlowStoreStub) url.Values {
				return url.Values{"feed_name": {"osv"}, "enabled": {"on"}, "mode": {"self"}, "sync_interval": {"45m"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				cfg, err := store.GetFeedConfig(context.Background(), "osv")
				if err != nil || cfg == nil || !cfg.Enabled || cfg.Mode != "self" || cfg.SyncInterval == nil || *cfg.SyncInterval != 45*time.Minute {
					t.Fatalf("saved feed config = %+v, err %v", cfg, err)
				}
			},
		},
		{
			name: "feed reset", path: "/admin/feeds/reset", auditAction: "feed_config_reset", targetAction: "feed_config_reset", wantLocation: "/admin/feeds?msg=" + url.QueryEscape(web.Message("admin.feeds.flash.reset_applied")),
			setup: func(t *testing.T, store *adminFlowStoreStub) url.Values {
				interval := 30 * time.Minute
				if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{FeedName: "osv", Enabled: true, Mode: "self", SyncInterval: &interval}); err != nil {
					t.Fatalf("seed feed config: %v", err)
				}
				return url.Values{"feed_name": {"osv"}, "confirm_reset": {"on"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				cfg, err := store.GetFeedConfig(context.Background(), "osv")
				if err != nil || cfg != nil {
					t.Fatalf("feed config after reset = %+v, err %v; want nil", cfg, err)
				}
			},
		},
		{
			name: "feed sync", path: "/admin/feeds/sync", auditAction: "feed_sync_trigger", targetAction: "feed_sync_trigger", wantLocation: "/admin/feeds?msg=" + url.QueryEscape(web.Message("admin.feeds.sync.flash.started", "OSV")),
			setup: func(*testing.T, *adminFlowStoreStub) url.Values { return url.Values{"feed_name": {"osv"}} },
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				status, err := store.GetFeedSyncStatus(context.Background(), "osv")
				if err != nil || status == nil || status.LastSyncStatus != "running" {
					t.Fatalf("manual sync status = %+v, err %v; want running", status, err)
				}
			},
		},
		f068QueueRouteCase("queue purge", "/admin/queue/purge", "queue_purge", db.RefreshStatusDone, "", ""),
		f068QueueRouteCase("queue priority", "/admin/queue/priority", "queue_priority_update", db.RefreshStatusPending, "0", db.RefreshStatusPending),
		f068QueueRouteCase("queue pause", "/admin/queue/pause", "queue_pause", db.RefreshStatusPending, "", db.RefreshStatusPaused),
		f068QueueRouteCase("queue resume", "/admin/queue/resume", "queue_resume", db.RefreshStatusPaused, "", db.RefreshStatusPending),
		f068QueueRouteCase("queue retry", "/admin/queue/retry", "queue_retry", db.RefreshStatusError, "", db.RefreshStatusPending),
		f068QueueRouteCase("queue clear", "/admin/queue/clear", "queue_clear", db.RefreshStatusPending, "", ""),
		{
			name: "key create", path: "/admin/keys/create", auditAction: "api_key_create", targetAction: "api_key_create", wantLocation: "/admin/keys?msg=" + url.QueryEscape(web.Message("admin.keys.flash.created")),
			setup: func(*testing.T, *adminFlowStoreStub) url.Values {
				return url.Values{"name": {"route-created"}, "expires_in_days": {"1"}, "current_password": {"current-password"}, apiKeyCreateNonceField: {"route-nonce"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil || len(keys) != 1 || keys[0].Name != "route-created" {
					t.Fatalf("keys after create = %+v, err %v", keys, err)
				}
			},
		},
		{
			name: "key revoke", path: "/admin/keys/revoke", auditAction: "api_key_revoke", targetAction: "api_key_revoke", wantLocation: "/admin/keys?msg=" + url.QueryEscape(web.Message("admin.keys.flash.revoked")),
			setup: func(_ *testing.T, store *adminFlowStoreStub) url.Values {
				store.apiKeys = []db.APIKey{{ID: 41, Name: "route-revoke", KeyHash: "hash", CreatedAt: time.Now().UTC()}}
				return url.Values{"key_id": {"41"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil || len(keys) != 1 || keys[0].RevokedAt == nil {
					t.Fatalf("keys after revoke = %+v, err %v", keys, err)
				}
			},
		},
		{
			name: "key delete", path: "/admin/keys/delete", auditAction: "api_key_delete", targetAction: "api_key_delete", wantLocation: "/admin/keys?msg=" + url.QueryEscape(web.Message("admin.keys.flash.deleted")),
			setup: func(_ *testing.T, store *adminFlowStoreStub) url.Values {
				now := time.Now().UTC()
				store.apiKeys = []db.APIKey{{ID: 42, Name: "route-delete", KeyHash: "hash", CreatedAt: now, RevokedAt: &now}}
				return url.Values{"key_id": {"42"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil || len(keys) != 0 {
					t.Fatalf("keys after delete = %+v, err %v", keys, err)
				}
			},
		},
		{
			name: "advisory create", path: "/admin/advisories/create", auditAction: "advisory_create", targetAction: "advisory_create", wantLocation: "/admin/advisories?msg=" + url.QueryEscape(web.Message("admin.advisories.flash.created")),
			setup: func(*testing.T, *adminFlowStoreStub) url.Values {
				return url.Values{"id": {"manual:f068-route"}, "finding_type": {"vulnerability"}, "ecosystem": {"npm"}, "name": {"route-package"}, "severity": {"HIGH"}, "summary": {"route advisory"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				rows, err := store.ListManualAdvisories(context.Background(), 10)
				if err != nil || len(rows) != 1 || rows[0].ID != "manual:f068-route" {
					t.Fatalf("advisories after create = %+v, err %v", rows, err)
				}
			},
		},
		{
			name: "advisory delete", path: "/admin/advisories/delete", auditAction: "advisory_delete", targetAction: "advisory_delete", wantLocation: "/admin/advisories?msg=" + url.QueryEscape(web.Message("admin.advisories.flash.deleted")),
			setup: func(_ *testing.T, store *adminFlowStoreStub) url.Values {
				store.manual["manual:f068-delete"] = db.ManualAdvisory{ID: "manual:f068-delete", FindingType: "vulnerability", Ecosystem: "npm", Name: "delete-package", Severity: "LOW", Summary: "delete me"}
				return url.Values{"id": {"manual:f068-delete"}, "confirm_id": {"manual:f068-delete"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				rows, err := store.ListManualAdvisories(context.Background(), 10)
				if err != nil || len(rows) != 0 {
					t.Fatalf("advisories after delete = %+v, err %v", rows, err)
				}
			},
		},
		{
			name: "system settings", path: "/admin/settings/system", auditAction: "system_settings_save", targetAction: "system_settings_save", wantLocation: "/admin/settings?msg=" + url.QueryEscape(web.Message("admin.settings.flash.saved")),
			setup: func(*testing.T, *adminFlowStoreStub) url.Values {
				return url.Values{"block_threshold": {"HIGH"}, "rate_limit_per_minute": {"121"}, "rate_limit_burst": {"31"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				settings, err := store.GetSystemSettings(context.Background())
				if err != nil || settings == nil || settings.BlockThreshold != "HIGH" || settings.RateLimitPerMinute != 121 || settings.RateLimitBurst != 31 {
					t.Fatalf("system settings = %+v, err %v", settings, err)
				}
			},
		},
		{
			name: "password change", path: "/admin/settings/password", auditAction: "password_change", targetAction: "password_change", wantLocation: "/admin/settings?msg=" + url.QueryEscape(web.Message("admin.settings.flash.password_changed")),
			setup: func(*testing.T, *adminFlowStoreStub) url.Values {
				return url.Values{"current_password": {"current-password"}, "new_password": {"new-route-password-123"}, "confirm_password": {"new-route-password-123"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, sm *auth.SessionManager, req *http.Request, rec *httptest.ResponseRecorder) {
				current, err := store.GetAdminAuth(context.Background())
				if err != nil || current == nil || !auth.CheckPassword(current.PasswordHash, "new-route-password-123") {
					t.Fatalf("admin auth after password change = %+v, err %v", current, err)
				}
				if sess := sm.Get(req); sess != nil {
					t.Fatalf("password change retained old session %+v", sess)
				}
				if f068AdminSessionCookie(rec) == nil {
					t.Fatal("password change did not issue replacement admin session")
				}
			},
		},
	}

	if len(cases) != 18 {
		t.Fatalf("POST route matrix has %d cases, want 18", len(cases))
	}

	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.login {
				f068AssertLoginCSRFContracts(t, passwordHash)
			} else if tc.path == "/admin/logout" {
				f068AssertLogoutCSRFContracts(t, passwordHash)
			} else {
				f068AssertProtectedRouteGates(t, passwordHash, tc, index)
			}

			store, mux, sm, callbacks, cancel := f068RouteFixture(t, passwordHash)
			defer cancel()
			values := tc.setup(t, store)
			var req *http.Request
			if tc.login {
				req = f068LoginRequest(t, sm, tc.path, values)
			} else {
				var sess *auth.Session
				req, sess = authenticatedAdminFormRequest(t, sm, tc.path, values)
				if tc.path == "/admin/keys/create" {
					sm.SetFlash(sess.ID, apiKeyCreateNonceFlashKey, values.Get(apiKeyCreateNonceField))
				}
			}
			correlationID := fmt.Sprintf("f068-route-%02d-success", index+1)
			req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), correlationID))
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != tc.wantLocation {
				t.Fatalf("POST %s = %d %q, want 303 %q; body=%s", tc.path, rec.Code, rec.Header().Get("Location"), tc.wantLocation, rec.Body.String())
			}
			f068WaitForCallback(t, tc.auditAction, callbacks)
			f068AssertCallbackCounts(t, callbacks, tc.auditAction)
			f068AssertSingleAudit(t, store, tc.auditAction, correlationID)
			tc.assertState(t, store, sm, req, rec)
		})
	}
}

func f068RouteFixture(t *testing.T, passwordHash string) (*adminFlowStoreStub, *http.ServeMux, *auth.SessionManager, *f068CallbackCounts, context.CancelFunc) {
	t.Helper()
	store := newAdminStoreStub()
	store.adminAuth = &db.AdminAuth{PasswordHash: passwordHash, PasswordIsBootstrap: false, CreatedAt: time.Now().UTC()}
	callbacks := &f068CallbackCounts{}
	mux, sm, cancel := f068RegisteredMux(t, store, adminFlowConfig(), callbacks)
	return store, mux, sm, callbacks, cancel
}

func f068AssertLoginCSRFContracts(t *testing.T, passwordHash string) {
	t.Helper()
	for _, tc := range []struct {
		name      string
		preAuth   bool
		csrfValue string
	}{
		{name: "missing preauth session"},
		{name: "bad preauth csrf", preAuth: true, csrfValue: "invalid-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, mux, sm, callbacks, cancel := f068RouteFixture(t, passwordHash)
			defer cancel()
			values := url.Values{"username": {"admin"}, "password": {"current-password"}}
			var req *http.Request
			if tc.preAuth {
				req = f068LoginRequest(t, sm, "/admin/login", values)
				values.Set(auth.CSRFFieldName, tc.csrfValue)
				f068ReplaceForm(req, values)
			} else {
				req = f068RawFormRequest("/admin/login", values)
			}
			req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), "f068-login-"+strings.ReplaceAll(tc.name, " ", "-")))
			before := f068BusinessSnapshot(t, store)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Invalid request. Please try again.") {
				t.Fatalf("login %s = %d body %q, want 200 invalid-request form", tc.name, rec.Code, rec.Body.String())
			}
			f068AssertNoAudit(t, store)
			f068AssertBusinessUnchanged(t, store, before)
			f068AssertCallbackCounts(t, callbacks, "")
		})
	}
}

func f068AssertLogoutCSRFContracts(t *testing.T, passwordHash string) {
	t.Helper()
	for _, tc := range []struct {
		name          string
		authenticated bool
	}{
		{name: "missing session"},
		{name: "bad csrf", authenticated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, mux, sm, callbacks, cancel := f068RouteFixture(t, passwordHash)
			defer cancel()
			values := url.Values{}
			var req *http.Request
			var sess *auth.Session
			if tc.authenticated {
				req, sess = authenticatedAdminFormRequest(t, sm, "/admin/logout", values)
				values.Set(auth.CSRFFieldName, "invalid-token")
				f068ReplaceForm(req, values)
			} else {
				req = f068RawFormRequest("/admin/logout", values)
			}
			correlationID := "f068-logout-" + strings.ReplaceAll(tc.name, " ", "-")
			req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), correlationID))
			before := f068BusinessSnapshot(t, store)
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
				t.Fatalf("logout %s = %d %q, want 303 /admin/login", tc.name, rec.Code, rec.Header().Get("Location"))
			}
			f068AssertRejectedAudit(t, store, correlationID, "logout", "/admin/logout")
			f068AssertBusinessUnchanged(t, store, before)
			f068AssertCallbackCounts(t, callbacks, "")
			if sess != nil {
				if got := sm.Get(req); got == nil || got.ID != sess.ID || !got.Admin {
					t.Fatalf("bad-CSRF logout changed authenticated session: got %+v, want %s", got, sess.ID)
				}
			}
		})
	}
}

func f068AssertProtectedRouteGates(t *testing.T, passwordHash string, tc f068RouteCase, index int) {
	t.Helper()
	for _, gate := range []string{"unauthenticated", "bad csrf"} {
		t.Run(gate, func(t *testing.T) {
			store, mux, sm, callbacks, cancel := f068RouteFixture(t, passwordHash)
			defer cancel()
			values := tc.setup(t, store)
			before := f068BusinessSnapshot(t, store)
			var req *http.Request
			var sess *auth.Session
			if gate == "unauthenticated" {
				req = f068RawFormRequest(tc.path, values)
			} else {
				req, sess = authenticatedAdminFormRequest(t, sm, tc.path, values)
				values.Set(auth.CSRFFieldName, "invalid-token")
				f068ReplaceForm(req, values)
			}
			correlationID := fmt.Sprintf("f068-route-%02d-%s", index+1, strings.ReplaceAll(gate, " ", "-"))
			req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), correlationID))
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if gate == "unauthenticated" {
				if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
					t.Fatalf("unauthenticated POST %s = %d %q, want 303 /admin/login", tc.path, rec.Code, rec.Header().Get("Location"))
				}
				f068AssertNoAudit(t, store)
			} else {
				wantLocation := f068CSRFErrorLocation(tc.path)
				if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != wantLocation {
					t.Fatalf("bad-CSRF POST %s = %d %q, want 303 %q", tc.path, rec.Code, rec.Header().Get("Location"), wantLocation)
				}
				f068AssertRejectedAudit(t, store, correlationID, tc.targetAction, tc.path)
				if got := sm.Get(req); got == nil || got.ID != sess.ID || !got.Admin {
					t.Fatalf("bad-CSRF POST %s changed authenticated session: got %+v, want %s", tc.path, got, sess.ID)
				}
			}
			f068AssertBusinessUnchanged(t, store, before)
			f068AssertCallbackCounts(t, callbacks, "")
		})
	}
}

func f068RawFormRequest(target string, values url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func f068ReplaceForm(req *http.Request, values url.Values) {
	encoded := values.Encode()
	req.Body = io.NopCloser(strings.NewReader(encoded))
	req.ContentLength = int64(len(encoded))
	req.PostForm = nil
	req.Form = nil
}

func f068CSRFErrorLocation(path string) string {
	base := "/admin/"
	for _, section := range []string{"feeds", "queue", "keys", "advisories", "settings"} {
		if strings.HasPrefix(path, "/admin/"+section+"/") {
			base = "/admin/" + section
			break
		}
	}
	return base + "?err=" + url.QueryEscape(adminInvalidRequestMessage)
}

func f068BusinessSnapshot(t *testing.T, store *adminFlowStoreStub) string {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	state := struct {
		AdminAuth      *db.AdminAuth
		APIKeys        []db.APIKey
		NextAPIKeyID   int
		FeedStatuses   map[string]db.FeedSyncStatus
		FeedConfigs    map[string]db.FeedConfig
		SystemSettings *db.SystemSettings
		Manual         map[string]db.ManualAdvisory
		QueueJobs      []db.RefreshJob
		NextJobID      int
	}{
		store.adminAuth,
		store.apiKeys,
		store.nextAPIKeyID,
		store.feedStatuses,
		store.feedConfigs,
		store.systemSettings,
		store.manual,
		store.queueJobs,
		store.nextJobID,
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal business snapshot: %v", err)
	}
	return string(raw)
}

func f068AssertBusinessUnchanged(t *testing.T, store *adminFlowStoreStub, before string) {
	t.Helper()
	if after := f068BusinessSnapshot(t, store); after != before {
		t.Fatalf("business state changed across rejected request\nbefore: %s\nafter:  %s", before, after)
	}
}

func f068AssertNoAudit(t *testing.T, store *adminFlowStoreStub) {
	t.Helper()
	audit, err := store.ListAdminAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("unexpected audit rows: %+v", audit)
	}
}

func f068AssertRejectedAudit(t *testing.T, store *adminFlowStoreStub, correlationID, targetAction, path string) {
	t.Helper()
	f068AssertSingleAudit(t, store, "admin_csrf_rejected", correlationID)
	audit, err := store.ListAdminAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	details := map[string]string{}
	if err := json.Unmarshal(audit[0].Details, &details); err != nil {
		t.Fatalf("decode rejected-CSRF audit details: %v", err)
	}
	if details["target_action"] != targetAction || details["path"] != path || len(details) != 2 {
		t.Fatalf("rejected-CSRF details = %#v, want target_action %q and path %q only", details, targetAction, path)
	}
}

func f068WaitForCallback(t *testing.T, action string, callbacks *f068CallbackCounts) {
	t.Helper()
	if action != "feed_sync_trigger" {
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _, syncCalls := callbacks.values()
		if syncCalls == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("manual feed sync callback did not run exactly once")
}

func f068AssertCallbackCounts(t *testing.T, callbacks *f068CallbackCounts, action string) {
	t.Helper()
	wantApply, wantReset, wantSync := 0, 0, 0
	switch action {
	case "feed_config_save":
		wantApply = 1
	case "feed_config_reset":
		wantReset = 1
	case "feed_sync_trigger":
		wantSync = 1
	}
	applyCalls, resetCalls, syncCalls := callbacks.values()
	if applyCalls != wantApply || resetCalls != wantReset || syncCalls != wantSync {
		t.Fatalf("callback counts after %s = apply %d/reset %d/sync %d, want %d/%d/%d", action, applyCalls, resetCalls, syncCalls, wantApply, wantReset, wantSync)
	}
}

func f068QueueRouteCase(name, path, action, startStatus, priority, wantStatus string) f068RouteCase {
	wantMessage := ""
	switch action {
	case "queue_purge":
		wantMessage = web.Message("admin.queue.flash.purged", 1, web.Message("admin.queue.count.purge.singular"))
	case "queue_priority_update":
		wantMessage = web.Message("admin.queue.flash.priority_updated")
	case "queue_pause":
		wantMessage = web.Message("admin.queue.flash.job_paused")
	case "queue_resume":
		wantMessage = web.Message("admin.queue.flash.job_resumed")
	case "queue_retry":
		wantMessage = web.Message("admin.queue.flash.job_retry")
	case "queue_clear":
		wantMessage = web.Message("admin.queue.flash.cleared", 1, web.Message("admin.queue.count.queue_job.singular"))
	}
	return f068RouteCase{
		name: name, path: path, auditAction: action, targetAction: action, wantLocation: "/admin/queue?msg=" + url.QueryEscape(wantMessage),
		setup: func(_ *testing.T, store *adminFlowStoreStub) url.Values {
			jobID := store.addQueueJob(startStatus)
			values := url.Values{"job_id": {strconv.Itoa(jobID)}}
			if priority != "" {
				values.Set("priority", priority)
			}
			if action == "queue_clear" {
				values = url.Values{"status": {startStatus}}
			}
			return values
		},
		assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
			jobs, err := store.ListQueueJobs(context.Background(), "", 10)
			if err != nil {
				t.Fatalf("ListQueueJobs after %s: %v", action, err)
			}
			if wantStatus == "" {
				if len(jobs) != 0 {
					t.Fatalf("jobs after %s = %+v, want empty", action, jobs)
				}
				return
			}
			if len(jobs) != 1 || jobs[0].Status != wantStatus {
				t.Fatalf("jobs after %s = %+v, want one %s job", action, jobs, wantStatus)
			}
			if priority != "" {
				want, _ := strconv.Atoi(priority)
				if jobs[0].Priority != want {
					t.Fatalf("priority after %s = %d, want %d", action, jobs[0].Priority, want)
				}
			}
		},
	}
}

func f068RegisteredMux(t *testing.T, store *adminFlowStoreStub, cfg *config.Config, callbacks *f068CallbackCounts) (*http.ServeMux, *auth.SessionManager, context.CancelFunc) {
	t.Helper()
	if callbacks == nil {
		callbacks = &f068CallbackCounts{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	runtime := config.NewRuntimeSettingsFromConfig(cfg)
	mux := http.NewServeMux()
	RegisterRoutes(
		ctx,
		mux,
		store,
		sm,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg,
		runtime,
		func(context.Context, string) error {
			callbacks.mu.Lock()
			callbacks.sync++
			callbacks.mu.Unlock()
			return nil
		},
		func(context.Context, config.FeedSettings) error {
			callbacks.mu.Lock()
			callbacks.apply++
			callbacks.mu.Unlock()
			return nil
		},
		func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
			callbacks.mu.Lock()
			callbacks.reset++
			callbacks.mu.Unlock()
			feed, ok := cfg.FeedSettings(feedName)
			return feed, ok, nil
		},
	)
	return mux, sm, cancel
}

func f068LoginRequest(t *testing.T, sm *auth.SessionManager, target string, values url.Values) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	sess, err := sm.CreatePreAuth(rec)
	if err != nil {
		t.Fatalf("CreatePreAuth: %v", err)
	}
	token, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}
	values.Set(auth.CSRFFieldName, token)
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func f068AdminSessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.SessionCookieName && cookie.Value != "" {
			copyCookie := *cookie
			return &copyCookie
		}
	}
	return nil
}

func f068AssertSingleAudit(t *testing.T, store *adminFlowStoreStub, action, correlationID string) {
	t.Helper()
	audit, err := store.ListAdminAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if len(audit) != 1 || audit[0].Action != action || audit[0].CorrelationID != correlationID {
		t.Fatalf("audit after %s = %+v, want exactly one action with correlation %q", action, audit, correlationID)
	}
}
