package admin

import (
	"context"
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
		t.Run(tc.name, func(t *testing.T) {
			store := newAdminStoreStub()
			jobID := store.addQueueJob(tc.startState)
			h, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
			req, _ := authenticatedAdminFormRequest(t, sm, tc.target, url.Values{"job_id": {"not-an-id"}})
			rec := httptest.NewRecorder()

			tc.call(h, rec, req)

			if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "Invalid+queue+job+ID") {
				t.Fatalf("invalid %s response = %d %q, want invalid-ID redirect", tc.name, rec.Code, rec.Header().Get("Location"))
			}
			jobs, err := store.ListQueueJobs(context.Background(), "", 10)
			if err != nil {
				t.Fatalf("ListQueueJobs: %v", err)
			}
			if len(jobs) != 1 || jobs[0].ID != jobID || jobs[0].Status != tc.startState {
				t.Fatalf("jobs after invalid %s = %+v, want unchanged %s job %d", tc.name, jobs, tc.startState, jobID)
			}
			audit, err := store.ListAdminAuditLog(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog: %v", err)
			}
			if adminFlowAuditContains(audit, tc.action) {
				t.Fatalf("invalid %s recorded %s audit: %+v", tc.name, tc.action, audit)
			}
		})
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
	wantLocation string
	setup        func(*testing.T, *adminFlowStoreStub) url.Values
	assertState  func(*testing.T, *adminFlowStoreStub, *auth.SessionManager, *http.Request, *httptest.ResponseRecorder)
	login        bool
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
			name: "logout", path: "/admin/logout", auditAction: "logout", wantLocation: "/admin/login",
			setup: func(*testing.T, *adminFlowStoreStub) url.Values { return url.Values{} },
			assertState: func(t *testing.T, _ *adminFlowStoreStub, sm *auth.SessionManager, req *http.Request, _ *httptest.ResponseRecorder) {
				if sess := sm.Get(req); sess != nil {
					t.Fatalf("logout retained session %+v", sess)
				}
			},
		},
		{
			name: "feed save", path: "/admin/feeds/save", auditAction: "feed_config_save", wantLocation: "/admin/feeds?msg=",
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
			name: "feed reset", path: "/admin/feeds/reset", auditAction: "feed_config_reset", wantLocation: "/admin/feeds?msg=",
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
			name: "feed sync", path: "/admin/feeds/sync", auditAction: "feed_sync_trigger", wantLocation: "/admin/feeds?msg=",
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
		f068QueueRouteCase("queue clear", "/admin/queue/clear", "queue_clear", db.RefreshStatusPaused, "", ""),
		{
			name: "key create", path: "/admin/keys/create", auditAction: "api_key_create", wantLocation: "/admin/keys?msg=",
			setup: func(*testing.T, *adminFlowStoreStub) url.Values {
				return url.Values{"name": {"route-created"}, "expires_in_days": {"1"}, "current_password": {"current-password"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil || len(keys) != 1 || keys[0].Name != "route-created" {
					t.Fatalf("keys after create = %+v, err %v", keys, err)
				}
			},
		},
		{
			name: "key revoke", path: "/admin/keys/revoke", auditAction: "api_key_revoke", wantLocation: "/admin/keys?msg=",
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
			name: "key delete", path: "/admin/keys/delete", auditAction: "api_key_delete", wantLocation: "/admin/keys?msg=",
			setup: func(_ *testing.T, store *adminFlowStoreStub) url.Values {
				now := time.Now().UTC()
				store.apiKeys = []db.APIKey{{ID: 42, Name: "route-delete", KeyHash: "hash", CreatedAt: now, RevokedAt: &now}}
				return url.Values{"key_id": {"42"}}
			},
			assertState: func(t *testing.T, store *adminFlowStoreStub, _ *auth.SessionManager, _ *http.Request, _ *httptest.ResponseRecorder) {
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil || len(keys) != 1 || keys[0].DeletedAt == nil || keys[0].Name != "" {
					t.Fatalf("keys after delete = %+v, err %v", keys, err)
				}
			},
		},
		{
			name: "advisory create", path: "/admin/advisories/create", auditAction: "advisory_create", wantLocation: "/admin/advisories?msg=",
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
			name: "advisory delete", path: "/admin/advisories/delete", auditAction: "advisory_delete", wantLocation: "/admin/advisories?msg=",
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
			name: "system settings", path: "/admin/settings/system", auditAction: "system_settings_save", wantLocation: "/admin/settings?msg=",
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
			name: "password change", path: "/admin/settings/password", auditAction: "password_change", wantLocation: "/admin/settings?msg=",
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
			store := newAdminStoreStub()
			store.adminAuth = &db.AdminAuth{PasswordHash: passwordHash, PasswordIsBootstrap: false, CreatedAt: time.Now().UTC()}
			cfg := adminFlowConfig()
			syncDone := make(chan struct{})
			var syncOnce sync.Once
			mux, sm, cancel := f068RegisteredMux(t, store, cfg, func(context.Context, string) error {
				syncOnce.Do(func() { close(syncDone) })
				return nil
			})
			defer cancel()

			values := tc.setup(t, store)
			var req *http.Request
			if tc.login {
				req = f068LoginRequest(t, sm, tc.path, values)
			} else {
				req, _ = authenticatedAdminFormRequest(t, sm, tc.path, values)
			}
			correlationID := fmt.Sprintf("f068-route-%02d", index+1)
			req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), correlationID))
			rec := httptest.NewRecorder()

			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), tc.wantLocation) {
				t.Fatalf("POST %s = %d %q, want 303 prefix %q; body=%s", tc.path, rec.Code, rec.Header().Get("Location"), tc.wantLocation, rec.Body.String())
			}
			if tc.auditAction == "feed_sync_trigger" {
				select {
				case <-syncDone:
				case <-time.After(2 * time.Second):
					t.Fatal("manual feed sync callback did not run")
				}
			}
			f068AssertSingleAudit(t, store, tc.auditAction, correlationID)
			tc.assertState(t, store, sm, req, rec)
		})
	}
}

func f068QueueRouteCase(name, path, action, startStatus, priority, wantStatus string) f068RouteCase {
	return f068RouteCase{
		name: name, path: path, auditAction: action, wantLocation: "/admin/queue?msg=",
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

func f068RegisteredMux(t *testing.T, store *adminFlowStoreStub, cfg *config.Config, syncFeed FeedSyncFunc) (*http.ServeMux, *auth.SessionManager, context.CancelFunc) {
	t.Helper()
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
		syncFeed,
		func(context.Context, config.FeedSettings) error { return nil },
		func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
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
