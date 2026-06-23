package admin

import (
	"context"
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
)

func TestRegisterRoutesIncludesWellKnownPasswordRedirect(t *testing.T) {
	store := newAdminStoreStub()
	cfg := adminFlowConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := auth.NewSessionManager(ctx, time.Hour, false)
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

func TestAdminWriteRejectsMissingCSRF(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/feeds/save")
	req.Body = http.NoBody
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = url.Values{"feed_name": {"osv"}, "mode": {"self"}}

	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
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
		{"unknown feed", url.Values{"feed_name": {"unknown"}, "mode": {"self"}}, "unknown+feed"},
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
	if len(audit) != 1 || audit[0].Action != "feed_config_save" {
		t.Fatalf("audit after apply failure = %+v, want feed_config_save", audit)
	}

	handler.SetFeedConfigResetFunc(func(context.Context, string) error {
		return context.Canceled
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
	if len(audit) != 1 || audit[0].Action != "feed_config_reset" {
		t.Fatalf("audit after reset apply failure = %+v, want feed_config_reset", audit)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"unknown"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Unknown+feed") {
		t.Fatalf("reset unknown Location = %q", got)
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
	})

	t.Run("reset apply failure restores override", func(t *testing.T) {
		store := newAdminStoreStub()
		store.feedConfigs["vulncheck"] = db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: "self", APIKey: "old-key"}
		handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		handler.SetFeedConfigResetFunc(func(context.Context, string) error {
			return context.Canceled
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
	})
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

func TestMarkFeedSyncRunningPreservesStatusMetadataAndHandlesErrors(t *testing.T) {
	store := newAdminErrorStore()
	metadata := []byte(`{"cursor":"old"}`)
	store.feedStatuses["osv"] = db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: "success",
		EntriesSynced:  12,
		EntriesTotal:   15,
		LastCommitHash: "commit-old",
		LastEtag:       "etag-old",
		Metadata:       metadata,
	}
	handler, _ := newAdminHandlerForStore(t, store, adminFlowConfig())

	handler.markFeedSyncRunning(context.Background(), "osv")
	metadata[0] = '['

	status, err := store.GetFeedSyncStatus(context.Background(), "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "running" {
		t.Fatalf("status = %+v, want running", status)
	}
	if status.EntriesSynced != 12 || status.EntriesTotal != 15 || status.LastCommitHash != "commit-old" || status.LastEtag != "etag-old" {
		t.Fatalf("status lost previous metadata: %+v", status)
	}
	if string(status.Metadata) != `{"cursor":"old"}` {
		t.Fatalf("metadata = %s, want copied metadata", string(status.Metadata))
	}

	store.fail = map[string]error{"GetFeedSyncStatus": context.Canceled, "UpsertFeedSyncStatus": context.Canceled}
	handler.markFeedSyncRunning(context.Background(), "osv")
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
		{"severity", url.Values{"ecosystem": {"npm"}, "name": {"left-pad"}, "severity": {"INFO"}, "summary": {"sum"}}, "Invalid+severity"},
		{"ecosystem", url.Values{"ecosystem": {"unknown"}, "name": {"left-pad"}, "severity": {"HIGH"}, "summary": {"sum"}}, "Unknown+ecosystem"},
		{"length", url.Values{"ecosystem": {"npm"}, "name": {strings.Repeat("a", 257)}, "severity": {"HIGH"}, "summary": {"sum"}}, "maximum+length"},
		{"feed id", url.Values{"id": {"GHSA-feed-id"}, "ecosystem": {"npm"}, "name": {"left-pad"}, "severity": {"HIGH"}, "summary": {"sum"}}, "must+start+with+manual"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", tt.values)
			rec := httptest.NewRecorder()
			handler.HandleAdvisoryCreate(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, tt.want) {
				t.Fatalf("Location = %q, want %q", got, tt.want)
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
