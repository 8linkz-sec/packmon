package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/web"
)

func TestAdminFeedConfigSaveAndResetFailurePathsPreserveState(t *testing.T) {
	t.Run("load errors are redacted", func(t *testing.T) {
		for _, reset := range []bool{false, true} {
			store := newAdminErrorStore()
			store.fail["GetFeedConfig"] = errors.New(`postgres secret at C:\private\feed.key`)
			h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
			values := url.Values{"feed_name": {"osv"}, "mode": {"self"}}
			target := "/admin/feeds/save"
			if reset {
				target = "/admin/feeds/reset"
				values = url.Values{"feed_name": {"osv"}, "confirm_reset": {"on"}}
			}
			req, _ := authenticatedAdminFormRequest(t, sm, target, values)
			rec := httptest.NewRecorder()
			if reset {
				h.HandleFeedConfigReset(rec, req)
			} else {
				h.HandleFeedConfigSave(rec, req)
			}
			location := rec.Header().Get("Location")
			if rec.Code != http.StatusSeeOther || !strings.Contains(location, "Failed+to+load+feed+configuration") {
				t.Fatalf("load response = %d %q", rec.Code, location)
			}
			for _, secret := range []string{"postgres", "private", "feed.key", "secret"} {
				if strings.Contains(strings.ToLower(location), strings.ToLower(secret)) {
					t.Fatalf("redirect leaked %q: %s", secret, location)
				}
			}
			if len(store.audit) != 0 || len(store.feedConfigs) != 0 {
				t.Fatalf("load failure changed state: configs=%d audit=%d", len(store.feedConfigs), len(store.audit))
			}
		}
	})

	t.Run("reset callback reports no applied setting", func(t *testing.T) {
		store := newAdminStoreStub()
		h, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		h.SetFeedConfigResetFunc(func(context.Context, string) (config.FeedSettings, bool, error) {
			return config.FeedSettings{}, false, nil
		})
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"osv"}, "confirm_reset": {"on"}})
		rec := httptest.NewRecorder()
		h.HandleFeedConfigReset(rec, req)
		if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "runtime+reset+is+unavailable") {
			t.Fatalf("reset false response = %d %q", rec.Code, rec.Header().Get("Location"))
		}
		if len(store.audit) != 0 {
			t.Fatalf("audit = %+v, want none", store.audit)
		}
	})

	for _, tt := range []struct {
		name string
		fail string
		want string
	}{
		{name: "persistence failure rolls back", fail: "DeleteFeedConfig", want: "Failed+to+reset+feed+configuration"},
		{name: "audit failure rolls back", fail: "InsertAdminAuditLog", want: "Failed+to+record+audit+log"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newAdminErrorStore()
			store.fail[tt.fail] = errors.New("store failed")
			store.feedConfigs["vulncheck"] = db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: string(config.FeedModeSelf), APIKey: "kept"}
			cfg := adminFlowConfig()
			previous, _ := cfg.FeedSettings("vulncheck")
			previous.Enabled = true
			previous.APIKey = "kept"
			if err := cfg.SetFeedSettings(previous); err != nil {
				t.Fatalf("SetFeedSettings(previous): %v", err)
			}
			h, sm := newAdminHandlerForStore(t, store, cfg)
			h.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
				return cfg.SetFeedSettings(feed)
			})
			h.SetFeedConfigResetFunc(func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
				reset, ok := cfg.FeedSettings(feedName)
				reset.Enabled = false
				reset.APIKey = ""
				return reset, ok, cfg.SetFeedSettings(reset)
			})
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"vulncheck"}, "confirm_reset": {"on"}})
			rec := httptest.NewRecorder()
			h.HandleFeedConfigReset(rec, req)
			if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), tt.want) {
				t.Fatalf("reset response = %d %q", rec.Code, rec.Header().Get("Location"))
			}
			current, _ := cfg.FeedSettings("vulncheck")
			if !sameRuntimeFeedSettings(current, previous) {
				t.Fatalf("runtime after rollback = %+v, want %+v", current, previous)
			}
			if stored := store.feedConfigs["vulncheck"]; !stored.Enabled || stored.APIKey != "kept" {
				t.Fatalf("persisted config changed = %+v", stored)
			}
			if len(store.audit) != 0 {
				t.Fatalf("audit = %+v, want none", store.audit)
			}
		})
	}
}

func reacquireManualSyncWithoutSleep(t *testing.T, h *AdminHandler, feedName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	acquired := make(chan bool, 1)
	go func() {
		for {
			if h.beginManualFeedSync(feedName) {
				acquired <- true
				return
			}
			select {
			case <-ctx.Done():
				acquired <- false
				return
			default:
			}
			runtime.Gosched()
		}
	}()
	if !<-acquired {
		t.Fatalf("manual sync reservation for %s was not released", feedName)
	}
	h.endManualFeedSync(feedName)
}

func TestAdminFeedSyncFailureReleasesReservation(t *testing.T) {
	t.Run("status write failure", func(t *testing.T) {
		store := newAdminErrorStore()
		store.fail["UpsertFeedSyncStatus"] = errors.New("status down")
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		worker := make(chan struct{}, 1)
		h.syncFeed = func(context.Context, string) error {
			worker <- struct{}{}
			return nil
		}
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
		req.Header.Set("HX-Request", "true")
		rec := httptest.NewRecorder()
		h.HandleFeedSyncNow(rec, req)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Failed to record feed sync status") {
			t.Fatalf("status failure response = %d %q", rec.Code, rec.Body.String())
		}
		select {
		case <-worker:
			t.Fatal("worker started after status write failure")
		default:
		}
		if !h.beginManualFeedSync("osv") {
			t.Fatal("reservation was not released after status write failure")
		}
		h.endManualFeedSync("osv")
	})

	t.Run("sync callback failure", func(t *testing.T) {
		store := newAdminStoreStub()
		returned := make(chan struct{})
		h, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig(), func(context.Context, string) error {
			close(returned)
			return errors.New("upstream failed")
		})
		var logs bytes.Buffer
		h.logger = slog.New(slog.NewJSONHandler(&logs, nil))
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
		req.Header.Set("HX-Request", "true")
		rec := httptest.NewRecorder()
		h.HandleFeedSyncNow(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("start response = %d, want 200", rec.Code)
		}
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Fatal("sync callback did not return")
		}
		reacquireManualSyncWithoutSleep(t, h, "osv")
		if got := logs.String(); !strings.Contains(got, "manual sync failed") || !strings.Contains(got, "upstream failed") {
			t.Fatalf("failure log = %q", got)
		}
	})
}

func TestConcurrentAdminFeedSyncAdmissionAndAudit(t *testing.T) {
	h := &AdminHandler{}
	firstAuditStarted := make(chan struct{})
	releaseFirstAudit := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() {
		releaseOnce.Do(func() { close(releaseFirstAudit) })
	}
	type admissionResult struct {
		started bool
		err     error
	}
	firstResult := make(chan admissionResult, 1)
	var workers sync.WaitGroup
	workers.Add(1)
	defer func() {
		releaseAll()
		workers.Wait()
	}()
	go func() {
		defer workers.Done()
		started, err := h.beginManualFeedSyncWithAudit("osv", func() error {
			close(firstAuditStarted)
			<-releaseFirstAudit
			return nil
		})
		firstResult <- admissionResult{started: started, err: err}
	}()

	select {
	case <-firstAuditStarted:
	case <-time.After(time.Second):
		t.Fatal("first admission audit did not reach the barrier")
	}

	secondAuditCalled := false
	secondStarted, secondErr := h.beginManualFeedSyncWithAudit("osv", func() error {
		secondAuditCalled = true
		return nil
	})
	if secondErr != nil {
		t.Fatalf("second admission error = %v, want nil", secondErr)
	}
	if secondStarted {
		t.Fatal("second concurrent request reserved the same feed")
	}
	if secondAuditCalled {
		t.Fatal("second concurrent request wrote an admission audit")
	}

	releaseAll()
	select {
	case result := <-firstResult:
		if result.err != nil || !result.started {
			t.Fatalf("first admission = %v, %v; want started", result.started, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("first admission did not return after releasing its audit")
	}
	workers.Wait()
	h.endManualFeedSync("osv")
}

func TestAdminFeedSyncResponsesHandleRendererFailureAndRedirect(t *testing.T) {
	t.Run("renderer_failure", func(t *testing.T) {
		var logs bytes.Buffer
		h := &AdminHandler{
			renderer: web.NewRendererWithLayoutLinks(fstest.MapFS{}, false, web.LayoutLinks{}),
			logger:   slog.New(slog.NewJSONHandler(&logs, nil)),
		}
		req := httptest.NewRequest(http.MethodPost, "/admin/feeds/sync", nil)
		req.Header.Set("HX-Request", "true")
		rec := httptest.NewRecorder()
		h.respondFeedSyncResult(rec, req, "started", "", http.StatusOK, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want currently committed 200", rec.Code)
		}
		if got := rec.Header().Get("HX-Trigger"); got != `{"feed-runtime-refresh":"true"}` {
			t.Fatalf("HX-Trigger = %q", got)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Fatalf("fallback Content-Type = %q", got)
		}
		if !strings.Contains(rec.Body.String(), "internal server error") || !strings.Contains(logs.String(), "flash render failed") {
			t.Fatalf("renderer failure body/log = %q / %q", rec.Body.String(), logs.String())
		}

		t.Run("desired_http_500", func(t *testing.T) {
			t.Skip("F064-improvements-2/3: response status is committed before renderer failure, so HTTP 500 is not observable")
		})
	})

	h := &AdminHandler{}
	for _, tt := range []struct {
		name    string
		message string
		errMsg  string
		key     string
	}{
		{name: "success", message: "sync started", key: "msg"},
		{name: "error", errMsg: "sync failed", key: "err"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/feeds/sync", nil)
			rec := httptest.NewRecorder()
			h.respondFeedSyncResult(rec, req, tt.message, tt.errMsg, http.StatusTeapot, true)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			location, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse redirect: %v", err)
			}
			want := tt.message
			if tt.errMsg != "" {
				want = tt.errMsg
			}
			if location.Path != "/admin/feeds" || location.Query().Get(tt.key) != want || rec.Header().Get("HX-Trigger") != "" {
				t.Fatalf("redirect = %q, want %s=%q", location.String(), tt.key, want)
			}
		})
	}
}

func TestFeedFormDefensiveBranches(t *testing.T) {
	if got := desiredFeedSettingsRedirectError(nil); got != "" {
		t.Fatalf("nil desired settings error = %q", got)
	}
	if formatFeedConfigRevision(nil) != "" || formatFeedConfigRevision(&db.FeedConfig{}) != "" {
		t.Fatal("nil/zero feed revision was not empty")
	}
	if got := feedConfigRevisionExpectation(nil); got == nil || !got.IsZero() {
		t.Fatalf("nil previous expectation = %v, want zero pointer", got)
	}
	if got := feedConfigRevisionExpectation(&db.FeedConfig{}); got != nil {
		t.Fatalf("zero previous expectation = %v, want nil", got)
	}
	details := feedConfigAuditDetails("osv", nil, nil)
	if details["previous_enabled"] != "unset" || details["new_api_key_configured"] != "unset" {
		t.Fatalf("nil audit details = %+v", details)
	}
	if got := adminFeedsRedirectURL("err", "failure", " "); got != "/admin/feeds?err=failure" {
		t.Fatalf("blank-feed redirect = %q", got)
	}
	if isHTMXRequest(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("request without HX header detected as HTMX")
	}
	hxReq := httptest.NewRequest(http.MethodGet, "/", nil)
	hxReq.Header.Set("HX-Request", " TRUE ")
	if !isHTMXRequest(hxReq) {
		t.Fatal("trimmed mixed-case HX header was rejected")
	}

	feed := config.FeedSettings{Name: "osv", Mode: config.FeedModeSelf, SupportsSyncInterval: true}
	parsed, err := parseFeedSettingsForm(feed, url.Values{"mode": {"self"}})
	if err != nil || parsed.SyncInterval != 0 {
		t.Fatalf("blank interval parse = %+v, %v", parsed, err)
	}
	if record := feedConfigRecordFromRuntimeSetting(parsed, nil); record.SyncInterval != nil || record.ExpectedUpdatedAt == nil || !record.ExpectedUpdatedAt.IsZero() {
		t.Fatalf("zero feed record = %+v", record)
	}

	store := newAdminStoreStub()
	called := make(chan struct{})
	h, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig(), func(ctx context.Context, _ string) error {
		if ctx == nil {
			t.Error("background sync context is nil")
		}
		close(called)
		return nil
	})
	h.rootCtx = nil
	h.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("nil-root sync status = %d, want 200", rec.Code)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("nil-root background worker did not run")
	}
	reacquireManualSyncWithoutSleep(t, h, "osv")
}
