package admin

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/web"
)

// seedFeedConfigOverride stores an override for feedName at a fixed revision
// and returns that revision as the feeds page renders it.
func seedFeedConfigOverride(store *adminFlowStoreStub, cfg db.FeedConfig, updatedAt time.Time) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	cfg.FeedName = config.NormalizeFeedName(cfg.FeedName)
	cfg.UpdatedAt = updatedAt.UTC()
	store.feedConfigs[cfg.FeedName] = cfg
	return cfg.UpdatedAt.Format(time.RFC3339Nano)
}

func storedFeedConfig(t *testing.T, store *adminFlowStoreStub, feedName string) *db.FeedConfig {
	t.Helper()
	stored, err := store.GetFeedConfig(context.Background(), feedName)
	if err != nil {
		t.Fatalf("GetFeedConfig(%s) error = %v", feedName, err)
	}
	return stored
}

func feedConfigConflictLocation(feedName string) string {
	return adminFeedsRedirectURL("err", web.Message("admin.feeds.error.save_conflict"), feedName)
}

func TestAdminFeedsFormsRenderOverrideRevision(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	interval := 2 * time.Hour
	revision := seedFeedConfigOverride(store, db.FeedConfig{FeedName: "osv", Enabled: true, Mode: "self", SyncInterval: &interval}, time.Date(2026, 3, 4, 5, 6, 7, 891011000, time.UTC))
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds")
	rec := httptest.NewRecorder()
	handler.HandleAdminFeeds(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/feeds status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	for _, action := range []string{"/admin/feeds/save", "/admin/feeds/reset"} {
		form := regexp.MustCompile(`(?s)<form action="` + regexp.QuoteMeta(action) + `".*?</form>`)
		var osvForm string
		for _, candidate := range form.FindAllString(body, -1) {
			if strings.Contains(candidate, `name="feed_name" value="osv"`) {
				osvForm = candidate
			}
		}
		if osvForm == "" {
			t.Fatalf("no osv %s form rendered", action)
		}
		want := `<input type="hidden" name="updated_at" value="` + html.EscapeString(revision) + `">`
		if !strings.Contains(osvForm, want) {
			t.Fatalf("osv %s form missing revision field %q:\n%s", action, want, osvForm)
		}
	}

	// A feed without an override renders an empty revision: "no override yet".
	saveForms := regexp.MustCompile(`(?s)<form action="/admin/feeds/save".*?</form>`).FindAllString(body, -1)
	for _, candidate := range saveForms {
		if strings.Contains(candidate, `name="feed_name" value="ghsa"`) && !strings.Contains(candidate, `<input type="hidden" name="updated_at" value="">`) {
			t.Fatalf("ghsa save form without override must render an empty revision:\n%s", candidate)
		}
	}
}

func TestHandleFeedConfigSaveRejectsStaleFormRevision(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	interval := 2 * time.Hour
	renderedRevision := seedFeedConfigOverride(store, db.FeedConfig{FeedName: "osv", Enabled: true, Mode: "self", SyncInterval: &interval}, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	applied := 0
	handler.SetFeedConfigApplyFunc(func(context.Context, config.FeedSettings) error {
		applied++
		return nil
	})

	// Another admin saves after this form was rendered.
	otherInterval := 3 * time.Hour
	seedFeedConfigOverride(store, db.FeedConfig{FeedName: "osv", Enabled: true, Mode: "self", SyncInterval: &otherInterval}, time.Date(2026, 3, 4, 6, 0, 0, 0, time.UTC))

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"osv"},
		"mode":          {"self"},
		"enabled":       {"on"},
		"sync_interval": {"4h"},
		"updated_at":    {renderedRevision},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != feedConfigConflictLocation("osv") {
		t.Fatalf("stale save = %d %q, want the save-conflict redirect", rec.Code, rec.Header().Get("Location"))
	}
	if stored := storedFeedConfig(t, store, "osv"); stored == nil || stored.SyncInterval == nil || *stored.SyncInterval != otherInterval {
		t.Fatalf("stored osv override = %+v, want the other admin's 3h save kept", stored)
	}
	if applied != 0 {
		t.Fatalf("runtime apply calls = %d, want none for a stale form", applied)
	}
}

func TestHandleFeedConfigSaveAcceptsCurrentFormRevision(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	interval := 2 * time.Hour
	// #nosec G101 -- this test fixture uses a fake feed credential.
	revision := seedFeedConfigOverride(store, db.FeedConfig{FeedName: "vulncheck", Enabled: true, Mode: "external", SyncInterval: &interval, APIKey: "kept-vulncheck-key"}, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	// A blank API key keeps the stored key.
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"vulncheck"},
		"mode":          {"external"},
		"enabled":       {"on"},
		"sync_interval": {"4h"},
		"api_key":       {""},
		"updated_at":    {revision},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "msg=") {
		t.Fatalf("current-revision save = %d %q, want success", rec.Code, rec.Header().Get("Location"))
	}
	stored := storedFeedConfig(t, store, "vulncheck")
	if stored == nil || stored.SyncInterval == nil || *stored.SyncInterval != 4*time.Hour || stored.APIKey != "kept-vulncheck-key" {
		t.Fatalf("stored vulncheck override = %+v, want 4h with the kept API key", stored)
	}
}

func TestHandleFeedConfigSaveFormRevisionWithoutOverride(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name         string
		revision     string
		wantConflict bool
	}{
		{name: "empty revision creates the first override", revision: ""},
		// The form was rendered with an override another admin reset since.
		{name: "revision of a reset override conflicts", revision: "2026-03-04T05:06:07Z", wantConflict: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newAdminStoreStub()
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
				"feed_name":  {"osv"},
				"mode":       {"self"},
				"enabled":    {"on"},
				"updated_at": {tt.revision},
			})
			rec := httptest.NewRecorder()
			handler.HandleFeedConfigSave(rec, req)

			stored := storedFeedConfig(t, store, "osv")
			if tt.wantConflict {
				if rec.Header().Get("Location") != feedConfigConflictLocation("osv") || stored != nil {
					t.Fatalf("save = %q, stored %+v; want the save-conflict redirect and no override", rec.Header().Get("Location"), stored)
				}
				return
			}
			if !strings.Contains(rec.Header().Get("Location"), "msg=") || stored == nil {
				t.Fatalf("save = %q, stored %+v; want success and a new override", rec.Header().Get("Location"), stored)
			}
		})
	}
}

func TestHandleFeedConfigResetRejectsStaleFormRevision(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	interval := 2 * time.Hour
	renderedRevision := seedFeedConfigOverride(store, db.FeedConfig{FeedName: "osv", Enabled: true, Mode: "self", SyncInterval: &interval}, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	resets := 0
	handler.SetFeedConfigResetFunc(func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
		resets++
		feed, ok := adminFlowConfig().FeedSettings(feedName)
		return feed, ok, nil
	})

	otherInterval := 3 * time.Hour
	seedFeedConfigOverride(store, db.FeedConfig{FeedName: "osv", Enabled: true, Mode: "self", SyncInterval: &otherInterval}, time.Date(2026, 3, 4, 6, 0, 0, 0, time.UTC))

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
		"feed_name":     {"osv"},
		"confirm_reset": {"on"},
		"updated_at":    {renderedRevision},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != feedConfigConflictLocation("osv") {
		t.Fatalf("stale reset = %d %q, want the save-conflict redirect", rec.Code, rec.Header().Get("Location"))
	}
	if stored := storedFeedConfig(t, store, "osv"); stored == nil || stored.SyncInterval == nil || *stored.SyncInterval != otherInterval {
		t.Fatalf("stored osv override = %+v, want the other admin's save kept", stored)
	}
	if resets != 0 {
		t.Fatalf("runtime reset calls = %d, want none for a stale form", resets)
	}
}

func TestFeedConfigFormsRejectMalformedRevision(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	interval := 2 * time.Hour
	seedFeedConfigOverride(store, db.FeedConfig{FeedName: "osv", Enabled: true, Mode: "self", SyncInterval: &interval}, time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	want := adminFeedsRedirectURL("err", web.Message("admin.feeds.error.invalid_revision"), "osv")

	for _, tt := range []struct {
		name   string
		target string
		values url.Values
		serve  func(http.ResponseWriter, *http.Request)
	}{
		{name: "save", target: "/admin/feeds/save", values: url.Values{"feed_name": {"osv"}, "mode": {"self"}, "updated_at": {"not-a-time"}}, serve: handler.HandleFeedConfigSave},
		{name: "reset", target: "/admin/feeds/reset", values: url.Values{"feed_name": {"osv"}, "confirm_reset": {"on"}, "updated_at": {"not-a-time"}}, serve: handler.HandleFeedConfigReset},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, tt.values)
			rec := httptest.NewRecorder()
			tt.serve(rec, req)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
				t.Fatalf("%s = %d %q, want %q", tt.name, rec.Code, rec.Header().Get("Location"), want)
			}
		})
	}
	if stored := storedFeedConfig(t, store, "osv"); stored == nil || stored.SyncInterval == nil || *stored.SyncInterval != interval {
		t.Fatalf("stored osv override = %+v, want it unchanged", stored)
	}
}
