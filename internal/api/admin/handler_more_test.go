package admin

import (
	"context"
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

	handler.SetFeedConfigResetFunc(func(context.Context, string) error {
		return context.Canceled
	})
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"osv"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "applying+it+failed") {
		t.Fatalf("reset Location = %q, want apply failure", got)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"unknown"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Unknown+feed") {
		t.Fatalf("reset unknown Location = %q", got)
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

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"socket"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Manual+sync+is+not+available") {
		t.Fatalf("Location = %q, want unavailable sync", got)
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
