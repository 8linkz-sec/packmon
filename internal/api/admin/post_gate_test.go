package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestAdminPostGateAppliesCommonChecks(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	t.Run("unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/feeds/save", strings.NewReader(url.Values{}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		if sess, ok := handler.requireAdminPost(rec, req, adminPostGate{
			csrfAction:            "feed_config_save",
			bootstrapRedirectPath: "/admin/feeds",
		}); ok || sess != nil {
			t.Fatalf("requireAdminPost() = (%+v, %v), want nil false", sess, ok)
		}
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
			t.Fatalf("unauthenticated response = %d %q, want login redirect", rec.Code, rec.Header().Get("Location"))
		}
	})

	t.Run("invalid csrf", func(t *testing.T) {
		req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/feeds/save")
		req.Body = http.NoBody
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = url.Values{"feed_name": {"osv"}}
		rec := httptest.NewRecorder()

		if sess, ok := handler.requireAdminPost(rec, req, adminPostGate{
			csrfAction:            "feed_config_save",
			bootstrapRedirectPath: "/admin/feeds",
		}); ok || sess != nil {
			t.Fatalf("requireAdminPost() = (%+v, %v), want nil false", sess, ok)
		}
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("invalid CSRF response = %d, want 303", rec.Code)
		}
		if got := rec.Header().Get("Location"); !strings.HasPrefix(got, "/admin/feeds?") || !strings.Contains(got, "err=") {
			t.Fatalf("invalid CSRF Location = %q, want feeds error redirect", got)
		}
		audit, err := store.ListAdminAuditLog(context.Background(), 10)
		if err != nil {
			t.Fatalf("ListAdminAuditLog() error = %v", err)
		}
		if !adminFlowAuditContains(audit, "admin_csrf_rejected") {
			t.Fatalf("audit = %+v, want admin_csrf_rejected", audit)
		}
	})

	t.Run("bootstrap rotation", func(t *testing.T) {
		store := newAdminStoreStub()
		store.adminAuth = &db.AdminAuth{PasswordIsBootstrap: true, CreatedAt: time.Now().UTC()}
		handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{"feed_name": {"osv"}})
		rec := httptest.NewRecorder()

		if sess, ok := handler.requireAdminPost(rec, req, adminPostGate{
			csrfAction:            "feed_config_save",
			bootstrapRedirectPath: "/admin/feeds",
		}); ok || sess != nil {
			t.Fatalf("requireAdminPost() = (%+v, %v), want nil false", sess, ok)
		}
		if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "bootstrap+password") {
			t.Fatalf("bootstrap response = %d %q, want rotation redirect", rec.Code, rec.Header().Get("Location"))
		}
		audit, err := store.ListAdminAuditLog(context.Background(), 10)
		if err != nil {
			t.Fatalf("ListAdminAuditLog() error = %v", err)
		}
		if !adminFlowAuditContains(audit, "bootstrap_rotation_required") {
			t.Fatalf("audit = %+v, want bootstrap_rotation_required", audit)
		}
	})

	t.Run("bootstrap rotation can be skipped", func(t *testing.T) {
		store := newAdminStoreStub()
		store.adminAuth = &db.AdminAuth{PasswordIsBootstrap: true, CreatedAt: time.Now().UTC()}
		handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		req, wantSess := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{})
		rec := httptest.NewRecorder()

		gotSess, ok := handler.requireAdminPost(rec, req, adminPostGate{csrfAction: "password_change"})
		if !ok || gotSess == nil || gotSess.ID != wantSess.ID {
			t.Fatalf("requireAdminPost() = (%+v, %v), want authenticated session", gotSess, ok)
		}
		if rec.Code != 200 {
			t.Fatalf("response code = %d, want untouched recorder", rec.Code)
		}
	})
}
