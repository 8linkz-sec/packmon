package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
)

// assertFailedAttemptRecorded checks that one rejected credential check was
// counted against both the client IP and the shared admin account, even
// though the rejection audit row could not be written.
func assertFailedAttemptRecorded(t *testing.T, h *AdminHandler, ip string) {
	t.Helper()

	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	for _, key := range []string{ip, adminLoginAccountKey} {
		attempt, ok := h.loginAttempts[key]
		if !ok || attempt.count != 1 {
			t.Fatalf("login attempts for %q = %+v, want exactly one recorded failure despite the audit write error", key, attempt)
		}
	}
}

func TestProcessLoginRecordsFailedAttemptWhenRejectionAuditFails(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	for _, tt := range []struct {
		name     string
		username string
		password string
	}{
		{name: "invalid password", username: "admin", password: "wrong-password"},
		{name: "invalid username", username: "root", password: "correct-password"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &adminStoreStub{
				adminAuth: &db.AdminAuth{PasswordHash: passwordHash, CreatedAt: time.Now()},
				auditErr:  errors.New("audit down"),
			}
			h, sm := testHandler(t, store)

			sess, err := sm.CreatePreAuth(httptest.NewRecorder())
			if err != nil {
				t.Fatalf("CreatePreAuth session: %v", err)
			}
			csrfToken, err := auth.CSRFToken(sess)
			if err != nil {
				t.Fatalf("CSRFToken: %v", err)
			}
			form := url.Values{
				"username": {tt.username},
				"password": {tt.password},
				"_csrf":    {csrfToken},
			}
			req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "127.0.0.1:12345"
			req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.ID}) //nolint:gosec // test injects an in-memory session cookie.
			rec := httptest.NewRecorder()

			h.HandleLogin(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 when the rejection audit fails", rec.Code)
			}
			assertFailedAttemptRecorded(t, h, clientIP(req))
		})
	}
}

func TestKeyCreateStepUpRecordsFailedAttemptWhenRejectionAuditFails(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":             {"ci"},
		"expires_in_days":  {validAPIKeyExpiryFormValue()},
		"current_password": {"wrong-password"},
	})
	store.mu.Lock()
	store.auditInsertErr = errors.New("audit down")
	store.mu.Unlock()
	rec := httptest.NewRecorder()

	handler.HandleKeyCreate(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyCreate status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "err=") {
		t.Fatalf("HandleKeyCreate Location = %q, want an error redirect", got)
	}
	keys, err := store.ListAPIKeys(t.Context())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("keys after failed step-up = %+v, want none", keys)
	}
	assertFailedAttemptRecorded(t, handler, clientIP(req))
}

func TestPasswordChangeRecordsFailedAttemptWhenRejectionAuditFails(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {"wrong-password"},
		"new_password":     {"replacement-password"},
		"confirm_password": {"replacement-password"},
	})
	store.mu.Lock()
	store.auditInsertErr = errors.New("audit down")
	store.mu.Unlock()
	rec := httptest.NewRecorder()

	handler.HandlePasswordChange(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandlePasswordChange status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "err=") {
		t.Fatalf("HandlePasswordChange Location = %q, want an error redirect", got)
	}
	store.mu.Lock()
	gotHash := store.adminAuth.PasswordHash
	store.mu.Unlock()
	if gotHash != hash {
		t.Fatal("password hash changed after a rejected password change")
	}
	assertFailedAttemptRecorded(t, handler, clientIP(req))
}
