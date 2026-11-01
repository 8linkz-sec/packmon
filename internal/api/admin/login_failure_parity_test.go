package admin

import (
	"context"
	"encoding/json"
	"errors"
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

func postLoginForm(t *testing.T, h *AdminHandler, sm *auth.SessionManager, username, password string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()

	sess, err := sm.CreatePreAuth(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("CreatePreAuth session: %v", err)
	}
	csrfToken, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}
	form := url.Values{
		"username": {username},
		"password": {password},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.ID}) //nolint:gosec // test injects an in-memory session cookie.
	rec := httptest.NewRecorder()
	h.HandleLogin(rec, req)
	return rec, req
}

func loginFailedAuditReasons(t *testing.T, store *adminStoreStub) []string {
	t.Helper()

	var reasons []string
	for _, entry := range store.auditLogs {
		if entry.Action != "login_failed" {
			continue
		}
		var details map[string]string
		if err := json.Unmarshal(entry.Details, &details); err != nil {
			t.Fatalf("login_failed audit details %q: %v", entry.Details, err)
		}
		reasons = append(reasons, details["reason"])
	}
	return reasons
}

// TestProcessLoginRecordsFailedAttemptWhenNoAdminAccountExists counts a login
// against an unconfigured admin account like every other failed login, so the
// path cannot be probed without lockout, metrics, or an audit row.
func TestProcessLoginRecordsFailedAttemptWhenNoAdminAccountExists(t *testing.T) {
	t.Parallel()

	store := &adminStoreStub{}
	h, sm := testHandler(t, store)

	rec, req := postLoginForm(t, h, sm, "admin", "any-password-123")

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), adminUnconfiguredLoginError) {
		t.Fatalf("unconfigured login response = %d %q, want the unconfigured notice", rec.Code, rec.Body.String())
	}
	h.loginMu.Lock()
	for _, key := range []string{clientIP(req), adminLoginAccountKey} {
		if attempt, ok := h.loginAttempts[key]; !ok || attempt.count != 1 {
			h.loginMu.Unlock()
			t.Fatalf("login attempts for %q = %+v, want one recorded failure", key, attempt)
		}
	}
	h.loginMu.Unlock()
	if reasons := loginFailedAuditReasons(t, store); len(reasons) != 1 || reasons[0] != "admin account not configured" {
		t.Fatalf("login_failed audit reasons = %q, want one unconfigured-account row", reasons)
	}
}

// TestProcessLoginUnconfiguredAccountFailsClosedWhenAuditFails matches the
// other login failures: the attempt is counted before the audit write, and a
// failing audit store answers 500 instead of skipping the audit row.
func TestProcessLoginUnconfiguredAccountFailsClosedWhenAuditFails(t *testing.T) {
	t.Parallel()

	store := &adminStoreStub{auditErr: errors.New("audit down")}
	h, sm := testHandler(t, store)

	rec, req := postLoginForm(t, h, sm, "admin", "any-password-123")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 when the rejection audit fails", rec.Code)
	}
	assertFailedAttemptRecorded(t, h, clientIP(req))
}

// TestProcessLoginUnconfiguredAccountLocksOutAfterRepeatedAttempts proves the
// recorded failures feed the normal lockout.
func TestProcessLoginUnconfiguredAccountLocksOutAfterRepeatedAttempts(t *testing.T) {
	t.Parallel()

	store := &adminStoreStub{}
	h, sm := testHandler(t, store)

	for range loginMaxAttempts {
		postLoginForm(t, h, sm, "admin", "any-password-123")
	}
	rec, _ := postLoginForm(t, h, sm, "admin", "any-password-123")
	if !strings.Contains(rec.Body.String(), "Too many failed login attempts") {
		t.Fatalf("login after %d unconfigured-account failures = %q, want lockout", loginMaxAttempts, rec.Body.String())
	}
}

// TestProcessLoginEqualizesPasswordCheckCostAcrossFailureKinds keeps unknown
// usernames and a missing admin account from answering faster than a wrong
// password: those branches run a dummy bcrypt comparison of the submitted
// password, while the wrong-password branch already pays for the real one.
func TestProcessLoginEqualizesPasswordCheckCostAcrossFailureKinds(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	for _, tt := range []struct {
		name          string
		adminAuth     *db.AdminAuth
		username      string
		wantEqualized int
		wantMessage   string
	}{
		{name: "unknown username", adminAuth: &db.AdminAuth{PasswordHash: passwordHash, CreatedAt: time.Now()}, username: "root", wantEqualized: 1, wantMessage: "Invalid username or password."},
		{name: "wrong password", adminAuth: &db.AdminAuth{PasswordHash: passwordHash, CreatedAt: time.Now()}, username: "admin", wantEqualized: 0, wantMessage: "Invalid username or password."},
		{name: "unconfigured account", username: "admin", wantEqualized: 1, wantMessage: adminUnconfiguredLoginError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &adminStoreStub{adminAuth: tt.adminAuth}
			h, sm := testHandler(t, store)
			var equalized []string
			h.equalizePasswordCheck = func(password string) {
				equalized = append(equalized, password)
			}

			rec, _ := postLoginForm(t, h, sm, tt.username, "submitted-password")

			if len(equalized) != tt.wantEqualized {
				t.Fatalf("dummy password checks = %d, want %d", len(equalized), tt.wantEqualized)
			}
			if tt.wantEqualized > 0 && equalized[0] != "submitted-password" {
				t.Fatal("dummy password check did not compare the submitted password")
			}
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tt.wantMessage) {
				t.Fatalf("login response = %d %q, want %q", rec.Code, rec.Body.String(), tt.wantMessage)
			}
		})
	}
}

// TestProcessLoginUnknownUsernameAndWrongPasswordLookTheSame keeps the two
// credential failures indistinguishable to the client: same status, same
// rendered message, and one failed attempt each.
func TestProcessLoginUnknownUsernameAndWrongPasswordLookTheSame(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	responses := map[string]*httptest.ResponseRecorder{}
	for _, username := range []string{"root", "admin"} {
		store := &adminStoreStub{adminAuth: &db.AdminAuth{PasswordHash: passwordHash, CreatedAt: time.Now()}}
		h, sm := testHandler(t, store)
		rec, req := postLoginForm(t, h, sm, username, "wrong-password")
		responses[username] = rec
		h.loginMu.Lock()
		count := h.loginAttempts[clientIP(req)].count
		h.loginMu.Unlock()
		if count != 1 {
			t.Fatalf("%s: login attempts = %d, want 1", username, count)
		}
	}
	unknown, wrong := responses["root"], responses["admin"]
	if unknown.Code != wrong.Code || !strings.Contains(unknown.Body.String(), "Invalid username or password.") || !strings.Contains(wrong.Body.String(), "Invalid username or password.") {
		t.Fatalf("unknown username = %d, wrong password = %d; want the same status and message", unknown.Code, wrong.Code)
	}
}

// restoreContextRecorder fails the first runtime apply after cancelling the
// request context, as a client disconnect would, and records the context the
// rollback apply receives.
type restoreContextRecorder struct {
	cancelRequest  context.CancelFunc
	cfg            *config.Config
	calls          int
	restoreErr     error
	restoreHasDead bool
}

func (r *restoreContextRecorder) apply(ctx context.Context, feed config.FeedSettings) error {
	r.calls++
	if r.calls == 1 {
		if err := r.cfg.SetFeedSettings(feed); err != nil {
			return err
		}
		r.cancelRequest()
		return errors.New("apply failed after client disconnect")
	}
	r.restoreErr = ctx.Err()
	_, r.restoreHasDead = ctx.Deadline()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return r.cfg.SetFeedSettings(feed)
}

// TestAdminFeedConfigRollbackSurvivesRequestCancellation keeps a client
// disconnect from cancelling the runtime rollback, which would leave the
// running process on a configuration that was never persisted.
func TestAdminFeedConfigRollbackSurvivesRequestCancellation(t *testing.T) {
	store := newAdminStoreStub()
	cfg := adminFlowConfig()
	handler, sm := newAdminHandlerForStore(t, store, cfg)
	before, ok := cfg.FeedSettings("osv")
	if !ok {
		t.Fatal("missing osv runtime config")
	}

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name": {"osv"},
		"mode":      {"external"},
	})
	reqCtx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(reqCtx)
	recorder := &restoreContextRecorder{cancelRequest: cancel, cfg: cfg}
	handler.SetFeedConfigApplyFunc(recorder.apply)

	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)

	if recorder.calls != 2 {
		t.Fatalf("apply calls = %d, want desired apply plus rollback", recorder.calls)
	}
	if recorder.restoreErr != nil {
		t.Fatalf("rollback context error = %v, want a context detached from the cancelled request", recorder.restoreErr)
	}
	if !recorder.restoreHasDead {
		t.Fatal("rollback context has no deadline, want its own timeout")
	}
	after, _ := cfg.FeedSettings("osv")
	if after.Mode != before.Mode || after.Enabled != before.Enabled {
		t.Fatalf("runtime feed after rollback = %+v, want previous %+v", after, before)
	}
}
