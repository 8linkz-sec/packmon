package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
)

const (
	f066OldPassword = "old-password-123"
	f066NewPassword = "new-password-456"
)

type f066RotationFixture struct {
	handler *AdminHandler
	sm      *auth.SessionManager
	store   *adminFlowStoreStub
	req     *http.Request
	primary *auth.Session
	other   *auth.Session
	preAuth *auth.Session
	ip      string
}

func TestF066PasswordRotationEntropyFailureInvalidatesAllAdminSessions(t *testing.T) {
	t.Parallel()

	fixture := newF066RotationFixture(t)
	entropyErr := errors.New("replacement session entropy unavailable")
	fixture.handler.createExclusiveAdminSession = func(http.ResponseWriter) (*auth.Session, error) {
		f066AssertPasswordAndAuditCommitted(t, fixture.store)
		return nil, entropyErr
	}
	rec := httptest.NewRecorder()

	fixture.handler.HandlePasswordChange(rec, fixture.req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	f066AssertPasswordAndAuditCommitted(t, fixture.store)
	f066AssertSessionsInvalidated(t, fixture, "")
	f066AssertDeletionCookies(t, rec, "")
	f066AssertAttemptsReset(t, fixture)
}

func TestF066PasswordRotationNilReplacementFailsClosed(t *testing.T) {
	t.Parallel()

	fixture := newF066RotationFixture(t)
	fixture.handler.createExclusiveAdminSession = func(http.ResponseWriter) (*auth.Session, error) {
		return nil, nil
	}
	rec := httptest.NewRecorder()

	fixture.handler.HandlePasswordChange(rec, fixture.req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	f066AssertPasswordAndAuditCommitted(t, fixture.store)
	f066AssertSessionsInvalidated(t, fixture, "")
	f066AssertDeletionCookies(t, rec, "")
}

func TestF066PasswordRotationPanicInvalidatesPartialReplacementAndPropagates(t *testing.T) {
	t.Parallel()

	fixture := newF066RotationFixture(t)
	panicValue := "replacement session panic"
	var partialID string
	fixture.handler.createExclusiveAdminSession = func(w http.ResponseWriter) (*auth.Session, error) {
		f066AssertPasswordAndAuditCommitted(t, fixture.store)
		partial, err := fixture.sm.CreateAdmin(w, false)
		if err != nil {
			t.Fatalf("create partial replacement: %v", err)
		}
		partialID = partial.ID
		panic(panicValue)
	}
	rec := httptest.NewRecorder()

	func() {
		defer func() {
			if got := recover(); got != panicValue {
				t.Fatalf("recovered panic = %#v, want %#v", got, panicValue)
			}
		}()
		fixture.handler.HandlePasswordChange(rec, fixture.req)
	}()

	if partialID == "" {
		t.Fatal("panic seam did not create a partial replacement session")
	}
	f066AssertPasswordAndAuditCommitted(t, fixture.store)
	f066AssertSessionsInvalidated(t, fixture, partialID)
	f066AssertDeletionCookies(t, rec, partialID)
	f066AssertAttemptsReset(t, fixture)
}

func newF066RotationFixture(t *testing.T) f066RotationFixture {
	t.Helper()
	oldHash, err := auth.HashPassword(f066OldPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	store := newAdminStoreStub()
	store.adminAuth = &db.AdminAuth{
		PasswordHash:        oldHash,
		PasswordIsBootstrap: false,
		CreatedAt:           time.Now().UTC(),
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	req, primary := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {f066OldPassword},
		"new_password":     {f066NewPassword},
		"confirm_password": {f066NewPassword},
	})
	ip := "192.0.2.166"
	req.RemoteAddr = ip + ":12345"

	other, err := sm.CreateAdmin(httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create other admin session: %v", err)
	}
	preAuth, err := sm.CreatePreAuth(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("create pre-auth session: %v", err)
	}
	handler.loginAttempts[ip] = &loginAttempt{count: 2}
	handler.loginAttempts[adminLoginAccountKey] = &loginAttempt{count: 2}

	return f066RotationFixture{
		handler: handler,
		sm:      sm,
		store:   store,
		req:     req,
		primary: primary,
		other:   other,
		preAuth: preAuth,
		ip:      ip,
	}
}

func f066AssertPasswordAndAuditCommitted(t *testing.T, store *adminFlowStoreStub) {
	t.Helper()
	adminAuth, err := store.GetAdminAuth(t.Context())
	if err != nil {
		t.Fatalf("GetAdminAuth: %v", err)
	}
	if adminAuth == nil || !auth.CheckPassword(adminAuth.PasswordHash, f066NewPassword) {
		t.Fatalf("new password was not committed: %+v", adminAuth)
	}
	if auth.CheckPassword(adminAuth.PasswordHash, f066OldPassword) {
		t.Fatal("old password still matches after committed rotation")
	}
	audit, err := store.ListAdminAuditLog(t.Context(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	count := 0
	for _, entry := range audit {
		if entry.Action == "password_change" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("password_change audits = %d, want 1: %+v", count, audit)
	}
}

func f066AssertSessionsInvalidated(t *testing.T, fixture f066RotationFixture, partialID string) {
	t.Helper()
	for name, sessionID := range map[string]string{
		"request": fixture.primary.ID,
		"other":   fixture.other.ID,
		"partial": partialID,
	} {
		if sessionID == "" {
			continue
		}
		if got := fixture.sm.Get(f066SessionRequest(sessionID)); got != nil {
			t.Fatalf("%s admin session survived compensation: %+v", name, got)
		}
	}
	if got := fixture.sm.Get(f066SessionRequest(fixture.preAuth.ID)); got == nil || got.Admin {
		t.Fatalf("pre-auth session was removed or promoted: %+v", got)
	}
}

func f066AssertDeletionCookies(t *testing.T, rec *httptest.ResponseRecorder, stagedSessionID string) {
	t.Helper()
	resp := rec.Result()
	defer resp.Body.Close() //nolint:errcheck // test response body cleanup.
	latest := make(map[string]*http.Cookie)
	stagedCookieSeen := stagedSessionID == ""
	for _, cookie := range resp.Cookies() {
		if cookie.Name != auth.SessionCookieName {
			continue
		}
		if cookie.Value == stagedSessionID {
			stagedCookieSeen = true
		}
		latest[cookie.Path] = cookie
	}
	if !stagedCookieSeen {
		t.Fatalf("staged replacement cookie %q was not observed", stagedSessionID)
	}
	for _, path := range []string{auth.SessionCookiePath, "/"} {
		cookie := latest[path]
		if cookie == nil || cookie.Value != "" || cookie.MaxAge >= 0 {
			t.Fatalf("final cookie for path %q = %+v, want deletion", path, cookie)
		}
	}
}

func f066AssertAttemptsReset(t *testing.T, fixture f066RotationFixture) {
	t.Helper()
	fixture.handler.loginMu.Lock()
	defer fixture.handler.loginMu.Unlock()
	for _, key := range []string{fixture.ip, adminLoginAccountKey} {
		if attempt := fixture.handler.loginAttempts[key]; attempt != nil {
			t.Fatalf("attempts for %q were not reset: %+v", key, attempt)
		}
	}
}

func f066SessionRequest(sessionID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionID}) //nolint:gosec // test injects an in-memory session cookie.
	return req
}
