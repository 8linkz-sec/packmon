package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
)

type f065AuditStore struct {
	*adminStoreStub
	beforeInsert func(*db.AdminAuditEntry)
}

func (s *f065AuditStore) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	if s.beforeInsert != nil {
		s.beforeInsert(entry)
	}
	return s.adminStoreStub.InsertAdminAuditLog(ctx, entry)
}

func TestF065LoginCreatesSessionBeforeSuccessAudit(t *testing.T) {
	t.Parallel()

	base := f065LoginStore(t)
	h, sm := testHandler(t, base)
	var createdID string
	h.createAdminSession = func(w http.ResponseWriter, bootstrap bool) (*auth.Session, error) {
		sess, err := sm.CreateAdmin(w, bootstrap)
		if sess != nil {
			createdID = sess.ID
		}
		return sess, err
	}
	store := &f065AuditStore{adminStoreStub: base}
	store.beforeInsert = func(entry *db.AdminAuditEntry) {
		if entry.Action != "login_success" {
			return
		}
		if createdID == "" {
			t.Fatal("login_success audit ran before session creation returned")
		}
		if sess := sm.Get(f065SessionRequest(createdID)); sess == nil || !sess.Admin {
			t.Fatalf("session during login_success audit = %+v, want authenticated admin", sess)
		}
	}
	h.store = adaptAdminStore(store)

	rec := postAdminLogin(t, h, sm, "192.0.2.65", "admin", "correct-password")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if got := adminTestAuditCount(base.auditLogs, "login_success"); got != 1 {
		t.Fatalf("login_success audits = %d, want 1", got)
	}
}

func TestF065LoginSessionEntropyFailureDoesNotAuditOrResetAttempts(t *testing.T) {
	t.Parallel()

	base := f065LoginStore(t)
	h, sm := testHandler(t, base)
	ip := "192.0.2.66"
	f065SeedAttempts(h, ip)
	entropyErr := errors.New("session entropy unavailable")
	h.createAdminSession = func(http.ResponseWriter, bool) (*auth.Session, error) {
		return nil, entropyErr
	}

	rec := postAdminLogin(t, h, sm, ip, "admin", "correct-password")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if adminTestAuditContains(base.auditLogs, "login_success") {
		t.Fatal("session creation failure recorded login_success")
	}
	f065AssertAttemptsPreserved(t, h, ip)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == auth.SessionCookieName && cookie.Value != "" {
			t.Fatalf("session creation failure returned live cookie: %+v", cookie)
		}
	}
}

func TestF065LoginAuditFailureRollsBackOnlyNewSessionBefore500(t *testing.T) {
	t.Parallel()

	base := f065LoginStore(t)
	base.auditErr = errors.New("audit unavailable")
	h, sm := testHandler(t, base)
	ip := "192.0.2.67"
	f065SeedAttempts(h, ip)
	existing, err := sm.CreateAdmin(httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create existing session: %v", err)
	}
	var createdID string
	h.createAdminSession = func(w http.ResponseWriter, bootstrap bool) (*auth.Session, error) {
		sess, createErr := sm.CreateAdmin(w, bootstrap)
		if sess != nil {
			createdID = sess.ID
		}
		return sess, createErr
	}

	rec := postAdminLogin(t, h, sm, ip, "admin", "correct-password")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if createdID == "" {
		t.Fatal("audit failure path did not first create a session")
	}
	if got := sm.Get(f065SessionRequest(createdID)); got != nil {
		t.Fatalf("new session survived audit failure: %+v", got)
	}
	if got := sm.Get(f065SessionRequest(existing.ID)); got == nil || !got.Admin {
		t.Fatalf("unrelated session was removed: %+v", got)
	}
	f065AssertRollbackCookies(t, rec, createdID)
	f065AssertAttemptsPreserved(t, h, ip)
}

func TestF065LoginAuditPanicRollsBackOnlyNewSession(t *testing.T) {
	t.Parallel()

	base := f065LoginStore(t)
	h, sm := testHandler(t, base)
	ip := "192.0.2.68"
	f065SeedAttempts(h, ip)
	existing, err := sm.CreateAdmin(httptest.NewRecorder(), false)
	if err != nil {
		t.Fatalf("create existing session: %v", err)
	}
	var createdID string
	h.createAdminSession = func(w http.ResponseWriter, bootstrap bool) (*auth.Session, error) {
		sess, createErr := sm.CreateAdmin(w, bootstrap)
		if sess != nil {
			createdID = sess.ID
		}
		return sess, createErr
	}
	panicValue := "audit panic"
	store := &f065AuditStore{adminStoreStub: base, beforeInsert: func(entry *db.AdminAuditEntry) {
		if entry.Action == "login_success" {
			panic(panicValue)
		}
	}}
	h.store = adaptAdminStore(store)
	req := f065CommitLoginRequest(t, sm, ip)
	rec := httptest.NewRecorder()

	func() {
		defer func() {
			if got := recover(); got != panicValue {
				t.Fatalf("recovered panic = %#v, want %#v", got, panicValue)
			}
		}()
		h.HandleLogin(rec, req)
	}()

	if createdID == "" {
		t.Fatal("audit panic path did not first create a session")
	}
	if got := sm.Get(f065SessionRequest(createdID)); got != nil {
		t.Fatalf("new session survived audit panic: %+v", got)
	}
	if got := sm.Get(f065SessionRequest(existing.ID)); got == nil || !got.Admin {
		t.Fatalf("unrelated session was removed: %+v", got)
	}
	f065AssertRollbackCookies(t, rec, createdID)
	f065AssertAttemptsPreserved(t, h, ip)
	if adminTestAuditContains(base.auditLogs, "login_success") {
		t.Fatal("panicking audit was recorded as successful")
	}
}

func f065LoginStore(t *testing.T) *adminStoreStub {
	t.Helper()
	hash, err := auth.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return &adminStoreStub{adminAuth: &db.AdminAuth{PasswordHash: hash}}
}

func f065CommitLoginRequest(t *testing.T, sm *auth.SessionManager, ip string) *http.Request {
	t.Helper()
	preAuth, err := sm.CreatePreAuth(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("CreatePreAuth: %v", err)
	}
	token, err := auth.CSRFToken(preAuth)
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}
	form := url.Values{
		"username": {"admin"},
		"password": {"correct-password"},
		"_csrf":    {token},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":12345"
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: preAuth.ID}) //nolint:gosec // test injects an in-memory session cookie.
	return req
}

func f065SessionRequest(sessionID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sessionID}) //nolint:gosec // test injects an in-memory session cookie.
	return req
}

func f065SeedAttempts(h *AdminHandler, ip string) {
	h.loginAttempts[ip] = &loginAttempt{count: 2}
	h.loginAttempts[adminLoginAccountKey] = &loginAttempt{count: 2}
}

func f065AssertAttemptsPreserved(t *testing.T, h *AdminHandler, ip string) {
	t.Helper()
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	for _, key := range []string{ip, adminLoginAccountKey} {
		if got := h.loginAttempts[key]; got == nil || got.count != 2 {
			t.Fatalf("attempts for %q = %+v, want count 2", key, got)
		}
	}
}

func f065AssertRollbackCookies(t *testing.T, rec *httptest.ResponseRecorder, createdID string) {
	t.Helper()
	resp := rec.Result()
	defer resp.Body.Close() //nolint:errcheck // test response body cleanup.
	latest := make(map[string]*http.Cookie)
	createdCookieSeen := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name != auth.SessionCookieName {
			continue
		}
		if cookie.Value == createdID {
			createdCookieSeen = true
		}
		latest[cookie.Path] = cookie
	}
	if !createdCookieSeen {
		t.Fatal("response did not stage the newly created session cookie before rollback")
	}
	for _, path := range []string{auth.SessionCookiePath, "/"} {
		cookie := latest[path]
		if cookie == nil || cookie.Value != "" || cookie.MaxAge >= 0 {
			t.Fatalf("final cookie for path %q = %+v, want deletion", path, cookie)
		}
	}
}
