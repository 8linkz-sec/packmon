package admin

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/web"
)

// -- Store stub ---------------------------------------------------------------

type adminStoreStub struct {
	db.Store
	adminAuth *db.AdminAuth
	auditLogs []*db.AdminAuditEntry

	feedStatuses []db.FeedSyncStatus
	queueStats   *db.QueueStatsResult
	dashStats    *db.DashboardStatsResult
}

func (s *adminStoreStub) GetAdminAuth(_ context.Context) (*db.AdminAuth, error) {
	return s.adminAuth, nil
}

func (s *adminStoreStub) UpsertAdminAuth(_ context.Context, _ string, _ bool) error {
	return nil
}

func (s *adminStoreStub) InsertAdminAuditLog(_ context.Context, entry *db.AdminAuditEntry) error {
	s.auditLogs = append(s.auditLogs, entry)
	return nil
}

func (s *adminStoreStub) ListFeedSyncStatuses(_ context.Context) ([]db.FeedSyncStatus, error) {
	return s.feedStatuses, nil
}

func (s *adminStoreStub) QueueStats(_ context.Context) (*db.QueueStatsResult, error) {
	if s.queueStats == nil {
		return &db.QueueStatsResult{}, nil
	}
	return s.queueStats, nil
}

func (s *adminStoreStub) DashboardStats(_ context.Context) (*db.DashboardStatsResult, error) {
	if s.dashStats == nil {
		return &db.DashboardStatsResult{BySeverity: map[string]int{}}, nil
	}
	return s.dashStats, nil
}

func (s *adminStoreStub) ListAdminAuditLog(_ context.Context, _ int) ([]db.AdminAuditLogEntry, error) {
	return nil, nil
}

// -- Minimal template FS for Renderer -----------------------------------------

// minimalTemplateFS returns an in-memory FS with a bare-bones layout and
// admin/login.html so that the web.Renderer can render without panicking.
// The templates produce minimal HTML that is sufficient for test assertions.
func minimalTemplateFS() fstest.MapFS {
	layout := `{{define "layout"}}{{template "content" .}}{{end}}`
	loginPage := `{{define "content"}}<html><body>{{.Error}}</body></html>{{end}}`
	return fstest.MapFS{
		"templates/layout.html":      {Data: []byte(layout)},
		"templates/admin/login.html": {Data: []byte(loginPage)},
	}
}

// testRenderer creates a web.Renderer backed by the minimal template FS.
func testRenderer() *web.Renderer {
	return web.NewRenderer(minimalTemplateFS(), true)
}

// -- Helper: create handler for tests -----------------------------------------

func testHandler(t *testing.T, store *adminStoreStub) (*AdminHandler, *auth.SessionManager) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sm := auth.NewSessionManager(context.Background(), 8*time.Hour, false)
	cfg := &config.Config{
		Server: config.ServerConfig{Mode: config.ModeDevelopment},
	}
	// Create the handler directly, bypassing NewAdminHandler to avoid
	// the background cleanup goroutine leaking in tests.
	h := &AdminHandler{
		store:         store,
		sm:            sm,
		renderer:      testRenderer(),
		logger:        logger,
		cfg:           cfg,
		syncFeed:      func(_ context.Context, _ string) error { return nil },
		loginAttempts: make(map[string]*loginAttempt),
	}
	return h, sm
}

// -- Tests --------------------------------------------------------------------

func TestHandleLogin_Success(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	store := &adminStoreStub{
		adminAuth: &db.AdminAuth{
			PasswordHash: passwordHash,
			CreatedAt:    time.Now(),
		},
	}

	h, sm := testHandler(t, store)

	// Pre-create a session with a CSRF token (simulates what GET /admin/login does).
	sess, err := sm.Create(httptest.NewRecorder())
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.Admin = false
	csrfToken, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}

	form := url.Values{
		"username": {"admin"},
		"password": {"correct-password"},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sess.ID,
	})
	rec := httptest.NewRecorder()

	h.HandleLogin(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	// Successful login should redirect to /admin/.
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d (SeeOther redirect)", resp.StatusCode, http.StatusSeeOther)
	}
	location := resp.Header.Get("Location")
	if location != "/admin/" {
		t.Errorf("Location = %q, want /admin/", location)
	}

	// A new session cookie should be set.
	foundNewSession := false
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName && c.Value != "" {
			foundNewSession = true
			break
		}
	}
	if !foundNewSession {
		t.Error("no new session cookie set after successful login")
	}

	// An audit log entry for the success should have been recorded.
	foundAudit := false
	for _, entry := range store.auditLogs {
		if entry.Action == "login_success" {
			foundAudit = true
			break
		}
	}
	if !foundAudit {
		t.Error("no login_success audit log entry recorded")
	}
}

func TestHandleLogin_WrongPassword(t *testing.T) {
	t.Parallel()

	passwordHash, _ := auth.HashPassword("correct-password")

	store := &adminStoreStub{
		adminAuth: &db.AdminAuth{
			PasswordHash: passwordHash,
			CreatedAt:    time.Now(),
		},
	}

	h, sm := testHandler(t, store)

	// Create a session with a CSRF token.
	sess, _ := sm.Create(httptest.NewRecorder())
	sess.Admin = false
	csrfToken, _ := auth.CSRFToken(sess)

	form := url.Values{
		"username": {"admin"},
		"password": {"wrong-password"},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sess.ID,
	})
	rec := httptest.NewRecorder()

	h.HandleLogin(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	// Wrong password should NOT redirect to /admin/.
	if resp.Header.Get("Location") == "/admin/" {
		t.Error("wrong password should not redirect to /admin/")
	}

	// The handler re-renders the login form (HTTP 200 with the form HTML).
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (re-rendered form)", resp.StatusCode, http.StatusOK)
	}

	// An audit entry for login_failed should exist.
	foundFailed := false
	for _, entry := range store.auditLogs {
		if entry.Action == "login_failed" {
			foundFailed = true
			var details map[string]string
			_ = json.Unmarshal(entry.Details, &details)
			if details["reason"] != "invalid password" {
				t.Errorf("audit details reason = %q, want %q", details["reason"], "invalid password")
			}
			break
		}
	}
	if !foundFailed {
		t.Error("no login_failed audit log entry recorded")
	}
}

func TestHandleLogin_RateLimited(t *testing.T) {
	t.Parallel()

	passwordHash, _ := auth.HashPassword("correct-password")

	store := &adminStoreStub{
		adminAuth: &db.AdminAuth{
			PasswordHash: passwordHash,
			CreatedAt:    time.Now(),
		},
	}

	h, sm := testHandler(t, store)

	ip := "192.168.1.100"

	// Simulate 5 failed login attempts to trigger lockout.
	for i := 0; i < loginMaxAttempts; i++ {
		sess, _ := sm.Create(httptest.NewRecorder())
		sess.Admin = false
		csrfToken, _ := auth.CSRFToken(sess)

		form := url.Values{
			"username": {"admin"},
			"password": {"wrong"},
			"_csrf":    {csrfToken},
		}
		req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip + ":12345"
		req.AddCookie(&http.Cookie{
			Name:  auth.SessionCookieName,
			Value: sess.ID,
		})
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)
	}

	// Verify the IP is now locked out.
	if !h.isLockedOut(ip) {
		t.Fatal("IP should be locked out after 5 failed attempts")
	}

	// Count audit logs before the 6th attempt.
	auditCountBefore := len(store.auditLogs)

	// The 6th attempt should be blocked before even checking credentials.
	// Use a request without an existing session so showLoginForm does not
	// redirect to /admin/ due to an existing (non-admin) session.
	form := url.Values{
		"username": {"admin"},
		"password": {"correct-password"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":12345"
	// No session cookie -> isLockedOut triggers -> showLoginForm -> renders form.
	rec := httptest.NewRecorder()
	h.HandleLogin(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	// The handler should NOT create an authenticated session. Verify no
	// "login_success" audit entry was added.
	for _, entry := range store.auditLogs[auditCountBefore:] {
		if entry.Action == "login_success" {
			t.Error("locked-out IP should not produce login_success audit entry")
		}
	}

	// Verify lockout audit log entry.
	foundLockout := false
	for _, entry := range store.auditLogs {
		if entry.Action == "login_lockout" {
			foundLockout = true
			break
		}
	}
	if !foundLockout {
		t.Error("no login_lockout audit log entry recorded")
	}
}

func TestHandleLogout_RequiresCSRF(t *testing.T) {
	t.Parallel()

	store := &adminStoreStub{}
	h, sm := testHandler(t, store)

	// Create a valid admin session.
	sessRec := httptest.NewRecorder()
	sess, _ := sm.Create(sessRec)
	sess.Admin = true
	_, _ = auth.CSRFToken(sess)

	// POST with an invalid CSRF token.
	form := url.Values{
		"_csrf": {"invalid-csrf-token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sess.ID,
	})
	rec := httptest.NewRecorder()

	h.HandleLogout(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	// With invalid CSRF, logout redirects to /admin/login.
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
	}
	location := resp.Header.Get("Location")
	if location != "/admin/login" {
		t.Errorf("Location = %q, want /admin/login", location)
	}

	// No logout audit log should be written for failed CSRF.
	for _, entry := range store.auditLogs {
		if entry.Action == "logout" {
			t.Error("logout audit log entry should NOT be written when CSRF fails")
		}
	}
}

func TestRequireAdmin_NoSession(t *testing.T) {
	t.Parallel()

	store := &adminStoreStub{}
	h, _ := testHandler(t, store)

	// Request without any session cookie.
	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	sess := h.requireAdmin(rec, req)

	if sess != nil {
		t.Error("requireAdmin() should return nil when no session exists")
	}

	resp := rec.Result()
	defer resp.Body.Close()

	// Should redirect to login.
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d (redirect to login)", resp.StatusCode, http.StatusSeeOther)
	}
	location := resp.Header.Get("Location")
	if location != "/admin/login" {
		t.Errorf("Location = %q, want /admin/login", location)
	}
}

func TestRequireAdmin_NonAdminSession(t *testing.T) {
	t.Parallel()

	store := &adminStoreStub{}
	h, sm := testHandler(t, store)

	// Create a session that is NOT an admin session.
	sessRec := httptest.NewRecorder()
	sess, _ := sm.Create(sessRec)
	sess.Admin = false

	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sess.ID,
	})
	rec := httptest.NewRecorder()

	result := h.requireAdmin(rec, req)

	if result != nil {
		t.Error("requireAdmin() should return nil for non-admin session")
	}

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want %d (redirect)", resp.StatusCode, http.StatusSeeOther)
	}
}

func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	store := &adminStoreStub{}
	h, _ := testHandler(t, store)

	req := httptest.NewRequest(http.MethodPut, "/admin/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	h.HandleLogin(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestHandleLogin_GET_RendersForm(t *testing.T) {
	t.Parallel()

	store := &adminStoreStub{}
	h, _ := testHandler(t, store)

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	h.HandleLogin(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	// The GET renders the login form.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// A session cookie should be set for the CSRF token.
	foundSession := false
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName {
			foundSession = true
			break
		}
	}
	if !foundSession {
		t.Error("GET /admin/login should set a session cookie for CSRF")
	}
}

func TestIsLockedOut_ExpiresAfterDuration(t *testing.T) {
	t.Parallel()

	h := &AdminHandler{
		loginAttempts: make(map[string]*loginAttempt),
	}

	ip := "10.0.0.1"

	// Simulate a lockout that has already expired.
	h.loginMu.Lock()
	h.loginAttempts[ip] = &loginAttempt{
		count:    loginMaxAttempts,
		lockedAt: time.Now().Add(-loginLockoutDuration - time.Minute),
	}
	h.loginMu.Unlock()

	if h.isLockedOut(ip) {
		t.Error("isLockedOut should return false after lockout duration expires")
	}
}

func TestResetAttempts_ClearsLockout(t *testing.T) {
	t.Parallel()

	h := &AdminHandler{
		loginAttempts: make(map[string]*loginAttempt),
	}

	ip := "10.0.0.1"

	// Simulate a lockout.
	h.loginMu.Lock()
	h.loginAttempts[ip] = &loginAttempt{
		count:    loginMaxAttempts,
		lockedAt: time.Now(),
	}
	h.loginMu.Unlock()

	if !h.isLockedOut(ip) {
		t.Fatal("should be locked out")
	}

	h.resetAttempts(ip)

	if h.isLockedOut(ip) {
		t.Error("should not be locked out after reset")
	}
}

func TestHandleLogin_InvalidUsername(t *testing.T) {
	t.Parallel()

	passwordHash, _ := auth.HashPassword("password")

	store := &adminStoreStub{
		adminAuth: &db.AdminAuth{
			PasswordHash: passwordHash,
			CreatedAt:    time.Now(),
		},
	}

	h, sm := testHandler(t, store)

	sess, _ := sm.Create(httptest.NewRecorder())
	sess.Admin = false
	csrfToken, _ := auth.CSRFToken(sess)

	form := url.Values{
		"username": {"notadmin"},
		"password": {"password"},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: sess.ID,
	})
	rec := httptest.NewRecorder()

	h.HandleLogin(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	// Should NOT redirect to /admin/.
	if resp.Header.Get("Location") == "/admin/" {
		t.Error("invalid username should not redirect to /admin/")
	}

	// An audit entry for login_failed with reason "invalid username" should exist.
	foundFailed := false
	for _, entry := range store.auditLogs {
		if entry.Action == "login_failed" {
			foundFailed = true
			var details map[string]string
			_ = json.Unmarshal(entry.Details, &details)
			if details["reason"] != "invalid username" {
				t.Errorf("audit details reason = %q, want %q", details["reason"], "invalid username")
			}
			break
		}
	}
	if !foundFailed {
		t.Error("no login_failed audit log entry recorded")
	}
}
