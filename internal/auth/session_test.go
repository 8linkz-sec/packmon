package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestSessionManager creates a SessionManager with a short maxAge for
// testing. It uses secure=false so we do not need TLS in tests.
func newTestSessionManager(maxAge time.Duration) *SessionManager {
	return NewSessionManager(context.Background(), maxAge, false)
}

// createSession is a helper that creates a session and returns both the
// session and the session ID from the Set-Cookie header.
func createSession(t *testing.T, sm *SessionManager) (*Session, string) {
	t.Helper()

	rec := httptest.NewRecorder()
	sess, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if sess == nil {
		t.Fatal("Create returned nil session")
	}

	// Extract the session ID from the Set-Cookie header.
	resp := rec.Result()
	defer resp.Body.Close() //nolint:errcheck // test helper
	var cookieValue string
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName {
			cookieValue = c.Value
			break
		}
	}
	if cookieValue == "" {
		t.Fatal("no session cookie found in response")
	}

	return sess, cookieValue
}

// requestWithSession builds an *http.Request carrying the session cookie.
func requestWithSession(sessionID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{ //nolint:gosec // test injects a minimal session cookie into httptest request.
		Name:  SessionCookieName,
		Value: sessionID,
	})
	return req
}

func TestCreateGeneratesUniqueSessionIDs(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	seen := make(map[string]struct{})

	for i := 0; i < 50; i++ {
		sess, cookieID := createSession(t, sm)
		if _, dup := seen[sess.ID]; dup {
			t.Fatalf("duplicate session ID %q on iteration %d", sess.ID, i)
		}
		seen[sess.ID] = struct{}{}

		// The cookie value must match the session ID.
		if cookieID != sess.ID {
			t.Fatalf("cookie value %q != session ID %q", cookieID, sess.ID)
		}
	}
}

func TestCreateSetsSessionFields(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	sess, _ := createSession(t, sm)

	if !sess.Admin {
		t.Fatal("session Admin = false, want true")
	}
	if sess.AuthenticatedWithBootstrap {
		t.Fatal("session AuthenticatedWithBootstrap = true, want false by default")
	}
	if sess.CreatedAt.IsZero() {
		t.Fatal("session CreatedAt is zero")
	}
	if sess.LastAccessed.IsZero() {
		t.Fatal("session LastAccessed is zero")
	}
	if len(sess.ID) != 64 {
		t.Fatalf("session ID length = %d, want 64 (32 bytes hex)", len(sess.ID))
	}
}

func TestCreateAdminCanMarkBootstrapAuthenticatedSession(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	rec := httptest.NewRecorder()
	sess, err := sm.CreateAdmin(rec, true)
	if err != nil {
		t.Fatalf("CreateAdmin returned error: %v", err)
	}
	if sess == nil || !sess.Admin || !sess.AuthenticatedWithBootstrap {
		t.Fatalf("CreateAdmin session = %+v, want bootstrap-authenticated admin session", sess)
	}
}

func TestCreateExclusiveAdminReplacesOnlyAdminSessions(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	_, oldAdminID := createSession(t, sm)

	preAuthRec := httptest.NewRecorder()
	preAuth, err := sm.CreatePreAuth(preAuthRec)
	if err != nil {
		t.Fatalf("CreatePreAuth returned error: %v", err)
	}

	rec := httptest.NewRecorder()
	newAdmin, err := sm.CreateExclusiveAdmin(rec)
	if err != nil {
		t.Fatalf("CreateExclusiveAdmin returned error: %v", err)
	}
	if newAdmin == nil || !newAdmin.Admin {
		t.Fatalf("CreateExclusiveAdmin session = %+v, want admin session", newAdmin)
	}

	if got := sm.Get(requestWithSession(oldAdminID)); got != nil {
		t.Fatalf("old admin session still exists: %+v", got)
	}
	if got := sm.Get(requestWithSession(preAuth.ID)); got == nil || got.Admin {
		t.Fatalf("pre-auth session after exclusive admin create = %+v, want retained non-admin session", got)
	}
	if got := sm.Get(requestWithSession(newAdmin.ID)); got == nil || !got.Admin {
		t.Fatalf("new admin session lookup = %+v, want admin session", got)
	}

	foundCookie := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName {
			foundCookie = true
			if c.Value != newAdmin.ID {
				t.Fatalf("session cookie value = %q, want %q", c.Value, newAdmin.ID)
			}
		}
	}
	if !foundCookie {
		t.Fatal("CreateExclusiveAdmin did not set session cookie")
	}
}

func TestGetRetrievesCreatedSession(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	created, cookieID := createSession(t, sm)

	req := requestWithSession(cookieID)
	got := sm.Get(req)
	if got == nil {
		t.Fatal("Get returned nil for valid session")
	}
	if got.ID != created.ID {
		t.Fatalf("Get returned session ID %q, want %q", got.ID, created.ID)
	}
	if !got.Admin {
		t.Fatal("retrieved session Admin = false")
	}
}

func TestReturnedSessionsDoNotExposeManagerState(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	created, cookieID := createSession(t, sm)
	created.Admin = false
	created.AuthenticatedWithBootstrap = true
	created.LastAccessed = time.Time{}

	got := sm.Get(requestWithSession(cookieID))
	if got == nil {
		t.Fatal("Get returned nil for valid session")
	}
	if !got.Admin {
		t.Fatal("mutating Create return changed stored Admin flag")
	}
	if got.AuthenticatedWithBootstrap {
		t.Fatal("mutating Create return changed stored bootstrap flag")
	}
	if got.LastAccessed.IsZero() {
		t.Fatal("mutating Create return changed stored LastAccessed")
	}

	got.Admin = false
	got.AuthenticatedWithBootstrap = true
	got.LastAccessed = time.Time{}

	next := sm.Get(requestWithSession(cookieID))
	if next == nil {
		t.Fatal("second Get returned nil for valid session")
	}
	if !next.Admin {
		t.Fatal("mutating Get return changed stored Admin flag")
	}
	if next.AuthenticatedWithBootstrap {
		t.Fatal("mutating Get return changed stored bootstrap flag")
	}
	if next.LastAccessed.IsZero() {
		t.Fatal("mutating Get return changed stored LastAccessed")
	}
}

func TestSessionCopiesShareManagerOwnedCSRFState(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	sess, cookieID := createSession(t, sm)
	token, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken(create return) error = %v", err)
	}

	req := requestWithSession(cookieID)
	req.Method = http.MethodPost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Form = map[string][]string{CSRFFieldName: {token}}
	req.PostForm = req.Form

	got := sm.Get(req)
	if got == nil {
		t.Fatal("Get returned nil for valid session")
	}
	if !ValidateCSRF(req, got) {
		t.Fatal("CSRF token generated on Create return was not valid on later Get copy")
	}

	secondReq := requestWithSession(cookieID)
	secondReq.Method = http.MethodPost
	secondReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	secondReq.Form = map[string][]string{CSRFFieldName: {token}}
	secondReq.PostForm = secondReq.Form
	if !ValidateCSRF(secondReq, sm.Get(secondReq)) {
		t.Fatal("CSRF token was not stable across repeated Get copies")
	}
}

func TestGetReturnsNilForUnknownSessionID(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)

	req := requestWithSession("nonexistent-session-id")
	got := sm.Get(req)
	if got != nil {
		t.Fatalf("Get returned non-nil session for unknown ID: %+v", got)
	}
}

func TestGetReturnsNilWithoutCookie(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := sm.Get(req)
	if got != nil {
		t.Fatalf("Get returned non-nil session without cookie: %+v", got)
	}
}

func TestDeleteRemovesSession(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	_, cookieID := createSession(t, sm)

	// Verify session exists.
	req := requestWithSession(cookieID)
	if sm.Get(req) == nil {
		t.Fatal("session should exist before deletion")
	}

	// Delete it.
	rec := httptest.NewRecorder()
	sm.Delete(rec, req)

	// Verify it is gone.
	req2 := requestWithSession(cookieID)
	if sm.Get(req2) != nil {
		t.Fatal("session still exists after Delete")
	}

	// Verify the response clears the cookie (MaxAge = -1).
	resp := rec.Result()
	defer resp.Body.Close() //nolint:errcheck // test helper //nolint:errcheck // test helper
	clearPaths := map[string]bool{}
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName {
			if c.MaxAge != -1 {
				t.Fatalf("cleared cookie MaxAge = %d, want -1", c.MaxAge)
			}
			if c.Value != "" {
				t.Fatalf("cleared cookie Value = %q, want empty", c.Value)
			}
			clearPaths[c.Path] = true
		}
	}
	for _, want := range []string{"/admin", "/"} {
		if !clearPaths[want] {
			t.Fatalf("cleared cookie paths = %v, missing %s", clearPaths, want)
		}
	}
}

func TestDeleteWithoutCookieIsNoop(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Should not panic or error.
	sm.Delete(rec, req)

	resp := rec.Result()
	defer resp.Body.Close() //nolint:errcheck // test helper //nolint:errcheck // test helper
	if len(resp.Cookies()) != 0 {
		t.Fatal("Delete without cookie should not set any cookies")
	}
}

func TestSessionExpiryByMaxAge(t *testing.T) {
	t.Parallel()

	// Use a very short maxAge so the session expires quickly.
	sm := newTestSessionManager(50 * time.Millisecond)
	_, cookieID := createSession(t, sm)

	// Immediately the session should be valid.
	req := requestWithSession(cookieID)
	if sm.Get(req) == nil {
		t.Fatal("session should be valid immediately after creation")
	}

	// Wait for it to expire.
	time.Sleep(100 * time.Millisecond)

	req2 := requestWithSession(cookieID)
	if sm.Get(req2) != nil {
		t.Fatal("session should have expired")
	}
}

func TestGetUpdatesLastAccessed(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	sess, cookieID := createSession(t, sm)
	initialAccess := sess.LastAccessed

	// Small delay to ensure time moves forward.
	time.Sleep(10 * time.Millisecond)

	req := requestWithSession(cookieID)
	got := sm.Get(req)
	if got == nil {
		t.Fatal("Get returned nil")
	}

	if !got.LastAccessed.After(initialAccess) {
		t.Fatalf("LastAccessed was not updated: initial=%v, got=%v", initialAccess, got.LastAccessed)
	}
}

func TestGetExpiresIdleAdminSession(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, 100*time.Millisecond, false)
	_, cookieID := createSession(t, sm)

	time.Sleep(200 * time.Millisecond)

	if got := sm.Get(requestWithSession(cookieID)); got != nil {
		t.Fatalf("Get returned idle session %+v, want nil", got)
	}
}

func TestGetRefreshesIdleWindow(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, 500*time.Millisecond, false)
	_, cookieID := createSession(t, sm)

	time.Sleep(100 * time.Millisecond)
	if got := sm.Get(requestWithSession(cookieID)); got == nil {
		t.Fatal("Get returned nil before idle timeout")
	}

	time.Sleep(150 * time.Millisecond)
	if got := sm.Get(requestWithSession(cookieID)); got == nil {
		t.Fatal("Get returned nil after activity refreshed the idle window")
	}
}

func TestCleanupExpiredSessionsRemovesExpiredAndIdleSessions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	sm := &SessionManager{
		sessions: map[string]*Session{
			"expired-admin": {
				ID:           "expired-admin",
				Admin:        true,
				LastAccessed: now,
				expiresAt:    now.Add(-time.Second),
			},
			"idle-admin": {
				ID:           "idle-admin",
				Admin:        true,
				LastAccessed: now.Add(-16 * time.Minute),
				expiresAt:    now.Add(time.Hour),
			},
			"active-admin": {
				ID:           "active-admin",
				Admin:        true,
				LastAccessed: now.Add(-15 * time.Minute),
				expiresAt:    now.Add(time.Hour),
			},
			"expired-pre-auth": {
				ID:           "expired-pre-auth",
				Admin:        false,
				LastAccessed: now,
				expiresAt:    now.Add(-time.Second),
			},
			"old-pre-auth-with-future-expiry": {
				ID:           "old-pre-auth-with-future-expiry",
				Admin:        false,
				LastAccessed: now.Add(-time.Hour),
				expiresAt:    now.Add(time.Minute),
			},
		},
		idleTimeout: 15 * time.Minute,
	}

	sm.cleanupExpiredSessions(now)

	for _, id := range []string{"expired-admin", "idle-admin", "expired-pre-auth"} {
		if _, ok := sm.sessions[id]; ok {
			t.Fatalf("cleanup retained %s", id)
		}
	}
	for _, id := range []string{"active-admin", "old-pre-auth-with-future-expiry"} {
		if _, ok := sm.sessions[id]; !ok {
			t.Fatalf("cleanup removed %s", id)
		}
	}
}

func TestCreatePreAuthIsNonAdminAndShortLived(t *testing.T) {
	t.Parallel()

	// maxAge is long, but a pre-auth session must use the shorter pre-auth TTL.
	sm := newTestSessionManager(8 * time.Hour)
	rec := httptest.NewRecorder()
	sess, err := sm.CreatePreAuth(rec)
	if err != nil {
		t.Fatalf("CreatePreAuth returned error: %v", err)
	}
	if sess.Admin {
		t.Fatal("pre-auth session must not be marked admin")
	}

	// The cookie lifetime must be the bounded pre-auth TTL, not maxAge.
	var maxAge int
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName {
			maxAge = c.MaxAge
		}
	}
	if want := int(preAuthSessionTTL.Seconds()); maxAge != want {
		t.Fatalf("pre-auth cookie MaxAge = %d, want %d", maxAge, want)
	}
	if sess.expiresAt.IsZero() || time.Until(sess.expiresAt) > preAuthSessionTTL+time.Second {
		t.Fatalf("pre-auth session expiry not bounded to %s", preAuthSessionTTL)
	}
}

func TestNewSessionManagerDefaultsMaxAge(t *testing.T) {
	t.Parallel()

	sm := NewSessionManager(context.Background(), 0, false)
	// We cannot read maxAge directly, but creating a session with maxAge=0
	// should default to 8h. We verify the cookie MaxAge reflects this.
	rec := httptest.NewRecorder()
	_, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close() //nolint:errcheck // test helper
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName {
			expected := int((8 * time.Hour).Seconds())
			if c.MaxAge != expected {
				t.Fatalf("cookie MaxAge = %d, want %d (8h default)", c.MaxAge, expected)
			}
			return
		}
	}
	t.Fatal("no session cookie found")
}

func TestCSRFTokenIsSetOnSession(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	sess, _ := createSession(t, sm)

	// Initially the session has no CSRF token (csrfToken is unexported,
	// but CSRFToken() generates one lazily).
	token, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken returned error: %v", err)
	}
	if token == "" {
		t.Fatal("CSRFToken returned empty token")
	}

	// Calling again returns the same token.
	token2, err := CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken(2) returned error: %v", err)
	}
	if token2 != token {
		t.Fatalf("CSRFToken returned different token on second call: %q vs %q", token, token2)
	}
}

func TestCookieAttributes(t *testing.T) {
	t.Parallel()

	sm := NewSessionManager(context.Background(), time.Hour, true) // secure=true
	rec := httptest.NewRecorder()
	_, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close() //nolint:errcheck // test helper
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName {
			if !c.HttpOnly {
				t.Fatal("cookie HttpOnly = false, want true")
			}
			if !c.Secure {
				t.Fatal("cookie Secure = false, want true (secure mode)")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("cookie SameSite = %d, want SameSiteStrictMode", c.SameSite)
			}
			if c.Path != "/admin" {
				t.Fatalf("cookie Path = %q, want /admin", c.Path)
			}
			return
		}
	}
	t.Fatal("no session cookie found")
}
