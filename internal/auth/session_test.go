package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestSessionManager creates a SessionManager with a short maxAge for
// testing. It uses secure=false so we do not need TLS in tests.
func newTestSessionManager(maxAge time.Duration) *SessionManager {
	return NewSessionManager(maxAge, false)
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
	defer resp.Body.Close()
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
	req.AddCookie(&http.Cookie{
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
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookieName {
			if c.MaxAge != -1 {
				t.Fatalf("cleared cookie MaxAge = %d, want -1", c.MaxAge)
			}
			if c.Value != "" {
				t.Fatalf("cleared cookie Value = %q, want empty", c.Value)
			}
			return
		}
	}
	t.Fatal("no Set-Cookie header found after Delete")
}

func TestDeleteWithoutCookieIsNoop(t *testing.T) {
	t.Parallel()

	sm := newTestSessionManager(time.Hour)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	// Should not panic or error.
	sm.Delete(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
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

func TestNewSessionManagerDefaultsMaxAge(t *testing.T) {
	t.Parallel()

	sm := NewSessionManager(0, false)
	// We cannot read maxAge directly, but creating a session with maxAge=0
	// should default to 8h. We verify the cookie MaxAge reflects this.
	rec := httptest.NewRecorder()
	_, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close()
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

	sm := NewSessionManager(time.Hour, true) // secure=true
	rec := httptest.NewRecorder()
	_, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	resp := rec.Result()
	defer resp.Body.Close()
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
			if c.Path != "/" {
				t.Fatalf("cookie Path = %q, want /", c.Path)
			}
			return
		}
	}
	t.Fatal("no session cookie found")
}
