package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// SessionCookieName is the name of the HTTP cookie that carries the
	// session ID.
	SessionCookieName = "packmon_session"

	// SessionCookiePath scopes browser delivery of the admin session cookie
	// to admin routes.
	SessionCookiePath = "/admin"

	// sessionIDBytes is the number of random bytes used for session IDs.
	// 32 bytes = 256 bits of entropy, hex-encoded to 64 characters.
	sessionIDBytes = 32

	// preAuthSessionTTL bounds the lifetime of the throwaway, non-admin
	// sessions created to carry a CSRF token on public forms (login page),
	// so anonymous form loads cannot accumulate long-lived session entries.
	preAuthSessionTTL = 15 * time.Minute
)

// DefaultAdminIdleTimeout is the server-side inactivity timeout for admin
// sessions when no explicit value is configured.
const DefaultAdminIdleTimeout = 15 * time.Minute

// Session holds the data associated with an authenticated admin session.
type Session struct {
	ID    string
	Admin bool
	// AuthenticatedWithBootstrap records that this session was created by
	// logging in with the bootstrap admin password. Such sessions remain
	// limited to password rotation even after another session clears the
	// global bootstrap flag.
	AuthenticatedWithBootstrap bool
	CreatedAt                  time.Time
	LastAccessed               time.Time
	// expiresAt is when the session becomes invalid. Most sessions expire
	// maxAge after creation; pre-auth login-form sessions expire sooner.
	expiresAt time.Time

	// CSRFToken is the per-session CSRF token, generated lazily on first
	// access via CSRFToken().
	csrf *sessionCSRFState

	// flash holds one-time key/value pairs that are deleted on first read.
	// Used to pass sensitive data (like newly created API keys) between
	// requests without exposing them in the URL.
	flash map[string]string
}

type sessionCSRFState struct {
	mu    sync.Mutex
	token string
}

// SessionManager manages in-memory admin sessions. It is safe for
// concurrent use.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session

	// maxAge is how long a session remains valid after creation.
	maxAge      time.Duration
	idleTimeout time.Duration
	// secure controls the Secure flag on the session cookie. It must
	// be true in production (HTTPS only) and may be false in development.
	secure bool
}

// NewSessionManagerWithIdleTimeout creates a SessionManager with separate
// absolute and inactivity timeouts for admin sessions.
func NewSessionManagerWithIdleTimeout(ctx context.Context, maxAge, idleTimeout time.Duration, secure bool) *SessionManager {
	if maxAge <= 0 {
		maxAge = 8 * time.Hour
	}
	if idleTimeout <= 0 {
		idleTimeout = DefaultAdminIdleTimeout
	}
	sm := &SessionManager{
		sessions:    make(map[string]*Session),
		maxAge:      maxAge,
		idleTimeout: idleTimeout,
		secure:      secure,
	}
	// Background goroutine to evict expired sessions every 5 minutes.
	go sm.cleanup(ctx)
	return sm
}

// CreateAdmin creates an authenticated admin session, optionally recording
// that the login used the bootstrap password.
func (sm *SessionManager) CreateAdmin(w http.ResponseWriter, authenticatedWithBootstrap bool) (*Session, error) {
	return sm.createAdmin(w, authenticatedWithBootstrap, false)
}

// CreateExclusiveAdmin creates a fresh admin session, removes all previous
// admin sessions, and writes the new session cookie. Non-admin pre-auth
// sessions are left intact because they only carry login CSRF tokens.
func (sm *SessionManager) CreateExclusiveAdmin(w http.ResponseWriter) (*Session, error) {
	return sm.createAdmin(w, false, true)
}

func (sm *SessionManager) createAdmin(w http.ResponseWriter, authenticatedWithBootstrap, exclusive bool) (*Session, error) {
	id, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("auth: generate session id: %w", err)
	}

	now := time.Now()
	sess := &Session{
		ID:                         id,
		Admin:                      true,
		AuthenticatedWithBootstrap: authenticatedWithBootstrap,
		CreatedAt:                  now,
		LastAccessed:               now,
		expiresAt:                  now.Add(sm.maxAge),
		csrf:                       &sessionCSRFState{},
	}

	sm.mu.Lock()
	if exclusive {
		for existingID, existing := range sm.sessions {
			if existing.Admin {
				delete(sm.sessions, existingID)
			}
		}
	}
	sm.sessions[id] = sess
	sm.mu.Unlock()

	sm.setAdminCookie(w, id)
	return cloneSession(sess), nil
}

// CreatePreAuth creates a short-lived, non-admin session used only to carry a
// CSRF token on a public form (the login page). The session is created
// non-admin atomically (no post-creation mutation, so there is no window in
// which it could be treated as authenticated) and expires quickly so anonymous
// form loads cannot accumulate long-lived session entries.
func (sm *SessionManager) CreatePreAuth(w http.ResponseWriter) (*Session, error) {
	id, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("auth: generate session id: %w", err)
	}

	ttl := min(sm.maxAge, preAuthSessionTTL)

	now := time.Now()
	sess := &Session{
		ID:           id,
		Admin:        false,
		CreatedAt:    now,
		LastAccessed: now,
		expiresAt:    now.Add(ttl),
		csrf:         &sessionCSRFState{},
	}

	sm.mu.Lock()
	sm.sessions[id] = sess
	sm.mu.Unlock()

	sm.setPreAuthCookie(w, id, ttl)
	return cloneSession(sess), nil
}

// CreateOrReusePreAuth returns the existing valid non-admin login session from
// the request when possible; otherwise it creates a new pre-auth session.
func (sm *SessionManager) CreateOrReusePreAuth(w http.ResponseWriter, r *http.Request) (*Session, error) {
	if sess, ttl := sm.reusablePreAuthSession(r); sess != nil {
		sm.setPreAuthCookie(w, sess.ID, ttl)
		return sess, nil
	}
	return sm.CreatePreAuth(w)
}

func (sm *SessionManager) reusablePreAuthSession(r *http.Request) (*Session, time.Duration) {
	if r == nil {
		return nil, 0
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, 0
	}

	now := time.Now()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessions[cookie.Value]
	if !ok || sess.Admin {
		return nil, 0
	}
	if sess.expiresAt.IsZero() || !now.Before(sess.expiresAt) {
		delete(sm.sessions, cookie.Value)
		return nil, 0
	}

	ttl := sess.expiresAt.Sub(now)
	if ttl < time.Second {
		delete(sm.sessions, cookie.Value)
		return nil, 0
	}

	sess.LastAccessed = now
	return cloneSession(sess), ttl
}

// Get retrieves the session associated with the request's session
// cookie. Returns nil if no valid session exists, or if the session
// has expired. A valid session's LastAccessed timestamp is updated.
func (sm *SessionManager) Get(r *http.Request) *Session {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessions[cookie.Value]
	if !ok {
		return nil
	}

	now := time.Now()

	// Check expiration.
	if !sess.expiresAt.IsZero() && now.After(sess.expiresAt) {
		delete(sm.sessions, cookie.Value)
		return nil
	}
	if sess.Admin && sm.idleTimeout > 0 && now.Sub(sess.LastAccessed) > sm.idleTimeout {
		delete(sm.sessions, cookie.Value)
		return nil
	}

	sess.LastAccessed = now
	return cloneSession(sess)
}

// Delete destroys the session and clears the session cookie.
func (sm *SessionManager) Delete(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return
	}

	sm.mu.Lock()
	delete(sm.sessions, cookie.Value)
	sm.mu.Unlock()

	sm.clearCookie(w, SessionCookiePath)
	// Also clear the legacy root-scoped cookie used by older Packmon builds.
	sm.clearCookie(w, "/")
}

func (sm *SessionManager) clearCookie(w http.ResponseWriter, path string) {
	// #nosec G124 -- Secure is intentionally configurable so local HTTP development remains usable; production enables it.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// setAdminCookie writes an authenticated admin browser-session cookie. The
// server-side session still carries absolute and idle expiration.
func (sm *SessionManager) setAdminCookie(w http.ResponseWriter, sessionID string) {
	// #nosec G124 -- Secure is intentionally configurable so local HTTP development remains usable; production enables it.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     SessionCookiePath,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// setPreAuthCookie writes the short-lived pre-auth session cookie used by login forms.
func (sm *SessionManager) setPreAuthCookie(w http.ResponseWriter, sessionID string, ttl time.Duration) {
	maxAge := int(ttl.Seconds())
	// #nosec G124 -- Secure is intentionally configurable so local HTTP development remains usable; production enables it.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     SessionCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// SetFlash stores a one-time value in the session that will be deleted
// on first read via GetFlash. The caller must hold the session (obtained
// via sm.Get or sm.Create). The session manager's lock is taken
// internally to protect concurrent access to the flash map.
func (sm *SessionManager) SetFlash(sessionID, key, value string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessions[sessionID]
	if !ok {
		return
	}
	if sess.flash == nil {
		sess.flash = make(map[string]string)
	}
	sess.flash[key] = value
}

// GetFlash retrieves and deletes a one-time value from the session.
// Returns the empty string if the key does not exist or the session is
// not found.
func (sm *SessionManager) GetFlash(sessionID, key string) string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessions[sessionID]
	if !ok || sess.flash == nil {
		return ""
	}
	val, exists := sess.flash[key]
	if !exists {
		return ""
	}
	delete(sess.flash, key)
	return val
}

// PeekFlash retrieves a flash value without deleting it. It is intended for
// idempotent redirects that must preserve a one-time value for the next page.
func (sm *SessionManager) PeekFlash(sessionID, key string) string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessions[sessionID]
	if !ok || sess.flash == nil {
		return ""
	}
	return sess.flash[key]
}

func cloneSession(sess *Session) *Session {
	if sess == nil {
		return nil
	}
	clone := *sess
	if clone.csrf == nil {
		clone.csrf = &sessionCSRFState{}
	}
	if sess.flash != nil {
		clone.flash = make(map[string]string, len(sess.flash))
		for key, value := range sess.flash {
			clone.flash[key] = value
		}
	}
	return &clone
}

// cleanup periodically evicts expired sessions. It runs in its own goroutine,
// started by NewSessionManagerWithIdleTimeout. It exits when ctx is cancelled.
func (sm *SessionManager) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.cleanupExpiredSessions(time.Now())
		}
	}
}

func (sm *SessionManager) cleanupExpiredSessions(now time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, sess := range sm.sessions {
		if !sess.expiresAt.IsZero() && now.After(sess.expiresAt) {
			delete(sm.sessions, id)
			continue
		}
		if sess.Admin && sm.idleTimeout > 0 && now.Sub(sess.LastAccessed) > sm.idleTimeout {
			delete(sm.sessions, id)
		}
	}
}

// generateSessionID returns a cryptographically random hex-encoded
// session ID.
func generateSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
