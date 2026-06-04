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

	// sessionIDBytes is the number of random bytes used for session IDs.
	// 32 bytes = 256 bits of entropy, hex-encoded to 64 characters.
	sessionIDBytes = 32

	// preAuthSessionTTL bounds the lifetime of the throwaway, non-admin
	// sessions created to carry a CSRF token on public forms (login page),
	// so anonymous form loads cannot accumulate long-lived session entries.
	preAuthSessionTTL = 15 * time.Minute
)

// Session holds the data associated with an authenticated admin session.
type Session struct {
	ID           string
	Admin        bool
	CreatedAt    time.Time
	LastAccessed time.Time
	// expiresAt is when the session becomes invalid. Most sessions expire
	// maxAge after creation; pre-auth login-form sessions expire sooner.
	expiresAt time.Time

	// CSRFToken is the per-session CSRF token, generated lazily on first
	// access via CSRFToken().
	csrfMu    sync.Mutex
	csrfToken string

	// flash holds one-time key/value pairs that are deleted on first read.
	// Used to pass sensitive data (like newly created API keys) between
	// requests without exposing them in the URL.
	flash map[string]string
}

// SessionManager manages in-memory admin sessions. It is safe for
// concurrent use.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session

	// maxAge is how long a session remains valid after creation.
	maxAge time.Duration
	// secure controls the Secure flag on the session cookie. It must
	// be true in production (HTTPS only) and may be false in development.
	secure bool
}

// NewSessionManager creates a SessionManager with the given maximum
// session age and cookie security mode. If maxAge is zero, it defaults
// to 8 hours. The provided context controls the lifetime of the
// background cleanup goroutine; when the context is cancelled the
// goroutine exits.
func NewSessionManager(ctx context.Context, maxAge time.Duration, secure bool) *SessionManager {
	if maxAge <= 0 {
		maxAge = 8 * time.Hour
	}
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		maxAge:   maxAge,
		secure:   secure,
	}
	// Background goroutine to evict expired sessions every 5 minutes.
	go sm.cleanup(ctx)
	return sm
}

// Create generates a new session, stores it, and writes the session
// cookie to the response.
func (sm *SessionManager) Create(w http.ResponseWriter) (*Session, error) {
	id, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("auth: generate session id: %w", err)
	}

	now := time.Now()
	sess := &Session{
		ID:           id,
		Admin:        true,
		CreatedAt:    now,
		LastAccessed: now,
		expiresAt:    now.Add(sm.maxAge),
	}

	sm.mu.Lock()
	sm.sessions[id] = sess
	sm.mu.Unlock()

	sm.setCookie(w, id, sm.maxAge)
	return sess, nil
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
	}

	sm.mu.Lock()
	sm.sessions[id] = sess
	sm.mu.Unlock()

	sm.setCookie(w, id, ttl)
	return sess, nil
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

	// Check expiration.
	if !sess.expiresAt.IsZero() && time.Now().After(sess.expiresAt) {
		delete(sm.sessions, cookie.Value)
		return nil
	}

	sess.LastAccessed = time.Now()
	return sess
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

	// Overwrite the cookie with an expired value.
	// #nosec G124 -- Secure is intentionally configurable so local HTTP development remains usable; production enables it.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// setCookie writes the session cookie to the response with the given lifetime.
func (sm *SessionManager) setCookie(w http.ResponseWriter, sessionID string, ttl time.Duration) {
	// #nosec G124 -- Secure is intentionally configurable so local HTTP development remains usable; production enables it.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
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

// cleanup periodically evicts expired sessions. It runs in its own
// goroutine, started by NewSessionManager. It exits when ctx is cancelled.
func (sm *SessionManager) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.mu.Lock()
			now := time.Now()
			for id, sess := range sm.sessions {
				if !sess.expiresAt.IsZero() && now.After(sess.expiresAt) {
					delete(sm.sessions, id)
				}
			}
			sm.mu.Unlock()
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
