package auth

import (
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
)

// Session holds the data associated with an authenticated admin session.
type Session struct {
	ID           string
	Admin        bool
	CreatedAt    time.Time
	LastAccessed time.Time

	// CSRFToken is the per-session CSRF token, generated lazily on first
	// access via CSRFToken().
	csrfToken string
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
// to 8 hours.
func NewSessionManager(maxAge time.Duration, secure bool) *SessionManager {
	if maxAge <= 0 {
		maxAge = 8 * time.Hour
	}
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		maxAge:   maxAge,
		secure:   secure,
	}
	// Background goroutine to evict expired sessions every 5 minutes.
	go sm.cleanup()
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
	}

	sm.mu.Lock()
	sm.sessions[id] = sess
	sm.mu.Unlock()

	sm.setCookie(w, id)
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
	if time.Since(sess.CreatedAt) > sm.maxAge {
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

// setCookie writes the session cookie to the response.
func (sm *SessionManager) setCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(sm.maxAge.Seconds()),
		HttpOnly: true,
		Secure:   sm.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// cleanup periodically evicts expired sessions. It runs in its own
// goroutine, started by NewSessionManager.
func (sm *SessionManager) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		sm.mu.Lock()
		for id, sess := range sm.sessions {
			if time.Since(sess.CreatedAt) > sm.maxAge {
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
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
