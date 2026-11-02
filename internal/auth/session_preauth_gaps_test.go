package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateOrReusePreAuthReusesValidSession(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, 15*time.Minute, false)

	firstRec := httptest.NewRecorder()
	first, err := sm.CreateOrReusePreAuth(firstRec, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if err != nil || first == nil {
		t.Fatalf("CreateOrReusePreAuth(no cookie) = %+v, %v; want new pre-auth session", first, err)
	}

	reuseReq := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	//nolint:gosec // G124: the test asserts cookie behaviour before authentication on purpose.
	reuseReq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: first.ID})
	reuseRec := httptest.NewRecorder()
	reused, err := sm.CreateOrReusePreAuth(reuseRec, reuseReq)
	if err != nil || reused == nil {
		t.Fatalf("CreateOrReusePreAuth(existing cookie) error = %v", err)
	}
	if reused.ID != first.ID {
		t.Fatalf("CreateOrReusePreAuth(existing cookie) ID = %q, want reused session %q", reused.ID, first.ID)
	}

	staleReq := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	//nolint:gosec // G124: the test asserts cookie behaviour before authentication on purpose.
	staleReq.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "does-not-exist"})
	staleRec := httptest.NewRecorder()
	fresh, err := sm.CreateOrReusePreAuth(staleRec, staleReq)
	if err != nil || fresh == nil {
		t.Fatalf("CreateOrReusePreAuth(unknown cookie) error = %v", err)
	}
	if fresh.ID == "does-not-exist" || fresh.ID == first.ID {
		t.Fatalf("CreateOrReusePreAuth(unknown cookie) ID = %q, want brand-new session", fresh.ID)
	}

	if sess, ttl := sm.reusablePreAuthSession(nil); sess != nil || ttl != 0 {
		t.Fatalf("reusablePreAuthSession(nil request) = %+v, %v; want nil, 0", sess, ttl)
	}
}

func TestCreateOrReusePreAuthEvictsInvalidExpiryBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		expiresAt func(time.Time) time.Time
	}{
		{name: "zero expiry", expiresAt: func(time.Time) time.Time { return time.Time{} }},
		{name: "past expiry", expiresAt: func(now time.Time) time.Time { return now.Add(-time.Minute) }},
		{name: "subsecond remaining", expiresAt: func(now time.Time) time.Time { return now.Add(500 * time.Millisecond) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			const staleID = "stale-pre-auth"
			sm := &SessionManager{
				sessions: map[string]*Session{
					staleID: {
						ID:           staleID,
						LastAccessed: now,
						expiresAt:    tt.expiresAt(now),
					},
				},
				maxAge:      time.Hour,
				idleTimeout: DefaultAdminIdleTimeout,
			}
			req := requestWithSession(staleID)
			rec := httptest.NewRecorder()

			fresh, err := sm.CreateOrReusePreAuth(rec, req)
			if err != nil {
				t.Fatalf("CreateOrReusePreAuth() error = %v", err)
			}
			if fresh == nil || fresh.Admin || fresh.ID == staleID {
				t.Fatalf("CreateOrReusePreAuth() = %+v, want fresh non-admin session", fresh)
			}
			sm.mu.Lock()
			_, staleExists := sm.sessions[staleID]
			_, freshExists := sm.sessions[fresh.ID]
			sm.mu.Unlock()
			if staleExists || !freshExists {
				t.Fatalf("stored sessions: stale exists=%t, fresh exists=%t; want false, true", staleExists, freshExists)
			}
		})
	}
}

func TestCreateOrReusePreAuthDoesNotExtendAbsoluteExpiry(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, DefaultAdminIdleTimeout, false)
	firstRec := httptest.NewRecorder()
	first, err := sm.CreatePreAuth(firstRec)
	if err != nil {
		t.Fatalf("CreatePreAuth() error = %v", err)
	}
	originalExpiry := first.expiresAt

	req := requestWithSession(first.ID)
	reused, err := sm.CreateOrReusePreAuth(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("CreateOrReusePreAuth() error = %v", err)
	}
	if reused.ID != first.ID {
		t.Fatalf("CreateOrReusePreAuth() ID = %q, want %q", reused.ID, first.ID)
	}
	if !reused.expiresAt.Equal(originalExpiry) {
		t.Fatalf("reused expiry = %v, want unchanged absolute expiry %v", reused.expiresAt, originalExpiry)
	}

	sm.mu.Lock()
	storedExpiry := sm.sessions[first.ID].expiresAt
	sm.mu.Unlock()
	if !storedExpiry.Equal(originalExpiry) {
		t.Fatalf("stored expiry = %v, want unchanged absolute expiry %v", storedExpiry, originalExpiry)
	}
}

func TestCreateOrReusePreAuthDoesNotReuseAdminSession(t *testing.T) {
	t.Parallel()

	sm := NewSessionManagerWithIdleTimeout(context.Background(), time.Hour, DefaultAdminIdleTimeout, false)
	admin, adminID := createSession(t, sm)
	fresh, err := sm.CreateOrReusePreAuth(httptest.NewRecorder(), requestWithSession(adminID))
	if err != nil {
		t.Fatalf("CreateOrReusePreAuth(admin cookie) error = %v", err)
	}
	if fresh == nil || fresh.Admin || fresh.ID == adminID {
		t.Fatalf("CreateOrReusePreAuth(admin cookie) = %+v, want distinct non-admin session", fresh)
	}
	if got := sm.Get(requestWithSession(admin.ID)); got == nil || !got.Admin {
		t.Fatalf("original admin session = %+v, want retained admin session", got)
	}
}

func TestCreatePreAuthCapsLifetimeToShorterManagerMaxAge(t *testing.T) {
	t.Parallel()

	const maxAge = 2 * time.Minute
	sm := NewSessionManagerWithIdleTimeout(context.Background(), maxAge, DefaultAdminIdleTimeout, false)
	rec := httptest.NewRecorder()
	sess, err := sm.CreatePreAuth(rec)
	if err != nil {
		t.Fatalf("CreatePreAuth() error = %v", err)
	}
	if got := sess.expiresAt.Sub(sess.CreatedAt); got != maxAge {
		t.Fatalf("pre-auth lifetime = %v, want manager max age %v", got, maxAge)
	}

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == SessionCookieName {
			if cookie.MaxAge != int(maxAge.Seconds()) {
				t.Fatalf("pre-auth cookie MaxAge = %d, want %d", cookie.MaxAge, int(maxAge.Seconds()))
			}
			return
		}
	}
	t.Fatal("CreatePreAuth() did not set a session cookie")
}
