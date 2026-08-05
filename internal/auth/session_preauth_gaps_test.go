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
