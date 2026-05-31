package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/auth"
)

func TestRequireAdminSessionRedirectsBrowserRequestsToLogin(t *testing.T) {
	t.Parallel()

	sm := auth.NewSessionManager(context.Background(), time.Hour, false)
	handler := RequireAdminSession(sm, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/feeds", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: "stale-session",
		Path:  "/",
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if location := rec.Header().Get("Location"); location != "/admin/login" {
		t.Fatalf("Location = %q, want /admin/login", location)
	}
	if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, auth.SessionCookieName+"=") {
		t.Fatalf("Set-Cookie = %q, want cleared session cookie", cookie)
	}
}

func TestRequireAdminSessionUsesHXRedirectForHTMXRequests(t *testing.T) {
	t.Parallel()

	sm := auth.NewSessionManager(context.Background(), time.Hour, false)
	handler := RequireAdminSession(sm, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/feeds?partial=runtime", nil)
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: "stale-session",
		Path:  "/",
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if redirect := rec.Header().Get("HX-Redirect"); redirect != "/admin/login" {
		t.Fatalf("HX-Redirect = %q, want /admin/login", redirect)
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Fatalf("Location = %q, want empty for HTMX redirect", location)
	}
	if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, auth.SessionCookieName+"=") {
		t.Fatalf("Set-Cookie = %q, want cleared session cookie", cookie)
	}
}

func TestRequireAdminSessionPassThroughBranches(t *testing.T) {
	t.Parallel()

	sm := auth.NewSessionManager(context.Background(), time.Hour, false)
	called := false
	handler := RequireAdminSession(sm, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("public path status=%d called=%v, want 204 true", rec.Code, called)
	}

	called = false
	req = httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("login path status=%d called=%v, want 204 true", rec.Code, called)
	}

	called = false
	sessionRecorder := httptest.NewRecorder()
	sess, err := sm.Create(sessionRecorder)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/admin/feeds", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.ID})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("admin session status=%d called=%v, want 204 true", rec.Code, called)
	}
}

func TestRequireAdminSessionRejectsPreAuthSession(t *testing.T) {
	t.Parallel()

	sm := auth.NewSessionManager(context.Background(), time.Hour, false)
	handler := RequireAdminSession(sm, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	sess, err := sm.CreatePreAuth(rec)
	if err != nil {
		t.Fatalf("CreatePreAuth() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/feeds", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.ID})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 for non-admin preauth session", rec.Code)
	}
}
