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
