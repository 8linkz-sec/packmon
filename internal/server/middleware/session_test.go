package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
)

func TestRequireAdminSessionRedirectsBrowserRequestsToLogin(t *testing.T) {
	t.Parallel()

	sm := auth.NewSessionManager(context.Background(), time.Hour, false)
	handler := RequireAdminSession(sm, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/feeds", nil)
	req.AddCookie(&http.Cookie{ //nolint:gosec // test injects a stale cookie to exercise clearing behavior.
		Name:  auth.SessionCookieName,
		Value: "stale-session",
		Path:  "/",
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if location := rec.Header().Get("Location"); location != "/admin/login?next=%2Fadmin%2Ffeeds" {
		t.Fatalf("Location = %q, want login redirect with preserved target", location)
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
	req.AddCookie(&http.Cookie{ //nolint:gosec // test injects a stale cookie to exercise HTMX redirect behavior.
		Name:  auth.SessionCookieName,
		Value: "stale-session",
		Path:  "/",
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if redirect := rec.Header().Get("HX-Redirect"); redirect != "/admin/login?next=%2Fadmin%2Ffeeds%3Fpartial%3Druntime" {
		t.Fatalf("HX-Redirect = %q, want login redirect with preserved target", redirect)
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
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.ID}) //nolint:gosec // test injects an in-memory session cookie.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("admin session status=%d called=%v, want 204 true", rec.Code, called)
	}
}

func TestRequireAdminSessionIgnoresAdminPrefixOutsideNamespace(t *testing.T) {
	t.Parallel()

	sm := auth.NewSessionManager(context.Background(), time.Hour, false)
	for _, path := range []string{"/administer", "/admin-assets", "/adminfoo"} {
		t.Run(path, func(t *testing.T) {
			called := false
			handler := RequireAdminSession(sm, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNotFound)
			}))
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(&http.Cookie{ //nolint:gosec // test injects a stale cookie to ensure non-admin prefixes are not cleared.
				Name:  auth.SessionCookieName,
				Value: "stale-session",
				Path:  "/admin",
			})
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusNotFound || !called {
				t.Fatalf("%s status=%d called=%v, want 404 passthrough", path, rec.Code, called)
			}
			if location := rec.Header().Get("Location"); location != "" {
				t.Fatalf("%s Location = %q, want empty", path, location)
			}
			if cookie := rec.Header().Get("Set-Cookie"); cookie != "" {
				t.Fatalf("%s Set-Cookie = %q, want no session clearing", path, cookie)
			}
		})
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
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: sess.ID}) //nolint:gosec // test injects an in-memory pre-auth session cookie.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 for non-admin preauth session", rec.Code)
	}
}

func TestRequireAdminSessionLogUsesTrustedClientIPAndRoutePathLabel(t *testing.T) {
	t.Parallel()

	sm := auth.NewSessionManager(context.Background(), time.Hour, false)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := TrustedClientIP([]string{"10.0.0.1"})(Correlation(RequireAdminSession(sm, logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))))

	rawPath := "/admin/C:%5CUsers%5CAdmin%5Csecret-token"
	req := httptest.NewRequest(http.MethodGet, rawPath, nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.91, 10.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	logLine := logs.String()
	for _, want := range []string{`"client_ip":"203.0.113.91"`, `"correlation_id":`, `"path":"/admin/..."`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("admin session log missing %s: %s", want, logLine)
		}
	}
	for _, leaked := range []string{`"remote_addr"`, "10.0.0.1:12345", "secret-token", "Users", "Admin"} {
		if strings.Contains(logLine, leaked) {
			t.Fatalf("admin session log leaked %q: %s", leaked, logLine)
		}
	}
}
