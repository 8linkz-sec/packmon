package httpsecurity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_SetsAllHeaders(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(false, "", nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	expected := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"X-XSS-Protection":        "0",
		"Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
		"Content-Security-Policy": contentSecurityPolicy,
	}

	for header, want := range expected {
		got := resp.Header.Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("Content-Security-Policy permits inline script/style execution: %q", csp)
	}
	for _, want := range []string{
		"script-src 'self'",
		"style-src 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Fatalf("Content-Security-Policy missing %q: %q", want, csp)
		}
	}
}

func TestSecurityHeaders_HSTS_ProductionOnly(t *testing.T) {
	t.Parallel()

	t.Run("production mode sets HSTS", func(t *testing.T) {
		t.Parallel()
		handler := SecurityHeaders(true, "", nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		hsts := rec.Result().Header.Get("Strict-Transport-Security")
		if hsts == "" {
			t.Error("HSTS header not set in production mode")
		}
		wantHSTS := "max-age=63072000; includeSubDomains"
		if hsts != wantHSTS {
			t.Errorf("HSTS = %q, want %q", hsts, wantHSTS)
		}
	})

	t.Run("development mode omits HSTS", func(t *testing.T) {
		t.Parallel()
		handler := SecurityHeaders(false, "", nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		hsts := rec.Result().Header.Get("Strict-Transport-Security")
		if hsts != "" {
			t.Errorf("HSTS header should not be set in development mode, got %q", hsts)
		}
	})
}

func TestSecurityHeaders_RedirectsHTTP(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(true, "packmon.example.com", []string{"192.0.2.1"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should not reach here"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Host = "attacker.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want %d (MovedPermanently)", resp.StatusCode, http.StatusMovedPermanently)
	}

	location := resp.Header.Get("Location")
	want := "https://packmon.example.com/dashboard"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
	}

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"X-XSS-Protection":          "0",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
		"Content-Security-Policy":   contentSecurityPolicy,
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	}
	for header, want := range expectedHeaders {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("redirect %s = %q, want %q", header, got, want)
		}
	}
}

func TestSecurityHeaders_NoRedirectWithoutXForwardedProto(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(true, "", []string{"192.0.2.1"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (no redirect without X-Forwarded-Proto)", rec.Code, http.StatusOK)
	}
}

func TestSecurityHeaders_NoRedirectFromUntrustedProxy(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(true, "packmon.example.com", nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (untrusted X-Forwarded-Proto must not redirect)", rec.Code, http.StatusOK)
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Errorf("Location = %q, want empty", location)
	}
}

func TestSecurityHeaders_NoRedirectInDevelopment(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(false, "", []string{"192.0.2.1"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (no redirect in development mode)", rec.Code, http.StatusOK)
	}
}

func TestSecurityHeaders_HTTPSDoesNotRedirect(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(true, "", []string{"192.0.2.1"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (HTTPS should not redirect)", rec.Code, http.StatusOK)
	}
}

func TestSecurityHeaders_RejectsHTTPFromTrustedProxyWhenRedirectHostUnsafe(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := SecurityHeaders(true, "", []string{"192.0.2.1"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Proto", "http")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want %d (reject HTTP from trusted proxy without safe redirect host)", rec.Code, http.StatusMisdirectedRequest)
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Errorf("Location = %q, want empty", location)
	}
	if nextCalled {
		t.Fatal("next handler was called for trusted-proxy HTTP request without safe redirect host")
	}
}

func TestRedirectTargetHostAndLoopbackBranches(t *testing.T) {
	t.Parallel()

	if got := redirectTargetHost(" packmon.example.com ", "ignored.example"); got != "packmon.example.com" {
		t.Fatalf("configured redirect host = %q", got)
	}
	if got := redirectTargetHost("bad/host", "127.0.0.1:8080"); got != "127.0.0.1:8080" {
		t.Fatalf("loopback request host = %q", got)
	}
	if got := redirectTargetHost("", "[::1]:8080"); got != "[::1]:8080" {
		t.Fatalf("IPv6 loopback request host = %q", got)
	}
	if got := redirectTargetHost("", "localhost"); got != "localhost" {
		t.Fatalf("localhost request host = %q", got)
	}
	if got := redirectTargetHost("", "example.com"); got != "" {
		t.Fatalf("external request host = %q, want empty", got)
	}
	if got := sanitizeHost("bad@host"); got != "" {
		t.Fatalf("sanitizeHost(bad@host) = %q, want empty", got)
	}
}
