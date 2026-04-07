package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders_SetsAllHeaders(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(false, "")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	expected := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"X-XSS-Protection":        "0",
		"Permissions-Policy":      "camera=(), microphone=(), geolocation=()",
	}

	for header, want := range expected {
		got := resp.Header.Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestSecurityHeaders_HSTS_ProductionOnly(t *testing.T) {
	t.Parallel()

	t.Run("production mode sets HSTS", func(t *testing.T) {
		t.Parallel()
		handler := SecurityHeaders(true, "")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		handler := SecurityHeaders(false, "")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	handler := SecurityHeaders(true, "packmon.example.com")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should not reach here"))
	}))

	// httptest.NewRequest sets RequestURI from the target string.
	// Use a path-only target so r.RequestURI = "/dashboard".
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Host = "attacker.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want %d (MovedPermanently)", resp.StatusCode, http.StatusMovedPermanently)
	}

	location := resp.Header.Get("Location")
	want := "https://packmon.example.com/dashboard"
	if location != want {
		t.Errorf("Location = %q, want %q", location, want)
	}
}

func TestSecurityHeaders_NoRedirectWithoutXForwardedProto(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(true, "")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Without X-Forwarded-Proto, no redirect should happen.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (no redirect without X-Forwarded-Proto)", rec.Code, http.StatusOK)
	}
}

func TestSecurityHeaders_NoRedirectInDevelopment(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(false, "")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Even with X-Forwarded-Proto: http, development mode should NOT redirect.
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

	handler := SecurityHeaders(true, "")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestSecurityHeaders_SkipsRedirectForUnconfiguredExternalHost(t *testing.T) {
	t.Parallel()

	handler := SecurityHeaders(true, "")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Proto", "http")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (skip redirect without trusted public host)", rec.Code, http.StatusOK)
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Errorf("Location = %q, want empty", location)
	}
}
