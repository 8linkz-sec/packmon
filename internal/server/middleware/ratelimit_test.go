package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RateLimit(context.Background(), logger, RateLimitConfig{
		Rate:  10, // 10 tokens/sec
		Burst: 5,  // bucket capacity 5
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Send 5 requests (= burst size) -- all should pass.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}
	}
}

type fakeRateLimitSource struct {
	perMinute int
	burst     int
}

func (f *fakeRateLimitSource) RateLimit() (int, int) { return f.perMinute, f.burst }

func TestRateLimitWithSourceUsesDynamicLimit(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Static fallback is generous; the dynamic source tightens it to burst 2.
	source := &fakeRateLimitSource{perMinute: 1, burst: 2}
	handler := RateLimitWithSource(context.Background(), logger, RateLimitConfig{Rate: 1000, Burst: 1000}, source)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	send := func() int {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.9.9.9:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// The source caps the burst at 2, so the first two pass and the third is
	// limited -- proving the limiter reads the dynamic source, not the static
	// fallback (which would have allowed 1000).
	if code := send(); code != http.StatusOK {
		t.Fatalf("request 1: status = %d, want 200", code)
	}
	if code := send(); code != http.StatusOK {
		t.Fatalf("request 2: status = %d, want 200", code)
	}
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("request 3: status = %d, want 429", code)
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RateLimit(context.Background(), logger, RateLimitConfig{
		Rate:  0.001, // extremely slow refill: practically 0 tokens
		Burst: 3,     // only 3 tokens
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Send 3 requests to exhaust the burst.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.2:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}
	}

	// The 4th request should be rate limited.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("4th request: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestRateLimiter_DifferentIPsAreIndependent(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RateLimit(context.Background(), logger, RateLimitConfig{
		Rate:  0.001,
		Burst: 1,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust the burst for IP A.
	reqA := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqA.RemoteAddr = "10.0.0.10:12345"
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("IP A first request: status = %d, want %d", recA.Code, http.StatusOK)
	}

	// IP A should now be blocked.
	reqA2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqA2.RemoteAddr = "10.0.0.10:12345"
	recA2 := httptest.NewRecorder()
	handler.ServeHTTP(recA2, reqA2)
	if recA2.Code != http.StatusTooManyRequests {
		t.Errorf("IP A second request: status = %d, want %d", recA2.Code, http.StatusTooManyRequests)
	}

	// IP B should still be allowed (independent bucket).
	reqB := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqB.RemoteAddr = "10.0.0.20:54321"
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Errorf("IP B first request: status = %d, want %d", recB.Code, http.StatusOK)
	}
}

func TestRateLimiter_ResponseBody(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RateLimit(context.Background(), logger, RateLimitConfig{
		Rate:  0.001,
		Burst: 1,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust burst.
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "10.0.0.50:12345"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	// Blocked request should include a JSON error body.
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "10.0.0.50:12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	body := rec2.Body.String()
	if body == "" {
		t.Error("rate limited response body is empty, expected error message")
	}
}
