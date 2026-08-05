package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/8linkz-sec/packmon/internal/requestctx"
)

// staticRateLimitSource supplies a fixed limit, standing in for the admin-UI
// backed source used in production.
type staticRateLimitSource struct {
	perMinute int
	burst     int
}

func (s staticRateLimitSource) RateLimit() (int, int) { return s.perMinute, s.burst }

// requestWithAPIKey builds a request carrying an authenticated API-key identity,
// which is what the middleware keys its buckets on.
func requestWithAPIKey(id int) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/check", nil)
	req.RemoteAddr = "203.0.113.7:44321"
	if id > 0 {
		req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(
			req.Context(), requestctx.APIKeyIdentity{ID: id, Name: "client"}))
	}
	return req
}

// TestAuthenticatedAPIKeyRateLimitPassesUnauthenticatedRequestsThrough covers the
// division of labour between the two limiters. This one only knows about API-key
// identities; requests without one belong to the pre-auth IP limiter, and
// blocking them here would rate-limit anonymous traffic twice.
func TestAuthenticatedAPIKeyRateLimitPassesUnauthenticatedRequestsThrough(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A burst of 1 means a second keyed request would be rejected.
	middleware := AuthenticatedAPIKeyRateLimitWithSource(ctx, slog.New(slog.DiscardHandler),
		RateLimitConfig{Rate: 1, Burst: 1}, staticRateLimitSource{perMinute: 60, burst: 1})

	var served int
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))

	for range 5 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestWithAPIKey(0))
		if recorder.Code != http.StatusOK {
			t.Fatalf("unauthenticated request = %d, want it passed through", recorder.Code)
		}
	}
	if served != 5 {
		t.Fatalf("handler ran %d times, want every unauthenticated request forwarded", served)
	}
}

// TestAuthenticatedAPIKeyRateLimitThrottlesPerIdentity is the core behaviour:
// once a key exhausts its bucket the next request is refused with 429. Keying on
// the client IP instead would let one key behind many IPs bypass its own limit.
func TestAuthenticatedAPIKeyRateLimitThrottlesPerIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	middleware := AuthenticatedAPIKeyRateLimitWithSource(ctx, slog.New(slog.DiscardHandler),
		RateLimitConfig{Rate: 0.0001, Burst: 2}, staticRateLimitSource{perMinute: 1, burst: 2})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := range 2 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, requestWithAPIKey(7))
		if recorder.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want it inside the burst", i, recorder.Code)
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, requestWithAPIKey(7))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("the request past the burst = %d, want 429", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got == "" {
		t.Error("the 429 response carries no content type")
	}
}

// TestAuthenticatedAPIKeyRateLimitKeepsIdentitiesIndependent pins the bucket
// key. One key exhausting its budget must not throttle another client, which is
// the failure mode of keying on anything shared.
func TestAuthenticatedAPIKeyRateLimitKeepsIdentitiesIndependent(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	middleware := AuthenticatedAPIKeyRateLimitWithSource(ctx, slog.New(slog.DiscardHandler),
		RateLimitConfig{Rate: 0.0001, Burst: 1}, staticRateLimitSource{perMinute: 1, burst: 1})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust key 1.
	for range 2 {
		handler.ServeHTTP(httptest.NewRecorder(), requestWithAPIKey(1))
	}
	exhausted := httptest.NewRecorder()
	handler.ServeHTTP(exhausted, requestWithAPIKey(1))
	if exhausted.Code != http.StatusTooManyRequests {
		t.Fatalf("key 1 = %d, want it throttled", exhausted.Code)
	}

	// Key 2 has its own bucket and must still be served.
	other := httptest.NewRecorder()
	handler.ServeHTTP(other, requestWithAPIKey(2))
	if other.Code != http.StatusOK {
		t.Fatalf("key 2 = %d, want it unaffected by key 1", other.Code)
	}
}

// TestAuthenticatedAPIKeyRateLimitIgnoresAnUnusableIdentity covers the guard on
// the identity itself: a zero or negative key ID is not a usable bucket key, so
// such a request must fall through to the IP limiter rather than share one
// bucket with every other malformed identity.
func TestAuthenticatedAPIKeyRateLimitIgnoresAnUnusableIdentity(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	middleware := AuthenticatedAPIKeyRateLimitWithSource(ctx, slog.New(slog.DiscardHandler),
		RateLimitConfig{Rate: 0.0001, Burst: 1}, staticRateLimitSource{perMinute: 1, burst: 1})
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, id := range []int{0, -1} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/check", nil)
		req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(
			req.Context(), requestctx.APIKeyIdentity{ID: id}))

		for range 3 {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("identity %d = %d, want it passed through to the IP limiter", id, recorder.Code)
			}
		}
	}
}
