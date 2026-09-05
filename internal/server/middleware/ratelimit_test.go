package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RateLimitWithSource(context.Background(), logger, RateLimitConfig{
		Rate:  10, // 10 tokens/sec
		Burst: 5,  // bucket capacity 5
	}, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		}),
	)

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

func TestRateLimiterBypassesOperationalProbePaths(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RateLimitWithSource(context.Background(), logger, RateLimitConfig{
		Rate:  0.001,
		Burst: 1,
	}, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	send := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.0.0.44:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for _, path := range []string{"/healthz", "/readyz", "/version", "/healthz"} {
		if code := send(path); code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, code)
		}
	}
	if code := send("/api/v1/check"); code != http.StatusOK {
		t.Fatalf("first protected request status = %d, want 200", code)
	}
	if code := send("/api/v1/check"); code != http.StatusTooManyRequests {
		t.Fatalf("second protected request status = %d, want 429", code)
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RateLimitWithSource(context.Background(), logger, RateLimitConfig{
		Rate:  0.001, // extremely slow refill: practically 0 tokens
		Burst: 3,     // only 3 tokens
	}, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	handler := RateLimitWithSource(context.Background(), logger, RateLimitConfig{
		Rate:  0.001,
		Burst: 1,
	}, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestRateLimiterStoresClientBucketsInOnlyTheirShard(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := newRateLimiter(ctx, 1, 2)
	if got := len(rl.shards); got != rateLimiterShardCount {
		t.Fatalf("shard count = %d, want %d", got, rateLimiterShardCount)
	}

	ip := "203.0.113.45"
	shardIndex := rl.shardIndex(ip)
	if !rl.allow(ip) {
		t.Fatal("first request was not allowed")
	}

	for i := range rl.shards {
		rl.shards[i].mu.Lock()
		_, ok := rl.shards[i].buckets[ip]
		rl.shards[i].mu.Unlock()

		if i == shardIndex && !ok {
			t.Fatalf("client bucket missing from shard %d", shardIndex)
		}
		if i != shardIndex && ok {
			t.Fatalf("client bucket stored in unrelated shard %d", i)
		}
	}
}

func TestRateLimiter_ResponseBody(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := RateLimitWithSource(context.Background(), logger, RateLimitConfig{
		Rate:  0.001,
		Burst: 1,
	}, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	assertJSONErrorResponse(t, rec2, http.StatusTooManyRequests, "rate limit exceeded")
}

func TestRateLimiterCleanupStaleBuckets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := newRateLimiter(ctx, 1, 1)
	for ip, lastSeen := range map[string]time.Time{
		"10.0.0.1": now.Add(-11 * time.Minute),
		"10.0.0.2": now.Add(-10 * time.Minute),
		"10.0.0.3": now.Add(-9 * time.Minute),
	} {
		shardIndex := rl.shardIndex(ip)
		shard := &rl.shards[shardIndex]
		shard.mu.Lock()
		shard.buckets[ip] = &bucket{
			tokens:   1,
			lastSeen: lastSeen,
		}
		shard.mu.Unlock()
	}

	rl.cleanupStaleBuckets(now)

	if rateLimiterHasBucket(rl, "10.0.0.1") {
		t.Fatal("cleanup retained stale bucket")
	}
	for _, ip := range []string{"10.0.0.2", "10.0.0.3"} {
		if !rateLimiterHasBucket(rl, ip) {
			t.Fatalf("cleanup removed %s bucket", ip)
		}
	}
}

func TestRateLimiterCleanupScansAllShards(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl := newRateLimiter(ctx, 1, 1)
	staleA := "10.10.0.1"
	staleB := findIPInDifferentRateLimitShard(t, rl, staleA)

	for _, ip := range []string{staleA, staleB} {
		shard := &rl.shards[rl.shardIndex(ip)]
		shard.mu.Lock()
		shard.buckets[ip] = &bucket{tokens: 1, lastSeen: now.Add(-11 * time.Minute)}
		shard.mu.Unlock()
	}

	rl.cleanupStaleBuckets(now)

	for _, ip := range []string{staleA, staleB} {
		if rateLimiterHasBucket(rl, ip) {
			t.Fatalf("cleanup retained stale bucket for %s", ip)
		}
	}
}

func rateLimiterHasBucket(rl *rateLimiter, ip string) bool {
	shard := &rl.shards[rl.shardIndex(ip)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	_, ok := shard.buckets[ip]
	return ok
}

func findIPInDifferentRateLimitShard(t *testing.T, rl *rateLimiter, base string) string {
	t.Helper()

	baseShard := rl.shardIndex(base)
	for i := 2; i < 255; i++ {
		ip := "10.10.0." + strconv.Itoa(i)
		if rl.shardIndex(ip) != baseShard {
			return ip
		}
	}
	t.Fatal("could not find IP in different rate-limit shard")
	return ""
}

func TestRateLimitLogUsesTrustedClientIPAndRoutePathLabel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rawPath := "/api/v1/packages/npm/C:%5CUsers%5CAdmin%5Csecret-token/refresh"
	handler := TrustedClientIP([]string{"10.0.0.1"})(Correlation(RateLimitWithSource(ctx, logger, RateLimitConfig{
		Rate:  0.001,
		Burst: 1,
	}, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))))

	send := func() int {
		req := httptest.NewRequest(http.MethodGet, rawPath, nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.90, 10.0.0.1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send(); code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", code)
	}
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", code)
	}

	logLine := logs.String()
	for _, want := range []string{`"client_ip":"203.0.113.90"`, `"correlation_id":`, `"path":"/api/v1/packages/{ecosystem}/{name...}/refresh"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("rate-limit log missing %s: %s", want, logLine)
		}
	}
	for _, leaked := range []string{`"ip"`, "10.0.0.1:12345", "secret-token", "Users", "Admin"} {
		if strings.Contains(logLine, leaked) {
			t.Fatalf("rate-limit log leaked %q: %s", leaked, logLine)
		}
	}
}
