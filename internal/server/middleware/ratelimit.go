package middleware

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/logsafe"
)

// RateLimitConfig defines the token bucket parameters.
type RateLimitConfig struct {
	// Rate is the number of tokens added per second.
	Rate float64
	// Burst is the maximum number of tokens (bucket capacity).
	Burst int
}

// RateLimitSource supplies the current rate limit at request time. It allows
// the limit to be reconfigured at runtime (e.g. from the admin UI) without
// restarting the server. perMinute is the allowed requests per minute and
// burst is the bucket capacity.
type RateLimitSource interface {
	RateLimit() (perMinute, burst int)
}

// bucket is a single token bucket keyed by client IP or authenticated API-key
// identity.
type bucket struct {
	tokens   float64
	lastSeen time.Time
}

const rateLimiterShardCount = 64

type rateLimiterShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// rateLimiter is a simple in-memory token-bucket rate limiter. Bucket state is
// sharded by key hash so unrelated clients do not contend on one process-wide
// mutex on the hot path.
//
// When source is non-nil the rate and burst are read from it on every request
// so runtime configuration changes take effect immediately; otherwise the
// static rate/burst captured at construction are used.
type rateLimiter struct {
	shards [rateLimiterShardCount]rateLimiterShard
	rate   float64
	burst  int
	source RateLimitSource
}

func newRateLimiter(ctx context.Context, rate float64, burst int) *rateLimiter {
	rl := &rateLimiter{
		rate:  rate,
		burst: burst,
	}
	for i := range rl.shards {
		rl.shards[i].buckets = make(map[string]*bucket)
	}
	// Background goroutine to evict stale entries (older than 10 minutes).
	// It exits when ctx is cancelled.
	go rl.cleanup(ctx)
	return rl
}

// currentLimits returns the rate (tokens/second) and burst to apply right now,
// reading the dynamic source when one is configured.
func (rl *rateLimiter) currentLimits() (float64, int) {
	if rl.source != nil {
		perMinute, burst := rl.source.RateLimit()
		if perMinute > 0 && burst > 0 {
			return float64(perMinute) / 60, burst
		}
	}
	return rl.rate, rl.burst
}

func (rl *rateLimiter) allow(ip string) bool {
	rate, burst := rl.currentLimits()

	now := time.Now()
	shard := &rl.shards[rl.shardIndex(ip)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	b, ok := shard.buckets[ip]
	if !ok {
		shard.buckets[ip] = &bucket{
			tokens:   float64(burst) - 1,
			lastSeen: now,
		}
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rate
	b.tokens = math.Min(b.tokens, float64(burst))
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

func (rl *rateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.cleanupStaleBuckets(time.Now())
		}
	}
}

func (rl *rateLimiter) cleanupStaleBuckets(now time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	for i := range rl.shards {
		shard := &rl.shards[i]
		shard.mu.Lock()
		for ip, b := range shard.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(shard.buckets, ip)
			}
		}
		shard.mu.Unlock()
	}
}

func (rl *rateLimiter) shardIndex(ip string) int {
	const (
		fnvOffset64 = 14695981039346656037
		fnvPrime64  = 1099511628211
	)

	hash := uint64(fnvOffset64)
	for i := 0; i < len(ip); i++ {
		hash ^= uint64(ip[i])
		hash *= fnvPrime64
	}
	return int(hash % rateLimiterShardCount)
}

// RateLimitWithSource applies a per-IP token-bucket rate limiter. It reads the
// current limit from source on every request, so admin changes take effect
// without a restart. cfg provides the initial fallback values used until/unless
// the source returns valid limits.
func RateLimitWithSource(ctx context.Context, logger *slog.Logger, cfg RateLimitConfig, source RateLimitSource) func(http.Handler) http.Handler {
	rl := newRateLimiter(ctx, cfg.Rate, cfg.Burst)
	rl.source = source
	return rateLimitMiddleware(rl, logger)
}

// AuthenticatedAPIKeyRateLimitWithSource applies the same token-bucket policy
// to the authenticated API-key identity set by Auth. Requests without an
// authenticated identity pass through so the pre-auth IP limiter remains
// responsible for unauthenticated or invalid requests.
func AuthenticatedAPIKeyRateLimitWithSource(ctx context.Context, logger *slog.Logger, cfg RateLimitConfig, source RateLimitSource) func(http.Handler) http.Handler {
	rl := newRateLimiter(ctx, cfg.Rate, cfg.Burst)
	rl.source = source
	return authenticatedAPIKeyRateLimitMiddleware(rl, logger)
}

func rateLimitMiddleware(rl *rateLimiter, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rateLimitBypassPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			ip := clientIP(r)
			if !rl.allow(ip) {
				logger.Debug("rate limit exceeded",
					slog.String("client_ip", ip),
					slog.String("path", logsafe.RequestPathLabel(r.URL.Path)),
					slog.String("correlation_id", CorrelationIDFromContext(r.Context())),
				)
				writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func authenticatedAPIKeyRateLimitMiddleware(rl *rateLimiter, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := APIKeyIdentityFromContext(r.Context())
			if !ok || identity.ID <= 0 {
				next.ServeHTTP(w, r)
				return
			}

			key := "api-key:" + strconv.Itoa(identity.ID)
			if !rl.allow(key) {
				logger.Debug("authenticated api key rate limit exceeded",
					slog.Int("api_key_id", identity.ID),
					slog.String("client_ip", ClientIP(r)),
					slog.String("path", logsafe.RequestPathLabel(r.URL.Path)),
					slog.String("correlation_id", CorrelationIDFromContext(r.Context())),
				)
				writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func rateLimitBypassPath(path string) bool {
	switch path {
	case "/healthz", "/readyz", "/version":
		return true
	default:
		return false
	}
}

// clientIP delegates to the shared ClientIP resolver. When TrustedClientIP ran
// earlier in the middleware chain this is the context-populated trusted client
// IP; otherwise it falls back to the direct peer from RemoteAddr. Forwarded IP
// headers are honored only for requests received from configured trusted
// proxies.
func clientIP(r *http.Request) string {
	return ClientIP(r)
}
