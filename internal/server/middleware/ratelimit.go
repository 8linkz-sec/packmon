package middleware

import (
	"context"
	"log/slog"
	"math"
	"net/http"
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

// bucket is a single per-IP token bucket.
type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// rateLimiter is a simple in-memory token-bucket rate limiter keyed by
// client IP. It uses sync.Map for concurrent access without a global lock
// on the hot path.
//
// When source is non-nil the rate and burst are read from it on every request
// so runtime configuration changes take effect immediately; otherwise the
// static rate/burst captured at construction are used.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   int
	source  RateLimitSource
}

func newRateLimiter(ctx context.Context, rate float64, burst int) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
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
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rate, burst := rl.currentLimits()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &bucket{
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
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := now.Add(-10 * time.Minute)
	for ip, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
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

func rateLimitMiddleware(rl *rateLimiter, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// clientIP delegates to the shared ClientIP function which only trusts
// r.RemoteAddr to prevent X-Forwarded-For spoofing.
func clientIP(r *http.Request) string {
	return ClientIP(r)
}
