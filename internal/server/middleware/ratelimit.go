package middleware

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"time"
)

// RateLimitConfig defines the token bucket parameters.
type RateLimitConfig struct {
	// Rate is the number of tokens added per second.
	Rate float64
	// Burst is the maximum number of tokens (bucket capacity).
	Burst int
}

// bucket is a single per-IP token bucket.
type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// rateLimiter is a simple in-memory token-bucket rate limiter keyed by
// client IP. It uses sync.Map for concurrent access without a global lock
// on the hot path.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   int
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

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &bucket{
			tokens:   float64(rl.burst) - 1,
			lastSeen: now,
		}
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rl.rate
	b.tokens = math.Min(b.tokens, float64(rl.burst))
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
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, b := range rl.buckets {
				if b.lastSeen.Before(cutoff) {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// RateLimit applies a per-IP token-bucket rate limiter. When a client
// exceeds the allowed rate, subsequent requests receive 429 Too Many
// Requests until tokens are replenished. The context controls the
// lifetime of the background cleanup goroutine.
func RateLimit(ctx context.Context, logger *slog.Logger, cfg RateLimitConfig) func(http.Handler) http.Handler {
	rl := newRateLimiter(ctx, cfg.Rate, cfg.Burst)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !rl.allow(ip) {
				logger.Warn("rate limit exceeded",
					slog.String("ip", ip),
					slog.String("path", r.URL.Path),
					slog.String("correlation_id", CorrelationIDFromContext(r.Context())),
				)
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
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
