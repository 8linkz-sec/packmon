package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

// skipAuth lists path prefixes that never require an API key inside the API
// namespace. Public web pages and admin routes are handled outside the API and
// are therefore never subject to Bearer-token auth.
var skipAuth = []string{
	"/healthz",
	"/readyz",
	"/version",
	"/metrics",
	"/admin/",
	"/admin",
	"/.well-known/",
}

// requireAuthEvenInDev lists path prefixes that are data-mutating and must not
// be exposed unauthenticated to a network. In development mode they remain
// reachable without an API key, but only from a loopback peer (local
// integration tests); a non-loopback caller still needs a valid key.
var requireAuthEvenInDev = []string{
	"/api/v1/feeds/",
}

// Auth validates the Bearer token in the Authorization header against hashed
// API keys stored in the database. Only /api/v1/* endpoints are protected.
// Public web pages and admin routes remain reachable without an API key.
//
// In development mode, auth is skipped entirely so that local testing
// does not require key provisioning.
func Auth(logger *slog.Logger, store db.Store, devMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
				next.ServeHTTP(w, r)
				return
			}

			// Skip auth for exempt paths.
			for _, prefix := range skipAuth {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Development mode is intentionally unauthenticated so local
			// integration tests can run without provisioning API keys. Data-
			// mutating write endpoints (feed import) are an exception: in dev
			// mode they are allowed without a key only from a loopback peer,
			// so a dev-mode server accidentally exposed on a network does not
			// offer unauthenticated writes.
			if devMode {
				if !requiresAuthInDev(r.URL.Path) || isLoopbackHost(r.RemoteAddr) {
					next.ServeHTTP(w, r)
					return
				}
				logger.Warn("dev-mode write endpoint requires auth from non-loopback peer",
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr),
				)
			}

			token := extractBearerToken(r)
			if token == "" {
				logger.Warn("missing api key",
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr),
				)
				http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
				return
			}

			keyHash := hashToken(token)
			apiKey, err := store.FindAPIKeyByHash(r.Context(), keyHash)
			if err != nil {
				logger.Error("api key lookup failed",
					slog.String("error", err.Error()),
					slog.String("correlation_id", CorrelationIDFromContext(r.Context())),
				)
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				return
			}
			if apiKey == nil {
				logger.Warn("invalid api key",
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr),
				)
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
				return
			}
			if apiKey.IsExpired(time.Now().UTC()) {
				logger.Warn("expired api key",
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr),
				)
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
				return
			}

			// Fire-and-forget: update last_used_at using a detached context
			// so the write completes even after the request handler returns.
			go func() {
				detached := context.WithoutCancel(r.Context())
				_ = store.TouchAPIKeyLastUsed(detached, apiKey.ID)
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// requiresAuthInDev reports whether the given path is a sensitive write
// endpoint that must not be served unauthenticated to a non-loopback peer
// even in development mode.
func requiresAuthInDev(path string) bool {
	for _, prefix := range requireAuthEvenInDev {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// extractBearerToken pulls the token from "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// hashToken returns the hex-encoded SHA-256 hash of a raw API key.
// Keys are stored hashed in the database so that a DB leak does not
// expose usable credentials.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
