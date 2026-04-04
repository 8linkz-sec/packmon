package middleware

import (
	"log/slog"
	"net/http"
	"strings"
)

// knownAgentPrefixes lists User-Agent prefixes that the server accepts.
// Unknown agents are rejected in production mode.
var knownAgentPrefixes = []string{
	"packmon-cli/",
	"packmon-n8n/",
}

// skipUserAgent lists path prefixes exempt from User-Agent validation.
var skipUserAgent = []string{
	"/healthz",
	"/readyz",
	"/version",
	"/metrics",
	"/admin",
	"/",
}

// UserAgent rejects requests with unknown User-Agent strings in
// production mode. In development mode all agents are accepted.
// Health, version, metrics, admin, and GUI endpoints are always exempt.
func UserAgent(logger *slog.Logger, devMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Development mode: allow all.
			if devMode {
				next.ServeHTTP(w, r)
				return
			}

			// Skip validation for exempt paths.
			if isUserAgentExempt(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			ua := r.UserAgent()
			if !isKnownAgent(ua) {
				logger.Warn("unknown user agent rejected",
					slog.String("user_agent", ua),
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr),
					slog.String("correlation_id", CorrelationIDFromContext(r.Context())),
				)
				http.Error(w, `{"error":"unknown user agent"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isKnownAgent(ua string) bool {
	for _, prefix := range knownAgentPrefixes {
		if strings.HasPrefix(ua, prefix) {
			return true
		}
	}
	return false
}

func isUserAgentExempt(path string) bool {
	// The GUI root "/" should be exempt, but API paths should not.
	// Check the more specific prefixes first.
	for _, prefix := range skipUserAgent {
		if prefix == "/" {
			// Only exact match for root.
			continue
		}
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	// Exempt non-API paths (GUI, static assets).
	if !strings.HasPrefix(path, "/api/") {
		return true
	}
	return false
}
