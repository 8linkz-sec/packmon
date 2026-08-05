package middleware

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/8linkz-sec/packmon/internal/netutil"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

// ClientIP returns the context-resolved trusted client IP when TrustedClientIP
// has run, otherwise it strips the port from RemoteAddr. X-Forwarded-For and
// X-Real-IP are ignored unless the direct peer is in PACKMON_TRUSTED_PROXIES.
var ClientIP = requestctx.ClientIP

// TrustedClientIP resolves the client IP once per request using a trusted
// proxy list and stores it in request context for downstream middleware and
// handlers. It honors X-Forwarded-For or X-Real-IP only when the direct peer is
// configured as trusted, and X-Forwarded-For selection uses the
// rightmost-untrusted address.
func TrustedClientIP(trustedProxies []string) func(http.Handler) http.Handler {
	proxies, _ := netutil.ParseTrustedProxies(trustedProxies)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIPWithTrustedProxyRules(r, proxies)
			ctx := requestctx.ContextWithClientIP(r.Context(), ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func clientIPWithTrustedProxyRules(r *http.Request, proxies netutil.TrustedProxySet) string {
	remote := requestctx.StripPort(r.RemoteAddr)
	if remote == "" || !proxies.Contains(remote) {
		return remote
	}

	if forwarded := forwardedClientIP(r.Header.Get("X-Forwarded-For"), proxies); forwarded != "" {
		return forwarded
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); validIP(realIP) {
		return realIP
	}
	return remote
}

// forwardedClientIP returns the rightmost syntactically valid X-Forwarded-For
// address that is not in the configured trusted proxy set.
func forwardedClientIP(raw string, proxies netutil.TrustedProxySet) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}

	parts := strings.Split(raw, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if !validIP(candidate) {
			continue
		}
		if proxies.Contains(candidate) {
			continue
		}
		return candidate
	}
	return ""
}

func validIP(raw string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(raw))
	return err == nil
}
