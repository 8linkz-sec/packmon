// Package middleware provides HTTP middleware for the Packmon server.
//
// ClientIP extracts the real client IP address from an HTTP request.
// By default it only trusts r.RemoteAddr. X-Forwarded-For is ignored
// unless a trusted proxy configuration is added in the future, because
// any anonymous client can set that header to spoof their IP.
package middleware

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/8linkz-sec/packmon/internal/netutil"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

// ClientIP returns the client IP address from the request. It strips
// the port from RemoteAddr and returns only the host portion.
//
// X-Forwarded-For is intentionally NOT trusted. An attacker can set
// this header to bypass IP-based rate limiting. When a reverse proxy
// is deployed, a trusted-proxy aware implementation should be added.
var ClientIP = requestctx.ClientIP

// TrustedClientIP resolves the client IP once per request using a trusted
// proxy list and stores it in request context for downstream middleware and
// handlers.
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

// stripPort removes the :port suffix from an address string.
// It handles both IPv4 ("1.2.3.4:8080") and bracketed IPv6
// ("[::1]:8080") forms.
var stripPort = requestctx.StripPort
