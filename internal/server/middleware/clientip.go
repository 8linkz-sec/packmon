// Package middleware provides HTTP middleware for the Packmon server.
//
// ClientIP extracts the real client IP address from an HTTP request.
// By default it only trusts r.RemoteAddr. X-Forwarded-For is ignored
// unless a trusted proxy configuration is added in the future, because
// any anonymous client can set that header to spoof their IP.
package middleware

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPContextKey struct{}

// ClientIP returns the client IP address from the request. It strips
// the port from RemoteAddr and returns only the host portion.
//
// X-Forwarded-For is intentionally NOT trusted. An attacker can set
// this header to bypass IP-based rate limiting. When a reverse proxy
// is deployed, a trusted-proxy aware implementation should be added.
func ClientIP(r *http.Request) string {
	if value, ok := r.Context().Value(clientIPContextKey{}).(string); ok && value != "" {
		return value
	}
	return stripPort(r.RemoteAddr)
}

// TrustedClientIP resolves the client IP once per request using a trusted
// proxy list and stores it in request context for downstream middleware and
// handlers.
func TrustedClientIP(trustedProxies []string) func(http.Handler) http.Handler {
	proxies := parseTrustedProxies(trustedProxies)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIPWithTrustedProxyRules(r, proxies)
			ctx := context.WithValue(r.Context(), clientIPContextKey{}, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClientIPWithTrustedProxies returns the forwarded client IP only when the
// direct peer is in the configured trusted proxy list.
func ClientIPWithTrustedProxies(r *http.Request, trustedProxies []string) string {
	return clientIPWithTrustedProxyRules(r, parseTrustedProxies(trustedProxies))
}

type trustedProxySet struct {
	prefixes []netip.Prefix
}

func parseTrustedProxies(values []string) trustedProxySet {
	set := trustedProxySet{}
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			set.prefixes = append(set.prefixes, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(raw); err == nil {
			set.prefixes = append(set.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return set
}

func clientIPWithTrustedProxyRules(r *http.Request, proxies trustedProxySet) string {
	remote := stripPort(r.RemoteAddr)
	if remote == "" || !proxies.contains(remote) {
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

func forwardedClientIP(raw string, proxies trustedProxySet) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}

	parts := strings.Split(raw, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if !validIP(candidate) {
			continue
		}
		if proxies.contains(candidate) {
			continue
		}
		return candidate
	}
	return ""
}

func (p trustedProxySet) contains(raw string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func validIP(raw string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(raw))
	return err == nil
}

// stripPort removes the :port suffix from an address string.
// It handles both IPv4 ("1.2.3.4:8080") and bracketed IPv6
// ("[::1]:8080") forms.
func stripPort(addr string) string {
	if addr == "" {
		return ""
	}

	// IPv6 with brackets: "[::1]:8080" -> "::1"
	if addr[0] == '[' {
		for i := 1; i < len(addr); i++ {
			if addr[i] == ']' {
				return addr[1:i]
			}
		}
		return addr
	}

	// Find the last colon. For IPv4 "1.2.3.4:8080" this is the port
	// separator. For bare IPv6 "::1" there is no port; in that case
	// we return as-is because there will be more than one colon.
	lastColon := -1
	colons := 0
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			if lastColon == -1 {
				lastColon = i
			}
			colons++
		}
	}

	// Multiple colons and no brackets means bare IPv6 without port.
	if colons > 1 {
		return addr
	}

	if lastColon >= 0 {
		return addr[:lastColon]
	}

	return addr
}
