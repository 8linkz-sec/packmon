// Package middleware provides HTTP middleware for the Packmon server.
//
// ClientIP extracts the real client IP address from an HTTP request.
// By default it only trusts r.RemoteAddr. X-Forwarded-For is ignored
// unless a trusted proxy configuration is added in the future, because
// any anonymous client can set that header to spoof their IP.
package middleware

import "net/http"

// ClientIP returns the client IP address from the request. It strips
// the port from RemoteAddr and returns only the host portion.
//
// X-Forwarded-For is intentionally NOT trusted. An attacker can set
// this header to bypass IP-based rate limiting. When a reverse proxy
// is deployed, a trusted-proxy aware implementation should be added.
func ClientIP(r *http.Request) string {
	return stripPort(r.RemoteAddr)
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
