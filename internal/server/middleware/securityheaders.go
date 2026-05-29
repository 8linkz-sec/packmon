package middleware

import (
	"net"
	"net/http"
	"strings"
)

const contentSecurityPolicy = "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"

// SecurityHeaders returns a middleware that sets essential security
// response headers on every response. In production mode it also
// enforces HSTS and redirects plain-HTTP requests (detected via
// X-Forwarded-Proto) to HTTPS.
//
// The productionMode flag should be true when the server is running
// behind TLS (directly or via a reverse proxy). redirectHost should be set
// to the public host name when HTTPS redirects are enabled behind a proxy.
//
// X-Forwarded-Proto is an attacker-controllable header, so it is honored only
// when the direct peer is in trustedProxies (mirroring the X-Forwarded-For
// trust model). With no trusted proxies configured the proxy-driven HTTPS
// redirect is disabled.
func SecurityHeaders(productionMode bool, redirectHost string, trustedProxies []string) func(http.Handler) http.Handler {
	proxies := parseTrustedProxies(trustedProxies)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// In production, redirect HTTP to HTTPS when behind a trusted
			// reverse proxy that sets X-Forwarded-Proto. The header is trusted
			// only from a configured trusted-proxy peer.
			if productionMode && proxies.contains(stripPort(r.RemoteAddr)) {
				proto := r.Header.Get("X-Forwarded-Proto")
				if strings.EqualFold(proto, "http") {
					if host := redirectTargetHost(redirectHost, r.Host); host != "" {
						target := "https://" + host + r.URL.RequestURI()
						http.Redirect(w, r, target, http.StatusMovedPermanently)
						return
					}
				}
			}

			h := w.Header()

			// Prevent MIME-sniffing.
			h.Set("X-Content-Type-Options", "nosniff")

			// Prevent framing (clickjacking).
			h.Set("X-Frame-Options", "DENY")

			// Control referrer leakage.
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Disable legacy XSS filter.
			h.Set("X-XSS-Protection", "0")

			// Restrict browser features.
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

			// Serve the UI with local-only assets and deny external origins by default.
			h.Set("Content-Security-Policy", contentSecurityPolicy)

			// HSTS only in production (do not lock dev environments into HTTPS).
			if productionMode {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}

func redirectTargetHost(configuredHost, requestHost string) string {
	if host := sanitizeHost(configuredHost); host != "" {
		return host
	}

	host := sanitizeHost(requestHost)
	if host == "" {
		return ""
	}
	if isLoopbackHost(host) {
		return host
	}
	return ""
}

func sanitizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "/\\@") {
		return ""
	}
	return raw
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		end := strings.Index(host, "]")
		host = host[1:end]
	} else if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	}

	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
