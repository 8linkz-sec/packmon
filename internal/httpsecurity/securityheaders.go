package httpsecurity

import (
	"net/http"
	"strings"

	"github.com/8linkz-sec/packmon/internal/netutil"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

const contentSecurityPolicy = "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'"

// SecurityHeaders returns a middleware that sets essential security response
// headers on every response. In production mode it also enforces HSTS and
// redirects plain-HTTP requests detected via trusted X-Forwarded-Proto.
//
// The productionMode flag should be true when the server is running behind TLS
// directly or via a reverse proxy. redirectHost should be set to the public
// host name when HTTPS redirects are enabled behind a proxy.
//
// X-Forwarded-Proto is an attacker-controllable header, so it is honored only
// when the direct peer is in trustedProxies, mirroring the X-Forwarded-For
// trust model. With no trusted proxies configured the proxy-driven HTTPS
// redirect is disabled.
func SecurityHeaders(productionMode bool, redirectHost string, trustedProxies []string) func(http.Handler) http.Handler {
	proxies, _ := netutil.ParseTrustedProxies(trustedProxies)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			setSecurityHeaders(w.Header(), productionMode)

			if productionMode && proxies.Contains(requestctx.StripPort(r.RemoteAddr)) {
				proto := r.Header.Get("X-Forwarded-Proto")
				if strings.EqualFold(proto, "http") {
					host := redirectTargetHost(redirectHost, r.Host)
					if host == "" {
						http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
						return
					}
					target := "https://" + host + r.URL.RequestURI()
					http.Redirect(w, r, target, http.StatusMovedPermanently) // #nosec G710 -- host is configured or loopback-only after sanitizeHost; untrusted external Host headers are not redirected.
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

func setSecurityHeaders(h http.Header, productionMode bool) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("X-XSS-Protection", "0")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	if productionMode {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
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
	if netutil.IsLoopbackHost(host) {
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
