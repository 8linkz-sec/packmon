package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeaders returns a middleware that sets essential security
// response headers on every response. In production mode it also
// enforces HSTS and redirects plain-HTTP requests (detected via
// X-Forwarded-Proto) to HTTPS.
//
// The productionMode flag should be true when the server is running
// behind TLS (directly or via a reverse proxy).
func SecurityHeaders(productionMode bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// In production, redirect HTTP to HTTPS when behind a
			// reverse proxy that sets X-Forwarded-Proto.
			if productionMode {
				proto := r.Header.Get("X-Forwarded-Proto")
				if strings.EqualFold(proto, "http") {
					target := "https://" + r.Host + r.RequestURI
					http.Redirect(w, r, target, http.StatusMovedPermanently)
					return
				}
			}

			h := w.Header()

			// Prevent MIME-sniffing.
			h.Set("X-Content-Type-Options", "nosniff")

			// Prevent framing (clickjacking).
			h.Set("X-Frame-Options", "DENY")

			// Control referrer leakage.
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Disable legacy XSS filter (modern best practice: rely on CSP).
			h.Set("X-XSS-Protection", "0")

			// Restrict browser features.
			h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

			// HSTS only in production (do not lock dev environments into HTTPS).
			if productionMode {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}
