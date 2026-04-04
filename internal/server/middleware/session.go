package middleware

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/8linkz/packmon/internal/auth"
)

// RequireAdminSession returns a middleware that protects /admin/* routes.
// Requests without a valid, authenticated admin session are redirected
// to /admin/login. The login page itself (/admin/login) is exempt so
// that unauthenticated users can reach it.
func RequireAdminSession(sm *auth.SessionManager, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only apply to /admin/* paths.
			if !strings.HasPrefix(r.URL.Path, "/admin") {
				next.ServeHTTP(w, r)
				return
			}

			// Allow the login page through without a session so the
			// user can authenticate.
			if r.URL.Path == "/admin/login" {
				next.ServeHTTP(w, r)
				return
			}

			sess := sm.Get(r)
			if sess == nil || !sess.Admin {
				logger.Debug("admin session required but not found, redirecting to login",
					slog.String("path", r.URL.Path),
					slog.String("remote_addr", r.RemoteAddr),
				)
				http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
