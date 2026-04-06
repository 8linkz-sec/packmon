package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// statusCapture wraps http.ResponseWriter to capture the status code.
type statusCapture struct {
	http.ResponseWriter
	code int
}

func (s *statusCapture) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// Logging logs every request with method, path, status, duration, and
// correlation ID. Uses slog at INFO level for 2xx/3xx and WARN for
// 4xx/5xx.
func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sc := &statusCapture{ResponseWriter: w, code: http.StatusOK}

			next.ServeHTTP(sc, r)

			duration := time.Since(start)
			correlationID := CorrelationIDFromContext(r.Context())

			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sc.code),
				slog.Int64("duration_ms", duration.Milliseconds()),
				slog.String("correlation_id", correlationID),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
			}

			level := slog.LevelInfo
			if sc.code >= 500 {
				level = slog.LevelError
			} else if sc.code >= 400 {
				level = slog.LevelWarn
			} else if strings.HasPrefix(r.URL.Path, "/static/") {
				level = slog.LevelDebug
			}

			logger.LogAttrs(r.Context(), level, "request completed", attrs...)
		})
	}
}
