package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recovery catches panics in downstream handlers, logs the stack trace,
// and returns a 500 Internal Server Error. This prevents the entire
// server from crashing on a single bad request.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					stack := string(debug.Stack())
					correlationID := CorrelationIDFromContext(r.Context())

					logger.Error("panic recovered",
						slog.Any("panic", v),
						slog.String("stack", stack),
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.String("correlation_id", correlationID),
					)

					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
