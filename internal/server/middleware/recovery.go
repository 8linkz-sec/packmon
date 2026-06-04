package middleware

import (
	"log/slog"
	"net/http"
)

// Recovery catches panics in downstream handlers and returns a 500 Internal
// Server Error. Panic logs intentionally omit stack traces because they can
// expose local paths and source layout in persistent production logs.
func Recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					correlationID := CorrelationIDFromContext(r.Context())

					logger.Error("panic recovered",
						slog.Any("panic", v),
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.String("client_ip", ClientIP(r)),
						slog.String("correlation_id", correlationID),
					)

					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
