package middleware

import (
	"log/slog"
	"net/http"

	"github.com/8linkz-sec/packmon/internal/logsafe"
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
						slog.String("path", logsafe.RequestPathLabel(r.URL.Path)),
						slog.String("correlation_id", correlationID),
					)

					writeJSONError(w, http.StatusInternalServerError, "internal server error")
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
