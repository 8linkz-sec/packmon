package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/8linkz-sec/packmon/internal/logsafe"
)

const (
	maxPanicTypeLogValueLength = 128
	maxPanicLogValueLength     = 512
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
					panicType, panicValue := panicLogFields(v)

					logger.Error("panic recovered",
						slog.String("panic_type", panicType),
						slog.String("panic", panicValue),
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

func panicLogFields(v any) (string, string) {
	panicType := logsafe.BoundedValue(fmt.Sprintf("%T", v), maxPanicTypeLogValueLength)
	switch value := v.(type) {
	case string:
		return panicType, logsafe.BoundedDiagnosticValue(value, maxPanicLogValueLength)
	case error:
		return panicType, logsafe.BoundedDiagnosticValue(value.Error(), maxPanicLogValueLength)
	default:
		return panicType, "(non-string panic value)"
	}
}
