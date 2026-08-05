// Package middleware provides HTTP middleware for the Packmon server.
package middleware

import (
	"log/slog"
	"net/http"

	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

const (
	// HeaderCorrelationID is the canonical header name for correlation IDs.
	HeaderCorrelationID = requestctx.HeaderCorrelationID
)

var newCorrelationID = correlation.NewID

// Correlation reads X-Correlation-ID from the incoming request. If the
// header is missing or does not look like a valid UUID, a new one is
// generated. The ID is stored in the request context and set on the
// response.
func Correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderCorrelationID)
		if !correlation.Valid(id) {
			generated, err := newCorrelationID()
			if err != nil {
				slog.Warn("failed to generate correlation id", "error", err)
				generated = correlation.FallbackID()
			}
			id = generated
		}

		w.Header().Set(HeaderCorrelationID, id)
		ctx := requestctx.ContextWithCorrelationID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CorrelationIDFromContext extracts the correlation ID from a context.
// Returns an empty string if none is set.
var CorrelationIDFromContext = requestctx.CorrelationIDFromContext
