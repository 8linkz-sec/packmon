// Package middleware provides HTTP middleware for the Packmon server.
package middleware

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"regexp"
)

// correlationKey is the unexported context key for the correlation ID.
type correlationKey struct{}

const (
	// HeaderCorrelationID is the canonical header name for correlation IDs.
	HeaderCorrelationID = "X-Correlation-ID"
)

// uuidPattern validates that a value looks like a UUID v4 (lowercase hex + dashes).
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Correlation reads X-Correlation-ID from the incoming request. If the
// header is missing or does not look like a valid UUID, a new one is
// generated. The ID is stored in the request context and set on the
// response.
func Correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderCorrelationID)
		if !uuidPattern.MatchString(id) {
			id = newUUID()
		}

		w.Header().Set(HeaderCorrelationID, id)
		ctx := context.WithValue(r.Context(), correlationKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CorrelationIDFromContext extracts the correlation ID from a context.
// Returns an empty string if none is set.
func CorrelationIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(correlationKey{}).(string); ok {
		return v
	}
	return ""
}

// newUUID generates a version-4 UUID using crypto/rand.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16],
	)
}
