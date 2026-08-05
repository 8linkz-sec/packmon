// Package requestctx stores request-scoped metadata shared by middleware and
// handlers without coupling handlers to the server composition layer.
package requestctx

import (
	"context"
	"net/http"

	"github.com/8linkz-sec/packmon/internal/correlation"
)

const HeaderCorrelationID = correlation.Header

type (
	correlationKey     struct{}
	apiKeyIdentityKey  struct{}
	clientIPContextKey struct{}
)

// APIKeyIdentity is the non-sensitive authenticated API-key metadata exposed
// to handlers for audit attribution.
type APIKeyIdentity struct {
	ID   int
	Name string
}

// ContextWithCorrelationID stores a correlation ID in ctx.
func ContextWithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationIDFromContext extracts the correlation ID from a context.
func CorrelationIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(correlationKey{}).(string); ok {
		return v
	}
	return ""
}

// ContextWithAPIKeyIdentity stores non-sensitive API-key metadata in ctx.
func ContextWithAPIKeyIdentity(ctx context.Context, identity APIKeyIdentity) context.Context {
	return context.WithValue(ctx, apiKeyIdentityKey{}, identity)
}

// APIKeyIdentityFromContext returns authenticated API-key metadata when the
// request passed through API-key authentication.
func APIKeyIdentityFromContext(ctx context.Context) (APIKeyIdentity, bool) {
	identity, ok := ctx.Value(apiKeyIdentityKey{}).(APIKeyIdentity)
	return identity, ok
}

// ContextWithClientIP stores the resolved client IP in ctx.
func ContextWithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPContextKey{}, ip)
}

// ClientIP returns the trusted client IP from context, falling back to
// RemoteAddr with the port stripped.
func ClientIP(r *http.Request) string {
	if value, ok := r.Context().Value(clientIPContextKey{}).(string); ok && value != "" {
		return value
	}
	return StripPort(r.RemoteAddr)
}

// StripPort removes the :port suffix from an address string. It handles IPv4,
// bracketed IPv6 with ports, and bare IPv6 addresses.
func StripPort(addr string) string {
	if addr == "" {
		return ""
	}
	if addr[0] == '[' {
		for i := 1; i < len(addr); i++ {
			if addr[i] == ']' {
				return addr[1:i]
			}
		}
		return addr
	}

	lastColon := -1
	colons := 0
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			if lastColon == -1 {
				lastColon = i
			}
			colons++
		}
	}
	if colons > 1 {
		return addr
	}
	if lastColon >= 0 {
		return addr[:lastColon]
	}
	return addr
}
