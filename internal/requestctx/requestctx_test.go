package requestctx

import (
	"context"
	"net/http"
	"testing"
)

func TestContextValues(t *testing.T) {
	ctx := context.Background()
	if got := CorrelationIDFromContext(ctx); got != "" {
		t.Fatalf("empty correlation ID = %q", got)
	}
	if identity, ok := APIKeyIdentityFromContext(ctx); ok || identity != (APIKeyIdentity{}) {
		t.Fatalf("empty API key identity = %+v, %v", identity, ok)
	}

	ctx = ContextWithCorrelationID(ctx, "corr-123")
	ctx = ContextWithAPIKeyIdentity(ctx, APIKeyIdentity{ID: 42, Name: "ci"})
	if got := CorrelationIDFromContext(ctx); got != "corr-123" {
		t.Fatalf("CorrelationIDFromContext = %q", got)
	}
	if identity, ok := APIKeyIdentityFromContext(ctx); !ok || identity.ID != 42 || identity.Name != "ci" {
		t.Fatalf("APIKeyIdentityFromContext = %+v, %v", identity, ok)
	}
}

func TestClientIPAndStripPort(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.RemoteAddr = "192.0.2.10:443"
	if got := ClientIP(req); got != "192.0.2.10" {
		t.Fatalf("ClientIP RemoteAddr fallback = %q", got)
	}

	req = req.WithContext(ContextWithClientIP(req.Context(), "198.51.100.7"))
	if got := ClientIP(req); got != "198.51.100.7" {
		t.Fatalf("ClientIP context value = %q", got)
	}

	tests := map[string]string{
		"":                   "",
		"192.0.2.10:8443":    "192.0.2.10",
		"192.0.2.10":         "192.0.2.10",
		"[2001:db8::1]:8443": "2001:db8::1",
		"[2001:db8::1":       "[2001:db8::1",
		"2001:db8::1":        "2001:db8::1",
		"example.test:8443":  "example.test",
	}
	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			if got := StripPort(in); got != want {
				t.Fatalf("StripPort(%q) = %q, want %q", in, got, want)
			}
		})
	}
}
