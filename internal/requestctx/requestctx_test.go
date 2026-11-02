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

func TestCorrelationContextIsolationRejectsTypedKeySpoofs(t *testing.T) {
	type siblingCorrelationKey struct{}
	type siblingAPIKeyIdentityKey struct{}
	type siblingClientIPKey struct{}

	parent := ContextWithCorrelationID(context.Background(), "parent-correlation")
	parent = ContextWithAPIKeyIdentity(parent, APIKeyIdentity{ID: 41, Name: "parent-key"})
	parent = ContextWithClientIP(parent, "198.51.100.41")
	sibling := context.WithValue(parent, siblingCorrelationKey{}, "spoofed-correlation")
	sibling = context.WithValue(sibling, siblingAPIKeyIdentityKey{}, APIKeyIdentity{ID: 99, Name: "spoofed-key"})
	sibling = context.WithValue(sibling, siblingClientIPKey{}, "203.0.113.99")

	assertContextValues := func(t *testing.T, ctx context.Context, wantCorrelation string, wantIdentity APIKeyIdentity, wantIP string) {
		t.Helper()
		if got := CorrelationIDFromContext(ctx); got != wantCorrelation {
			t.Fatalf("CorrelationIDFromContext() = %q, want %q", got, wantCorrelation)
		}
		if identity, ok := APIKeyIdentityFromContext(ctx); !ok || identity != wantIdentity {
			t.Fatalf("APIKeyIdentityFromContext() = %+v, %v; want %+v, true", identity, ok, wantIdentity)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test", nil)
		if err != nil {
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		req.RemoteAddr = "192.0.2.10:443"
		if got := ClientIP(req); got != wantIP {
			t.Fatalf("ClientIP() = %q, want %q", got, wantIP)
		}
	}

	assertContextValues(t, parent, "parent-correlation", APIKeyIdentity{ID: 41, Name: "parent-key"}, "198.51.100.41")
	assertContextValues(t, sibling, "parent-correlation", APIKeyIdentity{ID: 41, Name: "parent-key"}, "198.51.100.41")
	if got := sibling.Value(siblingCorrelationKey{}); got != "spoofed-correlation" {
		t.Fatalf("sibling lookalike correlation value = %#v", got)
	}
	if got := sibling.Value(siblingAPIKeyIdentityKey{}); got != (APIKeyIdentity{ID: 99, Name: "spoofed-key"}) {
		t.Fatalf("sibling lookalike API-key value = %#v", got)
	}
	if got := sibling.Value(siblingClientIPKey{}); got != "203.0.113.99" {
		t.Fatalf("sibling lookalike client-IP value = %#v", got)
	}

	child := ContextWithCorrelationID(sibling, "child-correlation")
	child = ContextWithAPIKeyIdentity(child, APIKeyIdentity{ID: 42, Name: "child-key"})
	child = ContextWithClientIP(child, "198.51.100.42")
	assertContextValues(t, child, "child-correlation", APIKeyIdentity{ID: 42, Name: "child-key"}, "198.51.100.42")
	assertContextValues(t, sibling, "parent-correlation", APIKeyIdentity{ID: 41, Name: "parent-key"}, "198.51.100.41")
	assertContextValues(t, parent, "parent-correlation", APIKeyIdentity{ID: 41, Name: "parent-key"}, "198.51.100.41")

	req, err := http.NewRequestWithContext(child, http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.RemoteAddr = "192.0.2.10:443"
	if got := ClientIP(req); got != "198.51.100.42" {
		t.Fatalf("child ClientIP() = %q, want child override", got)
	}
}
