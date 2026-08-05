package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP_UsesRemoteAddr(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:8080"
	// Set X-Forwarded-For to a different IP to verify it is NOT used.
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	ip := ClientIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("ClientIP() = %q, want %q", ip, "192.168.1.100")
	}
}

func TestClientIP_StripsPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "IPv4 with port",
			remoteAddr: "10.0.0.1:12345",
			want:       "10.0.0.1",
		},
		{
			name:       "IPv4 without port",
			remoteAddr: "10.0.0.1",
			want:       "10.0.0.1",
		},
		{
			name:       "IPv6 with brackets and port",
			remoteAddr: "[::1]:8080",
			want:       "::1",
		},
		{
			name:       "IPv6 bare (no port)",
			remoteAddr: "::1",
			want:       "::1",
		},
		{
			name:       "empty address",
			remoteAddr: "",
			want:       "",
		},
		{
			name:       "full IPv6 with brackets and port",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			got := ClientIP(req)
			if got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIP_IgnoresXForwardedFor(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:9999"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	ip := ClientIP(req)
	if ip != "172.16.0.1" {
		t.Errorf("ClientIP() = %q, want %q (should ignore X-Forwarded-For)", ip, "172.16.0.1")
	}
}

func TestClientIP_IgnoresXRealIP(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.16.0.1:9999"
	req.Header.Set("X-Real-IP", "1.2.3.4")

	ip := ClientIP(req)
	if ip != "172.16.0.1" {
		t.Errorf("ClientIP() = %q, want %q (should ignore X-Real-IP)", ip, "172.16.0.1")
	}
}

func resolvedTrustedClientIP(req *http.Request, trustedProxies []string) string {
	var got string
	handler := TrustedClientIP(trustedProxies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestClientIPWithTrustedProxiesUsesForwardedChain(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.10:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.20")

	ip := resolvedTrustedClientIP(req, []string{"10.0.0.0/8"})
	if ip != "203.0.113.9" {
		t.Fatalf("trusted ClientIP() = %q, want forwarded client", ip)
	}
}

func TestClientIPWithTrustedProxiesIgnoresUntrustedForwardedHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.1:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Real-IP", "203.0.113.10")

	ip := resolvedTrustedClientIP(req, []string{"10.0.0.0/8"})
	if ip != "198.51.100.1" {
		t.Fatalf("trusted ClientIP() = %q, want remote address", ip)
	}
}

func TestClientIPWithTrustedProxiesHandlesMalformedForwardedFor(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.10:443"
	// Garbage and empty entries must be skipped; the first valid untrusted IP
	// (walking right-to-left) is the real client.
	req.Header.Set("X-Forwarded-For", "not-an-ip, , 203.0.113.9, 10.0.0.20")

	ip := resolvedTrustedClientIP(req, []string{"10.0.0.0/8"})
	if ip != "203.0.113.9" {
		t.Fatalf("trusted ClientIP() = %q, want 203.0.113.9 from a malformed chain", ip)
	}
}

func TestClientIPWithTrustedProxiesAllHopsTrustedFallsBackToRemote(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.10:443"
	// Every forwarded hop is itself a trusted proxy: there is no untrusted
	// client IP to extract, so the resolver falls back to the direct peer.
	req.Header.Set("X-Forwarded-For", "10.0.0.20, 10.0.0.21")

	ip := resolvedTrustedClientIP(req, []string{"10.0.0.0/8"})
	if ip != "10.0.0.10" {
		t.Fatalf("trusted ClientIP() = %q, want the direct peer when all hops are trusted", ip)
	}
}

func TestClientIPWithTrustedProxiesIgnoresInvalidXRealIP(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.10:443"
	// Trusted peer but the X-Real-IP value is garbage: fall back to the peer.
	req.Header.Set("X-Real-IP", "definitely-not-an-ip")

	ip := resolvedTrustedClientIP(req, []string{"10.0.0.0/8"})
	if ip != "10.0.0.10" {
		t.Fatalf("trusted ClientIP() = %q, want the direct peer for an invalid X-Real-IP", ip)
	}
}

func TestTrustedClientIPMiddlewarePopulatesClientIP(t *testing.T) {
	t.Parallel()

	var got string
	handler := TrustedClientIP([]string{"10.0.0.0/8"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r)
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.10:443"
	req.Header.Set("X-Real-IP", "203.0.113.11")

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got != "203.0.113.11" {
		t.Fatalf("ClientIP() from trusted middleware context = %q, want X-Real-IP", got)
	}
}
