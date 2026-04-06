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
