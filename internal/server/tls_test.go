package server

import (
	"crypto/tls"
	"testing"

	"github.com/8linkz/packmon/internal/config"
)

// TestBuildServerTLSConfig_MinVersion verifies that the in-app TLS config
// honors the configured minimum protocol version. This covers the server-side
// TLS wiring (Run() assigns s.main.TLSConfig from this helper before calling
// ListenAndServeTLS) without binding a port.
func TestBuildServerTLSConfig_MinVersion(t *testing.T) {
	tests := []struct {
		name    string
		minVer  string
		wantTLS uint16
	}{
		{"tls12", "1.2", tls.VersionTLS12},
		{"tls13", "1.3", tls.VersionTLS13},
		{"empty defaults to 1.2", "", tls.VersionTLS12},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildServerTLSConfig(config.TLSConfig{
				CertFile:   "cert.pem",
				KeyFile:    "key.pem",
				MinVersion: tc.minVer,
			})
			if got == nil {
				t.Fatal("buildServerTLSConfig returned nil")
			}
			if got.MinVersion != tc.wantTLS {
				t.Fatalf("MinVersion = %d, want %d", got.MinVersion, tc.wantTLS)
			}
		})
	}
}

// TestTLSEnabledGate confirms the Enabled() gate that selects ListenAndServeTLS
// vs ListenAndServe in Run().
func TestTLSEnabledGate(t *testing.T) {
	if (config.TLSConfig{}).Enabled() {
		t.Fatal("empty TLS config must not be Enabled")
	}
	if (config.TLSConfig{CertFile: "c"}).Enabled() {
		t.Fatal("cert-only TLS config must not be Enabled")
	}
	if !(config.TLSConfig{CertFile: "c", KeyFile: "k"}).Enabled() {
		t.Fatal("cert+key TLS config must be Enabled")
	}
}
