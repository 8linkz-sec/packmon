package config

import (
	"crypto/tls"
	"testing"
)

func TestTLSMinVersionDefault(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_DB_PASSWORD", "secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if got := cfg.Server.TLS.MinVersion; got != "1.2" {
		t.Fatalf("default MinVersion = %q, want 1.2", got)
	}
	if got := cfg.Server.TLS.MinVersionTLS(); got != tls.VersionTLS12 {
		t.Fatalf("MinVersionTLS() = %d, want %d", got, tls.VersionTLS12)
	}
	if cfg.Server.TLS.Enabled() {
		t.Fatal("TLS should be disabled by default (no cert/key)")
	}
}

func TestTLSMinVersionParsing(t *testing.T) {
	tests := []struct {
		val     string
		wantErr bool
		wantTLS uint16
	}{
		{"1.2", false, tls.VersionTLS12},
		{"1.3", false, tls.VersionTLS13},
		{"1.1", true, 0},
		{"junk", true, 0},
		{"", false, tls.VersionTLS12}, // empty falls back to default
	}
	for _, tc := range tests {
		t.Run(tc.val, func(t *testing.T) {
			clearPackmonEnv(t)
			t.Setenv("PACKMON_DB_PASSWORD", "secret")
			if tc.val != "" {
				t.Setenv("PACKMON_TLS_MIN_VERSION", tc.val)
			}
			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load() with PACKMON_TLS_MIN_VERSION=%q: want error, got nil", tc.val)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if got := cfg.Server.TLS.MinVersionTLS(); got != tc.wantTLS {
				t.Fatalf("MinVersionTLS() = %d, want %d", got, tc.wantTLS)
			}
		})
	}
}

func TestTLSCertKeyLoad(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_DB_PASSWORD", "secret")
	t.Setenv("PACKMON_TLS_CERT_FILE", "/etc/packmon/tls.crt")
	t.Setenv("PACKMON_TLS_KEY_FILE", "/etc/packmon/tls.key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.Server.TLS.Enabled() {
		t.Fatal("TLS should be enabled when cert+key set")
	}
	if cfg.Server.TLS.CertFile != "/etc/packmon/tls.crt" {
		t.Fatalf("CertFile = %q", cfg.Server.TLS.CertFile)
	}
	if cfg.Server.TLS.KeyFile != "/etc/packmon/tls.key" {
		t.Fatalf("KeyFile = %q", cfg.Server.TLS.KeyFile)
	}
}

func TestTLSEnabledRequiresBoth(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_DB_PASSWORD", "secret")
	t.Setenv("PACKMON_TLS_CERT_FILE", "/etc/packmon/tls.crt")
	// no key file

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Server.TLS.Enabled() {
		t.Fatal("TLS should not be enabled with only a cert file")
	}
}

func TestValidateTransportSecurity(t *testing.T) {
	tests := []struct {
		name    string
		mode    ServerMode
		tlsCfg  TLSConfig
		proxies []string
		public  string
		localOK bool
		wantErr bool
	}{
		{
			name:    "production with TLS ok",
			mode:    ModeProduction,
			tlsCfg:  TLSConfig{CertFile: "c", KeyFile: "k", MinVersion: "1.2"},
			wantErr: false,
		},
		{
			name:    "production with trusted proxies ok",
			mode:    ModeProduction,
			proxies: []string{"127.0.0.1"},
			wantErr: false,
		},
		{
			name:    "production with local insecure HTTP override and loopback host ok",
			mode:    ModeProduction,
			public:  "localhost:8080",
			localOK: true,
			wantErr: false,
		},
		{
			name:    "production with local insecure HTTP override and external host errors",
			mode:    ModeProduction,
			public:  "packmon.example.com",
			localOK: true,
			wantErr: true,
		},
		{
			name:    "production with neither errors",
			mode:    ModeProduction,
			wantErr: true,
		},
		{
			name:    "development with neither ok",
			mode:    ModeDevelopment,
			wantErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{
					Mode:                   tc.mode,
					PublicHost:             tc.public,
					TrustedProxies:         tc.proxies,
					AllowInsecureLocalHTTP: tc.localOK,
					TLS:                    tc.tlsCfg,
				},
			}
			err := cfg.ValidateTransportSecurity()
			if tc.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
		})
	}
}

func TestLoadReadsInsecureLocalHTTPOverride(t *testing.T) {
	clearPackmonEnv(t)
	t.Setenv("PACKMON_DB_PASSWORD", "secret")
	t.Setenv("PACKMON_SERVER_PUBLIC_HOST", "localhost:8080")
	t.Setenv("PACKMON_ALLOW_INSECURE_LOCAL_HTTP", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.Server.AllowInsecureLocalHTTP {
		t.Fatal("AllowInsecureLocalHTTP = false, want true")
	}
	if err := cfg.ValidateTransportSecurity(); err != nil {
		t.Fatalf("ValidateTransportSecurity() error: %v", err)
	}
}
