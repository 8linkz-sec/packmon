package server

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/config"
)

func TestMainServerReadyMessageLeadsWithDashboardURL(t *testing.T) {
	t.Parallel()

	// The startup log line scrolls past among ~10 simultaneous feed-sync-loop
	// lines, so the human-readable message itself must carry the URL -- a
	// structured dashboard_url field alone is too easy to miss.
	got := mainServerReadyMessage("http://localhost:8080/")
	if !strings.Contains(got, "http://localhost:8080/") {
		t.Fatalf("mainServerReadyMessage() = %q, want it to contain the dashboard URL", got)
	}
}

func TestDashboardURLUsesLocalhostForWildcardBind(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Server.Port = 8080

	got := dashboardURL(cfg, "[::]:8080")
	if got != "http://localhost:8080/" {
		t.Fatalf("dashboardURL() = %q, want http://localhost:8080/", got)
	}
}

func TestDashboardURLUsesPublicHostWhenConfigured(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Server.Port = 8080
	cfg.Server.PublicHost = "packmon.internal.example"
	cfg.Server.TLS = config.TLSConfig{CertFile: "server.crt", KeyFile: "server.key"}

	got := dashboardURL(cfg, "[::]:8080")
	if got != "https://packmon.internal.example/" {
		t.Fatalf("dashboardURL() = %q, want https://packmon.internal.example/", got)
	}
}

func TestDashboardURLFallbacksAndNormalization(t *testing.T) {
	t.Parallel()

	if got := dashboardURL(nil, "bad-listener"); got != "http://localhost/" {
		t.Fatalf("dashboardURL(nil,bad) = %q, want http://localhost/", got)
	}

	cfg := &config.Config{}
	cfg.Server.Port = 9090
	if got := dashboardURL(cfg, "bad-listener"); got != "http://localhost:9090/" {
		t.Fatalf("dashboardURL(cfg,bad) = %q, want http://localhost:9090/", got)
	}
	if got := dashboardURL(cfg, "[::1]:8080"); got != "http://[::1]:8080/" {
		t.Fatalf("dashboardURL(ipv6) = %q, want http://[::1]:8080/", got)
	}

	cfg.Server.PublicHost = "https://packmon.example.test/base/"
	if got := dashboardURL(cfg, "127.0.0.1:8080"); got != "https://packmon.example.test/base/" {
		t.Fatalf("dashboardURL(public full URL) = %q", got)
	}

	for _, host := range []string{"", "0.0.0.0", "::", "[::]"} {
		if !isWildcardHost(host) {
			t.Fatalf("isWildcardHost(%q) = false, want true", host)
		}
	}
	if isWildcardHost("127.0.0.1") {
		t.Fatal("isWildcardHost(127.0.0.1) = true, want false")
	}
}
