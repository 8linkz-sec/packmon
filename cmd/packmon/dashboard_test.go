package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateBrowserURLOnlyAllowsLocalHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "localhost http", rawURL: "http://localhost:8080"},
		{name: "loopback https", rawURL: "https://127.0.0.1:8080/path"},
		{name: "ipv6 loopback", rawURL: "http://[::1]:8080"},
		{name: "unsupported scheme", rawURL: "file:///tmp/index.html", wantErr: true},
		{name: "remote host", rawURL: "https://example.com", wantErr: true},
		{name: "invalid", rawURL: "http://[::1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBrowserURL(tt.rawURL)
			if tt.wantErr && err == nil {
				t.Fatalf("validateBrowserURL(%q) error = nil", tt.rawURL)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateBrowserURL(%q): %v", tt.rawURL, err)
			}
		})
	}
}

func TestSignalContextCanBeCancelled(t *testing.T) {
	ctx, stop := signalContext(context.Background())
	stop()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("signal context was not cancelled")
	}
}

func TestOpenBrowserRejectsNonLocalURLBeforeLaunching(t *testing.T) {
	if err := openBrowser("https://example.com"); err == nil {
		t.Fatal("openBrowser(non-local) error = nil")
	}
}

func TestLocalDashboardRoutesExplainUnavailableAdminAndDoNotExposeStaleRefreshAPI(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	registerLocalDashboardRoutes(mux)

	adminRecorder := httptest.NewRecorder()
	mux.ServeHTTP(adminRecorder, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if adminRecorder.Code != http.StatusNotFound {
		t.Fatalf("admin unavailable status = %d, want %d", adminRecorder.Code, http.StatusNotFound)
	}
	adminBody := adminRecorder.Body.String()
	if !strings.Contains(adminBody, "Local dashboard is read-only") || !strings.Contains(adminBody, "packmon-server") {
		t.Fatalf("admin unavailable body = %q", adminBody)
	}

	noticeRecorder := httptest.NewRecorder()
	mux.ServeHTTP(noticeRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/pkg%3Cscript%3E", nil))
	if noticeRecorder.Code != http.StatusNotFound {
		t.Fatalf("stale refresh API status = %d, want %d", noticeRecorder.Code, http.StatusNotFound)
	}
	if strings.Contains(noticeRecorder.Body.String(), "<script>") {
		t.Fatalf("stale refresh API reflected package name: %q", noticeRecorder.Body.String())
	}
}

func TestOpenBrowserSourceReapsStartedProcess(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("dashboard.go")
	if err != nil {
		t.Fatalf("read dashboard.go: %v", err)
	}
	if !strings.Contains(string(source), ".Wait()") {
		t.Fatal("dashboard browser launcher should reap started helper processes with Wait")
	}
}
