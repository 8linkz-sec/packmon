package main

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestLocalDashboardRoutesRedirectAdminAndEscapeRefreshNotice(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	registerLocalDashboardRoutes(mux)

	redirectRecorder := httptest.NewRecorder()
	mux.ServeHTTP(redirectRecorder, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if redirectRecorder.Code != http.StatusSeeOther {
		t.Fatalf("admin redirect status = %d, want %d", redirectRecorder.Code, http.StatusSeeOther)
	}
	if got := redirectRecorder.Header().Get("Location"); got != "/" {
		t.Fatalf("admin redirect location = %q, want /", got)
	}

	noticeRecorder := httptest.NewRecorder()
	mux.ServeHTTP(noticeRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/pkg%3Cscript%3E", nil))
	if noticeRecorder.Code != http.StatusAccepted {
		t.Fatalf("refresh notice status = %d, want %d", noticeRecorder.Code, http.StatusAccepted)
	}
	body := noticeRecorder.Body.String()
	if !strings.Contains(body, "Local dashboard is read-only") {
		t.Fatalf("refresh notice body = %q", body)
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, "pkg&lt;script&gt;") {
		t.Fatalf("refresh notice did not escape package name: %q", body)
	}
}
