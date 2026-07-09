package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
	if got := adminRecorder.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("admin unavailable content type = %q, want text/html", got)
	}
	for _, want := range []string{
		`href="/"`,
		`href="/search"`,
		`href="/feeds"`,
		`Local dashboard destinations`,
	} {
		if !strings.Contains(adminBody, want) {
			t.Fatalf("admin unavailable body missing return path %q\nbody=%s", want, adminBody)
		}
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

func TestStartBrowserCommandWaitsForStartedProcess(t *testing.T) {
	originalWaitBrowserCommand := waitBrowserCommand
	t.Cleanup(func() {
		waitBrowserCommand = originalWaitBrowserCommand
	})

	waitResult := make(chan error, 1)
	waitBrowserCommand = func(cmd *exec.Cmd) error {
		err := cmd.Wait()
		waitResult <- err
		return err
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestDashboardBrowserHelperProcess$")
	cmd.Env = append(os.Environ(), "PACKMON_DASHBOARD_BROWSER_HELPER=1")

	if err := startBrowserCommand(cmd); err != nil {
		t.Fatalf("start browser command: %v", err)
	}

	select {
	case err := <-waitResult:
		if err != nil {
			t.Fatalf("wait browser command: %v", err)
		}
	case <-time.After(2 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		t.Fatal("startBrowserCommand did not wait for the helper process")
	}

	if cmd.ProcessState == nil {
		t.Fatal("browser helper process was not reaped")
	}
	if !cmd.ProcessState.Exited() {
		t.Fatalf("browser helper process state = %v, want exited", cmd.ProcessState)
	}
}

func TestDashboardBrowserHelperProcess(t *testing.T) {
	if os.Getenv("PACKMON_DASHBOARD_BROWSER_HELPER") != "1" {
		return
	}
	if os.Getenv("PACKMON_DASHBOARD_BROWSER_HELPER_EXIT") == "7" {
		os.Exit(7)
	}
	os.Exit(0)
}
