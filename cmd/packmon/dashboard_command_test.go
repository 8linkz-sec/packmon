package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

func TestDashboardCommandStartsAndStopsWithContext(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	cmd := newDashboardCmdWithOptions(dashboardOptions{
		shutdownTimeout: 200 * time.Millisecond,
		onReady: func(url string) {
			ready <- url
		},
	})
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--open=false", "--port=0"})

	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	select {
	case <-ready:
	case err := <-done:
		if err != nil {
			t.Fatalf("dashboard command error before ready = %v", err)
		}
		t.Fatal("dashboard command exited before ready")
	case <-time.After(15 * time.Second):
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		t.Fatal("dashboard command did not become ready")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("dashboard command error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dashboard command did not stop after context cancellation")
	}
}

func TestDashboardCommandOpenFlagDefaultsFalse(t *testing.T) {
	cmd := newDashboardCmd()
	flag := cmd.Flags().Lookup("open")
	if flag == nil {
		t.Fatal("dashboard --open flag missing")
	}
	if flag.DefValue != "false" {
		t.Fatalf("dashboard --open default = %q, want false", flag.DefValue)
	}
}

func TestDashboardCommandAppliesSecurityHeadersAndHidesAdminNav(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	cmd := newDashboardCmdWithOptions(dashboardOptions{
		shutdownTimeout: 200 * time.Millisecond,
		onReady: func(url string) {
			ready <- url
		},
	})
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--port=0"})

	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	var dashboardURL string
	select {
	case dashboardURL = <-ready:
	case err := <-done:
		t.Fatalf("dashboard command exited before ready: %v", err)
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("dashboard command did not become ready")
	}

	resp, err := http.Get(dashboardURL) // #nosec G107 -- test calls loopback dashboard URL returned by the command.
	if err != nil {
		cancel()
		t.Fatalf("GET dashboard: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	ioutils.CloseSilently(resp.Body)
	if err != nil {
		cancel()
		t.Fatalf("read dashboard body: %v", err)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"} {
		if resp.Header.Get(header) == "" {
			cancel()
			t.Fatalf("dashboard response missing security header %s", header)
		}
	}
	if strings.Contains(string(body), `href="/admin/"`) || strings.Contains(string(body), ">Admin</a>") {
		cancel()
		t.Fatalf("local dashboard rendered unavailable Admin navigation:\n%s", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("dashboard command error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dashboard command did not stop after context cancellation")
	}
}

func TestDashboardCommandReadinessBeforeStatusOutput(t *testing.T) {
	var readyCalled atomic.Bool
	statusOutput := &dashboardStatusOutputRecorder{
		ready:       &readyCalled,
		writes:      make(chan string, 2),
		beforeReady: make(chan string, 1),
	}

	announceLocalDashboardReady(statusOutput, "http://127.0.0.1:12345", func(url string) {
		if url != "http://127.0.0.1:12345" {
			t.Fatalf("ready URL = %q", url)
		}
		readyCalled.Store(true)
	})

	select {
	case output := <-statusOutput.beforeReady:
		t.Fatalf("dashboard wrote status output before readiness callback: %q", output)
	default:
	}
	if len(statusOutput.writes) == 0 {
		t.Fatal("dashboard did not write status output")
	}
}

type dashboardStatusOutputRecorder struct {
	ready       *atomic.Bool
	writes      chan string
	beforeReady chan string
}

func (w *dashboardStatusOutputRecorder) Write(p []byte) (int, error) {
	output := string(p)
	if !w.ready.Load() {
		select {
		case w.beforeReady <- output:
		default:
		}
	}
	select {
	case w.writes <- output:
	default:
	}
	return len(p), nil
}

func TestDashboardCommandShowsStaleLocalDBWarning(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	t.Setenv("PACKMON_DB_WARN_AFTER_DAYS", "7")

	store, _ := newTestSQLiteStore(t, dbDir)
	lastSync := time.Now().UTC().Add(-8 * 24 * time.Hour)
	if err := store.SetSyncMeta(context.Background(), "last_sync_at", lastSync.Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync timestamp: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	cmd := newDashboardCmdWithOptions(dashboardOptions{
		shutdownTimeout: 200 * time.Millisecond,
		onReady: func(url string) {
			ready <- url
		},
	})
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--port=0"})

	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	var dashboardURL string
	select {
	case dashboardURL = <-ready:
	case err := <-done:
		t.Fatalf("dashboard command exited before ready: %v", err)
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("dashboard command did not become ready")
	}

	resp, err := http.Get(dashboardURL) // #nosec G107 -- test calls loopback dashboard URL returned by the command.
	if err != nil {
		cancel()
		t.Fatalf("GET dashboard: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	ioutils.CloseSilently(resp.Body)
	if err != nil {
		cancel()
		t.Fatalf("read dashboard body: %v", err)
	}
	if !strings.Contains(string(body), "Local database last synced 8 days ago") ||
		!strings.Contains(string(body), "packmon db sync") {
		cancel()
		t.Fatalf("dashboard body missing stale local DB warning:\n%s", body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("dashboard command error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dashboard command did not stop after cancellation")
	}
}

func TestDashboardCommandReportsBrowserOpenFailure(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	opened := make(chan struct{}, 1)
	cmd := newDashboardCmdWithOptions(dashboardOptions{
		shutdownTimeout: 200 * time.Millisecond,
		onReady: func(url string) {
			ready <- url
		},
		openBrowser: func(string) error {
			opened <- struct{}{}
			return errors.New("browser unavailable")
		},
	})
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--open", "--port=0"})

	stderr := captureStderr(t, func() {
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()

		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("dashboard command exited before ready: %v", err)
		case <-time.After(15 * time.Second):
			cancel()
			t.Fatal("dashboard command did not become ready")
		}
		select {
		case <-opened:
		case err := <-done:
			t.Fatalf("dashboard command exited before browser opener: %v", err)
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("dashboard command did not call browser opener")
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("dashboard command error = %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("dashboard command did not stop after cancellation")
		}
	})

	if !strings.Contains(stderr, "warning: unable to open dashboard browser: browser unavailable") {
		t.Fatalf("dashboard stderr missing browser-open warning:\n%s", stderr)
	}
}

func TestDashboardCommandReportsFastBrowserProcessFailure(t *testing.T) {
	originalBrowserProcessStartupWait := browserProcessStartupWait
	browserProcessStartupWait = 2 * time.Second
	t.Cleanup(func() {
		browserProcessStartupWait = originalBrowserProcessStartupWait
	})

	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	opened := make(chan struct{}, 1)
	cmd := newDashboardCmdWithOptions(dashboardOptions{
		shutdownTimeout: 200 * time.Millisecond,
		onReady: func(url string) {
			ready <- url
		},
		openBrowser: func(string) error {
			//nolint:gosec // G204: the test re-executes its own binary as a helper process.
			helper := exec.Command(os.Args[0], "-test.run=^TestDashboardBrowserHelperProcess$")
			helper.Env = append(os.Environ(),
				"PACKMON_DASHBOARD_BROWSER_HELPER=1",
				"PACKMON_DASHBOARD_BROWSER_HELPER_EXIT=7",
			)
			err := startBrowserCommand(helper)
			opened <- struct{}{}
			return err
		},
	})
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--open", "--port=0"})

	stderr := captureStderr(t, func() {
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()

		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("dashboard command exited before ready: %v", err)
		case <-time.After(15 * time.Second):
			cancel()
			t.Fatal("dashboard command did not become ready")
		}
		select {
		case <-opened:
		case err := <-done:
			t.Fatalf("dashboard command exited before browser opener: %v", err)
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("dashboard command did not call browser opener")
		}
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("dashboard command error = %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("dashboard command did not stop after cancellation")
		}
	})

	if !strings.Contains(stderr, "warning: unable to open dashboard browser:") {
		t.Fatalf("dashboard stderr missing browser-open warning:\n%s", stderr)
	}
	if !strings.Contains(stderr, "exit status 7") {
		t.Fatalf("dashboard stderr missing helper exit status:\n%s", stderr)
	}
}

func TestOpenBrowserRejectsInvalidURLs(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"mailto:test@example.com", "https://example.com", "://bad"} {
		if err := openBrowser(raw); err == nil {
			t.Fatalf("openBrowser(%q) error = nil, want validation error", raw)
		}
	}
	if err := validateBrowserURL("http://localhost:8080"); err != nil {
		t.Fatalf("validateBrowserURL(localhost) error = %v", err)
	}
	if err := validateBrowserURL("https://[::1]:8080"); err != nil {
		t.Fatalf("validateBrowserURL(::1) error = %v", err)
	}
	if err := validateBrowserURL("ftp://localhost"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("validateBrowserURL(ftp) error = %v", err)
	}
}
