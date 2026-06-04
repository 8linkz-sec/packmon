package main

import (
	"context"
	"strings"
	"testing"
	"time"
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
