package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMainVersionCommandPrintsBuildInfo(t *testing.T) {
	originalArgs := os.Args
	defer func() { os.Args = originalArgs }()
	os.Args = []string{"packmon-server", "version"}

	output := captureServerStdout(t, main)
	if !strings.Contains(output, "packmon-server ") || !strings.Contains(output, version) {
		t.Fatalf("version output = %q", output)
	}
}

func TestRunReturnsConfigAndTransportErrorsBeforeDatabaseUse(t *testing.T) {
	t.Setenv("PACKMON_SERVER_PORT", "not-a-port")
	if err := run(); err == nil || !strings.Contains(err.Error(), "PACKMON_SERVER_PORT") {
		t.Fatalf("run(invalid config) error = %v", err)
	}

	t.Setenv("PACKMON_SERVER_PORT", "8080")
	t.Setenv("PACKMON_SERVER_MODE", "production")
	t.Setenv("PACKMON_TRUSTED_PROXIES", "")
	t.Setenv("PACKMON_TLS_CERT_FILE", "")
	t.Setenv("PACKMON_TLS_KEY_FILE", "")
	t.Setenv("PACKMON_ALLOW_INSECURE_LOCAL_HTTP", "false")
	if err := run(); err == nil || !strings.Contains(err.Error(), "refusing to start in production without transport security") {
		t.Fatalf("run(insecure production) error = %v", err)
	}
}

func TestRunMigrateReturnsConfigError(t *testing.T) {
	t.Setenv("PACKMON_DB_PORT", "bad")
	if err := runMigrate(); err == nil || !strings.Contains(err.Error(), "PACKMON_DB_PORT") {
		t.Fatalf("runMigrate() error = %v", err)
	}
}

func TestRunDevelopmentServerStartsAndStops(t *testing.T) {
	serverPort := freeTCPPort(t)
	metricsPort := freeTCPPort(t)

	t.Setenv("PACKMON_SERVER_MODE", "development")
	t.Setenv("PACKMON_SERVER_PORT", fmt.Sprintf("%d", serverPort))
	t.Setenv("PACKMON_METRICS_HOST", "127.0.0.1")
	t.Setenv("PACKMON_METRICS_PORT", fmt.Sprintf("%d", metricsPort))
	t.Setenv("PACKMON_SERVER_SHUTDOWN_TIMEOUT", "1s")
	t.Setenv("PACKMON_LOG_LEVEL", "error")

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	originalSignalContext := serverSignalContext
	originalHardExit := hardExit
	originalHardExitDelay := hardExitDelay
	hardExitCalled := make(chan struct{})
	var hardExitOnce sync.Once
	serverSignalContext = func(context.Context) (context.Context, context.CancelFunc) {
		return rootCtx, func() {}
	}
	hardExit = func(int) {
		hardExitOnce.Do(func() {
			close(hardExitCalled)
		})
	}
	hardExitDelay = time.Millisecond
	t.Cleanup(func() {
		serverSignalContext = originalSignalContext
		hardExit = originalHardExit
		hardExitDelay = originalHardExitDelay
	})

	done := make(chan error, 1)
	go func() {
		done <- run()
	}()

	waitForHTTPStatus(t, fmt.Sprintf("http://127.0.0.1:%d/healthz", serverPort), http.StatusOK)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not stop after context cancellation")
	}

	select {
	case <-hardExitCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("hard exit hook was not called after context cancellation")
	}
}

func captureServerStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writePipe

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, readPipe)
		done <- buf.String()
	}()

	fn()
	_ = writePipe.Close()
	os.Stdout = original
	output := <-done
	_ = readPipe.Close()
	return output
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free port: %v", err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForHTTPStatus(t *testing.T, rawURL string, want int) {
	t.Helper()

	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(rawURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("GET %s did not return %d: %v", rawURL, want, lastErr)
}
