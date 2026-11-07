package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testBrowserLauncherEnv        = "PACKMON_TEST_BROWSER_LAUNCHER"
	testBrowserLauncherCaptureEnv = "PACKMON_TEST_BROWSER_LAUNCHER_CAPTURE"
)

func TestMain(m *testing.M) {
	if os.Getenv(testBrowserLauncherEnv) == "1" {
		capturePath := os.Getenv(testBrowserLauncherCaptureEnv)
		if capturePath == "" {
			os.Exit(2)
		}
		captured, err := json.Marshal(os.Args[1:])
		if err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(capturePath, captured, 0o600); err != nil { // #nosec G703 -- capturePath is a t.TempDir path.
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestDashboardCommandFailurePathsDoNotAnnounceReadiness(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T) int
		wantErr string
	}{
		{
			name: "invalid configuration",
			prepare: func(t *testing.T) int {
				t.Helper()
				configPath := filepath.Join(t.TempDir(), "packmon.yaml")
				if err := os.WriteFile(configPath, []byte("db: [\n"), 0o600); err != nil {
					t.Fatalf("write invalid config: %v", err)
				}
				flagConfig = configPath
				return 0
			},
			wantErr: "parse",
		},
		{
			name: "database parent is a file",
			prepare: func(t *testing.T) int {
				t.Helper()
				parentFile := filepath.Join(t.TempDir(), "not-a-directory")
				if err := os.WriteFile(parentFile, []byte("sentinel"), 0o600); err != nil {
					t.Fatalf("write database parent file: %v", err)
				}
				t.Setenv("PACKMON_DB_PATH", parentFile)
				return 0
			},
			wantErr: "open local database",
		},
		{
			name: "occupied loopback port",
			prepare: func(t *testing.T) int {
				t.Helper()
				t.Setenv("PACKMON_DB_PATH", t.TempDir())
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("occupy loopback port: %v", err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				return listener.Addr().(*net.TCPAddr).Port
			},
			wantErr: "listen on localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateCLIConfigDiscovery(t)
			port := tt.prepare(t)

			var readyCalls atomic.Int32
			var stdout bytes.Buffer
			cmd := newDashboardCmdWithOptions(dashboardOptions{
				onReady: func(string) { readyCalls.Add(1) },
			})
			cmd.SetOut(&stdout)
			cmd.SetArgs([]string{"--port=" + strconv.Itoa(port)})

			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("dashboard error = %v, want context %q", err, tt.wantErr)
			}
			if got := readyCalls.Load(); got != 0 {
				t.Fatalf("readiness callback calls = %d, want 0", got)
			}
			if output := stdout.String(); strings.Contains(output, "Local dashboard available") || strings.Contains(output, "Press Ctrl+C") {
				t.Fatalf("dashboard emitted readiness output after failure: %q", output)
			}
		})
	}
}

func TestDashboardCommandForceClosesPartialHeaderAfterShutdownDeadline(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_DB_PATH", t.TempDir())

	const shutdownTimeout = 40 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan string, 1)
	cmd := newDashboardCmdWithOptions(dashboardOptions{
		shutdownTimeout: shutdownTimeout,
		onReady: func(rawURL string) {
			ready <- rawURL
		},
	})
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--port=0"})

	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	var rawURL string
	select {
	case rawURL = <-ready:
	case err := <-done:
		t.Fatalf("dashboard exited before readiness: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("dashboard did not become ready")
	}

	address := strings.TrimPrefix(rawURL, "http://")
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial dashboard: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nX-Partial: accepted\r\n"); err != nil {
		cancel()
		t.Fatalf("write partial request header: %v", err)
	}
	// Give Serve enough time to accept the connection and block while reading
	// the deliberately incomplete header before cancellation begins.
	time.Sleep(100 * time.Millisecond)

	started := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("dashboard shutdown error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dashboard did not terminate after forced close")
	}
	elapsed := time.Since(started)
	if elapsed < shutdownTimeout/2 {
		t.Fatalf("dashboard stopped in %s, want shutdown deadline before forced close", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("dashboard forced close took %s, want bounded termination", elapsed)
	}

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set peer read deadline: %v", err)
	}
	one := make([]byte, 1)
	n, readErr := conn.Read(one)
	if n != 0 || readErr == nil {
		t.Fatalf("read after forced close = (%d, %v), want closed peer connection", n, readErr)
	}
}

func TestNewLocalDashboardServerUsesBoundedTimeouts(t *testing.T) {
	srv := newLocalDashboardServer(nil)
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 5s", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 10*time.Second {
		t.Fatalf("ReadTimeout = %s, want 10s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Fatalf("WriteTimeout = %s, want 30s", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Fatalf("IdleTimeout = %s, want 60s", srv.IdleTimeout)
	}
}

func TestOpenBrowserDispatchesToCurrentPlatformLauncher(t *testing.T) {
	originalStartupWait := browserProcessStartupWait
	originalWaitCommand := waitBrowserCommand
	browserProcessStartupWait = 2 * time.Second
	waitBrowserCommand = func(cmd *exec.Cmd) error { return cmd.Wait() }
	t.Cleanup(func() {
		browserProcessStartupWait = originalStartupWait
		waitBrowserCommand = originalWaitCommand
	})

	launcherName := "xdg-open"
	wantArgs := []string{"http://127.0.0.1:43123/report"}
	switch runtime.GOOS {
	case "windows":
		launcherName = "rundll32.exe"
		wantArgs = []string{"url.dll,FileProtocolHandler", "http://127.0.0.1:43123/report"}
	case "darwin":
		launcherName = "open"
	}

	launcherDir := t.TempDir()
	launcherPath := filepath.Join(launcherDir, launcherName)
	copyTestExecutable(t, os.Args[0], launcherPath)
	t.Setenv("PATH", launcherDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	capturePath := filepath.Join(t.TempDir(), "launcher-args.json")
	restoreLauncherEnv := saveTestEnvironment(t, testBrowserLauncherEnv, testBrowserLauncherCaptureEnv)
	if err := os.Setenv(testBrowserLauncherEnv, "1"); err != nil {
		t.Fatalf("set launcher helper environment: %v", err)
	}
	if err := os.Setenv(testBrowserLauncherCaptureEnv, capturePath); err != nil {
		t.Fatalf("set launcher capture environment: %v", err)
	}

	if err := openBrowser("http://127.0.0.1:43123/report"); err != nil {
		t.Fatalf("open browser through fake launcher: %v", err)
	}
	if err := os.Unsetenv(testBrowserLauncherEnv); err != nil {
		t.Fatalf("clear launcher helper environment: %v", err)
	}
	if err := os.Unsetenv(testBrowserLauncherCaptureEnv); err != nil {
		t.Fatalf("clear launcher capture environment: %v", err)
	}
	restoreLauncherEnv()

	captured, err := os.ReadFile(capturePath) //nolint:gosec // G304: path is created by this test.
	if err != nil {
		t.Fatalf("read launcher arguments: %v", err)
	}
	var gotArgs []string
	if err := json.Unmarshal(captured, &gotArgs); err != nil {
		t.Fatalf("decode launcher arguments: %v", err)
	}
	if !equalStrings(gotArgs, wantArgs) {
		t.Fatalf("launcher arguments = %#v, want %#v", gotArgs, wantArgs)
	}
}

func saveTestEnvironment(t *testing.T, names ...string) func() {
	t.Helper()
	type savedValue struct {
		value string
		set   bool
	}
	saved := make(map[string]savedValue, len(names))
	for _, name := range names {
		value, set := os.LookupEnv(name)
		saved[name] = savedValue{value: value, set: set}
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("clear %s: %v", name, err)
		}
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		for _, name := range names {
			previous := saved[name]
			var err error
			if previous.set {
				err = os.Setenv(name, previous.value)
			} else {
				err = os.Unsetenv(name)
			}
			if err != nil {
				t.Errorf("restore %s: %v", name, err)
			}
		}
	}
	t.Cleanup(restore)
	return restore
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
