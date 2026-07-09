package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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

func TestMainLogsConfiguredStartupFatalWithJSONLogger(t *testing.T) {
	stdout, stderr, exitCode := runServerMainHelperProcess(t, "configured-startup-fatal", map[string]string{
		"PACKMON_SERVER_MODE":               "production",
		"PACKMON_LOG_LEVEL":                 "info",
		"PACKMON_LOG_FORMAT":                "json",
		"PACKMON_TRUSTED_PROXIES":           "",
		"PACKMON_TLS_CERT_FILE":             "",
		"PACKMON_TLS_KEY_FILE":              "",
		"PACKMON_ALLOW_INSECURE_LOCAL_HTTP": "false",
		"PACKMON_METRICS_HOST":              "127.0.0.1",
		"PACKMON_METRICS_PORT":              "9090",
	})
	if exitCode != 1 {
		t.Fatalf("helper exit code = %d, want 1; stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	record := findJSONLogRecord(t, stdout, "packmon-server startup failed")
	if record["service"] != "packmon-server" {
		t.Fatalf("fatal log service = %#v, want packmon-server; record=%v", record["service"], record)
	}
	if record["level"] != "ERROR" {
		t.Fatalf("fatal log level = %#v, want ERROR; record=%v", record["level"], record)
	}
	if got, _ := record["error"].(string); !strings.Contains(got, "refusing to start in production without transport security") {
		t.Fatalf("fatal log error = %#v, want transport-security rejection; record=%v", record["error"], record)
	}
	if strings.Contains(stderr, "packmon-server:") {
		t.Fatalf("configured fatal path wrote plain stderr: %q", stderr)
	}
}

func TestMainLogsConfiguredMigrateFatalWithJSONLogger(t *testing.T) {
	stdout, stderr, exitCode := runServerMainHelperProcess(t, "configured-migrate-fatal", map[string]string{
		"PACKMON_LOG_LEVEL":          "info",
		"PACKMON_LOG_FORMAT":         "json",
		"PACKMON_DB_HOST":            "127.0.0.1",
		"PACKMON_DB_PORT":            "1",
		"PACKMON_DB_USER":            "packmon",
		"PACKMON_DB_PASSWORD":        "packmon",
		"PACKMON_DB_NAME":            "packmon",
		"PACKMON_DB_SSLMODE":         "disable",
		"PACKMON_DB_CONNECT_TIMEOUT": "50ms",
	})
	if exitCode != 1 {
		t.Fatalf("helper exit code = %d, want 1; stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	record := findJSONLogRecord(t, stdout, "packmon-server migrate failed")
	if record["service"] != "packmon-server" {
		t.Fatalf("fatal log service = %#v, want packmon-server; record=%v", record["service"], record)
	}
	if record["level"] != "ERROR" {
		t.Fatalf("fatal log level = %#v, want ERROR; record=%v", record["level"], record)
	}
	if got, _ := record["error"].(string); !strings.Contains(got, "migrations failed") {
		t.Fatalf("fatal log error = %#v, want migration failure; record=%v", record["error"], record)
	}
	if strings.Contains(stderr, "packmon-server migrate:") {
		t.Fatalf("configured migrate fatal path wrote plain stderr: %q", stderr)
	}
}

func TestPackmonServerMainHelperProcess(t *testing.T) {
	switch os.Getenv("PACKMON_TEST_MAIN_HELPER") {
	case "configured-startup-fatal":
		os.Args = []string{"packmon-server"}
		main()
	case "configured-migrate-fatal":
		os.Args = []string{"packmon-server", "migrate"}
		main()
	}
}

func TestRunMigrateBranches(t *testing.T) {
	originalRun := runDatabaseMigrationsContext
	originalVersion := readDatabaseMigrationVersionContext
	t.Cleanup(func() {
		runDatabaseMigrationsContext = originalRun
		readDatabaseMigrationVersionContext = originalVersion
	})

	for _, key := range []string{
		"PACKMON_DB_HOST",
		"PACKMON_DB_PORT",
		"PACKMON_DB_USER",
		"PACKMON_DB_PASSWORD",
		"PACKMON_DB_NAME",
	} {
		t.Setenv(key, "")
	}

	runErr := errors.New("run failed")
	versionErr := errors.New("version failed")

	tests := []struct {
		name        string
		runErr      error
		version     uint
		dirty       bool
		versionErr  error
		wantErrPart string
		wantVersion bool
	}{
		{
			name:        "migration run error",
			runErr:      runErr,
			wantErrPart: "migrations failed: run failed",
		},
		{
			name:        "version read error",
			versionErr:  versionErr,
			wantErrPart: "failed to read schema version after migration: version failed",
			wantVersion: true,
		},
		{
			name:        "dirty schema",
			version:     42,
			dirty:       true,
			wantErrPart: "schema is in dirty state after migration (version 42)",
			wantVersion: true,
		},
		{
			name:        "success",
			version:     42,
			wantVersion: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				runDSN     string
				versionDSN string
			)
			runDatabaseMigrationsContext = func(ctx context.Context, dsn string) error {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("migration context has no deadline")
				}
				runDSN = dsn
				return tt.runErr
			}
			readDatabaseMigrationVersionContext = func(ctx context.Context, dsn string) (uint, bool, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("version context has no deadline")
				}
				versionDSN = dsn
				return tt.version, tt.dirty, tt.versionErr
			}

			err := runMigrate()
			if tt.wantErrPart == "" {
				if err != nil {
					t.Fatalf("runMigrate() error = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErrPart) {
				t.Fatalf("runMigrate() error = %v, want containing %q", err, tt.wantErrPart)
			}
			if runDSN == "" {
				t.Fatal("runDatabaseMigrations was not called")
			}
			if tt.wantVersion && versionDSN != runDSN {
				t.Fatalf("version DSN = %q, want run DSN %q", versionDSN, runDSN)
			}
			if !tt.wantVersion && versionDSN != "" {
				t.Fatalf("readDatabaseMigrationVersion called after run failure with DSN %q", versionDSN)
			}
		})
	}
}

func TestRunDevelopmentServerStartsAndStops(t *testing.T) {
	t.Setenv("PACKMON_SERVER_MODE", "development")
	t.Setenv("PACKMON_SERVER_PORT", "0")
	t.Setenv("PACKMON_METRICS_HOST", "127.0.0.1")
	t.Setenv("PACKMON_METRICS_PORT", "0")
	t.Setenv("PACKMON_SERVER_SHUTDOWN_TIMEOUT", "1s")
	t.Setenv("PACKMON_LOG_LEVEL", "info")
	t.Setenv("PACKMON_LOG_FORMAT", "json")

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mainAddrCh, stopLogCapture := captureMainServerAddrFromStdout(t)

	originalSignalContext := serverSignalContext
	originalHardExit := hardExit
	originalHardExitDelay := hardExitDelay
	hardExitCalled := make(chan int, 1)
	var hardExitOnce sync.Once
	serverSignalContext = func(context.Context) (context.Context, context.CancelFunc) {
		return rootCtx, func() {}
	}
	hardExit = func(code int) {
		hardExitOnce.Do(func() {
			hardExitCalled <- code
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

	mainAddr := waitForMainServerAddrOrRunDone(t, mainAddrCh, done)
	waitForHTTPStatus(t, "http://"+mainAddr+"/healthz", http.StatusOK)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() error = %v", err)
		}
		stopLogCapture()
	case <-time.After(3 * time.Second):
		t.Fatal("run() did not stop after context cancellation")
	}

	select {
	case code := <-hardExitCalled:
		if code != 1 {
			t.Fatalf("hard exit code = %d, want 1 for forced-shutdown failure", code)
		}
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

func captureMainServerAddrFromStdout(t *testing.T) (<-chan string, func()) {
	t.Helper()

	original := os.Stdout
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = writePipe

	addrCh := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(readPipe)
		for scanner.Scan() {
			addr := mainServerAddrFromJSONLog(scanner.Bytes())
			if addr == "" {
				continue
			}
			select {
			case addrCh <- addr:
			default:
			}
		}
	}()

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			os.Stdout = original
			_ = writePipe.Close()
			<-done
			_ = readPipe.Close()
		})
	}
	t.Cleanup(stop)

	return addrCh, stop
}

func mainServerAddrFromJSONLog(line []byte) string {
	var record struct {
		Message string `json:"msg"`
		Addr    string `json:"addr"`
	}
	if err := json.Unmarshal(line, &record); err != nil {
		return ""
	}
	if record.Message != "main server listening" {
		return ""
	}
	return record.Addr
}

func waitForMainServerAddr(t *testing.T, addrCh <-chan string) string {
	t.Helper()

	select {
	case addr := <-addrCh:
		if strings.TrimSpace(addr) == "" {
			t.Fatal("main server listen log did not include addr")
		}
		return addr
	case <-time.After(3 * time.Second):
		t.Fatal("main server did not log a bound address")
	}
	return ""
}

func waitForMainServerAddrOrRunDone(t *testing.T, addrCh <-chan string, done <-chan error) string {
	t.Helper()

	select {
	case addr := <-addrCh:
		if strings.TrimSpace(addr) == "" {
			t.Fatal("main server listen log did not include addr")
		}
		return addr
	case err := <-done:
		if err != nil {
			t.Fatalf("run() exited before main server listen log: %v", err)
		}
		t.Fatal("run() exited before main server listen log")
	case <-time.After(10 * time.Second):
		t.Fatal("main server did not log a bound address")
	}
	return ""
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

func runServerMainHelperProcess(t *testing.T, helper string, packmonEnv map[string]string) (string, string, int) {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestPackmonServerMainHelperProcess")
	cmd.Env = packmonServerMainHelperEnv(helper, packmonEnv)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("helper process failed to start: %v", err)
	}
	return stdout.String(), stderr.String(), exitErr.ExitCode()
}

func packmonServerMainHelperEnv(helper string, packmonEnv map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(packmonEnv)+1)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "PACKMON_") {
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "PACKMON_TEST_MAIN_HELPER="+helper)
	for key, value := range packmonEnv {
		env = append(env, key+"="+value)
	}
	return env
}

func findJSONLogRecord(t *testing.T, output, message string) map[string]any {
	t.Helper()

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("log line is not valid JSON: %v; line=%q output=%q", err, line, output)
		}
		if record["msg"] == message {
			return record
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan log output: %v", err)
	}
	t.Fatalf("missing JSON log message %q in stdout=%q", message, output)
	return nil
}
