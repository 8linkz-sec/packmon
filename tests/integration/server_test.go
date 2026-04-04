//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// serverBinaryPath returns the absolute path to the built packmon-server binary.
func serverBinaryPath(t *testing.T) string {
	t.Helper()
	for _, candidate := range binaryCandidates(testBinDir(t), "packmon-server") {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	path := binaryCandidates(testBinDir(t), "packmon-server")[0]
	t.Fatalf("packmon-server binary not found near %s -- run 'go build -o %s ./cmd/packmon-server' first", path, path)
	return ""
}

// freePort returns an available TCP port on localhost.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// startServerWithMetrics starts the packmon-server binary in development mode
// on random ports and returns both base URLs plus a cleanup function.
func startServerWithMetrics(t *testing.T) (baseURL, metricsURL string, cleanup func()) {
	t.Helper()

	serverPort := freePort(t)
	metricsPort := freePort(t)

	bin := serverBinaryPath(t)
	cmd := exec.Command(bin)
	cmd.Env = []string{
		"PACKMON_SERVER_MODE=development",
		fmt.Sprintf("PACKMON_SERVER_PORT=%d", serverPort),
		fmt.Sprintf("PACKMON_METRICS_PORT=%d", metricsPort),
		"PACKMON_LOG_LEVEL=warn",
		"PACKMON_LOG_FORMAT=console",
		// DB settings are irrelevant since the noop store is used in dev mode.
		"PACKMON_DB_HOST=localhost",
		"PACKMON_DB_PASSWORD=unused",
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USERPROFILE=" + os.Getenv("USERPROFILE"),
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
	}

	// Capture stderr for debugging.
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start packmon-server: %v", err)
	}

	base := fmt.Sprintf("http://127.0.0.1:%d", serverPort)

	// Wait for the server to become ready (up to 10 seconds).
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !ready {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("server did not become ready within 10 seconds; stderr: %s", stderrBuf.String())
	}

	cleanup = func() {
		cmd.Process.Kill()
		cmd.Wait()
	}

	return base, fmt.Sprintf("http://127.0.0.1:%d", metricsPort), cleanup
}

// startServer is a convenience wrapper for tests that only need the main URL.
func startServer(t *testing.T) (baseURL string, cleanup func()) {
	baseURL, _, cleanup = startServerWithMetrics(t)
	return baseURL, cleanup
}

// --- Test: GET /healthz -> 200 -----------------------------------------------

func TestServerHealthz(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %q", body["status"])
	}
}

// --- Test: GET /readyz -> 200 (noop pinger always succeeds) ------------------

func TestServerReadyz(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("expected status=ready, got %q", body["status"])
	}
}

// --- Test: GET /version -> JSON with version field ---------------------------

func TestServerVersion(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/version")
	if err != nil {
		t.Fatalf("GET /version failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	for _, field := range []string{"version", "commit", "date"} {
		if _, ok := body[field]; !ok {
			t.Errorf("missing field %q in /version response", field)
		}
	}
}

// --- Test: POST /api/v1/check with valid payload -> 200 + ScanResult ---------

func TestServerCheckValid(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	payload := map[string]any{
		"packages": []map[string]string{
			{"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
			{"name": "express", "version": "4.18.2", "ecosystem": "npm"},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(baseURL+"/api/v1/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/v1/check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(respBody))
	}

	// Verify response headers.
	if cid := resp.Header.Get("X-Correlation-ID"); cid == "" {
		t.Error("missing X-Correlation-ID header")
	}
	if dur := resp.Header.Get("X-Scan-Duration-Ms"); dur == "" {
		t.Error("missing X-Scan-Duration-Ms header")
	}

	// Decode and validate the ScanResult shape.
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	requiredFields := []string{
		"scan_id", "mode", "scanned_at", "packages_scanned",
		"findings_count", "findings", "feed_versions",
	}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field %q in /api/v1/check response", field)
		}
	}

	// The noop store returns no findings, so count should be 0.
	if count, ok := result["findings_count"].(float64); !ok || count != 0 {
		t.Errorf("expected findings_count=0 (noop store), got %v", result["findings_count"])
	}

	if scanned, ok := result["packages_scanned"].(float64); !ok || scanned != 2 {
		t.Errorf("expected packages_scanned=2, got %v", result["packages_scanned"])
	}

	// Verify mode is "remote" for server-side checks.
	if mode, ok := result["mode"].(string); !ok || mode != "remote" {
		t.Errorf("expected mode=remote, got %v", result["mode"])
	}

	// Verify findings is an array (possibly null/empty from noop store).
	switch f := result["findings"].(type) {
	case []any:
		if len(f) != 0 {
			t.Errorf("expected 0 findings, got %d", len(f))
		}
	case nil:
		// The noop store returns nil slices, which marshal as JSON null.
		// This is acceptable for integration testing.
	default:
		t.Errorf("expected findings to be an array or null, got %T", result["findings"])
	}
}

// --- Test: POST /api/v1/check with empty packages -> 400 --------------------

func TestServerCheckEmptyPackages(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	payload := map[string]any{
		"packages": []map[string]string{},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(baseURL+"/api/v1/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/v1/check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	var errResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

// --- Test: POST /api/v1/check with no body -> 400 ---------------------------

func TestServerCheckNoBody(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	resp, err := http.Post(baseURL+"/api/v1/check", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/v1/check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// --- Test: GET /api/v1/feeds/status -> 200 -----------------------------------

func TestServerFeedStatus(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	resp, err := http.Get(baseURL + "/api/v1/feeds/status")
	if err != nil {
		t.Fatalf("GET /api/v1/feeds/status failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// The noop store returns empty feeds list.
	if _, ok := body["feeds"]; !ok {
		t.Error("missing 'feeds' field in feed status response")
	}
}

// --- Test: GET /metrics -> Prometheus metrics payload ------------------------

func TestServerMetrics(t *testing.T) {
	t.Parallel()

	_, metricsURL, cleanup := startServerWithMetrics(t)
	defer cleanup()

	resp, err := http.Get(metricsURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read metrics body: %v", err)
	}
	text := string(body)

	for _, expected := range []string{
		"packmon_auth_login_failures_total",
		"packmon_degraded_responses_total",
		"packmon_queue_stuck_jobs_recovered_total",
		"packmon_db_migration_version",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("metrics output missing %q\n%s", expected, text)
		}
	}
}

// --- Test: server version subcommand -----------------------------------------

func TestServerVersionCommand(t *testing.T) {
	t.Parallel()

	bin := serverBinaryPath(t)
	cmd := exec.Command(bin, "version")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
	}

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("packmon-server version failed: %v", err)
	}

	stdout := string(out)
	if !strings.HasPrefix(stdout, "packmon-server ") {
		t.Errorf("expected output to start with 'packmon-server ', got %q", stdout)
	}
}
