//go:build integration

package integration

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
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

// startServerWithMetrics starts the packmon-server binary in development mode
// on random ports and returns both base URLs plus a cleanup function.
func startServerWithMetrics(t *testing.T) (baseURL, metricsURL string, cleanup func()) {
	t.Helper()

	bin := serverBinaryPath(t)
	cmd, cancel := integrationLongRunningCommand(t, bin)
	cmd.Env = []string{
		"PACKMON_SERVER_MODE=development",
		"PACKMON_SERVER_PORT=0",
		"PACKMON_METRICS_PORT=0",
		"PACKMON_LOG_LEVEL=info",
		"PACKMON_LOG_FORMAT=json",
		// DB settings are irrelevant since the noop store is used in dev mode.
		"PACKMON_DB_HOST=localhost",
		"PACKMON_DB_PASSWORD=unused",
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USERPROFILE=" + os.Getenv("USERPROFILE"),
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	logs := &serverProcessLogs{}
	addrCh := make(chan serverBoundAddr, 4)

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start packmon-server: %v", err)
	}

	go scanServerStdout(stdout, logs, addrCh)
	go scanServerStderr(stderr, logs)

	addrs := waitForServerBoundAddrs(t, addrCh, logs, 10*time.Second)
	base := loopbackHTTPURL(t, addrs.main)
	metrics := loopbackHTTPURL(t, addrs.metrics)

	// Wait for the server to become ready (up to 10 seconds).
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		resp, err := integrationHTTPGet(base + "/healthz")
		if err == nil {
			closeSilently(resp.Body)
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
		t.Fatalf("server did not become ready within 10 seconds; logs: %s", logs.String())
	}

	cleanup = func() {
		cancel()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}

	return base, metrics, cleanup
}

type serverProcessLogs struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *serverProcessLogs) appendLine(line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.WriteString(line)
	l.buf.WriteByte('\n')
}

func (l *serverProcessLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

type serverBoundAddr struct {
	kind string
	addr string
}

type serverBoundAddrs struct {
	main    string
	metrics string
}

func scanServerStdout(r io.Reader, logs *serverProcessLogs, addrCh chan<- serverBoundAddr) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		logs.appendLine(line)
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		msg, _ := entry["msg"].(string)
		addr, _ := entry["addr"].(string)
		if addr == "" {
			continue
		}
		switch msg {
		case "main server listening":
			addrCh <- serverBoundAddr{kind: "main", addr: addr}
		case "metrics server listening":
			addrCh <- serverBoundAddr{kind: "metrics", addr: addr}
		}
	}
}

func scanServerStderr(r io.Reader, logs *serverProcessLogs) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	for scanner.Scan() {
		logs.appendLine(scanner.Text())
	}
}

func waitForServerBoundAddrs(t *testing.T, addrCh <-chan serverBoundAddr, logs *serverProcessLogs, timeout time.Duration) serverBoundAddrs {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var addrs serverBoundAddrs
	for addrs.main == "" || addrs.metrics == "" {
		select {
		case addr := <-addrCh:
			switch addr.kind {
			case "main":
				addrs.main = addr.addr
			case "metrics":
				addrs.metrics = addr.addr
			}
		case <-timer.C:
			t.Fatalf("server did not report bound main and metrics addresses within %s; logs: %s", timeout, logs.String())
		}
	}
	return addrs
}

func loopbackHTTPURL(t *testing.T, boundAddr string) string {
	t.Helper()

	_, port, err := net.SplitHostPort(boundAddr)
	if err != nil {
		t.Fatalf("split bound address %q: %v", boundAddr, err)
	}
	return "http://127.0.0.1:" + port
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

	resp, err := integrationHTTPGet(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer closeSilently(resp.Body)

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

	resp, err := integrationHTTPGet(baseURL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	defer closeSilently(resp.Body)

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

	resp, err := integrationHTTPGet(baseURL + "/version")
	if err != nil {
		t.Fatalf("GET /version failed: %v", err)
	}
	defer closeSilently(resp.Body)

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

	resp, err := integrationHTTPPost(baseURL+"/api/v1/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/v1/check failed: %v", err)
	}
	defer closeSilently(resp.Body)

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
		"scan_id", "mode", "scanned_at", "duration_ms", "packages_scanned",
		"findings_count", "findings_blocking", "block_threshold", "feed_status",
		"db_age_days", "db_stale", "summary", "findings", "feed_versions",
		"manual_advisories_count",
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

	if threshold, ok := result["block_threshold"].(string); !ok || threshold != "CRITICAL" {
		t.Errorf("expected block_threshold=CRITICAL, got %v", result["block_threshold"])
	}

	if feedStatus, ok := result["feed_status"].(string); !ok || !allowedScanFeedStatus(feedStatus) {
		t.Errorf("expected machine-readable feed_status, got %v", result["feed_status"])
	}

	if blocking, ok := result["findings_blocking"].(bool); !ok || blocking {
		t.Errorf("expected findings_blocking=false, got %v", result["findings_blocking"])
	}

	if stale, ok := result["db_stale"].(bool); !ok || stale {
		t.Errorf("expected db_stale=false, got %v", result["db_stale"])
	}

	if manual, ok := result["manual_advisories_count"].(float64); !ok || manual != 0 {
		t.Errorf("expected manual_advisories_count=0, got %v", result["manual_advisories_count"])
	}

	summary, ok := result["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", result["summary"])
	}
	for _, field := range []string{"by_severity", "by_type", "by_source"} {
		if m, ok := summary[field].(map[string]any); !ok || len(m) != 0 {
			t.Errorf("expected summary.%s to be empty object, got %v", field, summary[field])
		}
	}

	findings, ok := result["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings to be an array, got %T", result["findings"])
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}

	feedVersions, ok := result["feed_versions"].(map[string]any)
	if !ok {
		t.Fatalf("expected feed_versions to be an object, got %T", result["feed_versions"])
	}
	if len(feedVersions) != 0 {
		t.Errorf("expected empty feed_versions, got %v", feedVersions)
	}
}

func allowedScanFeedStatus(status string) bool {
	switch status {
	case "healthy", "degraded", "error":
		return true
	default:
		return false
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

	resp, err := integrationHTTPPost(baseURL+"/api/v1/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/v1/check failed: %v", err)
	}
	defer closeSilently(resp.Body)

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

	resp, err := integrationHTTPPost(baseURL+"/api/v1/check", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/v1/check failed: %v", err)
	}
	defer closeSilently(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// --- Test: GET /api/v1/feeds/status -> 200 -----------------------------------

func TestServerFeedStatus(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	resp, err := integrationHTTPGet(baseURL + "/api/v1/feeds/status")
	if err != nil {
		t.Fatalf("GET /api/v1/feeds/status failed: %v", err)
	}
	defer closeSilently(resp.Body)

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

	resp, err := integrationHTTPGet(metricsURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer closeSilently(resp.Body)

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
	cmd, ctx, cancel := integrationCommandWithTimeout(t, 10*time.Second, bin, "version")
	defer cancel()
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
	}

	out, err := cmd.Output()
	failIfIntegrationCommandTimedOut(t, ctx, 10*time.Second, "packmon-server version", out)
	if err != nil {
		t.Fatalf("packmon-server version failed: %v", err)
	}

	stdout := string(out)
	if !strings.HasPrefix(stdout, "packmon-server ") {
		t.Errorf("expected output to start with 'packmon-server ', got %q", stdout)
	}
}
