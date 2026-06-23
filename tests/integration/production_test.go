//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

const postgresIntegrationImage = "cgr.dev/chainguard/postgres:latest@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"

func TestProductionServerWithPostgresAndAPIKey(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged integration tests require Docker: %v", err)
	}

	containerName, dbPort := startIntegrationPostgres(t, "packmon-it")

	serverBin := serverBinaryPath(t)
	feedImportSecret := "integration-import-secret"
	env := productionServerEnv(dbPort, feedImportSecret)

	runMigrateWithRetry(t, serverBin, env)

	cmd, cancelServer := integrationLongRunningCommand(t, serverBin)
	cmd.Env = env

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	logs := &serverProcessLogs{}
	addrCh := make(chan serverBoundAddr, 4)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start production server: %v", err)
	}
	go scanServerStdout(stdoutPipe, logs, addrCh)
	go scanServerStderr(stderrPipe, logs)
	defer func() {
		cancelServer()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	addrs := waitForServerBoundAddrs(t, addrCh, logs, 15*time.Second)
	baseURL := loopbackHTTPURL(t, addrs.main)
	waitForHTTPStatus(t, baseURL+"/healthz", http.StatusOK, logs.String())

	publicResp, err := integrationHTTPGet(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	closeSilently(publicResp.Body)
	if publicResp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", publicResp.StatusCode)
	}

	apiKey := "integration-key"
	if err := insertAPIKeyIntoContainer(containerName, hashSHA256(apiKey)); err != nil {
		t.Fatalf("insert api key: %v", err)
	}

	checkReqBody, err := json.Marshal(map[string]any{
		"packages": []map[string]string{
			{"name": "left-pad-evil", "version": "1.2.3", "ecosystem": "npm"},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal check body: %v", err)
	}

	reqNoAuth, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/check", bytes.NewReader(checkReqBody))
	if err != nil {
		t.Fatalf("NewRequest no auth: %v", err)
	}
	reqNoAuth.Header.Set("Content-Type", "application/json")
	reqNoAuth.Header.Set("User-Agent", "packmon-cli/integration")
	respNoAuth, err := integrationHTTPDo(reqNoAuth)
	if err != nil {
		t.Fatalf("POST /api/v1/check without auth: %v", err)
	}
	closeSilently(respNoAuth.Body)
	if respNoAuth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/check without auth status = %d, want 401", respNoAuth.StatusCode)
	}

	importBody, err := json.Marshal(map[string]any{
		"malicious": []map[string]any{
			{
				"id":        "MAL-PROD-1",
				"ecosystem": "npm",
				"name":      "left-pad-evil",
				"risk_type": "malware",
				"severity":  "CRITICAL",
				"summary":   "malicious package",
			},
		},
		"status": map[string]any{
			"last_sync_status": "success",
			"entries_synced":   1,
			"entries_total":    1,
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal import body: %v", err)
	}

	importReq, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/feeds/openssf/import", bytes.NewReader(importBody))
	if err != nil {
		t.Fatalf("NewRequest import: %v", err)
	}
	importReq.Header.Set("Content-Type", "application/json")
	importReq.Header.Set("Authorization", "Bearer "+apiKey)
	importReq.Header.Set("X-Packmon-Feed-Import-Secret", feedImportSecret)
	importReq.Header.Set("User-Agent", "packmon-cli/integration")
	importResp, err := integrationHTTPDo(importReq)
	if err != nil {
		t.Fatalf("POST malicious import: %v", err)
	}
	closeSilently(importResp.Body)
	if importResp.StatusCode != http.StatusOK {
		t.Fatalf("POST malicious import status = %d, want 200", importResp.StatusCode)
	}

	syncReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/sync", nil)
	if err != nil {
		t.Fatalf("NewRequest sync: %v", err)
	}
	syncReq.Header.Set("Authorization", "Bearer "+apiKey)
	syncReq.Header.Set("User-Agent", "packmon-cli/integration")
	syncResp, err := integrationHTTPDo(syncReq)
	if err != nil {
		t.Fatalf("GET /api/v1/sync: %v", err)
	}
	defer closeSilently(syncResp.Body)
	if syncResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(syncResp.Body)
		t.Fatalf("GET /api/v1/sync status = %d, body = %s", syncResp.StatusCode, string(body))
	}

	projectDir := t.TempDir()
	dbDir := filepath.Join(t.TempDir(), "db")
	lockContent := `{
  "name": "prod-sync-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "prod-sync-test",
      "version": "1.0.0"
    },
    "node_modules/left-pad-evil": {
      "version": "1.2.3"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockContent), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	jsonFile := filepath.Join(projectDir, "scan.json")
	stdout, stderr, exitCode := runPackmonWithEnv(t, map[string]string{
		"PACKMON_DB_PATH": dbDir,
	}, "scan", projectDir, "--mode", "remote", "--server", baseURL, "--api-key", apiKey, "--insecure-allow-http", "--output-json", jsonFile)
	if exitCode != 1 {
		t.Fatalf("packmon remote scan exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}
	remoteResult := readScanResultFile(t, jsonFile)
	assertProductionMaliciousScanResult(t, remoteResult, "remote")

	if stdout, stderr, exitCode := runPackmonWithEnv(t, map[string]string{
		"PACKMON_DB_PATH": dbDir,
	}, "db", "sync", "--server", baseURL, "--api-key", apiKey, "--insecure-allow-http"); exitCode != 0 {
		t.Fatalf("packmon db sync against production server exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}

	localJSONFile := filepath.Join(projectDir, "local-scan.json")
	stdout, stderr, exitCode = runPackmonWithEnv(t, map[string]string{
		"PACKMON_DB_PATH": dbDir,
	}, "scan", projectDir, "--mode", "local", "--output-json", localJSONFile)
	if exitCode != 1 {
		t.Fatalf("packmon local scan after production db sync exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}
	localResult := readScanResultFile(t, localJSONFile)
	assertProductionMaliciousScanResult(t, localResult, "local")
}

func TestProductionServerRefusesUnmigratedPostgres(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged integration tests require Docker: %v", err)
	}

	containerName, dbPort := startIntegrationPostgres(t, "packmon-unmigrated-it")
	serverBin := serverBinaryPath(t)
	env := productionServerEnv(dbPort, "integration-import-secret")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("production server kept running against unmigrated database; output:\n%s", string(output))
	}
	if err == nil {
		t.Fatalf("production server started against unmigrated database; output:\n%s", string(output))
	}
	outputText := string(output)
	if !strings.Contains(outputText, "schema") && !strings.Contains(outputText, "migration") {
		t.Fatalf("startup refusal output should mention schema or migration; output:\n%s", outputText)
	}
	if got := postgresRegclass(t, containerName, "public.schema_migrations"); got != "" {
		t.Fatalf("normal production startup created schema_migrations = %q; startup must not migrate", got)
	}
}

func productionServerEnv(dbPort int, feedImportSecret string) []string {
	return []string{
		"PACKMON_SERVER_MODE=production",
		"PACKMON_SERVER_PORT=0",
		"PACKMON_SERVER_PUBLIC_HOST=127.0.0.1",
		"PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true",
		"PACKMON_METRICS_PORT=0",
		"PACKMON_LOG_LEVEL=info",
		"PACKMON_LOG_FORMAT=json",
		"PACKMON_DB_HOST=127.0.0.1",
		fmt.Sprintf("PACKMON_DB_PORT=%d", dbPort),
		"PACKMON_DB_NAME=packmon",
		"PACKMON_DB_USER=packmon",
		"PACKMON_DB_PASSWORD=packmon",
		"PACKMON_DB_SSLMODE=disable",
		"PACKMON_ADMIN_INITIAL_PASSWORD=integration-admin",
		"PACKMON_ENCRYPTION_KEY=integration-encryption-key",
		"PACKMON_FEED_IMPORT_SECRET=" + feedImportSecret,
		"PACKMON_FEED_OSV_ENABLED=false",
		"PACKMON_FEED_GHSA_ENABLED=false",
		"PACKMON_FEED_OPENSSF_ENABLED=false",
		"PACKMON_FEED_VULNCHECK_ENABLED=false",
		"PACKMON_FEED_SOCKET_ENABLED=false",
		"PACKMON_FEED_CISAKEV_ENABLED=false",
		"PACKMON_FEED_EPSS_ENABLED=false",
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USERPROFILE=" + os.Getenv("USERPROFILE"),
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
	}
}

func readScanResultFile(t *testing.T, path string) domain.ScanResult {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scan result %s: %v", path, err)
	}
	var result domain.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode scan result %s: %v\n%s", path, err, string(data))
	}
	return result
}

func assertProductionMaliciousScanResult(t *testing.T, result domain.ScanResult, wantMode string) {
	t.Helper()

	if result.Mode != wantMode {
		t.Fatalf("ScanResult.Mode = %q, want %q", result.Mode, wantMode)
	}
	if !result.FindingsBlocking {
		t.Fatalf("FindingsBlocking = false, want malicious finding to block: %+v", result)
	}
	if result.FindingsCount < 1 || result.Summary.ByType[string(domain.FindingTypeMalicious)] < 1 {
		t.Fatalf("malicious finding count missing: count=%d summary=%+v findings=%+v", result.FindingsCount, result.Summary, result.Findings)
	}

	for _, finding := range result.Findings {
		if finding.AdvisoryID != "MAL-PROD-1" {
			continue
		}
		if finding.Type != domain.FindingTypeMalicious {
			t.Fatalf("MAL-PROD-1 Type = %q, want malicious", finding.Type)
		}
		if finding.RiskType != "malware" {
			t.Fatalf("MAL-PROD-1 RiskType = %q, want malware", finding.RiskType)
		}
		if finding.Severity != domain.SeverityCritical {
			t.Fatalf("MAL-PROD-1 Severity = %q, want CRITICAL", finding.Severity)
		}
		if finding.Ecosystem != domain.EcosystemNPM || finding.Name != "left-pad-evil" || finding.Version != "1.2.3" {
			t.Fatalf("MAL-PROD-1 package = %s/%s@%s, want npm/left-pad-evil@1.2.3", finding.Ecosystem, finding.Name, finding.Version)
		}
		if finding.Source != "openssf" {
			t.Fatalf("MAL-PROD-1 Source = %q, want openssf", finding.Source)
		}
		return
	}
	t.Fatalf("scan result missing MAL-PROD-1 finding: %+v", result.Findings)
}

func startIntegrationPostgres(t *testing.T, namePrefix string) (containerName string, hostPort int) {
	t.Helper()

	containerName = fmt.Sprintf("%s-%d", namePrefix, time.Now().UnixNano())
	run, ctx, cancel := integrationCommandWithTimeout(t, 30*time.Second, "docker", "run", "-d", "--rm",
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", "127.0.0.1::5432",
		postgresIntegrationImage,
	)
	defer cancel()
	out, err := run.Output()
	failIfIntegrationCommandTimedOut(t, ctx, 30*time.Second, "docker run postgres", out)
	if err != nil {
		t.Fatalf("docker run postgres: %v", err)
	}
	containerID := strings.TrimSpace(string(out))

	t.Cleanup(func() {
		removeDockerContainer(t, containerName)
		removeDockerContainer(t, containerID)
	})

	hostPort = dockerPublishedPort(t, containerName, "5432/tcp")
	waitForDockerPostgres(t, containerName)
	return containerName, hostPort
}

func dockerPublishedPort(t *testing.T, containerName, containerPort string) int {
	t.Helper()

	cmd, ctx, cancel := integrationCommandWithTimeout(t, 10*time.Second, "docker", "port", containerName, containerPort)
	defer cancel()
	out, err := cmd.Output()
	failIfIntegrationCommandTimedOut(t, ctx, 10*time.Second, "docker port "+containerName, out)
	if err != nil {
		t.Fatalf("docker port %s %s: %v", containerName, containerPort, err)
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) == 0 {
		t.Fatalf("docker port %s %s returned no mapping", containerName, containerPort)
	}
	_, port, err := net.SplitHostPort(lines[len(lines)-1])
	if err != nil {
		t.Fatalf("parse docker port mapping %q: %v", lines[len(lines)-1], err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse docker host port %q: %v", port, err)
	}
	return n
}

func waitForDockerPostgres(t *testing.T, containerName string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd, _, cancel := integrationCommandWithTimeout(t, 5*time.Second, "docker", "exec", containerName, "pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", "packmon", "-d", "packmon")
		if err := cmd.Run(); err == nil {
			cancel()
			return
		}
		cancel()
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres container %s did not become ready", containerName)
}

func runMigrateWithRetry(t *testing.T, serverBin string, env []string) {
	t.Helper()

	var lastErr error
	var lastOutput []byte

	for attempt := 0; attempt < 3; attempt++ {
		migrate, ctx, cancel := integrationCommandWithTimeout(t, 20*time.Second, serverBin, "migrate")
		migrate.Env = env
		output, err := migrate.CombinedOutput()
		if ctx.Err() == context.DeadlineExceeded {
			err = ctx.Err()
		}
		cancel()
		if err == nil {
			return
		}
		lastErr = err
		lastOutput = output
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("packmon-server migrate failed: %v\n%s", lastErr, string(lastOutput))
}

func waitForHTTPStatus(t *testing.T, url string, want int, stderr string) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := integrationHTTPGet(url)
		if err == nil {
			closeSilently(resp.Body)
			if resp.StatusCode == want {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("endpoint %s did not return %d; server stderr: %s", url, want, stderr)
}

func removeDockerContainer(t *testing.T, id string) {
	t.Helper()
	if strings.TrimSpace(id) == "" {
		return
	}

	cmd, _, cancel := integrationCommandWithTimeout(t, 10*time.Second, "docker", "rm", "-f", id)
	defer cancel()
	_ = cmd.Run()
}

func insertAPIKeyIntoContainer(containerName, keyHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, // #nosec G204 -- tagged integration test executes fixed docker command with test-controlled arguments.
		"psql", "-h", "127.0.0.1", "-p", "5432", "-U", "packmon", "-d", "packmon",
		"-c", fmt.Sprintf("INSERT INTO api_keys(name, key_hash) VALUES ('integration', '%s');", keyHash),
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("docker exec insert api key timed out after 10s: %s", string(output))
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

func postgresRegclass(t *testing.T, containerName, relation string) string {
	t.Helper()

	cmd, ctx, cancel := integrationCommandWithTimeout(t, 10*time.Second, "docker", "exec", containerName,
		"psql", "-h", "127.0.0.1", "-p", "5432", "-U", "packmon", "-d", "packmon", "-tAc",
		fmt.Sprintf("SELECT COALESCE(to_regclass('%s')::text, '')", relation),
	)
	defer cancel()
	output, err := cmd.CombinedOutput()
	failIfIntegrationCommandTimedOut(t, ctx, 10*time.Second, "docker exec query regclass", output)
	if err != nil {
		t.Fatalf("query regclass %s: %v\n%s", relation, err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func hashSHA256(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
