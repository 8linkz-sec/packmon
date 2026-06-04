//go:build integration

package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProductionServerWithPostgresAndAPIKey(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	containerName := fmt.Sprintf("packmon-it-%d", time.Now().UnixNano())
	dbPort := freePort(t)
	serverPort := freePort(t)
	metricsPort := freePort(t)

	run := exec.Command("docker", "run", "-d", "--rm",
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", fmt.Sprintf("%d:5432", dbPort),
		"postgres:18-alpine",
	)
	out, err := run.Output()
	if err != nil {
		t.Fatalf("docker run postgres: %v", err)
	}
	containerID := strings.TrimSpace(string(out))

	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})

	waitForDockerPostgres(t, containerName)

	serverBin := serverBinaryPath(t)
	env := []string{
		"PACKMON_SERVER_MODE=production",
		fmt.Sprintf("PACKMON_SERVER_PORT=%d", serverPort),
		fmt.Sprintf("PACKMON_SERVER_PUBLIC_HOST=127.0.0.1:%d", serverPort),
		"PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true",
		fmt.Sprintf("PACKMON_METRICS_PORT=%d", metricsPort),
		"PACKMON_LOG_LEVEL=warn",
		"PACKMON_LOG_FORMAT=console",
		"PACKMON_DB_HOST=127.0.0.1",
		fmt.Sprintf("PACKMON_DB_PORT=%d", dbPort),
		"PACKMON_DB_NAME=packmon",
		"PACKMON_DB_USER=packmon",
		"PACKMON_DB_PASSWORD=packmon",
		"PACKMON_DB_SSLMODE=disable",
		"PACKMON_ADMIN_INITIAL_PASSWORD=integration-admin",
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

	runMigrateWithRetry(t, serverBin, env)

	cmd := exec.Command(serverBin)
	cmd.Env = env

	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start production server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", serverPort)
	waitForHTTPStatus(t, baseURL+"/healthz", http.StatusOK, stderrBuf.String())

	publicResp, err := http.Get(baseURL + "/")
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
	respNoAuth, err := http.DefaultClient.Do(reqNoAuth)
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
	importReq.Header.Set("User-Agent", "packmon-cli/integration")
	importResp, err := http.DefaultClient.Do(importReq)
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
	syncResp, err := http.DefaultClient.Do(syncReq)
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
}

func waitForDockerPostgres(t *testing.T, containerName string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command("docker", "exec", containerName, "pg_isready", "-U", "packmon", "-d", "packmon")
		if err := cmd.Run(); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres container %s did not become ready", containerName)
}

func runMigrateWithRetry(t *testing.T, serverBin string, env []string) {
	t.Helper()

	var lastErr error
	var lastOutput []byte

	for attempt := 0; attempt < 3; attempt++ {
		migrate := exec.Command(serverBin, "migrate")
		migrate.Env = env
		output, err := migrate.CombinedOutput()
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
		resp, err := http.Get(url)
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

func insertAPIKeyIntoContainer(containerName, keyHash string) error {
	cmd := exec.Command("docker", "exec", containerName,
		"psql", "-U", "packmon", "-d", "packmon",
		"-c", fmt.Sprintf("INSERT INTO api_keys(name, key_hash) VALUES ('integration', '%s');", keyHash),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

func hashSHA256(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
