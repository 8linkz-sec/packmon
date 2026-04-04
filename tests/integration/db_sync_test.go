//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestDBSyncAndLocalScan(t *testing.T) {
	t.Parallel()

	baseURL, cleanup := startServer(t)
	defer cleanup()

	importBody := map[string]any{
		"malicious": []map[string]any{
			{
				"id":        "MAL-LOCAL-1",
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
	}

	payload, err := json.Marshal(importBody)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	resp, err := http.Post(baseURL+"/api/v1/feeds/malicious/import", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST feed import failed: %v", err)
	}
	closeSilently(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST feed import status = %d, want 200", resp.StatusCode)
	}

	dbDir := filepath.Join(t.TempDir(), "db")
	extraEnv := map[string]string{
		"PACKMON_DB_PATH": dbDir,
	}

	if stdout, stderr, exitCode := runPackmonWithEnv(t, extraEnv, "db", "sync", "--server", baseURL); exitCode != 0 {
		t.Fatalf("packmon db sync exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}

	projectDir := t.TempDir()
	lockContent := `{
  "name": "sync-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "sync-test",
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

	outputJSON := filepath.Join(projectDir, "result.json")
	stdout, stderr, exitCode := runPackmonWithEnv(t, extraEnv, "scan", projectDir, "--mode", "local", "--output-json", outputJSON)
	if exitCode != 1 {
		t.Fatalf("packmon scan exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}

	data, err := os.ReadFile(outputJSON)
	if err != nil {
		t.Fatalf("read scan result: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse scan result: %v", err)
	}

	if count, ok := result["findings_count"].(float64); !ok || count < 1 {
		t.Fatalf("findings_count = %v, want >= 1", result["findings_count"])
	}
}
