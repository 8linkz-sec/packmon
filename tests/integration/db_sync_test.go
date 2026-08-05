//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
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

	resp, err := integrationHTTPPost(baseURL+"/api/v1/feeds/openssf/import", "application/json", bytes.NewReader(payload))
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

	if stdout, stderr, exitCode := runPackmonWithEnv(t, extraEnv, "db", "sync", "--server", baseURL, "--insecure-allow-http"); exitCode != 0 {
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

	var result domain.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("parse scan result: %v", err)
	}
	assertDBSyncLocalMaliciousScanResult(t, result)
}

func assertDBSyncLocalMaliciousScanResult(t *testing.T, result domain.ScanResult) {
	t.Helper()

	if result.Mode != "local" {
		t.Fatalf("ScanResult.Mode = %q, want local", result.Mode)
	}
	if result.PackagesScanned != 1 {
		t.Fatalf("PackagesScanned = %d, want 1", result.PackagesScanned)
	}
	if result.FindingsCount != 1 {
		t.Fatalf("FindingsCount = %d, want 1: %+v", result.FindingsCount, result.Findings)
	}
	if !result.FindingsBlocking {
		t.Fatalf("FindingsBlocking = false, want malicious finding to block: %+v", result)
	}
	if result.Summary.ByType[string(domain.FindingTypeMalicious)] != 1 {
		t.Fatalf("malicious summary count = %d, want 1: %+v", result.Summary.ByType[string(domain.FindingTypeMalicious)], result.Summary)
	}

	for _, finding := range result.Findings {
		if finding.AdvisoryID != "MAL-LOCAL-1" {
			continue
		}
		if finding.Type != domain.FindingTypeMalicious {
			t.Fatalf("MAL-LOCAL-1 Type = %q, want malicious", finding.Type)
		}
		if finding.RiskType != "malware" {
			t.Fatalf("MAL-LOCAL-1 RiskType = %q, want malware", finding.RiskType)
		}
		if finding.Severity != domain.SeverityCritical {
			t.Fatalf("MAL-LOCAL-1 Severity = %q, want CRITICAL", finding.Severity)
		}
		if finding.Ecosystem != domain.EcosystemNPM || finding.Name != "left-pad-evil" || finding.Version != "1.2.3" {
			t.Fatalf("MAL-LOCAL-1 package = %s/%s@%s, want npm/left-pad-evil@1.2.3", finding.Ecosystem, finding.Name, finding.Version)
		}
		if finding.Source != "openssf" {
			t.Fatalf("MAL-LOCAL-1 Source = %q, want openssf", finding.Source)
		}
		return
	}
	t.Fatalf("scan result missing MAL-LOCAL-1 finding: %+v", result.Findings)
}
