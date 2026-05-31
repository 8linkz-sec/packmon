package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/scanner"
)

func TestRunSingleScanWritesAllReportFormatsForCleanLocalScan(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	scanDir := filepath.Join(t.TempDir(), "empty-project")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}
	outDir := t.TempDir()

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:        scanDir,
		Mode:        "local",
		FailOn:      "CRITICAL",
		MaxDepth:    2,
		Timeout:     1,
		Quiet:       true,
		OutputJSON:  filepath.Join(outDir, "json", "result.json"),
		OutputSARIF: filepath.Join(outDir, "sarif", "result.sarif"),
		OutputJUnit: filepath.Join(outDir, "junit", "result.xml"),
	})
	if err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}

	for _, rel := range []string{"json/result.json", "sarif/result.sarif", "junit/result.xml"} {
		path := filepath.Join(outDir, filepath.FromSlash(rel))
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("report %s stat = %v, %v; want non-empty file", rel, info, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(outDir, "json", "result.json")) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode JSON report: %v\n%s", err, data)
	}
}

func TestRunSingleScanRemotePostsPackagesAndSendsWebhook(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version":"1.0.0"},
			"node_modules/prod": {"version":"1.0.0"},
			"node_modules/dev-only": {"version":"2.0.0","dev":true}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	checkRequests := make(chan domain.ScanRequest, 1)
	checkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer remote-key" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		var req domain.ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		checkRequests <- req
		writeJSONForTest(t, w, domain.ScanResult{
			ScanID:          "remote-scan",
			Mode:            "remote",
			ScannedAt:       time.Now().UTC(),
			PackagesScanned: len(req.Packages),
			FindingsCount:   1,
			Summary: domain.ScanSummary{
				BySeverity: map[string]int{"HIGH": 1},
				ByType:     map[string]int{"vulnerability": 1},
				BySource:   map[string]int{"osv": 1},
			},
			Findings: []domain.Finding{{
				Name:       "prod",
				Version:    "1.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-remote",
				Title:      "remote finding",
				Source:     "osv",
			}},
			FeedStatus:   "healthy",
			FeedVersions: map[string]string{"osv": time.Now().UTC().Format(time.RFC3339)},
		})
	}))
	defer checkServer.Close()

	webhookRequests := make(chan domain.WebhookEnvelope, 1)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Packmon-Signature"); !strings.HasPrefix(got, "sha256=") {
			http.Error(w, "missing signature", http.StatusBadRequest)
			return
		}
		var envelope domain.WebhookEnvelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		webhookRequests <- envelope
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhookServer.Close()

	output := captureStdout(t, func() {
		exitCode, err := runSingleScan(context.Background(), scanSettings{
			Path:          projectDir,
			Mode:          string(scanner.ModeRemote),
			ServerURL:     checkServer.URL,
			APIKey:        "remote-key",
			FailOn:        "CRITICAL",
			MaxDepth:      3,
			Timeout:       2,
			IncludeDev:    true,
			NoColor:       true,
			InsecureHTTP:  true,
			WebhookURL:    webhookServer.URL,
			WebhookSecret: "hook-secret",
		})
		if err != nil {
			t.Fatalf("runSingleScan(remote) error = %v", err)
		}
		if exitCode != ExitUnderThreshold {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitUnderThreshold)
		}
	})
	if !strings.Contains(output, "GHSA-remote") || !strings.Contains(output, "prod") {
		t.Fatalf("remote scan table output missing finding:\n%s", output)
	}

	select {
	case req := <-checkRequests:
		if len(req.Packages) != 2 {
			t.Fatalf("remote request packages = %d, want prod and dev-only", len(req.Packages))
		}
	case <-time.After(time.Second):
		t.Fatal("remote check request was not received")
	}

	select {
	case envelope := <-webhookRequests:
		if envelope.Event != "scan_completed" || envelope.Result.Mode != "remote" || len(envelope.Result.Findings) != 1 {
			t.Fatalf("webhook envelope = %+v, want scan_completed remote result with one finding", envelope)
		}
	case <-time.After(time.Second):
		t.Fatal("webhook request was not received")
	}
}

func TestRunScanCommandScansMultipleCleanTargets(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	appDir := filepath.Join(t.TempDir(), "app")
	apiDir := filepath.Join(t.TempDir(), "api")
	if err := os.MkdirAll(appDir, 0o750); err != nil {
		t.Fatalf("mkdir app: %v", err)
	}
	if err := os.MkdirAll(apiDir, 0o750); err != nil {
		t.Fatalf("mkdir api: %v", err)
	}
	config := "repos:\n" +
		"  - name: app\n" +
		"    path: " + strconvQuoteForYAML(appDir) + "\n" +
		"    mode: local\n" +
		"  - name: api\n" +
		"    path: " + strconvQuoteForYAML(apiDir) + "\n" +
		"    mode: local\n"
	if err := os.WriteFile(".packmon.yaml", []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newScanCmd()
	cmd.SetContext(context.Background())
	output := captureStdout(t, func() {
		if err := runScanCommand(cmd, nil, scanFlagValues{All: true, FailOn: "CRITICAL", MaxDepth: 2, Timeout: 1, NoColor: true}); err != nil {
			t.Fatalf("runScanCommand() error = %v", err)
		}
	})
	if !strings.Contains(output, "== app ==") || !strings.Contains(output, "== api ==") {
		t.Fatalf("multi-target output missing headers:\n%s", output)
	}
}

func TestRunSingleScanRejectsInvalidModeAndFailOn(t *testing.T) {
	for _, tt := range []struct {
		name     string
		settings scanSettings
		want     string
	}{
		{name: "fail-on", settings: scanSettings{Mode: "local", FailOn: "SEVERE"}, want: "invalid fail_on"},
		{name: "mode", settings: scanSettings{Mode: "sideways", FailOn: "CRITICAL"}, want: "invalid mode"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, err := runSingleScan(context.Background(), tt.settings)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("runSingleScan() = %d, %v; want error containing %q", exitCode, err, tt.want)
			}
			if exitCode != ExitOperational {
				t.Fatalf("exitCode = %d, want %d", exitCode, ExitOperational)
			}
		})
	}
}

func TestRunListPackagesNoLockFilesAndNoPackages(t *testing.T) {
	noLockOutput := captureStdout(t, func() {
		if err := runListPackages([]string{t.TempDir()}, "npm", 1, true); err != nil {
			t.Fatalf("runListPackages(no lock files) error = %v", err)
		}
	})
	if !strings.Contains(noLockOutput, "No lock files found") {
		t.Fatalf("no lock output = %q", noLockOutput)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{}}`), 0o600); err != nil {
		t.Fatalf("write empty package-lock: %v", err)
	}
	noPackagesOutput := captureStdout(t, func() {
		if err := runListPackages([]string{projectDir}, "npm", 2, true); err != nil {
			t.Fatalf("runListPackages(no packages) error = %v", err)
		}
	})
	if !strings.Contains(noPackagesOutput, "No packages found") {
		t.Fatalf("no packages output = %q", noPackagesOutput)
	}
}

func strconvQuoteForYAML(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

func writeJSONForTest(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode JSON response: %v", err)
	}
}
