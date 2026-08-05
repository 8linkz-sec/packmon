package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
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

func TestRunSingleScanOperationalFailureReportsInSARIFAndJUnit(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "feed backend unavailable", http.StatusInternalServerError)
	}))
	defer server.Close()

	scanDir := t.TempDir()
	writePackageLockForScanCommand(t, scanDir, "prod", "1.0.0")
	outDir := t.TempDir()
	sarifPath := filepath.Join(outDir, "result.sarif")
	junitPath := filepath.Join(outDir, "result.xml")

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:         scanDir,
		Mode:         "remote",
		ServerURL:    server.URL,
		FailOn:       "CRITICAL",
		MaxDepth:     2,
		Timeout:      1,
		Quiet:        true,
		InsecureHTTP: true,
		OutputSARIF:  sarifPath,
		OutputJUnit:  junitPath,
	})
	if err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if exitCode != ExitOperational {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOperational)
	}

	sarifData, err := os.ReadFile(sarifPath) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read SARIF report: %v", err)
	}
	var sarifLog struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful        bool `json:"executionSuccessful"`
				ToolExecutionNotifications []struct {
					Level   string `json:"level"`
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifData, &sarifLog); err != nil {
		t.Fatalf("decode SARIF report: %v\n%s", err, sarifData)
	}
	if len(sarifLog.Runs) != 1 || len(sarifLog.Runs[0].Invocations) != 1 {
		t.Fatalf("SARIF invocations = %+v, want one failed invocation", sarifLog.Runs)
	}
	invocation := sarifLog.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful {
		t.Fatal("SARIF invocation executionSuccessful = true, want false")
	}
	if len(invocation.ToolExecutionNotifications) != 1 || invocation.ToolExecutionNotifications[0].Level != "error" {
		t.Fatalf("SARIF notifications = %+v, want one error notification", invocation.ToolExecutionNotifications)
	}
	if !strings.Contains(invocation.ToolExecutionNotifications[0].Message.Text, "remote check failed") {
		t.Fatalf("SARIF notification missing remote failure: %+v", invocation.ToolExecutionNotifications[0].Message.Text)
	}

	junitData, err := os.ReadFile(junitPath) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read JUnit report: %v", err)
	}
	var suites struct {
		XMLName xml.Name `xml:"testsuites"`
		Errors  int      `xml:"errors,attr"`
		Suites  []struct {
			Name   string `xml:"name,attr"`
			Errors int    `xml:"errors,attr"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(junitData, &suites); err != nil {
		t.Fatalf("decode JUnit report: %v\n%s", err, junitData)
	}
	if suites.Errors == 0 {
		t.Fatalf("JUnit top-level errors = 0, want operational error suite\n%s", junitData)
	}
	var warningSuiteErrors int
	for _, suite := range suites.Suites {
		if suite.Name == "packmon.scan-warnings" {
			warningSuiteErrors = suite.Errors
		}
	}
	if warningSuiteErrors == 0 {
		t.Fatalf("JUnit warning suite errors = 0, suites=%+v", suites.Suites)
	}
}

func TestRunSingleScanLocalJSONPreservesSyncedFindingSource(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if _, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary, source)
		VALUES(
			'GHSA-manual|npm|left-pad',
			'GHSA-manual',
			'npm',
			'left-pad',
			'[{"type":"SEMVER","events":[{"introduced":"0"}]}]',
			'HIGH',
			'manual synced finding',
			'manual'
		);
	`); err != nil {
		t.Fatalf("seed local vulnerability: %v", err)
	}

	scanDir := t.TempDir()
	lockContent := `{
  "name": "manual-source-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "manual-source-project",
      "version": "1.0.0",
      "dependencies": {
        "left-pad": "1.0.0"
      }
    },
    "node_modules/left-pad": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(scanDir, "package-lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	jsonPath := filepath.Join(t.TempDir(), "result.json")

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:       scanDir,
		Mode:       "local",
		FailOn:     "NONE",
		MaxDepth:   2,
		Timeout:    1,
		Quiet:      true,
		OutputJSON: jsonPath,
	})
	if err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if exitCode != ExitUnderThreshold {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitUnderThreshold)
	}

	data, err := os.ReadFile(jsonPath) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}
	var result domain.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode JSON report: %v\n%s", err, data)
	}
	if len(result.Findings) != 1 || result.Findings[0].Source != "manual" {
		t.Fatalf("findings = %+v, want one manual finding", result.Findings)
	}
	if result.Summary.BySource["manual"] != 1 {
		t.Fatalf("summary.by_source = %+v, want manual=1", result.Summary.BySource)
	}
}

func TestScanCommandHTMLFlagWritesReport(t *testing.T) {
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
	htmlPath := filepath.Join(t.TempDir(), "report.html")

	cmd := newScanCmd()
	// NOTE: --quiet / --no-color are persistent flags on the ROOT command
	// (cmd/packmon/root.go), not on the scan command. A standalone newScanCmd()
	// does not know them, so passing --quiet here would fail with
	// "unknown flag: --quiet". Only flags registered on the scan command itself
	// (--mode, --html, the scan target) may be used in this isolated execution.
	cmd.SetArgs([]string{"--mode", "local", "--html", htmlPath, scanDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan command execute: %v", err)
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read HTML report: %v", err)
	}
	out := string(data)
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatalf("report is not HTML:\n%.80s", out)
	}
	if !strings.Contains(out, `<h1><bdi dir="auto">empty-project</bdi></h1>`) {
		t.Fatal("report missing repo-name H1 title")
	}
}

func TestRunSingleScanWritesHTMLReport(t *testing.T) {
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
	htmlPath := filepath.Join(outDir, "html", "report.html")

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		TargetName: "empty-project",
		Path:       scanDir,
		Mode:       "local",
		FailOn:     "CRITICAL",
		MaxDepth:   2,
		Timeout:    1,
		Quiet:      true,
		OutputHTML: htmlPath,
	})
	if err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read HTML report: %v", err)
	}
	out := string(data)
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatalf("report is not HTML:\n%.80s", out)
	}
	if !strings.Contains(out, `<h1><bdi dir="auto">empty-project</bdi></h1>`) {
		t.Fatal("report missing repo-name H1 title")
	}
}

func TestRunSingleScanPrintsHTMLReportPath(t *testing.T) {
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
	htmlPath := filepath.Join(t.TempDir(), "report.html")

	out := captureStdout(t, func() {
		exitCode, err := runSingleScan(context.Background(), scanSettings{
			TargetName: "empty-project",
			Path:       scanDir,
			Mode:       "local",
			FailOn:     "CRITICAL",
			MaxDepth:   2,
			Timeout:    1,
			NoColor:    true,
			OutputHTML: htmlPath,
		})
		if err != nil {
			t.Fatalf("runSingleScan() error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
		}
	})

	if !strings.Contains(out, "HTML report written to: "+htmlPath) {
		t.Fatalf("scan output missing HTML report path %q:\n%s", htmlPath, out)
	}
}

func TestRunScanCommandRejectsHTMLForMultipleTargets(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	yaml := "repos:\n" +
		"  - name: a\n    path: .\n    mode: local\n" +
		"  - name: b\n    path: .\n    mode: local\n"
	if err := os.WriteFile(".packmon.yaml", []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cmd := newScanCmd()
	err := runScanCommand(cmd, nil, scanFlagValues{All: true, OutputHTML: "out.html"})
	if err == nil || !strings.Contains(err.Error(), "--html") {
		t.Fatalf("err = %v, want error mentioning --html", err)
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
	writePackageLockPackagesForScanCommand(t, projectDir,
		scanCommandLockPackage{Name: "prod", Version: "1.0.0"},
		scanCommandLockPackage{Name: "dev-only", Version: "2.0.0", Dev: true},
	)

	originalGitCommandOutput := gitCommandOutput
	t.Cleanup(func() { gitCommandOutput = originalGitCommandOutput })
	gitMetadataCalls := 0
	gitCommandOutput = func(context.Context, ...string) ([]byte, error) {
		gitMetadataCalls++
		return nil, errors.New("not a git repo")
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
		if err := writeJSONResponseForTest(w, domain.ScanResult{
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
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
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
		if envelope.Repository == nil {
			t.Fatal("webhook envelope repository is nil")
		}
		if envelope.Repository.Name == "" {
			t.Fatalf("webhook repository missing name: %+v", envelope.Repository)
		}
	case <-time.After(time.Second):
		t.Fatal("webhook request was not received")
	}
	if gitMetadataCalls != 1 {
		t.Fatalf("git metadata calls = %d, want one shared probe for scanner, history, and webhook", gitMetadataCalls)
	}
}

func TestRunSingleScanQuietSuppressesRoutineWebhookLogs(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")

	projectDir := t.TempDir()
	writePackageLockForScanCommand(t, projectDir, "prod", "1.0.0")

	checkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := writeJSONResponseForTest(w, domain.ScanResult{
			ScanID:          "quiet-webhook-scan",
			Mode:            "remote",
			ScannedAt:       time.Now().UTC(),
			PackagesScanned: 1,
			Summary:         domain.EmptyScanSummary(),
			FeedStatus:      "healthy",
			FeedVersions:    map[string]string{"osv": time.Now().UTC().Format(time.RFC3339)},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer checkServer.Close()

	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer webhookServer.Close()

	var defaultLogs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&defaultLogs, nil)))
	defer slog.SetDefault(previousLogger)

	stderr := captureStderr(t, func() {
		exitCode, err := runSingleScan(context.Background(), scanSettings{
			Path:         projectDir,
			Mode:         string(scanner.ModeRemote),
			ServerURL:    checkServer.URL,
			APIKey:       "remote-key",
			FailOn:       "CRITICAL",
			MaxDepth:     3,
			Timeout:      2,
			Quiet:        true,
			NoColor:      true,
			LogLevel:     "DEBUG",
			InsecureHTTP: true,
			WebhookURL:   webhookServer.URL,
		})
		if err != nil {
			t.Fatalf("runSingleScan(remote) error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
		}
	})

	if output := defaultLogs.String(); output != "" {
		t.Fatalf("webhook wrote through package default logger despite quiet scan logger:\n%s", output)
	}
	if strings.Contains(stderr, "webhook:") {
		t.Fatalf("quiet scan stderr included routine webhook log:\n%s", stderr)
	}
}

func TestRunSingleScanOmitsRepoMetadataWhenDisabled(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")

	projectDir := t.TempDir()
	writePackageLockForScanCommand(t, projectDir, "prod", "1.0.0")

	originalGitCommandOutput := gitCommandOutput
	t.Cleanup(func() { gitCommandOutput = originalGitCommandOutput })
	gitMetadataCalls := 0
	gitCommandOutput = func(context.Context, ...string) ([]byte, error) {
		gitMetadataCalls++
		return nil, errors.New("unexpected git metadata probe")
	}

	requests := make(chan domain.ScanRequest, 1)
	checkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req domain.ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		requests <- req
		if err := writeJSONResponseForTest(w, domain.ScanResult{
			ScanID:       "remote-scan",
			Mode:         "remote",
			ScannedAt:    time.Now().UTC(),
			Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:     []domain.Finding{},
			FeedStatus:   "healthy",
			FeedVersions: map[string]string{},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer checkServer.Close()

	webhooks := make(chan domain.WebhookEnvelope, 1)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope domain.WebhookEnvelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		webhooks <- envelope
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhookServer.Close()

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:             projectDir,
		Mode:             string(scanner.ModeRemote),
		ServerURL:        checkServer.URL,
		FailOn:           "CRITICAL",
		MaxDepth:         3,
		Timeout:          2,
		Quiet:            true,
		InsecureHTTP:     true,
		OmitRepoMetadata: true,
		WebhookURL:       webhookServer.URL,
	})
	if err != nil {
		t.Fatalf("runSingleScan(remote) error = %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}

	select {
	case req := <-requests:
		if req.Repo != nil {
			t.Fatalf("remote request repo = %+v, want nil", req.Repo)
		}
	case <-time.After(time.Second):
		t.Fatal("remote check request was not received")
	}

	select {
	case envelope := <-webhooks:
		if envelope.Repository != nil {
			t.Fatalf("webhook repository = %+v, want nil", envelope.Repository)
		}
	case <-time.After(time.Second):
		t.Fatal("webhook request was not received")
	}

	if gitMetadataCalls != 0 {
		t.Fatalf("git metadata calls = %d, want zero when metadata and history are disabled", gitMetadataCalls)
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

func TestScanCommandListPackagesUsesRepoFlagTarget(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	appDir := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(appDir, 0o750); err != nil {
		t.Fatalf("mkdir app: %v", err)
	}
	writePackageLockForScanCommand(t, appDir, "repo-only", "1.0.0")
	writeSingleRepoConfigForScanCommand(t, "app", appDir)

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--list-packages", "--repo", "app"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("scan --list-packages --repo app: %v", err)
		}
	})

	if !strings.Contains(output, "repo-only") || !strings.Contains(output, "1.0.0") {
		t.Fatalf("list-packages output did not use configured repo target:\n%s", output)
	}
}

func TestScanCommandListAllUsesRepoFlagTarget(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	seedListAllAdvisory(t, dbDir)
	appDir := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(appDir, 0o750); err != nil {
		t.Fatalf("mkdir app: %v", err)
	}
	writePackageLockForScanCommand(t, appDir, "repo-list-all", "1.0.0")
	writeSingleRepoConfigForScanCommand(t, "app", appDir)

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--mode", "local", "--list-all", "--list-all-offline", "--repo", "app"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("scan --list-all --repo app: %v", err)
		}
	})

	if !strings.Contains(output, "repo-list-all") || !strings.Contains(output, "1.0.0") {
		t.Fatalf("list-all output did not use configured repo target:\n%s", output)
	}
}

func TestScanCommandOutdatedUsesRepoFlagTarget(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	appDir := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(appDir, 0o750); err != nil {
		t.Fatalf("mkdir app: %v", err)
	}
	writePackageLockForScanCommand(t, appDir, "repo-outdated", "1.0.0")
	writeSingleRepoConfigForScanCommand(t, "app", appDir)
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "repo-outdated" {
			return "2.0.0"
		}
		return ""
	})

	cmd := newScanCmd()
	settings, err := resolveSingleTargetScanSettings(cmd, nil, scanFlagValues{Repo: "app", MaxDepth: 10}, "--outdated")
	if err != nil {
		t.Fatalf("resolve --outdated --repo app settings: %v", err)
	}
	output := captureStdout(t, func() {
		if err := runOutdatedWithOptions([]string{settings.Path}, outdatedOptions{
			Context:        context.Background(),
			Ecosystems:     strings.Join(settings.Ecosystems, ","),
			MaxDepth:       settings.MaxDepth,
			IncludeDev:     true,
			SBOMFiles:      settings.SBOMFiles,
			Timeout:        settings.Timeout,
			LatestRegistry: settings.LatestRegistry,
			resolver:       resolver,
		}); err != nil {
			t.Fatalf("run --outdated --repo app: %v", err)
		}
	})

	if !strings.Contains(output, "repo-outdated") || !strings.Contains(output, "2.0.0") {
		t.Fatalf("outdated output did not use configured repo target:\n%s", output)
	}
}

func TestScanCommandInventoryModesUseConfiguredEcosystemFilter(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	projectDir := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(projectDir, 0o750); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	writePackageLockForScanCommand(t, projectDir, "left-pad", "1.3.0")
	writeGoModForScanCommand(t, projectDir, "github.com/pkg/errors", "v0.8.1")
	if err := os.WriteFile(".packmon.yaml", []byte("ecosystems:\n  - go\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	listCmd := newScanCmd()
	listCmd.SetArgs([]string{"--list-packages", projectDir})
	listOutput := captureStdout(t, func() {
		if err := listCmd.Execute(); err != nil {
			t.Fatalf("scan --list-packages: %v", err)
		}
	})
	if !strings.Contains(listOutput, "github.com/pkg/errors") {
		t.Fatalf("list-packages output missing configured Go package:\n%s", listOutput)
	}
	if strings.Contains(listOutput, "left-pad") {
		t.Fatalf("list-packages output ignored configured ecosystem filter:\n%s", listOutput)
	}

	resolver := stubLatestVersion(t, func(_ context.Context, eco domain.Ecosystem, name string) string {
		if eco == domain.EcosystemNPM {
			t.Fatalf("outdated lookup reached npm package %q despite configured Go-only filter", name)
		}
		if eco == domain.EcosystemGo && name == "github.com/pkg/errors" {
			return "v0.9.1"
		}
		return ""
	})
	outdatedCmd := newScanCmd()
	settings, err := resolveSingleTargetScanSettings(outdatedCmd, []string{projectDir}, scanFlagValues{MaxDepth: 10}, "--outdated")
	if err != nil {
		t.Fatalf("resolve scan --outdated settings: %v", err)
	}
	outdatedOutput := captureStdout(t, func() {
		if err := runOutdatedWithOptions([]string{settings.Path}, outdatedOptions{
			Context:        context.Background(),
			Ecosystems:     strings.Join(settings.Ecosystems, ","),
			MaxDepth:       settings.MaxDepth,
			IncludeDev:     true,
			SBOMFiles:      settings.SBOMFiles,
			Timeout:        settings.Timeout,
			LatestRegistry: settings.LatestRegistry,
			resolver:       resolver,
		}); err != nil {
			t.Fatalf("run scan --outdated: %v", err)
		}
	})
	if !strings.Contains(outdatedOutput, "github.com/pkg/errors") || !strings.Contains(outdatedOutput, "v0.9.1") {
		t.Fatalf("outdated output missing configured Go package update:\n%s", outdatedOutput)
	}
	if strings.Contains(outdatedOutput, "left-pad") {
		t.Fatalf("outdated output ignored configured ecosystem filter:\n%s", outdatedOutput)
	}
}

func TestScanCommandInventoryViewsRejectAllTargets(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	appDir := filepath.Join(t.TempDir(), "app")
	apiDir := filepath.Join(t.TempDir(), "api")
	if err := os.MkdirAll(appDir, 0o750); err != nil {
		t.Fatalf("mkdir app: %v", err)
	}
	if err := os.MkdirAll(apiDir, 0o750); err != nil {
		t.Fatalf("mkdir api: %v", err)
	}
	config := "repos:\n" +
		"  - name: app\n    path: " + strconvQuoteForYAML(appDir) + "\n" +
		"  - name: api\n    path: " + strconvQuoteForYAML(apiDir) + "\n"
	if err := os.WriteFile(".packmon.yaml", []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	for _, args := range [][]string{
		{"--list-packages", "--all"},
		{"--list-all", "--all"},
		{"--outdated", "--all"},
	} {
		cmd := newScanCmd()
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "can only be used with a single target") {
			t.Fatalf("scan %v error = %v, want single-target error", args, err)
		}
	}
}

func TestScanCommandRejectsMultipleReportModeFlags(t *testing.T) {
	cases := [][]string{
		{"--list-packages", "--outdated"},
		{"--list-packages", "--list-all"},
		{"--outdated", "--list-all"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			isolateCLIConfigDiscovery(t)
			cmd := newScanCmd()
			cmd.SetArgs(append(args, t.TempDir()))
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("scan %v error = nil, want conflicting report mode error", args)
			}
			if !strings.Contains(err.Error(), "choose only one report mode") {
				t.Fatalf("scan %v error = %v, want report mode conflict", args, err)
			}
			if code := exitCodeForError(err); code != ExitOperational {
				t.Fatalf("scan %v exitCodeForError = %d, want %d", args, code, ExitOperational)
			}
		})
	}
}

func TestScanReportingModeErrorsUseOperationalExitCode(t *testing.T) {
	parentFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("file"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	badHTMLPath := filepath.Join(parentFile, "report.html")
	missingPath := filepath.Join(t.TempDir(), "missing")

	cases := []struct {
		name string
		args []string
	}{
		{name: "list packages missing path", args: []string{"--list-packages", missingPath}},
		{name: "outdated html path", args: []string{"--outdated", "--html", badHTMLPath, t.TempDir()}},
		{name: "list all html path", args: []string{"--list-all", "--mode", "local", "--html", badHTMLPath, t.TempDir()}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			isolateCLIConfigDiscovery(t)
			cmd := newScanCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("scan %v error = nil, want operational error", tt.args)
			}
			if code := exitCodeForError(err); code != ExitOperational {
				t.Fatalf("scan %v exitCodeForError = %d, want %d; err=%v", tt.args, code, ExitOperational, err)
			}
		})
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
		if err := runListPackagesWithSettings(scanSettings{
			Path:       t.TempDir(),
			Ecosystems: []string{"npm"},
			MaxDepth:   1,
			IncludeDev: true,
		}); err != nil {
			t.Fatalf("runListPackagesWithSettings(no lock files) error = %v", err)
		}
	})
	if !strings.Contains(noLockOutput, "No lockfiles found") {
		t.Fatalf("no lock output = %q", noLockOutput)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{}}`), 0o600); err != nil {
		t.Fatalf("write empty package-lock: %v", err)
	}
	noPackagesOutput := captureStdout(t, func() {
		if err := runListPackagesWithSettings(scanSettings{
			Path:       projectDir,
			Ecosystems: []string{"npm"},
			MaxDepth:   2,
			IncludeDev: true,
		}); err != nil {
			t.Fatalf("runListPackagesWithSettings(no packages) error = %v", err)
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

type scanCommandLockPackage struct {
	Name    string
	Version string
	Dev     bool
}

func writePackageLockForScanCommand(t *testing.T, dir, name, version string) {
	t.Helper()
	writePackageLockPackagesForScanCommand(t, dir, scanCommandLockPackage{Name: name, Version: version})
}

func writePackageLockPackagesForScanCommand(t *testing.T, dir string, packages ...scanCommandLockPackage) {
	t.Helper()
	type lockPackage struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev,omitempty"`
	}
	lock := struct {
		LockfileVersion int                    `json:"lockfileVersion"`
		Packages        map[string]lockPackage `json:"packages"`
	}{
		LockfileVersion: 3,
		Packages:        map[string]lockPackage{"": {Version: "1.0.0"}},
	}
	for _, pkg := range packages {
		lock.Packages["node_modules/"+pkg.Name] = lockPackage{Version: pkg.Version, Dev: pkg.Dev}
	}
	content, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal package-lock fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
}

func writeGoModForScanCommand(t *testing.T, dir, name, version string) {
	t.Helper()
	content := "module example.com/app\n\ngo 1.22\n\nrequire " + name + " " + version + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
}

func writeSingleRepoConfigForScanCommand(t *testing.T, name, path string) {
	t.Helper()
	config := "repos:\n" +
		"  - name: " + name + "\n" +
		"    path: " + strconvQuoteForYAML(path) + "\n" +
		"    mode: local\n"
	if err := os.WriteFile(".packmon.yaml", []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeJSONResponseForTest(w http.ResponseWriter, value any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(value)
}
