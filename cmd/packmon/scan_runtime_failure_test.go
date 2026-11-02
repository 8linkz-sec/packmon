package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

func TestRunSingleScanHistoryFailureStillWritesArtifactsAndWebhook(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("set sync timestamp: %v", err)
	}
	if _, err := store.DB().ExecContext(context.Background(),
		`CREATE TRIGGER block_scan_history_insert BEFORE INSERT ON scan_history BEGIN SELECT RAISE(ABORT, 'history insert blocked'); END`); err != nil {
		t.Fatalf("create scan-history insert trigger: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	projectDir := filepath.Join(t.TempDir(), "history-failure-project")
	if err := os.MkdirAll(projectDir, 0o750); err != nil {
		t.Fatalf("create scan directory: %v", err)
	}
	outDir := t.TempDir()
	paths := map[string]string{
		"JSON":  filepath.Join(outDir, "result.json"),
		"SARIF": filepath.Join(outDir, "result.sarif"),
		"JUnit": filepath.Join(outDir, "result.xml"),
		"HTML":  filepath.Join(outDir, "result.html"),
	}

	handlerErrors := make(chan string, 1)
	webhooks := make(chan domain.WebhookEnvelope, 1)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for format, path := range paths {
			data, err := os.ReadFile(path) // #nosec G304 -- test reads its own generated artifacts.
			if err != nil || len(data) == 0 {
				reportHandlerError(w, handlerErrors, http.StatusInternalServerError, "%s artifact was not ready before webhook delivery: %v", format, err)
				return
			}
		}
		var envelope domain.WebhookEnvelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			reportHandlerError(w, handlerErrors, http.StatusBadRequest, "decode webhook: %v", err)
			return
		}
		webhooks <- envelope
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhookServer.Close()

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:             projectDir,
		Mode:             string(scanner.ModeLocal),
		FailOn:           "CRITICAL",
		MaxDepth:         2,
		Timeout:          1,
		Quiet:            true,
		OmitRepoMetadata: true,
		OutputJSON:       paths["JSON"],
		OutputSARIF:      paths["SARIF"],
		OutputJUnit:      paths["JUnit"],
		OutputHTML:       paths["HTML"],
		WebhookURL:       webhookServer.URL,
	})
	var historyErr *scanHistoryRecordError
	if !errors.As(err, &historyErr) {
		t.Fatalf("runSingleScan() error = %v, want scanHistoryRecordError", err)
	}
	if exitCode != ExitOperational {
		t.Fatalf("runSingleScan() exit = %d, want %d", exitCode, ExitOperational)
	}
	assertNoHandlerError(t, handlerErrors)

	var webhook domain.WebhookEnvelope
	select {
	case webhook = <-webhooks:
	case <-time.After(time.Second):
		t.Fatal("webhook was not delivered")
	}
	if webhook.Event != "scan_completed" || webhook.Repository != nil {
		t.Fatalf("webhook envelope = %+v, want canonical event without repository metadata", webhook)
	}

	jsonData, readErr := os.ReadFile(paths["JSON"]) // #nosec G304 -- test reads its own generated artifact.
	if readErr != nil {
		t.Fatalf("read JSON artifact: %v", readErr)
	}
	var jsonResult domain.ScanResult
	if err := json.Unmarshal(jsonData, &jsonResult); err != nil {
		t.Fatalf("decode JSON artifact: %v", err)
	}
	if !reflect.DeepEqual(webhook.Result, jsonResult) {
		t.Fatalf("webhook result differs from canonical JSON artifact:\nwebhook=%+v\njson=%+v", webhook.Result, jsonResult)
	}

	sarifData, readErr := os.ReadFile(paths["SARIF"]) // #nosec G304 -- test reads its own generated artifact.
	if readErr != nil {
		t.Fatalf("read SARIF artifact: %v", readErr)
	}
	var sarif map[string]any
	if err := json.Unmarshal(sarifData, &sarif); err != nil || len(sarif) == 0 {
		t.Fatalf("decode SARIF artifact: %v", err)
	}
	junitData, readErr := os.ReadFile(paths["JUnit"]) // #nosec G304 -- test reads its own generated artifact.
	if readErr != nil {
		t.Fatalf("read JUnit artifact: %v", readErr)
	}
	var junit struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(junitData, &junit); err != nil || junit.XMLName.Local == "" {
		t.Fatalf("decode JUnit artifact: %v", err)
	}
	htmlData, readErr := os.ReadFile(paths["HTML"]) // #nosec G304 -- test reads its own generated artifact.
	if readErr != nil {
		t.Fatalf("read HTML artifact: %v", readErr)
	}
	if !strings.Contains(string(htmlData), "Packmon Security Report") {
		t.Fatalf("HTML artifact is not a scan report:\n%s", htmlData)
	}
}

func TestRunScanPipelineKeepsFreshnessAndRetentionFailuresNonBlocking(t *testing.T) {
	t.Run("invalid freshness timestamp", func(t *testing.T) {
		projectDir, store := runtimeFailureScanFixture(t, "freshness-project")
		t.Setenv("PACKMON_HISTORY_ENABLED", "false")
		if err := store.SetSyncMeta(context.Background(), "last_sync_at", "not-a-timestamp"); err != nil {
			t.Fatalf("set invalid sync timestamp: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("close seed store: %v", err)
		}

		var result *domain.ScanResult
		stderr := captureScanStderr(t, func() {
			var err error
			var exitCode int
			result, _, exitCode, _, _, err = runScanPipeline(context.Background(), runtimeFailureScanSettings(projectDir))
			if err != nil {
				t.Fatalf("runScanPipeline() error = %v", err)
			}
			if exitCode != ExitOK {
				t.Fatalf("runScanPipeline() exit = %d, want %d", exitCode, ExitOK)
			}
		})
		if result == nil || !result.DBStale || result.DBAgeDays != nil {
			t.Fatalf("freshness result = %+v, want stale with unknown age", result)
		}
		if result.FindingsCount != 0 || result.FindingsBlocking || result.ScanError != "" {
			t.Fatalf("freshness failure changed clean scan decision: %+v", result)
		}
		if !strings.Contains(stderr, "warning: unable to determine local DB freshness:") || !strings.Contains(stderr, "unsupported timestamp format") {
			t.Fatalf("stderr missing freshness warning:\n%s", stderr)
		}
	})

	t.Run("count retention", func(t *testing.T) {
		projectDir, store := runtimeFailureScanFixture(t, "count-retention-project")
		t.Setenv("PACKMON_HISTORY_MAX_SCANS_PER_REPO", "1")
		t.Setenv("PACKMON_HISTORY_MAX_AGE", "0")
		if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("set sync timestamp: %v", err)
		}
		repoName := filepath.Base(projectDir)
		seedRuntimeFailureHistory(t, store, repoName, time.Now().UTC().Add(-3*time.Hour), time.Now().UTC().Add(-2*time.Hour))
		if _, err := store.DB().ExecContext(context.Background(),
			`CREATE TRIGGER block_count_retention BEFORE DELETE ON scan_history BEGIN SELECT RAISE(ABORT, 'count retention blocked'); END`); err != nil {
			t.Fatalf("create count-retention trigger: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("close seed store: %v", err)
		}

		stderr := captureScanStderr(t, func() {
			result, _, exitCode, _, _, err := runScanPipeline(context.Background(), runtimeFailureScanSettings(projectDir))
			if err != nil || exitCode != ExitOK {
				t.Fatalf("runScanPipeline() = result %+v, exit %d, error %v; want successful clean scan", result, exitCode, err)
			}
		})
		if !strings.Contains(stderr, "warning: unable to enforce history retention:") || !strings.Contains(stderr, "count retention blocked") {
			t.Fatalf("stderr missing count-retention warning:\n%s", stderr)
		}
		if strings.Contains(stderr, "history age retention") {
			t.Fatalf("count-retention case emitted age warning:\n%s", stderr)
		}
		assertRuntimeFailureHistoryCount(t, store, 3)
	})

	t.Run("age retention", func(t *testing.T) {
		projectDir, store := runtimeFailureScanFixture(t, "age-retention-project")
		t.Setenv("PACKMON_HISTORY_MAX_SCANS_PER_REPO", "0")
		t.Setenv("PACKMON_HISTORY_MAX_AGE", "24h")
		if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("set sync timestamp: %v", err)
		}
		repoName := filepath.Base(projectDir)
		seedRuntimeFailureHistory(t, store, repoName, time.Now().UTC().Add(-72*time.Hour), time.Now().UTC().Add(-2*time.Hour))
		if _, err := store.DB().ExecContext(context.Background(),
			`CREATE TRIGGER block_age_retention BEFORE DELETE ON scan_history WHEN OLD.packages_count = 101 BEGIN SELECT RAISE(ABORT, 'age retention blocked'); END`); err != nil {
			t.Fatalf("create age-retention trigger: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatalf("close seed store: %v", err)
		}

		stderr := captureScanStderr(t, func() {
			result, _, exitCode, _, _, err := runScanPipeline(context.Background(), runtimeFailureScanSettings(projectDir))
			if err != nil || exitCode != ExitOK {
				t.Fatalf("runScanPipeline() = result %+v, exit %d, error %v; want successful clean scan", result, exitCode, err)
			}
		})
		if !strings.Contains(stderr, "warning: unable to enforce history age retention:") || !strings.Contains(stderr, "age retention blocked") {
			t.Fatalf("stderr missing age-retention warning:\n%s", stderr)
		}
		if strings.Contains(stderr, "warning: unable to enforce history retention:") {
			t.Fatalf("age-retention case emitted count warning:\n%s", stderr)
		}
		assertRuntimeFailureHistoryCount(t, store, 3)
	})
}

func TestLocalCheckerFailurePathsAreBoundedAndReleaseResources(t *testing.T) {
	t.Run("eager path resolution failure", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		unsetHomeDirectory(t)
		t.Setenv("PACKMON_DB_PATH", "")

		local, err := openLocalCheckerIfNeeded(context.Background(), scanner.ModeLocal, scanSettings{})
		if err == nil {
			local.close()
			t.Fatal("openLocalCheckerIfNeeded() error = nil, want unresolved database path")
		}
		if !strings.Contains(err.Error(), "home directory") || !strings.Contains(err.Error(), "PACKMON_DB_PATH or db.path") {
			t.Fatalf("openLocalCheckerIfNeeded() error = %v, want bounded override hint", err)
		}
	})

	t.Run("eager open failure", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		badRoot := filepath.Join(t.TempDir(), "private-eager-db-root")
		if err := os.WriteFile(badRoot, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("write database blocker: %v", err)
		}
		t.Setenv("PACKMON_DB_PATH", badRoot)

		var local localScanStore
		stderr := captureScanStderr(t, func() {
			var err error
			local, err = openLocalCheckerIfNeeded(context.Background(), scanner.ModeLocal, scanSettings{})
			if err != nil {
				t.Fatalf("openLocalCheckerIfNeeded() error = %v, want non-fatal unavailable checker", err)
			}
		})
		defer local.close()
		if local.localChecker() != nil || local.openedStore() != nil {
			t.Fatalf("eager open failure exposed checker/store: %+v", local)
		}
		assertBoundedRedactedDBWarning(t, stderr, badRoot)
	})

	t.Run("lazy path failure is cached for extended lookups", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		unsetHomeDirectory(t)
		t.Setenv("PACKMON_DB_PATH", "")
		checker := &lazyLocalChecker{}
		defer checker.close()

		stderr := captureScanStderr(t, func() {
			_, reputationErr := checker.FindReputationFindingsBatch(context.Background(), []scanner.PackageLookup{{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}}, "reversinglabs")
			_, lifecycleErr := checker.FindLifecycleFindingsBatch(context.Background(), []scanner.PackageLookup{{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}}, time.Now().UTC())
			for name, err := range map[string]error{"reputation": reputationErr, "lifecycle": lifecycleErr} {
				if !errors.Is(err, errLocalAdvisoryDataUnavailable) {
					t.Fatalf("%s lookup error = %v, want cached unavailable sentinel", name, err)
				}
			}
		})
		if strings.Count(stderr, "warning: unable to resolve local database path:") != 1 {
			t.Fatalf("lazy path failure was not cached:\n%s", stderr)
		}
	})

	t.Run("lazy open failure is cached and redacted", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		badRoot := filepath.Join(t.TempDir(), "private-lazy-db-root")
		if err := os.WriteFile(badRoot, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("write database blocker: %v", err)
		}
		t.Setenv("PACKMON_DB_PATH", badRoot)
		checker := &lazyLocalChecker{}
		defer checker.close()

		stderr := captureScanStderr(t, func() {
			_, reputationErr := checker.FindReputationFindingsBatch(context.Background(), nil, "reversinglabs")
			_, lifecycleErr := checker.FindLifecycleFindingsBatch(context.Background(), nil, time.Now().UTC())
			if !errors.Is(reputationErr, errLocalAdvisoryDataUnavailable) || !errors.Is(lifecycleErr, errLocalAdvisoryDataUnavailable) {
				t.Fatalf("lazy errors = (%v, %v), want cached unavailable sentinel", reputationErr, lifecycleErr)
			}
		})
		if strings.Count(stderr, "warning: unable to open local database:") != 1 {
			t.Fatalf("lazy open failure was retried:\n%s", stderr)
		}
		assertBoundedRedactedDBWarning(t, stderr, badRoot)
	})

	t.Run("canceled availability query closes store", func(t *testing.T) {
		dbDir := t.TempDir()
		dbPath := filepath.Join(dbDir, "packmon.db")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		store, available, err := openLocalSQLiteStore(ctx, dbPath)
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("openLocalSQLiteStore() error = %v, want context cancellation", err)
		}
		if store != nil || available {
			t.Fatalf("openLocalSQLiteStore() = (%v, %t), want released nil store", store, available)
		}
		renamed := dbDir + "-renamed"
		if err := os.Rename(dbDir, renamed); err != nil {
			t.Fatalf("rename database directory after failed availability query: %v", err)
		}
		if err := os.RemoveAll(renamed); err != nil {
			t.Fatalf("remove renamed database directory: %v", err)
		}
	})

	t.Run("history path resolution failure is non-fatal", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		unsetHomeDirectory(t)
		t.Setenv("PACKMON_DB_PATH", "")
		var store *sqlite.Store
		var closeStore bool
		stderr := captureScanStderr(t, func() {
			resolved, closeResolved := ensureHistoryStore(context.Background(), localScanStore{}, true)
			store = resolved
			closeStore = closeResolved
		})
		if store != nil || closeStore {
			t.Fatalf("ensureHistoryStore() = (%v, %t), want nil non-owned store", store, closeStore)
		}
		if len(stderr) > 512 || !strings.Contains(stderr, "warning: unable to resolve local database path:") || !strings.Contains(stderr, "PACKMON_DB_PATH or db.path") {
			t.Fatalf("history warning is missing or unbounded (%d bytes):\n%s", len(stderr), stderr)
		}
	})
}

func TestLazyLocalCheckerSingleLookupsReuseAndReleaseStore(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	seed, _ := newTestSQLiteStore(t, dbDir)
	if _, err := seed.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, versions_affected, severity, summary)
		VALUES('GHSA-lazy|npm|pkg', 'GHSA-lazy', 'npm', 'pkg', '["1.0.0"]', 'HIGH', 'lazy advisory')`); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	checker := &lazyLocalChecker{}
	vulnerabilities, err := checker.FindVulnerabilities(context.Background(), "npm", "pkg", "1.0.0")
	if err != nil || len(vulnerabilities) != 1 || vulnerabilities[0].AdvisoryID != "GHSA-lazy" {
		t.Fatalf("FindVulnerabilities() = %+v, %v; want seeded advisory", vulnerabilities, err)
	}
	firstStore, firstAdapter := checker.store, checker.adapter
	if firstStore == nil || firstAdapter == nil {
		t.Fatal("first lazy lookup did not retain the opened store and adapter")
	}
	malicious, err := checker.FindMalicious(context.Background(), "npm", "pkg", "1.0.0")
	if err != nil || len(malicious) != 0 {
		t.Fatalf("FindMalicious() = %+v, %v; want successful empty lookup", malicious, err)
	}
	if checker.store != firstStore || checker.adapter != firstAdapter {
		t.Fatal("second single lookup did not reuse the lazy store and adapter")
	}

	checker.close()
	if checker.store != nil || checker.adapter != nil {
		t.Fatalf("close() retained lazy fields: store=%v adapter=%v", checker.store, checker.adapter)
	}
	renamed := dbDir + "-renamed"
	if err := os.Rename(dbDir, renamed); err != nil {
		t.Fatalf("rename database directory after lazy close: %v", err)
	}
	if err := os.RemoveAll(renamed); err != nil {
		t.Fatalf("remove renamed database directory: %v", err)
	}
}

func TestRunSingleScanDiagnosesTerminalWriterFailure(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}
	projectDir := filepath.Join(t.TempDir(), "terminal-failure-project")
	if err := os.MkdirAll(projectDir, 0o750); err != nil {
		t.Fatalf("create scan directory: %v", err)
	}
	jsonPath := filepath.Join(t.TempDir(), "result.json")

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	if err := read.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	originalStdout := os.Stdout
	os.Stdout = write
	defer func() {
		os.Stdout = originalStdout
		_ = write.Close()
	}()

	stderr := captureScanStderr(t, func() {
		exitCode, runErr := runSingleScan(context.Background(), scanSettings{
			Path:       projectDir,
			Mode:       string(scanner.ModeLocal),
			FailOn:     "CRITICAL",
			MaxDepth:   2,
			Timeout:    1,
			NoColor:    true,
			OutputJSON: jsonPath,
		})
		if runErr != nil {
			t.Fatalf("runSingleScan() error = %v, want terminal failure to remain diagnostic", runErr)
		}
		if exitCode != ExitOK {
			t.Fatalf("runSingleScan() exit = %d, want scan-derived %d", exitCode, ExitOK)
		}
	})
	if !strings.Contains(stderr, "error writing table output:") {
		t.Fatalf("stderr missing terminal-writer diagnostic:\n%s", stderr)
	}
	data, err := os.ReadFile(jsonPath) // #nosec G304 -- test reads its own generated artifact.
	if err != nil {
		t.Fatalf("read JSON artifact after terminal failure: %v", err)
	}
	var result domain.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode JSON artifact after terminal failure: %v", err)
	}
}

func TestWriteJSONFileReportsMarshalAndOpenFailures(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		result := &domain.ScanResult{ScannedAt: time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)}
		err := writeJSONFile(filepath.Join(t.TempDir(), "result.json"), result)
		if err == nil || !strings.Contains(err.Error(), "marshal JSON:") {
			t.Fatalf("writeJSONFile() error = %v, want marshal context", err)
		}
	})

	t.Run("open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "result\x00.json")
		err := writeJSONFile(path, &domain.ScanResult{ScannedAt: time.Now().UTC()})
		if err == nil || !strings.Contains(err.Error(), "write file ") {
			t.Fatalf("writeJSONFile() error = %v, want contextual open failure", err)
		}
		if strings.Contains(err.Error(), "create output directory") {
			t.Fatalf("writeJSONFile() failed before the intended open branch: %v", err)
		}
	})
}

func runtimeFailureScanFixture(t *testing.T, projectName string) (string, *sqlite.Store) {
	t.Helper()
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	projectDir := filepath.Join(t.TempDir(), projectName)
	if err := os.MkdirAll(projectDir, 0o750); err != nil {
		t.Fatalf("create scan directory: %v", err)
	}
	store, _ := newTestSQLiteStore(t, dbDir)
	return projectDir, store
}

func runtimeFailureScanSettings(projectDir string) scanSettings {
	return scanSettings{
		Path:             projectDir,
		Mode:             string(scanner.ModeLocal),
		FailOn:           "CRITICAL",
		MaxDepth:         2,
		Timeout:          1,
		Quiet:            true,
		OmitRepoMetadata: true,
	}
}

func seedRuntimeFailureHistory(t *testing.T, store *sqlite.Store, repo string, timestamps ...time.Time) {
	t.Helper()
	for i, timestamp := range timestamps {
		if _, err := store.DB().ExecContext(context.Background(), `
			INSERT INTO scan_history(repo_name, scanned_at, packages_count, findings_count, finding_ids, finding_severities)
			VALUES(?, ?, ?, 0, '[]', '[]')`, repo, timestamp.Format(time.RFC3339), 101+i); err != nil {
			t.Fatalf("seed scan-history row %d: %v", i, err)
		}
	}
}

func assertRuntimeFailureHistoryCount(t *testing.T, closedStore *sqlite.Store, want int) {
	t.Helper()
	store, err := sqlite.New(closedStore.Path())
	if err != nil {
		t.Fatalf("reopen history store: %v", err)
	}
	defer func() { _ = store.Close() }()
	var count int
	if err := store.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history`).Scan(&count); err != nil {
		t.Fatalf("count scan-history rows: %v", err)
	}
	if count != want {
		t.Fatalf("scan-history rows = %d, want %d (new successful row retained despite cleanup failure)", count, want)
	}
}

func assertBoundedRedactedDBWarning(t *testing.T, stderr, sensitivePath string) {
	t.Helper()
	if len(stderr) > 1024 || !strings.Contains(stderr, "warning: unable to open local database:") {
		t.Fatalf("database warning is missing or unbounded (%d bytes):\n%s", len(stderr), stderr)
	}
	if strings.Contains(stderr, sensitivePath) || strings.Contains(stderr, filepath.Dir(sensitivePath)) {
		t.Fatalf("database warning disclosed full private path %q:\n%s", sensitivePath, stderr)
	}
}
