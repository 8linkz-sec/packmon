package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db/sqlite"
	"github.com/spf13/cobra"
)

func TestResolveScanSettingsPrecedenceAndValidation(t *testing.T) {
	t.Setenv("PACKMON_SERVER", "https://env.example")
	t.Setenv("PACKMON_API_KEY", "env-key")
	t.Setenv("PACKMON_MODE", "local")
	t.Setenv("PACKMON_FAIL_ON", "MEDIUM")
	t.Setenv("PACKMON_TIMEOUT", "44")
	t.Setenv("PACKMON_ECOSYSTEMS", "go,npm")
	t.Setenv("PACKMON_WEBHOOK_URL", "https://env.example/hook")
	t.Setenv("PACKMON_WEBHOOK_SECRET", "env-secret")
	t.Setenv("PACKMON_CA_CERT", "env-ca.pem")
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "true")
	t.Setenv("PACKMON_REQUIRE_REMOTE", "true")

	includeDev := true
	repoIncludeDev := false
	cfg := &cliConfig{
		Server:            "https://config.example",
		APIKey:            "config-key",
		Mode:              "remote",
		FailOn:            "HIGH",
		Timeout:           31,
		Ecosystems:        []string{"pypi"},
		IncludeDev:        &includeDev,
		CACert:            "config-ca.pem",
		InsecureAllowHTTP: &includeDev,
		RequireRemote:     &includeDev,
		Webhook: cliWebhookConfig{
			URL:    "https://config.example/hook",
			Secret: "config-secret",
		},
	}
	repo := &cliRepoConfig{
		Server:     "https://repo.example",
		APIKey:     "repo-key",
		Mode:       "auto",
		FailOn:     "LOW",
		Timeout:    32,
		Ecosystems: []string{"cargo"},
		IncludeDev: &repoIncludeDev,
		Webhook: cliWebhookConfig{
			URL:    "https://repo.example/hook",
			Secret: "repo-secret",
		},
	}

	cmd := newScanCmd()
	mustSetFlag(t, cmd, "mode", "remote")
	mustSetFlag(t, cmd, "server", "https://flag.example")
	mustSetFlag(t, cmd, "api-key", "flag-key")
	mustSetFlag(t, cmd, "fail-on", "CRITICAL")
	mustSetFlag(t, cmd, "ecosystems", "gem,composer")
	mustSetFlag(t, cmd, "timeout", "55")
	mustSetFlag(t, cmd, "include-dev", "true")
	mustSetFlag(t, cmd, "webhook-url", "https://flag.example/hook")
	mustSetFlag(t, cmd, "webhook-secret", "flag-secret")
	mustSetFlag(t, cmd, "cacert", "flag-ca.pem")
	mustSetFlag(t, cmd, "insecure-allow-http", "false")
	mustSetFlag(t, cmd, "require-remote", "false")

	settings, err := resolveScanSettings(cmd, cfg, scanTarget{Name: "repo", Path: ".", Repo: repo}, scanFlagValues{
		Mode:          "remote",
		Server:        "https://flag.example",
		APIKey:        "flag-key",
		FailOn:        "CRITICAL",
		Ecosystems:    "gem,composer",
		MaxDepth:      9,
		Timeout:       55,
		IncludeDev:    true,
		OutputJSON:    "result.json",
		OutputSARIF:   "result.sarif",
		OutputJUnit:   "result.xml",
		WebhookURL:    "https://flag.example/hook",
		WebhookSecret: "flag-secret",
		CACert:        "flag-ca.pem",
		InsecureHTTP:  false,
		RequireRemote: false,
		Quiet:         true,
		NoColor:       true,
	})
	if err != nil {
		t.Fatalf("resolve scan settings: %v", err)
	}

	if settings.ServerURL != "https://flag.example" || settings.APIKey != "flag-key" || settings.Mode != "remote" {
		t.Fatalf("flag precedence not applied: %+v", settings)
	}
	if settings.FailOn != "CRITICAL" || settings.Timeout != 55 || !settings.IncludeDev {
		t.Fatalf("flag scalar settings not applied: %+v", settings)
	}
	if got := strings.Join(settings.Ecosystems, ","); got != "gem,composer" {
		t.Fatalf("ecosystems = %q", got)
	}
	if settings.WebhookURL != "https://flag.example/hook" || settings.WebhookSecret != "flag-secret" || settings.CACertFile != "flag-ca.pem" {
		t.Fatalf("flag webhook/tls settings not applied: %+v", settings)
	}
	if settings.InsecureHTTP || settings.RequireRemote {
		t.Fatalf("flag bool overrides not applied: insecure=%v requireRemote=%v", settings.InsecureHTTP, settings.RequireRemote)
	}
	if settings.OutputJSON != "result.json" || settings.OutputSARIF != "result.sarif" || settings.OutputJUnit != "result.xml" {
		t.Fatalf("output paths not applied: %+v", settings)
	}
}

func TestRunScanCommandRejectsOutputFilesForMultipleTargets(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	if err := os.WriteFile(".packmon.yaml", []byte(`
repos:
  - name: app
    path: "."
  - name: api
    path: "."
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newScanCmd()
	err := runScanCommand(cmd, nil, scanFlagValues{All: true, OutputJSON: "result.json"})
	if err == nil {
		t.Fatal("runScanCommand multiple targets with output file error = nil")
	}
	if !strings.Contains(err.Error(), "can only be used when scanning a single target") {
		t.Fatalf("runScanCommand error = %v", err)
	}
}

func TestOpenLocalSQLiteStoreReportsAdvisoryAvailability(t *testing.T) {
	dbDir := t.TempDir()
	store, dbPath := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close empty store: %v", err)
	}

	emptyStore, advisoryDataAvailable, err := openLocalSQLiteStore(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open empty local store: %v", err)
	}
	if advisoryDataAvailable {
		t.Fatal("advisoryDataAvailable(empty) = true")
	}
	if err := emptyStore.Close(); err != nil {
		t.Fatalf("close empty opened store: %v", err)
	}

	seedStore, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	_, err = seedStore.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, severity)
		VALUES('GHSA-open|npm|pkg', 'GHSA-open', 'npm', 'pkg', 'LOW')`)
	if err != nil {
		t.Fatalf("seed advisory data: %v", err)
	}
	if err := seedStore.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}

	seededStore, advisoryDataAvailable, err := openLocalSQLiteStore(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open seeded local store: %v", err)
	}
	defer closeSilently(seededStore)
	if !advisoryDataAvailable {
		t.Fatal("advisoryDataAvailable(seeded) = false")
	}
}

func TestRunListPackagesPrintsDetectedPackages(t *testing.T) {
	projectDir := t.TempDir()
	lockContent := `{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "^4.17.15"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runListPackages([]string{projectDir}, "npm", 10, true); err != nil {
			t.Fatalf("run list packages: %v", err)
		}
	})
	if !strings.Contains(output, "lodash") || !strings.Contains(output, "4.17.15") || !strings.Contains(output, "1 package(s) found") {
		t.Fatalf("list packages output = %q", output)
	}
}

func TestRunSingleScanRecordsHistoryForCleanLocalScan(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	scanDir := filepath.Join(t.TempDir(), "empty-project")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:     scanDir,
		Mode:     "local",
		FailOn:   "CRITICAL",
		MaxDepth: 2,
		Timeout:  1,
		Quiet:    true,
	})
	if err != nil {
		t.Fatalf("run single scan: %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}

	verifyStore, _ := newTestSQLiteStore(t, dbDir)
	var count int
	if err := verifyStore.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM scan_history`).Scan(&count); err != nil {
		t.Fatalf("count scan history: %v", err)
	}
	if count != 1 {
		t.Fatalf("scan history rows = %d, want 1", count)
	}
}

func mustSetFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("set flag %s: %v", name, err)
	}
}
