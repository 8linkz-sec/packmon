package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewScanCmdRunEBranches(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	emptyDir := t.TempDir()
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{name: "list packages", args: []string{"--list-packages", emptyDir}, want: "No lock files found."},
		{name: "outdated", args: []string{"--outdated", emptyDir}, want: "No lock files found."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newScanCmd()
			cmd.SetArgs(tt.args)
			output := captureStdout(t, func() {
				if err := cmd.Execute(); err != nil {
					t.Fatalf("scan command error = %v", err)
				}
			})
			if !strings.Contains(output, tt.want) {
				t.Fatalf("scan command output = %q, want containing %q", output, tt.want)
			}
		})
	}

	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--mode", "local", emptyDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan command default branch error = %v", err)
	}
}

func TestRunSingleScanLocalChecksSBOMPackages(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	ctx := context.Background()
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, severity, summary)
		VALUES('GHSA-sbom|pypi|django', 'GHSA-sbom', 'pypi', 'django', 'HIGH', 'SBOM package advisory')`); err != nil {
		t.Fatalf("seed local vulnerability: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	projectDir := t.TempDir()
	sbomPath := filepath.Join(projectDir, "bom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[{"type":"library","name":"django","version":"4.2.11","purl":"pkg:pypi/django@4.2.11"}]
	}`), 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}

	output := captureStdout(t, func() {
		exitCode, err := runSingleScan(ctx, scanSettings{
			Path:      projectDir,
			Mode:      "local",
			FailOn:    "HIGH",
			MaxDepth:  2,
			Timeout:   1,
			NoColor:   true,
			SBOMFiles: []string{sbomPath},
		})
		if err != nil {
			t.Fatalf("runSingleScan(SBOM local) error = %v", err)
		}
		if exitCode != ExitBlocking {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitBlocking)
		}
	})
	if !strings.Contains(output, "GHSA-sbom") || !strings.Contains(output, "django") {
		t.Fatalf("SBOM local scan output missing finding:\n%s", output)
	}
}

func TestRunListPackagesIncludesSPDXSBOM(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	projectDir := t.TempDir()
	sbomPath := filepath.Join(projectDir, "sbom.spdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"spdxVersion":"SPDX-2.3",
		"packages":[{
			"name":"Django",
			"externalRefs":[{
				"referenceCategory":"PACKAGE-MANAGER",
				"referenceType":"purl",
				"referenceLocator":"pkg:pypi/django@4.2.11"
			}]
		}]
	}`), 0o600); err != nil {
		t.Fatalf("write SPDX SBOM: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runListPackages([]string{projectDir}, "", 2, true, []string{sbomPath}); err != nil {
			t.Fatalf("runListPackages(SBOM) error = %v", err)
		}
	})
	if !strings.Contains(output, "django") || !strings.Contains(output, "4.2.11") || !strings.Contains(output, "sbom.spdx.json") {
		t.Fatalf("list-packages SBOM output = %q", output)
	}
}

func TestRunOutdatedIncludesCycloneDXSBOM(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host+req.URL.EscapedPath() != "registry.npmjs.org/outdated/latest" {
			t.Fatalf("unexpected registry request: %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"version":"2.0.0"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}

	projectDir := t.TempDir()
	sbomPath := filepath.Join(projectDir, "bom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[{"type":"library","name":"outdated","version":"1.0.0","purl":"pkg:npm/outdated@1.0.0"}]
	}`), 0o600); err != nil {
		t.Fatalf("write CycloneDX SBOM: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runOutdated([]string{projectDir}, "npm", 2, []string{sbomPath}); err != nil {
			t.Fatalf("runOutdated(SBOM) error = %v", err)
		}
	})
	if !strings.Contains(output, "outdated") || !strings.Contains(output, "1.0.0") || !strings.Contains(output, "2.0.0") {
		t.Fatalf("outdated SBOM output = %q", output)
	}
}

func TestRunSingleScanSBOMErrors(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	projectDir := t.TempDir()
	missingPath := filepath.Join(projectDir, "missing.cdx.json")
	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:      projectDir,
		Mode:      "local",
		FailOn:    "CRITICAL",
		MaxDepth:  2,
		Timeout:   1,
		Quiet:     true,
		SBOMFiles: []string{missingPath},
	})
	if err != nil {
		t.Fatalf("runSingleScan(missing SBOM) error = %v", err)
	}
	if exitCode != ExitOperational {
		t.Fatalf("missing SBOM exitCode = %d, want %d", exitCode, ExitOperational)
	}

	badPath := filepath.Join(projectDir, "bad.cdx.json")
	if err := os.WriteFile(badPath, []byte(`{"bomFormat":"CycloneDX",`), 0o600); err != nil {
		t.Fatalf("write malformed SBOM: %v", err)
	}
	exitCode, err = runSingleScan(context.Background(), scanSettings{
		Path:      projectDir,
		Mode:      "local",
		FailOn:    "CRITICAL",
		MaxDepth:  2,
		Timeout:   1,
		Quiet:     true,
		SBOMFiles: []string{badPath},
	})
	if err != nil {
		t.Fatalf("runSingleScan(malformed SBOM) error = %v", err)
	}
	if exitCode != ExitParser {
		t.Fatalf("malformed SBOM exitCode = %d, want %d", exitCode, ExitParser)
	}
}

func TestRunListPackagesMalformedSBOMReturnsParserExit(t *testing.T) {
	projectDir := t.TempDir()
	badPath := filepath.Join(projectDir, "bad.cdx.json")
	if err := os.WriteFile(badPath, []byte(`{"bomFormat":"CycloneDX",`), 0o600); err != nil {
		t.Fatalf("write malformed SBOM: %v", err)
	}

	err := runListPackages([]string{projectDir}, "", 2, true, []string{badPath})
	if err == nil {
		t.Fatal("runListPackages(malformed SBOM) error = nil")
	}
	if code := exitCodeForError(err); code != ExitParser {
		t.Fatalf("exitCodeForError = %d, want %d; err=%v", code, ExitParser, err)
	}
}

func TestBuildScanTargetsValidationBranches(t *testing.T) {
	cfg := &cliConfig{Repos: []cliRepoConfig{{Name: "app", Path: "."}}}

	cases := []struct {
		name  string
		cfg   *cliConfig
		args  []string
		flags scanFlagValues
		want  string
	}{
		{name: "all and repo", cfg: cfg, flags: scanFlagValues{All: true, Repo: "app"}, want: "--all and --repo"},
		{name: "all and path", cfg: cfg, args: []string{"."}, flags: scanFlagValues{All: true}, want: "positional PATH cannot be used with --all"},
		{name: "repo and path", cfg: cfg, args: []string{"."}, flags: scanFlagValues{Repo: "app"}, want: "positional PATH cannot be used with --repo"},
		{name: "all without config", flags: scanFlagValues{All: true}, want: "no repositories configured"},
		{name: "repo without config", flags: scanFlagValues{Repo: "app"}, want: "no config file loaded"},
		{name: "repo missing", cfg: cfg, flags: scanFlagValues{Repo: "api"}, want: "configured repo \"api\" not found"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := buildScanTargets(tt.cfg, tt.args, tt.flags)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("buildScanTargets() = %+v, %v; want error containing %q", targets, err, tt.want)
			}
		})
	}
}

func TestResolveScanSettingsAPIKeyEnvAndValidationBranches(t *testing.T) {
	t.Setenv("PACKMON_TEST_API_KEY", "from-env")
	// #nosec G101 -- test fixture references an environment variable name, not a secret.
	repo := &cliRepoConfig{APIKeyEnv: "PACKMON_TEST_API_KEY"}
	settings, err := resolveScanSettings(newScanCmd(), nil, scanTarget{Path: ".", Repo: repo}, scanFlagValues{
		Mode:    "local",
		FailOn:  "CRITICAL",
		Timeout: 1,
	})
	if err != nil {
		t.Fatalf("resolveScanSettings(api key env) error = %v", err)
	}
	if settings.APIKey != "from-env" {
		t.Fatalf("APIKey = %q, want env value", settings.APIKey)
	}

	for _, tt := range []struct {
		name  string
		flags scanFlagValues
		want  string
	}{
		{name: "missing api key env", flags: scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: 1}, want: "api_key_env"},
		{name: "invalid mode", flags: scanFlagValues{Mode: "sideways", FailOn: "CRITICAL", Timeout: 1, APIKey: "flag"}, want: "invalid mode"},
		{name: "invalid fail on", flags: scanFlagValues{Mode: "local", FailOn: "SEVERE", Timeout: 1, APIKey: "flag"}, want: "invalid severity"},
		{name: "invalid timeout", flags: scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: 0, APIKey: "flag"}, want: "timeout must be greater than zero"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newScanCmd()
			switch tt.name {
			case "invalid mode":
				mustSetFlag(t, cmd, "mode", tt.flags.Mode)
			case "invalid fail on":
				mustSetFlag(t, cmd, "fail-on", tt.flags.FailOn)
			case "invalid timeout":
				mustSetFlag(t, cmd, "timeout", "0")
			}
			target := scanTarget{Path: "."}
			if tt.name == "missing api key env" {
				target.Repo = &cliRepoConfig{APIKeyEnv: "PACKMON_MISSING_API_KEY"}
			}
			_, err := resolveScanSettings(cmd, nil, target, tt.flags)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("resolveScanSettings() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestResolveScanSettingsUsesOutputAndLogConfig(t *testing.T) {
	cfg := &cliConfig{
		Output: cliOutputConfig{Format: "json", File: "configured.json"},
		Log:    cliLogConfig{Level: "WARN"},
	}
	cmd := newScanCmd()
	settings, err := resolveScanSettings(cmd, cfg, scanTarget{Path: "."}, scanFlagValues{
		Mode:    "local",
		FailOn:  "CRITICAL",
		Timeout: 1,
	})
	if err != nil {
		t.Fatalf("resolveScanSettings(config output) error = %v", err)
	}
	if settings.OutputJSON != "configured.json" || settings.LogLevel != "WARN" {
		t.Fatalf("settings = %+v, want configured JSON output and WARN log level", settings)
	}

	mustSetFlag(t, cmd, "output-json", "flag.json")
	settings, err = resolveScanSettings(cmd, cfg, scanTarget{Path: "."}, scanFlagValues{
		Mode:       "local",
		FailOn:     "CRITICAL",
		Timeout:    1,
		OutputJSON: "flag.json",
	})
	if err != nil {
		t.Fatalf("resolveScanSettings(flag output) error = %v", err)
	}
	if settings.OutputJSON != "flag.json" {
		t.Fatalf("OutputJSON = %q, want flag.json", settings.OutputJSON)
	}
}

func TestRunSingleScanReportPreparationErrorsBecomeOperational(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	projectDir := t.TempDir()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:        projectDir,
		Mode:        "local",
		FailOn:      "CRITICAL",
		MaxDepth:    2,
		Timeout:     1,
		Quiet:       true,
		OutputJSON:  filepath.Join(blocker, "result.json"),
		OutputSARIF: filepath.Join(blocker, "result.sarif"),
		OutputJUnit: filepath.Join(blocker, "result.xml"),
	})
	if err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if exitCode != ExitOperational {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOperational)
	}
}

func TestRunSingleScanReportErrorsOverrideFindingExit(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	ctx := context.Background()
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, severity, summary)
		VALUES('GHSA-report|npm|vulnerable', 'GHSA-report', 'npm', 'vulnerable', 'HIGH', 'local advisory')`); err != nil {
		t.Fatalf("seed local vulnerability: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version":"1.0.0"},
			"node_modules/vulnerable": {"version":"1.2.3"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	exitCode, err := runSingleScan(ctx, scanSettings{
		Path:       projectDir,
		Mode:       "local",
		FailOn:     "HIGH",
		MaxDepth:   2,
		Timeout:    1,
		Quiet:      true,
		OutputJSON: filepath.Join(blocker, "result.json"),
	})
	if err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if exitCode != ExitOperational {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOperational)
	}
}

func TestRunScanCommandReturnsTypedOperationalError(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	cmd := newScanCmd()
	cmd.SetContext(context.Background())
	mustSetFlag(t, cmd, "fail-on", "SEVERE")

	err := runScanCommand(cmd, []string{t.TempDir()}, scanFlagValues{
		Mode:     "local",
		FailOn:   "SEVERE",
		MaxDepth: 2,
		Timeout:  1,
	})
	var codeErr exitCodeError
	if !errors.As(err, &codeErr) {
		t.Fatalf("runScanCommand() error = %T %[1]v, want exitCodeError", err)
	}
	if codeErr.Code() != ExitOperational {
		t.Fatalf("exit code = %d, want %d", codeErr.Code(), ExitOperational)
	}
}

func TestScanSmallHelpersAndLogLevels(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	apiKey, err := resolveAPIKeyEnv("   ")
	if err != nil {
		t.Fatalf("resolveAPIKeyEnv(blank) error = %v", err)
	}
	if apiKey != "" {
		t.Fatalf("resolveAPIKeyEnv(blank) = %q, want empty", apiKey)
	}

	if err := ensureOutputDir("result.json"); err != nil {
		t.Fatalf("ensureOutputDir(current directory) error = %v", err)
	}

	ctx := context.Background()
	for _, tt := range []struct {
		level           string
		enabledLevel    slog.Level
		disabledLevel   slog.Level
		wantEnabledName string
	}{
		{level: "DEBUG", enabledLevel: slog.LevelDebug, disabledLevel: slog.Level(-8), wantEnabledName: "debug"},
		{level: "WARN", enabledLevel: slog.LevelWarn, disabledLevel: slog.LevelInfo, wantEnabledName: "warn"},
		{level: "ERROR", enabledLevel: slog.LevelError, disabledLevel: slog.LevelWarn, wantEnabledName: "error"},
	} {
		t.Run(tt.level, func(t *testing.T) {
			flagLogLevel = tt.level
			logger := scanLogger(false, tt.level)
			if !logger.Enabled(ctx, tt.enabledLevel) {
				t.Fatalf("scanLogger(%s) disabled %s level", tt.level, tt.wantEnabledName)
			}
			if logger.Enabled(ctx, tt.disabledLevel) {
				t.Fatalf("scanLogger(%s) enabled level below threshold", tt.level)
			}
		})
	}

	flagLogLevel = "DEBUG"
	quietLogger := scanLogger(true, "DEBUG")
	if !quietLogger.Enabled(ctx, slog.LevelError) || quietLogger.Enabled(ctx, slog.LevelWarn) {
		t.Fatal("quiet scanLogger did not raise threshold to error")
	}
}

func TestRunSingleScanAutoModeWithNoLockFiles(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	scanDir := t.TempDir()
	exitCode, err := runSingleScan(context.Background(), scanSettings{
		Path:     scanDir,
		Mode:     "",
		FailOn:   "CRITICAL",
		MaxDepth: 1,
		Timeout:  1,
		Quiet:    true,
	})
	if err != nil {
		t.Fatalf("runSingleScan(auto empty mode) error = %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}
}

func TestRunSingleScanLocalUsesSeededAdvisoryData(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	ctx := context.Background()
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, severity, summary)
		VALUES('GHSA-local|npm|vulnerable', 'GHSA-local', 'npm', 'vulnerable', 'HIGH', 'local advisory')`); err != nil {
		t.Fatalf("seed local vulnerability: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"version":"1.0.0"},
			"node_modules/vulnerable": {"version":"1.2.3"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}

	output := captureStdout(t, func() {
		exitCode, err := runSingleScan(ctx, scanSettings{
			Path:     projectDir,
			Mode:     "local",
			FailOn:   "CRITICAL",
			MaxDepth: 2,
			Timeout:  1,
			NoColor:  true,
		})
		if err != nil {
			t.Fatalf("runSingleScan(local advisory) error = %v", err)
		}
		if exitCode != ExitUnderThreshold {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitUnderThreshold)
		}
	})
	if !strings.Contains(output, "GHSA-local") || !strings.Contains(output, "vulnerable") {
		t.Fatalf("local advisory output missing finding:\n%s", output)
	}
}

func TestRunSingleScanWarnsAboutPartialParseErrors(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if _, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, severity, summary)
		VALUES('GHSA-parse-warn-seed|npm|unrelated', 'GHSA-parse-warn-seed', 'npm', 'unrelated', 'LOW', 'unrelated advisory')`); err != nil {
		t.Fatalf("seed unrelated advisory: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {"": {"version":"1.0.0"}, "node_modules/prod": {"version":"1.0.0"}}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "pnpm-lock.yaml"), []byte(`{{{not yaml`), 0o600); err != nil {
		t.Fatalf("write pnpm-lock: %v", err)
	}

	stderr := captureStderr(t, func() {
		exitCode, err := runSingleScan(context.Background(), scanSettings{
			Path:     projectDir,
			Mode:     "local",
			FailOn:   "CRITICAL",
			MaxDepth: 2,
			Timeout:  1,
			NoColor:  true,
		})
		if err != nil {
			t.Fatalf("runSingleScan() error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
		}
	})
	if !strings.Contains(stderr, "warning: parse error in pnpm-lock.yaml") {
		t.Fatalf("stderr missing parse warning:\n%s", stderr)
	}

	quietStderr := captureStderr(t, func() {
		exitCode, err := runSingleScan(context.Background(), scanSettings{
			Path:     projectDir,
			Mode:     "local",
			FailOn:   "CRITICAL",
			MaxDepth: 2,
			Timeout:  1,
			Quiet:    true,
		})
		if err != nil {
			t.Fatalf("quiet runSingleScan() error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("quiet exitCode = %d, want %d", exitCode, ExitOK)
		}
	})
	if strings.Contains(quietStderr, "parse error") {
		t.Fatalf("quiet stderr contains parse warning:\n%s", quietStderr)
	}
}
