package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewScanCmdRunEBranches(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	emptyDir := t.TempDir()
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{name: "list packages", args: []string{"--list-packages", emptyDir}, want: "No lockfiles found."},
		{name: "outdated", args: []string{"--outdated", emptyDir}, want: "No lockfiles found."},
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
		if err := runListPackagesWithSettings(scanSettings{
			Path:       projectDir,
			MaxDepth:   2,
			SBOMFiles:  []string{sbomPath},
			IncludeDev: true,
		}); err != nil {
			t.Fatalf("runListPackagesWithSettings(SBOM) error = %v", err)
		}
	})
	if !strings.Contains(output, "django") || !strings.Contains(output, "4.2.11") || !strings.Contains(output, "sbom.spdx.json") {
		t.Fatalf("list-packages SBOM output = %q", output)
	}
}

func TestRunListPackagesSanitizesTerminalControlText(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	projectDir := t.TempDir()
	sbomPath := filepath.Join(projectDir, "sbom.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
		"bomFormat":"CycloneDX",
		"components":[{
			"type":"library",
			"name":"fallback",
			"version":"1.0.0",
			"purl":"pkg:npm/pkg%1B%5D8%3B%3Bhttps%3A%2F%2Fevil.example%07%0A%3A%3Awarning%3A%3Apkg@1.0.0%0Dspoof"
		}]
	}`), 0o600); err != nil {
		t.Fatalf("write CycloneDX SBOM: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runListPackagesWithSettings(scanSettings{
			Path:       projectDir,
			MaxDepth:   2,
			SBOMFiles:  []string{sbomPath},
			IncludeDev: true,
		}); err != nil {
			t.Fatalf("runListPackagesWithSettings(SBOM) error = %v", err)
		}
	})

	for _, blocked := range []string{"\x1b", "\a", "\r", "\n::warning::"} {
		if strings.Contains(output, blocked) {
			t.Fatalf("list-packages output contains raw terminal control %q:\n%s", blocked, output)
		}
	}
	if !strings.Contains(output, `\x1B`) || !strings.Contains(output, `\n::warning::pkg`) {
		t.Fatalf("list-packages output missing sanitized controls:\n%s", output)
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
		if err := runOutdatedForTest([]string{projectDir}, "npm", 2, []string{sbomPath}); err != nil {
			t.Fatalf("runOutdated(SBOM) error = %v", err)
		}
	})
	if !strings.Contains(output, "outdated") || !strings.Contains(output, "1.0.0") || !strings.Contains(output, "2.0.0") {
		t.Fatalf("outdated SBOM output = %q", output)
	}
}

func TestRunOutdatedKeepsPackageVersionsDistinct(t *testing.T) {
	originalClient := registryClient
	t.Cleanup(func() { registryClient = originalClient })
	registryClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host+req.URL.EscapedPath() != "registry.npmjs.org/dupe/latest" {
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
		"components":[
			{"type":"library","name":"dupe","version":"2.0.0","purl":"pkg:npm/dupe@2.0.0"},
			{"type":"library","name":"dupe","version":"1.0.0","purl":"pkg:npm/dupe@1.0.0"}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write CycloneDX SBOM: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runOutdatedForTest([]string{projectDir}, "npm", 2, []string{sbomPath}); err != nil {
			t.Fatalf("runOutdated(SBOM duplicate versions) error = %v", err)
		}
	})
	for _, want := range []string{"dupe", "1.0.0", "2.0.0", "1 outdated, 1 up to date (2 total)"} {
		if !strings.Contains(output, want) {
			t.Fatalf("outdated duplicate-version output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "All 1 packages are up to date") {
		t.Fatalf("outdated duplicate-version output collapsed versions:\n%s", output)
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

	err := runListPackagesWithSettings(scanSettings{
		Path:       projectDir,
		MaxDepth:   2,
		SBOMFiles:  []string{badPath},
		IncludeDev: true,
	})
	if err == nil {
		t.Fatal("runListPackagesWithSettings(malformed SBOM) error = nil")
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
		{name: "negative max depth", flags: scanFlagValues{Mode: "local", FailOn: "CRITICAL", MaxDepth: -1, Timeout: 1, APIKey: "flag"}, want: "max-depth must be zero or greater"},
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
		Log:    cliLogConfig{Level: "WARN", Format: "json"},
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
	if settings.OutputJSON != "configured.json" || settings.LogLevel != "WARN" || settings.LogFormat != "json" {
		t.Fatalf("settings = %+v, want configured JSON output, WARN log level, and JSON log format", settings)
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

func TestResolveScanSettingsLogLevelOverridesConfig(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	cfg := &cliConfig{Log: cliLogConfig{Level: "WARN"}}
	target := scanTarget{Path: "."}
	flags := scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: 1}
	originalLogLevel := flagLogLevel
	t.Cleanup(func() { flagLogLevel = originalLogLevel })

	t.Setenv("PACKMON_LOG_LEVEL", "debug")
	flagLogLevel = "debug"
	settings, err := resolveScanSettings(newScanCmd(), cfg, target, flags)
	if err != nil {
		t.Fatalf("resolveScanSettings(env log level) error = %v", err)
	}
	if settings.LogLevel != "DEBUG" {
		t.Fatalf("LogLevel = %q, want env DEBUG over config WARN", settings.LogLevel)
	}

	cmd := newScanCmd()
	cmd.Flags().String("log-level", "INFO", "")
	mustSetFlag(t, cmd, "log-level", "ERROR")
	flagLogLevel = "ERROR"
	settings, err = resolveScanSettings(cmd, cfg, target, flags)
	if err != nil {
		t.Fatalf("resolveScanSettings(flag log level) error = %v", err)
	}
	if settings.LogLevel != "ERROR" {
		t.Fatalf("LogLevel = %q, want flag ERROR over env/config", settings.LogLevel)
	}
}

func TestResolveScanSettingsRejectsInvalidLogLevelInputs(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	originalLogLevel := flagLogLevel
	t.Cleanup(func() { flagLogLevel = originalLogLevel })

	target := scanTarget{Path: "."}
	flags := scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: 1}

	t.Run("environment", func(t *testing.T) {
		t.Setenv("PACKMON_LOG_LEVEL", "verbose")
		flagLogLevel = "INFO"

		_, err := resolveScanSettings(newScanCmd(), nil, target, flags)
		if err == nil || !strings.Contains(err.Error(), "PACKMON_LOG_LEVEL") {
			t.Fatalf("resolveScanSettings() error = %v, want invalid PACKMON_LOG_LEVEL rejection", err)
		}
	})

	t.Run("flag", func(t *testing.T) {
		t.Setenv("PACKMON_LOG_LEVEL", "")
		cmd := newScanCmd()
		cmd.Flags().String("log-level", "INFO", "")
		mustSetFlag(t, cmd, "log-level", "verbose")
		flagLogLevel = "verbose"

		_, err := resolveScanSettings(cmd, nil, target, flags)
		if err == nil || !strings.Contains(err.Error(), "--log-level") {
			t.Fatalf("resolveScanSettings() error = %v, want invalid --log-level rejection", err)
		}
	})

	t.Run("flag overrides invalid environment", func(t *testing.T) {
		t.Setenv("PACKMON_LOG_LEVEL", "verbose")
		cmd := newScanCmd()
		cmd.Flags().String("log-level", "INFO", "")
		mustSetFlag(t, cmd, "log-level", "ERROR")
		flagLogLevel = "ERROR"

		settings, err := resolveScanSettings(cmd, nil, target, flags)
		if err != nil {
			t.Fatalf("resolveScanSettings() error = %v, want valid --log-level to override invalid env", err)
		}
		if settings.LogLevel != "ERROR" {
			t.Fatalf("LogLevel = %q, want ERROR", settings.LogLevel)
		}
	})
}

func TestResolveScanSettingsRejectsInvalidLogFormatEnv(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	target := scanTarget{Path: "."}
	flags := scanFlagValues{Mode: "local", FailOn: "CRITICAL", Timeout: 1}
	t.Setenv("PACKMON_LOG_FORMAT", "xml")

	_, err := resolveScanSettings(newScanCmd(), nil, target, flags)
	if err == nil || !strings.Contains(err.Error(), "PACKMON_LOG_FORMAT") {
		t.Fatalf("resolveScanSettings() error = %v, want invalid PACKMON_LOG_FORMAT rejection", err)
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
	writePackageLockForScanCommand(t, projectDir, "vulnerable", "1.2.3")
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
			logger := scanLogger(false, tt.level, "text")
			if !logger.Enabled(ctx, tt.enabledLevel) {
				t.Fatalf("scanLogger(%s) disabled %s level", tt.level, tt.wantEnabledName)
			}
			if logger.Enabled(ctx, tt.disabledLevel) {
				t.Fatalf("scanLogger(%s) enabled level below threshold", tt.level)
			}
		})
	}

	flagLogLevel = "DEBUG"
	quietLogger := scanLogger(true, "DEBUG", "text")
	if !quietLogger.Enabled(ctx, slog.LevelError) || quietLogger.Enabled(ctx, slog.LevelWarn) {
		t.Fatal("quiet scanLogger did not raise threshold to error")
	}

	var jsonLogs bytes.Buffer
	jsonLogger := newScanLogger(&jsonLogs, false, "INFO", "json")
	jsonLogger.Info("hello", slog.String("component", "scan"))
	if !strings.Contains(jsonLogs.String(), `"msg":"hello"`) || !strings.Contains(jsonLogs.String(), `"component":"scan"`) {
		t.Fatalf("json scan logger output = %s", jsonLogs.String())
	}

	var textLogs bytes.Buffer
	textLogger := newScanLogger(&textLogs, false, "INFO", "text")
	textLogger.Info("hello", slog.String("component", "scan"))
	if strings.Contains(textLogs.String(), `"msg":"hello"`) || !strings.Contains(textLogs.String(), "msg=hello") {
		t.Fatalf("text scan logger output = %s", textLogs.String())
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
	writePackageLockForScanCommand(t, projectDir, "vulnerable", "1.2.3")

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
	writePackageLockForScanCommand(t, projectDir, "prod", "1.0.0")
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
		if exitCode != ExitParser {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitParser)
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
		if exitCode != ExitParser {
			t.Fatalf("quiet exitCode = %d, want %d", exitCode, ExitParser)
		}
	})
	if !strings.Contains(quietStderr, "warning: parse error in pnpm-lock.yaml") {
		t.Fatalf("quiet stderr missing parse warning:\n%s", quietStderr)
	}
}

func TestRunSingleScanQuietWarnsAboutAutoFallback(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if _, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, severity, summary)
		VALUES('GHSA-auto-fallback-seed|npm|unrelated', 'GHSA-auto-fallback-seed', 'npm', 'unrelated', 'LOW', 'unrelated advisory')`); err != nil {
		t.Fatalf("seed local advisory: %v", err)
	}
	if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	projectDir := t.TempDir()
	writePackageLockForScanCommand(t, projectDir, "prod", "1.0.0")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverURL := "http://" + ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	stderr := captureStderr(t, func() {
		exitCode, err := runSingleScan(context.Background(), scanSettings{
			Path:         projectDir,
			Mode:         "auto",
			ServerURL:    serverURL,
			InsecureHTTP: true,
			FailOn:       "CRITICAL",
			MaxDepth:     2,
			Timeout:      1,
			Quiet:        true,
		})
		if err != nil {
			t.Fatalf("runSingleScan() error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
		}
	})
	if !strings.Contains(stderr, "warning: remote server unreachable, scanned against local database") {
		t.Fatalf("quiet stderr missing auto-fallback warning:\n%s", stderr)
	}
}

func TestRunScanPipelineRemoteSkipsLocalSQLiteWhenHistoryDisabled(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	projectDir := t.TempDir()
	writePackageLockForScanCommand(t, projectDir, "prod", "1.0.0")

	badDBRoot := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(badDBRoot, []byte("file, not directory"), 0o600); err != nil {
		t.Fatalf("write bad db root: %v", err)
	}
	t.Setenv("PACKMON_DB_PATH", badDBRoot)
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")

	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"scan_id":"remote-scan",
			"mode":"remote",
			"scanned_at":"2026-06-22T12:00:00Z",
			"duration_ms":1,
			"packages_scanned":1,
			"findings_count":0,
			"findings_blocking":false,
			"feed_status":"healthy",
			"summary":{"by_severity":{},"by_type":{},"by_source":{}},
			"findings":[],
			"feed_versions":{},
			"manual_advisories_count":0
		}`))
	}))
	defer server.Close()

	var resultMode string
	stderr := captureStderr(t, func() {
		result, _, exitCode, _, _, err := runScanPipeline(context.Background(), scanSettings{
			Path:         projectDir,
			Mode:         "remote",
			ServerURL:    server.URL,
			FailOn:       "CRITICAL",
			MaxDepth:     3,
			Timeout:      2,
			InsecureHTTP: true,
			Quiet:        true,
		})
		if err != nil {
			t.Fatalf("runScanPipeline(remote) error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("exitCode = %d, want %d; result=%+v", exitCode, ExitOK, result)
		}
		resultMode = string(result.Mode)
	})

	if strings.Contains(stderr, "unable to open local database") {
		t.Fatalf("remote scan opened local SQLite despite disabled history:\n%s", stderr)
	}
	if resultMode != "remote" {
		t.Fatalf("result mode = %q, want remote", resultMode)
	}
	select {
	case <-requests:
	default:
		t.Fatal("remote check server was not called")
	}
}

func TestRunScanPipelineAutoRemoteSuccessDoesNotOpenLocalFallbackDB(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	projectDir := t.TempDir()
	writePackageLockForScanCommand(t, projectDir, "prod", "1.0.0")

	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "packmon.db")
	t.Setenv("PACKMON_DB_PATH", dbDir)
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")

	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"scan_id":"remote-scan",
			"mode":"remote",
			"scanned_at":"2026-06-22T12:00:00Z",
			"duration_ms":1,
			"packages_scanned":1,
			"findings_count":0,
			"findings_blocking":false,
			"feed_status":"healthy",
			"summary":{"by_severity":{},"by_type":{},"by_source":{}},
			"findings":[],
			"feed_versions":{},
			"manual_advisories_count":0
		}`))
	}))
	defer server.Close()

	var resultMode string
	stderr := captureStderr(t, func() {
		result, _, exitCode, _, _, err := runScanPipeline(context.Background(), scanSettings{
			Path:         projectDir,
			Mode:         "auto",
			ServerURL:    server.URL,
			FailOn:       "CRITICAL",
			MaxDepth:     3,
			Timeout:      2,
			InsecureHTTP: true,
			Quiet:        true,
		})
		if err != nil {
			t.Fatalf("runScanPipeline(auto) error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("exitCode = %d, want %d; result=%+v", exitCode, ExitOK, result)
		}
		resultMode = string(result.Mode)
	})

	if strings.Contains(stderr, "unable to open local database") {
		t.Fatalf("auto remote success opened local SQLite fallback:\n%s", stderr)
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Fatalf("auto remote success initialized local fallback database at %s", dbPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat local fallback database: %v", err)
	}
	if resultMode != "remote" {
		t.Fatalf("result mode = %q, want remote", resultMode)
	}
	select {
	case <-requests:
	default:
		t.Fatal("remote check server was not called")
	}
}

func TestRunScanPipelineLocalDatabaseWarningRedactsPath(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	projectDir := t.TempDir()
	writePackageLockForScanCommand(t, projectDir, "prod", "1.0.0")

	badDBRoot := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(badDBRoot, []byte("file, not directory"), 0o600); err != nil {
		t.Fatalf("write bad db root: %v", err)
	}
	t.Setenv("PACKMON_DB_PATH", badDBRoot)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"scan_id":"remote-scan",
			"mode":"remote",
			"scanned_at":"2026-06-22T12:00:00Z",
			"duration_ms":1,
			"packages_scanned":1,
			"findings_count":0,
			"findings_blocking":false,
			"feed_status":"healthy",
			"summary":{"by_severity":{},"by_type":{},"by_source":{}},
			"findings":[],
			"feed_versions":{},
			"manual_advisories_count":0
		}`))
	}))
	defer server.Close()

	stderr := captureStderr(t, func() {
		result, _, exitCode, _, _, err := runScanPipeline(context.Background(), scanSettings{
			Path:         projectDir,
			Mode:         "remote",
			ServerURL:    server.URL,
			FailOn:       "CRITICAL",
			MaxDepth:     3,
			Timeout:      2,
			InsecureHTTP: true,
			Quiet:        true,
		})
		if err != nil {
			t.Fatalf("runScanPipeline(remote) error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("exitCode = %d, want %d; result=%+v", exitCode, ExitOK, result)
		}
	})

	if !strings.Contains(stderr, "warning: unable to open local database:") {
		t.Fatalf("stderr missing local database warning:\n%s", stderr)
	}
	for _, leaked := range []string{badDBRoot, "not-a-directory", "packmon.db"} {
		if strings.Contains(stderr, leaked) {
			t.Fatalf("stderr leaked local database path marker %q:\n%s", leaked, stderr)
		}
	}
	if !strings.Contains(stderr, "(redacted-path)") {
		t.Fatalf("stderr missing redacted path marker:\n%s", stderr)
	}
}

func TestRunScanPipelineWarnsWhenFailOnNoneIsEffective(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	projectDir := t.TempDir()
	writePackageLockForScanCommand(t, projectDir, "prod", "1.0.0")

	t.Setenv("PACKMON_HISTORY_ENABLED", "false")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"scan_id":"remote-scan",
			"mode":"remote",
			"scanned_at":"2026-06-22T12:00:00Z",
			"duration_ms":1,
			"packages_scanned":1,
			"findings_count":0,
			"findings_blocking":false,
			"feed_status":"healthy",
			"summary":{"by_severity":{},"by_type":{},"by_source":{}},
			"findings":[],
			"feed_versions":{},
			"manual_advisories_count":0
		}`))
	}))
	defer server.Close()

	stderr := captureStderr(t, func() {
		_, _, exitCode, _, _, err := runScanPipeline(context.Background(), scanSettings{
			Path:         projectDir,
			Mode:         "remote",
			ServerURL:    server.URL,
			FailOn:       "NONE",
			MaxDepth:     3,
			Timeout:      2,
			InsecureHTTP: true,
			Quiet:        true,
		})
		if err != nil {
			t.Fatalf("runScanPipeline(remote NONE) error = %v", err)
		}
		if exitCode != ExitOK {
			t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
		}
	})

	for _, want := range []string{
		"warning: fail_on NONE disables vulnerability blocking only",
		"malicious and active supply-chain risk findings still block",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr)
		}
	}
}
