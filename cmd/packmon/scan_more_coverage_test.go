package main

import (
	"context"
	"log/slog"
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
			logger := scanLogger(false)
			if !logger.Enabled(ctx, tt.enabledLevel) {
				t.Fatalf("scanLogger(%s) disabled %s level", tt.level, tt.wantEnabledName)
			}
			if logger.Enabled(ctx, tt.disabledLevel) {
				t.Fatalf("scanLogger(%s) enabled level below threshold", tt.level)
			}
		})
	}

	flagLogLevel = "DEBUG"
	quietLogger := scanLogger(true)
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
