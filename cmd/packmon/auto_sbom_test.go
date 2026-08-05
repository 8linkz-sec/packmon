package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/sbomgen"
	"github.com/spf13/cobra"
)

func TestValidateAutoSBOMFlags(t *testing.T) {
	cases := []struct {
		name  string
		auto  autoSBOMFlags
		flags scanFlagValues
		args  []string
		want  string
	}{
		{name: "install tools requires auto", auto: autoSBOMFlags{InstallTools: true}, want: "require --auto-sbom"},
		{name: "keep requires auto", auto: autoSBOMFlags{KeepSBOM: "out"}, want: "require --auto-sbom"},
		{name: "sbom only requires auto", auto: autoSBOMFlags{SBOMOnly: true}, want: "require --auto-sbom"},
		{name: "all incompatible", auto: autoSBOMFlags{Enabled: true}, flags: scanFlagValues{All: true}, want: "cannot be combined with --all"},
		{name: "multiple args incompatible", auto: autoSBOMFlags{Enabled: true}, args: []string{"a", "b"}, want: "exactly one target"},
		{name: "sbom only rejects raw sbom", auto: autoSBOMFlags{Enabled: true, SBOMOnly: true}, flags: scanFlagValues{SBOMFiles: []string{"manual.json"}}, want: "cannot be combined with --sbom"},
		{name: "sbom only rejects report", auto: autoSBOMFlags{Enabled: true, SBOMOnly: true}, flags: scanFlagValues{OutputJSON: "out.json"}, want: "report output"},
		{name: "sbom only rejects webhook", auto: autoSBOMFlags{Enabled: true, SBOMOnly: true}, flags: scanFlagValues{WebhookURL: "https://example.invalid/hook"}, want: "webhook"},
		{name: "valid", auto: autoSBOMFlags{Enabled: true}, args: []string{"."}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAutoSBOMFlags(tt.auto, tt.flags, tt.args)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("validateAutoSBOMFlags: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateAutoSBOMOnlySettingsRejectsResolvedOutputs(t *testing.T) {
	cases := map[string]scanSettings{
		"json":    {OutputJSON: "configured.json"},
		"sarif":   {OutputSARIF: "configured.sarif"},
		"junit":   {OutputJUnit: "configured.xml"},
		"html":    {OutputHTML: "configured.html"},
		"webhook": {WebhookURL: "https://example.invalid/hook"},
		"secret":  {WebhookSecret: "secret"},
		"sbom":    {SBOMFiles: []string{"manual.cdx.json"}},
	}
	for name, settings := range cases {
		if err := validateAutoSBOMOnlySettings(settings); err == nil {
			t.Errorf("%s should be rejected in --sbom-only", name)
		}
	}
	if err := validateAutoSBOMOnlySettings(scanSettings{}); err != nil {
		t.Fatalf("empty settings should be valid: %v", err)
	}
}

func TestBuildAutoSBOMConfigUsesResolvedSettings(t *testing.T) {
	settings := scanSettings{
		Path:       filepath.Clean("/repo/project"),
		Ecosystems: []string{"go", "npm"},
		IncludeDev: true,
		MaxDepth:   4,
		Quiet:      true,
		LogLevel:   "WARN",
		Timeout:    75,
	}

	cfg := buildAutoSBOMConfig(settings, autoSBOMFlags{Enabled: true, SBOMOnly: true})
	if cfg.Target != settings.Path {
		t.Fatalf("Target = %q, want %q", cfg.Target, settings.Path)
	}
	if len(cfg.Ecosystems) != 2 || cfg.Ecosystems[0] != domain.EcosystemGo || cfg.Ecosystems[1] != domain.EcosystemNPM {
		t.Fatalf("Ecosystems = %v, want [%s %s]", cfg.Ecosystems, domain.EcosystemGo, domain.EcosystemNPM)
	}
	if !cfg.IncludeDev || cfg.MaxDepth != 4 {
		t.Fatalf("IncludeDev/MaxDepth not copied from resolved settings: %+v", cfg)
	}
	if cfg.Timeout != 75*time.Second {
		t.Fatalf("Timeout = %s, want 75s", cfg.Timeout)
	}
	if cfg.KeepSBOMDir != "." {
		t.Fatalf("--sbom-only without --keep-sbom must keep files in cwd, got %q", cfg.KeepSBOMDir)
	}

	cfg = buildAutoSBOMConfig(settings, autoSBOMFlags{Enabled: true, KeepSBOM: "out"})
	if cfg.KeepSBOMDir != "out" {
		t.Fatalf("--keep-sbom dir = %q, want out", cfg.KeepSBOMDir)
	}
}

func TestResolveAutoSBOMRunUsesSingleResolvedTarget(t *testing.T) {
	root := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	run, err := resolveAutoSBOMRun(cmd, []string{root}, scanFlagValues{Quiet: true}, autoSBOMFlags{Enabled: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
	})
	if err != nil {
		t.Fatalf("resolveAutoSBOMRun: %v", err)
	}
	if run.settings.Path != root {
		t.Fatalf("resolved path = %q, want %q", run.settings.Path, root)
	}
	if !run.settings.Quiet {
		t.Fatalf("resolved settings did not preserve quiet flag: %+v", run.settings)
	}
}

func TestPrintAutoSBOMOnlyPathsHonorsQuiet(t *testing.T) {
	result := sbomgen.Result{SBOMPaths: []string{"one.cdx.json", "two.cdx.json"}}

	output := captureStdout(t, func() {
		printAutoSBOMOnlyPaths(scanSettings{}, result)
	})
	if output != "one.cdx.json\ntwo.cdx.json\n" {
		t.Fatalf("stdout = %q", output)
	}

	output = captureStdout(t, func() {
		printAutoSBOMOnlyPaths(scanSettings{Quiet: true}, result)
	})
	if output != "" {
		t.Fatalf("quiet stdout = %q, want empty", output)
	}
}

func TestDispatchAutoSBOMScanUsesGeneratedSBOMsForListAll(t *testing.T) {
	settings := scanSettings{SBOMFiles: []string{"manual.cdx.json"}}
	result := sbomgen.Result{SBOMPaths: []string{"generated.cdx.json"}}
	scanCalled := false
	var listed scanSettings

	exitCode, err := dispatchAutoSBOMScan(context.Background(), scanFlagValues{ListAll: true}, settings, result, autoSBOMDeps{
		scan: func(context.Context, scanSettings) (int, error) {
			scanCalled = true
			return ExitOK, nil
		},
		listAll: func(_ context.Context, settings scanSettings) (int, error) {
			listed = settings
			return ExitUnderThreshold, nil
		},
	})
	if err != nil {
		t.Fatalf("dispatchAutoSBOMScan: %v", err)
	}
	if exitCode != ExitUnderThreshold {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitUnderThreshold)
	}
	if scanCalled {
		t.Fatalf("list-all dispatch called normal scan")
	}
	if got := strings.Join(listed.SBOMFiles, ","); got != "manual.cdx.json,generated.cdx.json" {
		t.Fatalf("list-all SBOMFiles = %q", got)
	}
}

func TestFinalizeGeneratedSBOMCleanupRunsOnceAndWrapsError(t *testing.T) {
	cleanupErr := errors.New("cleanup failed")
	calls := 0
	result := sbomgen.Result{Cleanup: func() error {
		calls++
		return cleanupErr
	}}

	err := finalizeGeneratedSBOMCleanup(&result)
	if !errors.Is(err, cleanupErr) || !strings.Contains(err.Error(), "cleanup generated SBOMs") {
		t.Fatalf("cleanup error = %v, want wrapped cleanup failure", err)
	}
	if err := finalizeGeneratedSBOMCleanup(&result); err != nil {
		t.Fatalf("second cleanup should be a no-op: %v", err)
	}
	if calls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", calls)
	}
}

func TestRunAutoSBOMCommandSBOMOnlySkipsScan(t *testing.T) {
	root := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	var generated sbomgen.Config
	scanCalled := false
	err := runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{Quiet: true}, autoSBOMFlags{Enabled: true, SBOMOnly: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
		generate: func(_ context.Context, cfg sbomgen.Config) (sbomgen.Result, error) {
			generated = cfg
			return sbomgen.Result{SBOMPaths: []string{filepath.Join(root, "generated.cdx.json")}, Cleanup: func() error { return nil }}, nil
		},
		scan: func(context.Context, scanSettings) (int, error) {
			scanCalled = true
			return ExitOK, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSBOMCommandWithDeps: %v", err)
	}
	if scanCalled {
		t.Fatalf("--sbom-only must not invoke the scan pipeline")
	}
	if generated.Target != root || generated.KeepSBOMDir != "." {
		t.Fatalf("generated config = %+v, want target %q and cwd keep dir", generated, root)
	}
}

func TestRunAutoSBOMCommandAppendsGeneratedSBOMs(t *testing.T) {
	root := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.Flags().StringArray("sbom", nil, "")
	if err := cmd.Flags().Set("sbom", "manual.cdx.json"); err != nil {
		t.Fatal(err)
	}

	var scanned scanSettings
	cleanupCalled := false
	err := runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{Quiet: true, SBOMFiles: []string{"manual.cdx.json"}}, autoSBOMFlags{Enabled: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
		generate: func(_ context.Context, cfg sbomgen.Config) (sbomgen.Result, error) {
			if cfg.Target != root {
				t.Fatalf("generator Target = %q, want %q", cfg.Target, root)
			}
			return sbomgen.Result{SBOMPaths: []string{"generated.cdx.json"}, Cleanup: func() error {
				cleanupCalled = true
				return nil
			}}, nil
		},
		scan: func(_ context.Context, settings scanSettings) (int, error) {
			scanned = settings
			return ExitOK, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSBOMCommandWithDeps: %v", err)
	}
	if got := strings.Join(scanned.SBOMFiles, ","); got != "manual.cdx.json,generated.cdx.json" {
		t.Fatalf("SBOMFiles = %q", got)
	}
	if !cleanupCalled {
		t.Fatalf("generated SBOM cleanup was not called")
	}
}

func TestRunAutoSBOMCommandReturnsCleanupError(t *testing.T) {
	root := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	cleanupErr := errors.New("cleanup failed")
	err := runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{Quiet: true}, autoSBOMFlags{Enabled: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
		generate: func(_ context.Context, _ sbomgen.Config) (sbomgen.Result, error) {
			return sbomgen.Result{SBOMPaths: []string{"generated.cdx.json"}, Cleanup: func() error {
				return cleanupErr
			}}, nil
		},
		scan: func(context.Context, scanSettings) (int, error) {
			return ExitOK, nil
		},
	})
	if !errors.Is(err, cleanupErr) || !strings.Contains(err.Error(), "cleanup generated SBOMs") {
		t.Fatalf("cleanup error = %v, want wrapped cleanup failure", err)
	}
}

func TestRunAutoSBOMInstallDisclosureVisibleWhenQuiet(t *testing.T) {
	root := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	var runErr error
	stderr := captureStderr(t, func() {
		runErr = runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{Quiet: true}, autoSBOMFlags{Enabled: true, InstallTools: true}, autoSBOMDeps{
			loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
			generate: func(_ context.Context, cfg sbomgen.Config) (sbomgen.Result, error) {
				cfg.Logger.Info("installing SBOM generator", "package", "@cyclonedx/cyclonedx-npm", "source", "npm registry", "command", "npm install --global --ignore-scripts @cyclonedx/cyclonedx-npm")
				return sbomgen.Result{SBOMPaths: []string{"generated.cdx.json"}}, nil
			},
			scan: func(context.Context, scanSettings) (int, error) {
				return ExitOK, nil
			},
		})
	})
	if runErr != nil {
		t.Fatalf("runAutoSBOMCommandWithDeps: %v", runErr)
	}
	for _, want := range []string{
		"installing SBOM generator",
		"@cyclonedx/cyclonedx-npm",
		"npm install --global --ignore-scripts",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing install disclosure %q:\n%s", want, stderr)
		}
	}
}

func TestRunAutoSBOMCommandRoutesListAllWithGeneratedSBOMs(t *testing.T) {
	root := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.Flags().StringArray("sbom", nil, "")

	var listed scanSettings
	scanCalled := false
	cleanupCalled := false
	err := runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{Quiet: true, ListAll: true}, autoSBOMFlags{Enabled: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
		generate: func(_ context.Context, cfg sbomgen.Config) (sbomgen.Result, error) {
			if cfg.Target != root {
				t.Fatalf("generator Target = %q, want %q", cfg.Target, root)
			}
			return sbomgen.Result{SBOMPaths: []string{"generated.cdx.json"}, Cleanup: func() error {
				cleanupCalled = true
				return nil
			}}, nil
		},
		scan: func(context.Context, scanSettings) (int, error) {
			scanCalled = true
			return ExitOK, nil
		},
		listAll: func(_ context.Context, settings scanSettings) (int, error) {
			listed = settings
			return ExitOK, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSBOMCommandWithDeps: %v", err)
	}
	if scanCalled {
		t.Fatalf("--auto-sbom --list-all must use list-all, not normal scan")
	}
	if got := strings.Join(listed.SBOMFiles, ","); got != "generated.cdx.json" {
		t.Fatalf("list-all SBOMFiles = %q", got)
	}
	if !cleanupCalled {
		t.Fatalf("generated SBOM cleanup was not called")
	}
}

func TestRunAutoSBOMCommandUsesDefaultDeps(t *testing.T) {
	root := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	originalDeps := defaultAutoSBOMDeps
	t.Cleanup(func() { defaultAutoSBOMDeps = originalDeps })

	scanCalled := false
	defaultAutoSBOMDeps = autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
		generate: func(context.Context, sbomgen.Config) (sbomgen.Result, error) {
			return sbomgen.Result{SBOMPaths: []string{"generated.cdx.json"}}, nil
		},
		scan: func(context.Context, scanSettings) (int, error) {
			scanCalled = true
			return ExitOK, nil
		},
	}

	if err := runAutoSBOMCommand(cmd, []string{root}, scanFlagValues{Quiet: true}, autoSBOMFlags{Enabled: true}); err != nil {
		t.Fatalf("runAutoSBOMCommand() error = %v", err)
	}
	if !scanCalled {
		t.Fatal("runAutoSBOMCommand() did not use the configured default scan dependency")
	}
}

func TestRunAutoSBOMCommandWithDepsErrorBranches(t *testing.T) {
	root := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	loadErr := errors.New("config failed")
	err := runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{}, autoSBOMFlags{Enabled: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", loadErr },
	})
	if !errors.Is(err, loadErr) {
		t.Fatalf("load config error = %v, want wrapped config error", err)
	}

	cfg := &cliConfig{
		Repos: []cliRepoConfig{
			{Name: "one", Path: filepath.Join(root, "one")},
			{Name: "two", Path: filepath.Join(root, "two")},
		},
	}
	err = runAutoSBOMCommandWithDeps(cmd, nil, scanFlagValues{All: true}, autoSBOMFlags{Enabled: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return cfg, "", nil },
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one target") {
		t.Fatalf("multi-target error = %v, want exactly one target", err)
	}

	err = runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{}, autoSBOMFlags{Enabled: true, SBOMOnly: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) {
			return &cliConfig{Output: cliOutputConfig{Format: "json", File: "scan.json"}}, "", nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "report outputs") {
		t.Fatalf("sbom-only output error = %v, want report outputs", err)
	}

	generateErr := errors.New("generator failed")
	err = runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{}, autoSBOMFlags{Enabled: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
		generate:   func(context.Context, sbomgen.Config) (sbomgen.Result, error) { return sbomgen.Result{}, generateErr },
	})
	if !errors.Is(err, generateErr) {
		t.Fatalf("generate error = %v, want wrapped generator error", err)
	}

	scanErr := errors.New("scan failed")
	err = runAutoSBOMCommandWithDeps(cmd, []string{root}, scanFlagValues{}, autoSBOMFlags{Enabled: true}, autoSBOMDeps{
		loadConfig: func() (*cliConfig, string, error) { return nil, "", nil },
		generate: func(context.Context, sbomgen.Config) (sbomgen.Result, error) {
			return sbomgen.Result{SBOMPaths: []string{"generated.cdx.json"}}, nil
		},
		scan: func(context.Context, scanSettings) (int, error) {
			return ExitOperational, scanErr
		},
	})
	if !errors.Is(err, scanErr) {
		t.Fatalf("scan error = %v, want wrapped scan error", err)
	}
}

func TestScanCommandRejectsAutoSBOMPackageListModes(t *testing.T) {
	cmd := newScanCmd()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--auto-sbom", "--list-packages"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--auto-sbom cannot be combined") {
		t.Fatalf("Execute err = %v, want auto-sbom list-mode rejection", err)
	}
}
