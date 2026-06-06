package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/sbomgen"
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
	}

	cfg := buildAutoSBOMConfig(settings, autoSBOMFlags{Enabled: true, SBOMOnly: true})
	if cfg.Target != settings.Path {
		t.Fatalf("Target = %q, want %q", cfg.Target, settings.Path)
	}
	if got := strings.Join(cfg.Ecosystems, ","); got != "go,npm" {
		t.Fatalf("Ecosystems = %q", got)
	}
	if !cfg.IncludeDev || cfg.MaxDepth != 4 {
		t.Fatalf("IncludeDev/MaxDepth not copied from resolved settings: %+v", cfg)
	}
	if cfg.KeepSBOMDir != "." {
		t.Fatalf("--sbom-only without --keep-sbom must keep files in cwd, got %q", cfg.KeepSBOMDir)
	}

	cfg = buildAutoSBOMConfig(settings, autoSBOMFlags{Enabled: true, KeepSBOM: "out"})
	if cfg.KeepSBOMDir != "out" {
		t.Fatalf("--keep-sbom dir = %q, want out", cfg.KeepSBOMDir)
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

func TestScanCommandRejectsAutoSBOMListModes(t *testing.T) {
	cmd := newScanCmd()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--auto-sbom", "--list-packages"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--auto-sbom cannot be combined") {
		t.Fatalf("Execute err = %v, want auto-sbom list-mode rejection", err)
	}
}
