package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/sbomgen"
	"github.com/spf13/cobra"
)

type autoSBOMFlags struct {
	Enabled      bool
	InstallTools bool
	KeepSBOM     string
	SBOMOnly     bool
}

func validateAutoSBOMFlags(auto autoSBOMFlags, flags scanFlagValues, args []string) error {
	if !auto.Enabled {
		if auto.InstallTools || strings.TrimSpace(auto.KeepSBOM) != "" || auto.SBOMOnly {
			return fmt.Errorf("--install-tools, --keep-sbom, and --sbom-only require --auto-sbom")
		}
		return nil
	}
	if flags.All {
		return fmt.Errorf("--auto-sbom cannot be combined with --all (auto-SBOM needs exactly one target)")
	}
	if len(args) > 1 {
		return fmt.Errorf("--auto-sbom needs exactly one target, got %d", len(args))
	}
	if auto.SBOMOnly {
		if len(flags.SBOMFiles) > 0 {
			return fmt.Errorf("--sbom-only cannot be combined with --sbom because no scan is run")
		}
		if hasAutoSBOMOnlyResultOutput(flags) {
			return fmt.Errorf("--sbom-only cannot be combined with report output flags because no scan result is produced")
		}
		if strings.TrimSpace(flags.WebhookURL) != "" || strings.TrimSpace(flags.WebhookSecret) != "" {
			return fmt.Errorf("--sbom-only cannot be combined with webhook flags because no scan result is produced")
		}
	}
	return nil
}

func hasAutoSBOMOnlyResultOutput(flags scanFlagValues) bool {
	return hasScanOutputArtifactFlags(flags)
}

type autoSBOMDeps struct {
	loadConfig func() (*cliConfig, string, error)
	generate   func(context.Context, sbomgen.Config) (sbomgen.Result, error)
	scan       func(context.Context, scanSettings) (int, error)
	listAll    func(context.Context, scanSettings) (int, error)
}

var defaultAutoSBOMDeps = autoSBOMDeps{
	loadConfig: loadCurrentCLIConfig,
	generate:   sbomgen.Run,
	scan:       runSingleScan,
	listAll:    runListAll,
}

func validateAutoSBOMOnlySettings(settings scanSettings) error {
	if len(settings.SBOMFiles) > 0 {
		return fmt.Errorf("--sbom-only cannot be combined with --sbom because no scan is run")
	}
	if hasScanOutputArtifactSettings(settings) {
		return fmt.Errorf("--sbom-only cannot be combined with report outputs because no scan result is produced")
	}
	if strings.TrimSpace(settings.WebhookURL) != "" || strings.TrimSpace(settings.WebhookSecret) != "" {
		return fmt.Errorf("--sbom-only cannot be combined with webhook output because no scan result is produced")
	}
	return nil
}

func buildAutoSBOMConfig(settings scanSettings, auto autoSBOMFlags) sbomgen.Config {
	keepDir := strings.TrimSpace(auto.KeepSBOM)
	if auto.SBOMOnly && keepDir == "" {
		keepDir = "."
	}
	logger := scanLogger(settings.Quiet, settings.LogLevel, settings.LogFormat)
	if auto.InstallTools {
		logger = newScanLogger(os.Stderr, false, "INFO", settings.LogFormat)
	}
	return sbomgen.Config{
		Target:       settings.Path,
		Ecosystems:   autoSBOMEcosystemFilters(settings.Ecosystems),
		InstallTools: auto.InstallTools,
		KeepSBOMDir:  keepDir,
		IncludeDev:   settings.IncludeDev,
		MaxDepth:     settings.MaxDepth,
		Timeout:      time.Duration(settings.Timeout) * time.Second,
		Logger:       logger,
	}
}

func autoSBOMEcosystemFilters(ecosystems []string) []domain.Ecosystem {
	out := make([]domain.Ecosystem, 0, len(ecosystems))
	for _, ecosystem := range ecosystems {
		ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
		if ecosystem != "" {
			out = append(out, domain.Ecosystem(ecosystem))
		}
	}
	return out
}

func runAutoSBOMCommand(cmd *cobra.Command, args []string, flags scanFlagValues, auto autoSBOMFlags) error {
	return runAutoSBOMCommandWithDeps(cmd, args, flags, auto, defaultAutoSBOMDeps)
}

type autoSBOMRun struct {
	settings scanSettings
}

func resolveAutoSBOMRun(cmd *cobra.Command, args []string, flags scanFlagValues, auto autoSBOMFlags, deps autoSBOMDeps) (autoSBOMRun, error) {
	cfg, _, err := deps.loadConfig()
	if err != nil {
		return autoSBOMRun{}, withExitCode(ExitOperational, err)
	}
	targets, err := buildScanTargets(cfg, args, flags)
	if err != nil {
		return autoSBOMRun{}, withExitCode(ExitOperational, err)
	}
	if len(targets) != 1 {
		return autoSBOMRun{}, withExitCode(ExitOperational, fmt.Errorf("--auto-sbom needs exactly one target, got %d", len(targets)))
	}

	settings, err := resolveScanSettings(cmd, cfg, targets[0], flags)
	if err != nil {
		return autoSBOMRun{}, withExitCode(ExitOperational, err)
	}
	if auto.SBOMOnly {
		if err := validateAutoSBOMOnlySettings(settings); err != nil {
			return autoSBOMRun{}, withExitCode(ExitOperational, err)
		}
	}

	return autoSBOMRun{settings: settings}, nil
}

func generateAutoSBOMs(ctx context.Context, settings scanSettings, auto autoSBOMFlags, deps autoSBOMDeps) (sbomgen.Result, error) {
	res, err := deps.generate(ctx, buildAutoSBOMConfig(settings, auto))
	if err != nil {
		return sbomgen.Result{}, withExitCode(ExitOperational, err)
	}
	return res, nil
}

func printAutoSBOMOnlyPaths(settings scanSettings, res sbomgen.Result) {
	if settings.Quiet {
		return
	}
	for _, path := range res.SBOMPaths {
		_, _ = fmt.Fprintln(os.Stdout, path)
	}
}

func dispatchAutoSBOMScan(ctx context.Context, flags scanFlagValues, settings scanSettings, res sbomgen.Result, deps autoSBOMDeps) (int, error) {
	settings.SBOMFiles = append(append([]string(nil), settings.SBOMFiles...), res.SBOMPaths...)
	run := deps.scan
	if flags.ListAll {
		run = deps.listAll
	}
	return run(ctx, settings)
}

func finalizeGeneratedSBOMCleanup(res *sbomgen.Result) error {
	if res == nil || res.Cleanup == nil {
		return nil
	}
	err := res.Cleanup()
	res.Cleanup = nil
	if err != nil {
		return fmt.Errorf("cleanup generated SBOMs: %w", err)
	}
	return nil
}

func runAutoSBOMCommandWithDeps(cmd *cobra.Command, args []string, flags scanFlagValues, auto autoSBOMFlags, deps autoSBOMDeps) error {
	run, err := resolveAutoSBOMRun(cmd, args, flags, auto, deps)
	if err != nil {
		return err
	}

	res, err := generateAutoSBOMs(cmd.Context(), run.settings, auto, deps)
	if err != nil {
		return err
	}

	if auto.SBOMOnly {
		printAutoSBOMOnlyPaths(run.settings, res)
		return nil
	}

	exitCode, err := dispatchAutoSBOMScan(cmd.Context(), flags, run.settings, res, deps)
	if err != nil {
		if cleanupErr := finalizeGeneratedSBOMCleanup(&res); cleanupErr != nil {
			return withExitCode(exitCode, errors.Join(err, cleanupErr))
		}
		return withExitCode(exitCode, err)
	}
	if cleanupErr := finalizeGeneratedSBOMCleanup(&res); cleanupErr != nil {
		return withExitCode(ExitOperational, cleanupErr)
	}
	if exitCode != ExitOK {
		os.Exit(exitCode)
	}
	return nil
}
