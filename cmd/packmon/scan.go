package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/parser"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/termtext"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		flagMode           string
		flagServer         string
		flagAPIKey         string
		flagFailOn         string
		flagEcosystems     string
		flagMaxDepth       int
		flagTimeout        int
		flagIncludeDev     bool
		flagOutputJSON     string
		flagOutputSARIF    string
		flagOutputJUnit    string
		flagOutputHTML     string
		flagWebhookURL     string
		flagWebhookSecret  string
		flagAll            bool
		flagRepo           string
		flagListPackages   bool
		flagOutdated       bool
		flagListAll        bool
		flagListAllOffline bool
		flagCACert         string
		flagInsecureHTTP   bool
		flagRequireRemote  bool
		flagNoRepoMetadata bool
		flagSBOMFiles      []string
		flagAutoSBOM       bool
		flagInstallTools   bool
		flagKeepSBOM       string
		flagSBOMOnly       bool
	)

	cmd := &cobra.Command{
		Use:   "scan [PATH]",
		Short: "Scan dependencies and SBOMs for security and lifecycle findings",
		Long: `Scan the given directory (default ".") for lockfiles and SBOMs,
parse dependencies, and check them for known vulnerabilities, malicious
packages, supply-chain risk findings, and lifecycle risks.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanFlags := scanFlagValues{
				Mode:             flagMode,
				Server:           flagServer,
				APIKey:           flagAPIKey,
				FailOn:           flagFailOn,
				Ecosystems:       flagEcosystems,
				MaxDepth:         flagMaxDepth,
				Timeout:          flagTimeout,
				IncludeDev:       flagIncludeDev,
				OutputJSON:       flagOutputJSON,
				OutputSARIF:      flagOutputSARIF,
				OutputJUnit:      flagOutputJUnit,
				OutputHTML:       flagOutputHTML,
				WebhookURL:       flagWebhookURL,
				WebhookSecret:    flagWebhookSecret,
				All:              flagAll,
				Repo:             flagRepo,
				Quiet:            flagQuiet,
				NoColor:          flagNoColor,
				CACert:           flagCACert,
				InsecureHTTP:     flagInsecureHTTP,
				RequireRemote:    flagRequireRemote,
				OmitRepoMetadata: flagNoRepoMetadata,
				SBOMFiles:        flagSBOMFiles,
				ListAll:          flagListAll,
				ListAllOffline:   flagListAllOffline,
			}
			auto := autoSBOMFlags{
				Enabled:      flagAutoSBOM,
				InstallTools: flagInstallTools,
				KeepSBOM:     flagKeepSBOM,
				SBOMOnly:     flagSBOMOnly,
			}
			if err := validateAutoSBOMFlags(auto, scanFlags, args); err != nil {
				return withExitCode(ExitOperational, err)
			}
			if flagAutoSBOM {
				if flagListPackages || flagOutdated {
					return withExitCode(ExitOperational, fmt.Errorf("--auto-sbom cannot be combined with --list-packages or --outdated"))
				}
				return runAutoSBOMCommand(cmd, args, scanFlags, auto)
			}
			if err := validateScanReportModeFlags(flagListPackages, flagOutdated, flagListAll); err != nil {
				return withExitCode(ExitOperational, err)
			}
			if flagListAllOffline && !flagListAll {
				return withExitCode(ExitOperational, fmt.Errorf("--list-all-offline can only be used with --list-all"))
			}
			if flagListPackages {
				settings, err := resolveSingleTargetScanSettings(cmd, args, scanFlags, "--list-packages")
				if err != nil {
					return err
				}
				return withDefaultExitCode(ExitOperational, runListPackagesWithSettings(settings))
			}
			if flagOutdated {
				settings, err := resolveSingleTargetScanSettings(cmd, args, scanFlags, "--outdated")
				if err != nil {
					return err
				}
				return withDefaultExitCode(ExitOperational, runOutdatedWithOptions([]string{settings.Path}, outdatedOptions{
					Context:        cmd.Context(),
					Ecosystems:     strings.Join(settings.Ecosystems, ","),
					MaxDepth:       settings.MaxDepth,
					IncludeDev:     true,
					OutputHTML:     settings.OutputHTML,
					Quiet:          settings.Quiet,
					SBOMFiles:      settings.SBOMFiles,
					Timeout:        settings.Timeout,
					LatestRegistry: settings.LatestRegistry,
				}))
			}
			if flagListAll {
				settings, err := resolveSingleTargetScanSettings(cmd, args, scanFlags, "--list-all")
				if err != nil {
					return err
				}
				exitCode, err := runListAll(cmd.Context(), settings)
				if err != nil {
					return withDefaultExitCode(ExitOperational, err)
				}
				if exitCode != ExitOK {
					os.Exit(exitCode)
				}
				return nil
			}
			return runScanCommand(cmd, args, scanFlags)
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagMode, "mode", "auto", "scan mode (local|remote|auto)")
	f.StringVar(&flagServer, "server", "", "feed server URL")
	f.StringVar(&flagAPIKey, "api-key", "", "deprecated: use PACKMON_API_KEY or api_key_env; command-line secrets are rejected by default")
	f.StringVar(&flagFailOn, "fail-on", "CRITICAL", "block on vulnerability severity (CRITICAL|HIGH|MEDIUM|LOW|NONE); NONE disables vulnerability blocking only; malicious and active supply-chain risk findings still block")
	f.StringVar(&flagEcosystems, "ecosystems", "", "comma-separated ecosystem filter")
	f.IntVar(&flagMaxDepth, "max-depth", 10, "directory walk depth")
	f.IntVar(&flagTimeout, "timeout", 30, "HTTP timeout in seconds")
	f.BoolVar(&flagIncludeDev, "include-dev", false, "include dev dependencies")
	f.StringVar(&flagOutputJSON, "output-json", "", "write JSON results to file")
	f.StringVar(&flagOutputSARIF, "output-sarif", "", "write SARIF 2.1.0 results to file")
	f.StringVar(&flagOutputJUnit, "output-junit", "", "write JUnit XML results to file")
	f.StringVar(&flagOutputHTML, "html", "", "write a self-contained HTML report to file")
	f.StringVar(&flagWebhookURL, "webhook-url", "", "webhook URL to POST results to")
	f.StringVar(&flagWebhookSecret, "webhook-secret", "", "deprecated: use PACKMON_WEBHOOK_SECRET or config webhook secret; command-line secrets are rejected by default")
	f.BoolVar(&flagAll, "all", false, "scan all repositories configured in .packmon.yaml")
	f.StringVar(&flagRepo, "repo", "", "scan a configured repository by name")
	f.BoolVar(&flagListPackages, "list-packages", false, "list all detected packages and exit (no vulnerability check)")
	f.BoolVar(&flagOutdated, "outdated", false, "show packages with newer versions available by querying public registries and Git remotes")
	f.BoolVar(&flagListAll, "list-all", false, "list findings, then all packages with available-update info")
	f.BoolVar(&flagListAllOffline, "list-all-offline", false, "with --list-all: skip external latest-version and Docker digest lookups")
	f.StringVar(&flagCACert, "cacert", "", "path to a PEM CA bundle used to verify the server's TLS certificate")
	f.BoolVar(&flagInsecureHTTP, "insecure-allow-http", false, "allow plain http:// server URLs (sends bearer token in cleartext; opt-in)")
	f.BoolVar(&flagRequireRemote, "require-remote", false, "in auto mode, fail hard on remote error instead of falling back to the local database")
	f.BoolVar(&flagNoRepoMetadata, "no-repo-metadata", false, "omit optional repository metadata from remote scan requests and webhooks")
	f.StringArrayVar(&flagSBOMFiles, "sbom", nil, "SBOM file to include as package input (CycloneDX JSON/XML or SPDX JSON); can be repeated")
	f.BoolVar(&flagAutoSBOM, "auto-sbom", false, "generate SBOMs with local ecosystem tools and scan them")
	f.BoolVar(&flagInstallTools, "install-tools", false, "with --auto-sbom: auto-install supported missing CycloneDX generators (pinned versions)")
	f.StringVar(&flagKeepSBOM, "keep-sbom", "", "with --auto-sbom: write timestamped generated SBOM snapshots to this dir and keep them")
	f.BoolVar(&flagSBOMOnly, "sbom-only", false, "with --auto-sbom: only generate SBOMs, do not scan")

	return cmd
}

func validateScanReportModeFlags(listPackages, outdated, listAll bool) error {
	var modes []string
	if listPackages {
		modes = append(modes, "--list-packages")
	}
	if outdated {
		modes = append(modes, "--outdated")
	}
	if listAll {
		modes = append(modes, "--list-all")
	}
	if len(modes) > 1 {
		return fmt.Errorf("choose only one report mode flag: %s", strings.Join(modes, ", "))
	}
	return nil
}

type scanFlagValues struct {
	Mode             string
	Server           string
	APIKey           string
	FailOn           string
	Ecosystems       string
	MaxDepth         int
	Timeout          int
	IncludeDev       bool
	OutputJSON       string
	OutputSARIF      string
	OutputJUnit      string
	OutputHTML       string
	WebhookURL       string
	WebhookSecret    string
	All              bool
	Repo             string
	Quiet            bool
	NoColor          bool
	CACert           string
	InsecureHTTP     bool
	RequireRemote    bool
	OmitRepoMetadata bool
	SBOMFiles        []string
	ListAll          bool
	ListAllOffline   bool
}

type scanTarget struct {
	Name string
	Path string
	Repo *cliRepoConfig
}

type scanSettings struct {
	TargetName       string
	Path             string
	Mode             string
	ServerURL        string
	APIKey           string
	FailOn           string
	Ecosystems       []string
	MaxDepth         int
	Timeout          int
	IncludeDev       bool
	OutputJSON       string
	OutputSARIF      string
	OutputJUnit      string
	OutputHTML       string
	WebhookURL       string
	WebhookSecret    string
	LogLevel         string
	LogFormat        string
	Logger           *slog.Logger
	Quiet            bool
	NoColor          bool
	CACertFile       string
	InsecureHTTP     bool
	RequireRemote    bool
	OmitRepoMetadata bool
	SBOMFiles        []string
	ListAllOffline   bool
	InventoryAll     bool
	LatestRegistry   latestRegistryConfig
	resolver         packageUpdateResolver
}

type scanOutputArtifact struct {
	format           string
	flagName         string
	displayName      string
	includeHTMLOnly  bool
	prepareOutputDir bool
	pathFromSettings func(scanSettings) string
	pathFromFlags    func(scanFlagValues) string
	setPath          func(*scanSettings, string)
	write            func(scanOutputArtifactWrite) error
	announce         func(scanOutputArtifactWrite)
}

type scanOutputArtifactWrite struct {
	path     string
	settings scanSettings
	result   *domain.ScanResult
	failOn   domain.Severity
}

var scanOutputArtifacts = []scanOutputArtifact{
	{
		format:      "json",
		flagName:    "output-json",
		displayName: "JSON",
		pathFromSettings: func(settings scanSettings) string {
			return settings.OutputJSON
		},
		pathFromFlags: func(flags scanFlagValues) string {
			return flags.OutputJSON
		},
		setPath: func(settings *scanSettings, path string) {
			settings.OutputJSON = path
		},
		write: func(ctx scanOutputArtifactWrite) error {
			return writeJSONFile(ctx.path, ctx.result)
		},
	},
	{
		format:           "sarif",
		flagName:         "output-sarif",
		displayName:      "SARIF",
		prepareOutputDir: true,
		pathFromSettings: func(settings scanSettings) string {
			return settings.OutputSARIF
		},
		pathFromFlags: func(flags scanFlagValues) string {
			return flags.OutputSARIF
		},
		setPath: func(settings *scanSettings, path string) {
			settings.OutputSARIF = path
		},
		write: func(ctx scanOutputArtifactWrite) error {
			sw := scanner.NewSARIFWriter(version)
			return sw.WriteFile(ctx.path, ctx.result)
		},
	},
	{
		format:           "junit",
		flagName:         "output-junit",
		displayName:      "JUnit",
		prepareOutputDir: true,
		pathFromSettings: func(settings scanSettings) string {
			return settings.OutputJUnit
		},
		pathFromFlags: func(flags scanFlagValues) string {
			return flags.OutputJUnit
		},
		setPath: func(settings *scanSettings, path string) {
			settings.OutputJUnit = path
		},
		write: func(ctx scanOutputArtifactWrite) error {
			jw := scanner.NewJUnitWriter()
			return jw.WriteFile(ctx.path, ctx.result)
		},
	},
	{
		format:           "html",
		flagName:         "html",
		displayName:      "HTML",
		includeHTMLOnly:  true,
		prepareOutputDir: true,
		pathFromSettings: func(settings scanSettings) string {
			return settings.OutputHTML
		},
		pathFromFlags: func(flags scanFlagValues) string {
			return flags.OutputHTML
		},
		setPath: func(settings *scanSettings, path string) {
			settings.OutputHTML = path
		},
		write: func(ctx scanOutputArtifactWrite) error {
			hw := scanner.NewHTMLWriter(version)
			return hw.WriteFile(ctx.path, ctx.settings.TargetName, ctx.failOn, ctx.result)
		},
		announce: func(ctx scanOutputArtifactWrite) {
			if !ctx.settings.Quiet {
				_, _ = fmt.Fprintf(os.Stdout, "HTML report written to: %s\n", ctx.path)
			}
		},
	},
}

func scanOutputArtifactForFormat(format string) (scanOutputArtifact, bool) {
	format = strings.ToLower(strings.TrimSpace(format))
	for _, artifact := range scanOutputArtifacts {
		if artifact.format == format {
			return artifact, true
		}
	}
	return scanOutputArtifact{}, false
}

func scanOutputArtifactFormats() []string {
	formats := make([]string, 0, len(scanOutputArtifacts))
	for _, artifact := range scanOutputArtifacts {
		formats = append(formats, artifact.format)
	}
	return formats
}

func scanOutputConfigFormats() []string {
	formats := []string{"table"}
	return append(formats, scanOutputArtifactFormats()...)
}

func scanOutputConfigFormatList() string {
	return strings.Join(scanOutputConfigFormats(), "|")
}

func isValidScanOutputConfigFormat(format string) bool {
	format = strings.TrimSpace(format)
	if format == "" || format == "table" {
		return true
	}
	_, ok := scanOutputArtifactForFormat(format)
	return ok
}

func scanOutputConfigRequestsArtifact(cfg cliOutputConfig) bool {
	if strings.TrimSpace(cfg.File) == "" {
		return false
	}
	_, ok := scanOutputArtifactForFormat(cfg.Format)
	return ok
}

func hasScanOutputArtifactFlags(flags scanFlagValues) bool {
	for _, artifact := range scanOutputArtifacts {
		if strings.TrimSpace(artifact.pathFromFlags(flags)) != "" {
			return true
		}
	}
	return false
}

func hasScanOutputArtifactSettings(settings scanSettings) bool {
	for _, artifact := range scanOutputArtifacts {
		if strings.TrimSpace(artifact.pathFromSettings(settings)) != "" {
			return true
		}
	}
	return false
}

func scanOutputArtifactFlagList() string {
	names := make([]string, 0, len(scanOutputArtifacts))
	for _, artifact := range scanOutputArtifacts {
		names = append(names, "--"+artifact.flagName)
	}
	if len(names) == 0 {
		return ""
	}
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + ", and " + names[len(names)-1]
}

func runScanCommand(cmd *cobra.Command, args []string, flags scanFlagValues) error {
	cfg, _, err := loadCurrentCLIConfig()
	if err != nil {
		return withExitCode(ExitOperational, err)
	}

	targets, err := buildScanTargets(cfg, args, flags)
	if err != nil {
		return withExitCode(ExitOperational, err)
	}
	hasConfigOutput := cfg != nil && scanOutputConfigRequestsArtifact(cfg.Output)
	if len(targets) > 1 && (hasConfigOutput || hasScanOutputArtifactFlags(flags)) {
		return withExitCode(ExitOperational, fmt.Errorf("%s can only be used when scanning a single target, not multiple targets", scanOutputArtifactFlagList()))
	}

	finalExitCode := ExitOK
	for i, target := range targets {
		settings, err := resolveScanSettings(cmd, cfg, target, flags)
		if err != nil {
			return withExitCode(ExitOperational, err)
		}

		if len(targets) > 1 && !flags.Quiet {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("== %s ==\n", target.Name)
			fmt.Printf("Path: %s\n\n", target.Path)
		}

		exitCode, err := runSingleScan(cmd.Context(), settings)
		if err != nil {
			return withExitCode(exitCode, err)
		}
		finalExitCode = worstExitCode(finalExitCode, exitCode)
	}

	if finalExitCode != ExitOK {
		os.Exit(finalExitCode)
	}
	return nil
}

func resolveSingleTargetScanSettings(cmd *cobra.Command, args []string, flags scanFlagValues, commandName string) (scanSettings, error) {
	cfg, _, err := loadCurrentCLIConfig()
	if err != nil {
		return scanSettings{}, withExitCode(ExitOperational, err)
	}
	targets, err := buildScanTargets(cfg, args, flags)
	if err != nil {
		return scanSettings{}, withExitCode(ExitOperational, err)
	}
	if len(targets) != 1 {
		return scanSettings{}, withExitCode(ExitOperational, fmt.Errorf("%s can only be used with a single target; use --repo or a positional PATH", commandName))
	}
	settings, err := resolveScanSettings(cmd, cfg, targets[0], flags)
	if err != nil {
		return scanSettings{}, withExitCode(ExitOperational, err)
	}
	return settings, nil
}

// worstExitCode merges two scan exit codes into the most severe one. Severity
// order (worst first): internal(10) > parser(4) > operational(2) >
// blocking(1) > under-threshold(3) > ok(0). A blocking target therefore wins
// over a sibling that only had non-blocking findings, even though 3 > 1
// numerically.
func worstExitCode(a, b int) int {
	if exitCodeSeverity(b) > exitCodeSeverity(a) {
		return b
	}
	return a
}

func exitCodeSeverity(code int) int {
	switch code {
	case ExitInternal:
		return 5
	case ExitParser:
		return 4
	case ExitOperational:
		return 3
	case ExitBlocking:
		return 2
	case ExitUnderThreshold:
		return 1
	default: // ExitOK
		return 0
	}
}

func buildScanTargets(cfg *cliConfig, args []string, flags scanFlagValues) ([]scanTarget, error) {
	if flags.All && strings.TrimSpace(flags.Repo) != "" {
		return nil, fmt.Errorf("--all and --repo cannot be used together")
	}
	if flags.All && len(args) > 0 {
		return nil, fmt.Errorf("positional PATH cannot be used with --all")
	}
	if strings.TrimSpace(flags.Repo) != "" && len(args) > 0 {
		return nil, fmt.Errorf("positional PATH cannot be used with --repo")
	}

	if flags.All {
		if cfg == nil || len(cfg.Repos) == 0 {
			return nil, fmt.Errorf("no repositories configured in %s", valueOrDefault(selectCLIConfigPath(""), defaultCLIConfigFile))
		}
		targets := make([]scanTarget, 0, len(cfg.Repos))
		for i := range cfg.Repos {
			repo := &cfg.Repos[i]
			targets = append(targets, scanTarget{
				Name: repo.Name,
				Path: repo.Path,
				Repo: repo,
			})
		}
		return targets, nil
	}

	if repoName := strings.TrimSpace(flags.Repo); repoName != "" {
		if cfg == nil {
			return nil, fmt.Errorf("no config file loaded; --repo requires configured repositories")
		}
		repo := cfg.findRepo(repoName)
		if repo == nil {
			return nil, fmt.Errorf("configured repo %q not found", repoName)
		}
		return []scanTarget{{
			Name: repo.Name,
			Path: repo.Path,
			Repo: repo,
		}}, nil
	}

	path := "."
	if len(args) > 0 {
		path = args[0]
	}
	return []scanTarget{{Name: scanTargetDisplayName(path), Path: path}}, nil
}

// scanTargetDisplayName names a scan target after the directory it points at.
// filepath.Base alone cannot do that: for the most common invocations -- `scan
// .`, `scan ./`, or no argument at all -- it returns a value that carries no
// information about which project was scanned. That used to collapse to the
// literal "local", so every report produced that way was titled the same and
// reports from different repositories could not be told apart.
func scanTargetDisplayName(path string) string {
	name := filepath.Base(path)
	if uninformativeTargetName(name) {
		if abs, err := filepath.Abs(path); err == nil {
			name = filepath.Base(abs)
		}
	}
	if uninformativeTargetName(name) {
		// Reached only for a filesystem root, which has no directory name.
		return "local"
	}
	return name
}

func uninformativeTargetName(name string) bool {
	return name == "" || name == "." || name == ".." ||
		(len(name) == 1 && os.IsPathSeparator(name[0]))
}

func resolveScanSettings(cmd *cobra.Command, cfg *cliConfig, target scanTarget, flags scanFlagValues) (scanSettings, error) {
	if err := rejectSecretFlagValue(cmd, "api-key", "PACKMON_API_KEY or config api_key_env"); err != nil {
		return scanSettings{}, err
	}
	if err := rejectSecretFlagValue(cmd, "webhook-secret", "PACKMON_WEBHOOK_SECRET or config webhook secret"); err != nil {
		return scanSettings{}, err
	}

	envAPIKey := strings.TrimSpace(os.Getenv("PACKMON_API_KEY"))
	settings := defaultScanSettings(target, flags)
	skipConfigAPIKeyEnv := envAPIKey != "" || commandFlagChanged(cmd, "api-key")

	if err := applyScanConfigSettings(&settings, cfg, skipConfigAPIKeyEnv); err != nil {
		return scanSettings{}, err
	}
	if err := applyScanRepoSettings(&settings, target.Repo, skipConfigAPIKeyEnv); err != nil {
		return scanSettings{}, err
	}
	if err := applyScanEnvSettings(&settings, envAPIKey); err != nil {
		return scanSettings{}, err
	}
	applyScanFlagSettings(&settings, cmd, flags)
	if err := validateResolvedScanSettings(&settings, flags, cmd); err != nil {
		return scanSettings{}, err
	}

	return settings, nil
}

func defaultScanSettings(target scanTarget, flags scanFlagValues) scanSettings {
	return scanSettings{
		TargetName:     target.Name,
		Path:           target.Path,
		Mode:           "auto",
		FailOn:         string(defaultFailSeverity()),
		MaxDepth:       flags.MaxDepth,
		Timeout:        30,
		Quiet:          flags.Quiet,
		NoColor:        flags.NoColor,
		LogLevel:       "INFO",
		LogFormat:      "text",
		LatestRegistry: defaultLatestRegistryConfig(),
	}
}

// scanSharedSettings contains scan fields supported by both top-level config
// and per-repository overrides.
type scanSharedSettings struct {
	ServerURL        string
	APIKey           string
	APIKeyEnv        string
	Mode             string
	FailOn           string
	Timeout          int
	Ecosystems       []string
	IncludeDev       *bool
	SendRepoMetadata *bool
	WebhookURL       string
	WebhookSecret    string
}

func scanSharedSettingsFromConfig(cfg *cliConfig) scanSharedSettings {
	return scanSharedSettings{
		ServerURL:        cfg.Server,
		APIKey:           cfg.APIKey,
		APIKeyEnv:        cfg.APIKeyEnv,
		Mode:             cfg.Mode,
		FailOn:           cfg.FailOn,
		Timeout:          cfg.Timeout,
		Ecosystems:       cfg.Ecosystems,
		IncludeDev:       cfg.IncludeDev,
		SendRepoMetadata: cfg.SendRepoMetadata,
		WebhookURL:       cfg.Webhook.URL,
		WebhookSecret:    cfg.Webhook.Secret,
	}
}

func scanSharedSettingsFromRepo(repo *cliRepoConfig) scanSharedSettings {
	return scanSharedSettings{
		ServerURL:        repo.Server,
		APIKey:           repo.APIKey,
		APIKeyEnv:        repo.APIKeyEnv,
		Mode:             repo.Mode,
		FailOn:           repo.FailOn,
		Timeout:          repo.Timeout,
		Ecosystems:       repo.Ecosystems,
		IncludeDev:       repo.IncludeDev,
		SendRepoMetadata: repo.SendRepoMetadata,
		WebhookURL:       repo.Webhook.URL,
		WebhookSecret:    repo.Webhook.Secret,
	}
}

func applyScanSharedSettings(settings *scanSettings, shared scanSharedSettings, skipAPIKeyEnv bool) error {
	if shared.ServerURL != "" {
		settings.ServerURL = shared.ServerURL
	}
	if shared.APIKey != "" {
		settings.APIKey = shared.APIKey
	}
	if shared.APIKeyEnv != "" && !skipAPIKeyEnv {
		apiKey, err := resolveAPIKeyEnv(shared.APIKeyEnv)
		if err != nil {
			return err
		}
		settings.APIKey = apiKey
	}
	if shared.Mode != "" {
		settings.Mode = shared.Mode
	}
	if shared.FailOn != "" {
		settings.FailOn = shared.FailOn
	}
	if shared.Timeout > 0 {
		settings.Timeout = shared.Timeout
	}
	if len(shared.Ecosystems) > 0 {
		settings.Ecosystems = append([]string(nil), shared.Ecosystems...)
	}
	settings.IncludeDev = boolValue(shared.IncludeDev, settings.IncludeDev)
	if shared.SendRepoMetadata != nil {
		settings.OmitRepoMetadata = !*shared.SendRepoMetadata
	}
	if shared.WebhookURL != "" {
		settings.WebhookURL = shared.WebhookURL
	}
	if shared.WebhookSecret != "" {
		settings.WebhookSecret = shared.WebhookSecret
	}

	return nil
}

func applyScanConfigSettings(settings *scanSettings, cfg *cliConfig, skipAPIKeyEnv bool) error {
	if cfg == nil {
		return nil
	}

	if err := applyScanSharedSettings(settings, scanSharedSettingsFromConfig(cfg), skipAPIKeyEnv); err != nil {
		return err
	}
	if cfg.Output.File != "" {
		applyOutputConfig(settings, cfg.Output)
	}
	if cfg.Log.Level != "" {
		settings.LogLevel = cfg.Log.Level
	}
	if cfg.Log.Format != "" {
		settings.LogFormat = strings.ToLower(strings.TrimSpace(cfg.Log.Format))
	}
	if cfg.CACert != "" {
		settings.CACertFile = cfg.CACert
	}
	applyCLIRegistryConfig(settings, cfg.Registries)
	settings.InsecureHTTP = boolValue(cfg.InsecureAllowHTTP, settings.InsecureHTTP)
	settings.RequireRemote = boolValue(cfg.RequireRemote, settings.RequireRemote)

	return nil
}

func applyScanRepoSettings(settings *scanSettings, repo *cliRepoConfig, skipAPIKeyEnv bool) error {
	if repo == nil {
		return nil
	}

	return applyScanSharedSettings(settings, scanSharedSettingsFromRepo(repo), skipAPIKeyEnv)
}

func applyScanEnvSettings(settings *scanSettings, envAPIKey string) error {
	applyScanStringEnvSettings(settings, envAPIKey)
	if err := applyScanTimeoutEnvSetting(settings); err != nil {
		return err
	}
	if err := applyScanBooleanEnvSettings(settings); err != nil {
		return err
	}
	if err := applyLatestRegistryEnvSettings(settings); err != nil {
		return err
	}
	return nil
}

func applyScanStringEnvSettings(settings *scanSettings, envAPIKey string) {
	if envServer := strings.TrimSpace(os.Getenv("PACKMON_SERVER")); envServer != "" {
		settings.ServerURL = envServer
	}
	if envAPIKey != "" {
		settings.APIKey = envAPIKey
	}
	if envMode := normalizeModeString(os.Getenv("PACKMON_MODE")); envMode != "" {
		settings.Mode = envMode
	}
	if envFailOn := normalizeSeverityString(os.Getenv("PACKMON_FAIL_ON")); envFailOn != "" {
		settings.FailOn = envFailOn
	}
	if envEcosystems := strings.TrimSpace(os.Getenv("PACKMON_ECOSYSTEMS")); envEcosystems != "" {
		settings.Ecosystems = splitCSV(envEcosystems)
	}
	if envWebhookURL := strings.TrimSpace(os.Getenv("PACKMON_WEBHOOK_URL")); envWebhookURL != "" {
		settings.WebhookURL = envWebhookURL
	}
	if envWebhookSecret := strings.TrimSpace(os.Getenv("PACKMON_WEBHOOK_SECRET")); envWebhookSecret != "" {
		settings.WebhookSecret = envWebhookSecret
	}
	if envCACert := clientCACertEnvValue(); envCACert != "" {
		settings.CACertFile = envCACert
	}
	if envLogLevel := normalizeLogLevel(os.Getenv("PACKMON_LOG_LEVEL")); envLogLevel != "" {
		settings.LogLevel = envLogLevel
	}
	if envLogFormat := strings.TrimSpace(os.Getenv("PACKMON_LOG_FORMAT")); envLogFormat != "" {
		settings.LogFormat = strings.ToLower(envLogFormat)
	}
}

func applyScanTimeoutEnvSetting(settings *scanSettings) error {
	if envTimeout := strings.TrimSpace(os.Getenv("PACKMON_TIMEOUT")); envTimeout != "" {
		parsed, parseErr := parseTimeoutSeconds(envTimeout)
		if parseErr != nil {
			return fmt.Errorf("PACKMON_TIMEOUT: %w", parseErr)
		}
		if parsed <= 0 {
			return fmt.Errorf("PACKMON_TIMEOUT must be greater than zero")
		}
		settings.Timeout = parsed
	}
	return nil
}

func applyScanBooleanEnvSettings(settings *scanSettings) error {
	if envInsecure := strings.TrimSpace(os.Getenv("PACKMON_INSECURE_ALLOW_HTTP")); envInsecure != "" {
		insecure, _, parseErr := strictEnvBool("PACKMON_INSECURE_ALLOW_HTTP")
		if parseErr != nil {
			return parseErr
		}
		settings.InsecureHTTP = insecure
	}
	if envRequireRemote := strings.TrimSpace(os.Getenv("PACKMON_REQUIRE_REMOTE")); envRequireRemote != "" {
		requireRemote, _, parseErr := strictEnvBool("PACKMON_REQUIRE_REMOTE")
		if parseErr != nil {
			return parseErr
		}
		settings.RequireRemote = requireRemote
	}
	if envNoRepoMetadata := strings.TrimSpace(os.Getenv("PACKMON_NO_REPO_METADATA")); envNoRepoMetadata != "" {
		noRepoMetadata, _, parseErr := strictEnvBool("PACKMON_NO_REPO_METADATA")
		if parseErr != nil {
			return parseErr
		}
		settings.OmitRepoMetadata = noRepoMetadata
	}

	return nil
}

func applyScanFlagSettings(settings *scanSettings, cmd *cobra.Command, flags scanFlagValues) {
	applyScanCoreFlagSettings(settings, cmd, flags)
	applyScanRemoteFlagSettings(settings, cmd, flags)
	applyScanOutputFlagSettings(settings, cmd, flags)
}

func applyScanCoreFlagSettings(settings *scanSettings, cmd *cobra.Command, flags scanFlagValues) {
	if commandFlagChanged(cmd, "mode") {
		settings.Mode = normalizeModeString(flags.Mode)
	}
	if commandFlagChanged(cmd, "server") {
		settings.ServerURL = strings.TrimSpace(flags.Server)
	}
	if commandFlagChanged(cmd, "api-key") {
		settings.APIKey = strings.TrimSpace(flags.APIKey)
	}
	if commandFlagChanged(cmd, "fail-on") {
		settings.FailOn = normalizeSeverityString(flags.FailOn)
	}
	if commandFlagChanged(cmd, "ecosystems") {
		settings.Ecosystems = splitCSV(flags.Ecosystems)
	}
	if commandFlagChanged(cmd, "timeout") {
		settings.Timeout = flags.Timeout
	}
	if commandFlagChanged(cmd, "include-dev") {
		settings.IncludeDev = flags.IncludeDev
	}
	if commandFlagChanged(cmd, "sbom") {
		settings.SBOMFiles = append([]string(nil), flags.SBOMFiles...)
	}
	if commandFlagChanged(cmd, "list-all-offline") {
		settings.ListAllOffline = flags.ListAllOffline
	}
}

func applyScanRemoteFlagSettings(settings *scanSettings, cmd *cobra.Command, flags scanFlagValues) {
	if commandFlagChanged(cmd, "webhook-url") {
		settings.WebhookURL = strings.TrimSpace(flags.WebhookURL)
	}
	if commandFlagChanged(cmd, "webhook-secret") {
		settings.WebhookSecret = strings.TrimSpace(flags.WebhookSecret)
	}
	if commandFlagChanged(cmd, "cacert") {
		settings.CACertFile = strings.TrimSpace(flags.CACert)
	}
	if commandFlagChanged(cmd, "insecure-allow-http") {
		settings.InsecureHTTP = flags.InsecureHTTP
	}
	if commandFlagChanged(cmd, "require-remote") {
		settings.RequireRemote = flags.RequireRemote
	}
	if commandFlagChanged(cmd, "no-repo-metadata") {
		settings.OmitRepoMetadata = flags.OmitRepoMetadata
	}
	if commandFlagChanged(cmd, "log-level") {
		settings.LogLevel = normalizeLogLevel(flagLogLevel)
	}
}

func applyScanOutputFlagSettings(settings *scanSettings, cmd *cobra.Command, flags scanFlagValues) {
	for _, artifact := range scanOutputArtifacts {
		path := strings.TrimSpace(artifact.pathFromFlags(flags))
		if commandFlagChanged(cmd, artifact.flagName) || path != "" {
			artifact.setPath(settings, path)
		}
	}
}

func validateResolvedScanSettings(settings *scanSettings, flags scanFlagValues, cmd *cobra.Command) error {
	if err := validateModeString(settings.Mode); err != nil {
		return err
	}
	if err := validateSeverityString(settings.FailOn); err != nil {
		return err
	}
	if err := validateResolvedScanLogLevel(settings, cmd); err != nil {
		return err
	}
	if err := validateResolvedScanLogFormat(settings); err != nil {
		return err
	}
	if settings.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	if settings.MaxDepth < 0 {
		return fmt.Errorf("max-depth must be zero or greater")
	}
	ecosystems, err := validateScanEcosystemFilters(settings.Ecosystems, flags.ListAll)
	if err != nil {
		return err
	}
	settings.Ecosystems = ecosystems

	return nil
}

func validateResolvedScanLogLevel(settings *scanSettings, cmd *cobra.Command) error {
	level := normalizeLogLevel(settings.LogLevel)
	switch level {
	case "DEBUG", "INFO", "WARN", "ERROR":
		settings.LogLevel = level
		return nil
	}

	if commandFlagChanged(cmd, "log-level") {
		return fmt.Errorf("--log-level must be one of DEBUG, INFO, WARN, ERROR (got %q)", settings.LogLevel)
	}
	if raw := strings.TrimSpace(os.Getenv("PACKMON_LOG_LEVEL")); raw != "" && normalizeLogLevel(raw) == level {
		return fmt.Errorf("PACKMON_LOG_LEVEL must be one of DEBUG, INFO, WARN, ERROR (got %q)", raw)
	}
	return fmt.Errorf("invalid log level %q (want DEBUG|INFO|WARN|ERROR)", settings.LogLevel)
}

func validateResolvedScanLogFormat(settings *scanSettings) error {
	format := strings.ToLower(strings.TrimSpace(settings.LogFormat))
	switch format {
	case "text", "json":
		settings.LogFormat = format
		return nil
	}

	if raw := strings.TrimSpace(os.Getenv("PACKMON_LOG_FORMAT")); raw != "" && strings.EqualFold(strings.TrimSpace(raw), strings.TrimSpace(settings.LogFormat)) {
		return fmt.Errorf("PACKMON_LOG_FORMAT must be one of text, json (got %q)", raw)
	}
	return fmt.Errorf("invalid log format %q (want text|json)", settings.LogFormat)
}

func commandFlagChanged(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	flag := cmd.Flag(name)
	return flag != nil && flag.Changed
}

func validateScanEcosystemFilters(ecosystems []string, allowInventoryOnly bool) ([]string, error) {
	if len(ecosystems) == 0 {
		return nil, nil
	}
	valid := validScanEcosystemFilterValues(allowInventoryOnly)
	allowed := make(map[string]struct{}, len(valid))
	for _, value := range valid {
		allowed[value] = struct{}{}
	}
	out := make([]string, 0, len(ecosystems))
	for _, raw := range ecosystems {
		ecosystem := strings.ToLower(strings.TrimSpace(raw))
		if ecosystem == "" {
			continue
		}
		if _, ok := allowed[ecosystem]; !ok {
			return nil, fmt.Errorf("unknown ecosystem filter %q (valid values: %s)", ecosystem, strings.Join(valid, ", "))
		}
		out = append(out, ecosystem)
	}
	return out, nil
}

// validScanEcosystemFilterValues lists the accepted --ecosystems values.
// Inventory-only ecosystems (docker, chocolatey) are accepted only when the
// caller renders inventory (--list-all), because they never take part in
// vulnerability scanning.
func validScanEcosystemFilterValues(allowInventoryOnly bool) []string {
	values := []string{
		string(domain.EcosystemNPM),
		string(domain.EcosystemPyPI),
		string(domain.EcosystemGo),
		string(domain.EcosystemMaven),
		string(domain.EcosystemCargo),
		string(domain.EcosystemNuGet),
		string(domain.EcosystemComposer),
		string(domain.EcosystemGem),
		string(domain.EcosystemPub),
		string(domain.EcosystemGitHubActions),
		string(domain.EcosystemCocoaPods),
		string(domain.EcosystemSwiftPM),
		string(domain.EcosystemHex),
		string(domain.EcosystemCRAN),
	}
	if allowInventoryOnly {
		values = append(values, string(domain.EcosystemDocker), string(domain.EcosystemChocolatey))
	}
	sort.Strings(values)
	return values
}

func resolveAPIKeyEnv(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("api_key_env %q is not set", name)
	}
	return value, nil
}

func applyOutputConfig(settings *scanSettings, cfg cliOutputConfig) {
	file := strings.TrimSpace(cfg.File)
	if file == "" {
		return
	}
	artifact, ok := scanOutputArtifactForFormat(cfg.Format)
	if !ok {
		return
	}
	artifact.setPath(settings, file)
}

// scanLogger builds the structured logger for the scan pipeline. It writes
// text to stderr at the level selected by --log-level (raised to ERROR when
// --quiet is set). Sensitive values are never logged by the scanner.
func scanLogger(quiet bool, logLevel, logFormat string) *slog.Logger {
	return newScanLogger(os.Stderr, quiet, logLevel, logFormat)
}

func newScanLogger(w io.Writer, quiet bool, logLevel, logFormat string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToUpper(strings.TrimSpace(logLevel)) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	}
	if quiet {
		level = slog.LevelError
	}
	options := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(strings.TrimSpace(logFormat), "json") {
		return slog.New(slog.NewJSONHandler(w, options))
	}
	return slog.New(slog.NewTextHandler(w, options))
}

func scanSettingsLogger(settings scanSettings) *slog.Logger {
	if settings.Logger != nil {
		return settings.Logger
	}
	return scanLogger(settings.Quiet, settings.LogLevel, settings.LogFormat)
}

// autoFallbackWarning returns a user-facing warning when an auto-mode scan fell
// back to the local database (remote unreachable), or "" when no warning is
// needed. The local DB age is included when known.
func autoFallbackWarning(mode scanner.Mode, result *domain.ScanResult) string {
	if mode != scanner.ModeAuto || result == nil || result.Mode != scanner.ModeLocal {
		return ""
	}
	if result.DBAgeDays != nil {
		return fmt.Sprintf("warning: remote server unreachable, scanned against local database (%s old)", plural.Count(*result.DBAgeDays, "day", "days"))
	}
	return "warning: remote server unreachable, scanned against local database"
}

const failOnNoneWarning = "warning: fail_on NONE disables vulnerability blocking only; malicious and active supply-chain risk findings still block."

// runScanPipeline builds the scanner.Config from settings, opens local SQLite
// only when local checking or history needs it, runs the scan, applies DB
// freshness, surfaces the auto fallback warning, and records scan history. It is
// the shared core used by both runSingleScan (which then prints tables and
// writes output files) and runListAll (which renders its own combined report).
// It does NOT print the findings table or write any output files.
func runScanPipeline(ctx context.Context, settings scanSettings) (*domain.ScanResult, domain.Severity, int, *domain.RepoInfo, *scanner.PackageCollection, error) {
	input, err := resolveScanPipelineInput(settings)
	if err != nil {
		return nil, input.failOn, ExitOperational, nil, nil, err
	}
	if input.failOn == domain.SeverityNone {
		fmt.Fprintln(os.Stderr, failOnNoneWarning)
	}

	var repoInfo *domain.RepoInfo
	if scanNeedsRepoMetadata(settings) {
		repoInfo = scanRepoInfo(settings.Path)
	}
	cfg := buildScannerConfig(settings, repoInfo, input.failOn, input.mode)
	reg := parser.NewRegistry()
	sc := scanner.New(reg, cfg)

	local, err := openLocalCheckerIfNeeded(ctx, input.mode, settings)
	if err != nil {
		return nil, input.failOn, ExitOperational, repoInfo, nil, err
	}
	defer local.close()
	if checker := local.localChecker(); checker != nil {
		sc.SetLocalChecker(checker)
	}

	result, exitCode, collection := sc.RunWithCollection(ctx)
	if store := local.openedStore(); store != nil {
		if err := applyLocalDBFreshness(ctx, store, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to determine local DB freshness: %v\n", err)
		}
	}

	// Auto mode falls back to the local database when the remote server is
	// unreachable. Surface this to the user along with the local DB age so a
	// silent stale-data scan cannot be mistaken for a fresh remote scan.
	if msg := autoFallbackWarning(input.mode, result); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}

	historyConfig, recordHistory, err := scanHistoryConfigForExitCode(exitCode)
	if err != nil {
		return result, input.failOn, ExitOperational, repoInfo, collection, err
	}
	if recordHistory && repoInfo == nil {
		repoInfo = scanRepoInfo(settings.Path)
	}
	history, closeHistory := ensureHistoryStore(ctx, local, recordHistory)
	if closeHistory {
		defer ioutils.CloseSilently(history)
	}
	if err := recordSuccessfulScanHistory(ctx, history, repoInfo, result, recordHistory, historyConfig); err != nil {
		return result, input.failOn, ExitOperational, repoInfo, collection, &scanHistoryRecordError{err: err}
	}

	return result, input.failOn, exitCode, repoInfo, collection, nil
}

func scanNeedsRepoMetadata(settings scanSettings) bool {
	return !settings.OmitRepoMetadata
}

type scanPipelineInput struct {
	failOn domain.Severity
	mode   scanner.Mode
}

type localScanStore struct {
	store                 *sqlite.Store
	dbPath                string
	advisoryDataAvailable bool
	lazyChecker           *lazyLocalChecker
}

type scanHistoryConfig struct {
	MaxScansPerRepo int
	MaxAge          time.Duration
}

func resolveScanPipelineInput(settings scanSettings) (scanPipelineInput, error) {
	failOn, ok := domain.ParseBlockThreshold(settings.FailOn)
	if !ok {
		return scanPipelineInput{failOn: failOn}, fmt.Errorf("invalid fail_on value %q", settings.FailOn)
	}

	mode, err := scanner.ParseMode(settings.Mode)
	if err != nil {
		return scanPipelineInput{failOn: failOn}, fmt.Errorf("invalid mode value %q", settings.Mode)
	}

	return scanPipelineInput{failOn: failOn, mode: mode}, nil
}

func buildScannerConfig(settings scanSettings, repoInfo *domain.RepoInfo, failOn domain.Severity, mode scanner.Mode) scanner.Config {
	return scanner.Config{
		Path:                 settings.Path,
		Mode:                 mode,
		ServerURL:            settings.ServerURL,
		APIKey:               settings.APIKey,
		Repo:                 repoInfo,
		FailOn:               failOn,
		Ecosystems:           settings.Ecosystems,
		MaxDepth:             settings.MaxDepth,
		Timeout:              time.Duration(settings.Timeout) * time.Second,
		IncludeDev:           settings.IncludeDev,
		InventoryAllPackages: settings.InventoryAll,
		Quiet:                settings.Quiet,
		NoColor:              settings.NoColor,
		Version:              version,
		SBOMFiles:            settings.SBOMFiles,

		CACertFile:        settings.CACertFile,
		AllowInsecureHTTP: settings.InsecureHTTP,
		RequireRemote:     settings.RequireRemote,
		OmitRepoMetadata:  settings.OmitRepoMetadata,

		Logger: scanSettingsLogger(settings),
	}
}

func openLocalCheckerIfNeeded(ctx context.Context, mode scanner.Mode, settings scanSettings) (localScanStore, error) {
	if !scanNeedsLocalChecker(mode, settings.RequireRemote) {
		return localScanStore{}, nil
	}
	if mode == scanner.ModeAuto {
		return localScanStore{lazyChecker: &lazyLocalChecker{}}, nil
	}

	dbPath, err := resolveLocalDBPath()
	if err != nil {
		return localScanStore{}, err
	}

	store, advisoryDataAvailable, historyErr := openLocalSQLiteStore(ctx, dbPath)
	if historyErr != nil {
		warnUnableToOpenLocalDatabase(historyErr)
		return localScanStore{dbPath: dbPath}, nil
	}

	return localScanStore{store: store, dbPath: dbPath, advisoryDataAvailable: advisoryDataAvailable}, nil
}

func (l localScanStore) localChecker() scanner.LocalChecker {
	if l.lazyChecker != nil {
		return l.lazyChecker
	}
	if l.store == nil || !l.advisoryDataAvailable {
		return nil
	}
	return scanner.NewDBLocalCheckerAdapter(l.store)
}

func (l localScanStore) openedStore() *sqlite.Store {
	if l.store != nil {
		return l.store
	}
	if l.lazyChecker != nil {
		return l.lazyChecker.openedStore()
	}
	return nil
}

func (l localScanStore) close() {
	if l.store != nil {
		ioutils.CloseSilently(l.store)
	}
	if l.lazyChecker != nil {
		l.lazyChecker.close()
	}
}

var errLocalAdvisoryDataUnavailable = errors.New("local advisory data unavailable (run 'packmon db sync' first)")

type lazyLocalChecker struct {
	mu      sync.Mutex
	store   *sqlite.Store
	adapter *scanner.DBLocalCheckerAdapter
	err     error
}

var (
	_ scanner.LocalChecker      = (*lazyLocalChecker)(nil)
	_ scanner.BatchLocalChecker = (*lazyLocalChecker)(nil)
)

func (l *lazyLocalChecker) ensure(ctx context.Context) (*scanner.DBLocalCheckerAdapter, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.adapter != nil {
		return l.adapter, nil
	}
	if l.err != nil {
		return nil, l.err
	}

	dbPath, err := resolveLocalDBPath()
	if err != nil {
		l.err = errLocalAdvisoryDataUnavailable
		fmt.Fprintf(os.Stderr, "warning: unable to resolve local database path: %v\n", err)
		return nil, l.err
	}
	store, advisoryDataAvailable, openErr := openLocalSQLiteStore(ctx, dbPath)
	if openErr != nil {
		l.err = errLocalAdvisoryDataUnavailable
		warnUnableToOpenLocalDatabase(openErr)
		return nil, l.err
	}
	l.store = store
	if !advisoryDataAvailable {
		l.err = errLocalAdvisoryDataUnavailable
		return nil, l.err
	}

	l.adapter = scanner.NewDBLocalCheckerAdapter(store)
	return l.adapter, nil
}

func (l *lazyLocalChecker) openedStore() *sqlite.Store {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.store
}

func (l *lazyLocalChecker) close() {
	l.mu.Lock()
	store := l.store
	l.store = nil
	l.adapter = nil
	l.mu.Unlock()

	if store != nil {
		ioutils.CloseSilently(store)
	}
}

func (l *lazyLocalChecker) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	checker, err := l.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return checker.FindVulnerabilities(ctx, ecosystem, name, version)
}

func (l *lazyLocalChecker) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	checker, err := l.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return checker.FindMalicious(ctx, ecosystem, name, version)
}

func (l *lazyLocalChecker) FindVulnerabilitiesBatch(ctx context.Context, packages []scanner.PackageLookup) ([]domain.Finding, error) {
	checker, err := l.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return checker.FindVulnerabilitiesBatch(ctx, packages)
}

func (l *lazyLocalChecker) FindMaliciousBatch(ctx context.Context, packages []scanner.PackageLookup) ([]domain.Finding, error) {
	checker, err := l.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return checker.FindMaliciousBatch(ctx, packages)
}

func (l *lazyLocalChecker) FindReputationFindingsBatch(ctx context.Context, packages []scanner.PackageLookup, source string) ([]domain.Finding, error) {
	checker, err := l.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return checker.FindReputationFindingsBatch(ctx, packages, source)
}

func (l *lazyLocalChecker) FindLifecycleFindingsBatch(ctx context.Context, packages []scanner.PackageLookup, now time.Time) ([]domain.Finding, error) {
	checker, err := l.ensure(ctx)
	if err != nil {
		return nil, err
	}
	return checker.FindLifecycleFindingsBatch(ctx, packages, now)
}

func ensureHistoryStore(ctx context.Context, local localScanStore, recordHistory bool) (*sqlite.Store, bool) {
	if !recordHistory {
		return nil, false
	}
	if store := local.openedStore(); store != nil {
		return store, false
	}

	dbPath := local.dbPath
	if dbPath == "" {
		var err error
		dbPath, err = resolveLocalDBPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to resolve local database path: %v\n", err)
			return nil, false
		}
	}

	store, _, historyErr := openLocalSQLiteStore(ctx, dbPath)
	if historyErr != nil {
		warnUnableToOpenLocalDatabase(historyErr)
		return nil, false
	}
	return store, true
}

func warnUnableToOpenLocalDatabase(err error) {
	fmt.Fprintf(os.Stderr, "warning: unable to open local database: %s\n", logsafe.RedactDiagnosticMessage(err.Error()))
}

type scanHistoryRecordError struct {
	err error
}

func (e *scanHistoryRecordError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *scanHistoryRecordError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func recordSuccessfulScanHistory(ctx context.Context, historyStore *sqlite.Store, repoInfo *domain.RepoInfo, result *domain.ScanResult, recordHistory bool, historyConfig scanHistoryConfig) error {
	if historyStore == nil || !recordHistory {
		return nil
	}
	if err := recordScanHistoryWithRepo(ctx, historyStore, repoInfo, result); err != nil {
		repoName, packageCount, findingCount := scanHistoryFailureContext(repoInfo, result)
		wrapped := fmt.Errorf("store scan history for repo %s (packages=%d findings=%d): %w", repoName, packageCount, findingCount, err)
		fmt.Fprintf(os.Stderr, "warning: unable to store scan history for repo %s (packages=%d findings=%d): %s\n",
			repoName, packageCount, findingCount, logsafe.RedactDiagnosticMessage(err.Error()))
		return wrapped
	}
	if historyConfig.MaxScansPerRepo > 0 {
		if err := historyStore.EnforceRetention(ctx, historyConfig.MaxScansPerRepo); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to enforce history retention: %v\n", err)
		}
	}
	if historyConfig.MaxAge > 0 {
		cutoff := time.Now().UTC().Add(-historyConfig.MaxAge)
		if _, err := historyStore.ClearHistory(ctx, &cutoff, ""); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to enforce history age retention: %v\n", err)
		}
	}
	return nil
}

func scanHistoryFailureContext(repoInfo *domain.RepoInfo, result *domain.ScanResult) (string, int, int) {
	repoName := "unknown"
	if repoInfo != nil && strings.TrimSpace(repoInfo.Name) != "" {
		repoName = logsafe.BoundedDiagnosticValue(repoInfo.Name, 128)
	}
	if result == nil {
		return repoName, 0, 0
	}
	return repoName, result.PackagesScanned, result.FindingsCount
}

func scanHistoryConfigForExitCode(exitCode int) (scanHistoryConfig, bool, error) {
	enabled, err := historyEnabled()
	if err != nil {
		return scanHistoryConfig{}, false, err
	}
	if !enabled || !historyRecordableExitCode(exitCode) {
		return scanHistoryConfig{}, false, nil
	}
	maxPerRepo, err := historyMaxScansPerRepo()
	if err != nil {
		return scanHistoryConfig{}, false, err
	}
	maxAge, err := historyMaxAge()
	if err != nil {
		return scanHistoryConfig{}, false, err
	}
	return scanHistoryConfig{MaxScansPerRepo: maxPerRepo, MaxAge: maxAge}, true, nil
}

func shouldRecordScanHistory(exitCode int) (bool, error) {
	enabled, err := historyEnabled()
	if err != nil {
		return false, err
	}
	return enabled && historyRecordableExitCode(exitCode), nil
}

func historyRecordableExitCode(exitCode int) bool {
	return exitCode == ExitOK || exitCode == ExitBlocking || exitCode == ExitUnderThreshold
}

func scanNeedsLocalChecker(mode scanner.Mode, requireRemote bool) bool {
	return mode == scanner.ModeLocal || (mode == scanner.ModeAuto && !requireRemote)
}

func runSingleScan(ctx context.Context, settings scanSettings) (int, error) {
	logger := scanSettingsLogger(settings)
	settings.Logger = logger

	result, failOn, exitCode, repoInfo, _, err := runScanPipeline(ctx, settings)
	var historyErr *scanHistoryRecordError
	if err != nil && !errors.As(err, &historyErr) {
		return exitCode, err
	}

	reportScanParseErrors(result)

	if !settings.Quiet {
		tw := scanner.NewTableWriter(settings.NoColor, failOn)
		if err := tw.Write(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing table output: %v\n", err)
		}
	}

	if writeScanOutputArtifacts(settings, result, failOn, true) {
		exitCode = ExitOperational
	}

	if settings.WebhookURL != "" {
		webhookRepo := repoInfo
		if settings.OmitRepoMetadata {
			webhookRepo = nil
		}
		whCfg := scanner.WebhookConfig{
			URL:     settings.WebhookURL,
			Secret:  settings.WebhookSecret,
			Version: version,
			Logger:  logger,
		}
		scanner.SendWebhook(ctx, whCfg, result, webhookRepo)
	}

	if historyErr != nil {
		return exitCode, historyErr
	}
	return exitCode, nil
}

func writeScanOutputArtifacts(settings scanSettings, result *domain.ScanResult, failOn domain.Severity, includeHTML bool) bool {
	hadError := false
	for _, artifact := range scanOutputArtifacts {
		if artifact.includeHTMLOnly && !includeHTML {
			continue
		}
		path := strings.TrimSpace(artifact.pathFromSettings(settings))
		if path == "" {
			continue
		}
		if artifact.prepareOutputDir {
			if err := ensureOutputDir(path); err != nil {
				fmt.Fprintf(os.Stderr, "error preparing %s output: %v\n", artifact.displayName, err)
				hadError = true
				continue
			}
		}
		ctx := scanOutputArtifactWrite{
			path:     path,
			settings: settings,
			result:   result,
			failOn:   failOn,
		}
		if err := artifact.write(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s output: %v\n", artifact.displayName, err)
			hadError = true
			continue
		}
		if artifact.announce != nil {
			artifact.announce(ctx)
		}
	}
	return hadError
}

func reportScanParseErrors(result *domain.ScanResult) {
	if result == nil {
		return
	}
	parseErrors, omitted := scanner.BoundedParseDiagnostics(result.ParseErrors)
	for _, parseErr := range parseErrors {
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", termtext.Sanitize(parseErr))
	}
	if summary := scanner.ParseDiagnosticsOmittedSummary(omitted); summary != "" {
		fmt.Fprintf(os.Stderr, "warning: %s\n", summary)
	}
}

func writeJSONFile(path string, result *domain.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	if err := ensureOutputDir(path); err != nil {
		return err
	}
	file, err := ioutils.OpenPrivateFile(path)
	if err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		ioutils.CloseSilently(file)
		return fmt.Errorf("write file %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close file %s: %w", path, err)
	}
	return nil
}

func ensureOutputDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create output directory %s: %w", dir, err)
	}
	return nil
}

func openLocalSQLiteStore(ctx context.Context, dbPath string) (*sqlite.Store, bool, error) {
	store, err := sqlite.New(dbPath)
	if err != nil {
		return nil, false, err
	}

	advisoryDataAvailable, err := store.HasAdvisoryData(ctx)
	if err != nil {
		ioutils.CloseSilently(store)
		return nil, false, err
	}

	return store, advisoryDataAvailable, nil
}

func fatalCollectionParseError(collection *scanner.PackageCollection) error {
	if collection == nil || len(collection.FatalParseErrors) == 0 {
		return nil
	}
	return withExitCode(ExitParser, fmt.Errorf("%s", termtext.Sanitize(strings.Join(collection.FatalParseErrors, "; "))))
}
