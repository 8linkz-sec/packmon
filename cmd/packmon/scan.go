package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
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
		Long: `Scan the given directory (default ".") for lock files and SBOMs,
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
					Context:    cmd.Context(),
					Ecosystems: strings.Join(settings.Ecosystems, ","),
					MaxDepth:   settings.MaxDepth,
					IncludeDev: true,
					OutputHTML: settings.OutputHTML,
					Quiet:      settings.Quiet,
					SBOMFiles:  settings.SBOMFiles,
					Timeout:    settings.Timeout,
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
	f.StringVar(&flagAPIKey, "api-key", "", "API key for authenticated remote scans")
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
	f.StringVar(&flagWebhookSecret, "webhook-secret", "", "HMAC-SHA256 secret for webhook authentication header")
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
	Quiet            bool
	NoColor          bool
	CACertFile       string
	InsecureHTTP     bool
	RequireRemote    bool
	OmitRepoMetadata bool
	SBOMFiles        []string
	ListAllOffline   bool
	InventoryAll     bool
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
	hasConfigOutput := cfg != nil && strings.TrimSpace(cfg.Output.File) != ""
	if len(targets) > 1 && (hasConfigOutput || strings.TrimSpace(flags.OutputJSON) != "" || strings.TrimSpace(flags.OutputSARIF) != "" || strings.TrimSpace(flags.OutputJUnit) != "" || strings.TrimSpace(flags.OutputHTML) != "") {
		return withExitCode(ExitOperational, fmt.Errorf("--output-json, --output-sarif, --output-junit, and --html can only be used when scanning a single target, not multiple targets"))
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
	targetName := filepath.Base(path)
	if targetName == "" || targetName == "." || (len(targetName) == 1 && os.IsPathSeparator(targetName[0])) {
		targetName = "local"
	}
	return []scanTarget{{Name: targetName, Path: path}}, nil
}

func resolveScanSettings(cmd *cobra.Command, cfg *cliConfig, target scanTarget, flags scanFlagValues) (scanSettings, error) {
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
	if err := validateResolvedScanSettings(&settings, flags); err != nil {
		return scanSettings{}, err
	}

	return settings, nil
}

func defaultScanSettings(target scanTarget, flags scanFlagValues) scanSettings {
	return scanSettings{
		TargetName: target.Name,
		Path:       target.Path,
		Mode:       "auto",
		FailOn:     string(defaultFailSeverity()),
		MaxDepth:   flags.MaxDepth,
		Timeout:    30,
		Quiet:      flags.Quiet,
		NoColor:    flags.NoColor,
		LogLevel:   "INFO",
		LogFormat:  "text",
	}
}

func applyScanConfigSettings(settings *scanSettings, cfg *cliConfig, skipAPIKeyEnv bool) error {
	if cfg == nil {
		return nil
	}

	if cfg.Server != "" {
		settings.ServerURL = cfg.Server
	}
	if cfg.APIKey != "" {
		settings.APIKey = cfg.APIKey
	}
	if cfg.APIKeyEnv != "" && !skipAPIKeyEnv {
		apiKey, err := resolveAPIKeyEnv(cfg.APIKeyEnv)
		if err != nil {
			return err
		}
		settings.APIKey = apiKey
	}
	if cfg.Mode != "" {
		settings.Mode = cfg.Mode
	}
	if cfg.FailOn != "" {
		settings.FailOn = cfg.FailOn
	}
	if cfg.Timeout > 0 {
		settings.Timeout = cfg.Timeout
	}
	if len(cfg.Ecosystems) > 0 {
		settings.Ecosystems = append([]string(nil), cfg.Ecosystems...)
	}
	settings.IncludeDev = boolValue(cfg.IncludeDev, settings.IncludeDev)
	if cfg.Webhook.URL != "" {
		settings.WebhookURL = cfg.Webhook.URL
	}
	if cfg.Webhook.Secret != "" {
		settings.WebhookSecret = cfg.Webhook.Secret
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
	settings.InsecureHTTP = boolValue(cfg.InsecureAllowHTTP, settings.InsecureHTTP)
	settings.RequireRemote = boolValue(cfg.RequireRemote, settings.RequireRemote)
	if cfg.SendRepoMetadata != nil {
		settings.OmitRepoMetadata = !*cfg.SendRepoMetadata
	}

	return nil
}

func applyScanRepoSettings(settings *scanSettings, repo *cliRepoConfig, skipAPIKeyEnv bool) error {
	if repo == nil {
		return nil
	}

	if repo.Server != "" {
		settings.ServerURL = repo.Server
	}
	if repo.APIKey != "" {
		settings.APIKey = repo.APIKey
	}
	if repo.APIKeyEnv != "" && !skipAPIKeyEnv {
		apiKey, err := resolveAPIKeyEnv(repo.APIKeyEnv)
		if err != nil {
			return err
		}
		settings.APIKey = apiKey
	}
	if repo.Mode != "" {
		settings.Mode = repo.Mode
	}
	if repo.FailOn != "" {
		settings.FailOn = repo.FailOn
	}
	if repo.Timeout > 0 {
		settings.Timeout = repo.Timeout
	}
	if len(repo.Ecosystems) > 0 {
		settings.Ecosystems = append([]string(nil), repo.Ecosystems...)
	}
	settings.IncludeDev = boolValue(repo.IncludeDev, settings.IncludeDev)
	if repo.SendRepoMetadata != nil {
		settings.OmitRepoMetadata = !*repo.SendRepoMetadata
	}
	if repo.Webhook.URL != "" {
		settings.WebhookURL = repo.Webhook.URL
	}
	if repo.Webhook.Secret != "" {
		settings.WebhookSecret = repo.Webhook.Secret
	}

	return nil
}

func applyScanEnvSettings(settings *scanSettings, envAPIKey string) error {
	applyScanStringEnvSettings(settings, envAPIKey)
	if err := applyScanTimeoutEnvSetting(settings); err != nil {
		return err
	}
	if err := applyScanBooleanEnvSettings(settings); err != nil {
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
	if envCACert := strings.TrimSpace(os.Getenv("PACKMON_CA_CERT")); envCACert != "" {
		settings.CACertFile = envCACert
	}
	if envLogLevel := normalizeLogLevel(os.Getenv("PACKMON_LOG_LEVEL")); envLogLevel != "" {
		settings.LogLevel = envLogLevel
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
	if commandFlagChanged(cmd, "output-json") || strings.TrimSpace(flags.OutputJSON) != "" {
		settings.OutputJSON = strings.TrimSpace(flags.OutputJSON)
	}
	if commandFlagChanged(cmd, "output-sarif") || strings.TrimSpace(flags.OutputSARIF) != "" {
		settings.OutputSARIF = strings.TrimSpace(flags.OutputSARIF)
	}
	if commandFlagChanged(cmd, "output-junit") || strings.TrimSpace(flags.OutputJUnit) != "" {
		settings.OutputJUnit = strings.TrimSpace(flags.OutputJUnit)
	}
	if commandFlagChanged(cmd, "html") || strings.TrimSpace(flags.OutputHTML) != "" {
		settings.OutputHTML = strings.TrimSpace(flags.OutputHTML)
	}
}

func validateResolvedScanSettings(settings *scanSettings, flags scanFlagValues) error {
	if err := validateModeString(settings.Mode); err != nil {
		return err
	}
	if err := validateSeverityString(settings.FailOn); err != nil {
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

func commandFlagChanged(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	flag := cmd.Flag(name)
	return flag != nil && flag.Changed
}

func validateScanEcosystemFilters(ecosystems []string, allowDocker bool) ([]string, error) {
	if len(ecosystems) == 0 {
		return nil, nil
	}
	valid := validScanEcosystemFilterValues(allowDocker)
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

func validScanEcosystemFilterValues(allowDocker bool) []string {
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
	if allowDocker {
		values = append(values, string(domain.EcosystemDocker))
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
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "json":
		settings.OutputJSON = file
	case "sarif":
		settings.OutputSARIF = file
	case "junit":
		settings.OutputJUnit = file
	case "html":
		settings.OutputHTML = file
	}
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

// autoFallbackWarning returns a user-facing warning when an auto-mode scan fell
// back to the local database (remote unreachable), or "" when no warning is
// needed. The local DB age is included when known.
func autoFallbackWarning(mode scanner.Mode, result *domain.ScanResult) string {
	if mode != scanner.ModeAuto || result == nil || result.Mode != string(scanner.ModeLocal) {
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
	failOn, ok := scanner.SeverityFromString(settings.FailOn)
	if !ok {
		return nil, failOn, ExitOperational, nil, nil, fmt.Errorf("invalid fail_on value %q", settings.FailOn)
	}

	var mode scanner.Mode
	switch settings.Mode {
	case string(scanner.ModeRemote):
		mode = scanner.ModeRemote
	case string(scanner.ModeLocal):
		mode = scanner.ModeLocal
	case "", string(scanner.ModeAuto):
		mode = scanner.ModeAuto
	default:
		return nil, failOn, ExitOperational, nil, nil, fmt.Errorf("invalid mode value %q", settings.Mode)
	}

	if failOn == domain.SeverityNone {
		fmt.Fprintln(os.Stderr, failOnNoneWarning)
	}

	repoInfo := scanRepoInfo(settings.Path)
	cfg := scanner.Config{
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

		Logger: scanLogger(settings.Quiet, settings.LogLevel, settings.LogFormat),
	}

	reg := parser.NewRegistry()
	sc := scanner.New(reg, cfg)

	var dbPath string
	var historyStore *sqlite.Store
	if scanNeedsLocalChecker(mode, settings.RequireRemote) {
		var err error
		dbPath, err = resolveLocalDBPath()
		if err != nil {
			return nil, failOn, ExitOperational, repoInfo, nil, err
		}

		var advisoryDataAvailable bool
		var historyErr error
		historyStore, advisoryDataAvailable, historyErr = openLocalSQLiteStore(ctx, dbPath)
		if historyErr != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to open local database %s: %v\n", dbPath, historyErr)
		} else {
			defer closeSilently(historyStore)
			if advisoryDataAvailable {
				sc.SetLocalChecker(historyStore)
			}
		}
	}

	result, exitCode, collection := sc.RunWithCollection(ctx)
	if historyStore != nil {
		if err := applyLocalDBFreshness(ctx, historyStore, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to determine local DB freshness: %v\n", err)
		}
	}

	// Auto mode falls back to the local database when the remote server is
	// unreachable. Surface this to the user along with the local DB age so a
	// silent stale-data scan cannot be mistaken for a fresh remote scan.
	if msg := autoFallbackWarning(mode, result); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}

	if historyEnabled() && (exitCode == ExitOK || exitCode == ExitBlocking || exitCode == ExitUnderThreshold) {
		if historyStore == nil {
			if dbPath == "" {
				var err error
				dbPath, err = resolveLocalDBPath()
				if err != nil {
					fmt.Fprintf(os.Stderr, "warning: unable to resolve local database path: %v\n", err)
				}
			}
			if dbPath != "" {
				store, _, historyErr := openLocalSQLiteStore(ctx, dbPath)
				if historyErr != nil {
					fmt.Fprintf(os.Stderr, "warning: unable to open local database %s: %v\n", dbPath, historyErr)
				} else {
					historyStore = store
					defer closeSilently(historyStore)
				}
			}
		}
	}
	if historyStore != nil && historyEnabled() && (exitCode == ExitOK || exitCode == ExitBlocking || exitCode == ExitUnderThreshold) {
		if err := recordScanHistoryWithRepo(ctx, historyStore, repoInfo, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to store scan history: %v\n", err)
		} else if maxPerRepo := historyMaxScansPerRepo(); maxPerRepo > 0 {
			if err := historyStore.EnforceRetention(ctx, maxPerRepo); err != nil {
				fmt.Fprintf(os.Stderr, "warning: unable to enforce history retention: %v\n", err)
			}
		}
	}

	return result, failOn, exitCode, repoInfo, collection, nil
}

func scanNeedsLocalChecker(mode scanner.Mode, requireRemote bool) bool {
	return mode == scanner.ModeLocal || (mode == scanner.ModeAuto && !requireRemote)
}

func runSingleScan(ctx context.Context, settings scanSettings) (int, error) {
	result, failOn, exitCode, repoInfo, _, err := runScanPipeline(ctx, settings)
	if err != nil {
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
		}
		scanner.SendWebhook(ctx, whCfg, result, webhookRepo)
	}

	return exitCode, nil
}

func writeScanOutputArtifacts(settings scanSettings, result *domain.ScanResult, failOn domain.Severity, includeHTML bool) bool {
	hadError := false
	if settings.OutputJSON != "" {
		if err := writeJSONFile(settings.OutputJSON, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON output: %v\n", err)
			hadError = true
		}
	}

	if settings.OutputSARIF != "" {
		if err := ensureOutputDir(settings.OutputSARIF); err != nil {
			fmt.Fprintf(os.Stderr, "error preparing SARIF output: %v\n", err)
			hadError = true
		} else {
			sw := scanner.NewSARIFWriter(version)
			if err := sw.WriteFile(settings.OutputSARIF, result); err != nil {
				fmt.Fprintf(os.Stderr, "error writing SARIF output: %v\n", err)
				hadError = true
			}
		}
	}

	if settings.OutputJUnit != "" {
		if err := ensureOutputDir(settings.OutputJUnit); err != nil {
			fmt.Fprintf(os.Stderr, "error preparing JUnit output: %v\n", err)
			hadError = true
		} else {
			jw := scanner.NewJUnitWriter()
			if err := jw.WriteFile(settings.OutputJUnit, result); err != nil {
				fmt.Fprintf(os.Stderr, "error writing JUnit output: %v\n", err)
				hadError = true
			}
		}
	}

	if includeHTML && settings.OutputHTML != "" {
		if err := ensureOutputDir(settings.OutputHTML); err != nil {
			fmt.Fprintf(os.Stderr, "error preparing HTML output: %v\n", err)
			hadError = true
		} else {
			hw := scanner.NewHTMLWriter(version)
			if err := hw.WriteFile(settings.OutputHTML, settings.TargetName, failOn, result); err != nil {
				fmt.Fprintf(os.Stderr, "error writing HTML output: %v\n", err)
				hadError = true
			} else if !settings.Quiet {
				_, _ = fmt.Fprintf(os.Stdout, "HTML report written to: %s\n", settings.OutputHTML)
			}
		}
	}
	return hadError
}

func reportScanParseErrors(result *domain.ScanResult) {
	if result == nil {
		return
	}
	for _, parseErr := range result.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", termtext.Sanitize(parseErr))
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
		closeSilently(file)
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
		closeSilently(store)
		return nil, false, err
	}

	return store, advisoryDataAvailable, nil
}

// runListPackages walks the target directory, parses all lock files, and
// prints every detected package with version and ecosystem. No
// vulnerability check is performed.
func runListPackages(args []string, ecosystems string, maxDepth int, sbomFilesOpt ...[]string) error {
	var sbomFiles []string
	if len(sbomFilesOpt) > 0 {
		sbomFiles = sbomFilesOpt[0]
	}
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}
	return runListPackagesWithSettings(scanSettings{
		Path:       scanPath,
		Ecosystems: splitCSV(ecosystems),
		MaxDepth:   maxDepth,
		SBOMFiles:  sbomFiles,
		IncludeDev: true,
	})
}

func runListPackagesWithSettings(settings scanSettings) error {
	absPath, err := filepath.Abs(settings.Path)
	if err != nil {
		return withExitCode(ExitOperational, fmt.Errorf("resolve path: %w", err))
	}

	reg := parser.NewRegistry()
	collection, err := scanner.CollectPackages(scanner.CollectConfig{
		Registry:   reg,
		Root:       absPath,
		MaxDepth:   settings.MaxDepth,
		Ecosystems: settings.Ecosystems,
		SBOMFiles:  settings.SBOMFiles,
		IncludeDev: true,
	})
	if err != nil {
		return withDefaultExitCode(ExitOperational, err)
	}
	if err := fatalCollectionParseError(collection); err != nil {
		return err
	}

	if collection.LockFiles == 0 && collection.SBOMFiles == 0 {
		fmt.Println("No lock files found.")
		return nil
	}

	// Parse all lock files and collect packages.
	type pkgEntry struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
		LockFile  string `json:"lock_file"`
	}

	seen := make(map[string]struct{})
	var packages []pkgEntry

	for _, parseErr := range collection.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", termtext.Sanitize(parseErr))
	}
	for _, entry := range collection.Entries {
		p := entry.Package
		key := string(p.Ecosystem) + "/" + p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, pkgEntry{
			Name:      termtext.Sanitize(p.Name),
			Version:   termtext.Sanitize(p.Version),
			Ecosystem: termtext.Sanitize(string(p.Ecosystem)),
			LockFile:  termtext.Sanitize(entry.SourceFile),
		})
	}

	if len(packages) == 0 {
		fmt.Println("No packages found.")
		return nil
	}

	// Compute column widths.
	maxName, maxVer, maxEco := 4, 7, 9 // header widths: NAME, VERSION, ECOSYSTEM
	for _, p := range packages {
		if len(p.Name) > maxName {
			maxName = len(p.Name)
		}
		if len(p.Version) > maxVer {
			maxVer = len(p.Version)
		}
		if len(p.Ecosystem) > maxEco {
			maxEco = len(p.Ecosystem)
		}
	}

	gap := "  "
	fmtStr := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%s\n", maxName, gap, maxVer, gap, maxEco, gap)

	fmt.Printf(fmtStr, "NAME", "VERSION", "ECOSYSTEM", "LOCK FILE")
	for _, p := range packages {
		fmt.Printf(fmtStr, p.Name, p.Version, p.Ecosystem, p.LockFile)
	}

	fmt.Printf("\n%s found in %s\n",
		plural.Count(len(packages), "package", "packages"),
		plural.Count(collection.LockFiles+collection.SBOMFiles, "input file", "input files"))
	return nil
}

func fatalCollectionParseError(collection *scanner.PackageCollection) error {
	if collection == nil || len(collection.FatalParseErrors) == 0 {
		return nil
	}
	return withExitCode(ExitParser, fmt.Errorf("%s", termtext.Sanitize(strings.Join(collection.FatalParseErrors, "; "))))
}
