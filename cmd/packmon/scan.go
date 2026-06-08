package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db/sqlite"
	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
	"github.com/8linkz/packmon/internal/scanner"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		flagMode          string
		flagServer        string
		flagAPIKey        string
		flagFailOn        string
		flagEcosystems    string
		flagMaxDepth      int
		flagTimeout       int
		flagIncludeDev    bool
		flagOutputJSON    string
		flagOutputSARIF   string
		flagOutputJUnit   string
		flagOutputHTML    string
		flagWebhookURL    string
		flagWebhookSecret string
		flagAll           bool
		flagRepo          string
		flagListPackages  bool
		flagOutdated      bool
		flagListAll       bool
		flagCACert        string
		flagInsecureHTTP  bool
		flagRequireRemote bool
		flagSBOMFiles     []string
		flagAutoSBOM      bool
		flagInstallTools  bool
		flagKeepSBOM      string
		flagSBOMOnly      bool
	)

	cmd := &cobra.Command{
		Use:   "scan [PATH]",
		Short: "Scan directory for vulnerable dependencies",
		Long: `Scan the given directory (default ".") for lock files,
parse dependencies, and check them against known vulnerabilities
and malicious package databases.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanFlags := scanFlagValues{
				Mode:          flagMode,
				Server:        flagServer,
				APIKey:        flagAPIKey,
				FailOn:        flagFailOn,
				Ecosystems:    flagEcosystems,
				MaxDepth:      flagMaxDepth,
				Timeout:       flagTimeout,
				IncludeDev:    flagIncludeDev,
				OutputJSON:    flagOutputJSON,
				OutputSARIF:   flagOutputSARIF,
				OutputJUnit:   flagOutputJUnit,
				OutputHTML:    flagOutputHTML,
				WebhookURL:    flagWebhookURL,
				WebhookSecret: flagWebhookSecret,
				All:           flagAll,
				Repo:          flagRepo,
				Quiet:         flagQuiet,
				NoColor:       flagNoColor,
				CACert:        flagCACert,
				InsecureHTTP:  flagInsecureHTTP,
				RequireRemote: flagRequireRemote,
				SBOMFiles:     flagSBOMFiles,
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
				if flagListPackages || flagOutdated || flagListAll {
					return withExitCode(ExitOperational, fmt.Errorf("--auto-sbom cannot be combined with --list-packages, --outdated, or --list-all"))
				}
				return runAutoSBOMCommand(cmd, args, scanFlags, auto)
			}
			if flagListPackages {
				return runListPackages(args, flagEcosystems, flagMaxDepth, flagNoColor, flagSBOMFiles)
			}
			if flagOutdated {
				return runOutdatedWithOptions(args, outdatedOptions{
					Ecosystems: flagEcosystems,
					MaxDepth:   flagMaxDepth,
					IncludeDev: true,
					OutputHTML: flagOutputHTML,
					Quiet:      flagQuiet,
					SBOMFiles:  flagSBOMFiles,
				})
			}
			if flagListAll {
				cfg, _, err := loadCurrentCLIConfig()
				if err != nil {
					return err
				}
				targets, err := buildScanTargets(cfg, args, scanFlagValues{})
				if err != nil {
					return err
				}
				settings, err := resolveScanSettings(cmd, cfg, targets[0], scanFlagValues{
					Mode:          flagMode,
					Server:        flagServer,
					APIKey:        flagAPIKey,
					FailOn:        flagFailOn,
					Ecosystems:    flagEcosystems,
					MaxDepth:      flagMaxDepth,
					Timeout:       flagTimeout,
					IncludeDev:    flagIncludeDev,
					OutputHTML:    flagOutputHTML,
					Quiet:         flagQuiet,
					NoColor:       flagNoColor,
					CACert:        flagCACert,
					InsecureHTTP:  flagInsecureHTTP,
					RequireRemote: flagRequireRemote,
					SBOMFiles:     flagSBOMFiles,
				})
				if err != nil {
					return err
				}
				exitCode, err := runListAll(cmd.Context(), settings)
				if err != nil {
					return err
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
	f.StringVar(&flagFailOn, "fail-on", "CRITICAL", "block on severity (CRITICAL|HIGH|MEDIUM|LOW|NONE)")
	f.StringVar(&flagEcosystems, "ecosystems", "", "comma-separated ecosystem filter")
	f.IntVar(&flagMaxDepth, "max-depth", 10, "directory walk depth")
	f.IntVar(&flagTimeout, "timeout", 30, "HTTP timeout in seconds")
	f.BoolVar(&flagIncludeDev, "include-dev", false, "include dev dependencies")
	f.StringVar(&flagOutputJSON, "output-json", "", "write JSON results to file")
	f.StringVar(&flagOutputSARIF, "output-sarif", "", "write SARIF 2.1.0 results to file")
	f.StringVar(&flagOutputJUnit, "output-junit", "", "write JUnit XML results to file")
	f.StringVar(&flagOutputHTML, "html", "", "write a self-contained HTML report to file")
	f.StringVar(&flagWebhookURL, "webhook-url", "", "webhook URL to POST results to")
	f.StringVar(&flagWebhookSecret, "webhook-secret", "", "HMAC-SHA256 secret for webhook signature")
	f.BoolVar(&flagAll, "all", false, "scan all repositories configured in .packmon.yaml")
	f.StringVar(&flagRepo, "repo", "", "scan a configured repository by name")
	f.BoolVar(&flagListPackages, "list-packages", false, "list all detected packages and exit (no vulnerability check)")
	f.BoolVar(&flagOutdated, "outdated", false, "show packages with newer versions available")
	f.BoolVar(&flagListAll, "list-all", false, "list findings, then all packages with available-update info")
	f.StringVar(&flagCACert, "cacert", "", "path to a PEM CA bundle used to verify the server's TLS certificate")
	f.BoolVar(&flagInsecureHTTP, "insecure-allow-http", false, "allow plain http:// server URLs (sends bearer token in cleartext; opt-in)")
	f.BoolVar(&flagRequireRemote, "require-remote", false, "in auto mode, fail hard on remote error instead of falling back to the local database")
	f.StringArrayVar(&flagSBOMFiles, "sbom", nil, "SBOM file to include as package input (CycloneDX JSON/XML or SPDX JSON); can be repeated")
	f.BoolVar(&flagAutoSBOM, "auto-sbom", false, "generate an SBOM with CycloneDX tools and scan it")
	f.BoolVar(&flagInstallTools, "install-tools", false, "with --auto-sbom: auto-install missing CycloneDX generators (pinned versions)")
	f.StringVar(&flagKeepSBOM, "keep-sbom", "", "with --auto-sbom: write timestamped generated SBOM snapshots to this dir and keep them")
	f.BoolVar(&flagSBOMOnly, "sbom-only", false, "with --auto-sbom: only generate SBOMs, do not scan")

	return cmd
}

type scanFlagValues struct {
	Mode          string
	Server        string
	APIKey        string
	FailOn        string
	Ecosystems    string
	MaxDepth      int
	Timeout       int
	IncludeDev    bool
	OutputJSON    string
	OutputSARIF   string
	OutputJUnit   string
	OutputHTML    string
	WebhookURL    string
	WebhookSecret string
	All           bool
	Repo          string
	Quiet         bool
	NoColor       bool
	CACert        string
	InsecureHTTP  bool
	RequireRemote bool
	SBOMFiles     []string
}

type scanTarget struct {
	Name string
	Path string
	Repo *cliRepoConfig
}

type scanSettings struct {
	TargetName    string
	Path          string
	Mode          string
	ServerURL     string
	APIKey        string
	FailOn        string
	Ecosystems    []string
	MaxDepth      int
	Timeout       int
	IncludeDev    bool
	OutputJSON    string
	OutputSARIF   string
	OutputJUnit   string
	OutputHTML    string
	WebhookURL    string
	WebhookSecret string
	LogLevel      string
	Quiet         bool
	NoColor       bool
	CACertFile    string
	InsecureHTTP  bool
	RequireRemote bool
	SBOMFiles     []string
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
	skipConfigAPIKeyEnv := envAPIKey != "" || cmd.Flags().Changed("api-key")
	settings := scanSettings{
		TargetName: target.Name,
		Path:       target.Path,
		Mode:       "auto",
		FailOn:     string(defaultFailSeverity()),
		MaxDepth:   flags.MaxDepth,
		Timeout:    30,
		Quiet:      flags.Quiet,
		NoColor:    flags.NoColor,
		LogLevel:   strings.ToUpper(strings.TrimSpace(flagLogLevel)),
	}

	if cfg != nil {
		if cfg.Server != "" {
			settings.ServerURL = cfg.Server
		}
		if cfg.APIKey != "" {
			settings.APIKey = cfg.APIKey
		}
		if cfg.APIKeyEnv != "" && !skipConfigAPIKeyEnv {
			apiKey, err := resolveAPIKeyEnv(cfg.APIKeyEnv)
			if err != nil {
				return scanSettings{}, err
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
			applyOutputConfig(&settings, cfg.Output)
		}
		if cfg.Log.Level != "" {
			settings.LogLevel = cfg.Log.Level
		}
		if cfg.CACert != "" {
			settings.CACertFile = cfg.CACert
		}
		settings.InsecureHTTP = boolValue(cfg.InsecureAllowHTTP, settings.InsecureHTTP)
		settings.RequireRemote = boolValue(cfg.RequireRemote, settings.RequireRemote)
	}

	if target.Repo != nil {
		if target.Repo.Server != "" {
			settings.ServerURL = target.Repo.Server
		}
		if target.Repo.APIKey != "" {
			settings.APIKey = target.Repo.APIKey
		}
		if target.Repo.APIKeyEnv != "" && !skipConfigAPIKeyEnv {
			apiKey, err := resolveAPIKeyEnv(target.Repo.APIKeyEnv)
			if err != nil {
				return scanSettings{}, err
			}
			settings.APIKey = apiKey
		}
		if target.Repo.Mode != "" {
			settings.Mode = target.Repo.Mode
		}
		if target.Repo.FailOn != "" {
			settings.FailOn = target.Repo.FailOn
		}
		if target.Repo.Timeout > 0 {
			settings.Timeout = target.Repo.Timeout
		}
		if len(target.Repo.Ecosystems) > 0 {
			settings.Ecosystems = append([]string(nil), target.Repo.Ecosystems...)
		}
		settings.IncludeDev = boolValue(target.Repo.IncludeDev, settings.IncludeDev)
		if target.Repo.Webhook.URL != "" {
			settings.WebhookURL = target.Repo.Webhook.URL
		}
		if target.Repo.Webhook.Secret != "" {
			settings.WebhookSecret = target.Repo.Webhook.Secret
		}
	}

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
	if envTimeout := strings.TrimSpace(os.Getenv("PACKMON_TIMEOUT")); envTimeout != "" {
		if parsed, parseErr := parseTimeoutSeconds(envTimeout); parseErr == nil && parsed > 0 {
			settings.Timeout = parsed
		}
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
	if envInsecure := strings.TrimSpace(os.Getenv("PACKMON_INSECURE_ALLOW_HTTP")); envInsecure != "" {
		settings.InsecureHTTP = envBool("PACKMON_INSECURE_ALLOW_HTTP")
	}
	if envRequireRemote := strings.TrimSpace(os.Getenv("PACKMON_REQUIRE_REMOTE")); envRequireRemote != "" {
		settings.RequireRemote = envBool("PACKMON_REQUIRE_REMOTE")
	}

	if cmd.Flags().Changed("mode") {
		settings.Mode = normalizeModeString(flags.Mode)
	}
	if cmd.Flags().Changed("server") {
		settings.ServerURL = strings.TrimSpace(flags.Server)
	}
	if cmd.Flags().Changed("api-key") {
		settings.APIKey = strings.TrimSpace(flags.APIKey)
	}
	if cmd.Flags().Changed("fail-on") {
		settings.FailOn = normalizeSeverityString(flags.FailOn)
	}
	if cmd.Flags().Changed("ecosystems") {
		settings.Ecosystems = splitCSV(flags.Ecosystems)
	}
	if cmd.Flags().Changed("timeout") {
		settings.Timeout = flags.Timeout
	}
	if cmd.Flags().Changed("include-dev") {
		settings.IncludeDev = flags.IncludeDev
	}
	if cmd.Flags().Changed("webhook-url") {
		settings.WebhookURL = strings.TrimSpace(flags.WebhookURL)
	}
	if cmd.Flags().Changed("webhook-secret") {
		settings.WebhookSecret = strings.TrimSpace(flags.WebhookSecret)
	}
	if cmd.Flags().Changed("cacert") {
		settings.CACertFile = strings.TrimSpace(flags.CACert)
	}
	if cmd.Flags().Changed("insecure-allow-http") {
		settings.InsecureHTTP = flags.InsecureHTTP
	}
	if cmd.Flags().Changed("require-remote") {
		settings.RequireRemote = flags.RequireRemote
	}
	if cmd.Flags().Changed("sbom") {
		settings.SBOMFiles = append([]string(nil), flags.SBOMFiles...)
	}

	if cmd.Flags().Changed("output-json") || strings.TrimSpace(flags.OutputJSON) != "" {
		settings.OutputJSON = strings.TrimSpace(flags.OutputJSON)
	}
	if cmd.Flags().Changed("output-sarif") || strings.TrimSpace(flags.OutputSARIF) != "" {
		settings.OutputSARIF = strings.TrimSpace(flags.OutputSARIF)
	}
	if cmd.Flags().Changed("output-junit") || strings.TrimSpace(flags.OutputJUnit) != "" {
		settings.OutputJUnit = strings.TrimSpace(flags.OutputJUnit)
	}
	if cmd.Flags().Changed("html") || strings.TrimSpace(flags.OutputHTML) != "" {
		settings.OutputHTML = strings.TrimSpace(flags.OutputHTML)
	}

	if err := validateModeString(settings.Mode); err != nil {
		return scanSettings{}, err
	}
	if err := validateSeverityString(settings.FailOn); err != nil {
		return scanSettings{}, err
	}
	if settings.Timeout <= 0 {
		return scanSettings{}, fmt.Errorf("timeout must be greater than zero")
	}

	return settings, nil
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
func scanLogger(quiet bool, logLevel string) *slog.Logger {
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
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// autoFallbackWarning returns a user-facing warning when an auto-mode scan fell
// back to the local database (remote unreachable), or "" when no warning is
// needed. The local DB age is included when known.
func autoFallbackWarning(mode scanner.Mode, result *domain.ScanResult) string {
	if mode != scanner.ModeAuto || result == nil || result.Mode != string(scanner.ModeLocal) {
		return ""
	}
	if result.DBAgeDays != nil {
		return fmt.Sprintf("warning: remote server unreachable, scanned against local database (%d day(s) old)", *result.DBAgeDays)
	}
	return "warning: remote server unreachable, scanned against local database"
}

// runScanPipeline builds the scanner.Config from settings, opens the local
// SQLite checker, runs the scan, applies DB freshness, surfaces the auto
// fallback warning, and records scan history. It is the shared core used by
// both runSingleScan (which then prints tables and writes output files) and
// runListAll (which renders its own combined report). It does NOT print the
// findings table or write any output files.
func runScanPipeline(ctx context.Context, settings scanSettings) (*domain.ScanResult, domain.Severity, int, error) {
	failOn, ok := scanner.SeverityFromString(settings.FailOn)
	if !ok {
		return nil, failOn, ExitOperational, fmt.Errorf("invalid fail_on value %q", settings.FailOn)
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
		return nil, failOn, ExitOperational, fmt.Errorf("invalid mode value %q", settings.Mode)
	}

	cfg := scanner.Config{
		Path:       settings.Path,
		Mode:       mode,
		ServerURL:  settings.ServerURL,
		APIKey:     settings.APIKey,
		Repo:       scanRepoInfo(settings.Path),
		FailOn:     failOn,
		Ecosystems: settings.Ecosystems,
		MaxDepth:   settings.MaxDepth,
		Timeout:    time.Duration(settings.Timeout) * time.Second,
		IncludeDev: settings.IncludeDev,
		Quiet:      settings.Quiet,
		NoColor:    settings.NoColor,
		SBOMFiles:  settings.SBOMFiles,

		CACertFile:        settings.CACertFile,
		AllowInsecureHTTP: settings.InsecureHTTP,
		RequireRemote:     settings.RequireRemote,

		Logger: scanLogger(settings.Quiet, settings.LogLevel),
	}

	reg := parser.NewRegistry()
	sc := scanner.New(reg, cfg)

	dbPath, err := resolveLocalDBPath()
	if err != nil {
		return nil, failOn, ExitOperational, err
	}

	historyStore, advisoryDataAvailable, historyErr := openLocalSQLiteStore(ctx, dbPath)
	if historyErr != nil {
		fmt.Fprintf(os.Stderr, "warning: unable to open local database %s: %v\n", dbPath, historyErr)
	} else {
		defer closeSilently(historyStore)
		if advisoryDataAvailable {
			sc.SetLocalChecker(historyStore)
		}
	}

	result, exitCode := sc.Run(ctx)
	if historyStore != nil {
		if err := applyLocalDBFreshness(ctx, historyStore, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to determine local DB freshness: %v\n", err)
		}
	}

	// Auto mode falls back to the local database when the remote server is
	// unreachable. Surface this to the user along with the local DB age so a
	// silent stale-data scan cannot be mistaken for a fresh remote scan.
	if msg := autoFallbackWarning(mode, result); msg != "" && !settings.Quiet {
		fmt.Fprintln(os.Stderr, msg)
	}

	if historyStore != nil && historyEnabled() && (exitCode == ExitOK || exitCode == ExitBlocking || exitCode == ExitUnderThreshold) {
		if err := recordScanHistory(ctx, historyStore, settings.Path, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to store scan history: %v\n", err)
		} else if maxPerRepo := historyMaxScansPerRepo(); maxPerRepo > 0 {
			if err := historyStore.EnforceRetention(ctx, maxPerRepo); err != nil {
				fmt.Fprintf(os.Stderr, "warning: unable to enforce history retention: %v\n", err)
			}
		}
	}

	return result, failOn, exitCode, nil
}

func runSingleScan(ctx context.Context, settings scanSettings) (int, error) {
	result, failOn, exitCode, err := runScanPipeline(ctx, settings)
	if err != nil {
		return exitCode, err
	}

	reportScanParseErrors(result, settings.Quiet)

	if !settings.Quiet {
		tw := scanner.NewTableWriter(settings.NoColor, failOn)
		if err := tw.Write(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing table output: %v\n", err)
		}
	}

	if settings.OutputJSON != "" {
		if err := writeJSONFile(settings.OutputJSON, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON output: %v\n", err)
			exitCode = ExitOperational
		}
	}

	if settings.OutputSARIF != "" {
		if err := ensureOutputDir(settings.OutputSARIF); err != nil {
			fmt.Fprintf(os.Stderr, "error preparing SARIF output: %v\n", err)
			exitCode = ExitOperational
		} else {
			sw := scanner.NewSARIFWriter(version)
			if err := sw.WriteFile(settings.OutputSARIF, result); err != nil {
				fmt.Fprintf(os.Stderr, "error writing SARIF output: %v\n", err)
				exitCode = ExitOperational
			}
		}
	}

	if settings.OutputJUnit != "" {
		if err := ensureOutputDir(settings.OutputJUnit); err != nil {
			fmt.Fprintf(os.Stderr, "error preparing JUnit output: %v\n", err)
			exitCode = ExitOperational
		} else {
			jw := scanner.NewJUnitWriter()
			if err := jw.WriteFile(settings.OutputJUnit, result); err != nil {
				fmt.Fprintf(os.Stderr, "error writing JUnit output: %v\n", err)
				exitCode = ExitOperational
			}
		}
	}

	if settings.OutputHTML != "" {
		if err := ensureOutputDir(settings.OutputHTML); err != nil {
			fmt.Fprintf(os.Stderr, "error preparing HTML output: %v\n", err)
			exitCode = ExitOperational
		} else {
			hw := scanner.NewHTMLWriter(version)
			if err := hw.WriteFile(settings.OutputHTML, settings.TargetName, failOn, result); err != nil {
				fmt.Fprintf(os.Stderr, "error writing HTML output: %v\n", err)
				exitCode = ExitOperational
			} else if !settings.Quiet {
				_, _ = fmt.Fprintf(os.Stdout, "HTML report written to: %s\n", settings.OutputHTML)
			}
		}
	}

	if settings.WebhookURL != "" {
		whCfg := scanner.WebhookConfig{
			URL:     settings.WebhookURL,
			Secret:  settings.WebhookSecret,
			Version: version,
		}
		scanner.SendWebhook(ctx, whCfg, result, scanRepoInfo(settings.Path))
	}

	return exitCode, nil
}

func reportScanParseErrors(result *domain.ScanResult, quiet bool) {
	if quiet || result == nil {
		return
	}
	for _, parseErr := range result.ParseErrors {
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", parseErr)
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
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
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
func runListPackages(args []string, ecosystems string, maxDepth int, noColor bool, sbomFilesOpt ...[]string) error {
	var sbomFiles []string
	if len(sbomFilesOpt) > 0 {
		sbomFiles = sbomFilesOpt[0]
	}
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	reg := parser.NewRegistry()
	ecoFilter := splitCSV(ecosystems)
	collection, err := scanner.CollectPackages(scanner.CollectConfig{
		Registry:   reg,
		Root:       absPath,
		MaxDepth:   maxDepth,
		Ecosystems: ecoFilter,
		SBOMFiles:  sbomFiles,
		IncludeDev: true,
	})
	if err != nil {
		return err
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
		fmt.Fprintf(os.Stderr, "warning: parse error in %s\n", parseErr)
	}
	for _, entry := range collection.Entries {
		p := entry.Package
		key := string(p.Ecosystem) + "/" + p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		packages = append(packages, pkgEntry{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: string(p.Ecosystem),
			LockFile:  entry.SourceFile,
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

	fmt.Printf("\n%d package(s) found in %d input file(s)\n", len(packages), collection.LockFiles+collection.SBOMFiles)
	return nil
}

func fatalCollectionParseError(collection *scanner.PackageCollection) error {
	if collection == nil || len(collection.FatalParseErrors) == 0 {
		return nil
	}
	return withExitCode(ExitParser, fmt.Errorf("%s", strings.Join(collection.FatalParseErrors, "; ")))
}
