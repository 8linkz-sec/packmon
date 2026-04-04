package main

import (
	"context"
	"encoding/json"
	"fmt"
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
		flagWebhookURL    string
		flagWebhookSecret string
		flagAll           bool
		flagRepo          string
	)

	cmd := &cobra.Command{
		Use:   "scan [PATH]",
		Short: "Scan directory for vulnerable dependencies",
		Long: `Scan the given directory (default ".") for lock files,
parse dependencies, and check them against known vulnerabilities
and malicious package databases.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScanCommand(cmd, args, scanFlagValues{
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
				WebhookURL:    flagWebhookURL,
				WebhookSecret: flagWebhookSecret,
				All:           flagAll,
				Repo:          flagRepo,
				Quiet:         flagQuiet,
				NoColor:       flagNoColor,
			})
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
	f.StringVar(&flagWebhookURL, "webhook-url", "", "webhook URL to POST results to")
	f.StringVar(&flagWebhookSecret, "webhook-secret", "", "HMAC-SHA256 secret for webhook signature")
	f.BoolVar(&flagAll, "all", false, "scan all repositories configured in .packmon.yaml")
	f.StringVar(&flagRepo, "repo", "", "scan a configured repository by name")

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
	WebhookURL    string
	WebhookSecret string
	All           bool
	Repo          string
	Quiet         bool
	NoColor       bool
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
	WebhookURL    string
	WebhookSecret string
	Quiet         bool
	NoColor       bool
}

func runScanCommand(cmd *cobra.Command, args []string, flags scanFlagValues) error {
	cfg, _, err := loadCurrentCLIConfig()
	if err != nil {
		return err
	}

	targets, err := buildScanTargets(cfg, args, flags)
	if err != nil {
		return err
	}
	if len(targets) > 1 && (strings.TrimSpace(flags.OutputJSON) != "" || strings.TrimSpace(flags.OutputSARIF) != "" || strings.TrimSpace(flags.OutputJUnit) != "") {
		return fmt.Errorf("--output-json, --output-sarif and --output-junit are only supported for a single scan target")
	}

	finalExitCode := ExitOK
	for i, target := range targets {
		settings, err := resolveScanSettings(cmd, cfg, target, flags)
		if err != nil {
			return err
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
			return err
		}
		if exitCode > finalExitCode {
			finalExitCode = exitCode
		}
	}

	if finalExitCode != ExitOK {
		os.Exit(finalExitCode)
	}
	return nil
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
	if targetName == "" || targetName == "." || targetName == string(filepath.Separator) {
		targetName = "local"
	}
	return []scanTarget{{Name: targetName, Path: path}}, nil
}

func resolveScanSettings(cmd *cobra.Command, cfg *cliConfig, target scanTarget, flags scanFlagValues) (scanSettings, error) {
	settings := scanSettings{
		TargetName: target.Name,
		Path:       target.Path,
		Mode:       "auto",
		FailOn:     string(defaultFailSeverity()),
		MaxDepth:   flags.MaxDepth,
		Timeout:    30,
		Quiet:      flags.Quiet,
		NoColor:    flags.NoColor,
	}

	if cfg != nil {
		if cfg.Server != "" {
			settings.ServerURL = cfg.Server
		}
		if cfg.APIKey != "" {
			settings.APIKey = cfg.APIKey
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
	}

	if target.Repo != nil {
		if target.Repo.Server != "" {
			settings.ServerURL = target.Repo.Server
		}
		if target.Repo.APIKey != "" {
			settings.APIKey = target.Repo.APIKey
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
	if envAPIKey := strings.TrimSpace(os.Getenv("PACKMON_API_KEY")); envAPIKey != "" {
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

	settings.OutputJSON = strings.TrimSpace(flags.OutputJSON)
	settings.OutputSARIF = strings.TrimSpace(flags.OutputSARIF)
	settings.OutputJUnit = strings.TrimSpace(flags.OutputJUnit)

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

func runSingleScan(ctx context.Context, settings scanSettings) (int, error) {
	failOn, ok := scanner.SeverityFromString(settings.FailOn)
	if !ok {
		return ExitOperational, fmt.Errorf("invalid fail_on value %q", settings.FailOn)
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
		return ExitOperational, fmt.Errorf("invalid mode value %q", settings.Mode)
	}

	cfg := scanner.Config{
		Path:       settings.Path,
		Mode:       mode,
		ServerURL:  settings.ServerURL,
		APIKey:     settings.APIKey,
		FailOn:     failOn,
		Ecosystems: settings.Ecosystems,
		MaxDepth:   settings.MaxDepth,
		Timeout:    time.Duration(settings.Timeout) * time.Second,
		IncludeDev: settings.IncludeDev,
		Quiet:      settings.Quiet,
		NoColor:    settings.NoColor,
	}

	reg := parser.NewRegistry()
	sc := scanner.New(reg, cfg)

	dbPath, err := resolveLocalDBPath()
	if err != nil {
		return ExitOperational, err
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

	if historyStore != nil && historyEnabled() && (exitCode == ExitOK || exitCode == ExitBlocking) {
		if err := recordScanHistory(ctx, historyStore, settings.Path, result); err != nil {
			fmt.Fprintf(os.Stderr, "warning: unable to store scan history: %v\n", err)
		} else if maxPerRepo := historyMaxScansPerRepo(); maxPerRepo > 0 {
			if err := historyStore.EnforceRetention(ctx, maxPerRepo); err != nil {
				fmt.Fprintf(os.Stderr, "warning: unable to enforce history retention: %v\n", err)
			}
		}
	}

	if !settings.Quiet {
		tw := scanner.NewTableWriter(settings.NoColor)
		if err := tw.Write(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing table output: %v\n", err)
		}
	}

	if settings.OutputJSON != "" {
		if err := writeJSONFile(settings.OutputJSON, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JSON output: %v\n", err)
			if exitCode == ExitOK {
				exitCode = ExitOperational
			}
		}
	}

	if settings.OutputSARIF != "" {
		sw := scanner.NewSARIFWriter(version)
		if err := sw.WriteFile(settings.OutputSARIF, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing SARIF output: %v\n", err)
			if exitCode == ExitOK {
				exitCode = ExitOperational
			}
		}
	}

	if settings.OutputJUnit != "" {
		jw := scanner.NewJUnitWriter()
		if err := jw.WriteFile(settings.OutputJUnit, result); err != nil {
			fmt.Fprintf(os.Stderr, "error writing JUnit output: %v\n", err)
			if exitCode == ExitOK {
				exitCode = ExitOperational
			}
		}
	}

	if settings.WebhookURL != "" {
		whCfg := scanner.WebhookConfig{
			URL:     settings.WebhookURL,
			Secret:  settings.WebhookSecret,
			Version: version,
		}
		repoName, branch := scanRepoMetadata(settings.Path)
		scanner.SendWebhook(ctx, whCfg, result, &domain.RepoInfo{Name: repoName, Branch: branch})
	}

	return exitCode, nil
}

func writeJSONFile(path string, result *domain.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
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
