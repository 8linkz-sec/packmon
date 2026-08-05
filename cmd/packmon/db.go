package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/spf13/cobra"
)

func newDBCmd() *cobra.Command {
	dbCmd := &cobra.Command{
		Use:   "db",
		Short: "Manage local vulnerability database",
		Long:  "Commands for synchronizing and inspecting the local SQLite database used in offline mode.",
	}

	dbCmd.AddCommand(
		newDBSyncCmd(),
		newDBInfoCmd(),
		newDBExportCmd(),
	)

	return dbCmd
}

type dbSyncSettings struct {
	serverURL         string
	apiKey            string
	caCertFile        string
	allowInsecureHTTP bool
	ecosystems        []string
	full              bool
	timeout           time.Duration
}

type dbSyncRun struct {
	settings dbSyncSettings
	dbPath   string
}

func newDBSyncCmd() *cobra.Command {
	var (
		flagEcosystems   string
		flagFull         bool
		flagSource       string
		flagServer       string
		flagAPIKey       string
		flagTimeout      int
		flagCACert       string
		flagInsecureHTTP bool
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize local database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDBSync(cmd.Context(), cmd)
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagEcosystems, "ecosystems", "", "comma-separated ecosystem filter")
	f.BoolVar(&flagFull, "full", false, "full sync instead of incremental")
	f.StringVar(&flagSource, "source", "server", "sync source (server)")
	f.StringVar(&flagServer, "server", "", "feed server URL")
	f.StringVar(&flagAPIKey, "api-key", "", "deprecated: use PACKMON_API_KEY or api_key_env; command-line secrets are rejected by default")
	f.IntVar(&flagTimeout, "timeout", 60, "sync timeout in seconds")
	f.StringVar(&flagCACert, "cacert", "", "path to a PEM CA bundle used to verify the server's TLS certificate")
	f.BoolVar(&flagInsecureHTTP, "insecure-allow-http", false, "allow plain http:// server URLs (sends bearer token in cleartext; opt-in)")

	return cmd
}

func runDBSync(ctx context.Context, cmd *cobra.Command) error {
	run, err := resolveDBSyncRun(cmd)
	if err != nil {
		return err
	}
	return executeDBSync(ctx, run)
}

func resolveDBSyncRun(cmd *cobra.Command) (dbSyncRun, error) {
	cfg, _, err := loadCurrentCLIConfig()
	if err != nil {
		return dbSyncRun{}, err
	}
	settings, err := resolveDBSyncSettings(cmd, cfg)
	if err != nil {
		return dbSyncRun{}, err
	}

	dbPath, err := resolveLocalDBPath()
	if err != nil {
		return dbSyncRun{}, err
	}

	return dbSyncRun{
		settings: settings,
		dbPath:   dbPath,
	}, nil
}

func executeDBSync(ctx context.Context, run dbSyncRun) error {
	store, err := sqlite.New(run.dbPath)
	if err != nil {
		return fmt.Errorf("open local database: %w", err)
	}
	defer ioutils.CloseSilently(store)

	var syncStats sqlite.SyncStats
	if err := sqlite.Sync(ctx, store, sqlite.SyncConfig{
		ServerURL:         run.settings.serverURL,
		APIKey:            run.settings.apiKey,
		Ecosystems:        run.settings.ecosystems,
		Full:              run.settings.full,
		Timeout:           run.settings.timeout,
		CACertFile:        run.settings.caCertFile,
		AllowInsecureHTTP: run.settings.allowInsecureHTTP,
		Stats:             &syncStats,
	}); err != nil {
		return err
	}

	info, err := loadLocalDBInfo(ctx, store)
	if err != nil {
		return err
	}

	fmt.Println("Local database synchronized.")
	if info.LastSyncAt != nil {
		fmt.Printf("Last sync:       %s\n", info.LastSyncAt.Format(time.RFC3339))
	}
	fmt.Printf("Vulnerabilities: %d\n", info.Vulnerabilities)
	fmt.Printf("Malicious:       %d\n", info.Malicious)
	fmt.Printf("Reputation:      %d\n", info.Reputation)
	fmt.Printf("Lifecycle:       %d\n", info.Lifecycle)
	printSyncRemovalStats(syncStats)
	return nil
}

func resolveDBSyncSettings(cmd *cobra.Command, cfg *cliConfig) (dbSyncSettings, error) {
	source, err := dbSyncStringFlag(cmd, "source", "server")
	if err != nil {
		return dbSyncSettings{}, err
	}
	if cfg != nil && cfg.DB.SyncSource != "" {
		source = cfg.DB.SyncSource
	}
	if commandFlagChanged(cmd, "source") {
		source, err = dbSyncStringFlag(cmd, "source", "server")
		if err != nil {
			return dbSyncSettings{}, err
		}
	}
	if strings.TrimSpace(strings.ToLower(source)) != "server" {
		return dbSyncSettings{}, fmt.Errorf("db sync source %q is not yet implemented (supported: server)", source)
	}

	settings := dbSyncSettings{}
	if cfg != nil && cfg.Server != "" {
		settings.serverURL = cfg.Server
	}
	if envServer := strings.TrimSpace(os.Getenv("PACKMON_SERVER")); envServer != "" {
		settings.serverURL = envServer
	}
	if commandFlagChanged(cmd, "server") {
		settings.serverURL, err = dbSyncTrimmedStringFlag(cmd, "server")
		if err != nil {
			return dbSyncSettings{}, err
		}
	}
	if settings.serverURL == "" {
		return dbSyncSettings{}, fmt.Errorf("missing server URL (use --server, PACKMON_SERVER, user-global config, or explicit --config)")
	}
	if err := rejectSecretFlagValue(cmd, "api-key", "PACKMON_API_KEY or config api_key_env"); err != nil {
		return dbSyncSettings{}, err
	}

	envAPIKey := strings.TrimSpace(os.Getenv("PACKMON_API_KEY"))
	skipConfigAPIKeyEnv := envAPIKey != "" || commandFlagChanged(cmd, "api-key")
	if cfg != nil && cfg.APIKey != "" {
		settings.apiKey = cfg.APIKey
	}
	if cfg != nil && cfg.APIKeyEnv != "" && !skipConfigAPIKeyEnv {
		resolvedAPIKey, keyErr := resolveAPIKeyEnv(cfg.APIKeyEnv)
		if keyErr != nil {
			return dbSyncSettings{}, keyErr
		}
		settings.apiKey = resolvedAPIKey
	}
	if envAPIKey != "" {
		settings.apiKey = envAPIKey
	}
	if commandFlagChanged(cmd, "api-key") {
		settings.apiKey, err = dbSyncTrimmedStringFlag(cmd, "api-key")
		if err != nil {
			return dbSyncSettings{}, err
		}
	}

	if cfg != nil && cfg.CACert != "" {
		settings.caCertFile = cfg.CACert
	}
	if envCACert := clientCACertEnvValue(); envCACert != "" {
		settings.caCertFile = envCACert
	}
	if commandFlagChanged(cmd, "cacert") {
		settings.caCertFile, err = dbSyncTrimmedStringFlag(cmd, "cacert")
		if err != nil {
			return dbSyncSettings{}, err
		}
	}

	if cfg != nil {
		settings.allowInsecureHTTP = boolValue(cfg.InsecureAllowHTTP, false)
	}
	if strings.TrimSpace(os.Getenv("PACKMON_INSECURE_ALLOW_HTTP")) != "" {
		parsed, _, parseErr := strictEnvBool("PACKMON_INSECURE_ALLOW_HTTP")
		if parseErr != nil {
			return dbSyncSettings{}, parseErr
		}
		settings.allowInsecureHTTP = parsed
	}
	if commandFlagChanged(cmd, "insecure-allow-http") {
		settings.allowInsecureHTTP, err = dbSyncBoolFlag(cmd, "insecure-allow-http", false)
		if err != nil {
			return dbSyncSettings{}, err
		}
	}

	if cfg != nil && len(cfg.Ecosystems) > 0 {
		settings.ecosystems = append(settings.ecosystems, cfg.Ecosystems...)
	}
	if envEcosystems := strings.TrimSpace(os.Getenv("PACKMON_ECOSYSTEMS")); envEcosystems != "" {
		settings.ecosystems = splitCSV(envEcosystems)
	}
	if commandFlagChanged(cmd, "ecosystems") {
		flagEcosystems, flagErr := dbSyncStringFlag(cmd, "ecosystems", "")
		if flagErr != nil {
			return dbSyncSettings{}, flagErr
		}
		settings.ecosystems = splitCSV(flagEcosystems)
	}

	timeoutSeconds, err := dbSyncIntFlag(cmd, "timeout", 60)
	if err != nil {
		return dbSyncSettings{}, err
	}
	if cfg != nil && cfg.Timeout > 0 {
		timeoutSeconds = cfg.Timeout
	}
	if envTimeout := strings.TrimSpace(os.Getenv("PACKMON_TIMEOUT")); envTimeout != "" {
		parsed, parseErr := parseTimeoutSeconds(envTimeout)
		if parseErr != nil {
			return dbSyncSettings{}, fmt.Errorf("PACKMON_TIMEOUT: %w", parseErr)
		}
		if parsed <= 0 {
			return dbSyncSettings{}, fmt.Errorf("PACKMON_TIMEOUT must be greater than zero")
		}
		timeoutSeconds = parsed
	}
	if commandFlagChanged(cmd, "timeout") {
		timeoutSeconds, err = dbSyncIntFlag(cmd, "timeout", 60)
		if err != nil {
			return dbSyncSettings{}, err
		}
	}
	if timeoutSeconds <= 0 {
		return dbSyncSettings{}, fmt.Errorf("timeout must be greater than zero")
	}
	settings.timeout = time.Duration(timeoutSeconds) * time.Second

	settings.full, err = dbSyncBoolFlag(cmd, "full", false)
	if err != nil {
		return dbSyncSettings{}, err
	}

	return settings, nil
}

func dbSyncTrimmedStringFlag(cmd *cobra.Command, name string) (string, error) {
	value, err := dbSyncStringFlag(cmd, name, "")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func dbSyncStringFlag(cmd *cobra.Command, name, fallback string) (string, error) {
	if cmd == nil {
		return fallback, nil
	}
	if cmd.Flags().Lookup(name) == nil {
		return fallback, nil
	}
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		return "", err
	}
	return value, nil
}

func dbSyncBoolFlag(cmd *cobra.Command, name string, fallback bool) (bool, error) {
	if cmd == nil {
		return fallback, nil
	}
	if cmd.Flags().Lookup(name) == nil {
		return fallback, nil
	}
	value, err := cmd.Flags().GetBool(name)
	if err != nil {
		return false, err
	}
	return value, nil
}

func dbSyncIntFlag(cmd *cobra.Command, name string, fallback int) (int, error) {
	if cmd == nil {
		return fallback, nil
	}
	if cmd.Flags().Lookup(name) == nil {
		return fallback, nil
	}
	value, err := cmd.Flags().GetInt(name)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func newDBInfoCmd() *cobra.Command {
	var flagJSON bool

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show local database version, age, and entry count",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dbPath, err := resolveLocalDBPath()
			if err != nil {
				return err
			}
			info, err := inspectLocalDB(cmd.Context(), dbPath)
			if err != nil {
				return err
			}

			if flagJSON {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetEscapeHTML(false)
				encoder.SetIndent("", "  ")
				return encoder.Encode(info)
			}

			fmt.Printf("Path:            %s\n", info.Path)
			fmt.Printf("Initialized:     %t\n", info.Exists)
			if !info.Exists {
				fmt.Println("Status:          local database not initialized")
				return nil
			}

			fmt.Printf("File size:       %d bytes\n", info.FileSizeBytes)
			fmt.Printf("Vulnerabilities: %d\n", info.Vulnerabilities)
			fmt.Printf("Malicious:       %d\n", info.Malicious)
			fmt.Printf("Reputation:      %d\n", info.Reputation)
			fmt.Printf("Lifecycle:       %d\n", info.Lifecycle)
			fmt.Printf("History entries: %d\n", info.HistoryEntries)
			if info.LastSyncAt != nil {
				fmt.Printf("Last sync:       %s\n", info.LastSyncAt.Format(time.RFC3339))
			} else {
				fmt.Println("Last sync:       never")
			}
			if info.DBAgeDays != nil {
				fmt.Printf("DB age:          %s\n", plural.Count(*info.DBAgeDays, "day", "days"))
			}
			fmt.Printf("DB stale:        %t\n", info.DBStale)
			return nil
		},
	}

	cmd.Flags().BoolVar(&flagJSON, "json", false, "print database info as JSON")
	return cmd
}

func newDBExportCmd() *cobra.Command {
	var flagOutput string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export local database as JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dbPath, err := resolveLocalDBPath()
			if err != nil {
				return err
			}
			info, err := inspectLocalDB(cmd.Context(), dbPath)
			if err != nil {
				return err
			}
			if !info.Exists {
				return fmt.Errorf("local database does not exist yet")
			}

			store, err := sqlite.New(dbPath)
			if err != nil {
				return fmt.Errorf("open local database: %w", err)
			}
			defer ioutils.CloseSilently(store)

			if strings.TrimSpace(flagOutput) == "" {
				return exportLocalDB(cmd.Context(), store, os.Stdout)
			}

			// #nosec G304 -- CLI export path is supplied intentionally by the local user.
			file, err := ioutils.OpenPrivateFile(flagOutput)
			if err != nil {
				return fmt.Errorf("create export file: %w", err)
			}
			return writeLocalDBExport(cmd.Context(), store, file, file)
		},
	}

	cmd.Flags().StringVar(&flagOutput, "output", "", "write export JSON to file instead of stdout")
	return cmd
}

func writeLocalDBExport(ctx context.Context, store *sqlite.Store, writer io.Writer, closer io.Closer) error {
	exportErr := exportLocalDB(ctx, store, writer)
	if closer == nil {
		return exportErr
	}
	closeErr := closer.Close()
	if exportErr != nil {
		return exportErr
	}
	if closeErr != nil {
		return fmt.Errorf("close export file: %w", closeErr)
	}
	return nil
}

func printSyncRemovalStats(stats sqlite.SyncStats) {
	if !stats.AnyRemoved() {
		return
	}
	fmt.Println("Removed cached rows:")
	if stats.FullCleared.Any() {
		printSyncRemovalLine("Full sync clear", stats.FullCleared)
	}
	if stats.TombstoneDeleted.Any() {
		printSyncRemovalLine("Tombstones", stats.TombstoneDeleted)
	}
}

func printSyncRemovalLine(label string, stats sqlite.SyncRemovalStats) {
	fmt.Printf("  %s: vulnerabilities=%d malicious=%d reputation=%d lifecycle=%d\n",
		label, stats.Vulnerabilities, stats.Malicious, stats.Reputation, stats.Lifecycle)
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
