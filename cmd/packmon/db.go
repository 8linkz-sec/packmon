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
			cfg, _, err := loadCurrentCLIConfig()
			if err != nil {
				return err
			}

			source := "server"
			if cfg != nil && cfg.DB.SyncSource != "" {
				source = cfg.DB.SyncSource
			}
			if cmd.Flags().Changed("source") {
				source = flagSource
			}
			if strings.TrimSpace(strings.ToLower(source)) != "server" {
				return fmt.Errorf("db sync source %q is not yet implemented (supported: server)", source)
			}

			serverURL := ""
			if cfg != nil && cfg.Server != "" {
				serverURL = cfg.Server
			}
			if envServer := strings.TrimSpace(os.Getenv("PACKMON_SERVER")); envServer != "" {
				serverURL = envServer
			}
			if cmd.Flags().Changed("server") {
				serverURL = strings.TrimSpace(flagServer)
			}
			if serverURL == "" {
				return fmt.Errorf("missing server URL (use --server, PACKMON_SERVER, user-global config, or explicit --config)")
			}

			apiKey := ""
			envAPIKey := strings.TrimSpace(os.Getenv("PACKMON_API_KEY"))
			skipConfigAPIKeyEnv := envAPIKey != "" || cmd.Flags().Changed("api-key")
			if cfg != nil && cfg.APIKey != "" {
				apiKey = cfg.APIKey
			}
			if cfg != nil && cfg.APIKeyEnv != "" && !skipConfigAPIKeyEnv {
				resolvedAPIKey, keyErr := resolveAPIKeyEnv(cfg.APIKeyEnv)
				if keyErr != nil {
					return keyErr
				}
				apiKey = resolvedAPIKey
			}
			if envAPIKey != "" {
				apiKey = envAPIKey
			}
			if cmd.Flags().Changed("api-key") {
				apiKey = strings.TrimSpace(flagAPIKey)
			}

			caCertFile := ""
			if cfg != nil && cfg.CACert != "" {
				caCertFile = cfg.CACert
			}
			if envCACert := strings.TrimSpace(os.Getenv("PACKMON_CA_CERT")); envCACert != "" {
				caCertFile = envCACert
			}
			if cmd.Flags().Changed("cacert") {
				caCertFile = strings.TrimSpace(flagCACert)
			}

			insecureHTTP := false
			if cfg != nil {
				insecureHTTP = boolValue(cfg.InsecureAllowHTTP, false)
			}
			if strings.TrimSpace(os.Getenv("PACKMON_INSECURE_ALLOW_HTTP")) != "" {
				parsed, _, parseErr := strictEnvBool("PACKMON_INSECURE_ALLOW_HTTP")
				if parseErr != nil {
					return parseErr
				}
				insecureHTTP = parsed
			}
			if cmd.Flags().Changed("insecure-allow-http") {
				insecureHTTP = flagInsecureHTTP
			}

			ecosystems := []string{}
			if cfg != nil && len(cfg.Ecosystems) > 0 {
				ecosystems = append(ecosystems, cfg.Ecosystems...)
			}
			if envEcosystems := strings.TrimSpace(os.Getenv("PACKMON_ECOSYSTEMS")); envEcosystems != "" {
				ecosystems = splitCSV(envEcosystems)
			}
			if cmd.Flags().Changed("ecosystems") {
				ecosystems = splitCSV(flagEcosystems)
			}

			timeoutSeconds := flagTimeout
			if cfg != nil && cfg.Timeout > 0 {
				timeoutSeconds = cfg.Timeout
			}
			if envTimeout := strings.TrimSpace(os.Getenv("PACKMON_TIMEOUT")); envTimeout != "" {
				parsed, parseErr := parseTimeoutSeconds(envTimeout)
				if parseErr != nil {
					return fmt.Errorf("PACKMON_TIMEOUT: %w", parseErr)
				}
				if parsed <= 0 {
					return fmt.Errorf("PACKMON_TIMEOUT must be greater than zero")
				}
				timeoutSeconds = parsed
			}
			if cmd.Flags().Changed("timeout") {
				timeoutSeconds = flagTimeout
			}
			if timeoutSeconds <= 0 {
				return fmt.Errorf("timeout must be greater than zero")
			}

			dbPath, err := resolveLocalDBPath()
			if err != nil {
				return err
			}

			store, err := sqlite.New(dbPath)
			if err != nil {
				return fmt.Errorf("open local database: %w", err)
			}
			defer closeSilently(store)

			var syncStats sqlite.SyncStats
			if err := sqlite.Sync(cmd.Context(), store, sqlite.SyncConfig{
				ServerURL:         serverURL,
				APIKey:            apiKey,
				Ecosystems:        ecosystems,
				Full:              flagFull,
				Timeout:           time.Duration(timeoutSeconds) * time.Second,
				CACertFile:        caCertFile,
				AllowInsecureHTTP: insecureHTTP,
				Stats:             &syncStats,
			}); err != nil {
				return err
			}

			info, err := loadLocalDBInfo(cmd.Context(), store)
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
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagEcosystems, "ecosystems", "", "comma-separated ecosystem filter")
	f.BoolVar(&flagFull, "full", false, "full sync instead of incremental")
	f.StringVar(&flagSource, "source", "server", "sync source (server)")
	f.StringVar(&flagServer, "server", "", "feed server URL")
	f.StringVar(&flagAPIKey, "api-key", "", "API key for authenticated sync requests")
	f.IntVar(&flagTimeout, "timeout", 60, "sync timeout in seconds")
	f.StringVar(&flagCACert, "cacert", "", "path to a PEM CA bundle used to verify the server's TLS certificate")
	f.BoolVar(&flagInsecureHTTP, "insecure-allow-http", false, "allow plain http:// server URLs (sends bearer token in cleartext; opt-in)")

	return cmd
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
			defer closeSilently(store)

			if strings.TrimSpace(flagOutput) == "" {
				return exportLocalDB(cmd.Context(), store, os.Stdout)
			}

			// #nosec G304 -- CLI export path is supplied intentionally by the local user.
			file, err := openPrivateExportFile(flagOutput)
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

func openPrivateExportFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- CLI export path is supplied intentionally by the local user.
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		closeSilently(file)
		return nil, err
	}
	return file, nil
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
