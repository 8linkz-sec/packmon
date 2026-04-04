package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db/sqlite"
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
		flagEcosystems string
		flagFull       bool
		flagSource     string
		flagServer     string
		flagAPIKey     string
		flagTimeout    int
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize local database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(strings.ToLower(flagSource)) != "server" {
				return fmt.Errorf("db sync source %q is not yet implemented (supported: server)", flagSource)
			}

			serverURL := strings.TrimSpace(flagServer)
			if serverURL == "" {
				serverURL = strings.TrimSpace(os.Getenv("PACKMON_SERVER"))
			}
			if serverURL == "" {
				return fmt.Errorf("missing server URL (use --server or PACKMON_SERVER)")
			}

			apiKey := strings.TrimSpace(flagAPIKey)
			if apiKey == "" {
				apiKey = strings.TrimSpace(os.Getenv("PACKMON_API_KEY"))
			}

			store, err := sqlite.New(defaultDBPath())
			if err != nil {
				return fmt.Errorf("open local database: %w", err)
			}
			defer store.Close()

			if err := sqlite.Sync(cmd.Context(), store, sqlite.SyncConfig{
				ServerURL:  serverURL,
				APIKey:     apiKey,
				Ecosystems: splitCSV(flagEcosystems),
				Full:       flagFull,
				Timeout:    time.Duration(flagTimeout) * time.Second,
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
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagEcosystems, "ecosystems", "", "comma-separated ecosystem filter")
	f.BoolVar(&flagFull, "full", false, "full sync instead of incremental")
	f.StringVar(&flagSource, "source", "server", "sync source (server|osv)")
	f.StringVar(&flagServer, "server", "", "feed server URL")
	f.StringVar(&flagAPIKey, "api-key", "", "API key for authenticated sync requests")
	f.IntVar(&flagTimeout, "timeout", 60, "sync timeout in seconds")

	return cmd
}

func newDBInfoCmd() *cobra.Command {
	var flagJSON bool

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show local database version, age, and entry count",
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := inspectLocalDB(cmd.Context(), defaultDBPath())
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
			fmt.Printf("History entries: %d\n", info.HistoryEntries)
			if info.LastSyncAt != nil {
				fmt.Printf("Last sync:       %s\n", info.LastSyncAt.Format(time.RFC3339))
			} else {
				fmt.Println("Last sync:       never")
			}
			if info.DBAgeDays != nil {
				fmt.Printf("DB age:          %d days\n", *info.DBAgeDays)
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
			info, err := inspectLocalDB(cmd.Context(), defaultDBPath())
			if err != nil {
				return err
			}
			if !info.Exists {
				return fmt.Errorf("local database does not exist yet")
			}

			store, err := sqlite.New(defaultDBPath())
			if err != nil {
				return fmt.Errorf("open local database: %w", err)
			}
			defer store.Close()

			output := os.Stdout
			if strings.TrimSpace(flagOutput) != "" {
				file, err := os.Create(flagOutput)
				if err != nil {
					return fmt.Errorf("create export file: %w", err)
				}
				defer file.Close()
				output = file
			}

			return exportLocalDB(cmd.Context(), store, output)
		},
	}

	cmd.Flags().StringVar(&flagOutput, "output", "", "write export JSON to file instead of stdout")
	return cmd
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
