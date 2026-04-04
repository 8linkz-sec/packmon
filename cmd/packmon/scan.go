package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	)

	cmd := &cobra.Command{
		Use:   "scan [PATH]",
		Short: "Scan directory for vulnerable dependencies",
		Long: `Scan the given directory (default ".") for lock files,
parse dependencies, and check them against known vulnerabilities
and malicious package databases.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}

			// Resolve server URL: flag > env > empty.
			serverURL := flagServer
			if serverURL == "" {
				serverURL = os.Getenv("PACKMON_SERVER")
			}
			apiKey := strings.TrimSpace(flagAPIKey)
			if apiKey == "" {
				apiKey = strings.TrimSpace(os.Getenv("PACKMON_API_KEY"))
			}

			// Parse fail-on severity.
			failOn := domain.SeverityCritical
			if flagFailOn != "" {
				sev, ok := scanner.SeverityFromString(flagFailOn)
				if !ok {
					return fmt.Errorf("invalid --fail-on value %q (want CRITICAL|HIGH|MEDIUM|LOW|NONE)", flagFailOn)
				}
				failOn = sev
			}

			// Parse ecosystems filter.
			var ecosystems []string
			if flagEcosystems != "" {
				for _, e := range strings.Split(flagEcosystems, ",") {
					e = strings.TrimSpace(e)
					if e != "" {
						ecosystems = append(ecosystems, e)
					}
				}
			}

			// Parse mode.
			var mode scanner.Mode
			switch strings.ToLower(flagMode) {
			case "remote":
				mode = scanner.ModeRemote
			case "local":
				mode = scanner.ModeLocal
			case "auto", "":
				mode = scanner.ModeAuto
			default:
				return fmt.Errorf("invalid --mode value %q (want local|remote|auto)", flagMode)
			}

			cfg := scanner.Config{
				Path:       path,
				Mode:       mode,
				ServerURL:  serverURL,
				APIKey:     apiKey,
				FailOn:     failOn,
				Ecosystems: ecosystems,
				MaxDepth:   flagMaxDepth,
				Timeout:    time.Duration(flagTimeout) * time.Second,
				IncludeDev: flagIncludeDev,
				Quiet:      flagQuiet,
				NoColor:    flagNoColor,
			}

			reg := parser.NewRegistry()
			sc := scanner.New(reg, cfg)

			ctx := context.Background()
			historyStore, advisoryDataAvailable, historyErr := openLocalSQLiteStore(ctx)
			if historyErr != nil {
				fmt.Fprintf(os.Stderr, "warning: unable to open local database %s: %v\n", defaultDBPath(), historyErr)
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
				if err := recordScanHistory(ctx, historyStore, path, result); err != nil {
					fmt.Fprintf(os.Stderr, "warning: unable to store scan history: %v\n", err)
				} else if maxPerRepo := historyMaxScansPerRepo(); maxPerRepo > 0 {
					if err := historyStore.EnforceRetention(ctx, maxPerRepo); err != nil {
						fmt.Fprintf(os.Stderr, "warning: unable to enforce history retention: %v\n", err)
					}
				}
			}

			// Write table to stdout unless --quiet.
			if !flagQuiet {
				tw := scanner.NewTableWriter(flagNoColor)
				if err := tw.Write(os.Stdout, result); err != nil {
					fmt.Fprintf(os.Stderr, "error writing table output: %v\n", err)
				}
			}

			// Write JSON to file if requested.
			if flagOutputJSON != "" {
				if err := writeJSONFile(flagOutputJSON, result); err != nil {
					fmt.Fprintf(os.Stderr, "error writing JSON output: %v\n", err)
					if exitCode == ExitOK {
						exitCode = ExitOperational
					}
				}
			}

			// Write SARIF to file if requested.
			if flagOutputSARIF != "" {
				sw := scanner.NewSARIFWriter(version)
				if err := sw.WriteFile(flagOutputSARIF, result); err != nil {
					fmt.Fprintf(os.Stderr, "error writing SARIF output: %v\n", err)
					if exitCode == ExitOK {
						exitCode = ExitOperational
					}
				}
			}

			// Write JUnit XML to file if requested.
			if flagOutputJUnit != "" {
				jw := scanner.NewJUnitWriter()
				if err := jw.WriteFile(flagOutputJUnit, result); err != nil {
					fmt.Fprintf(os.Stderr, "error writing JUnit output: %v\n", err)
					if exitCode == ExitOK {
						exitCode = ExitOperational
					}
				}
			}

			// Send webhook if configured. Delivery is best-effort;
			// failures are logged but do not change the exit code.
			webhookURL := flagWebhookURL
			if webhookURL == "" {
				webhookURL = os.Getenv("PACKMON_WEBHOOK_URL")
			}
			webhookSecret := flagWebhookSecret
			if webhookSecret == "" {
				webhookSecret = os.Getenv("PACKMON_WEBHOOK_SECRET")
			}
			if webhookURL != "" {
				whCfg := scanner.WebhookConfig{
					URL:     webhookURL,
					Secret:  webhookSecret,
					Version: version,
				}
				scanner.SendWebhook(ctx, whCfg, result, nil)
			}

			if exitCode != ExitOK {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagMode, "mode", envOrDefault("PACKMON_MODE", "auto"), "scan mode (local|remote|auto)")
	f.StringVar(&flagServer, "server", "", "feed server URL")
	f.StringVar(&flagAPIKey, "api-key", "", "API key for authenticated remote scans")
	f.StringVar(&flagFailOn, "fail-on", envOrDefault("PACKMON_FAIL_ON", "CRITICAL"), "block on severity (CRITICAL|HIGH|MEDIUM|LOW|NONE)")
	f.StringVar(&flagEcosystems, "ecosystems", os.Getenv("PACKMON_ECOSYSTEMS"), "comma-separated ecosystem filter")
	f.IntVar(&flagMaxDepth, "max-depth", 10, "directory walk depth")
	f.IntVar(&flagTimeout, "timeout", 30, "HTTP timeout in seconds")
	f.BoolVar(&flagIncludeDev, "include-dev", false, "include dev dependencies")
	f.StringVar(&flagOutputJSON, "output-json", "", "write JSON results to file")
	f.StringVar(&flagOutputSARIF, "output-sarif", "", "write SARIF 2.1.0 results to file")
	f.StringVar(&flagOutputJUnit, "output-junit", "", "write JUnit XML results to file")
	f.StringVar(&flagWebhookURL, "webhook-url", "", "webhook URL to POST results to")
	f.StringVar(&flagWebhookSecret, "webhook-secret", os.Getenv("PACKMON_WEBHOOK_SECRET"), "HMAC-SHA256 secret for webhook signature")

	return cmd
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

func openLocalSQLiteStore(ctx context.Context) (*sqlite.Store, bool, error) {
	store, err := sqlite.New(defaultDBPath())
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
