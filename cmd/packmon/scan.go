package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/parser"
	"github.com/8linkz/packmon/internal/scanner"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		flagMode       string
		flagServer     string
		flagFailOn     string
		flagEcosystems string
		flagMaxDepth   int
		flagTimeout    int
		flagIncludeDev bool
		flagOutputJSON string
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
			mode := scanner.ModeAuto
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
			result, exitCode := sc.Run(ctx)

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

			if exitCode != ExitOK {
				os.Exit(exitCode)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagMode, "mode", envOrDefault("PACKMON_MODE", "auto"), "scan mode (local|remote|auto)")
	f.StringVar(&flagServer, "server", "", "feed server URL")
	f.StringVar(&flagFailOn, "fail-on", envOrDefault("PACKMON_FAIL_ON", "CRITICAL"), "block on severity (CRITICAL|HIGH|MEDIUM|LOW|NONE)")
	f.StringVar(&flagEcosystems, "ecosystems", os.Getenv("PACKMON_ECOSYSTEMS"), "comma-separated ecosystem filter")
	f.IntVar(&flagMaxDepth, "max-depth", 10, "directory walk depth")
	f.IntVar(&flagTimeout, "timeout", 30, "HTTP timeout in seconds")
	f.BoolVar(&flagIncludeDev, "include-dev", false, "include dev dependencies")
	f.StringVar(&flagOutputJSON, "output-json", "", "write JSON results to file")

	return cmd
}

func writeJSONFile(path string, result *domain.ScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write file %s: %w", path, err)
	}
	return nil
}
