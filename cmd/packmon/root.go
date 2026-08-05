package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/spf13/cobra"
)

// Exit codes per DE-2.
const (
	ExitOK             = scanner.ExitOK
	ExitBlocking       = scanner.ExitBlocking
	ExitOperational    = scanner.ExitOperational
	ExitUnderThreshold = scanner.ExitUnderThreshold
	ExitParser         = scanner.ExitParser
	ExitInternal       = scanner.ExitInternal
)

// Global flag values bound at the root level.
var (
	flagConfig          string
	flagLogLevel        string
	flagQuiet           bool
	flagNoColor         bool
	flagNoProjectConfig bool
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "packmon",
		Short: "Scan dependencies and SBOMs for vulnerability, malicious-package, supply-chain, and lifecycle findings",
		Long:  "packmon scans project dependencies and SBOMs for known vulnerabilities, malicious packages, supply-chain risk findings, and lifecycle risks.",
		// Do not print usage on every error -- only on bad flags.
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags.
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagConfig, "config", "", "path to config file")
	pf.StringVar(&flagLogLevel, "log-level", envOrDefault("PACKMON_LOG_LEVEL", "INFO"), "log level (DEBUG|INFO|WARN|ERROR)")
	pf.BoolVar(&flagQuiet, "quiet", false, "suppress stdout except errors")
	pf.BoolVar(&flagNoColor, "no-color", defaultNoColor(), "disable colored output")
	pf.BoolVar(&flagNoProjectConfig, "no-project-config", false, "ignore auto-discovered repository .packmon.yaml config")

	// Register sub-commands.
	rootCmd.AddCommand(
		newScanCmd(),
		newVersionCmd(),
		newDashboardCmd(),
		newDBCmd(),
		newConfigCmd(),
		newHookCmd(),
		newHistoryCmd(),
		newReportCmd(),
	)

	return rootCmd
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string) bool {
	v := strings.ToLower(os.Getenv(key))
	return v == "true" || v == "1" || v == "yes"
}

func defaultNoColor() bool {
	return envBool("PACKMON_NO_COLOR") || strings.TrimSpace(os.Getenv("NO_COLOR")) != ""
}

func strictEnvBool(key string) (bool, bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return false, false, nil
	}
	value, err := parseBoolLiteral(raw)
	if err != nil {
		return false, true, fmt.Errorf("%s must be a boolean (true/false, 1/0, yes/no)", key)
	}
	return value, true, nil
}

func parseBoolLiteral(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", raw)
	}
}
