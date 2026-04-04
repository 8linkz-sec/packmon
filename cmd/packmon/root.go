package main

import (
	"os"
	"strings"

	"github.com/8linkz/packmon/internal/scanner"
	"github.com/spf13/cobra"
)

// Exit codes per DE-2.
const (
	ExitOK          = scanner.ExitOK
	ExitBlocking    = scanner.ExitBlocking
	ExitOperational = scanner.ExitOperational
	ExitParser      = scanner.ExitParser
	ExitInternal    = scanner.ExitInternal
)

// Global flag values bound at the root level.
var (
	flagConfig   string
	flagLogLevel string
	flagQuiet    bool
	flagNoColor  bool
)

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "packmon",
		Short: "Dependency Security Scanner",
		Long:  "packmon scans project dependencies for known CVEs and malicious packages.",
		// Do not print usage on every error -- only on bad flags.
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags.
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagConfig, "config", "", "path to config file")
	pf.StringVar(&flagLogLevel, "log-level", envOrDefault("PACKMON_LOG_LEVEL", "INFO"), "log level (DEBUG|INFO|WARN|ERROR)")
	pf.BoolVar(&flagQuiet, "quiet", false, "suppress stdout except errors")
	pf.BoolVar(&flagNoColor, "no-color", envBool("PACKMON_NO_COLOR"), "disable colored output")

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
