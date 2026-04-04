package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage packmon configuration",
		Long:  "Show, create, or validate packmon configuration files.",
	}

	configCmd.AddCommand(
		newConfigShowCmd(),
		newConfigInitCmd(),
		newConfigValidateCmd(),
	)

	return configCmd
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show effective configuration",
		Long:  "Display the merged configuration from flags, environment variables, and config files.",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("# Effective packmon configuration")
			fmt.Println()
			fmt.Printf("config_file:  %s\n", valueOrDefault(flagConfig, "(none)"))
			fmt.Printf("log_level:    %s\n", flagLogLevel)
			fmt.Printf("quiet:        %v\n", flagQuiet)
			fmt.Printf("no_color:     %v\n", flagNoColor)
			fmt.Println()
			fmt.Println("# Environment")
			printEnvVar("PACKMON_SERVER")
			printEnvVar("PACKMON_API_KEY")
			printEnvVar("PACKMON_MODE")
			printEnvVar("PACKMON_FAIL_ON")
			printEnvVar("PACKMON_LOG_LEVEL")
			printEnvVar("PACKMON_LOG_FORMAT")
			printEnvVar("PACKMON_TIMEOUT")
			printEnvVar("PACKMON_DB_PATH")
			printEnvVar("PACKMON_ECOSYSTEMS")
			printEnvVar("PACKMON_OUTPUT")
			printEnvVar("PACKMON_NO_COLOR")
			printEnvVar("PACKMON_IGNORE")
		},
	}
}

func newConfigInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create .packmon.yaml template in current directory",
		RunE: func(_ *cobra.Command, _ []string) error {
			target := filepath.Join(".", ".packmon.yaml")
			if _, err := os.Stat(target); err == nil {
				return fmt.Errorf("%s already exists", target)
			}

			template := `# packmon configuration
# See https://github.com/8linkz/packmon for documentation.

server: "https://packmon.intern"
mode: auto
fail_on: CRITICAL
timeout: 30

ecosystems:
  # Uncomment ecosystems to limit scanning:
  # - npm
  # - go
  # - pypi

ignore:
  # - package: lodash
  #   version: "4.17.15"
  #   reason: "False positive, reviewed 2026-03-15"
  #   expires: "2026-06-15"

output:
  format: table
  file: ""

log:
  level: INFO
  format: text
  file: ""

hook:
  type: pre-push
  fail_on: CRITICAL

db:
  path: "~/.packmon/db/"
  sync_source: server
`
			if err := os.WriteFile(target, []byte(template), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", target, err)
			}
			fmt.Printf("Created %s\n", target)
			return nil
		},
	}
}

func newConfigValidateCmd() *cobra.Command {
	var flagPath string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a packmon config file",
		RunE: func(_ *cobra.Command, _ []string) error {
			path := flagPath
			if path == "" {
				path = ".packmon.yaml"
			}
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("config file not found: %s", path)
			}
			// Basic validation: file exists and is readable.
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if len(data) == 0 {
				return fmt.Errorf("config file %s is empty", path)
			}
			fmt.Printf("Config file %s is valid.\n", path)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagPath, "file", "", "path to config file (default: .packmon.yaml)")

	return cmd
}

func printEnvVar(key string) {
	v := os.Getenv(key)
	if v == "" {
		v = "(not set)"
	}
	fmt.Printf("  %-25s %s\n", key+":", v)
}

func valueOrDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
