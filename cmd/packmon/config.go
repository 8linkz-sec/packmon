package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	var flagPath string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show effective configuration",
		Long:  "Display the merged configuration from flags, environment variables, and config files.",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, configPath, err := loadCLIConfig(selectCLIConfigPath(flagPath))
			if err != nil {
				return err
			}

			fmt.Println("# Effective packmon configuration")
			fmt.Println()
			fmt.Printf("config_file:  %s\n", valueOrDefault(configPath, "(none)"))
			if cfg != nil {
				fmt.Printf("server:       %s\n", valueOrDefault(cfg.Server, "(not set)"))
				fmt.Printf("api_key:      %s\n", maskSecret(cfg.APIKey))
				fmt.Printf("mode:         %s\n", valueOrDefault(cfg.Mode, "auto"))
				fmt.Printf("fail_on:      %s\n", valueOrDefault(cfg.FailOn, "CRITICAL"))
				fmt.Printf("timeout:      %ds\n", defaultConfigTimeout(cfg.Timeout))
				fmt.Printf("db_path:      %s\n", valueOrDefault(cfg.DB.Path, defaultDBPath()))
				fmt.Printf("repos:        %d\n", len(cfg.Repos))
				if len(cfg.Repos) > 0 {
					for _, repo := range cfg.Repos {
						fmt.Printf("  - %s -> %s\n", repo.Name, repo.Path)
					}
				}
			}
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
			printEnvVar("PACKMON_WEBHOOK_URL")
			printEnvVar("PACKMON_OUTPUT")
			printEnvVar("PACKMON_NO_COLOR")
			printEnvVar("PACKMON_IGNORE")
			return nil
		},
	}
	cmd.Flags().StringVar(&flagPath, "file", "", "path to config file (default: .packmon.yaml)")
	return cmd
}

func newConfigInitCmd() *cobra.Command {
	var flagPath string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create .packmon.yaml template in current directory",
		RunE: func(_ *cobra.Command, _ []string) error {
			target := selectCLIConfigPath(flagPath)
			if strings.TrimSpace(target) == "" {
				target = defaultCLIConfigFile
			}
			target = filepath.Clean(target)
			if _, err := os.Stat(target); err == nil {
				return fmt.Errorf("%s already exists", target)
			}

			template := `# packmon configuration
# See https://github.com/8linkz/packmon for documentation.

server: "http://localhost:8080"
api_key: ""
mode: auto
fail_on: CRITICAL
timeout: 30
include_dev: false

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

webhook:
  url: ""
  secret: ""

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

repos:
  - name: packmon
    path: "."
    mode: auto
    fail_on: CRITICAL
    include_dev: false

  # - name: my-other-repo
  #   path: "../my-other-repo"
  #   mode: remote
  #   ecosystems:
  #     - npm
  #   webhook:
  #     url: "http://localhost:9000/hooks/packmon"
`
			dir := filepath.Dir(target)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fmt.Errorf("create config directory %s: %w", dir, err)
			}
			if err := os.WriteFile(target, []byte(template), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", target, err)
			}
			fmt.Printf("Created %s\n", target)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagPath, "file", "", "path to config file (default: .packmon.yaml)")
	return cmd
}

func newConfigValidateCmd() *cobra.Command {
	var flagPath string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a packmon config file",
		RunE: func(_ *cobra.Command, _ []string) error {
			path := selectCLIConfigPath(flagPath)
			if path == "" {
				path = defaultCLIConfigFile
			}
			cfg, path, err := loadCLIConfig(path)
			if err != nil {
				return err
			}
			fmt.Printf("Config file %s is valid.\n", path)
			if cfg != nil {
				fmt.Printf("Configured repos: %d\n", len(cfg.Repos))
			}
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

func defaultConfigTimeout(timeout int) int {
	if timeout > 0 {
		return timeout
	}
	return 30
}

func selectCLIConfigPath(localPath string) string {
	if strings.TrimSpace(localPath) != "" {
		return strings.TrimSpace(localPath)
	}
	if strings.TrimSpace(flagConfig) != "" {
		return strings.TrimSpace(flagConfig)
	}
	return ""
}
