package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/termtext"
	"github.com/spf13/cobra"
)

const (
	clientCACertFileEnv       = "PACKMON_CA_CERT_FILE"
	clientCACertLegacyFileEnv = "PACKMON_CA_CERT"
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

			effective, err := effectiveConfigShowSettings(cfg)
			if err != nil {
				return err
			}

			fmt.Println("# Effective packmon configuration")
			fmt.Println()
			fmt.Printf("config_file:  %s\n", valueOrDefault(configPath, "(none)"))
			if cfg != nil {
				fmt.Printf("server:       %s\n", valueOrDefault(logsafe.RedactURL(effective.Server), "(not set)"))
				fmt.Printf("api_key:      %s\n", maskSecret(effective.APIKey))
				fmt.Printf("api_key_env:  %s\n", valueOrDefault(effective.APIKeyEnv, "(not set)"))
				fmt.Printf("mode:         %s\n", effective.Mode)
				fmt.Printf("fail_on:      %s\n", effective.FailOn)
				fmt.Printf("timeout:      %ds\n", effective.Timeout)
				fmt.Printf("ecosystems:   %s\n", valueOrDefault(strings.Join(effective.Ecosystems, ","), "(all)"))
				fmt.Printf("include_dev:  %v\n", effective.IncludeDev)
				fmt.Printf("cacert:       %s\n", valueOrDefault(effective.CACertFile, "(not set)"))
				fmt.Printf("insecure_allow_http: %v\n", effective.InsecureHTTP)
				fmt.Printf("require_remote: %v\n", effective.RequireRemote)
				fmt.Printf("send_repo_metadata: %v\n", effective.SendRepoMetadata)
				fmt.Printf("webhook_url:  %s\n", valueOrDefault(logsafe.RedactURL(effective.WebhookURL), "(not set)"))
				fmt.Printf("webhook_secret: %s\n", maskSecret(effective.WebhookSecret))
				fmt.Printf("db_path:      %s\n", effective.DBPath)
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
			for _, key := range configuredAPIKeyEnvVars(cfg) {
				printEnvVarMasked(key)
			}
			printEnvVar("PACKMON_MODE")
			printEnvVar("PACKMON_FAIL_ON")
			printEnvVar("PACKMON_LOG_LEVEL")
			printEnvVar("PACKMON_LOG_FORMAT")
			printEnvVar("PACKMON_TIMEOUT")
			printEnvVar("PACKMON_DB_PATH")
			printEnvVar("PACKMON_ECOSYSTEMS")
			printEnvVar("PACKMON_NPM_REGISTRY_BASE_URL")
			printEnvVar("PACKMON_PYPI_API_BASE_URL")
			printEnvVar("PACKMON_RUBYGEMS_API_BASE_URL")
			printEnvVar("PACKMON_CARGO_REGISTRY_API_BASE_URL")
			printEnvVar("PACKMON_COCOAPODS_TRUNK_API_BASE_URL")
			printEnvVar("PACKMON_COMPOSER_REPOSITORY_BASE_URL")
			printEnvVar("PACKMON_GO_PROXY_URL")
			printEnvVar("PACKMON_MAVEN_REPOSITORY_BASE_URL")
			printEnvVar("PACKMON_DOCKER_REGISTRY_MIRRORS")
			printEnvVar("PACKMON_SWIFTPM_GIT_ALLOWED_HOSTS")
			printEnvVar("PACKMON_CRAN_MIRROR_URL")
			printEnvVar("PACKMON_PUB_HOSTED_URL")
			printEnvVar("PACKMON_HEX_API_BASE_URL")
			printEnvVar("PACKMON_NUGET_V3_BASE_URL")
			printEnvVar(clientCACertFileEnv)
			printEnvVar(clientCACertLegacyFileEnv)
			printEnvVar("PACKMON_INSECURE_ALLOW_HTTP")
			printEnvVar("PACKMON_REQUIRE_REMOTE")
			printEnvVar("PACKMON_NO_REPO_METADATA")
			printEnvVar("PACKMON_WEBHOOK_URL")
			printEnvVar("PACKMON_WEBHOOK_SECRET")
			printEnvVar("PACKMON_NO_COLOR")
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

			template := `# packmon project configuration
# See https://github.com/8linkz-sec/packmon for documentation.
# Keep server URL, API key, CA, insecure HTTP, require-remote, webhook URL/secret,
# report output settings, latest-version registry mirrors, and local DB path in
# flags, environment variables, the user-global config, or an explicit --config
# file. Auto-discovered project config is intentionally ignored for those
# trusted routing settings.

mode: auto
# NONE disables vulnerability blocking only; malicious and active supply-chain risk findings still block.
fail_on: CRITICAL
timeout: 30
include_dev: false
# Set to false to omit the optional repository name from remote scan requests and webhooks.
# send_repo_metadata: false

ecosystems:
  # Uncomment ecosystems to limit scanning:
  # - npm
  # - go
  # - pypi

log:
  level: INFO
  format: text
  file: ""

hook:
  type: pre-push
  # Same NONE behavior applies to hook scans.
  fail_on: CRITICAL

db:
  sync_source: server

# Trusted latest-version mirrors belong in user-global config, an explicit
# --config file, or PACKMON_* environment variables, not auto-discovered
# project config:
# registries:
#   npm_registry_base_url: "https://npm-mirror.example/registry"
#   pypi_api_base_url: "https://pypi-mirror.example/pypi"
#   rubygems_api_base_url: "https://rubygems-mirror.example/api/v1/gems"
#   cargo_registry_api_base_url: "https://cargo-mirror.example/api/v1/crates"
#   cocoapods_trunk_api_base_url: "https://cocoapods-mirror.example/api/v1/pods"
#   composer_repository_base_url: "https://composer-mirror.example/p2"
#   go_proxy_url: "https://go-proxy.example"
#   maven_repository_base_url: "https://maven-mirror.example/repository/maven-public"
#   docker_registry_mirrors:
#     docker.io: "https://docker-mirror.example/dockerhub"
#     ghcr.io: "https://ghcr-mirror.example"
#   swiftpm_git_allowed_hosts:
#     - git.example.com
#   cran_mirror_url: "https://cran-mirror.example"
#   pub_hosted_url: "https://pub-mirror.example"
#   hex_api_base_url: "https://hex-mirror.example/api"
#   nuget_v3_base_url: "https://nuget-mirror.example/v3-flatcontainer"

repos:
  - name: packmon
    path: "."
    mode: auto
    # Same NONE behavior applies to repo overrides.
    fail_on: CRITICAL
    include_dev: false

  # - name: my-other-repo
  #   path: "../my-other-repo"
  #   mode: remote
  #   ecosystems:
  #     - npm
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

type configShowSettings struct {
	Server           string
	APIKey           string
	APIKeyEnv        string
	Mode             string
	FailOn           string
	Timeout          int
	Ecosystems       []string
	IncludeDev       bool
	CACertFile       string
	InsecureHTTP     bool
	RequireRemote    bool
	SendRepoMetadata bool
	WebhookURL       string
	WebhookSecret    string
	DBPath           string
}

func effectiveConfigShowSettings(cfg *cliConfig) (configShowSettings, error) { // #nosec G101 -- this reads a user-provided API key from env/config; no credential is hardcoded.
	settings := defaultConfigShowSettings()
	applyConfigShowFileSettings(&settings, cfg)
	if err := applyConfigShowEnvironmentSettings(&settings); err != nil {
		return configShowSettings{}, err
	}
	return settings, nil
}

func defaultConfigShowSettings() configShowSettings { // #nosec G101 -- this reads a user-provided API key from env/config; no credential is hardcoded.
	return configShowSettings{
		Mode:             "auto",
		FailOn:           string(defaultFailSeverity()),
		Timeout:          30,
		DBPath:           defaultDBPath(),
		APIKey:           configShowEnvValue("PACKMON_API_KEY"),
		APIKeyEnv:        "PACKMON_API_KEY",
		SendRepoMetadata: true,
	}
}

func applyConfigShowFileSettings(settings *configShowSettings, cfg *cliConfig) {
	if cfg == nil {
		return
	}

	settings.Server = cfg.Server
	applyConfigShowFileAPIKey(settings, cfg)
	applyConfigShowFileScanPolicy(settings, cfg)
	applyConfigShowFileConnection(settings, cfg)
	applyConfigShowFileWebhook(settings, cfg)
	applyConfigShowFileDB(settings, cfg)
}

func applyConfigShowFileAPIKey(settings *configShowSettings, cfg *cliConfig) { // #nosec G101 -- this reads user-provided API key env names/values.
	settings.APIKey = cfg.APIKey
	settings.APIKeyEnv = cfg.APIKeyEnv
	if cfg.APIKeyEnv != "" && configShowEnvValue("PACKMON_API_KEY") == "" {
		settings.APIKey = configShowEnvValue(cfg.APIKeyEnv)
	}
}

func applyConfigShowFileScanPolicy(settings *configShowSettings, cfg *cliConfig) {
	if cfg.Mode != "" {
		settings.Mode = cfg.Mode
	}
	if cfg.FailOn != "" {
		settings.FailOn = cfg.FailOn
	}
	if cfg.Timeout > 0 {
		settings.Timeout = cfg.Timeout
	}
	settings.Ecosystems = append([]string(nil), cfg.Ecosystems...)
	settings.IncludeDev = boolValue(cfg.IncludeDev, false)
	settings.SendRepoMetadata = boolValue(cfg.SendRepoMetadata, true)
}

func applyConfigShowFileConnection(settings *configShowSettings, cfg *cliConfig) {
	settings.CACertFile = cfg.CACert
	settings.InsecureHTTP = boolValue(cfg.InsecureAllowHTTP, false)
	settings.RequireRemote = boolValue(cfg.RequireRemote, false)
}

func applyConfigShowFileWebhook(settings *configShowSettings, cfg *cliConfig) {
	settings.WebhookURL = cfg.Webhook.URL
	settings.WebhookSecret = cfg.Webhook.Secret
}

func applyConfigShowFileDB(settings *configShowSettings, cfg *cliConfig) {
	if cfg.DB.Path != "" {
		settings.DBPath = filepath.Join(cfg.DB.Path, "packmon.db")
	}
}

func applyConfigShowEnvironmentSettings(settings *configShowSettings) error {
	applyConfigShowEnvironmentIdentity(settings)
	if err := applyConfigShowEnvironmentScanPolicy(settings); err != nil {
		return err
	}
	if err := applyConfigShowEnvironmentConnection(settings); err != nil {
		return err
	}
	applyConfigShowEnvironmentWebhook(settings)
	applyConfigShowEnvironmentDB(settings)
	return nil
}

func applyConfigShowEnvironmentIdentity(settings *configShowSettings) { // #nosec G101 -- this reads user-provided API key env values.
	if envServer := configShowEnvValue("PACKMON_SERVER"); envServer != "" {
		settings.Server = envServer
	}
	if envAPIKey := configShowEnvValue("PACKMON_API_KEY"); envAPIKey != "" {
		settings.APIKey = envAPIKey
		settings.APIKeyEnv = "PACKMON_API_KEY"
	}
}

func applyConfigShowEnvironmentScanPolicy(settings *configShowSettings) error {
	if envMode := normalizeModeString(os.Getenv("PACKMON_MODE")); envMode != "" {
		settings.Mode = envMode
	}
	if envFailOn := normalizeSeverityString(os.Getenv("PACKMON_FAIL_ON")); envFailOn != "" {
		settings.FailOn = envFailOn
	}
	if envTimeout := configShowEnvValue("PACKMON_TIMEOUT"); envTimeout != "" {
		parsed, parseErr := parseTimeoutSeconds(envTimeout)
		if parseErr != nil {
			return fmt.Errorf("PACKMON_TIMEOUT: %w", parseErr)
		}
		if parsed <= 0 {
			return fmt.Errorf("PACKMON_TIMEOUT must be greater than zero")
		}
		settings.Timeout = parsed
	}
	if envEcosystems := configShowEnvValue("PACKMON_ECOSYSTEMS"); envEcosystems != "" {
		settings.Ecosystems = splitCSV(envEcosystems)
	}
	if envNoRepoMetadata := configShowEnvValue("PACKMON_NO_REPO_METADATA"); envNoRepoMetadata != "" {
		noRepoMetadata, err := configShowBoolEnv("PACKMON_NO_REPO_METADATA")
		if err != nil {
			return err
		}
		settings.SendRepoMetadata = !noRepoMetadata
	}
	return nil
}

func applyConfigShowEnvironmentConnection(settings *configShowSettings) error {
	if envCACert := clientCACertEnvValue(); envCACert != "" {
		settings.CACertFile = envCACert
	}
	if envInsecure := configShowEnvValue("PACKMON_INSECURE_ALLOW_HTTP"); envInsecure != "" {
		insecureHTTP, err := configShowBoolEnv("PACKMON_INSECURE_ALLOW_HTTP")
		if err != nil {
			return err
		}
		settings.InsecureHTTP = insecureHTTP
	}
	if envRequireRemote := configShowEnvValue("PACKMON_REQUIRE_REMOTE"); envRequireRemote != "" {
		requireRemote, err := configShowBoolEnv("PACKMON_REQUIRE_REMOTE")
		if err != nil {
			return err
		}
		settings.RequireRemote = requireRemote
	}
	return nil
}

func applyConfigShowEnvironmentWebhook(settings *configShowSettings) {
	if envWebhookURL := configShowEnvValue("PACKMON_WEBHOOK_URL"); envWebhookURL != "" {
		settings.WebhookURL = envWebhookURL
	}
	if envWebhookSecret := configShowEnvValue("PACKMON_WEBHOOK_SECRET"); envWebhookSecret != "" {
		settings.WebhookSecret = envWebhookSecret
	}
}

func applyConfigShowEnvironmentDB(settings *configShowSettings) {
	if envDBPath := configShowEnvValue("PACKMON_DB_PATH"); envDBPath != "" {
		settings.DBPath = filepath.Join(envDBPath, "packmon.db")
	}
}

func configShowEnvValue(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func clientCACertEnvValue() string {
	if value := configShowEnvValue(clientCACertFileEnv); value != "" {
		return value
	}
	return configShowEnvValue(clientCACertLegacyFileEnv)
}

func configShowBoolEnv(key string) (bool, error) {
	value, _, err := strictEnvBool(key)
	return value, err
}

func printEnvVar(key string) {
	printEnvVarWithMask(key, false)
}

func printEnvVarMasked(key string) {
	printEnvVarWithMask(key, true)
}

func printEnvVarWithMask(key string, forceSecret bool) {
	v := os.Getenv(key)
	if v == "" {
		v = "(not set)"
	} else if isURLSecretEnvVar(key) {
		v = logsafe.RedactURL(v)
	} else if forceSecret || isSecretEnvVar(key) {
		v = maskSecret(v)
	}
	fmt.Printf("  %-25s %s\n", termtext.Sanitize(key)+":", termtext.Sanitize(v))
}

func configuredAPIKeyEnvVars(cfg *cliConfig) []string {
	if cfg == nil {
		return nil
	}
	seen := map[string]struct{}{
		"PACKMON_API_KEY": {},
	}
	keys := make([]string, 0, 1+len(cfg.Repos))
	add := func(key string) {
		key = strings.TrimSpace(key)
		if key == "" {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	add(cfg.APIKeyEnv)
	for _, repo := range cfg.Repos {
		add(repo.APIKeyEnv)
	}
	return keys
}

func isURLSecretEnvVar(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	return upper == "PACKMON_WEBHOOK_URL" || upper == "PACKMON_SERVER"
}

func isSecretEnvVar(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	return strings.Contains(upper, "API_KEY") ||
		strings.Contains(upper, "SECRET") ||
		strings.Contains(upper, "TOKEN") ||
		strings.Contains(upper, "PASSWORD")
}

func valueOrDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
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
