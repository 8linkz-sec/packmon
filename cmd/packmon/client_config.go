package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/scanner"
	"go.yaml.in/yaml/v3"
)

const (
	defaultCLIConfigFile             = ".packmon.yaml"
	maxAutoProjectCLIConfigFileBytes = 64 * 1024
)

type cliConfig struct {
	Server            string            `yaml:"server"`
	APIKey            string            `yaml:"api_key"`
	APIKeyEnv         string            `yaml:"api_key_env"`
	Mode              string            `yaml:"mode"`
	FailOn            string            `yaml:"fail_on"`
	Timeout           int               `yaml:"timeout"`
	Ecosystems        []string          `yaml:"ecosystems"`
	IncludeDev        *bool             `yaml:"include_dev"`
	CACert            string            `yaml:"cacert"`
	InsecureAllowHTTP *bool             `yaml:"insecure_allow_http"`
	RequireRemote     *bool             `yaml:"require_remote"`
	SendRepoMetadata  *bool             `yaml:"send_repo_metadata"`
	Webhook           cliWebhookConfig  `yaml:"webhook"`
	Output            cliOutputConfig   `yaml:"output"`
	Log               cliLogConfig      `yaml:"log"`
	Hook              cliHookConfig     `yaml:"hook"`
	DB                cliDBConfig       `yaml:"db"`
	Registries        cliRegistryConfig `yaml:"registries"`
	Repos             []cliRepoConfig   `yaml:"repos"`
}

type cliWebhookConfig struct {
	URL    string `yaml:"url"`
	Secret string `yaml:"secret"`
}

type cliOutputConfig struct {
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

type cliLogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

type cliHookConfig struct {
	Type   string `yaml:"type"`
	FailOn string `yaml:"fail_on"`
}

type cliDBConfig struct {
	Path       string `yaml:"path"`
	SyncSource string `yaml:"sync_source"`
}

type cliRepoConfig struct {
	Name             string           `yaml:"name"`
	Path             string           `yaml:"path"`
	Server           string           `yaml:"server"`
	APIKey           string           `yaml:"api_key"`
	APIKeyEnv        string           `yaml:"api_key_env"`
	Mode             string           `yaml:"mode"`
	FailOn           string           `yaml:"fail_on"`
	Timeout          int              `yaml:"timeout"`
	Ecosystems       []string         `yaml:"ecosystems"`
	IncludeDev       *bool            `yaml:"include_dev"`
	SendRepoMetadata *bool            `yaml:"send_repo_metadata"`
	Webhook          cliWebhookConfig `yaml:"webhook"`
}

func loadCurrentCLIConfig() (*cliConfig, string, error) {
	return loadCLIConfigWithOptions(flagConfig, cliConfigLoadOptions{SkipProjectConfig: flagNoProjectConfig})
}

func loadCLIConfig(path string) (*cliConfig, string, error) {
	return loadCLIConfigWithOptions(path, cliConfigLoadOptions{})
}

type cliConfigLoadOptions struct {
	SkipProjectConfig bool
}

func loadCLIConfigWithOptions(path string, opts cliConfigLoadOptions) (*cliConfig, string, error) {
	configPath := strings.TrimSpace(path)
	if configPath != "" {
		// An explicit --config path is loaded as a single file.
		return loadExplicitCLIConfig(configPath)
	}

	// Layered precedence (DESIGN.md CLI behavior): the user-global config
	// (~/.packmon/config/packmon.yaml) is the trusted base. The auto-discovered
	// project ./.packmon.yaml is overlaid only after credential/server/DB
	// routing fields have been removed from that untrusted repository layer.
	var (
		cfg        cliConfig
		loaded     bool
		sourcePath string
	)

	if userPath, ok := userGlobalConfigPath(); ok {
		data, err := os.ReadFile(userPath) // #nosec G304 -- user-owned config path.
		switch {
		case err == nil:
			var userCfg cliConfig
			if derr := decodeCLIConfig(data, &userCfg); derr != nil {
				return nil, "", fmt.Errorf("parse %s: %w", userPath, derr)
			}
			if err := userCfg.normalize(filepath.Dir(userPath)); err != nil {
				return nil, "", fmt.Errorf("validate %s: %w", userPath, err)
			}
			cfg = userCfg
			loaded = true
			sourcePath = userPath
		case !os.IsNotExist(err):
			return nil, "", fmt.Errorf("read %s: %w", userPath, err)
		}
	}

	if !opts.SkipProjectConfig {
		projectData, err := readAutoProjectCLIConfig(defaultCLIConfigFile)
		switch {
		case err == nil:
			var projectCfg cliConfig
			if derr := decodeCLIConfig(projectData, &projectCfg); derr != nil {
				return nil, "", fmt.Errorf("parse %s: %w", defaultCLIConfigFile, derr)
			}
			abs, aerr := filepath.Abs(defaultCLIConfigFile)
			if aerr != nil {
				abs = defaultCLIConfigFile
			}
			projectCfg.stripUntrustedAutoProjectFields()
			if err := projectCfg.normalize(filepath.Dir(abs)); err != nil {
				return nil, "", fmt.Errorf("validate %s: %w", abs, err)
			}
			overlayCLIConfig(&cfg, projectCfg)
			loaded = true
			sourcePath = abs
		case !os.IsNotExist(err):
			return nil, "", fmt.Errorf("read %s: %w", defaultCLIConfigFile, err)
		}
	}

	if !loaded {
		return nil, "", nil
	}

	return &cfg, sourcePath, nil
}

func readAutoProjectCLIConfig(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- repo-local config.
	if err != nil {
		return nil, err
	}
	defer ioutils.CloseSilently(file)

	data, err := io.ReadAll(io.LimitReader(file, maxAutoProjectCLIConfigFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAutoProjectCLIConfigFileBytes {
		return nil, fmt.Errorf("project config exceeds %d byte limit", maxAutoProjectCLIConfigFileBytes)
	}
	return data, nil
}

// loadExplicitCLIConfig loads a single config file supplied via --config.
func loadExplicitCLIConfig(configPath string) (*cliConfig, string, error) {
	if _, err := os.Stat(configPath); err != nil {
		return nil, "", fmt.Errorf("config file not found: %s", configPath)
	}

	// #nosec G304 -- CLI config path is supplied intentionally by the local user.
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", configPath, err)
	}

	var cfg cliConfig
	if err := decodeCLIConfig(data, &cfg); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", configPath, err)
	}

	absPath, err := filepath.Abs(configPath)
	if err != nil {
		absPath = configPath
	}
	if err := cfg.normalize(filepath.Dir(absPath)); err != nil {
		return nil, "", fmt.Errorf("validate %s: %w", configPath, err)
	}
	return &cfg, absPath, nil
}

// decodeCLIConfig decodes YAML into cfg, overlaying onto any existing values.
// An empty document is a no-op so a present-but-empty file does not clear the
// base layer.
func decodeCLIConfig(data []byte, cfg *cliConfig) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

func (c *cliConfig) stripUntrustedAutoProjectFields() {
	c.Server = ""
	c.APIKey = ""
	c.APIKeyEnv = ""
	c.CACert = ""
	c.InsecureAllowHTTP = nil
	c.RequireRemote = nil
	if c.SendRepoMetadata != nil && *c.SendRepoMetadata {
		c.SendRepoMetadata = nil
	}
	c.Webhook = cliWebhookConfig{}
	c.Output = cliOutputConfig{}
	c.DB.Path = ""
	c.Registries = cliRegistryConfig{}
	for i := range c.Repos {
		c.Repos[i].Server = ""
		c.Repos[i].APIKey = ""
		c.Repos[i].APIKeyEnv = ""
		if c.Repos[i].SendRepoMetadata != nil && *c.Repos[i].SendRepoMetadata {
			c.Repos[i].SendRepoMetadata = nil
		}
		c.Repos[i].Webhook = cliWebhookConfig{}
	}
}

func overlayCLIConfig(dst *cliConfig, src cliConfig) {
	overlayCLIConnectionConfig(dst, src)
	overlayCLIScanPolicyConfig(dst, src)
	overlayCLIRepoMetadataConfig(dst, src)
	overlayCLIWebhookConfig(&dst.Webhook, src.Webhook)
	overlayCLIOutputConfig(&dst.Output, src.Output)
	overlayCLILogConfig(&dst.Log, src.Log)
	overlayCLIHookConfig(&dst.Hook, src.Hook)
	overlayCLIDBConfig(&dst.DB, src.DB)
	overlayCLIRegistryConfig(&dst.Registries, src.Registries)
	overlayCLIReposConfig(dst, src)
}

func overlayCLIConnectionConfig(dst *cliConfig, src cliConfig) {
	if src.Server != "" {
		dst.Server = src.Server
	}
	if src.APIKey != "" {
		dst.APIKey = src.APIKey
	}
	if src.APIKeyEnv != "" {
		dst.APIKeyEnv = src.APIKeyEnv
	}
	if src.CACert != "" {
		dst.CACert = src.CACert
	}
	if src.InsecureAllowHTTP != nil {
		dst.InsecureAllowHTTP = src.InsecureAllowHTTP
	}
	if src.RequireRemote != nil {
		dst.RequireRemote = src.RequireRemote
	}
}

func overlayCLIScanPolicyConfig(dst *cliConfig, src cliConfig) {
	if src.Mode != "" {
		dst.Mode = src.Mode
	}
	if src.FailOn != "" {
		dst.FailOn = src.FailOn
	}
	if src.Timeout != 0 {
		dst.Timeout = src.Timeout
	}
	if len(src.Ecosystems) > 0 {
		dst.Ecosystems = append([]string(nil), src.Ecosystems...)
	}
	if src.IncludeDev != nil {
		dst.IncludeDev = src.IncludeDev
	}
}

func overlayCLIRepoMetadataConfig(dst *cliConfig, src cliConfig) {
	if src.SendRepoMetadata != nil {
		dst.SendRepoMetadata = src.SendRepoMetadata
	}
}

func overlayCLIWebhookConfig(dst *cliWebhookConfig, src cliWebhookConfig) {
	if src.URL != "" {
		dst.URL = src.URL
	}
	if src.Secret != "" {
		dst.Secret = src.Secret
	}
}

func overlayCLIOutputConfig(dst *cliOutputConfig, src cliOutputConfig) {
	if src.Format != "" {
		dst.Format = src.Format
	}
	if src.File != "" {
		dst.File = src.File
	}
}

func overlayCLILogConfig(dst *cliLogConfig, src cliLogConfig) {
	if src.Level != "" {
		dst.Level = src.Level
	}
	if src.Format != "" {
		dst.Format = src.Format
	}
	if src.File != "" {
		dst.File = src.File
	}
}

func overlayCLIHookConfig(dst *cliHookConfig, src cliHookConfig) {
	if src.Type != "" {
		dst.Type = src.Type
	}
	if src.FailOn != "" {
		dst.FailOn = src.FailOn
	}
}

func overlayCLIDBConfig(dst *cliDBConfig, src cliDBConfig) {
	if src.Path != "" {
		dst.Path = src.Path
	}
	if src.SyncSource != "" {
		dst.SyncSource = src.SyncSource
	}
}

func overlayCLIRegistryConfig(dst *cliRegistryConfig, src cliRegistryConfig) {
	if src.NPMRegistryBaseURL != "" {
		dst.NPMRegistryBaseURL = src.NPMRegistryBaseURL
	}
	if src.PyPIAPIBaseURL != "" {
		dst.PyPIAPIBaseURL = src.PyPIAPIBaseURL
	}
	if src.RubyGemsAPIBaseURL != "" {
		dst.RubyGemsAPIBaseURL = src.RubyGemsAPIBaseURL
	}
	if src.CargoRegistryAPIBaseURL != "" {
		dst.CargoRegistryAPIBaseURL = src.CargoRegistryAPIBaseURL
	}
	if src.CocoaPodsTrunkAPIBaseURL != "" {
		dst.CocoaPodsTrunkAPIBaseURL = src.CocoaPodsTrunkAPIBaseURL
	}
	if src.ComposerRepositoryBaseURL != "" {
		dst.ComposerRepositoryBaseURL = src.ComposerRepositoryBaseURL
	}
	if src.GoModuleProxyURL != "" {
		dst.GoModuleProxyURL = src.GoModuleProxyURL
	}
	if src.MavenRepositoryBaseURL != "" {
		dst.MavenRepositoryBaseURL = src.MavenRepositoryBaseURL
	}
	if len(src.DockerRegistryMirrors) > 0 {
		dst.DockerRegistryMirrors = mergeStringMaps(dst.DockerRegistryMirrors, src.DockerRegistryMirrors)
	}
	if len(src.SwiftPMGitAllowedHosts) > 0 {
		dst.SwiftPMGitAllowedHosts = mergeStringSlices(dst.SwiftPMGitAllowedHosts, src.SwiftPMGitAllowedHosts)
	}
	if src.CRANMirrorURL != "" {
		dst.CRANMirrorURL = src.CRANMirrorURL
	}
	if src.PubHostedURL != "" {
		dst.PubHostedURL = src.PubHostedURL
	}
	if src.HexAPIBaseURL != "" {
		dst.HexAPIBaseURL = src.HexAPIBaseURL
	}
	if src.NuGetV3BaseURL != "" {
		dst.NuGetV3BaseURL = src.NuGetV3BaseURL
	}
}

func overlayCLIReposConfig(dst *cliConfig, src cliConfig) {
	if len(src.Repos) > 0 {
		dst.Repos = append([]cliRepoConfig(nil), src.Repos...)
	}
}

// userGlobalConfigPath returns the path to the user-global CLI config
// (~/.packmon/config/packmon.yaml) and whether the home directory is known.
func userGlobalConfigPath() (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", false
	}
	return filepath.Join(home, ".packmon", "config", "packmon.yaml"), true
}

func (c *cliConfig) normalize(baseDir string) error {
	if err := normalizeTopLevelCLIConfig(c, baseDir); err != nil {
		return err
	}
	return normalizeCLIRepoConfigs(c.Repos, baseDir)
}

func normalizeTopLevelCLIConfig(c *cliConfig, baseDir string) error {
	c.Server = strings.TrimSpace(c.Server)
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.APIKeyEnv = strings.TrimSpace(c.APIKeyEnv)
	c.Mode = normalizeModeString(c.Mode)
	c.FailOn = normalizeSeverityString(c.FailOn)
	c.Ecosystems = normalizeStringList(c.Ecosystems)
	if err := validateCanonicalEcosystemFilters("ecosystems", c.Ecosystems); err != nil {
		return err
	}
	c.CACert = strings.TrimSpace(c.CACert)
	c.Webhook.URL = strings.TrimSpace(c.Webhook.URL)
	c.Webhook.Secret = strings.TrimSpace(c.Webhook.Secret)
	c.Output.Format = strings.ToLower(strings.TrimSpace(c.Output.Format))
	c.Output.File = strings.TrimSpace(c.Output.File)
	c.Log.Level = normalizeLogLevel(c.Log.Level)
	c.Log.Format = strings.ToLower(strings.TrimSpace(c.Log.Format))
	c.Log.File = strings.TrimSpace(c.Log.File)
	c.Hook.Type = strings.TrimSpace(c.Hook.Type)
	c.Hook.FailOn = normalizeSeverityString(c.Hook.FailOn)
	c.DB.Path = strings.TrimSpace(c.DB.Path)
	c.DB.SyncSource = strings.TrimSpace(c.DB.SyncSource)
	if err := normalizeCLIRegistryConfig(&c.Registries); err != nil {
		return err
	}

	if err := validateTopLevelCLIConfig(c); err != nil {
		return err
	}

	if c.DB.Path != "" {
		resolvedPath, err := resolveConfigPath(baseDir, c.DB.Path)
		if err != nil {
			return fmt.Errorf("resolve db.path: %w", err)
		}
		c.DB.Path = resolvedPath
	}

	return nil
}

func validateTopLevelCLIConfig(c *cliConfig) error {
	if err := validateModeString(c.Mode); err != nil {
		return err
	}
	if err := validateSeverityString(c.FailOn); err != nil {
		return err
	}
	if c.Timeout < 0 {
		return fmt.Errorf("timeout must not be negative")
	}
	if err := validateOutputConfig(c.Output); err != nil {
		return err
	}
	if err := validateLogConfig(c.Log); err != nil {
		return err
	}
	if c.Hook.Type != "" && c.Hook.Type != "pre-push" && c.Hook.Type != "pre-commit" {
		return fmt.Errorf("invalid hook.type %q (want pre-push|pre-commit)", c.Hook.Type)
	}
	if err := validateSeverityString(c.Hook.FailOn); err != nil {
		return fmt.Errorf("hook.fail_on: %w", err)
	}

	return nil
}

func normalizeCLIRepoConfigs(repos []cliRepoConfig, baseDir string) error {
	seenNames := make(map[string]struct{}, len(repos))
	for i := range repos {
		if err := normalizeCLIRepoConfig(&repos[i], baseDir, i); err != nil {
			return err
		}

		if _, exists := seenNames[repos[i].Name]; exists {
			return fmt.Errorf("duplicate repo name %q", repos[i].Name)
		}
		seenNames[repos[i].Name] = struct{}{}
	}

	return nil
}

func normalizeCLIRepoConfig(repo *cliRepoConfig, baseDir string, index int) error {
	repo.Name = strings.TrimSpace(repo.Name)
	repo.Path = strings.TrimSpace(repo.Path)
	repo.Server = strings.TrimSpace(repo.Server)
	repo.APIKey = strings.TrimSpace(repo.APIKey)
	repo.APIKeyEnv = strings.TrimSpace(repo.APIKeyEnv)
	repo.Mode = normalizeModeString(repo.Mode)
	repo.FailOn = normalizeSeverityString(repo.FailOn)
	repo.Ecosystems = normalizeStringList(repo.Ecosystems)
	if err := validateCanonicalEcosystemFilters(fmt.Sprintf("repos[%d].ecosystems", index), repo.Ecosystems); err != nil {
		return err
	}
	repo.Webhook.URL = strings.TrimSpace(repo.Webhook.URL)
	repo.Webhook.Secret = strings.TrimSpace(repo.Webhook.Secret)

	if repo.Path == "" {
		return fmt.Errorf("repos[%d].path is required", index)
	}
	resolvedPath, err := resolveConfigPath(baseDir, repo.Path)
	if err != nil {
		return fmt.Errorf("resolve repos[%d].path: %w", index, err)
	}
	repo.Path = resolvedPath

	if repo.Name == "" {
		repo.Name = filepath.Base(repo.Path)
	}

	return validateCLIRepoConfig(repo, index)
}

func validateCLIRepoConfig(repo *cliRepoConfig, index int) error {
	if repo.Name == "" || repo.Name == "." || repo.Name == string(filepath.Separator) {
		return fmt.Errorf("repos[%d].name could not be derived from path", index)
	}
	if err := validateModeString(repo.Mode); err != nil {
		return fmt.Errorf("repos[%d].mode: %w", index, err)
	}
	if err := validateSeverityString(repo.FailOn); err != nil {
		return fmt.Errorf("repos[%d].fail_on: %w", index, err)
	}
	if repo.Timeout < 0 {
		return fmt.Errorf("repos[%d].timeout must not be negative", index)
	}
	return nil
}

func validateOutputConfig(cfg cliOutputConfig) error {
	if !isValidScanOutputConfigFormat(cfg.Format) {
		return fmt.Errorf("invalid output.format %q (want %s)", cfg.Format, scanOutputConfigFormatList())
	}
	if cfg.File != "" && cfg.Format == "" {
		return fmt.Errorf("output.format is required when output.file is set")
	}
	if cfg.File != "" && cfg.Format == "table" {
		return fmt.Errorf("output.file does not support output.format table")
	}
	return nil
}

func validateLogConfig(cfg cliLogConfig) error {
	switch cfg.Level {
	case "", "INFO", "DEBUG", "WARN", "ERROR":
	default:
		return fmt.Errorf("invalid log.level %q (want DEBUG|INFO|WARN|ERROR)", cfg.Level)
	}
	switch cfg.Format {
	case "", "text", "json":
	default:
		return fmt.Errorf("invalid log.format %q (want text|json)", cfg.Format)
	}
	if cfg.File != "" {
		return fmt.Errorf("log.file is not supported by the CLI scanner")
	}
	return nil
}

func normalizeLogLevel(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func resolveConfigPath(baseDir, rawPath string) (string, error) {
	resolved := strings.TrimSpace(rawPath)
	if resolved == "" {
		return "", nil
	}

	resolved = os.ExpandEnv(resolved)
	if strings.HasPrefix(resolved, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		switch {
		case resolved == "~":
			resolved = home
		case strings.HasPrefix(resolved, "~/") || strings.HasPrefix(resolved, "~\\"):
			resolved = filepath.Join(home, resolved[2:])
		}
	}

	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, resolved)
	}

	return filepath.Clean(resolved), nil
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func validateCanonicalEcosystemFilters(field string, ecosystems []string) error {
	valid := validScanEcosystemFilterValues(true)
	for i, raw := range ecosystems {
		ecosystem := strings.ToLower(strings.TrimSpace(raw))
		if ecosystem == "" {
			continue
		}
		if !domain.Ecosystem(ecosystem).Valid() {
			return fmt.Errorf("%s[%d]: unknown ecosystem filter %q (valid values: %s)", field, i, ecosystem, strings.Join(valid, ", "))
		}
		ecosystems[i] = ecosystem
	}
	return nil
}

func normalizeModeString(value string) string {
	mode, err := scanner.ParseMode(value)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(value))
	}
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return string(mode)
}

func normalizeSeverityString(value string) string {
	if severity, ok := domain.ParseBlockThreshold(value); ok {
		return string(severity)
	}
	return strings.ToUpper(strings.TrimSpace(value))
}

func validateModeString(value string) error {
	_, err := scanner.ParseMode(value)
	return err
}

func validateSeverityString(value string) error {
	if value == "" {
		return nil
	}
	if _, ok := domain.ParseBlockThreshold(value); ok {
		return nil
	}
	return fmt.Errorf("invalid severity %q (want CRITICAL|HIGH|MEDIUM|LOW|NONE)", value)
}

func resolveLocalDBPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("PACKMON_DB_PATH")); p != "" {
		return filepath.Join(p, "packmon.db"), nil
	}
	cfg, _, err := loadCurrentCLIConfig()
	if err != nil {
		return "", err
	}
	if cfg != nil && strings.TrimSpace(cfg.DB.Path) != "" {
		return filepath.Join(cfg.DB.Path, "packmon.db"), nil
	}
	return defaultDBPath(), nil
}

func defaultDBPath() string {
	if p := os.Getenv("PACKMON_DB_PATH"); p != "" {
		return filepath.Join(p, "packmon.db")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".packmon", "db", "packmon.db")
}

func (c *cliConfig) findRepo(name string) *cliRepoConfig {
	if c == nil {
		return nil
	}
	for i := range c.Repos {
		if c.Repos[i].Name == name {
			return &c.Repos[i]
		}
	}
	return nil
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func defaultFailSeverity() domain.Severity {
	return domain.SeverityCritical
}

func maskSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "(not set)"
	}
	if len(value) <= 4 {
		return "****"
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}

func parseTimeoutSeconds(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	raw = strings.TrimSuffix(raw, "s")
	timeout, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid timeout %q", raw)
	}
	return timeout, nil
}
