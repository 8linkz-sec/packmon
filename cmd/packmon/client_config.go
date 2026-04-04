package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/scanner"
	"gopkg.in/yaml.v3"
)

const defaultCLIConfigFile = ".packmon.yaml"

type cliConfig struct {
	Server     string           `yaml:"server"`
	APIKey     string           `yaml:"api_key"`
	Mode       string           `yaml:"mode"`
	FailOn     string           `yaml:"fail_on"`
	Timeout    int              `yaml:"timeout"`
	Ecosystems []string         `yaml:"ecosystems"`
	IncludeDev *bool            `yaml:"include_dev"`
	Webhook    cliWebhookConfig `yaml:"webhook"`
	Output     cliOutputConfig  `yaml:"output"`
	Log        cliLogConfig     `yaml:"log"`
	Hook       cliHookConfig    `yaml:"hook"`
	DB         cliDBConfig      `yaml:"db"`
	Repos      []cliRepoConfig  `yaml:"repos"`
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
	Name       string           `yaml:"name"`
	Path       string           `yaml:"path"`
	Server     string           `yaml:"server"`
	APIKey     string           `yaml:"api_key"`
	Mode       string           `yaml:"mode"`
	FailOn     string           `yaml:"fail_on"`
	Timeout    int              `yaml:"timeout"`
	Ecosystems []string         `yaml:"ecosystems"`
	IncludeDev *bool            `yaml:"include_dev"`
	Webhook    cliWebhookConfig `yaml:"webhook"`
}

func loadCurrentCLIConfig() (*cliConfig, string, error) {
	return loadCLIConfig(flagConfig)
}

func loadCLIConfig(path string) (*cliConfig, string, error) {
	configPath := strings.TrimSpace(path)
	explicitPath := configPath != ""
	if configPath == "" {
		configPath = defaultCLIConfigFile
	}

	if _, err := os.Stat(configPath); err != nil {
		if os.IsNotExist(err) && !explicitPath {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("config file not found: %s", configPath)
	}

	// #nosec G304 -- CLI config path is supplied intentionally by the local user.
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", configPath, err)
	}

	var cfg cliConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
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

func (c *cliConfig) normalize(baseDir string) error {
	c.Server = strings.TrimSpace(c.Server)
	c.APIKey = strings.TrimSpace(c.APIKey)
	c.Mode = normalizeModeString(c.Mode)
	c.FailOn = normalizeSeverityString(c.FailOn)
	c.Ecosystems = normalizeStringList(c.Ecosystems)
	c.Webhook.URL = strings.TrimSpace(c.Webhook.URL)
	c.Webhook.Secret = strings.TrimSpace(c.Webhook.Secret)
	c.DB.Path = strings.TrimSpace(c.DB.Path)
	c.DB.SyncSource = strings.TrimSpace(c.DB.SyncSource)

	if err := validateModeString(c.Mode); err != nil {
		return err
	}
	if err := validateSeverityString(c.FailOn); err != nil {
		return err
	}
	if c.Timeout < 0 {
		return fmt.Errorf("timeout must not be negative")
	}

	if c.DB.Path != "" {
		resolvedPath, err := resolveConfigPath(baseDir, c.DB.Path)
		if err != nil {
			return fmt.Errorf("resolve db.path: %w", err)
		}
		c.DB.Path = resolvedPath
	}

	seenNames := make(map[string]struct{}, len(c.Repos))
	for i := range c.Repos {
		repo := &c.Repos[i]
		repo.Name = strings.TrimSpace(repo.Name)
		repo.Path = strings.TrimSpace(repo.Path)
		repo.Server = strings.TrimSpace(repo.Server)
		repo.APIKey = strings.TrimSpace(repo.APIKey)
		repo.Mode = normalizeModeString(repo.Mode)
		repo.FailOn = normalizeSeverityString(repo.FailOn)
		repo.Ecosystems = normalizeStringList(repo.Ecosystems)
		repo.Webhook.URL = strings.TrimSpace(repo.Webhook.URL)
		repo.Webhook.Secret = strings.TrimSpace(repo.Webhook.Secret)

		if repo.Path == "" {
			return fmt.Errorf("repos[%d].path is required", i)
		}
		resolvedPath, err := resolveConfigPath(baseDir, repo.Path)
		if err != nil {
			return fmt.Errorf("resolve repos[%d].path: %w", i, err)
		}
		repo.Path = resolvedPath

		if repo.Name == "" {
			repo.Name = filepath.Base(repo.Path)
		}
		if repo.Name == "" || repo.Name == "." || repo.Name == string(filepath.Separator) {
			return fmt.Errorf("repos[%d].name could not be derived from path", i)
		}

		if err := validateModeString(repo.Mode); err != nil {
			return fmt.Errorf("repos[%d].mode: %w", i, err)
		}
		if err := validateSeverityString(repo.FailOn); err != nil {
			return fmt.Errorf("repos[%d].fail_on: %w", i, err)
		}
		if repo.Timeout < 0 {
			return fmt.Errorf("repos[%d].timeout must not be negative", i)
		}
		if _, exists := seenNames[repo.Name]; exists {
			return fmt.Errorf("duplicate repo name %q", repo.Name)
		}
		seenNames[repo.Name] = struct{}{}
	}

	return nil
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

func normalizeModeString(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeSeverityString(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func validateModeString(value string) error {
	switch value {
	case "", string(scanner.ModeAuto), string(scanner.ModeLocal), string(scanner.ModeRemote):
		return nil
	default:
		return fmt.Errorf("invalid mode %q (want auto|local|remote)", value)
	}
}

func validateSeverityString(value string) error {
	if value == "" {
		return nil
	}
	if _, ok := scanner.SeverityFromString(value); ok {
		return nil
	}
	return fmt.Errorf("invalid severity %q (want CRITICAL|HIGH|MEDIUM|LOW|NONE)", value)
}

func resolveLocalDBPath() (string, error) {
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
