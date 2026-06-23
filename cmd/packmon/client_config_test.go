package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestLoadCLIConfigNormalizesRepoPaths(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".packmon.yaml")
	configYAML := `server: "http://localhost:8080"
db:
  path: "./state"
repos:
  - path: "./repo-one"
  - name: api
    path: "../shared/api"
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, resolvedPath, err := loadCLIConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if resolvedPath != configPath {
		t.Fatalf("resolvedPath = %q, want %q", resolvedPath, configPath)
	}
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}

	wantDBPath := filepath.Join(tempDir, "state")
	if cfg.DB.Path != wantDBPath {
		t.Fatalf("db.path = %q, want %q", cfg.DB.Path, wantDBPath)
	}

	if len(cfg.Repos) != 2 {
		t.Fatalf("len(repos) = %d, want 2", len(cfg.Repos))
	}

	if cfg.Repos[0].Name != "repo-one" {
		t.Fatalf("repo[0].name = %q, want %q", cfg.Repos[0].Name, "repo-one")
	}
	if cfg.Repos[0].Path != filepath.Join(tempDir, "repo-one") {
		t.Fatalf("repo[0].path = %q", cfg.Repos[0].Path)
	}
	if cfg.Repos[1].Path != filepath.Clean(filepath.Join(tempDir, "..", "shared", "api")) {
		t.Fatalf("repo[1].path = %q", cfg.Repos[1].Path)
	}
}

func TestLoadCLIConfigValidatesEcosystemFilters(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "top level",
			yaml: "ecosystems: [npm, nmp]\n",
		},
		{
			name: "repo",
			yaml: "repos:\n  - name: app\n    path: .\n    ecosystems: [pypi, nmp]\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), ".packmon.yaml")
			if err := os.WriteFile(configPath, []byte(tt.yaml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, _, err := loadCLIConfig(configPath)
			if err == nil {
				t.Fatal("loadCLIConfig() error = nil, want unknown ecosystem rejection")
			}
			if !strings.Contains(err.Error(), `unknown ecosystem filter "nmp"`) {
				t.Fatalf("loadCLIConfig() error = %v, want unknown ecosystem", err)
			}
			if !strings.Contains(err.Error(), "valid values") {
				t.Fatalf("loadCLIConfig() error = %v, want valid values list", err)
			}
		})
	}

	configPath := filepath.Join(t.TempDir(), ".packmon.yaml")
	if err := os.WriteFile(configPath, []byte("ecosystems: [Docker, NPM]\n"), 0o600); err != nil {
		t.Fatalf("write docker config: %v", err)
	}
	cfg, _, err := loadCLIConfig(configPath)
	if err != nil {
		t.Fatalf("loadCLIConfig(docker config) error = %v", err)
	}
	if got := strings.Join(cfg.Ecosystems, ","); got != "docker,npm" {
		t.Fatalf("ecosystems = %q, want docker,npm", got)
	}
}

func TestLoadCLIConfigLayersUserGlobalUnderProject(t *testing.T) {
	// Uses t.Chdir/t.Setenv, so it cannot run in parallel.
	home := t.TempDir()
	t.Setenv("HOME", home)        // Unix
	t.Setenv("USERPROFILE", home) // Windows

	userCfgDir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(userCfgDir, 0o750); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	userCfg := "server: \"https://global.example\"\nfail_on: HIGH\ntimeout: 99\n"
	if err := os.WriteFile(filepath.Join(userCfgDir, "packmon.yaml"), []byte(userCfg), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, ".packmon.yaml"), []byte("fail_on: CRITICAL\n"), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}
	t.Chdir(project)

	cfg, _, err := loadCLIConfig("")
	if err != nil {
		t.Fatalf("loadCLIConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a merged config, got nil")
	}
	// Inherited from the user-global layer (project did not set these).
	if cfg.Server != "https://global.example" {
		t.Errorf("server = %q, want user-global value", cfg.Server)
	}
	if cfg.Timeout != 99 {
		t.Errorf("timeout = %d, want 99 from user-global", cfg.Timeout)
	}
	// Project overrides the user-global value.
	if cfg.FailOn != "CRITICAL" {
		t.Errorf("fail_on = %q, want CRITICAL (project overrides user-global)", cfg.FailOn)
	}
}

func TestLoadCLIConfigCanSkipAutoDiscoveredProjectConfig(t *testing.T) {
	// Uses t.Chdir/t.Setenv, so it cannot run in parallel.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	userCfgDir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(userCfgDir, 0o750); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	userPath := filepath.Join(userCfgDir, "packmon.yaml")
	if err := os.WriteFile(userPath, []byte("fail_on: HIGH\n"), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}

	project := t.TempDir()
	projectCfg := "fail_on: LOW\necosystems:\n  - npm\n"
	if err := os.WriteFile(filepath.Join(project, ".packmon.yaml"), []byte(projectCfg), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}
	t.Chdir(project)

	cfg, sourcePath, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{SkipProjectConfig: true})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if sourcePath != userPath {
		t.Fatalf("sourcePath = %q, want user-global config %q", sourcePath, userPath)
	}
	if cfg.FailOn != "HIGH" {
		t.Fatalf("fail_on = %q, want user-global value when project config is skipped", cfg.FailOn)
	}
	if len(cfg.Ecosystems) != 0 {
		t.Fatalf("ecosystems = %v, want project ecosystem filter skipped", cfg.Ecosystems)
	}
}

func TestLoadCLIConfigAutoProjectCannotOverrideSensitiveUserConfig(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	userCfgDir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(userCfgDir, 0o750); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	trustedDB := filepath.Join(home, "trusted-db")
	userCfg := "server: \"https://trusted.example\"\n" +
		"api_key_env: PACKMON_TRUSTED_KEY\n" +
		"api_key: trusted-inline\n" +
		"cacert: trusted-ca.pem\n" +
		"insecure_allow_http: true\n" +
		"db:\n  path: " + strconvQuoteForYAML(trustedDB) + "\n" +
		"webhook:\n  url: \"https://trusted.example/hook\"\n  secret: trusted-hook-secret\n" +
		"output:\n  format: json\n  file: trusted-result.json\n" +
		"send_repo_metadata: false\n" +
		"fail_on: HIGH\n"
	if err := os.WriteFile(filepath.Join(userCfgDir, "packmon.yaml"), []byte(userCfg), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}

	projectCfg := `server: "https://evil.example"
api_key_env: EVIL_ENV
api_key: evil-inline
cacert: evil-ca.pem
insecure_allow_http: false
db:
  path: ./evil-db
webhook:
  url: "https://evil.example/hook"
  secret: evil-hook-secret
output:
  format: html
  file: ../evil-result.html
send_repo_metadata: true
fail_on: LOW
repos:
  - name: app
    path: .
    server: "https://repo-evil.example"
    api_key_env: REPO_EVIL_ENV
    api_key: repo-evil-inline
    webhook:
      url: "https://repo-evil.example/hook"
      secret: repo-evil-hook-secret
    send_repo_metadata: true
    fail_on: MEDIUM
`
	if err := os.WriteFile(defaultCLIConfigFile, []byte(projectCfg), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	cfg, _, err := loadCLIConfig("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Server != "https://trusted.example" || cfg.APIKeyEnv != "PACKMON_TRUSTED_KEY" || cfg.APIKey != "trusted-inline" {
		t.Fatalf("trusted credential routing was overwritten: %+v", cfg)
	}
	if cfg.CACert != "trusted-ca.pem" || cfg.InsecureAllowHTTP == nil || !*cfg.InsecureAllowHTTP {
		t.Fatalf("trusted TLS/server trust fields were overwritten: %+v", cfg)
	}
	if cfg.DB.Path != trustedDB {
		t.Fatalf("db.path = %q, want trusted user path %q", cfg.DB.Path, trustedDB)
	}
	if cfg.Webhook.URL != "https://trusted.example/hook" || cfg.Webhook.Secret != "trusted-hook-secret" {
		t.Fatalf("trusted webhook config was overwritten: %+v", cfg.Webhook)
	}
	if cfg.Output.Format != "json" || cfg.Output.File != "trusted-result.json" {
		t.Fatalf("trusted output config was overwritten: %+v", cfg.Output)
	}
	if cfg.SendRepoMetadata == nil || *cfg.SendRepoMetadata {
		t.Fatalf("trusted repo-metadata privacy opt-out was overwritten: %+v", cfg.SendRepoMetadata)
	}
	if cfg.FailOn != "LOW" {
		t.Fatalf("non-sensitive project fail_on did not override user config: %q", cfg.FailOn)
	}
	if len(cfg.Repos) != 1 {
		t.Fatalf("repos = %+v, want project repo preserved", cfg.Repos)
	}
	repo := cfg.Repos[0]
	if repo.Server != "" || repo.APIKeyEnv != "" || repo.APIKey != "" {
		t.Fatalf("project repo credential routing fields were not stripped: %+v", repo)
	}
	if repo.Webhook.URL != "" || repo.Webhook.Secret != "" {
		t.Fatalf("project repo webhook fields were not stripped: %+v", repo.Webhook)
	}
	if repo.SendRepoMetadata != nil {
		t.Fatalf("project repo cannot re-enable repo metadata: %+v", repo.SendRepoMetadata)
	}
	if repo.FailOn != "MEDIUM" {
		t.Fatalf("repo non-sensitive policy not preserved: %+v", repo)
	}
}

func TestLoadCLIConfigAutoProjectIgnoresSensitiveFieldsWithoutUserConfig(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	projectCfg := `server: "https://evil.example"
api_key_env: EVIL_ENV
api_key: evil-inline
cacert: evil-ca.pem
insecure_allow_http: true
db:
  path: ./evil-db
webhook:
  url: "https://evil.example/hook"
  secret: evil-hook-secret
output:
  format: html
  file: ../evil-result.html
send_repo_metadata: false
mode: remote
repos:
  - name: app
    path: .
    server: "https://repo-evil.example"
    api_key_env: REPO_EVIL_ENV
    api_key: repo-evil-inline
    webhook:
      url: "https://repo-evil.example/hook"
      secret: repo-evil-hook-secret
    send_repo_metadata: false
`
	if err := os.WriteFile(defaultCLIConfigFile, []byte(projectCfg), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	cfg, _, err := loadCLIConfig("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Server != "" || cfg.APIKeyEnv != "" || cfg.APIKey != "" || cfg.CACert != "" || cfg.InsecureAllowHTTP != nil {
		t.Fatalf("auto project sensitive top-level fields were trusted: %+v", cfg)
	}
	if cfg.DB.Path != "" {
		t.Fatalf("auto project db.path = %q, want ignored", cfg.DB.Path)
	}
	if cfg.Webhook.URL != "" || cfg.Webhook.Secret != "" {
		t.Fatalf("auto project webhook fields were trusted: %+v", cfg.Webhook)
	}
	if cfg.Output.File != "" {
		t.Fatalf("auto project output.file = %q, want ignored", cfg.Output.File)
	}
	if cfg.SendRepoMetadata == nil || *cfg.SendRepoMetadata {
		t.Fatalf("auto project send_repo_metadata=false should be preserved: %+v", cfg.SendRepoMetadata)
	}
	if cfg.Mode != "remote" {
		t.Fatalf("non-routing project mode should still load: %q", cfg.Mode)
	}
	if len(cfg.Repos) != 1 {
		t.Fatalf("repos = %+v, want project repo preserved", cfg.Repos)
	}
	if cfg.Repos[0].Server != "" || cfg.Repos[0].APIKeyEnv != "" || cfg.Repos[0].APIKey != "" {
		t.Fatalf("auto project repo sensitive fields were trusted: %+v", cfg.Repos[0])
	}
	if cfg.Repos[0].SendRepoMetadata == nil || *cfg.Repos[0].SendRepoMetadata {
		t.Fatalf("auto project repo send_repo_metadata=false should be preserved: %+v", cfg.Repos[0].SendRepoMetadata)
	}
	if cfg.Repos[0].Webhook.URL != "" || cfg.Repos[0].Webhook.Secret != "" {
		t.Fatalf("auto project repo webhook fields were trusted: %+v", cfg.Repos[0].Webhook)
	}
}

func TestLoadCLIConfigNoFilesAndExplicitMissing(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	cfg, source, err := loadCLIConfig("")
	if err != nil {
		t.Fatalf("loadCLIConfig(no files) error = %v", err)
	}
	if cfg != nil || source != "" {
		t.Fatalf("loadCLIConfig(no files) = %+v %q, want nil empty source", cfg, source)
	}

	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, _, err := loadCLIConfig(missing); err == nil || !strings.Contains(err.Error(), "config file not found") {
		t.Fatalf("loadCLIConfig(missing explicit) error = %v", err)
	}
}

func TestResolveLocalDBPathUsesTrustedUserConfigAndReportsProjectConfigErrors(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	userCfgDir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(userCfgDir, 0o750); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	dbDir := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(filepath.Join(userCfgDir, "packmon.yaml"), []byte("db:\n  path: "+strconvQuoteForYAML(dbDir)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	path, err := resolveLocalDBPath()
	if err != nil {
		t.Fatalf("resolveLocalDBPath(config) error = %v", err)
	}
	if path != filepath.Join(dbDir, "packmon.db") {
		t.Fatalf("resolveLocalDBPath(config) = %q, want configured DB file", path)
	}

	if err := os.WriteFile(defaultCLIConfigFile, []byte("server: ["), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if _, err := resolveLocalDBPath(); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("resolveLocalDBPath(invalid config) error = %v", err)
	}
}

func TestResolveLocalDBPathEnvOverridesAutoProjectDBPath(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	envDBDir := filepath.Join(t.TempDir(), "env-db")
	t.Setenv("PACKMON_DB_PATH", envDBDir)
	if err := os.WriteFile(defaultCLIConfigFile, []byte("db:\n  path: ./repo-db\n"), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	path, err := resolveLocalDBPath()
	if err != nil {
		t.Fatalf("resolveLocalDBPath() error = %v", err)
	}
	if path != filepath.Join(envDBDir, "packmon.db") {
		t.Fatalf("resolveLocalDBPath() = %q, want env-controlled DB path", path)
	}
}

func TestLoadCLIConfigRejectsDuplicateRepoNames(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, ".packmon.yaml")
	configYAML := `repos:
  - name: app
    path: "./one"
  - name: app
    path: "./two"
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, _, err := loadCLIConfig(configPath); err == nil {
		t.Fatal("expected duplicate repo name error, got nil")
	}
}

func TestLoadCLIConfigValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "unknown field", yaml: "unknown: true\n", want: "field unknown"},
		{name: "invalid mode", yaml: "mode: sideways\n", want: "invalid mode"},
		{name: "invalid severity", yaml: "fail_on: SEVERE\n", want: "invalid severity"},
		{name: "negative timeout", yaml: "timeout: -1\n", want: "timeout must not be negative"},
		{name: "repo missing path", yaml: "repos:\n  - name: app\n", want: "path is required"},
		{name: "repo invalid mode", yaml: "repos:\n  - path: .\n    mode: sideways\n", want: "repos[0].mode"},
		{name: "repo invalid severity", yaml: "repos:\n  - path: .\n    fail_on: SEVERE\n", want: "repos[0].fail_on"},
		{name: "repo negative timeout", yaml: "repos:\n  - path: .\n    timeout: -2\n", want: "timeout must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".packmon.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, _, err := loadCLIConfig(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadCLIConfig() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestDecodeCLIConfigEmptyDocumentAndFindRepoBranches(t *testing.T) {
	t.Parallel()

	cfg := &cliConfig{Server: "keep"}
	if err := decodeCLIConfig(nil, cfg); err != nil {
		t.Fatalf("decodeCLIConfig(empty) error = %v", err)
	}
	if cfg.Server != "keep" {
		t.Fatalf("empty decode mutated config: %+v", cfg)
	}

	if repo := (*cliConfig)(nil).findRepo("missing"); repo != nil {
		t.Fatalf("nil findRepo = %+v, want nil", repo)
	}
	cfg.Repos = []cliRepoConfig{{Name: "api", Path: "."}}
	if repo := cfg.findRepo("missing"); repo != nil {
		t.Fatalf("missing findRepo = %+v, want nil", repo)
	}
}

func TestResolveConfigPathExpandsHomeEnvAndRelativePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PACKMON_CONFIG_TEST_DIR", "envdir")
	base := t.TempDir()

	got, err := resolveConfigPath(base, "~/state")
	if err != nil {
		t.Fatalf("resolve home: %v", err)
	}
	if got != filepath.Join(home, "state") {
		t.Fatalf("home path = %q, want under %q", got, home)
	}

	got, err = resolveConfigPath(base, "~")
	if err != nil {
		t.Fatalf("resolve home root: %v", err)
	}
	// resolveConfigPath normalises to OS-native separators; compare against a
	// cleaned home so the test is robust to how GOTMPDIR/TMP was set (e.g. a
	// forward-slash value on Windows yields a mixed-separator t.TempDir()).
	if got != filepath.Clean(home) {
		t.Fatalf("home root path = %q, want %q", got, filepath.Clean(home))
	}

	got, err = resolveConfigPath(base, "$PACKMON_CONFIG_TEST_DIR/db")
	if err != nil {
		t.Fatalf("resolve env relative: %v", err)
	}
	if got != filepath.Join(base, "envdir", "db") {
		t.Fatalf("env relative path = %q", got)
	}

	got, err = resolveConfigPath(base, "")
	if err != nil || got != "" {
		t.Fatalf("resolve empty = %q, %v; want empty nil", got, err)
	}
}

func TestParseTimeoutSecondsEmptyValue(t *testing.T) {
	t.Parallel()

	timeout, err := parseTimeoutSeconds(" ")
	if err != nil || timeout != 0 {
		t.Fatalf("parseTimeoutSeconds(empty) = %d, %v; want 0 nil", timeout, err)
	}
}

func TestBuildScanTargets(t *testing.T) {
	t.Parallel()

	cfg := &cliConfig{
		Repos: []cliRepoConfig{
			{Name: "frontend", Path: "E:/repos/frontend"},
			{Name: "backend", Path: "E:/repos/backend"},
		},
	}

	targets, err := buildScanTargets(cfg, nil, scanFlagValues{All: true})
	if err != nil {
		t.Fatalf("build all targets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}

	targets, err = buildScanTargets(cfg, nil, scanFlagValues{Repo: "backend"})
	if err != nil {
		t.Fatalf("build named target: %v", err)
	}
	if len(targets) != 1 || targets[0].Name != "backend" {
		t.Fatalf("unexpected named target result: %+v", targets)
	}
}

func TestCLIConfigHelperBranches(t *testing.T) {
	t.Parallel()

	outputCases := []struct {
		name string
		cfg  cliOutputConfig
		want string
	}{
		{"invalid format", cliOutputConfig{Format: "xml"}, "invalid output.format"},
		{"file without format", cliOutputConfig{File: "scan.json"}, "output.format is required"},
		{"table file", cliOutputConfig{Format: "table", File: "scan.txt"}, "does not support"},
	}
	for _, tt := range outputCases {
		if err := validateOutputConfig(tt.cfg); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("validateOutputConfig(%s) = %v, want %q", tt.name, err, tt.want)
		}
	}
	if err := validateOutputConfig(cliOutputConfig{Format: "html", File: "scan.html"}); err != nil {
		t.Fatalf("validateOutputConfig(html file) error = %v", err)
	}

	logCases := []struct {
		name string
		cfg  cliLogConfig
		want string
	}{
		{"invalid level", cliLogConfig{Level: "TRACE"}, "invalid log.level"},
		{"invalid format", cliLogConfig{Format: "xml"}, "invalid log.format"},
		{"file unsupported", cliLogConfig{File: "packmon.log"}, "not supported"},
	}
	for _, tt := range logCases {
		if err := validateLogConfig(tt.cfg); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("validateLogConfig(%s) = %v, want %q", tt.name, err, tt.want)
		}
	}

	if got := normalizeLogLevel(" warn "); got != "WARN" {
		t.Fatalf("normalizeLogLevel() = %q, want WARN", got)
	}
	if got := boolValue(nil, true); !got {
		t.Fatal("boolValue(nil,true) = false")
	}
	no := false
	if got := boolValue(&no, true); got {
		t.Fatal("boolValue(false,true) = true")
	}
	if got := defaultFailSeverity(); got != domain.SeverityCritical {
		t.Fatalf("defaultFailSeverity() = %s", got)
	}
	for input, want := range map[string]string{
		"":       "(not set)",
		"abcd":   "****",
		"secret": "se**et",
	} {
		if got := maskSecret(input); got != want {
			t.Fatalf("maskSecret(%q) = %q, want %q", input, got, want)
		}
	}
	if timeout, err := parseTimeoutSeconds("45s"); err != nil || timeout != 45 {
		t.Fatalf("parseTimeoutSeconds(45s) = %d, %v", timeout, err)
	}
	if _, err := parseTimeoutSeconds("bad"); err == nil || !strings.Contains(err.Error(), "invalid timeout") {
		t.Fatalf("parseTimeoutSeconds(bad) error = %v", err)
	}
}
