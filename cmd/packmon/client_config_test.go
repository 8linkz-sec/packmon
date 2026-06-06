package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
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

func TestResolveLocalDBPathUsesConfigAndReportsConfigErrors(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(".packmon.yaml", []byte("db:\n  path: "+strconvQuoteForYAML(dbDir)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	path, err := resolveLocalDBPath()
	if err != nil {
		t.Fatalf("resolveLocalDBPath(config) error = %v", err)
	}
	if path != filepath.Join(dbDir, "packmon.db") {
		t.Fatalf("resolveLocalDBPath(config) = %q, want configured DB file", path)
	}

	if err := os.WriteFile(".packmon.yaml", []byte("server: ["), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if _, err := resolveLocalDBPath(); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("resolveLocalDBPath(invalid config) error = %v", err)
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
