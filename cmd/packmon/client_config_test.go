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

func TestLoadCLIConfigRejectsOversizedAutoProjectConfig(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	if err := os.WriteFile(defaultCLIConfigFile, oversizedAutoProjectConfigYAML(), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	_, _, err := loadCLIConfig("")
	if err == nil {
		t.Fatal("loadCLIConfig() error = nil, want oversized project config rejection")
	}
	if !strings.Contains(err.Error(), "project config") || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("loadCLIConfig() error = %v, want clear project config size error", err)
	}
}

func TestLoadCLIConfigSkipProjectConfigIgnoresOversizedAutoProjectConfig(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	userCfgDir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(userCfgDir, 0o750); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	userPath := filepath.Join(userCfgDir, "packmon.yaml")
	if err := os.WriteFile(userPath, []byte("fail_on: HIGH\n"), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}
	if err := os.WriteFile(defaultCLIConfigFile, oversizedAutoProjectConfigYAML(), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	cfg, sourcePath, err := loadCLIConfigWithOptions("", cliConfigLoadOptions{SkipProjectConfig: true})
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if sourcePath != userPath {
		t.Fatalf("sourcePath = %q, want user-global config %q", sourcePath, userPath)
	}
	if cfg.FailOn != "HIGH" {
		t.Fatalf("fail_on = %q, want user-global value when oversized project config is skipped", cfg.FailOn)
	}
}

func TestLoadCLIConfigLoadsSmallAutoProjectConfig(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	if err := os.WriteFile(defaultCLIConfigFile, []byte("fail_on: LOW\necosystems: [npm]\n"), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	cfg, sourcePath, err := loadCLIConfig("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected project config, got nil")
	}
	if cfg.FailOn != "LOW" {
		t.Fatalf("fail_on = %q, want LOW", cfg.FailOn)
	}
	if got := strings.Join(cfg.Ecosystems, ","); got != "npm" {
		t.Fatalf("ecosystems = %q, want npm", got)
	}
	if !filepath.IsAbs(sourcePath) || filepath.Base(sourcePath) != defaultCLIConfigFile {
		t.Fatalf("sourcePath = %q, want absolute project config path", sourcePath)
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
		"registries:\n  npm_registry_base_url: \"https://npm-trusted.example/registry\"\n  pypi_api_base_url: \"https://pypi-trusted.example/pypi\"\n  rubygems_api_base_url: \"https://rubygems-trusted.example/api/v1/gems\"\n  cargo_registry_api_base_url: \"https://cargo-trusted.example/api/v1/crates\"\n  cocoapods_trunk_api_base_url: \"https://cocoapods-trusted.example/api/v1/pods\"\n  composer_repository_base_url: \"https://composer-trusted.example/p2\"\n  go_proxy_url: \"https://go-trusted.example\"\n  maven_repository_base_url: \"https://maven-trusted.example/repository/maven-public\"\n  docker_registry_mirrors:\n    docker.io: \"https://docker-trusted.example/dockerhub\"\n    ghcr.io: \"https://ghcr-trusted.example\"\n  swiftpm_git_allowed_hosts:\n    - git-trusted.example\n    - gitlab-trusted.example\n  cran_mirror_url: \"https://cran-trusted.example\"\n  pub_hosted_url: \"https://pub-trusted.example\"\n  hex_api_base_url: \"https://hex-trusted.example/api\"\n  nuget_v3_base_url: \"https://nuget-trusted.example/v3-flatcontainer\"\n" +
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
registries:
  npm_registry_base_url: "https://npm-evil.example/registry"
  pypi_api_base_url: "https://pypi-evil.example/pypi"
  rubygems_api_base_url: "https://rubygems-evil.example/api/v1/gems"
  cargo_registry_api_base_url: "https://cargo-evil.example/api/v1/crates"
  cocoapods_trunk_api_base_url: "https://cocoapods-evil.example/api/v1/pods"
  composer_repository_base_url: "https://composer-evil.example/p2"
  go_proxy_url: "https://go-evil.example"
  maven_repository_base_url: "https://maven-evil.example/repository/maven-public"
  docker_registry_mirrors:
    docker.io: "https://docker-evil.example/dockerhub"
  swiftpm_git_allowed_hosts:
    - git-evil.example
  cran_mirror_url: "https://cran-evil.example"
  pub_hosted_url: "https://pub-evil.example"
  hex_api_base_url: "https://hex-evil.example/api"
  nuget_v3_base_url: "https://nuget-evil.example/v3-flatcontainer"
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
	if cfg.Registries.NPMRegistryBaseURL != "https://npm-trusted.example/registry" ||
		cfg.Registries.PyPIAPIBaseURL != "https://pypi-trusted.example/pypi" ||
		cfg.Registries.RubyGemsAPIBaseURL != "https://rubygems-trusted.example/api/v1/gems" ||
		cfg.Registries.CargoRegistryAPIBaseURL != "https://cargo-trusted.example/api/v1/crates" ||
		cfg.Registries.CocoaPodsTrunkAPIBaseURL != "https://cocoapods-trusted.example/api/v1/pods" ||
		cfg.Registries.ComposerRepositoryBaseURL != "https://composer-trusted.example/p2" ||
		cfg.Registries.GoModuleProxyURL != "https://go-trusted.example" ||
		cfg.Registries.MavenRepositoryBaseURL != "https://maven-trusted.example/repository/maven-public" ||
		cfg.Registries.DockerRegistryMirrors["registry-1.docker.io"] != "https://docker-trusted.example/dockerhub" ||
		cfg.Registries.DockerRegistryMirrors["ghcr.io"] != "https://ghcr-trusted.example" ||
		strings.Join(cfg.Registries.SwiftPMGitAllowedHosts, ",") != "git-trusted.example,gitlab-trusted.example" ||
		cfg.Registries.CRANMirrorURL != "https://cran-trusted.example" ||
		cfg.Registries.PubHostedURL != "https://pub-trusted.example" ||
		cfg.Registries.HexAPIBaseURL != "https://hex-trusted.example/api" ||
		cfg.Registries.NuGetV3BaseURL != "https://nuget-trusted.example/v3-flatcontainer" {
		t.Fatalf("trusted registry mirror config was overwritten: %+v", cfg.Registries)
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
registries:
  npm_registry_base_url: "https://npm-evil.example/registry"
  pypi_api_base_url: "https://pypi-evil.example/pypi"
  rubygems_api_base_url: "https://rubygems-evil.example/api/v1/gems"
  cargo_registry_api_base_url: "https://cargo-evil.example/api/v1/crates"
  cocoapods_trunk_api_base_url: "https://cocoapods-evil.example/api/v1/pods"
  composer_repository_base_url: "https://composer-evil.example/p2"
  go_proxy_url: "https://go-evil.example"
  maven_repository_base_url: "https://maven-evil.example/repository/maven-public"
  docker_registry_mirrors:
    docker.io: "https://docker-evil.example/dockerhub"
  swiftpm_git_allowed_hosts:
    - git-evil.example
  cran_mirror_url: "https://cran-evil.example"
  pub_hosted_url: "https://pub-evil.example"
  hex_api_base_url: "https://hex-evil.example/api"
  nuget_v3_base_url: "https://nuget-evil.example/v3-flatcontainer"
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
	if cfg.Output.Format != "" || cfg.Output.File != "" {
		t.Fatalf("auto project output config was trusted: %+v", cfg.Output)
	}
	if cfg.Registries.NPMRegistryBaseURL != "" || cfg.Registries.PyPIAPIBaseURL != "" ||
		cfg.Registries.RubyGemsAPIBaseURL != "" || cfg.Registries.CargoRegistryAPIBaseURL != "" ||
		cfg.Registries.CocoaPodsTrunkAPIBaseURL != "" || cfg.Registries.ComposerRepositoryBaseURL != "" ||
		cfg.Registries.GoModuleProxyURL != "" || cfg.Registries.MavenRepositoryBaseURL != "" ||
		len(cfg.Registries.DockerRegistryMirrors) != 0 ||
		len(cfg.Registries.SwiftPMGitAllowedHosts) != 0 ||
		cfg.Registries.CRANMirrorURL != "" || cfg.Registries.PubHostedURL != "" ||
		cfg.Registries.HexAPIBaseURL != "" ||
		cfg.Registries.NuGetV3BaseURL != "" {
		t.Fatalf("auto project registry mirror config was trusted: %+v", cfg.Registries)
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

func TestOverlayCLIConnectionConfigPreservesUnsetFields(t *testing.T) {
	t.Parallel()

	allowHTTP := true
	//nolint:gosec // G101: fixture credential, deliberately fake.
	dst := &cliConfig{
		Server:            "https://base.example",
		APIKey:            "base-key",
		APIKeyEnv:         "PACKMON_BASE_KEY",
		CACert:            "base-ca.pem",
		InsecureAllowHTTP: boolPtr(false),
		RequireRemote:     boolPtr(false),
	}
	src := cliConfig{
		Server:            "https://override.example",
		APIKeyEnv:         "PACKMON_OVERRIDE_KEY",
		InsecureAllowHTTP: &allowHTTP,
	}

	overlayCLIConnectionConfig(dst, src)

	if dst.Server != "https://override.example" {
		t.Fatalf("server = %q, want override", dst.Server)
	}
	if dst.APIKey != "base-key" {
		t.Fatalf("api_key = %q, want base retained", dst.APIKey)
	}
	if dst.APIKeyEnv != "PACKMON_OVERRIDE_KEY" {
		t.Fatalf("api_key_env = %q, want override", dst.APIKeyEnv)
	}
	if dst.CACert != "base-ca.pem" {
		t.Fatalf("cacert = %q, want base retained", dst.CACert)
	}
	if dst.InsecureAllowHTTP == nil || !*dst.InsecureAllowHTTP {
		t.Fatalf("insecure_allow_http = %+v, want true override", dst.InsecureAllowHTTP)
	}
	if dst.RequireRemote == nil || *dst.RequireRemote {
		t.Fatalf("require_remote = %+v, want base false retained", dst.RequireRemote)
	}
}

func TestOverlayCLIScanPolicyConfigCopiesConfiguredFields(t *testing.T) {
	t.Parallel()

	dst := &cliConfig{
		Mode:       "local",
		FailOn:     "HIGH",
		Timeout:    45,
		Ecosystems: []string{"npm"},
		IncludeDev: boolPtr(false),
	}
	src := cliConfig{
		Mode:       "remote",
		FailOn:     "LOW",
		Ecosystems: []string{"pypi", "go"},
		IncludeDev: boolPtr(true),
	}

	overlayCLIScanPolicyConfig(dst, src)
	src.Ecosystems[0] = "mutated"

	if dst.Mode != "remote" || dst.FailOn != "LOW" {
		t.Fatalf("scan policy strings = mode %q fail_on %q, want remote/LOW", dst.Mode, dst.FailOn)
	}
	if dst.Timeout != 45 {
		t.Fatalf("timeout = %d, want base retained for zero source timeout", dst.Timeout)
	}
	if got := strings.Join(dst.Ecosystems, ","); got != "pypi,go" {
		t.Fatalf("ecosystems = %q, want copied pypi,go", got)
	}
	if dst.IncludeDev == nil || !*dst.IncludeDev {
		t.Fatalf("include_dev = %+v, want true override", dst.IncludeDev)
	}
}

func TestOverlayCLISectionHelpersPreserveSparseSemantics(t *testing.T) {
	t.Parallel()

	dst := &cliConfig{
		SendRepoMetadata: boolPtr(false),
		Webhook:          cliWebhookConfig{URL: "https://base.example/hook", Secret: "base-secret"},
		Output:           cliOutputConfig{Format: "json", File: "base.json"},
		Log:              cliLogConfig{Level: "INFO", Format: "text", File: "base.log"},
		Hook:             cliHookConfig{Type: "pre-push", FailOn: "HIGH"},
		DB:               cliDBConfig{Path: "base-db", SyncSource: "server"},
		Registries: cliRegistryConfig{
			NPMRegistryBaseURL:        "https://npm-base.example/registry",
			PyPIAPIBaseURL:            "https://pypi-base.example/pypi",
			RubyGemsAPIBaseURL:        "https://rubygems-base.example/api/v1/gems",
			CargoRegistryAPIBaseURL:   "https://cargo-base.example/api/v1/crates",
			CocoaPodsTrunkAPIBaseURL:  "https://cocoapods-base.example/api/v1/pods",
			ComposerRepositoryBaseURL: "https://composer-base.example/p2",
			GoModuleProxyURL:          "https://go-base.example",
			MavenRepositoryBaseURL:    "https://maven-base.example/repository/maven-public",
			DockerRegistryMirrors:     map[string]string{"docker.io": "https://docker-base.example/dockerhub"},
			SwiftPMGitAllowedHosts:    []string{"git-base.example"},
			CRANMirrorURL:             "https://cran-base.example",
			PubHostedURL:              "https://pub-base.example",
			HexAPIBaseURL:             "https://hex-base.example/api",
			NuGetV3BaseURL:            "https://nuget-base.example/v3",
		},
		Repos: []cliRepoConfig{{Name: "base", Path: "base-path"}},
	}
	src := cliConfig{
		SendRepoMetadata: boolPtr(true),
		Webhook:          cliWebhookConfig{Secret: "override-secret"},
		Output:           cliOutputConfig{File: "override.json"},
		Log:              cliLogConfig{Format: "json"},
		Hook:             cliHookConfig{FailOn: "LOW"},
		DB:               cliDBConfig{SyncSource: "server"},
		Registries: cliRegistryConfig{
			PyPIAPIBaseURL:            "https://pypi-override.example/pypi",
			CocoaPodsTrunkAPIBaseURL:  "https://cocoapods-override.example/api/v1/pods",
			ComposerRepositoryBaseURL: "https://composer-override.example/p2",
			MavenRepositoryBaseURL:    "https://maven-override.example/repository/maven-public",
			DockerRegistryMirrors:     map[string]string{"ghcr.io": "https://ghcr-override.example"},
			SwiftPMGitAllowedHosts:    []string{"git-override.example"},
			PubHostedURL:              "https://pub-override.example",
			NuGetV3BaseURL:            "https://nuget-override.example/v3",
		},
		Repos: []cliRepoConfig{{Name: "override", Path: "override-path"}},
	}

	overlayCLIRepoMetadataConfig(dst, src)
	overlayCLIWebhookConfig(&dst.Webhook, src.Webhook)
	overlayCLIOutputConfig(&dst.Output, src.Output)
	overlayCLILogConfig(&dst.Log, src.Log)
	overlayCLIHookConfig(&dst.Hook, src.Hook)
	overlayCLIDBConfig(&dst.DB, src.DB)
	overlayCLIRegistryConfig(&dst.Registries, src.Registries)
	overlayCLIReposConfig(dst, src)
	src.Repos[0].Name = "mutated"

	if dst.SendRepoMetadata == nil || !*dst.SendRepoMetadata {
		t.Fatalf("send_repo_metadata = %+v, want true override", dst.SendRepoMetadata)
	}
	if dst.Webhook.URL != "https://base.example/hook" || dst.Webhook.Secret != "override-secret" {
		t.Fatalf("webhook = %+v, want base URL and override secret", dst.Webhook)
	}
	if dst.Output.Format != "json" || dst.Output.File != "override.json" {
		t.Fatalf("output = %+v, want base format and override file", dst.Output)
	}
	if dst.Log.Level != "INFO" || dst.Log.Format != "json" || dst.Log.File != "base.log" {
		t.Fatalf("log = %+v, want sparse overlay", dst.Log)
	}
	if dst.Hook.Type != "pre-push" || dst.Hook.FailOn != "LOW" {
		t.Fatalf("hook = %+v, want base type and override fail_on", dst.Hook)
	}
	if dst.DB.Path != "base-db" || dst.DB.SyncSource != "server" {
		t.Fatalf("db = %+v, want base path and override sync source", dst.DB)
	}
	if dst.Registries.NPMRegistryBaseURL != "https://npm-base.example/registry" ||
		dst.Registries.PyPIAPIBaseURL != "https://pypi-override.example/pypi" ||
		dst.Registries.RubyGemsAPIBaseURL != "https://rubygems-base.example/api/v1/gems" ||
		dst.Registries.CargoRegistryAPIBaseURL != "https://cargo-base.example/api/v1/crates" ||
		dst.Registries.CocoaPodsTrunkAPIBaseURL != "https://cocoapods-override.example/api/v1/pods" ||
		dst.Registries.ComposerRepositoryBaseURL != "https://composer-override.example/p2" ||
		dst.Registries.GoModuleProxyURL != "https://go-base.example" ||
		dst.Registries.MavenRepositoryBaseURL != "https://maven-override.example/repository/maven-public" ||
		dst.Registries.DockerRegistryMirrors["docker.io"] != "https://docker-base.example/dockerhub" ||
		dst.Registries.DockerRegistryMirrors["ghcr.io"] != "https://ghcr-override.example" ||
		strings.Join(dst.Registries.SwiftPMGitAllowedHosts, ",") != "git-base.example,git-override.example" ||
		dst.Registries.CRANMirrorURL != "https://cran-base.example" ||
		dst.Registries.PubHostedURL != "https://pub-override.example" ||
		dst.Registries.HexAPIBaseURL != "https://hex-base.example/api" ||
		dst.Registries.NuGetV3BaseURL != "https://nuget-override.example/v3" {
		t.Fatalf("registries = %+v, want sparse overlay", dst.Registries)
	}
	if len(dst.Repos) != 1 || dst.Repos[0].Name != "override" || dst.Repos[0].Path != "override-path" {
		t.Fatalf("repos = %+v, want copied override repos", dst.Repos)
	}
}

func TestNormalizeTopLevelCLIConfigOnlyHandlesTopLevelScope(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	//nolint:gosec // G101: fixture credential, deliberately fake.
	cfg := &cliConfig{
		Server:    " https://packmon.example ",
		APIKey:    " inline-key ",
		APIKeyEnv: " PACKMON_API_KEY ",
		Mode:      " Remote ",
		FailOn:    " high ",
		Ecosystems: []string{
			" NPM ",
			"",
			"Docker",
		},
		CACert: " ca.pem ",
		Webhook: cliWebhookConfig{
			URL:    " https://hooks.example/packmon ",
			Secret: " webhook-secret ",
		},
		Output: cliOutputConfig{
			Format: " JSON ",
			File:   " result.json ",
		},
		Log: cliLogConfig{
			Level:  " warn ",
			Format: " JSON ",
		},
		Hook: cliHookConfig{
			Type:   " pre-push ",
			FailOn: " low ",
		},
		DB: cliDBConfig{
			Path:       " ./state ",
			SyncSource: " server ",
		},
		Repos: []cliRepoConfig{{Name: " app "}},
	}

	if err := normalizeTopLevelCLIConfig(cfg, baseDir); err != nil {
		t.Fatalf("normalizeTopLevelCLIConfig() error = %v", err)
	}

	if cfg.Server != "https://packmon.example" || cfg.APIKey != "inline-key" || cfg.APIKeyEnv != "PACKMON_API_KEY" {
		t.Fatalf("top-level connection fields were not normalized: %+v", cfg)
	}
	if cfg.Mode != "remote" || cfg.FailOn != "HIGH" {
		t.Fatalf("top-level scan policy = mode %q fail_on %q, want remote/HIGH", cfg.Mode, cfg.FailOn)
	}
	if got := strings.Join(cfg.Ecosystems, ","); got != "npm,docker" {
		t.Fatalf("ecosystems = %q, want npm,docker", got)
	}
	if cfg.Webhook.URL != "https://hooks.example/packmon" || cfg.Webhook.Secret != "webhook-secret" {
		t.Fatalf("webhook fields were not normalized: %+v", cfg.Webhook)
	}
	if cfg.Output.Format != "json" || cfg.Output.File != "result.json" {
		t.Fatalf("output fields were not normalized: %+v", cfg.Output)
	}
	if cfg.Log.Level != "WARN" || cfg.Log.Format != "json" {
		t.Fatalf("log fields were not normalized: %+v", cfg.Log)
	}
	if cfg.Hook.Type != "pre-push" || cfg.Hook.FailOn != "LOW" {
		t.Fatalf("hook fields were not normalized: %+v", cfg.Hook)
	}
	if cfg.DB.Path != filepath.Join(baseDir, "state") || cfg.DB.SyncSource != "server" {
		t.Fatalf("db fields were not normalized: %+v", cfg.DB)
	}
	if cfg.Repos[0].Name != " app " {
		t.Fatalf("repo scope was normalized by top-level helper: %+v", cfg.Repos[0])
	}
}

func TestNormalizeCLIRepoConfigHandlesRepoScope(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	//nolint:gosec // G101: fixture credential, deliberately fake.
	repo := &cliRepoConfig{
		Path:      " ./service ",
		Server:    " https://repo.example ",
		APIKey:    " repo-key ",
		APIKeyEnv: " PACKMON_REPO_KEY ",
		Mode:      " Local ",
		FailOn:    " medium ",
		Ecosystems: []string{
			" PyPI ",
			"",
		},
		Timeout: 30,
		//nolint:gosec // G101: fixture credential, deliberately fake.
		Webhook: cliWebhookConfig{
			URL:    " https://repo.example/hook ",
			Secret: " repo-secret ",
		},
	}

	if err := normalizeCLIRepoConfig(repo, baseDir, 2); err != nil {
		t.Fatalf("normalizeCLIRepoConfig() error = %v", err)
	}

	if repo.Name != "service" {
		t.Fatalf("repo.name = %q, want service derived from path", repo.Name)
	}
	if repo.Path != filepath.Join(baseDir, "service") {
		t.Fatalf("repo.path = %q, want resolved path", repo.Path)
	}
	if repo.Server != "https://repo.example" || repo.APIKey != "repo-key" || repo.APIKeyEnv != "PACKMON_REPO_KEY" {
		t.Fatalf("repo connection fields were not normalized: %+v", repo)
	}
	if repo.Mode != "local" || repo.FailOn != "MEDIUM" || repo.Timeout != 30 {
		t.Fatalf("repo scan policy was not normalized: %+v", repo)
	}
	if got := strings.Join(repo.Ecosystems, ","); got != "pypi" {
		t.Fatalf("repo ecosystems = %q, want pypi", got)
	}
	if repo.Webhook.URL != "https://repo.example/hook" || repo.Webhook.Secret != "repo-secret" {
		t.Fatalf("repo webhook fields were not normalized: %+v", repo.Webhook)
	}

	missingPath := &cliRepoConfig{Name: "app"}
	if err := normalizeCLIRepoConfig(missingPath, baseDir, 2); err == nil || !strings.Contains(err.Error(), "repos[2].path is required") {
		t.Fatalf("normalizeCLIRepoConfig(missing path) error = %v, want repos[2].path is required", err)
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

func TestOutputConfigUsesScanOutputArtifactRegistry(t *testing.T) {
	t.Parallel()

	if got := scanOutputConfigFormatList(); got != "table|json|sarif|junit|html" {
		t.Fatalf("scanOutputConfigFormatList() = %q", got)
	}
	for _, format := range scanOutputArtifactFormats() {
		if err := validateOutputConfig(cliOutputConfig{Format: format, File: "scan." + format}); err != nil {
			t.Fatalf("validateOutputConfig(%s file) error = %v", format, err)
		}
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func oversizedAutoProjectConfigYAML() []byte {
	return []byte("fail_on: LOW\n" + strings.Repeat("# padding\n", 8*1024))
}
