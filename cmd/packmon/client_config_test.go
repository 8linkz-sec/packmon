package main

import (
	"os"
	"path/filepath"
	"testing"
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
