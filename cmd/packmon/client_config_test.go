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
