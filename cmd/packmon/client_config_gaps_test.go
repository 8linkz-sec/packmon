package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestOverlayCLIConfigCopiesConfiguredTrustedSections(t *testing.T) {
	enabled := true
	dst := cliConfig{}
	src := cliConfig{
		Server:            "https://packmon.example",
		APIKey:            "api-key",
		APIKeyEnv:         "PACKMON_CUSTOM_KEY",
		Mode:              "remote",
		FailOn:            "HIGH",
		Timeout:           45,
		Ecosystems:        []string{"npm"},
		IncludeDev:        &enabled,
		CACert:            "ca.pem",
		InsecureAllowHTTP: &enabled,
		RequireRemote:     &enabled,
		SendRepoMetadata:  &enabled,
		Webhook:           cliWebhookConfig{URL: "https://hooks.example", Secret: "hook-secret"},
		Output:            cliOutputConfig{Format: "json", File: "result.json"},
		Log:               cliLogConfig{Level: "DEBUG", Format: "json", File: "packmon.log"},
		Hook:              cliHookConfig{Type: "pre-commit", FailOn: "MEDIUM"},
		DB:                cliDBConfig{Path: "state", SyncSource: "server"},
		Registries: cliRegistryConfig{
			NPMRegistryBaseURL:     "https://npm.example",
			PyPIAPIBaseURL:         "https://pypi.example",
			DockerRegistryMirrors:  map[string]string{"docker.io": "https://docker.example"},
			SwiftPMGitAllowedHosts: []string{"git.example"},
			ChocolateyFeedURLs:     []string{"https://choco.example"},
		},
	}

	overlayCLIConfig(&dst, src)
	if dst.Server != src.Server || dst.APIKey != src.APIKey || dst.APIKeyEnv != src.APIKeyEnv ||
		dst.CACert != src.CACert || dst.InsecureAllowHTTP != src.InsecureAllowHTTP || dst.RequireRemote != src.RequireRemote {
		t.Fatalf("connection overlay = %+v, want configured source fields", dst)
	}
	if dst.Mode != src.Mode || dst.FailOn != src.FailOn || dst.Timeout != src.Timeout ||
		!reflect.DeepEqual(dst.Ecosystems, src.Ecosystems) || dst.IncludeDev != src.IncludeDev || dst.SendRepoMetadata != src.SendRepoMetadata {
		t.Fatalf("policy overlay = %+v, want configured source fields", dst)
	}
	if dst.Webhook != src.Webhook || dst.Output != src.Output || dst.Log != src.Log || dst.Hook != src.Hook || dst.DB != src.DB {
		t.Fatalf("section overlay = %+v, want configured source sections", dst)
	}
	if !reflect.DeepEqual(dst.Registries.DockerRegistryMirrors, src.Registries.DockerRegistryMirrors) ||
		!reflect.DeepEqual(dst.Registries.SwiftPMGitAllowedHosts, src.Registries.SwiftPMGitAllowedHosts) ||
		!reflect.DeepEqual(dst.Registries.ChocolateyFeedURLs, src.Registries.ChocolateyFeedURLs) ||
		dst.Registries.NPMRegistryBaseURL != src.Registries.NPMRegistryBaseURL ||
		dst.Registries.PyPIAPIBaseURL != src.Registries.PyPIAPIBaseURL {
		t.Fatalf("registry overlay = %+v, want configured source registry fields", dst.Registries)
	}
}

func TestLoadCLIConfigReportsLayerReadFailures(t *testing.T) {
	t.Run("user global config is a directory", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)

		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("resolve home: %v", err)
		}
		path := filepath.Join(home, ".packmon", "config", "packmon.yaml")
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatalf("create directory at user config path: %v", err)
		}

		_, _, err = loadCLIConfig("")
		if err == nil || !strings.Contains(err.Error(), "read "+path) {
			t.Fatalf("loadCLIConfig() error = %v, want user config read failure", err)
		}
	})

	t.Run("project config is a directory", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)

		if err := os.Mkdir(defaultCLIConfigFile, 0o750); err != nil {
			t.Fatalf("create directory at project config path: %v", err)
		}

		_, _, err := loadCLIConfig("")
		if err == nil || !strings.Contains(err.Error(), "read "+defaultCLIConfigFile) {
			t.Fatalf("loadCLIConfig() error = %v, want project config read failure", err)
		}
	})

	t.Run("explicit config is a directory", func(t *testing.T) {
		path := t.TempDir()

		_, _, err := loadExplicitCLIConfig(path)
		if err == nil || !strings.Contains(err.Error(), "read "+path) {
			t.Fatalf("loadExplicitCLIConfig() error = %v, want explicit config read failure", err)
		}
	})
}

func TestLoadCLIConfigPropagatesLayerValidationFailures(t *testing.T) {
	t.Run("user global", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)

		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("resolve home: %v", err)
		}
		path := filepath.Join(home, ".packmon", "config", "packmon.yaml")
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("create user config directory: %v", err)
		}
		if err := os.WriteFile(path, []byte("output:\n  format: unsupported\n"), 0o600); err != nil {
			t.Fatalf("write user config: %v", err)
		}

		_, _, err = loadCLIConfig("")
		if err == nil || !strings.Contains(err.Error(), "validate "+path) || !strings.Contains(err.Error(), "invalid output.format") {
			t.Fatalf("loadCLIConfig() error = %v, want user validation context", err)
		}
	})

	t.Run("project", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		if err := os.WriteFile(defaultCLIConfigFile, []byte("log:\n  file: forbidden.log\n"), 0o600); err != nil {
			t.Fatalf("write project config: %v", err)
		}

		_, _, err := loadCLIConfig("")
		if err == nil || !strings.Contains(err.Error(), "validate ") || !strings.Contains(err.Error(), "log.file is not supported") {
			t.Fatalf("loadCLIConfig() error = %v, want project validation context", err)
		}
	})
}

func TestLoadExplicitCLIConfigPropagatesValidationFailures(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "registry URL", yaml: "registries:\n  npm_registry_base_url: ftp://registry.example\n", wantErr: "registries.npm_registry_base_url"},
		{name: "output file without format", yaml: "output:\n  file: result.json\n", wantErr: "output.format is required"},
		{name: "table output file", yaml: "output:\n  format: table\n  file: result.txt\n", wantErr: "does not support"},
		{name: "log level", yaml: "log:\n  level: verbose\n", wantErr: "invalid log.level"},
		{name: "log format", yaml: "log:\n  format: xml\n", wantErr: "invalid log.format"},
		{name: "log file", yaml: "log:\n  file: packmon.log\n", wantErr: "log.file is not supported"},
		{name: "hook type", yaml: "hook:\n  type: post-commit\n", wantErr: "invalid hook.type"},
		{name: "hook severity", yaml: "hook:\n  fail_on: urgent\n", wantErr: "hook.fail_on"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "packmon.yaml")
			if err := os.WriteFile(path, []byte(test.yaml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, _, err := loadExplicitCLIConfig(path)
			if err == nil || !strings.Contains(err.Error(), "validate "+path) || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("loadExplicitCLIConfig() error = %v, want validation containing %q", err, test.wantErr)
			}
		})
	}
}

func TestLoadExplicitCLIConfigRejectsRepoNameThatCannotBeDerivedFromRoot(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	path := filepath.Join(t.TempDir(), "packmon.yaml")
	yaml := "repos:\n  - path: " + strconv.Quote(root) + "\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, _, err := loadExplicitCLIConfig(path)
	if err == nil || !strings.Contains(err.Error(), "name could not be derived from path") {
		t.Fatalf("loadExplicitCLIConfig() error = %v, want root repo name rejection", err)
	}
}

func TestLoadExplicitCLIConfigRejectsTrailingYAMLDocuments(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		forbidden []string
	}{
		{
			name:      "valid second document",
			data:      "mode: local\n---\nmode: remote\napi_key: second-doc-secret-marker\n",
			forbidden: []string{"api_key", "second-doc-secret-marker", "mode: remote"},
		},
		{
			name:      "empty second document",
			data:      "mode: local\n---\n",
			forbidden: []string{"line ", "yaml: line"},
		},
		{
			name: "malformed second document",
			data: "mode: local\n---\n" +
				"api_key: second-doc-secret-marker\n" +
				"fail_on: [second-doc-policy-marker\n",
			forbidden: []string{
				"api_key", "fail_on", "second-doc-secret-marker", "second-doc-policy-marker",
				"did not find expected", "line ", "yaml: line",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "packmon.yaml")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg, source, err := loadExplicitCLIConfig(path)
			if !errors.Is(err, errCLIConfigAdditionalYAMLDocument) {
				t.Fatalf("loadExplicitCLIConfig() error = %v, want additional-document sentinel", err)
			}
			wantError := "parse " + path + ": " + errCLIConfigAdditionalYAMLDocument.Error()
			if err.Error() != wantError {
				t.Fatalf("loadExplicitCLIConfig() error = %q, want %q", err, wantError)
			}
			if cfg != nil || source != "" {
				t.Fatalf("rejected config returned cfg/source = %+v/%q, want nil/empty", cfg, source)
			}
			for _, forbidden := range test.forbidden {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("loadExplicitCLIConfig() error contains trailing YAML detail %q: %q", forbidden, err)
				}
			}
		})
	}
}

func TestLoadExplicitCLIConfigAcceptsTrailingWhitespaceAndComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packmon.yaml")
	data := "mode: local\r\n\r\n  \r\n# trailing comment\r\n  # indented trailing comment\r\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, source, err := loadExplicitCLIConfig(path)
	if err != nil {
		t.Fatalf("loadExplicitCLIConfig() error = %v", err)
	}
	if cfg == nil || cfg.Mode != "local" {
		t.Fatalf("loadExplicitCLIConfig() config = %+v, want local mode", cfg)
	}
	wantSource, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve config path: %v", err)
	}
	if source != wantSource {
		t.Fatalf("loadExplicitCLIConfig() source = %q, want %q", source, wantSource)
	}
}

func TestLoadCLIConfigPreservesTrustedRepoMetadataOptOutOnSameNameAndPath(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolve home: %v", err)
	}
	userPath := filepath.Join(home, ".packmon", "config", "packmon.yaml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o750); err != nil {
		t.Fatalf("create user config directory: %v", err)
	}
	repoPath := filepath.Join(t.TempDir(), "app")
	trusted := "repos:\n  - name: app\n    path: " + strconv.Quote(repoPath) + "\n    send_repo_metadata: false\n"
	if err := os.WriteFile(userPath, []byte(trusted), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}
	project := "repos:\n  - name: app\n    path: " + strconv.Quote(repoPath) + "\n    send_repo_metadata: true\n    fail_on: HIGH\n"
	if err := os.WriteFile(defaultCLIConfigFile, []byte(project), 0o600); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	cfg, _, err := loadCLIConfig("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg == nil || len(cfg.Repos) != 1 {
		t.Fatalf("repos = %+v, want one merged repo", cfg)
	}
	if cfg.Repos[0].SendRepoMetadata == nil || *cfg.Repos[0].SendRepoMetadata {
		t.Fatalf("trusted metadata opt-out was not preserved: %+v", cfg.Repos[0])
	}
	if cfg.Repos[0].FailOn != "HIGH" {
		t.Fatalf("project scan policy was not preserved: %+v", cfg.Repos[0])
	}
}
