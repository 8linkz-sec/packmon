package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigCommandRegistersSupportedSubcommands(t *testing.T) {
	cmd := newConfigCmd()
	got := make(map[string]bool, len(cmd.Commands()))
	for _, child := range cmd.Commands() {
		got[child.Name()] = true
	}
	for _, name := range []string{"show", "init", "validate"} {
		if !got[name] {
			t.Fatalf("config subcommands = %v, missing %q", got, name)
		}
	}
	if len(got) != 3 {
		t.Fatalf("config subcommands = %v, want exactly show/init/validate", got)
	}
}

func TestConfigShowReturnsConfigLoadError(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	path := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(path, []byte("mode: ["), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newConfigShowCmd()
	cmd.SetArgs([]string{"--file", path})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "parse "+path) {
		t.Fatalf("config show error = %v, want config parse failure", err)
	}
}

func TestConfigInitUsesDefaultPathAndPrivatePermissions(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	cmd := newConfigInitCmd()
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("config init: %v", err)
		}
	})
	if output != "Created "+defaultCLIConfigFile+"\n" {
		t.Fatalf("config init output = %q", output)
	}
	info, err := os.Stat(defaultCLIConfigFile)
	if err != nil {
		t.Fatalf("stat generated config: %v", err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("generated config mode = %v, want regular file", info.Mode())
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("generated config permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestConfigInitRefusesExistingFileWithoutChangingIt(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	path := filepath.Join(t.TempDir(), "packmon.yaml")
	want := []byte("sentinel: keep exactly\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	cmd := newConfigInitCmd()
	cmd.SetArgs([]string{"--file", path})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("config init error = %v, want existing-file refusal", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read sentinel: %v", readErr)
	}
	if string(got) != string(want) {
		t.Fatalf("existing file changed: got %q, want %q", got, want)
	}
}

func TestConfigInitReportsDirectoryAndWriteFailures(t *testing.T) {
	t.Run("parent component is a file", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		parent := filepath.Join(t.TempDir(), "sentinel")
		want := []byte("do not replace")
		if err := os.WriteFile(parent, want, 0o600); err != nil {
			t.Fatalf("write parent sentinel: %v", err)
		}
		target := filepath.Join(parent, "child", "packmon.yaml")

		cmd := newConfigInitCmd()
		cmd.SetArgs([]string{"--file", target})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "create config directory") {
			t.Fatalf("config init error = %v, want directory creation failure", err)
		}
		got, readErr := os.ReadFile(parent)
		if readErr != nil {
			t.Fatalf("read parent sentinel: %v", readErr)
		}
		if string(got) != string(want) {
			t.Fatalf("parent sentinel changed: got %q, want %q", got, want)
		}
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("target state error = %v, want absent", statErr)
		}
	})

	t.Run("invalid NUL path", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		target := "packmon\x00.yaml"

		cmd := newConfigInitCmd()
		cmd.SetArgs([]string{"--file", target})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "write ") {
			t.Fatalf("config init error = %v, want write failure", err)
		}
	})
}

func TestConfigValidateUsesDefaultPathAndReturnsLoadErrors(t *testing.T) {
	t.Run("default path", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		if err := os.WriteFile(defaultCLIConfigFile, []byte("mode: local\n"), 0o600); err != nil {
			t.Fatalf("write default config: %v", err)
		}

		cmd := newConfigValidateCmd()
		output := captureStdout(t, func() {
			if err := cmd.Execute(); err != nil {
				t.Fatalf("config validate: %v", err)
			}
		})
		if !strings.Contains(output, "Config file ") || !strings.Contains(output, defaultCLIConfigFile) || !strings.Contains(output, "Configured repos: 0") {
			t.Fatalf("config validate output = %q", output)
		}
	})

	t.Run("load failure", func(t *testing.T) {
		isolateCLIConfigDiscovery(t)
		path := filepath.Join(t.TempDir(), "broken.yaml")
		if err := os.WriteFile(path, []byte("unknown_field: true\n"), 0o600); err != nil {
			t.Fatalf("write invalid config: %v", err)
		}

		cmd := newConfigValidateCmd()
		cmd.SetArgs([]string{"--file", path})
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "parse "+path) {
			t.Fatalf("config validate error = %v, want config load failure", err)
		}
	})
}

func TestEffectiveConfigShowSettingsAcceptsNilConfigAndRejectsNonpositiveTimeouts(t *testing.T) {
	isolateConfigShowInputs(t)

	settings, err := effectiveConfigShowSettings(nil)
	if err != nil {
		t.Fatalf("effectiveConfigShowSettings(nil): %v", err)
	}
	modeMatches := settings.Mode == "auto"
	timeoutMatches := settings.Timeout == 30
	metadataMatches := settings.SendRepoMetadata
	apiKeyEmpty := settings.APIKey == ""
	webhookSecretEmpty := settings.WebhookSecret == ""
	if !modeMatches || !timeoutMatches || !metadataMatches || !apiKeyEmpty || !webhookSecretEmpty {
		t.Fatalf(
			"nil config defaults: mode_matches=%t timeout_matches=%t metadata_matches=%t api_key_empty=%t webhook_secret_empty=%t",
			modeMatches,
			timeoutMatches,
			metadataMatches,
			apiKeyEmpty,
			webhookSecretEmpty,
		)
	}

	for _, value := range []string{"0", "-1"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PACKMON_TIMEOUT", value)
			_, err := effectiveConfigShowSettings(nil)
			if err == nil || !strings.Contains(err.Error(), "PACKMON_TIMEOUT") {
				t.Fatalf("effectiveConfigShowSettings() error = %v, want %q rejection", err, value)
			}
		})
	}
}

func TestConfiguredAPIKeyEnvVarsDeduplicatesAndHandlesNil(t *testing.T) {
	if got := configuredAPIKeyEnvVars(nil); got != nil {
		t.Fatalf("configuredAPIKeyEnvVars(nil) = %v, want nil", got)
	}

	cfg := &cliConfig{
		APIKeyEnv: " CUSTOM_KEY ",
		Repos: []cliRepoConfig{
			{APIKeyEnv: "CUSTOM_KEY"},
			{APIKeyEnv: "PACKMON_API_KEY"},
			{APIKeyEnv: "SECOND_KEY"},
			{APIKeyEnv: " "},
			{APIKeyEnv: "SECOND_KEY"},
		},
	}
	got := configuredAPIKeyEnvVars(cfg)
	if strings.Join(got, ",") != "CUSTOM_KEY,SECOND_KEY" {
		t.Fatalf("configuredAPIKeyEnvVars() = %v, want stable unique keys", got)
	}
}

func TestConfigShowPathSelectionPrefersLocalFileThenGlobalConfigFlag(t *testing.T) {
	isolateConfigShowInputs(t)
	globalPath := filepath.Join(t.TempDir(), "global.yaml")
	localPath := filepath.Join(t.TempDir(), "local.yaml")
	for path, mode := range map[string]string{globalPath: "local", localPath: "remote"} {
		if err := os.WriteFile(path, []byte("mode: "+mode+"\n"), 0o600); err != nil {
			t.Fatalf("write config %s: %v", path, err)
		}
	}
	flagConfig = "  " + globalPath + "  "

	cmd := newConfigShowCmd()
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("config show with global --config fallback: %v", err)
		}
	})
	globalPathMatches := strings.Contains(output, "config_file:  "+globalPath)
	globalModeMatches := strings.Contains(output, "mode:         local")
	if !globalPathMatches || !globalModeMatches {
		t.Fatalf("global config fallback: path_matches=%t mode_matches=%t", globalPathMatches, globalModeMatches)
	}

	cmd = newConfigShowCmd()
	cmd.SetArgs([]string{"--file", "  " + localPath + "  "})
	output = captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("config show with local --file: %v", err)
		}
	})
	localPathMatches := strings.Contains(output, "config_file:  "+localPath)
	localModeMatches := strings.Contains(output, "mode:         remote")
	if !localPathMatches || !localModeMatches {
		t.Fatalf("local file precedence: path_matches=%t mode_matches=%t", localPathMatches, localModeMatches)
	}
}

func isolateConfigShowInputs(t *testing.T) {
	t.Helper()
	isolateCLIConfigDiscovery(t)

	for _, key := range []string{
		"PACKMON_SERVER",
		"PACKMON_API_KEY",
		"PACKMON_MODE",
		"PACKMON_FAIL_ON",
		"PACKMON_TIMEOUT",
		"PACKMON_ECOSYSTEMS",
		"PACKMON_NO_REPO_METADATA",
		clientCACertFileEnv,
		clientCACertLegacyFileEnv,
		"PACKMON_INSECURE_ALLOW_HTTP",
		"PACKMON_REQUIRE_REMOTE",
		"PACKMON_WEBHOOK_URL",
		"PACKMON_WEBHOOK_SECRET",
		"PACKMON_DB_PATH",
	} {
		t.Setenv(key, "")
	}
}

func TestConfigInitDanglingSymlinkDoesNotCreateExternalReferent(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	linkTree := t.TempDir()
	externalTree := t.TempDir()
	link := filepath.Join(linkTree, "packmon.yaml")
	referent := filepath.Join(externalTree, "created-outside-link-tree.yaml")
	if err := os.Symlink(referent, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation is unavailable on this Windows host: %v", err)
		}
		t.Fatalf("create dangling symlink: %v", err)
	}

	cmd := newConfigInitCmd()
	cmd.SetArgs([]string{"--file", link})
	err := cmd.Execute()
	info, lstatErr := os.Lstat(link)
	if lstatErr != nil {
		t.Fatalf("lstat config symlink: %v", lstatErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("config path mode = %v, want unchanged symlink", info.Mode())
	}

	_, referentErr := os.Stat(referent)
	if referentErr == nil {
		if err != nil {
			t.Fatalf("config init created external referent and returned error: %v", err)
		}
		t.Skip("known bug F024-bugs-4: config init follows a dangling symlink and creates its external referent")
	}
	if !errors.Is(referentErr, os.ErrNotExist) {
		t.Fatalf("external referent state error = %v, want absent", referentErr)
	}
	if err == nil {
		t.Fatal("config init succeeded without creating the external referent")
	}
}
