package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorstExitCodeUsesSemanticSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    int
		b    int
		want int
	}{
		{name: "blocking beats under threshold despite numeric order", a: ExitUnderThreshold, b: ExitBlocking, want: ExitBlocking},
		{name: "parser beats operational", a: ExitOperational, b: ExitParser, want: ExitParser},
		{name: "internal beats parser", a: ExitParser, b: ExitInternal, want: ExitInternal},
		{name: "ok yields to under threshold", a: ExitOK, b: ExitUnderThreshold, want: ExitUnderThreshold},
		{name: "keeps worse first argument", a: ExitBlocking, b: ExitUnderThreshold, want: ExitBlocking},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := worstExitCode(tt.a, tt.b); got != tt.want {
				t.Fatalf("worstExitCode(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSecretAndTimeoutHelpers(t *testing.T) {
	t.Parallel()

	if got := maskSecret(""); got != "(not set)" {
		t.Fatalf("maskSecret(empty) = %q", got)
	}
	if got := maskSecret("abcd"); got != "****" {
		t.Fatalf("maskSecret(short) = %q", got)
	}
	if got := maskSecret("abcdef"); got != "ab**ef" {
		t.Fatalf("maskSecret(long) = %q", got)
	}
	timeout, err := parseTimeoutSeconds("45s")
	if err != nil || timeout != 45 {
		t.Fatalf("parseTimeoutSeconds(45s) = %d, %v", timeout, err)
	}
	if _, err := parseTimeoutSeconds("not-a-duration"); err == nil {
		t.Fatal("parseTimeoutSeconds(invalid) error = nil")
	}
}

func TestDefaultDBPathHonorsEnvDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dir)

	if got := defaultDBPath(); got != filepath.Join(dir, "packmon.db") {
		t.Fatalf("defaultDBPath() = %q, want env directory packmon.db", got)
	}
}

func TestDefaultDBPathUsesHomeWhenEnvIsEmpty(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if got := defaultDBPath(); got != filepath.Join(home, ".packmon", "db", "packmon.db") {
		t.Fatalf("defaultDBPath() = %q, want home-local path", got)
	}
}

func TestConfigInitTemplateUsesSecretFreeDefaults(t *testing.T) {
	target := filepath.Join(t.TempDir(), "packmon.yaml")
	cmd := newConfigInitCmd()
	cmd.SetArgs([]string{"--file", target})

	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("config init failed: %v", err)
		}
	})
	if !strings.Contains(output, "Created "+target) {
		t.Fatalf("config init output = %q", output)
	}

	data, err := os.ReadFile(target) // #nosec G304 -- test reads a generated temp-file path.
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		`api_key_env: "PACKMON_API_KEY"`,
		"require_remote: true",
		"sync_source: server",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated config missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "api_key:") {
		t.Fatalf("generated config contains plaintext api_key field:\n%s", text)
	}
}

func TestConfigInitTemplateValidatesRoundTrip(t *testing.T) {
	target := filepath.Join(t.TempDir(), "packmon.yaml")
	initCmd := newConfigInitCmd()
	initCmd.SetArgs([]string{"--file", target})
	captureStdout(t, func() {
		if err := initCmd.Execute(); err != nil {
			t.Fatalf("config init failed: %v", err)
		}
	})

	validateCmd := newConfigValidateCmd()
	validateCmd.SetArgs([]string{"--file", target})
	output := captureStdout(t, func() {
		if err := validateCmd.Execute(); err != nil {
			t.Fatalf("config validate generated template: %v", err)
		}
	})
	if !strings.Contains(output, "is valid") {
		t.Fatalf("validate output = %q", output)
	}
}

func TestConfigValidateReportsConfiguredRepos(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "packmon.yaml")
	repoDir := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(configPath, []byte(`
server: "https://packmon.internal"
api_key_env: "PACKMON_API_KEY"
repos:
  - name: app
    path: "./repo"
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newConfigValidateCmd()
	cmd.SetArgs([]string{"--file", configPath})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("config validate failed: %v", err)
		}
	})

	if !strings.Contains(output, "is valid") || !strings.Contains(output, "Configured repos: 1") {
		t.Fatalf("config validate output = %q", output)
	}
}

func TestConfigShowMasksConfigSecretAndPrintsDefaults(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	configPath := filepath.Join(t.TempDir(), "packmon.yaml")
	if err := os.WriteFile(configPath, []byte(`
server: "https://packmon.internal"
api_key: "supersecret"
repos:
  - name: app
    path: "."
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newConfigShowCmd()
	cmd.SetArgs([]string{"--file", configPath})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("config show: %v", err)
		}
	})

	if !strings.Contains(output, "server:       https://packmon.internal") {
		t.Fatalf("config show output missing server:\n%s", output)
	}
	if !strings.Contains(output, "api_key:      su*******et") {
		t.Fatalf("config show output did not mask api key:\n%s", output)
	}
	if strings.Contains(output, "supersecret") {
		t.Fatalf("config show leaked plaintext api key:\n%s", output)
	}
	if !strings.Contains(output, "repos:        1") || !strings.Contains(output, "log_level:    INFO") {
		t.Fatalf("config show output missing repo/default values:\n%s", output)
	}
}

func TestConfigShowMasksSecretEnvironmentValues(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	configPath := filepath.Join(t.TempDir(), "packmon.yaml")
	if err := os.WriteFile(configPath, []byte(`
server: "https://packmon.internal"
api_key_env: "PACKMON_CUSTOM_API_KEY"
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("PACKMON_API_KEY", "env-secret-key")
	t.Setenv("PACKMON_CUSTOM_API_KEY", "custom-secret-key")
	t.Setenv("PACKMON_WEBHOOK_SECRET", "webhook-secret-key")

	cmd := newConfigShowCmd()
	cmd.SetArgs([]string{"--file", configPath})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("config show: %v", err)
		}
	})

	for _, leaked := range []string{"env-secret-key", "custom-secret-key", "webhook-secret-key"} {
		if strings.Contains(output, leaked) {
			t.Fatalf("config show leaked %q:\n%s", leaked, output)
		}
	}
	for _, want := range []string{"PACKMON_API_KEY:", "PACKMON_CUSTOM_API_KEY:", "PACKMON_WEBHOOK_SECRET:"} {
		if !strings.Contains(output, want) {
			t.Fatalf("config show output missing %q:\n%s", want, output)
		}
	}
	if !strings.Contains(output, "en**********ey") || !strings.Contains(output, "cu*************ey") || !strings.Contains(output, "we**************ey") {
		t.Fatalf("config show did not mask expected secret env values:\n%s", output)
	}
}

func TestConfigCommandHelpers(t *testing.T) {
	if got := valueOrDefault("", "fallback"); got != "fallback" {
		t.Fatalf("valueOrDefault(empty) = %q", got)
	}
	if got := valueOrDefault("value", "fallback"); got != "value" {
		t.Fatalf("valueOrDefault(value) = %q", got)
	}
	if got := defaultConfigTimeout(0); got != 30 {
		t.Fatalf("defaultConfigTimeout(0) = %d", got)
	}
	if got := defaultConfigTimeout(12); got != 12 {
		t.Fatalf("defaultConfigTimeout(12) = %d", got)
	}

	t.Setenv("PACKMON_PRINT_ENV_TEST", "visible")
	output := captureStdout(t, func() {
		printEnvVar("PACKMON_PRINT_ENV_TEST")
		printEnvVar("PACKMON_PRINT_ENV_MISSING")
	})
	if !strings.Contains(output, "PACKMON_PRINT_ENV_TEST:") || !strings.Contains(output, "visible") {
		t.Fatalf("printEnvVar set output = %q", output)
	}
	if !strings.Contains(output, "PACKMON_PRINT_ENV_MISSING:") || !strings.Contains(output, "(not set)") {
		t.Fatalf("printEnvVar missing output = %q", output)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = write
	defer func() { os.Stdout = original }()

	fn()

	if err := write.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	out, err := io.ReadAll(read)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	return string(out)
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	original := os.Stderr
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = write
	defer func() { os.Stderr = original }()

	fn()

	if err := write.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	out, err := io.ReadAll(read)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	return string(out)
}
