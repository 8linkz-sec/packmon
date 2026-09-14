package ci

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestN8NOnDemandScanShellHarnessGuards(t *testing.T) {
	shell := n8nPOSIXShell(t)
	for _, tc := range []struct {
		name  string
		env   map[string]string
		unset string
	}{
		{name: "missing API key", unset: "PACKMON_API_KEY"},
		{name: "empty API key", env: map[string]string{"PACKMON_API_KEY": ""}},
		{name: "missing server", unset: "PACKMON_SERVER"},
		{name: "empty server", env: map[string]string{"PACKMON_SERVER": ""}},
		{name: "missing path", unset: "PACKMON_SCAN_PATH"},
		{name: "empty path", env: map[string]string{"PACKMON_SCAN_PATH": ""}},
		{name: "absolute path", env: map[string]string{"PACKMON_SCAN_PATH": "/tmp/project"}},
		{name: "leading dash path", env: map[string]string{"PACKMON_SCAN_PATH": "-project"}},
		{name: "parent traversal path", env: map[string]string{"PACKMON_SCAN_PATH": "project/../other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recordPath, binDir := n8nPackmonStub(t)
			env := n8nScanEnvironment(binDir, recordPath, map[string]string{
				"PACKMON_API_KEY": "test-api-key", "PACKMON_SERVER": "https://packmon.example.test", "PACKMON_SCAN_PATH": "project/package-lock.json",
			})
			for key, value := range tc.env {
				env = n8nSetEnvironment(env, key, value)
			}
			if tc.unset != "" {
				env = n8nUnsetEnvironment(env, tc.unset)
			}
			exitCode, output := n8nRunOnDemandScan(t, shell, env)
			if exitCode == 0 {
				t.Fatalf("guard exit code = 0, want failure; output=%q", output)
			}
			if _, err := os.Stat(recordPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("guard invoked packmon stub: stat record: %v", err)
			}
		})
	}
}

func TestN8NOnDemandScanShellHarnessPassesSafeArgumentAndEnvironment(t *testing.T) {
	shell := n8nPOSIXShell(t)
	recordPath, binDir := n8nPackmonStub(t)
	apiKey := "test-api-key-not-in-argv"
	path := "fixtures/space dir/$(touch should-not-exist); * ? [brackets]"
	env := n8nScanEnvironment(binDir, recordPath, map[string]string{
		"PACKMON_API_KEY": apiKey, "PACKMON_SERVER": "https://packmon.example.test/base", "PACKMON_SCAN_PATH": path,
	})
	exitCode, output := n8nRunOnDemandScan(t, shell, env)
	if exitCode != 0 {
		t.Fatalf("helper exit code = %d, want 0; output=%q", exitCode, output)
	}
	record := n8nReadPackmonRecord(t, recordPath)
	if got := record["argc"]; got != "7" {
		t.Fatalf("packmon argc = %q, want 7; record=%v", got, record)
	}
	for index, want := range []string{"scan", path, "--mode", "remote", "--require-remote", "--server", "https://packmon.example.test/base"} {
		if got := record[fmt.Sprintf("argv[%d]", index)]; got != want {
			t.Fatalf("packmon argv[%d] = %q, want %q; record=%v", index, got, want, record)
		}
	}
	if got := record["api_key"]; got != apiKey {
		t.Fatalf("packmon PACKMON_API_KEY = %q, want configured value", got)
	}
	for key, value := range record {
		if key != "api_key" && value == apiKey {
			t.Fatalf("API key leaked into packmon argv: record=%v", record)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(recordPath), "should-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shell metacharacters executed while invoking packmon: stat sentinel: %v", err)
	}
}

func TestN8NOnDemandScanShellHarnessPropagatesPackmonExitStatus(t *testing.T) {
	shell := n8nPOSIXShell(t)
	for _, wantExitCode := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(wantExitCode), func(t *testing.T) {
			recordPath, binDir := n8nPackmonStub(t)
			env := n8nScanEnvironment(binDir, recordPath, map[string]string{
				"PACKMON_API_KEY": "test-api-key", "PACKMON_SERVER": "https://packmon.example.test", "PACKMON_SCAN_PATH": "project/package-lock.json", "PACKMON_STUB_EXIT": strconv.Itoa(wantExitCode),
			})
			gotExitCode, output := n8nRunOnDemandScan(t, shell, env)
			if gotExitCode != wantExitCode {
				t.Fatalf("helper exit code = %d, want %d; output=%q", gotExitCode, wantExitCode, output)
			}
			_ = n8nReadPackmonRecord(t, recordPath)
		})
	}
}

func TestN8NOnDemandScanShellHarnessFailsWhenPackmonIsUnavailable(t *testing.T) {
	shell := n8nPOSIXShell(t)
	binDir := t.TempDir()
	recordPath := filepath.Join(t.TempDir(), "packmon-record")
	env := n8nScanEnvironment(binDir, recordPath, map[string]string{
		"PACKMON_API_KEY": "test-api-key", "PACKMON_SERVER": "https://packmon.example.test", "PACKMON_SCAN_PATH": "project/package-lock.json",
	})
	exitCode, output := n8nRunOnDemandScan(t, shell, env)
	if exitCode == 0 {
		t.Fatalf("helper exit code = 0 with unavailable packmon; output=%q", output)
	}
	if _, err := os.Stat(recordPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected stub record with unavailable packmon: %v", err)
	}
}

func n8nPOSIXShell(t *testing.T) string {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell is required for the on-demand scan helper harness")
	}
	return shell
}

func n8nPackmonStub(t *testing.T) (recordPath, binDir string) {
	t.Helper()
	binDir = t.TempDir()
	recordPath = filepath.Join(t.TempDir(), "packmon-record")
	stub := "#!/bin/sh\n{\n  printf 'argc=%s\\n' \"$#\"\n  i=0\n  for arg do\n    printf 'argv[%s]=%s\\n' \"$i\" \"$arg\"\n    i=$((i + 1))\n  done\n  printf 'api_key=%s\\n' \"${PACKMON_API_KEY-}\"\n} > \"$PACKMON_TEST_RECORD\"\nexit \"${PACKMON_STUB_EXIT:-0}\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "packmon"), []byte(stub), 0o700); err != nil {
		t.Fatalf("write packmon stub: %v", err)
	}
	return recordPath, binDir
}

func n8nScanEnvironment(binDir, recordPath string, values map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(values)+2)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "PATH" || strings.HasPrefix(key, "PACKMON_") {
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "PATH="+binDir, "PACKMON_TEST_RECORD="+recordPath)
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func n8nSetEnvironment(env []string, key, value string) []string {
	prefix := key + "="
	for index, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[index] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func n8nUnsetEnvironment(env []string, key string) []string {
	prefix := key + "="
	filtered := env[:0]
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func n8nRunOnDemandScan(t *testing.T, shell string, env []string) (int, string) {
	t.Helper()
	helperPath, err := filepath.Abs(filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.sh"))
	if err != nil {
		t.Fatalf("resolve on-demand scan helper path: %v", err)
	}
	command := exec.Command(shell, helperPath)
	command.Dir = filepath.Dir(recordPathFromEnvironment(env))
	command.Env = env
	output, err := command.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(output)
	}
	t.Fatalf("run on-demand scan helper: %v", err)
	return 0, ""
}

func recordPathFromEnvironment(env []string) string {
	const prefix = "PACKMON_TEST_RECORD="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix)
		}
	}
	return ""
}

func n8nReadPackmonRecord(t *testing.T, recordPath string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(recordPath) //nolint:gosec // test-controlled path under t.TempDir.
	if err != nil {
		t.Fatalf("read packmon stub record: %v", err)
	}
	record := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed packmon stub record line %q", line)
		}
		record[key] = value
	}
	return record
}
