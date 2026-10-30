package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const hookExitHelperEnv = "PACKMON_F029_HOOK_EXIT_HELPER"

func TestGitResolvedHooksDirValidatesGitOutput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repository")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("create repository fixture: %v", err)
	}

	cases := []struct {
		name string
		out  string
		err  error
		want string
	}{
		{name: "command error", err: errors.New("git unavailable")},
		{name: "single line", out: root + "\n"},
		{name: "mismatched top level", out: filepath.Join(root, "other") + "\nhooks\n"},
		{name: "empty hooks path", out: root + "\n \nignored trailing line\n"},
		{name: "absolute hooks path", out: root + "\n" + filepath.Join(root, "external-hooks") + "\n", want: filepath.Join(root, "external-hooks")},
		{name: "relative hooks path", out: root + "\n.git/custom-hooks\n", want: filepath.Join(root, ".git", "custom-hooks")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setGitCommandOutputForHookTest(t, func(ctx context.Context, args ...string) ([]byte, error) {
				if ctx.Err() != nil {
					t.Fatalf("git command context already done: %v", ctx.Err())
				}
				wantArgs := []string{"-C", root, "rev-parse", "--show-toplevel", "--git-path", "hooks"}
				if strings.Join(args, "\x00") != strings.Join(wantArgs, "\x00") {
					t.Fatalf("git command args = %#v, want %#v", args, wantArgs)
				}
				return []byte(tc.out), tc.err
			})

			if got := gitResolvedHooksDir(root); got != tc.want {
				t.Fatalf("gitResolvedHooksDir() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHookDefaultsFromConfigUsesTopLevelFallback(t *testing.T) {
	cases := []struct {
		name   string
		config string
		want   string
	}{
		{name: "empty config", want: "CRITICAL"},
		{name: "top level fallback", config: "fail_on: HIGH\n", want: "HIGH"},
		{name: "hook setting wins", config: "fail_on: HIGH\nhook:\n  fail_on: LOW\n", want: "LOW"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateCLIConfigDiscovery(t)
			if tc.config != "" {
				if err := os.WriteFile(defaultCLIConfigFile, []byte(tc.config), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
			}

			hookType, failOn, err := hookDefaultsFromConfig()
			if err != nil {
				t.Fatalf("hookDefaultsFromConfig(): %v", err)
			}
			if hookType != "pre-push" || failOn != tc.want {
				t.Fatalf("hookDefaultsFromConfig() = (%q, %q), want (%q, %q)", hookType, failOn, "pre-push", tc.want)
			}
		})
	}
}

func TestHookInstallOperationalFailuresPreserveHooks(t *testing.T) {
	cases := []struct {
		name          string
		config        string
		args          []string
		hook          []byte
		wantOutput    string
		wantHookExist bool
	}{
		{
			name:       "malformed config",
			config:     "hook: [broken\n",
			wantOutput: "cannot load hook configuration",
		},
		{
			name:          "unsupported type",
			args:          []string{"--type", "commit-msg"},
			hook:          []byte("#!/bin/sh\necho preserve unsupported type\n"),
			wantOutput:    "unsupported hook type",
			wantHookExist: true,
		},
		{
			name:          "custom hook",
			hook:          []byte("#!/bin/sh\necho preserve custom hook\n"),
			wantOutput:    "not managed by packmon",
			wantHookExist: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			hooksDir := filepath.Join(root, ".git", "hooks")
			if err := os.MkdirAll(hooksDir, 0o750); err != nil {
				t.Fatalf("create hooks fixture: %v", err)
			}
			if tc.config != "" {
				if err := os.WriteFile(filepath.Join(root, defaultCLIConfigFile), []byte(tc.config), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
			}
			hookPath := filepath.Join(hooksDir, "pre-push")
			if tc.hook != nil {
				if err := os.WriteFile(hookPath, tc.hook, 0o700); err != nil { //nolint:gosec // G306: git hooks must be executable.
					t.Fatalf("write custom hook: %v", err)
				}
			}

			output, exitCode := runHookInstallExitHelper(t, root, tc.args)
			if exitCode != ExitOperational {
				t.Fatalf("hook install exit code = %d, want %d; output=%s", exitCode, ExitOperational, output)
			}
			if !strings.Contains(output, tc.wantOutput) {
				t.Fatalf("hook install output = %q, want %q", output, tc.wantOutput)
			}
			data, err := os.ReadFile(hookPath) // #nosec G304 -- test reads the fixture it created.
			if tc.wantHookExist {
				if err != nil {
					t.Fatalf("read preserved hook: %v", err)
				}
				if string(data) != string(tc.hook) {
					t.Fatalf("hook changed after operational failure: got %q, want %q", data, tc.hook)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("hook exists after configuration failure or stat error = %v", err)
			}
		})
	}
}

func TestHookInstallExitHelper(t *testing.T) {
	if os.Getenv(hookExitHelperEnv) != "1" {
		return
	}

	cmd := newHookInstallCmd()
	cmd.SetArgs(os.Args[3:])
	if err := cmd.Execute(); err != nil {
		os.Exit(99)
	}
	os.Exit(0)
}

func setGitCommandOutputForHookTest(t *testing.T, output func(context.Context, ...string) ([]byte, error)) {
	t.Helper()
	original := gitCommandOutput
	gitCommandOutput = output
	t.Cleanup(func() {
		gitCommandOutput = original
	})
}

func runHookInstallExitHelper(t *testing.T, directory string, args []string) (string, int) {
	t.Helper()

	//nolint:gosec // G204: the test re-executes its own binary as a helper process.
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestHookInstallExitHelper$", "--"}, args...)...)
	cmd.Dir = directory
	home := t.TempDir()
	cmd.Env = append(os.Environ(), hookExitHelperEnv+"=1", "HOME="+home, "USERPROFILE="+home)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("start hook helper: %v", err)
	}
	return string(output), exitErr.ExitCode()
}
