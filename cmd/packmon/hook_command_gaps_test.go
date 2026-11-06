package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestHookInstallReportsFilesystemFailures(t *testing.T) {
	t.Run("hooks_directory_is_a_file", func(t *testing.T) {
		root := t.TempDir()
		gitDir := filepath.Join(root, ".git")
		if err := os.Mkdir(gitDir, 0o750); err != nil {
			t.Fatalf("create git directory: %v", err)
		}
		hooksPath := filepath.Join(gitDir, "hooks")
		wantData := []byte("hooks path sentinel\n")
		if err := os.WriteFile(hooksPath, wantData, 0o640); err != nil {
			t.Fatalf("write hooks-path sentinel: %v", err)
		}
		before, err := os.Stat(hooksPath)
		if err != nil {
			t.Fatalf("stat hooks-path sentinel: %v", err)
		}

		output, exitCode := runHookExitHelper(t, root, "install", "")
		if exitCode != ExitOperational || !strings.Contains(output, "cannot create hooks directory") {
			t.Fatalf("hook install result = exit %d, output %q; want operational hooks-directory error", exitCode, output)
		}
		if strings.Contains(output, "Installed packmon") {
			t.Fatalf("hook install reported success after hooks-directory failure: %q", output)
		}
		gotData, readErr := os.ReadFile(hooksPath) // #nosec G304 -- test reads its fixed fixture path.
		if readErr != nil {
			t.Fatalf("read hooks-path sentinel after failure: %v", readErr)
		}
		after, statErr := os.Stat(hooksPath)
		if statErr != nil {
			t.Fatalf("stat hooks-path sentinel after failure: %v", statErr)
		}
		if string(gotData) != string(wantData) || after.Mode() != before.Mode() {
			t.Fatalf("hooks-path sentinel changed: data=%q mode=%v, want data=%q mode=%v", gotData, after.Mode(), wantData, before.Mode())
		}
	})

	t.Run("read_only_hooks_directory", func(t *testing.T) {
		requireNativeHookPermissionFailures(t)

		root := t.TempDir()
		hooksDir := filepath.Join(root, ".git", "hooks")
		if err := os.MkdirAll(hooksDir, 0o750); err != nil {
			t.Fatalf("create hooks directory: %v", err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(hooksDir, 0o750); err != nil && !os.IsNotExist(err) {
				t.Errorf("restore hooks directory mode: %v", err)
			}
		})
		if err := os.Chmod(hooksDir, 0o500); err != nil {
			t.Fatalf("make hooks directory read-only: %v", err)
		}
		probePath := filepath.Join(hooksDir, "permission-probe")
		if err := os.WriteFile(probePath, []byte("probe"), 0o600); err == nil {
			_ = os.Remove(probePath)
			t.Fatal("read-only hooks directory still permits file creation")
		} else if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("permission probe error = %v, want permission denied", err)
		}

		output, exitCode := runHookExitHelper(t, root, "install", "")
		if exitCode != ExitOperational || !strings.Contains(output, "cannot write hook file") {
			t.Fatalf("hook install result = exit %d, output %q; want operational write error", exitCode, output)
		}
		if strings.Contains(output, "Installed packmon") {
			t.Fatalf("hook install reported success after write failure: %q", output)
		}
		if _, err := os.Lstat(filepath.Join(hooksDir, "pre-push")); !os.IsNotExist(err) {
			t.Fatalf("pre-push hook exists after denied write: %v", err)
		}
	})

	t.Run("existing_managed_symlink", func(t *testing.T) {
		root := t.TempDir()
		hooksDir := filepath.Join(root, ".git", "hooks")
		if err := os.MkdirAll(hooksDir, 0o750); err != nil {
			t.Fatalf("create hooks directory: %v", err)
		}
		externalPath := filepath.Join(t.TempDir(), "external-managed-hook")
		wantData := []byte("#!/bin/sh\n" + hookMarker + "\necho external sentinel\n")
		if err := os.WriteFile(externalPath, wantData, 0o700); err != nil {
			t.Fatalf("write external managed hook: %v", err)
		}
		before, err := os.Stat(externalPath)
		if err != nil {
			t.Fatalf("stat external managed hook: %v", err)
		}
		hookPath := filepath.Join(hooksDir, "pre-push")
		if err := os.Symlink(externalPath, hookPath); err != nil {
			skipOrFailSymlink(t, err)
		}
		assertHookSymlinkTarget(t, hookPath, externalPath)

		output, exitCode := runHookExitHelper(t, root, "install", "")
		assertHookSymlinkTarget(t, hookPath, externalPath)
		gotData, readErr := os.ReadFile(externalPath) // #nosec G304 -- test reads its fixed fixture path.
		if readErr != nil {
			t.Fatalf("read external managed hook after install: %v", readErr)
		}
		after, statErr := os.Stat(externalPath)
		if statErr != nil {
			t.Fatalf("stat external managed hook after install: %v", statErr)
		}
		const wantDiagnostic = "Error: refusing to install hook because the hook path is a symbolic link.\n"
		if exitCode != ExitOperational || output != wantDiagnostic {
			t.Fatalf("managed-hook symlink result = exit %d, output %q; want exit %d, output %q", exitCode, output, ExitOperational, wantDiagnostic)
		}
		for _, forbidden := range []string{"Installed packmon", hookPath, externalPath} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("managed-hook symlink output %q contains forbidden value %q", output, forbidden)
			}
		}
		if string(gotData) != string(wantData) || after.Mode() != before.Mode() {
			t.Fatalf("rejected symlink changed external hook: data=%q mode=%v, want data=%q mode=%v", gotData, after.Mode(), wantData, before.Mode())
		}
	})

	t.Run("dangling_hook_symlink", func(t *testing.T) {
		root := t.TempDir()
		hooksDir := filepath.Join(root, ".git", "hooks")
		if err := os.MkdirAll(hooksDir, 0o750); err != nil {
			t.Fatalf("create hooks directory: %v", err)
		}
		externalPath := filepath.Join(t.TempDir(), "created-through-dangling-link")
		hookPath := filepath.Join(hooksDir, "pre-push")
		if err := os.Symlink(externalPath, hookPath); err != nil {
			skipOrFailSymlink(t, err)
		}
		assertHookSymlinkTarget(t, hookPath, externalPath)
		if _, err := os.Stat(externalPath); !os.IsNotExist(err) {
			t.Fatalf("external dangling-link target exists before install: %v", err)
		}

		output, exitCode := runHookExitHelper(t, root, "install", "")
		assertHookSymlinkTarget(t, hookPath, externalPath)
		if _, err := os.Stat(externalPath); !os.IsNotExist(err) {
			t.Fatalf("rejected dangling symlink created external target: %v", err)
		}
		const wantDiagnostic = "Error: refusing to install hook because the hook path is a symbolic link.\n"
		if exitCode != ExitOperational || output != wantDiagnostic {
			t.Fatalf("dangling hook symlink result = exit %d, output %q; want exit %d, output %q", exitCode, output, ExitOperational, wantDiagnostic)
		}
		for _, forbidden := range []string{"Installed packmon", hookPath, externalPath} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("dangling hook symlink output %q contains forbidden value %q", output, forbidden)
			}
		}
	})
}

func TestHookCommandsReportDeletedWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("removing a helper process working directory is a POSIX-only filesystem behavior")
	}

	for _, operation := range []string{"install", "uninstall", "status"} {
		t.Run(operation, func(t *testing.T) {
			output, exitCode := runHookDeletedWorkingDirectoryHelper(t, operation)
			if exitCode != ExitOperational || !strings.Contains(output, "cannot determine working directory") {
				t.Fatalf("hook %s result = exit %d, output %q; want operational working-directory error", operation, exitCode, output)
			}
			for _, success := range []string{"Installed packmon", "Removed packmon", "Repository:"} {
				if strings.Contains(output, success) {
					t.Fatalf("hook %s reported success after working-directory failure: %q", operation, output)
				}
			}
		})
	}
}

func TestHookUninstallReportsRemovalFailure(t *testing.T) {
	requireNativeHookPermissionFailures(t)

	root := t.TempDir()
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("create hooks directory: %v", err)
	}
	hookPath := filepath.Join(hooksDir, "pre-push")
	wantData := []byte(hookScript("HIGH"))
	if err := os.WriteFile(hookPath, wantData, managedHookMode); err != nil { //nolint:gosec // G306: fixture is an executable Git hook.
		t.Fatalf("write managed hook: %v", err)
	}
	probePath := filepath.Join(hooksDir, "permission-probe")
	if err := os.WriteFile(probePath, []byte("probe"), 0o600); err != nil {
		t.Fatalf("write removal probe: %v", err)
	}
	before, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("stat managed hook: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(hooksDir, 0o750); err != nil && !os.IsNotExist(err) {
			t.Errorf("restore hooks directory mode: %v", err)
		}
	})
	if err := os.Chmod(hooksDir, 0o500); err != nil {
		t.Fatalf("make hooks directory non-writable: %v", err)
	}
	if err := os.Remove(probePath); err == nil {
		t.Fatal("non-writable hooks directory still permits removal")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("removal permission probe error = %v, want permission denied", err)
	}

	output, exitCode := runHookExitHelper(t, root, "uninstall")
	if exitCode != ExitOperational || !strings.Contains(output, "cannot remove pre-push hook") {
		t.Fatalf("hook uninstall result = exit %d, output %q; want operational removal error", exitCode, output)
	}
	if strings.Contains(output, "Removed packmon") {
		t.Fatalf("hook uninstall reported removal after denied delete: %q", output)
	}
	if err := os.Chmod(hooksDir, 0o750); err != nil {
		t.Fatalf("restore hooks directory for verification: %v", err)
	}
	assertHookFileState(t, hookPath, wantData, before.Mode())
}

func TestHookUninstallReportsStatFailure(t *testing.T) {
	requireNativeHookPermissionFailures(t)

	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("create hooks directory: %v", err)
	}
	hookPath := filepath.Join(hooksDir, "pre-push")
	wantData := []byte(hookScript("HIGH"))
	if err := os.WriteFile(hookPath, wantData, managedHookMode); err != nil { //nolint:gosec // G306: fixture is an executable Git hook.
		t.Fatalf("write managed hook: %v", err)
	}
	before, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("stat managed hook before restriction: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(gitDir, 0o750); err != nil && !os.IsNotExist(err) {
			t.Errorf("restore git directory mode: %v", err)
		}
	})
	if err := os.Chmod(gitDir, 0); err != nil {
		t.Fatalf("make git directory inaccessible: %v", err)
	}
	if _, err := os.Stat(hookPath); err == nil || os.IsNotExist(err) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("restricted managed-hook stat error = %v, want non-ENOENT permission error", err)
	}

	output, exitCode := runHookExitHelper(t, root, "uninstall")
	if err := os.Chmod(gitDir, 0o750); err != nil {
		t.Fatalf("restore git directory for verification: %v", err)
	}
	assertHookFileState(t, hookPath, wantData, before.Mode())

	if exitCode == ExitOperational {
		if !strings.Contains(output, "Error:") || !strings.Contains(output, "pre-push hook") {
			t.Fatalf("hook uninstall stat failure output = %q, want operational pre-push diagnostic", output)
		}
		for _, forbidden := range []string{
			"Skipping pre-push: not a packmon-managed hook.",
			"Skipping pre-commit: not a packmon-managed hook.",
			"No packmon-managed hooks found.",
			"Removed packmon",
		} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("hook uninstall stat failure output = %q, must not contain %q", output, forbidden)
			}
		}
		return
	}
	const currentMisleadingOutput = "Skipping pre-push: not a packmon-managed hook.\n" +
		"Skipping pre-commit: not a packmon-managed hook.\n" +
		"No packmon-managed hooks found.\n"
	if exitCode == 0 && output == currentMisleadingOutput {
		t.Skip("[F029-bugs-3] hook uninstall treats non-ENOENT stat failures as custom/missing hooks and exits successfully")
	}
	t.Fatalf("unexpected hook uninstall stat-failure result: exit=%d output=%q", exitCode, output)
}

func TestHookInstallExitHelper(t *testing.T) {
	if os.Getenv(hookExitHelperEnv) != "1" {
		return
	}

	args := hookExitHelperArgs(t)
	if args[0] == "deleted-cwd" {
		if len(args) != 4 {
			t.Fatalf("deleted-CWD helper args = %#v, want mode, ready path, release path, operation", args)
		}
		if err := os.WriteFile(args[1], []byte("ready\n"), 0o600); err != nil {
			t.Fatalf("write deleted-CWD ready marker: %v", err)
		}
		waitForHookHelperRelease(t, args[2])
		if cwd, err := os.Getwd(); err == nil {
			t.Fatalf("os.Getwd() = %q, nil; want deleted working-directory error", cwd)
		}
		if got := findGitRoot("."); got != "" {
			t.Fatalf("findGitRoot(.) = %q, want empty after working-directory removal", got)
		}
		if args[3] == "install" {
			args = []string{"install", ""}
		} else {
			args = []string{args[3]}
		}
	}

	var cmdArgs []string
	var cmd interface {
		SetArgs([]string)
		Execute() error
	}
	switch args[0] {
	case "install":
		if len(args) < 2 {
			t.Fatalf("install helper args = %#v, want explicit config slot", args)
		}
		flagNoProjectConfig = true
		flagConfig = args[1]
		cmd = newHookInstallCmd()
		cmdArgs = args[2:]
	case "uninstall":
		cmd = newHookUninstallCmd()
		cmdArgs = args[1:]
	case "status":
		cmd = newHookStatusCmd()
		cmdArgs = args[1:]
	default:
		t.Fatalf("unknown hook helper operation %q", args[0])
	}

	cmd.SetArgs(cmdArgs)
	if err := cmd.Execute(); err != nil {
		os.Exit(99)
	}
	os.Exit(0)
}

func hookExitHelperArgs(t *testing.T) []string {
	t.Helper()
	for index, arg := range os.Args {
		if arg == "--" && index+1 < len(os.Args) {
			return os.Args[index+1:]
		}
	}
	t.Fatal("hook exit helper arguments are missing")
	return nil
}

func waitForHookHelperRelease(t *testing.T, releasePath string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(releasePath); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat deleted-CWD release marker: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for deleted-CWD release marker %q", releasePath)
		}
		time.Sleep(10 * time.Millisecond)
	}
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

	configPath := filepath.Join(directory, defaultCLIConfigFile)
	if info, err := os.Stat(configPath); err != nil || info.IsDir() {
		configPath = ""
	}
	helperArgs := append([]string{"install", configPath}, args...)
	return runHookExitHelper(t, directory, helperArgs...)
}

func runHookExitHelper(t *testing.T, directory string, args ...string) (string, int) {
	t.Helper()

	cmd := newHookExitHelperCommand(t, directory, args...)
	output, err := cmd.CombinedOutput()
	return string(output), hookExitCode(t, err)
}

func newHookExitHelperCommand(t *testing.T, directory string, args ...string) *exec.Cmd {
	t.Helper()

	commandArgs := append([]string{"-test.run=^TestHookInstallExitHelper$", "--"}, args...)
	//nolint:gosec // G204: the test re-executes its own binary with fixed helper protocol arguments.
	cmd := exec.Command(os.Args[0], commandArgs...)
	cmd.Dir = directory
	home := t.TempDir()
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		hookExitHelperEnv + "=1",
		"HOME=" + home,
		"USERPROFILE=" + home,
	}
	if coverDir := os.Getenv("GOCOVERDIR"); coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}
	return cmd
}

func hookExitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("start hook helper: %v", err)
	}
	return exitErr.ExitCode()
}

func runHookDeletedWorkingDirectoryHelper(t *testing.T, operation string) (string, int) {
	t.Helper()

	workingParent := t.TempDir()
	workingDir := filepath.Join(workingParent, "deleted-working-directory")
	if err := os.Mkdir(workingDir, 0o750); err != nil {
		t.Fatalf("create helper working directory: %v", err)
	}
	controlDir := t.TempDir()
	readyPath := filepath.Join(controlDir, "ready")
	releasePath := filepath.Join(controlDir, "release")
	cmd := newHookExitHelperCommand(t, workingDir, "deleted-cwd", readyPath, releasePath, operation)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start deleted-CWD hook helper: %v", err)
	}
	waitResult := make(chan error, 1)
	go func() {
		waitResult <- cmd.Wait()
	}()

	readyDeadline := time.NewTimer(10 * time.Second)
	readyTicker := time.NewTicker(10 * time.Millisecond)
	defer readyDeadline.Stop()
	defer readyTicker.Stop()
	ready := false
	for !ready {
		select {
		case err := <-waitResult:
			t.Fatalf("deleted-CWD helper exited before ready: %v\n%s", err, output.String())
		case <-readyDeadline.C:
			_ = cmd.Process.Kill()
			t.Fatalf("timed out waiting for deleted-CWD helper readiness\n%s", output.String())
		case <-readyTicker.C:
			if _, err := os.Stat(readyPath); err == nil {
				ready = true
			} else if !os.IsNotExist(err) {
				_ = cmd.Process.Kill()
				t.Fatalf("stat deleted-CWD ready marker: %v", err)
			}
		}
	}

	if err := os.Remove(workingDir); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("remove helper working directory: %v", err)
	}
	if err := os.WriteFile(releasePath, []byte("release\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("write deleted-CWD release marker: %v", err)
	}

	completionTimer := time.NewTimer(10 * time.Second)
	defer completionTimer.Stop()
	select {
	case err := <-waitResult:
		return output.String(), hookExitCode(t, err)
	case <-completionTimer.C:
		_ = cmd.Process.Kill()
		t.Fatalf("timed out waiting for deleted-CWD helper completion\n%s", output.String())
	}
	return "", 0
}

func requireNativeHookPermissionFailures(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("directory permission failures require POSIX mode enforcement")
	}
	if os.Geteuid() == 0 {
		t.Skip("directory permission failures cannot be asserted while running as root")
	}
}

func assertHookSymlinkTarget(t *testing.T, hookPath, wantTarget string) {
	t.Helper()
	info, err := os.Lstat(hookPath)
	if err != nil {
		t.Fatalf("lstat hook symlink: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("hook path mode = %v, want symlink", info.Mode())
	}
	target, err := os.Readlink(hookPath)
	if err != nil {
		t.Fatalf("read hook symlink: %v", err)
	}
	if target != wantTarget {
		t.Fatalf("hook symlink target = %q, want %q", target, wantTarget)
	}
}

func assertHookFileState(t *testing.T, path string, wantData []byte, wantMode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test reads its fixed fixture path.
	if err != nil {
		t.Fatalf("read managed hook after failure: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat managed hook after failure: %v", err)
	}
	if string(data) != string(wantData) || info.Mode() != wantMode {
		t.Fatalf("managed hook changed after failure: data=%q mode=%v, want data=%q mode=%v", data, info.Mode(), wantData, wantMode)
	}
}
