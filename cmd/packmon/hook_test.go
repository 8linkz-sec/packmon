package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestFindGitRootAndIsPackmonHook(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(filepath.Join(root, ".git", "hooks"), 0o750); err != nil {
		t.Fatalf("mkdir .git/hooks: %v", err)
	}
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	// findGitRoot normalizes via filepath.Abs, so compare against a cleaned
	// path: t.TempDir() echoes GOTMPDIR verbatim, which may use forward slashes
	// on Windows when GOTMPDIR is set that way.
	wantRoot := filepath.Clean(root)
	if got := findGitRoot(nested); got != wantRoot {
		t.Fatalf("findGitRoot() = %q, want %q", got, wantRoot)
	}
	hookPath := filepath.Join(root, ".git", "hooks", "pre-push")
	// #nosec G306 -- git hooks must be executable.
	if err := os.WriteFile(hookPath, []byte(hookScript("CRITICAL")), 0o755); err != nil {
		t.Fatalf("write hook: %v", err)
	}
	if !isPackmonHook(hookPath) {
		t.Fatal("isPackmonHook(packmon hook) = false")
	}
	if isPackmonHook(filepath.Join(root, ".git", "hooks", "missing")) {
		t.Fatal("isPackmonHook(missing hook) = true")
	}
}

func tempDirOutsideGit(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	root := findGitRoot(dir)
	if root == "" {
		return dir
	}

	parent := filepath.Dir(root)
	if parent == root {
		t.Fatalf("cannot create temp directory outside git root %q", root)
	}

	outside, err := os.MkdirTemp(parent, "packmon-outside-git-*")
	if err != nil {
		t.Fatalf("create temp directory outside git root %q: %v", root, err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(outside); err != nil {
			t.Errorf("remove temp directory outside git root %q: %v", outside, err)
		}
	})

	if found := findGitRoot(outside); found != "" {
		t.Fatalf("temp directory %q is still inside git repository %q", outside, found)
	}
	return outside
}

func TestHookStatusOutsideGitRepository(t *testing.T) {
	t.Chdir(tempDirOutsideGit(t))

	cmd := newHookStatusCmd()
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("hook status: %v", err)
		}
	})
	if !strings.Contains(output, "Not in a git repository.") {
		t.Fatalf("hook status output = %q", output)
	}
}

func TestHookInstallStatusAndUninstallManagedHook(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o750); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	t.Chdir(root)

	installCmd := newHookInstallCmd()
	installCmd.SetArgs([]string{"--type", "pre-commit"})
	installOutput := captureStdout(t, func() {
		if err := installCmd.Execute(); err != nil {
			t.Fatalf("hook install: %v", err)
		}
	})
	if !strings.Contains(installOutput, "Installed packmon pre-commit hook") {
		t.Fatalf("hook install output = %q", installOutput)
	}

	hookPath := filepath.Join(root, ".git", "hooks", "pre-commit")
	if !isPackmonHook(hookPath) {
		t.Fatal("installed pre-commit hook is not packmon-managed")
	}

	statusCmd := newHookStatusCmd()
	statusOutput := captureStdout(t, func() {
		if err := statusCmd.Execute(); err != nil {
			t.Fatalf("hook status: %v", err)
		}
	})
	if !strings.Contains(statusOutput, "pre-commit:") || !strings.Contains(statusOutput, "packmon hook installed") {
		t.Fatalf("hook status output = %q", statusOutput)
	}

	uninstallCmd := newHookUninstallCmd()
	uninstallOutput := captureStdout(t, func() {
		if err := uninstallCmd.Execute(); err != nil {
			t.Fatalf("hook uninstall: %v", err)
		}
	})
	if !strings.Contains(uninstallOutput, "Removed packmon pre-commit hook.") {
		t.Fatalf("hook uninstall output = %q", uninstallOutput)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Fatalf("pre-commit hook still exists or stat failed: %v", err)
	}
}

func TestHookInstallUsesGitResolvedHooksDirForWorktree(t *testing.T) {
	git := requireGit(t)
	repo := t.TempDir()
	runGit(t, git, repo, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.test/repo\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	runGit(t, git, repo, "add", "go.mod")
	runGit(t, git, repo, "-c", "user.name=Packmon Test", "-c", "user.email=packmon@example.invalid", "commit", "--quiet", "-m", "init")

	worktree := filepath.Join(t.TempDir(), "linked")
	runGit(t, git, repo, "worktree", "add", "--quiet", "-b", "packmon-hook-test", worktree, "HEAD")
	t.Chdir(worktree)

	output := captureStdout(t, func() {
		if err := newHookInstallCmd().Execute(); err != nil {
			t.Fatalf("hook install in worktree: %v", err)
		}
	})
	if !strings.Contains(output, "Installed packmon pre-push hook") {
		t.Fatalf("hook install output = %q", output)
	}

	hooksDir := testGitOutput(t, git, worktree, "rev-parse", "--git-path", "hooks")
	if !filepath.IsAbs(hooksDir) {
		hooksDir = filepath.Join(worktree, hooksDir)
	}
	hookPath := filepath.Join(filepath.Clean(hooksDir), "pre-push")
	if !isPackmonHook(hookPath) {
		t.Fatalf("worktree hook was not installed in git-resolved hooks dir %s", hookPath)
	}
}

func TestHookInstallUsesConfigDefaults(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o750); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, defaultCLIConfigFile), []byte(`hook:
  type: pre-commit
  fail_on: HIGH
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Chdir(root)

	output := captureStdout(t, func() {
		if err := newHookInstallCmd().Execute(); err != nil {
			t.Fatalf("hook install: %v", err)
		}
	})
	if !strings.Contains(output, "Installed packmon pre-commit hook") {
		t.Fatalf("hook install output = %q", output)
	}
	data, err := os.ReadFile(filepath.Join(root, ".git", "hooks", "pre-commit")) // #nosec G304 -- test reads generated hook path.
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	if !strings.Contains(string(data), "--fail-on HIGH") {
		t.Fatalf("hook script = %s, want HIGH threshold", data)
	}
}

func requireGit(t *testing.T) string {
	t.Helper()

	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git executable not available")
	}
	return git
}

func runGit(t *testing.T, git, dir string, args ...string) {
	t.Helper()

	cmd := exec.Command(git, args...) // #nosec G204 -- test helper invokes the resolved git binary with fixed test-controlled arguments and no shell.
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func testGitOutput(t *testing.T, git, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command(git, args...) // #nosec G204 -- test helper invokes the resolved git binary with fixed test-controlled arguments and no shell.
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s failed: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

func TestHookInstallUpdatesExistingPackmonHook(t *testing.T) {
	root := t.TempDir()
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	hookPath := filepath.Join(hooksDir, "pre-push")
	// #nosec G306 -- git hooks must be executable.
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\n"+hookMarker+"\necho old\n"), 0o755); err != nil {
		t.Fatalf("write existing hook: %v", err)
	}
	t.Chdir(root)

	output := captureStdout(t, func() {
		if err := newHookInstallCmd().Execute(); err != nil {
			t.Fatalf("hook install update: %v", err)
		}
	})
	if !strings.Contains(output, "Installed packmon pre-push hook") {
		t.Fatalf("hook install output = %q", output)
	}
	data, err := os.ReadFile(hookPath) // #nosec G304 -- test reads a generated git-hook path.
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	if strings.Contains(string(data), "echo old") || !strings.Contains(string(data), "packmon scan") {
		t.Fatalf("hook was not updated:\n%s", data)
	}
}

func TestHookInstallAndUninstallOutsideGitRepository(t *testing.T) {
	t.Chdir(tempDirOutsideGit(t))

	for _, cmd := range []*cobra.Command{newHookInstallCmd(), newHookUninstallCmd()} {
		output := captureStdout(t, func() {
			if err := cmd.Execute(); err != nil {
				t.Fatalf("%s outside git: %v", cmd.Use, err)
			}
		})
		if !strings.Contains(output, "Not in a git repository.") {
			t.Fatalf("%s outside git output = %q", cmd.Use, output)
		}
	}
}

func TestHookStatusAndUninstallCustomHooks(t *testing.T) {
	root := t.TempDir()
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	// #nosec G306 -- git hooks must be executable.
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-push"), []byte("#!/bin/sh\necho custom\n"), 0o755); err != nil {
		t.Fatalf("write custom hook: %v", err)
	}
	t.Chdir(root)

	statusOutput := captureStdout(t, func() {
		if err := newHookStatusCmd().Execute(); err != nil {
			t.Fatalf("hook status: %v", err)
		}
	})
	if !strings.Contains(statusOutput, "custom hook (not packmon)") || !strings.Contains(statusOutput, "pre-commit:") {
		t.Fatalf("hook status output = %q", statusOutput)
	}

	uninstallOutput := captureStdout(t, func() {
		if err := newHookUninstallCmd().Execute(); err != nil {
			t.Fatalf("hook uninstall custom: %v", err)
		}
	})
	if !strings.Contains(uninstallOutput, "Skipping pre-push") || !strings.Contains(uninstallOutput, "No packmon-managed hooks found.") {
		t.Fatalf("hook uninstall output = %q", uninstallOutput)
	}
}

func TestHookStatusSanitizesRepositoryPath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo\u202e")
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	t.Chdir(root)

	output := captureStdout(t, func() {
		if err := newHookStatusCmd().Execute(); err != nil {
			t.Fatalf("hook status: %v", err)
		}
	})

	if strings.Contains(output, "\u202e") {
		t.Fatalf("hook status output contains raw format control:\n%s", output)
	}
	if !strings.Contains(output, `\u202E`) {
		t.Fatalf("hook status output missing sanitized path:\n%s", output)
	}
}
