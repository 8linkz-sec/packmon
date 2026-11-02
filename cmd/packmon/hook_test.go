package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestFindGitRootReturnsEmptyAfterWorkingDirectoryRemoval(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("removing a process working directory is a POSIX-only filesystem behavior")
	}

	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original working directory: %v", err)
	}
	removedDir := filepath.Join(t.TempDir(), "removed-working-directory")
	if err := os.Mkdir(removedDir, 0o750); err != nil {
		t.Fatalf("create removable working directory: %v", err)
	}
	if err := os.Chdir(removedDir); err != nil {
		t.Fatalf("chdir to removable working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDir); err != nil {
			t.Errorf("restore original working directory: %v", err)
		}
	})

	if err := os.Remove(removedDir); err != nil {
		t.Fatalf("remove current working directory: %v", err)
	}
	if cwd, err := os.Getwd(); err == nil {
		t.Fatalf("os.Getwd() = %q, nil; want an error after working directory removal", cwd)
	}
	if got := findGitRoot("."); got != "" {
		t.Fatalf("findGitRoot(.) = %q, want empty after working directory removal", got)
	}
}

func TestWriteManagedHookReportsFilesystemErrors(t *testing.T) {
	t.Run("parent path is a file", func(t *testing.T) {
		parentPath := filepath.Join(t.TempDir(), "hooks")
		wantData := []byte("parent sentinel\n")
		if err := os.WriteFile(parentPath, wantData, 0o640); err != nil {
			t.Fatalf("write parent sentinel: %v", err)
		}
		before, err := os.Stat(parentPath)
		if err != nil {
			t.Fatalf("stat parent sentinel: %v", err)
		}

		err = writeManagedHook(filepath.Join(parentPath, "pre-push"), hookScript("HIGH"))
		if err == nil {
			t.Fatal("writeManagedHook(parent file) error = nil")
		}
		gotData, readErr := os.ReadFile(parentPath) // #nosec G304 -- test reads its fixed fixture path.
		if readErr != nil {
			t.Fatalf("read parent sentinel after failure: %v", readErr)
		}
		after, statErr := os.Stat(parentPath)
		if statErr != nil {
			t.Fatalf("stat parent sentinel after failure: %v", statErr)
		}
		if string(gotData) != string(wantData) || after.Mode() != before.Mode() {
			t.Fatalf("parent sentinel changed after failure: data=%q mode=%v, want data=%q mode=%v", gotData, after.Mode(), wantData, before.Mode())
		}
	})

	t.Run("target path is a directory", func(t *testing.T) {
		targetPath := filepath.Join(t.TempDir(), "pre-push")
		if err := os.Mkdir(targetPath, 0o750); err != nil {
			t.Fatalf("create unusable target directory: %v", err)
		}
		sentinelPath := filepath.Join(targetPath, "sentinel")
		wantData := []byte("target sentinel\n")
		if err := os.WriteFile(sentinelPath, wantData, 0o640); err != nil {
			t.Fatalf("write target sentinel: %v", err)
		}
		beforeDir, err := os.Stat(targetPath)
		if err != nil {
			t.Fatalf("stat target directory: %v", err)
		}
		beforeSentinel, err := os.Stat(sentinelPath)
		if err != nil {
			t.Fatalf("stat target sentinel: %v", err)
		}

		err = writeManagedHook(targetPath, hookScript("HIGH"))
		if err == nil {
			t.Fatal("writeManagedHook(directory target) error = nil")
		}
		gotData, readErr := os.ReadFile(sentinelPath) // #nosec G304 -- test reads its fixed fixture path.
		if readErr != nil {
			t.Fatalf("read target sentinel after failure: %v", readErr)
		}
		afterDir, statErr := os.Stat(targetPath)
		if statErr != nil {
			t.Fatalf("stat target directory after failure: %v", statErr)
		}
		afterSentinel, statErr := os.Stat(sentinelPath)
		if statErr != nil {
			t.Fatalf("stat target sentinel after failure: %v", statErr)
		}
		if !afterDir.IsDir() || afterDir.Mode() != beforeDir.Mode() {
			t.Fatalf("target directory changed after failure: mode=%v, want directory mode=%v", afterDir.Mode(), beforeDir.Mode())
		}
		if string(gotData) != string(wantData) || afterSentinel.Mode() != beforeSentinel.Mode() {
			t.Fatalf("target sentinel changed after failure: data=%q mode=%v, want data=%q mode=%v", gotData, afterSentinel.Mode(), wantData, beforeSentinel.Mode())
		}
	})
}

func TestIsHookModePackmonHookRecognizesCurrentInvocation(t *testing.T) {
	root := t.TempDir()
	currentPath := filepath.Join(root, "current")
	if err := os.WriteFile(currentPath, []byte(hookScript("HIGH")), 0o700); err != nil {
		t.Fatalf("write current managed hook: %v", err)
	}
	legacyPath := filepath.Join(root, "legacy")
	legacy := "#!/bin/sh\n" + hookMarker + "\npackmon scan . --fail-on HIGH --quiet\n"
	if err := os.WriteFile(legacyPath, []byte(legacy), 0o700); err != nil {
		t.Fatalf("write legacy managed hook: %v", err)
	}
	unusablePath := filepath.Join(root, "unusable")
	if err := os.Mkdir(unusablePath, 0o750); err != nil {
		t.Fatalf("create unusable hook path: %v", err)
	}

	if !isHookModePackmonHook(currentPath) {
		t.Fatal("isHookModePackmonHook(current hook) = false")
	}
	for name, path := range map[string]string{
		"legacy":   legacyPath,
		"missing":  filepath.Join(root, "missing"),
		"unusable": unusablePath,
	} {
		t.Run(name, func(t *testing.T) {
			if isHookModePackmonHook(path) {
				t.Fatalf("isHookModePackmonHook(%s) = true", name)
			}
		})
	}
}

func TestFindGitHooksDirDoesNotEscapeDiscoveredRoot(t *testing.T) {
	git := requireGit(t)

	parent := t.TempDir()
	runGit(t, git, parent, "init", "--quiet")
	root := filepath.Join(parent, "nested")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o750); err != nil {
		t.Fatalf("mkdir nested .git: %v", err)
	}

	want := filepath.Clean(filepath.Join(root, ".git", "hooks"))
	if got := findGitHooksDir(root); got != want {
		t.Fatalf("findGitHooksDir() = %q, want %q", got, want)
	}
}

func tempDirOutsideGit(t *testing.T) string {
	t.Helper()

	start := t.TempDir()
	for base := start; ; {
		if root := findGitRoot(base); root != "" {
			parent := filepath.Dir(root)
			if parent == root {
				break
			}
			base = parent
			continue
		}

		outside, err := os.MkdirTemp(base, "packmon-outside-git-*")
		if err == nil {
			t.Cleanup(func() {
				if err := os.RemoveAll(outside); err != nil {
					t.Errorf("remove temp directory outside git repositories %q: %v", outside, err)
				}
			})
			return outside
		}

		parent := filepath.Dir(base)
		if parent == base {
			break
		}
		base = parent
	}

	t.Skipf("no writable directory exists outside every Git repository enclosing %q", start)
	return ""
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

// skipHookModeTestOnWindows skips tests of the hook execute bit on Windows: Go
// reports no POSIX execute bits there and Git for Windows does not use them to
// decide whether to run a hook.
func skipHookModeTestOnWindows(t *testing.T) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("hook execute bits are POSIX-only; Windows has no executable mode bit for Git hooks")
	}
}

// TestHookInstallRestoresTheExecutableBitOfAManagedHook covers updating a
// managed hook that lost its execute bit: os.WriteFile keeps an existing file's
// mode, so without an explicit chmod the install reported success while Git
// kept skipping the non-executable hook.
func TestHookInstallRestoresTheExecutableBitOfAManagedHook(t *testing.T) {
	skipHookModeTestOnWindows(t)

	root := t.TempDir()
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	hookPath := filepath.Join(hooksDir, "pre-push")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\n"+hookMarker+"\necho old\n"), 0o600); err != nil {
		t.Fatalf("write existing hook: %v", err)
	}
	t.Chdir(root)

	captureStdout(t, func() {
		if err := newHookInstallCmd().Execute(); err != nil {
			t.Fatalf("hook install update: %v", err)
		}
	})

	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("stat hook: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("hook mode = %o, want 755 restored by install", got)
	}
}

// TestHookStatusReportsANonExecutableManagedHook keeps status from claiming a
// managed hook is installed when Git would skip it.
func TestHookStatusReportsANonExecutableManagedHook(t *testing.T) {
	skipHookModeTestOnWindows(t)

	root := t.TempDir()
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-push"), []byte(hookScript("HIGH")), 0o600); err != nil {
		t.Fatalf("write hook: %v", err)
	}
	t.Chdir(root)

	output := captureStdout(t, func() {
		if err := newHookStatusCmd().Execute(); err != nil {
			t.Fatalf("hook status: %v", err)
		}
	})
	if strings.Contains(output, "packmon hook installed") || !strings.Contains(output, "packmon hook not executable") {
		t.Fatalf("hook status output = %q, want the non-executable managed hook reported", output)
	}
}

// TestHookStatusSanitizesStatErrors covers the status error line: the stat
// error embeds the hook path, which comes from the repository's .git gitdir
// file, so a crafted path must not reach the terminal raw.
func TestHookStatusSanitizesStatErrors(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(t.TempDir(), "gitdir\x1b[31m")
	if runtime.GOOS != "windows" {
		// A regular file in place of the git dir makes the hook stat fail
		// with ENOTDIR. Windows rejects the control character in the name
		// itself, which fails the stat the same way.
		if err := os.WriteFile(gitDir, []byte("not a directory\n"), 0o600); err != nil {
			t.Fatalf("write gitdir placeholder: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o600); err != nil {
		t.Fatalf("write .git file: %v", err)
	}
	t.Chdir(root)

	output := captureStdout(t, func() {
		if err := newHookStatusCmd().Execute(); err != nil {
			t.Fatalf("hook status: %v", err)
		}
	})
	if !strings.Contains(output, "error:") {
		t.Fatalf("hook status output = %q, want a stat error line", output)
	}
	if strings.Contains(output, "\x1b") {
		t.Fatalf("hook status error line contains a raw terminal control:\n%q", output)
	}
	if !strings.Contains(output, `gitdir\x1B[31m`) {
		t.Fatalf("hook status output missing the sanitized path:\n%q", output)
	}
}

func TestHookFileExecutable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode os.FileMode
		goos string
		want bool
	}{
		{name: "unix owner executable", mode: 0o755, goos: "linux", want: true},
		{name: "unix owner-only executable", mode: 0o700, goos: "darwin", want: true},
		{name: "unix not executable", mode: 0o644, goos: "linux", want: false},
		{name: "unix group and other executable only", mode: 0o655, goos: "linux", want: false},
		{name: "windows ignores mode bits", mode: 0o666, goos: "windows", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hookFileExecutable(tt.mode, tt.goos); got != tt.want {
				t.Fatalf("hookFileExecutable(%o, %q) = %v, want %v", tt.mode, tt.goos, got, tt.want)
			}
		})
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
