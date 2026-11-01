package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// hookGuardRepo creates a fake Git working tree (a directory with a .git
// directory), makes it the working directory the way Git does for a hook, and
// stubs git so the guard falls back to the filesystem walk. It returns the
// repository root.
func hookGuardRepo(t *testing.T) string {
	t.Helper()
	isolateCLIConfigDiscovery(t)
	stubGitCommandOutput(t, func(context.Context, ...string) ([]byte, error) {
		return nil, errors.New("git unavailable in this test")
	})

	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o750); err != nil {
		t.Fatalf("create fake repository: %v", err)
	}
	t.Chdir(root)
	return root
}

func stubGitCommandOutput(t *testing.T, output func(context.Context, ...string) ([]byte, error)) {
	t.Helper()
	original := gitCommandOutput
	gitCommandOutput = output
	t.Cleanup(func() { gitCommandOutput = original })
}

// hookGuardSettings resolves scan settings for a hook-mode scan of "." with
// the history database pointed outside the repository, so only the destination
// under test can trip the guard.
func hookGuardSettings(t *testing.T, flags scanFlagValues) scanSettings {
	t.Helper()
	t.Setenv("PACKMON_DB_PATH", t.TempDir())
	t.Setenv("PACKMON_HISTORY_ENABLED", "")

	cfg, _, err := loadCurrentCLIConfig()
	if err != nil {
		t.Fatalf("loadCurrentCLIConfig: %v", err)
	}
	flags.Hook = true
	cmd := newScanCmd()
	settings, err := resolveScanSettings(cmd, cfg, scanTarget{Name: "repo", Path: "."}, flags)
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	return settings
}

func TestHookScriptRunsTheScanInHookMode(t *testing.T) {
	t.Parallel()

	if script := hookScript("HIGH"); !strings.Contains(script, "packmon scan . --hook --fail-on HIGH --quiet\n") {
		t.Fatalf("hook script = %q, want the scan to run with --hook", script)
	}
}

// TestRunScanCommandHookModeRefusesAUserGlobalRelativeOutputFile is the
// AUDIT-035 regression: a trusted user-global output.file with a relative path
// resolves against the working directory, which is the repository when Git
// runs the hook. The hook scan must fail before it scans or writes anything.
func TestRunScanCommandHookModeRefusesAUserGlobalRelativeOutputFile(t *testing.T) {
	root := hookGuardRepo(t)
	writeUserGlobalConfig(t, "output:\n  format: json\n  file: packmon-report.json\n")
	t.Setenv("PACKMON_DB_PATH", t.TempDir())

	cmd := newScanCmd()
	cmd.SetContext(context.Background())
	err := runScanCommand(cmd, []string{"."}, scanFlagValues{Hook: true, FailOn: "CRITICAL", MaxDepth: 2, Timeout: 1, Quiet: true})
	if err == nil || !strings.Contains(err.Error(), "hook scans never write inside the repository") || !strings.Contains(err.Error(), "JSON report") {
		t.Fatalf("runScanCommand(--hook) error = %v, want the in-repository JSON report rejected", err)
	}
	if code := exitCodeForError(err); code != ExitOperational {
		t.Fatalf("exit code = %d, want %d", code, ExitOperational)
	}
	if _, statErr := os.Stat(filepath.Join(root, "packmon-report.json")); !os.IsNotExist(statErr) {
		t.Fatalf("report file in repository: stat error = %v, want it never written", statErr)
	}
}

func TestValidateHookScanWriteDestinationsRejectsEveryReportInsideTheRepository(t *testing.T) {
	root := hookGuardRepo(t)

	for _, tt := range []struct {
		name  string
		flags scanFlagValues
		want  string
	}{
		{name: "json", flags: scanFlagValues{OutputJSON: "out/result.json"}, want: "JSON report"},
		{name: "sarif", flags: scanFlagValues{OutputSARIF: filepath.Join(root, "result.sarif")}, want: "SARIF report"},
		{name: "junit", flags: scanFlagValues{OutputJUnit: "result.xml"}, want: "JUnit report"},
		{name: "html", flags: scanFlagValues{OutputHTML: "report.html"}, want: "HTML report"},
		{name: "git metadata", flags: scanFlagValues{OutputJSON: filepath.Join(".git", "packmon.json")}, want: "JSON report"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			settings := hookGuardSettings(t, tt.flags)
			err := validateHookScanWriteDestinations(settings)
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "hook scans never write inside the repository") {
				t.Fatalf("validateHookScanWriteDestinations() error = %v, want %s rejected", err, tt.want)
			}
		})
	}
}

func TestValidateHookScanWriteDestinationsAllowsReportsOutsideTheRepository(t *testing.T) {
	hookGuardRepo(t)
	outside := t.TempDir()
	// A sibling whose name extends the repository name is still outside it.
	sibling := filepath.Join(filepath.Dir(mustGetwd(t)), "repo-reports", "result.json")

	settings := hookGuardSettings(t, scanFlagValues{
		OutputJSON:  sibling,
		OutputSARIF: filepath.Join(outside, "result.sarif"),
		OutputHTML:  filepath.Join(outside, "nested", "report.html"),
	})
	if err := validateHookScanWriteDestinations(settings); err != nil {
		t.Fatalf("validateHookScanWriteDestinations() error = %v, want reports outside the repository allowed", err)
	}
}

func TestValidateHookScanWriteDestinationsIgnoresNonHookScans(t *testing.T) {
	hookGuardRepo(t)

	settings := hookGuardSettings(t, scanFlagValues{OutputJSON: "result.json"})
	settings.Hook = false
	if err := validateHookScanWriteDestinations(settings); err != nil {
		t.Fatalf("validateHookScanWriteDestinations() error = %v, want a manual scan to keep writing where asked", err)
	}
}

func TestValidateHookScanWriteDestinationsRejectsALocalDatabaseInsideTheRepository(t *testing.T) {
	hookGuardRepo(t)

	settings := hookGuardSettings(t, scanFlagValues{})
	t.Setenv("PACKMON_DB_PATH", "packmon-db")
	err := validateHookScanWriteDestinations(settings)
	if err == nil || !strings.Contains(err.Error(), "local database") || !strings.Contains(err.Error(), "PACKMON_DB_PATH or db.path") {
		t.Fatalf("validateHookScanWriteDestinations() error = %v, want the in-repository database rejected", err)
	}
}

// TestValidateHookScanWriteDestinationsSkipsAnUnusedLocalDatabase covers a
// remote-only hook scan with history disabled: it never opens the local
// database, so its location does not matter.
func TestValidateHookScanWriteDestinationsSkipsAnUnusedLocalDatabase(t *testing.T) {
	hookGuardRepo(t)

	settings := hookGuardSettings(t, scanFlagValues{})
	settings.Mode = "remote"
	t.Setenv("PACKMON_DB_PATH", "packmon-db")
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")
	if err := validateHookScanWriteDestinations(settings); err != nil {
		t.Fatalf("validateHookScanWriteDestinations() error = %v, want an unused database location ignored", err)
	}
}

func TestValidateHookScanWriteDestinationsUsesTheGitReportedRepositoryDirectories(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	work := filepath.Join(t.TempDir(), "work")
	gitDir := filepath.Join(t.TempDir(), "main", ".git", "worktrees", "work")
	commonDir := filepath.Dir(filepath.Dir(gitDir))
	for _, dir := range []string{work, gitDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	t.Chdir(work)
	stubGitCommandOutput(t, func(_ context.Context, args ...string) ([]byte, error) {
		if !strings.Contains(strings.Join(args, " "), "rev-parse --show-toplevel --absolute-git-dir --git-common-dir") {
			return nil, errors.New("unexpected git call")
		}
		return []byte(filepath.ToSlash(work) + "\n" + filepath.ToSlash(gitDir) + "\n" + filepath.ToSlash(commonDir) + "\n"), nil
	})

	for _, path := range []string{filepath.Join(gitDir, "result.json"), filepath.Join(commonDir, "result.json")} {
		settings := hookGuardSettings(t, scanFlagValues{OutputJSON: path})
		if err := validateHookScanWriteDestinations(settings); err == nil || !strings.Contains(err.Error(), "JSON report") {
			t.Fatalf("validateHookScanWriteDestinations(%s) error = %v, want Git metadata outside the work tree protected", path, err)
		}
	}
}

func TestValidateHookScanWriteDestinationsFollowsSymlinksIntoTheRepository(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs elevated rights or developer mode on Windows")
	}
	root := hookGuardRepo(t)
	link := filepath.Join(t.TempDir(), "into-repo")
	if err := os.Symlink(root, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	settings := hookGuardSettings(t, scanFlagValues{OutputJSON: filepath.Join(link, "new", "result.json")})
	if err := validateHookScanWriteDestinations(settings); err == nil || !strings.Contains(err.Error(), "JSON report") {
		t.Fatalf("validateHookScanWriteDestinations() error = %v, want a symlinked path into the repository rejected", err)
	}
}

func TestScanCommandRejectsHookWithOtherReportModes(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	for _, extra := range []string{"--list-all", "--list-packages", "--outdated", "--auto-sbom"} {
		t.Run(extra, func(t *testing.T) {
			cmd := newScanCmd()
			cmd.SetArgs([]string{"--hook", extra, "."})
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "--hook cannot be combined with "+extra) {
				t.Fatalf("scan --hook %s error = %v, want rejection", extra, err)
			}
		})
	}
}

// TestHookStatusReportsAHookWithoutHookMode covers hooks installed before the
// scan ran with --hook: they still work but do not get the in-repository write
// guard, so status asks for a reinstall instead of reporting them as current.
func TestHookStatusReportsAHookWithoutHookMode(t *testing.T) {
	root := t.TempDir()
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	legacy := "#!/bin/sh\n" + hookMarker + " -- do not edit\n# To remove: packmon hook uninstall\npackmon scan . --fail-on CRITICAL --quiet\n"
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-push"), []byte(legacy), 0o755); err != nil { //nolint:gosec // G306: a Git hook must be executable.
		t.Fatalf("write legacy hook: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "pre-commit"), []byte(hookScript("HIGH")), 0o755); err != nil { //nolint:gosec // G306: a Git hook must be executable.
		t.Fatalf("write current hook: %v", err)
	}
	t.Chdir(root)

	output := captureStdout(t, func() {
		if err := newHookStatusCmd().Execute(); err != nil {
			t.Fatalf("hook status: %v", err)
		}
	})
	if !strings.Contains(output, "pre-push:    packmon hook outdated (run packmon hook install to update)") {
		t.Fatalf("hook status output = %q, want the legacy pre-push hook reported as outdated", output)
	}
	if !strings.Contains(output, "pre-commit:  packmon hook installed") {
		t.Fatalf("hook status output = %q, want the current pre-commit hook reported as installed", output)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}
