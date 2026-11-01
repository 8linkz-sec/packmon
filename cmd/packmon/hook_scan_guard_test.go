package main

import (
	"bytes"
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

// hookGuardResolve resolves hook-mode scan settings for "." with the history
// database pointed outside the repository, so only the destination under test
// can trip the guard. Report paths in flags count as explicit flags.
func hookGuardResolve(t *testing.T, flags scanFlagValues) (scanSettings, scanFlagValues) {
	t.Helper()
	t.Setenv("PACKMON_DB_PATH", t.TempDir())
	t.Setenv("PACKMON_HISTORY_ENABLED", "")

	cfg, _, err := loadCurrentCLIConfig()
	if err != nil {
		t.Fatalf("loadCurrentCLIConfig: %v", err)
	}
	flags.Hook = true
	settings, err := resolveScanSettings(newScanCmd(), cfg, scanTarget{Name: "repo", Path: "."}, flags)
	if err != nil {
		t.Fatalf("resolveScanSettings: %v", err)
	}
	return settings, flags
}

// applyHookGuard runs the guard and returns the adjusted settings, the
// warnings it printed, and its error.
func applyHookGuard(t *testing.T, settings scanSettings, flags scanFlagValues) (scanSettings, string, error) {
	t.Helper()
	var warnings bytes.Buffer
	guarded, err := applyHookScanWriteGuard(newScanCmd(), settings, flags, &warnings)
	return guarded, warnings.String(), err
}

func runHookScan(t *testing.T, flags scanFlagValues) (string, error) {
	t.Helper()
	cmd := newScanCmd()
	cmd.SetContext(context.Background())
	flags.Hook = true
	flags.FailOn = "CRITICAL"
	flags.MaxDepth = 2
	flags.Timeout = 1
	flags.Quiet = true
	var err error
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			err = runScanCommand(cmd, []string{"."}, flags)
		})
	})
	return stderr, err
}

func TestHookScriptRunsTheScanInHookMode(t *testing.T) {
	t.Parallel()

	if script := hookScript("HIGH"); !strings.Contains(script, "packmon scan . --hook --fail-on HIGH --quiet\n") {
		t.Fatalf("hook script = %q, want the scan to run with --hook", script)
	}
}

// TestRunScanCommandHookModeSkipsAUserGlobalRelativeOutputFile is the
// AUDIT-035 regression: a trusted user-global output.file with a relative path
// resolves against the working directory, which is the repository when Git
// runs the hook. The hook scan must still run and gate, but write nothing into
// the repository and say so on stderr even under --quiet.
func TestRunScanCommandHookModeSkipsAUserGlobalRelativeOutputFile(t *testing.T) {
	root := hookGuardRepo(t)
	writeUserGlobalConfig(t, "output:\n  format: json\n  file: packmon-report.json\n")
	t.Setenv("PACKMON_DB_PATH", t.TempDir())

	stderr, err := runHookScan(t, scanFlagValues{})
	if err != nil {
		t.Fatalf("runScanCommand(--hook) error = %v, want the scan to run without the in-repository report", err)
	}
	if !strings.Contains(stderr, "warning: --hook: skipping output.file packmon-report.json (inside the repository)") {
		t.Fatalf("stderr = %q, want the skipped output.file warning", stderr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "packmon-report.json")); !os.IsNotExist(statErr) {
		t.Fatalf("report file in repository: stat error = %v, want it never written", statErr)
	}
}

func TestRunScanCommandHookModeWritesAUserGlobalOutputFileOutsideTheRepository(t *testing.T) {
	hookGuardRepo(t)
	outside := filepath.Join(t.TempDir(), "reports", "packmon-report.json")
	writeUserGlobalConfig(t, "output:\n  format: json\n  file: "+yamlQuote(outside)+"\n")
	t.Setenv("PACKMON_DB_PATH", t.TempDir())

	stderr, err := runHookScan(t, scanFlagValues{})
	if err != nil {
		t.Fatalf("runScanCommand(--hook) error = %v", err)
	}
	if strings.Contains(stderr, "skipping output.file") {
		t.Fatalf("stderr = %q, want no skip warning for a destination outside the repository", stderr)
	}
	if _, statErr := os.Stat(outside); statErr != nil {
		t.Fatalf("report outside the repository: stat error = %v, want it written", statErr)
	}
}

func TestRunScanCommandHookModeRejectsAnExplicitReportFlagInsideTheRepository(t *testing.T) {
	root := hookGuardRepo(t)
	t.Setenv("PACKMON_DB_PATH", t.TempDir())

	_, err := runHookScan(t, scanFlagValues{OutputJSON: "result.json"})
	if err == nil || !strings.Contains(err.Error(), "hook scans never write inside the repository") || !strings.Contains(err.Error(), "--output-json") {
		t.Fatalf("runScanCommand(--hook --output-json) error = %v, want the explicit in-repository flag rejected", err)
	}
	if code := exitCodeForError(err); code != ExitOperational {
		t.Fatalf("exit code = %d, want %d", code, ExitOperational)
	}
	if _, statErr := os.Stat(filepath.Join(root, "result.json")); !os.IsNotExist(statErr) {
		t.Fatalf("report file in repository: stat error = %v, want it never written", statErr)
	}
}

func TestRunScanCommandHookModeRejectsALocalDatabaseInsideTheRepository(t *testing.T) {
	root := hookGuardRepo(t)
	t.Setenv("PACKMON_DB_PATH", "packmon-db")
	t.Setenv("PACKMON_HISTORY_ENABLED", "")

	_, err := runHookScan(t, scanFlagValues{})
	if err == nil || !strings.Contains(err.Error(), "local database") || !strings.Contains(err.Error(), "PACKMON_DB_PATH or db.path") {
		t.Fatalf("runScanCommand(--hook) error = %v, want the in-repository database rejected", err)
	}
	if code := exitCodeForError(err); code != ExitOperational {
		t.Fatalf("exit code = %d, want %d", code, ExitOperational)
	}
	if _, statErr := os.Stat(filepath.Join(root, "packmon-db")); !os.IsNotExist(statErr) {
		t.Fatalf("database directory in repository: stat error = %v, want it never created", statErr)
	}
}

// TestRunScanCommandHookModeSkipsConfigOutputForMultipleTargets keeps the
// multi-target output check from rejecting a hook scan whose only report is a
// config-derived destination that the hook skips anyway.
func TestRunScanCommandHookModeSkipsConfigOutputForMultipleTargets(t *testing.T) {
	root := hookGuardRepo(t)
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	writeUserGlobalConfig(t, "output:\n  format: json\n  file: packmon-report.json\nrepos:\n"+
		"  - name: a\n    path: "+yamlQuote(root)+"\n"+
		"  - name: b\n    path: "+yamlQuote(sub)+"\n")
	t.Setenv("PACKMON_DB_PATH", t.TempDir())

	cmd := newScanCmd()
	cmd.SetContext(context.Background())
	var err error
	stderr := captureStderr(t, func() {
		captureStdout(t, func() {
			err = runScanCommand(cmd, nil, scanFlagValues{All: true, Hook: true, FailOn: "CRITICAL", MaxDepth: 2, Timeout: 1, Quiet: true})
		})
	})
	if err != nil {
		t.Fatalf("runScanCommand(--hook --all) error = %v, want both targets scanned", err)
	}
	if got := strings.Count(stderr, "skipping output.file"); got != 2 {
		t.Fatalf("stderr = %q, want one skip warning per target", stderr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "packmon-report.json")); !os.IsNotExist(statErr) {
		t.Fatalf("report file in repository: stat error = %v, want it never written", statErr)
	}
}

func TestApplyHookScanWriteGuardRejectsEveryExplicitReportFlagInsideTheRepository(t *testing.T) {
	root := hookGuardRepo(t)

	for _, tt := range []struct {
		name  string
		flags scanFlagValues
		want  string
	}{
		{name: "json", flags: scanFlagValues{OutputJSON: "out/result.json"}, want: "--output-json"},
		{name: "sarif", flags: scanFlagValues{OutputSARIF: filepath.Join(root, "result.sarif")}, want: "--output-sarif"},
		{name: "junit", flags: scanFlagValues{OutputJUnit: "result.xml"}, want: "--output-junit"},
		{name: "html", flags: scanFlagValues{OutputHTML: "report.html"}, want: "--html"},
		{name: "git metadata", flags: scanFlagValues{OutputJSON: filepath.Join(".git", "packmon.json")}, want: "--output-json"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			settings, flags := hookGuardResolve(t, tt.flags)
			_, _, err := applyHookGuard(t, settings, flags)
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "hook scans never write inside the repository") {
				t.Fatalf("applyHookScanWriteGuard() error = %v, want %s rejected", err, tt.want)
			}
		})
	}
}

func TestApplyHookScanWriteGuardSkipsEveryConfigReportInsideTheRepository(t *testing.T) {
	for _, format := range []string{"json", "sarif", "junit", "html"} {
		t.Run(format, func(t *testing.T) {
			hookGuardRepo(t)
			writeUserGlobalConfig(t, "output:\n  format: "+format+"\n  file: reports/packmon."+format+"\n")
			settings, flags := hookGuardResolve(t, scanFlagValues{})
			if !hasScanOutputArtifactSettings(settings) {
				t.Fatalf("settings = %+v, want the config output resolved before the guard", settings)
			}

			guarded, warnings, err := applyHookGuard(t, settings, flags)
			if err != nil {
				t.Fatalf("applyHookScanWriteGuard() error = %v, want the config output skipped", err)
			}
			if hasScanOutputArtifactSettings(guarded) {
				t.Fatalf("guarded settings still write a report: %+v", guarded)
			}
			want := "warning: --hook: skipping output.file reports/packmon." + format + " (inside the repository)\n"
			if warnings != want {
				t.Fatalf("warnings = %q, want %q", warnings, want)
			}
		})
	}
}

func TestApplyHookScanWriteGuardKeepsReportsOutsideTheRepository(t *testing.T) {
	hookGuardRepo(t)
	outside := t.TempDir()
	// A sibling whose name extends the repository name is still outside it.
	sibling := filepath.Join(filepath.Dir(mustGetwd(t)), "repo-reports", "result.json")
	configured := filepath.Join(outside, "configured.junit.xml")
	writeUserGlobalConfig(t, "output:\n  format: junit\n  file: "+yamlQuote(configured)+"\n")

	settings, flags := hookGuardResolve(t, scanFlagValues{
		OutputJSON:  sibling,
		OutputSARIF: filepath.Join(outside, "result.sarif"),
		OutputHTML:  filepath.Join(outside, "nested", "report.html"),
	})
	guarded, warnings, err := applyHookGuard(t, settings, flags)
	if err != nil || warnings != "" {
		t.Fatalf("applyHookScanWriteGuard() = %q, %v; want reports outside the repository kept silently", warnings, err)
	}
	if guarded.OutputJSON != sibling || guarded.OutputJUnit != configured || guarded.OutputHTML == "" || guarded.OutputSARIF == "" {
		t.Fatalf("guarded settings = %+v, want every outside destination kept", guarded)
	}
}

func TestApplyHookScanWriteGuardIgnoresNonHookScans(t *testing.T) {
	hookGuardRepo(t)

	settings, flags := hookGuardResolve(t, scanFlagValues{OutputJSON: "result.json"})
	settings.Hook = false
	guarded, warnings, err := applyHookGuard(t, settings, flags)
	if err != nil || warnings != "" || guarded.OutputJSON != "result.json" {
		t.Fatalf("applyHookScanWriteGuard() = %+v, %q, %v; want a manual scan to keep writing where asked", guarded, warnings, err)
	}
}

func TestApplyHookScanWriteGuardRejectsALocalDatabaseInsideTheRepository(t *testing.T) {
	hookGuardRepo(t)

	settings, flags := hookGuardResolve(t, scanFlagValues{})
	t.Setenv("PACKMON_DB_PATH", "packmon-db")
	_, _, err := applyHookGuard(t, settings, flags)
	if err == nil || !strings.Contains(err.Error(), "local database") || !strings.Contains(err.Error(), "PACKMON_DB_PATH or db.path") {
		t.Fatalf("applyHookScanWriteGuard() error = %v, want the in-repository database rejected", err)
	}
}

// TestApplyHookScanWriteGuardSkipsAnUnusedLocalDatabase covers a remote-only
// hook scan with history disabled: it never opens the local database, so its
// location does not matter.
func TestApplyHookScanWriteGuardSkipsAnUnusedLocalDatabase(t *testing.T) {
	hookGuardRepo(t)

	settings, flags := hookGuardResolve(t, scanFlagValues{})
	settings.Mode = "remote"
	t.Setenv("PACKMON_DB_PATH", "packmon-db")
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")
	if _, _, err := applyHookGuard(t, settings, flags); err != nil {
		t.Fatalf("applyHookScanWriteGuard() error = %v, want an unused database location ignored", err)
	}
}

func TestApplyHookScanWriteGuardUsesTheGitReportedRepositoryDirectories(t *testing.T) {
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
		settings, flags := hookGuardResolve(t, scanFlagValues{OutputJSON: path})
		if _, _, err := applyHookGuard(t, settings, flags); err == nil || !strings.Contains(err.Error(), "--output-json") {
			t.Fatalf("applyHookScanWriteGuard(%s) error = %v, want Git metadata outside the work tree protected", path, err)
		}
	}
}

// skipOrFailSymlink skips on Windows, where creating symlinks needs developer
// mode or elevated rights, and fails elsewhere.
func skipOrFailSymlink(t *testing.T, err error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skipf("creating symlinks needs developer mode or elevated rights on Windows: %v", err)
	}
	t.Fatalf("symlink: %v", err)
}

func TestPathInsideAnyRootFollowsSymlinksIntoTheRepository(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "into-repo")
	if err := os.Symlink(root, link); err != nil {
		skipOrFailSymlink(t, err)
	}
	if !pathInsideAnyRoot([]string{root}, filepath.Join(link, "new", "result.json")) {
		t.Fatal("pathInsideAnyRoot() = false, want a path through a symlink into the repository inside")
	}
}

// TestPathInsideAnyRootFollowsDanglingSymlinks covers a destination that is,
// or runs through, a symlink whose target does not exist yet: writing it would
// create the target, so the target path decides.
func TestPathInsideAnyRootFollowsDanglingSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	intoRepo := filepath.Join(outside, "report.json")
	if err := os.Symlink(filepath.Join(root, "missing", "report.json"), intoRepo); err != nil {
		skipOrFailSymlink(t, err)
	}
	intoRepoDir := filepath.Join(outside, "reports")
	if err := os.Symlink(filepath.Join(root, "missing-dir"), intoRepoDir); err != nil {
		skipOrFailSymlink(t, err)
	}
	relativeIntoRepo := filepath.Join(root, "linked.json")
	if err := os.Symlink(filepath.Join("missing", "linked.json"), relativeIntoRepo); err != nil {
		skipOrFailSymlink(t, err)
	}
	away := filepath.Join(root, "away.json")
	if err := os.Symlink(filepath.Join(outside, "missing", "away.json"), away); err != nil {
		skipOrFailSymlink(t, err)
	}

	for _, path := range []string{intoRepo, filepath.Join(intoRepoDir, "result.json"), relativeIntoRepo} {
		if !pathInsideAnyRoot([]string{root}, path) {
			t.Fatalf("pathInsideAnyRoot(%s) = false, want a dangling symlink into the repository inside", path)
		}
	}
	// A dangling link that lives in the repository but points out of it is
	// treated conservatively: the destination path itself is inside.
	if !pathInsideAnyRoot([]string{root}, away) {
		t.Fatalf("pathInsideAnyRoot(%s) = false, want a link that lives in the repository inside", away)
	}
}

// TestPathInsideAnyRootIgnoresCaseOnCaseInsensitiveFilesystems compares by
// file identity, so a destination spelled with different case still counts as
// inside the repository where the filesystem treats both spellings as one
// directory (Windows, default macOS).
func TestPathInsideAnyRootIgnoresCaseOnCaseInsensitiveFilesystems(t *testing.T) {
	root := filepath.Join(t.TempDir(), "CaseRepo")
	if err := os.MkdirAll(filepath.Join(root, "Reports"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	swapped := filepath.Join(filepath.Dir(root), "caserepo", "REPORTS")
	if _, err := os.Stat(swapped); err != nil {
		t.Skipf("filesystem is case-sensitive (stat %s: %v); nothing to compare", filepath.Base(swapped), err)
	}

	for _, path := range []string{filepath.Join(swapped, "result.json"), filepath.Join(swapped, "new", "result.json")} {
		if !pathInsideAnyRoot([]string{root}, path) {
			t.Fatalf("pathInsideAnyRoot(%s) = false, want a differently cased path into the repository inside", path)
		}
	}
	if pathInsideAnyRoot([]string{root}, filepath.Join(filepath.Dir(root), "caserepo-other", "result.json")) {
		t.Fatal("pathInsideAnyRoot() = true for a sibling directory, want outside")
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
