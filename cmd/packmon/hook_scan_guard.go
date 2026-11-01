package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/termtext"
)

// hookScanWriteGuardHint is the shared tail of every hook-mode write refusal.
const hookScanWriteGuardHint = "hook scans never write inside the repository"

// validateHookScanWriteDestinations enforces the hook contract (F029): apart
// from writing the managed hook itself, neither installation nor hook
// execution may write repository data, generated files, configuration, or Git
// metadata. A `scan --hook` therefore refuses, before it scans, every report
// destination and a used local database that resolve inside the repository
// work tree or its Git directories. A relative path resolves against the
// working directory, which is the repository when Git runs the hook, so a
// trusted user-global output.file such as `packmon.json` is refused too.
// Destinations outside the repository are kept. Manual scans are unaffected.
func validateHookScanWriteDestinations(settings scanSettings) error {
	if !settings.Hook {
		return nil
	}
	roots := hookScanProtectedRoots(settings.Path)

	for _, artifact := range scanOutputArtifacts {
		path := strings.TrimSpace(artifact.pathFromSettings(settings))
		if path == "" {
			continue
		}
		if pathInsideAnyRoot(roots, path) {
			return fmt.Errorf("%s: the %s report destination %q is inside the repository; point output.file or --%s outside the repository or remove it",
				hookScanWriteGuardHint, artifact.displayName, termtext.Sanitize(path), artifact.flagName)
		}
	}

	if !hookScanUsesLocalDatabase(settings) {
		return nil
	}
	dbPath, err := resolveLocalDBPath()
	if err != nil {
		return err
	}
	if pathInsideAnyRoot(roots, filepath.Dir(dbPath)) {
		return fmt.Errorf("%s: the local database directory %q is inside the repository; set PACKMON_DB_PATH or db.path to a directory outside the repository",
			hookScanWriteGuardHint, termtext.Sanitize(filepath.Dir(dbPath)))
	}
	return nil
}

// hookScanUsesLocalDatabase reports whether the scan opens the local SQLite
// database, either as the local advisory checker or to record scan history.
// An invalid history setting counts as "used": the pipeline reports it later.
func hookScanUsesLocalDatabase(settings scanSettings) bool {
	if enabled, err := historyEnabled(); err != nil || enabled {
		return true
	}
	mode, err := scanner.ParseMode(settings.Mode)
	if err != nil {
		return true
	}
	return scanNeedsLocalChecker(mode, settings.RequireRemote)
}

// hookScanProtectedRoots returns the directories a hook scan must not write
// into: the scan path, the Git work tree around it, and the Git directory and
// common directory (which live outside the work tree for linked worktrees).
// Git reports them; without Git the filesystem walk of findGitRoot is used.
func hookScanProtectedRoots(scanPath string) []string {
	if strings.TrimSpace(scanPath) == "" {
		scanPath = "."
	}
	absScan, err := filepath.Abs(scanPath)
	if err != nil {
		absScan = filepath.Clean(scanPath)
	}
	roots := []string{absScan}
	if root := findGitRoot(absScan); root != "" {
		roots = append(roots, root)
		if gitDir := gitDirFileTarget(root); gitDir != "" {
			roots = append(roots, gitDir)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), gitMetadataTimeout)
	defer cancel()
	out, err := gitCommandOutput(ctx, "-C", absScan, "rev-parse", "--show-toplevel", "--absolute-git-dir", "--git-common-dir")
	if err != nil {
		return roots
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		dir := strings.TrimSpace(line)
		if dir == "" {
			continue
		}
		if !filepath.IsAbs(dir) {
			// --git-common-dir may be relative to the directory git ran in.
			dir = filepath.Join(absScan, dir)
		}
		roots = append(roots, filepath.Clean(dir))
	}
	return roots
}

// pathInsideAnyRoot reports whether path, resolved against the working
// directory and through symlinks of its existing ancestors, is one of roots or
// below one of them.
func pathInsideAnyRoot(roots []string, path string) bool {
	target := resolveExistingPathPrefix(path)
	for _, root := range roots {
		if pathWithinDir(resolveExistingPathPrefix(root), target) {
			return true
		}
	}
	return false
}

// resolveExistingPathPrefix makes path absolute and resolves symlinks in its
// longest existing prefix, so a path through a symlink into the repository is
// compared by where it really lands, including parts not created yet.
func resolveExistingPathPrefix(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	existing, rest := abs, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return abs
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return abs
	}
	return filepath.Join(resolved, rest)
}

// pathWithinDir reports whether target is dir or below it. filepath.Rel
// compares path elements case-insensitively on Windows.
func pathWithinDir(dir, target string) bool {
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// rejectHookWithReportModes keeps `scan --hook` to the plain gated scan: the
// report modes and auto-SBOM generation have their own write paths (HTML
// reports, generated SBOM snapshots) that the hook never needs.
func rejectHookWithReportModes(hook bool, modes map[string]bool) error {
	if !hook {
		return nil
	}
	for _, name := range []string{"--list-packages", "--outdated", "--list-all", "--auto-sbom"} {
		if modes[name] {
			return fmt.Errorf("--hook cannot be combined with %s", name)
		}
	}
	return nil
}
