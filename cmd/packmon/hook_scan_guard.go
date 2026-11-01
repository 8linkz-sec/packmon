package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/scanner"
	"github.com/8linkz-sec/packmon/internal/termtext"
	"github.com/spf13/cobra"
)

// hookScanWriteGuardHint is the shared head of every hook-mode write refusal.
const hookScanWriteGuardHint = "hook scans never write inside the repository"

// maxHookGuardSymlinkHops bounds dangling-symlink resolution, so a link loop
// cannot spin the containment check.
const maxHookGuardSymlinkHops = 40

// applyHookScanWriteGuard enforces the hook contract (F029): apart from writing
// the managed hook itself, neither installation nor hook execution may write
// repository data, generated files, configuration, or Git metadata. It runs
// for `scan --hook` before the scan and only constrains destinations that
// resolve inside the repository work tree or its Git directories:
//
//   - A config-derived report destination (output.file) inside the repository
//     is skipped: one warning goes to stderr (also under --quiet), the path is
//     cleared, and the scan still runs and gates. A relative output.file
//     resolves against the working directory, which is the repository when
//     Git runs the hook, so blocking on it would disable the gate entirely.
//   - An explicit report flag (--output-json, --output-sarif, --output-junit,
//     --html) inside the repository is a hard error: the caller asked for a
//     write the hook cannot perform read-only.
//   - A local database directory inside the repository is a hard error when
//     the scan opens it (local checker or history).
//
// Destinations outside the repository are kept. Manual scans are unaffected.
func applyHookScanWriteGuard(cmd *cobra.Command, settings scanSettings, flags scanFlagValues, warnings io.Writer) (scanSettings, error) {
	if !settings.Hook {
		return settings, nil
	}
	roots := hookScanProtectedRoots(settings.Path)

	for _, artifact := range scanOutputArtifacts {
		path := strings.TrimSpace(artifact.pathFromSettings(settings))
		if path == "" || !pathInsideAnyRoot(roots, path) {
			continue
		}
		if scanOutputArtifactFromFlag(cmd, artifact, flags) {
			return settings, fmt.Errorf("%s: --%s %q is inside the repository; write the %s report outside the repository or drop the flag",
				hookScanWriteGuardHint, artifact.flagName, termtext.Sanitize(path), artifact.displayName)
		}
		_, _ = fmt.Fprintf(warnings, "warning: --hook: skipping output.file %s (inside the repository)\n", termtext.Sanitize(path))
		artifact.setPath(&settings, "")
	}

	if !hookScanUsesLocalDatabase(settings) {
		return settings, nil
	}
	dbPath, err := resolveLocalDBPath()
	if err != nil {
		return settings, err
	}
	if pathInsideAnyRoot(roots, filepath.Dir(dbPath)) {
		return settings, fmt.Errorf("%s: the local database directory %q is inside the repository; set PACKMON_DB_PATH or db.path to a directory outside the repository",
			hookScanWriteGuardHint, termtext.Sanitize(filepath.Dir(dbPath)))
	}
	return settings, nil
}

// scanOutputArtifactFromFlag reports whether the artifact's path came from its
// command-line flag rather than from config, mirroring
// applyScanOutputFlagSettings, which lets the flag win.
func scanOutputArtifactFromFlag(cmd *cobra.Command, artifact scanOutputArtifact, flags scanFlagValues) bool {
	return commandFlagChanged(cmd, artifact.flagName) || strings.TrimSpace(artifact.pathFromFlags(flags)) != ""
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
// directory, is one of roots or below one of them. It checks two ways and
// treats either match as inside:
//
//   - by name: the path with symlinks resolved (dangling ones followed to
//     their target) lies lexically below a root, and
//   - by identity: the deepest existing ancestor of that resolved path, or
//     one of its parents, is the same directory as a root (os.SameFile). This
//     catches spellings that a name comparison misses, such as a different
//     letter case on a case-insensitive filesystem.
//
// The unresolved path is checked as well, so a symlink that lives in the
// repository counts as inside even when it points out of it (conservative).
func pathInsideAnyRoot(roots []string, path string) bool {
	targets := []string{resolveHookGuardPath(path)}
	if abs, err := filepath.Abs(path); err == nil {
		targets = append(targets, abs)
	}
	rootInfos := make([]os.FileInfo, 0, len(roots))
	for _, root := range roots {
		names := []string{resolveHookGuardPath(root)}
		if abs, err := filepath.Abs(root); err == nil {
			names = append(names, abs)
		}
		for _, name := range names {
			for _, target := range targets {
				if pathWithinDir(name, target) {
					return true
				}
			}
		}
		if info, err := os.Stat(names[0]); err == nil {
			rootInfos = append(rootInfos, info)
		}
	}
	for _, target := range targets {
		if ancestorIsSameFileAsAny(target, rootInfos) {
			return true
		}
	}
	return false
}

// ancestorIsSameFileAsAny walks from the deepest existing ancestor of target
// up to the filesystem root and reports whether any of them is one of roots.
func ancestorIsSameFileAsAny(target string, roots []os.FileInfo) bool {
	if len(roots) == 0 {
		return false
	}
	dir := target
	for {
		if info, err := os.Stat(dir); err == nil {
			for _, root := range roots {
				if os.SameFile(info, root) {
					return true
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// resolveHookGuardPath makes path absolute and resolves the symlinks in its
// longest existing prefix, so a path through a symlink is compared by where a
// write would really land, including parts not created yet. A dangling
// symlink in that prefix is followed to its (missing) target, because writing
// through it creates that target.
func resolveHookGuardPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	for hops := 0; hops < maxHookGuardSymlinkHops; hops++ {
		existing, rest := longestLstatPrefix(abs)
		if existing == "" {
			return abs
		}
		if resolved, err := filepath.EvalSymlinks(existing); err == nil {
			return filepath.Join(resolved, rest)
		}
		target, ok := danglingSymlinkTarget(existing)
		if !ok {
			return abs
		}
		abs = filepath.Join(target, rest)
	}
	return abs
}

// longestLstatPrefix splits abs into its longest prefix that exists (without
// following a final symlink) and the remaining, not yet existing, elements.
func longestLstatPrefix(abs string) (string, string) {
	existing, rest := abs, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			return existing, rest
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", ""
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}
}

// danglingSymlinkTarget returns the absolute target of the symlink at path
// when filepath.EvalSymlinks could not resolve it.
func danglingSymlinkTarget(path string) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", false
	}
	target, err := os.Readlink(path)
	if err != nil {
		return "", false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return filepath.Clean(target), true
}

// pathWithinDir reports whether target is dir or below it by name.
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
