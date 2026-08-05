package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestHookScriptAlwaysPinsAUsableThreshold covers the generated Git hook. The
// script runs on every push, so an unvalidated `--fail-on` value would either
// break the hook or -- worse -- be interpreted as a laxer threshold than the
// user intended. Anything unusable falls back to CRITICAL.
func TestHookScriptAlwaysPinsAUsableThreshold(t *testing.T) {
	t.Parallel()

	for _, failOn := range []string{"", "   ", "not-a-severity", "URGENT"} {
		script := hookScript(failOn)
		if !strings.Contains(script, "--fail-on CRITICAL") {
			t.Errorf("hookScript(%q) = %q, want the CRITICAL fallback", failOn, script)
		}
	}

	for _, failOn := range []string{"HIGH", "high", "  medium  "} {
		script := hookScript(failOn)
		want := "--fail-on " + normalizeSeverityString(failOn)
		if !strings.Contains(script, want) {
			t.Errorf("hookScript(%q) = %q, want %q", failOn, script, want)
		}
	}
}

// TestHookScriptIsSelfDescribing keeps the generated file recognisable. Users
// find these hooks months later, so the script has to say what wrote it and how
// to remove it.
func TestHookScriptIsSelfDescribing(t *testing.T) {
	t.Parallel()

	script := hookScript("HIGH")
	for _, want := range []string{"#!/bin/sh", "packmon managed hook", "packmon hook uninstall", "packmon scan ."} {
		if !strings.Contains(script, want) {
			t.Errorf("hook script is missing %q:\n%s", want, script)
		}
	}
}

// TestFindGitRootWalksUpToTheRepository covers the discovery used by
// `packmon hook install`. Installing into the wrong directory would leave the
// user with a hook that never runs.
func TestFindGitRootWalksUpToTheRepository(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o750); err != nil {
		t.Fatalf("create .git: %v", err)
	}
	nested := filepath.Join(root, "src", "pkg")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}

	for _, start := range []string{root, nested} {
		got := findGitRoot(start)
		if !sameCleanPath(got, root) {
			t.Errorf("findGitRoot(%q) = %q, want %q", start, got, root)
		}
	}
}

// TestFindGitRootPicksTheNearestRepository covers the walk-up. With nested
// repositories -- a vendored checkout inside a project, say -- the hook must be
// installed into the innermost one, not the outer project.
//
// Note: this deliberately does not assert that a directory outside any
// repository yields "". Under `go test` the temp directory lives inside this
// repository's own tree, so the walk legitimately finds Packmon's `.git`.
func TestFindGitRootPicksTheNearestRepository(t *testing.T) {
	t.Parallel()

	outer := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outer, ".git"), 0o750); err != nil {
		t.Fatalf("create outer .git: %v", err)
	}
	inner := filepath.Join(outer, "vendor", "nested")
	if err := os.MkdirAll(filepath.Join(inner, ".git"), 0o750); err != nil {
		t.Fatalf("create inner .git: %v", err)
	}
	deep := filepath.Join(inner, "src")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatalf("create nested source dir: %v", err)
	}

	if got := findGitRoot(deep); !sameCleanPath(got, inner) {
		t.Fatalf("findGitRoot(%q) = %q, want the nearest repository %q", deep, got, inner)
	}
	if got := findGitRoot(filepath.Join(outer, "docs")); !sameCleanPath(got, outer) {
		t.Fatalf("findGitRoot outside the nested repo = %q, want %q", got, outer)
	}
}

// TestFindGitRootFollowsAGitdirFile covers the worktree and submodule layout,
// where `.git` is a file pointing at the real git directory rather than a
// directory itself. Without this the hook would land in a path that git ignores.
func TestFindGitRootFollowsAGitdirFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	realGitDir := filepath.Join(root, "actual-git-dir")
	if err := os.MkdirAll(realGitDir, 0o750); err != nil {
		t.Fatalf("create git dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: "+realGitDir+"\n"), 0o600); err != nil {
		t.Fatalf("write gitdir file: %v", err)
	}

	if got := findGitRoot(root); !sameCleanPath(got, root) {
		t.Fatalf("findGitRoot = %q, want %q", got, root)
	}
	if got := gitDirFileTarget(root); !sameCleanPath(got, realGitDir) {
		t.Fatalf("gitDirFileTarget = %q, want %q", got, realGitDir)
	}
}

// TestGitDirFileTargetRejectsUnusableContent covers the parsing of the `.git`
// file. Anything that is not a `gitdir:` pointer must be ignored rather than
// turned into a path the hook installer would write into.
func TestGitDirFileTargetRejectsUnusableContent(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		"",
		"not a gitdir pointer\n",
		"gitdir:\n",
		"gitdir:   \n",
		"worktree: /somewhere\n",
	} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, ".git"), []byte(content), 0o600); err != nil {
			t.Fatalf("write .git: %v", err)
		}
		if got := gitDirFileTarget(root); got != "" {
			t.Errorf("gitDirFileTarget(%q) = %q, want empty", content, got)
		}
	}

	// A missing .git file is likewise not an error.
	if got := gitDirFileTarget(t.TempDir()); got != "" {
		t.Errorf("gitDirFileTarget(no file) = %q, want empty", got)
	}
}

// TestGitDirFileTargetResolvesARelativePointer covers the relative form git uses
// for submodules, which has to be resolved against the repository root.
func TestGitDirFileTargetResolvesARelativePointer(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: ../shared/modules/pkg\n"), 0o600); err != nil {
		t.Fatalf("write .git: %v", err)
	}

	got := gitDirFileTarget(root)
	if !filepath.IsAbs(got) {
		t.Fatalf("gitDirFileTarget = %q, want an absolute path", got)
	}
	want := filepath.Clean(filepath.Join(root, "..", "shared", "modules", "pkg"))
	if !sameCleanPath(got, want) {
		t.Fatalf("gitDirFileTarget = %q, want %q", got, want)
	}
}

// TestFindGitHooksDirFallsBackThroughEveryLayout pins the resolution order.
// Without a usable git binary the gitdir pointer decides, and failing that the
// plain `.git/hooks` layout.
func TestFindGitHooksDirFallsBackThroughEveryLayout(t *testing.T) {
	t.Parallel()

	// Plain repository: hooks live under .git/hooks.
	plain := t.TempDir()
	if err := os.MkdirAll(filepath.Join(plain, ".git"), 0o750); err != nil {
		t.Fatalf("create .git: %v", err)
	}
	if got := findGitHooksDir(plain); !sameCleanPath(got, filepath.Join(plain, ".git", "hooks")) {
		t.Errorf("findGitHooksDir(plain) = %q, want .git/hooks", got)
	}

	// gitdir pointer: hooks live under the referenced directory.
	pointed := t.TempDir()
	realGitDir := filepath.Join(pointed, "actual-git-dir")
	if err := os.MkdirAll(realGitDir, 0o750); err != nil {
		t.Fatalf("create git dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pointed, ".git"), []byte("gitdir: "+realGitDir+"\n"), 0o600); err != nil {
		t.Fatalf("write gitdir file: %v", err)
	}
	if got := findGitHooksDir(pointed); !sameCleanPath(got, filepath.Join(realGitDir, "hooks")) {
		t.Errorf("findGitHooksDir(gitdir pointer) = %q, want %q", got, filepath.Join(realGitDir, "hooks"))
	}
}

// TestSameCleanPathMatchesPlatformSemantics covers the comparison used to decide
// whether git reported the repository the user asked about. Windows paths are
// case-insensitive; treating them as case-sensitive would reject a correct match
// and silently fall back to the wrong hooks directory.
func TestSameCleanPathMatchesPlatformSemantics(t *testing.T) {
	t.Parallel()

	base := filepath.Join("project", "repo")
	if !sameCleanPath(base, filepath.Join("project", "sub", "..", "repo")) {
		t.Error("sameCleanPath did not normalise a traversal segment")
	}
	if !sameCleanPath("  "+base+"  ", base) {
		t.Error("sameCleanPath did not trim surrounding whitespace")
	}
	if sameCleanPath(base, filepath.Join("project", "other")) {
		t.Error("sameCleanPath matched two different paths")
	}

	upper := strings.ToUpper(base)
	if runtime.GOOS == "windows" {
		if !sameCleanPath(base, upper) {
			t.Error("sameCleanPath is case-sensitive on Windows")
		}
	} else if sameCleanPath(base, upper) {
		t.Error("sameCleanPath is case-insensitive on a case-sensitive platform")
	}
}

// TestHookTypesCoverTheDocumentedHooks keeps the managed hook list in step with
// what the CLI advertises; a missing entry means `hook install` silently skips
// one.
func TestHookTypesCoverTheDocumentedHooks(t *testing.T) {
	t.Parallel()

	want := map[string]bool{"pre-push": false, "pre-commit": false}
	for _, hook := range hookTypes {
		if _, ok := want[hook]; !ok {
			t.Errorf("unexpected managed hook %q", hook)
		}
		want[hook] = true
	}
	for hook, seen := range want {
		if !seen {
			t.Errorf("managed hook %q is missing", hook)
		}
	}
}
