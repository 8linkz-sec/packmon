package sbomgen

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeJSONFixture writes a JSON manifest and returns its path.
func writeJSONFixture(t *testing.T, dir, name string, value any) string {
	t.Helper()

	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestValidateNPMWorkspacePatternRejectsEscapes is the security-relevant one.
// The workspace patterns come from the scanned repository's package.json, so a
// pattern must never be able to send the generator outside the scan root.
func TestValidateNPMWorkspacePatternRejectsEscapes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	bounds, err := newScanRootBounds(root)
	if err != nil {
		t.Fatalf("newScanRootBounds: %v", err)
	}

	// Note: an absolute pattern is only recognised as such by the host platform's
	// rules, so the fixture uses a genuinely absolute path for this OS. A POSIX
	// path on Windows is a *relative* path there and is correctly joined into the
	// scan root instead of being rejected.
	absolutePattern := "/etc/passwd"
	if runtime.GOOS == "windows" {
		absolutePattern = `C:\Windows\System32`
	}

	for _, pattern := range []string{
		"../outside",
		"../../etc/*",
		"packages/../../outside",
		absolutePattern,
	} {
		err := validateNPMWorkspacePattern(bounds, root, pattern)
		if err == nil {
			t.Errorf("pattern %q was accepted", pattern)
			continue
		}
		if !errors.Is(err, errScanRootEscape) {
			t.Errorf("pattern %q error = %v, want the scan-root escape sentinel", pattern, err)
		}
	}
}

// TestValidateNPMWorkspacePatternAcceptsInBoundPatterns is the positive side,
// including the glob forms npm actually uses. The check has to look at the
// literal prefix before the first wildcard, not at the raw pattern.
func TestValidateNPMWorkspacePatternAcceptsInBoundPatterns(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	bounds, err := newScanRootBounds(root)
	if err != nil {
		t.Fatalf("newScanRootBounds: %v", err)
	}

	for _, pattern := range []string{
		"packages/*",
		"packages/**",
		"apps/web",
		"*",
		"**",
		"pkg-[abc]/*",
		"packages/?pp",
	} {
		if err := validateNPMWorkspacePattern(bounds, root, pattern); err != nil {
			t.Errorf("pattern %q was rejected: %v", pattern, err)
		}
	}
}

// TestValidateNPMWorkspacePatternIsInertWithoutBounds covers the unbounded mode,
// where no scan root was configured and every pattern is the caller's own
// responsibility.
func TestValidateNPMWorkspacePatternIsInertWithoutBounds(t *testing.T) {
	t.Parallel()

	var bounds scanRootBounds
	for _, pattern := range []string{"../outside", "/etc/passwd", "packages/*"} {
		if err := validateNPMWorkspacePattern(bounds, "project", pattern); err != nil {
			t.Errorf("pattern %q was rejected without bounds: %v", pattern, err)
		}
	}
}

// TestNPMWorkspaceGlobsReadsBothManifestShapes covers the two forms npm accepts
// for the `workspaces` key. Supporting only one would silently skip half the
// monorepos Packmon is pointed at.
func TestNPMWorkspaceGlobsReadsBothManifestShapes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	arrayForm := writeJSONFixture(t, filepath.Join(root, "array"), "package.json", map[string]any{
		"name":       "root",
		"workspaces": []string{"packages/*", "apps/web"},
	})
	globs, err := npmWorkspaceGlobs(root, arrayForm)
	if err != nil {
		t.Fatalf("array form: %v", err)
	}
	if len(globs) != 2 || globs[0] != "packages/*" || globs[1] != "apps/web" {
		t.Fatalf("array form globs = %v, want both patterns in order", globs)
	}

	objectForm := writeJSONFixture(t, filepath.Join(root, "object"), "package.json", map[string]any{
		"name": "root",
		"workspaces": map[string]any{
			"packages": []string{"packages/*"},
			"nohoist":  []string{"**/react-native"},
		},
	})
	globs, err = npmWorkspaceGlobs(root, objectForm)
	if err != nil {
		t.Fatalf("object form: %v", err)
	}
	if len(globs) != 1 || globs[0] != "packages/*" {
		t.Fatalf("object form globs = %v, want the packages list", globs)
	}
}

// TestNPMWorkspaceGlobsHandlesManifestsWithoutWorkspaces covers the ordinary
// single-package repository, which must produce no globs and no error.
func TestNPMWorkspaceGlobsHandlesManifestsWithoutWorkspaces(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	plain := writeJSONFixture(t, filepath.Join(root, "plain"), "package.json", map[string]any{
		"name":    "single",
		"version": "1.0.0",
	})

	globs, err := npmWorkspaceGlobs(root, plain)
	if err != nil {
		t.Fatalf("npmWorkspaceGlobs: %v", err)
	}
	if len(globs) != 0 {
		t.Fatalf("globs = %v, want none", globs)
	}
}

// TestNPMWorkspaceGlobsRejectsAnUnusableWorkspacesValue keeps a malformed
// manifest from being read as "no workspaces", which would silently scan only
// the root package of a monorepo.
func TestNPMWorkspaceGlobsRejectsAnUnusableWorkspacesValue(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	dir := filepath.Join(root, "broken")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create dir: %v", err)
	}
	path := filepath.Join(dir, "package.json")
	if err := os.WriteFile(path, []byte(`{"workspaces": 42}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	if globs, err := npmWorkspaceGlobs(root, path); err == nil {
		t.Fatalf("globs = %v, nil; want an error for an unusable workspaces value", globs)
	}
}

// TestNPMWorkspaceGlobsRefusesAManifestOutsideTheScanRoot pins that the manifest
// read itself is bounded, not just the patterns it contains.
func TestNPMWorkspaceGlobsRefusesAManifestOutsideTheScanRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := writeJSONFixture(t, t.TempDir(), "package.json", map[string]any{"name": "outside"})

	if _, err := npmWorkspaceGlobs(root, outside); err == nil {
		t.Fatal("a manifest outside the scan root was read")
	}
}

// TestDepthExceededBoundsTheWalk covers the recursion limit on manifest
// discovery. Without it a deeply nested monorepo -- or a symlink loop -- would
// make detection walk indefinitely.
func TestDepthExceededBoundsTheWalk(t *testing.T) {
	t.Parallel()

	root := filepath.Join("project", "root")

	if depthExceeded(root, root, 0) {
		t.Error("the root itself was reported as too deep")
	}
	if depthExceeded(root, filepath.Join(root, "a"), 1) {
		t.Error("a first-level directory was rejected at maxDepth 1")
	}
	if !depthExceeded(root, filepath.Join(root, "a", "b"), 1) {
		t.Error("a second-level directory was accepted at maxDepth 1")
	}
	if depthExceeded(root, filepath.Join(root, "a", "b", "c"), 3) {
		t.Error("a third-level directory was rejected at maxDepth 3")
	}

	// maxDepth 0 confines the walk to the root itself; only a *negative* limit
	// means "unlimited".
	if !depthExceeded(root, filepath.Join(root, "a"), 0) {
		t.Error("maxDepth 0 admitted a subdirectory; want the walk confined to the root")
	}
	if depthExceeded(root, root, 0) {
		t.Error("maxDepth 0 rejected the root itself")
	}
	if depthExceeded(root, filepath.Join(root, "a", "b", "c", "d"), -1) {
		t.Error("a negative maxDepth rejected a nested directory; want it unlimited")
	}
}
