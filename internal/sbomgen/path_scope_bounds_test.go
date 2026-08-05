package sbomgen

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRelWithinRootRejectsEveryEscapeShape covers the predicate every scan-root
// check ultimately reduces to. It decides whether a resolved path is still
// inside the directory the user asked to scan, so a false positive here is a
// file read outside the scan root.
func TestRelWithinRootRejectsEveryEscapeShape(t *testing.T) {
	t.Parallel()

	if !relWithinRoot(".") {
		t.Error("the root itself was rejected")
	}
	for _, rel := range []string{"pkg", filepath.Join("pkg", "sub"), "file.json"} {
		if !relWithinRoot(rel) {
			t.Errorf("relWithinRoot(%q) = false, want it inside the root", rel)
		}
	}
	for _, rel := range []string{
		"..",
		".." + string(filepath.Separator) + "secrets",
		filepath.Join("..", "..", "etc", "passwd"),
	} {
		if relWithinRoot(rel) {
			t.Errorf("relWithinRoot(%q) = true, want an escape", rel)
		}
	}

	absolute := "/etc/passwd"
	if runtime.GOOS == "windows" {
		absolute = `C:\Windows\System32\config`
	}
	if relWithinRoot(absolute) {
		t.Errorf("relWithinRoot(%q) = true, want an absolute path rejected", absolute)
	}
}

// TestPathWithinRootComparesResolvedPaths covers the wrapper used against real
// directories. Comparing uncleaned paths would let "root/../root2" pass.
func TestPathWithinRootComparesResolvedPaths(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if !pathWithinRoot(root, filepath.Join(root, "pkg", "manifest.json")) {
		t.Error("a file below the root was reported as outside it")
	}
	if !pathWithinRoot(root, root) {
		t.Error("the root itself was reported as outside itself")
	}
	if pathWithinRoot(root, filepath.Join(root, "..", "sibling")) {
		t.Error("a sibling directory was reported as inside the root")
	}
	// A path that only shares a name prefix is not inside the root.
	if pathWithinRoot(root, root+"-other") {
		t.Error("a name-prefixed sibling was reported as inside the root")
	}
}

// TestNewScanRootBoundsResolvesSymlinks covers the second root the bounds carry.
// The check has to compare against the *resolved* root as well, otherwise a
// symlinked scan root would make every real path look like an escape.
func TestNewScanRootBoundsResolvesSymlinks(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	bounds, err := newScanRootBounds(root)
	if err != nil {
		t.Fatalf("newScanRootBounds: %v", err)
	}
	if !bounds.enabled() {
		t.Fatal("bounds built from a real directory report themselves disabled")
	}
	if bounds.absRoot == "" || bounds.realRoot == "" {
		t.Fatalf("bounds = %+v, want both roots populated", bounds)
	}
	if !filepath.IsAbs(bounds.absRoot) {
		t.Errorf("absRoot = %q, want an absolute path", bounds.absRoot)
	}
}

// TestNewScanRootBoundsRejectsAMissingRoot keeps a typo'd --path from being
// treated as an unbounded scan.
func TestNewScanRootBoundsRejectsAMissingRoot(t *testing.T) {
	t.Parallel()

	if _, err := newScanRootBounds(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("newScanRootBounds(missing) = nil error, want a refusal")
	}
}

// TestScanRootBoundsRequireRejectsEscapes is the behavioural check: a path
// outside the scan root must be refused with the sentinel, so callers can tell
// an escape apart from an I/O failure.
func TestScanRootBoundsRequireRejectsEscapes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	inside := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(inside, []byte("{}"), 0o600); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}

	bounds, err := newScanRootBounds(root)
	if err != nil {
		t.Fatalf("newScanRootBounds: %v", err)
	}

	if err := bounds.requireExisting(inside); err != nil {
		t.Fatalf("requireExisting(inside) = %v, want it accepted", err)
	}

	outside := filepath.Join(root, "..", "outside.json")
	err = bounds.requireDerived(outside)
	if !errors.Is(err, errScanRootEscape) {
		t.Fatalf("requireDerived(outside) = %v, want the scan-root escape sentinel", err)
	}
	// The message must name the path relatively, not leak the absolute location.
	if strings.Contains(err.Error(), root) {
		t.Errorf("escape error = %v, want a relative path in the message", err)
	}
}

// TestScanRootBoundsRequireDistinguishesDerivedFromExisting covers the two
// modes. A derived path that does not exist yet is fine -- the generator is
// about to create it -- while an input file that must already exist is not.
func TestScanRootBoundsRequireDistinguishesDerivedFromExisting(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	bounds, err := newScanRootBounds(root)
	if err != nil {
		t.Fatalf("newScanRootBounds: %v", err)
	}

	notYetCreated := filepath.Join(root, "generated", "sbom.json")
	if err := bounds.requireDerived(notYetCreated); err != nil {
		t.Errorf("requireDerived(not yet created) = %v, want it accepted", err)
	}
	if err := bounds.requireExisting(notYetCreated); err == nil {
		t.Error("requireExisting(missing) = nil, want a refusal")
	}
}

// TestScanRootBoundsAreInertWhenDisabled covers the unbounded mode used when no
// scan root was configured: the checks must pass everything rather than reject
// everything.
func TestScanRootBoundsAreInertWhenDisabled(t *testing.T) {
	t.Parallel()

	var bounds scanRootBounds
	if bounds.enabled() {
		t.Fatal("zero-value bounds report themselves enabled")
	}
	if err := bounds.requireExisting(filepath.Join("any", "path")); err != nil {
		t.Fatalf("requireExisting on disabled bounds = %v, want a no-op", err)
	}
	if err := bounds.requireDerived("/somewhere/else"); err != nil {
		t.Fatalf("requireDerived on disabled bounds = %v, want a no-op", err)
	}
}

// TestRelDisplayFallsBackToTheRawPath covers the message helper: when a path
// cannot be expressed relative to the root, the error still has to name
// something the user can act on.
func TestRelDisplayFallsBackToTheRawPath(t *testing.T) {
	t.Parallel()

	root := filepath.Join("project", "root")
	if got := relDisplay(root, filepath.Join(root, "pkg", "file.json")); got != filepath.Join("pkg", "file.json") {
		t.Errorf("relDisplay = %q, want the relative path", got)
	}

	if runtime.GOOS == "windows" {
		// Rel across drive letters is impossible, so the raw path must survive.
		raw := `D:\elsewhere\file.json`
		if got := relDisplay(`C:\project`, raw); got != raw {
			t.Errorf("relDisplay across drives = %q, want the raw path %q", got, raw)
		}
	}
}

// TestPythonPackagePinAppendsTheExpectedVersion covers the pin used when
// installing the Python SBOM tool. An unpinned install would silently pull a
// different tool version than the one the config declares.
func TestPythonPackagePinAppendsTheExpectedVersion(t *testing.T) {
	t.Parallel()

	if got := pythonPackagePin(InstallSpec{Package: "cyclonedx-bom"}); got != "cyclonedx-bom" {
		t.Errorf("pin without a version = %q, want the bare package", got)
	}
	if got := pythonPackagePin(InstallSpec{Package: "cyclonedx-bom", ExpectedVersion: "   "}); got != "cyclonedx-bom" {
		t.Errorf("pin with a blank version = %q, want the bare package", got)
	}
	if got := pythonPackagePin(InstallSpec{
		Package:         "cyclonedx-bom",
		ExpectedVersion: "  4.6.1  ",
	}); got != "cyclonedx-bom==4.6.1" {
		t.Errorf("pin = %q, want cyclonedx-bom==4.6.1", got)
	}
}

// TestPythonToolVenvDirSeparatesPackagesAndVersions covers the cache layout. Two
// tool versions must not share a virtualenv, or upgrading one config would
// silently reuse the other's installed package.
func TestPythonToolVenvDirSeparatesPackagesAndVersions(t *testing.T) {
	t.Parallel()

	cacheRoot := t.TempDir()
	cfg := Config{ToolCacheDir: cacheRoot}

	first, err := pythonToolVenvDir(cfg, InstallSpec{Package: "cyclonedx-bom", ExpectedVersion: "4.6.1"})
	if err != nil {
		t.Fatalf("pythonToolVenvDir: %v", err)
	}
	second, err := pythonToolVenvDir(cfg, InstallSpec{Package: "cyclonedx-bom", ExpectedVersion: "4.7.0"})
	if err != nil {
		t.Fatalf("pythonToolVenvDir: %v", err)
	}
	if first == second {
		t.Fatal("two tool versions resolved to the same virtualenv")
	}
	for _, dir := range []string{first, second} {
		if !strings.HasPrefix(dir, cacheRoot) {
			t.Errorf("venv dir %q escaped the configured cache root %q", dir, cacheRoot)
		}
	}

	// A spec without a version still needs a stable directory of its own.
	unversioned, err := pythonToolVenvDir(cfg, InstallSpec{Package: "cyclonedx-bom"})
	if err != nil {
		t.Fatalf("pythonToolVenvDir(no version): %v", err)
	}
	if unversioned == first {
		t.Error("an unversioned spec collided with a pinned one")
	}
}

// TestPythonToolVenvDirSanitisesPathSegments is the security-relevant part: the
// package name reaches the filesystem, so a name carrying separators must not be
// able to place the virtualenv outside the cache root.
func TestPythonToolVenvDirSanitisesPathSegments(t *testing.T) {
	t.Parallel()

	cacheRoot := t.TempDir()
	dir, err := pythonToolVenvDir(Config{ToolCacheDir: cacheRoot}, InstallSpec{
		Package:         "../../evil",
		ExpectedVersion: "../1.0.0",
	})
	if err != nil {
		t.Fatalf("pythonToolVenvDir: %v", err)
	}
	if !strings.HasPrefix(filepath.Clean(dir), filepath.Clean(cacheRoot)) {
		t.Fatalf("venv dir %q escaped the cache root %q", dir, cacheRoot)
	}
	// The sanitiser neutralises separators rather than dots, so "../../evil"
	// becomes the single segment "..-..-evil". What matters is that no path
	// *element* is "..", which is what would actually traverse.
	for _, element := range strings.Split(filepath.Clean(dir), string(filepath.Separator)) {
		if element == ".." {
			t.Fatalf("venv dir %q still contains a traversal element", dir)
		}
	}
	rel, err := filepath.Rel(cacheRoot, dir)
	if err != nil {
		t.Fatalf("venv dir %q is not relative to the cache root: %v", dir, err)
	}
	if !relWithinRoot(rel) {
		t.Fatalf("venv dir %q resolves outside the cache root", dir)
	}
}

// TestPythonToolBinDirAndPythonMatchThePlatform pins the per-OS virtualenv
// layout. Getting this wrong means the generated SBOM tool is never found and
// the scan silently falls back to no SBOM at all.
func TestPythonToolBinDirAndPythonMatchThePlatform(t *testing.T) {
	t.Parallel()

	venv := filepath.Join("cache", "python", "cyclonedx-bom", "4.6.1")
	binDir := pythonToolBinDir(venv)
	python := pythonToolVenvPython(venv)

	if runtime.GOOS == "windows" {
		if filepath.Base(binDir) != "Scripts" {
			t.Errorf("bin dir = %q, want Scripts on Windows", binDir)
		}
		if filepath.Base(python) != "python.exe" {
			t.Errorf("python = %q, want python.exe on Windows", python)
		}
	} else {
		if filepath.Base(binDir) != "bin" {
			t.Errorf("bin dir = %q, want bin", binDir)
		}
		if filepath.Base(python) != "python" {
			t.Errorf("python = %q, want python", python)
		}
	}
	if !strings.HasPrefix(python, binDir) {
		t.Errorf("python %q does not live in the bin dir %q", python, binDir)
	}
}

// TestSafeToolCachePartProducesUsableSegments covers the sanitiser directly. It
// keeps dots (versions need them) and replaces everything else outside
// [a-z0-9._-] with a dash, so a value carrying separators collapses into one
// harmless segment rather than a traversal.
func TestSafeToolCachePartProducesUsableSegments(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		"cyclonedx-bom": "cyclonedx-bom",
		"CycloneDX_BOM": "cyclonedx_bom",
		"  4.6.1  ":     "4.6.1",
		"":              "unknown",
		"   ":           "unknown",
		"../../etc":     "..-..-etc",
		"a/b":           "a-b",
		`a\b`:           "a-b",
		"-lead-trail-":  "lead-trail",
	} {
		if got := safeToolCachePart(input); got != want {
			t.Errorf("safeToolCachePart(%q) = %q, want %q", input, got, want)
		}
	}

	// Whatever it produces must be a single path element.
	for _, input := range []string{"../../etc", "a/b", `a\b`, "pkg name"} {
		got := safeToolCachePart(input)
		if strings.ContainsRune(got, '/') || strings.ContainsRune(got, '\\') {
			t.Errorf("safeToolCachePart(%q) = %q, want a single path element", input, got)
		}
	}
}
