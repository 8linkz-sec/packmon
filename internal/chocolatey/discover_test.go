package chocolatey

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyFile(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		base string
		kind Kind
		ok   bool
	}{
		{"config.xml", KindConfigXML, true},
		{"CONFIG.XML", KindConfigXML, true},
		{"foo.config.xml", "", false},
		{"config.xml.bak", "", false},
		{"web.config", "", false},
		{"install.ps1", KindScript, true},
		{"Module.PSM1", KindScript, true},
		{"setup.bat", KindScript, true},
		{"setup.CMD", KindScript, true},
		{"install.ps1.txt", "", false},
		{"README.md", "", false},
		{".ps1", KindScript, true},
	} {
		kind, ok := classifyFile(tt.base)
		if kind != tt.kind || ok != tt.ok {
			t.Errorf("classifyFile(%q) = (%q, %v), want (%q, %v)", tt.base, kind, ok, tt.kind, tt.ok)
		}
	}
}

// fakeDirEntry is a minimal fs.DirEntry for walk-callback tests.
type fakeDirEntry struct {
	name string
	dir  bool
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return f.dir }
func (f fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return nil, errors.New("no info") }

func withFakeWalk(t *testing.T, walk func(root string, fn fs.WalkDirFunc) error) {
	t.Helper()
	orig := walkInventoryDir
	walkInventoryDir = walk
	t.Cleanup(func() { walkInventoryDir = orig })
}

func TestWalkWarningsNeverLeakAbsolutePaths(t *testing.T) {
	// not parallel: swaps the package-level walk hook
	dir := t.TempDir()
	absRoot, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	withFakeWalk(t, func(root string, fn fs.WalkDirFunc) error {
		// error on the root itself, on a child, and on a path outside the root
		_ = fn(root, fakeDirEntry{name: filepath.Base(root), dir: true}, &fs.PathError{Op: "readdir", Path: root, Err: fs.ErrPermission})
		_ = fn(filepath.Join(root, "sub"), fakeDirEntry{name: "sub", dir: true}, &fs.PathError{Op: "readdir", Path: filepath.Join(root, "sub"), Err: fs.ErrPermission})
		_ = fn(filepath.Join(filepath.Dir(root), "elsewhere", "x.ps1"), fakeDirEntry{name: "x.ps1"}, fs.ErrPermission)
		return nil
	})

	_, warnings, err := DiscoverFilesWithWarnings(dir, 5)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings() error = %v", err)
	}
	if len(warnings) != 3 {
		t.Fatalf("warnings = %v, want 3", warnings)
	}
	for _, w := range warnings {
		if strings.Contains(w, absRoot) || strings.Contains(w, filepath.ToSlash(absRoot)) || strings.Contains(w, "elsewhere") {
			t.Errorf("warning %q leaks a host path", w)
		}
	}
	if !strings.HasPrefix(warnings[1], "sub: ") {
		t.Errorf("child warning = %q, want relative display", warnings[1])
	}
}

func TestParseErrorsForUnreadableFilesAreRelative(t *testing.T) {
	// not parallel: swaps the package-level walk hook
	dir := t.TempDir()
	absRoot, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	withFakeWalk(t, func(root string, fn fs.WalkDirFunc) error {
		// discovered, then vanished before it was opened
		_ = fn(filepath.Join(root, "sub", "ghost.ps1"), fakeDirEntry{name: "ghost.ps1"}, nil)
		return nil
	})

	collection, err := Collect(dir, 5)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.ParseErrors) != 1 {
		t.Fatalf("ParseErrors = %v, want exactly one", collection.ParseErrors)
	}
	msg := collection.ParseErrors[0]
	if !strings.HasPrefix(msg, "sub/ghost.ps1: ") || strings.Contains(msg, absRoot) || strings.Contains(msg, filepath.ToSlash(absRoot)) {
		t.Fatalf("parse error %q must be repository-relative", msg)
	}
	if strings.Count(msg, "ghost.ps1") != 1 {
		t.Fatalf("parse error %q repeats the file name", msg)
	}
}

func TestCollectSkipsDirectoriesNamedLikeScripts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tools.ps1"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "tools.ps1", "config.xml"), `<config><packages><package name="inside"/></packages></config>`)
	writeTestFile(t, filepath.Join(dir, "CONFIG.XML"), `<config><packages><package name="upper"/></packages></config>`)
	writeTestFile(t, filepath.Join(dir, "app.config.xml"), `<config><packages><package name="suffix"/></packages></config>`)

	collection, err := Collect(dir, 5)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.ParseErrors) != 0 || len(collection.DiscoveryWarnings) != 0 {
		t.Fatalf("errors = %v warnings = %v, want none", collection.ParseErrors, collection.DiscoveryWarnings)
	}
	names := make([]string, 0, len(collection.Packages))
	for _, pkg := range collection.Packages {
		names = append(names, pkg.SourceFile+":"+pkg.Name)
	}
	if got := strings.Join(names, " "); got != "CONFIG.XML:upper tools.ps1/config.xml:inside" {
		t.Fatalf("packages = %q", got)
	}
	if collection.Files != 2 {
		t.Fatalf("Files = %d, want 2", collection.Files)
	}
}
