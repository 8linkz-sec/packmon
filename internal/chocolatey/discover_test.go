package chocolatey

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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
		{"install.ps1", KindPowerShellScript, true},
		{"Module.PSM1", KindPowerShellScript, true},
		{"setup.bat", KindBatchScript, true},
		{"setup.CMD", KindBatchScript, true},
		{"install.ps1.txt", "", false},
		{"README.md", "", false},
		{".ps1", KindPowerShellScript, true},
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

func TestDiscoverFilesWithWarningsHonorsDepthAndDirectoryExclusions(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "config.xml"), `<config/>`)
	writeTestFile(t, filepath.Join(root, "scripts", "install.ps1"), "choco install alpha")
	writeTestFile(t, filepath.Join(root, ".github", "setup.cmd"), "choco install beta")
	writeTestFile(t, filepath.Join(root, ".hidden", "hidden.ps1"), "choco install hidden")
	writeTestFile(t, filepath.Join(root, "vendor", "vendored.ps1"), "choco install vendor")
	writeTestFile(t, filepath.Join(root, "nested", "deeper", "too-deep.ps1"), "choco install deep")

	files, warnings, err := DiscoverFilesWithWarnings(root, 1)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	got := make([]string, 0, len(files))
	for _, file := range files {
		got = append(got, string(file.Kind)+":"+file.RelPath)
	}
	want := []string{
		"batch-script:.github/setup.cmd",
		"config-xml:config.xml",
		"powershell-script:scripts/install.ps1",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("discovered files = %v, want %v", got, want)
	}
}

func TestDiscoverFilesWithWarningsRejectsFileRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-a-directory.ps1")
	writeTestFile(t, root, "choco install alpha")

	_, _, err := DiscoverFilesWithWarnings(root, 1)
	if !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("DiscoverFilesWithWarnings() error = %v, want fs.ErrInvalid", err)
	}
}

func TestDiscoverFilesWithWarningsRejectsMissingRoot(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "missing")
	files, warnings, err := DiscoverFilesWithWarnings(root, 1)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("DiscoverFilesWithWarnings(%q) error = %v, want fs.ErrNotExist", root, err)
	}
	if files != nil || warnings != nil {
		t.Fatalf("DiscoverFilesWithWarnings(%q) = (%v, %v), want nil results", root, files, warnings)
	}
}

func TestCleanRelPathBoundaries(t *testing.T) {
	t.Parallel()

	absolute := filepath.Join(t.TempDir(), "absolute.ps1")
	for _, tt := range []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "nested local", input: "scripts/install.ps1", want: filepath.Join("scripts", "install.ps1")},
		{name: "cleaned local", input: "scripts/../install.ps1", want: "install.ps1"},
		{name: "dot", input: ".", wantErr: true},
		{name: "parent traversal", input: "../outside.ps1", wantErr: true},
		{name: "absolute", input: absolute, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cleanRelPath(tt.input)
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "escapes scan root") {
					t.Fatalf("cleanRelPath(%q) = (%q, %v), want root-escape error", tt.input, got, err)
				}
				if filepath.IsAbs(tt.input) && strings.Contains(err.Error(), filepath.Dir(tt.input)) {
					t.Fatalf("cleanRelPath(%q) error leaks host directory: %v", tt.input, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("cleanRelPath(%q) = (%q, %v), want (%q, nil)", tt.input, got, err, tt.want)
			}
		})
	}
}

func TestDiscoverFilesWithWarningsHandlesCrossVolumePath(t *testing.T) {
	// not parallel: swaps the package-level walk hook
	if runtime.GOOS != "windows" {
		t.Skip("cross-volume filepath.Rel failure is Windows-specific")
	}
	root := t.TempDir()
	rootVolume := filepath.VolumeName(root)
	var otherRoot string
	for drive := 'A'; drive <= 'Z'; drive++ {
		candidate := string(drive) + ":" + string(filepath.Separator)
		if strings.EqualFold(filepath.VolumeName(candidate), rootVolume) {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			otherRoot = candidate
			break
		}
	}
	if otherRoot == "" {
		t.Skipf("no volume distinct from %q is available", rootVolume)
	}
	crossVolumePath := filepath.Join(otherRoot, "outside.ps1")
	withFakeWalk(t, func(_ string, fn fs.WalkDirFunc) error {
		return fn(crossVolumePath, fakeDirEntry{name: "outside.ps1"}, nil)
	})

	files, warnings, err := DiscoverFilesWithWarnings(root, 1)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings() error = %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("files = %v, want none", files)
	}
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "outside.ps1: ") {
		t.Fatalf("warnings = %v, want one cross-volume warning for outside.ps1", warnings)
	}
}

func TestDiscoverFilesWithWarningsSignalsDirectoryExclusions(t *testing.T) {
	// not parallel: swaps the package-level walk hook
	root := t.TempDir()
	want := map[string]error{
		".hidden":      fs.SkipDir,
		"node_modules": fs.SkipDir,
		"vendor":       fs.SkipDir,
		"__pycache__":  fs.SkipDir,
		".github":      nil,
		"src":          nil,
	}
	withFakeWalk(t, func(walkRoot string, fn fs.WalkDirFunc) error {
		for name, wantErr := range want {
			gotErr := fn(filepath.Join(walkRoot, name), fakeDirEntry{name: name, dir: true}, nil)
			if !errors.Is(gotErr, wantErr) || (wantErr == nil && gotErr != nil) {
				t.Errorf("walk callback for %q = %v, want %v", name, gotErr, wantErr)
			}
		}
		return nil
	})

	files, warnings, err := DiscoverFilesWithWarnings(root, 5)
	if err != nil || len(files) != 0 || len(warnings) != 0 {
		t.Fatalf("DiscoverFilesWithWarnings() = (%v, %v, %v), want empty success", files, warnings, err)
	}
}

func TestDiscoverFilesWithWarningsHonorsZeroDepth(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "root.ps1"), "choco install root\n")
	writeTestFile(t, filepath.Join(root, "nested", "hidden.ps1"), "choco install nested\n")

	files, warnings, err := DiscoverFilesWithWarnings(root, 0)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(files) != 1 || files[0].RelPath != "root.ps1" || files[0].Kind != KindPowerShellScript {
		t.Fatalf("files = %+v, want only root.ps1", files)
	}
}

func TestDiscoverFilesWithWarningsReturnsPartialResultsWithWalkerError(t *testing.T) {
	// not parallel: swaps the package-level walk hook
	root := t.TempDir()
	walkErr := errors.New("walker stopped")
	withFakeWalk(t, func(walkRoot string, fn fs.WalkDirFunc) error {
		if err := fn(filepath.Join(walkRoot, "denied"), nil, &fs.PathError{Op: "read", Path: filepath.Join(walkRoot, "denied"), Err: fs.ErrPermission}); err != nil {
			return err
		}
		if err := fn(filepath.Join(walkRoot, "kept.cmd"), fakeDirEntry{name: "kept.cmd"}, nil); err != nil {
			return err
		}
		return walkErr
	})

	files, warnings, err := DiscoverFilesWithWarnings(root, 1)
	if !errors.Is(err, walkErr) {
		t.Fatalf("DiscoverFilesWithWarnings() error = %v, want %v", err, walkErr)
	}
	if len(files) != 1 || files[0].RelPath != "kept.cmd" || files[0].Kind != KindBatchScript {
		t.Fatalf("files = %+v, want kept.cmd partial result", files)
	}
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "denied: ") {
		t.Fatalf("warnings = %v, want one relative denied warning", warnings)
	}
}

func TestDiscoverFilesWithWarningsAllowsExplicitGitHubRoot(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), ".github")
	writeTestFile(t, filepath.Join(root, "bootstrap.ps1"), "choco install bootstrap\n")

	files, warnings, err := DiscoverFilesWithWarnings(root, 0)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(files) != 1 || files[0].RelPath != "bootstrap.ps1" {
		t.Fatalf("files = %+v, want bootstrap.ps1 from explicit .github root", files)
	}
}

func TestRelDisplayNeverReturnsAbsoluteHostPath(t *testing.T) {
	absFile := filepath.Join(t.TempDir(), "sensitive.ps1")
	absRoot := filepath.VolumeName(absFile) + string(filepath.Separator)
	for _, tt := range []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: "", want: "chocolatey-inventory-file"},
		{name: "dot", path: ".", want: "chocolatey-inventory-file"},
		{name: "whitespace", path: "   ", want: "chocolatey-inventory-file"},
		{name: "absolute file", path: absFile, want: "sensitive.ps1"},
		{name: "absolute root", path: absRoot, want: "chocolatey-inventory-file"},
		{name: "relative path", path: "scripts\\install.ps1", want: "scripts/install.ps1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := relDisplay(tt.path); got != tt.want {
				t.Fatalf("relDisplay(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDiscoverFilesWithWarningsRejectsRootEscapingCallbackPath(t *testing.T) {
	// not parallel: swaps the package-level walk hook
	root := t.TempDir()
	withFakeWalk(t, func(root string, fn fs.WalkDirFunc) error {
		if err := fn(filepath.Join(root, "..", "outside.ps1"), fakeDirEntry{name: "outside.ps1"}, nil); err != nil {
			return err
		}
		return nil
	})

	files, warnings, err := DiscoverFilesWithWarnings(root, 2)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings() error = %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("files = %v, want none", files)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one warning", warnings)
	}
	if !strings.Contains(warnings[0], "escapes scan root") {
		t.Fatalf("first warning = %q, want root escape", warnings[0])
	}
}
