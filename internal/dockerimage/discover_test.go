package dockerimage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverFilesFindsDockerfilesAndComposeFiles(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.23\n")
	writeTestFile(t, filepath.Join(root, "Dockerfile.cli"), "FROM alpine:3.23\n")
	writeTestFile(t, filepath.Join(root, "docker-compose.yml"), "services:\n  db:\n    image: postgres:18-alpine\n")
	writeTestFile(t, filepath.Join(root, "node_modules", "pkg", "Dockerfile"), "FROM ignored:latest\n")
	writeTestFile(t, filepath.Join(root, "deep", "too", "far", "Dockerfile"), "FROM ignored:latest\n")

	files, _, err := DiscoverFilesWithWarnings(root, 2)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings: %v", err)
	}
	got := make(map[string]Kind)
	for _, file := range files {
		got[file.RelPath] = file.Kind
	}
	want := map[string]Kind{
		"Dockerfile":         KindDockerfile,
		"Dockerfile.cli":     KindDockerfile,
		"docker-compose.yml": KindCompose,
	}
	if len(got) != len(want) {
		t.Fatalf("files = %#v, want %#v", got, want)
	}
	for path, kind := range want {
		if got[path] != kind {
			t.Fatalf("files[%q] = %q, want %q; all files %#v", path, got[path], kind, got)
		}
	}
}

func TestDiscoverFilesWithWarningsReportsWalkErrorsAndContinues(t *testing.T) {
	root := t.TempDir()
	originalWalkDir := walkDockerInventoryDir
	t.Cleanup(func() { walkDockerInventoryDir = originalWalkDir })

	denied := filepath.Join(root, "private")
	walkDockerInventoryDir = func(_ string, fn fs.WalkDirFunc) error {
		if err := fn(root, fakeDockerDirEntry{name: filepath.Base(root), dir: true}, nil); err != nil {
			return err
		}
		if err := fn(filepath.Join(root, "Dockerfile"), fakeDockerDirEntry{name: "Dockerfile"}, nil); err != nil {
			return err
		}
		err := fn(denied, fakeDockerDirEntry{name: "private", dir: true}, &fs.PathError{
			Op:   "readdir",
			Path: denied,
			Err:  fs.ErrPermission,
		})
		if err != nil && !errors.Is(err, fs.SkipDir) {
			return err
		}
		return nil
	}

	files, warnings, err := DiscoverFilesWithWarnings(root, 5)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings: %v", err)
	}
	if len(files) != 1 || files[0].RelPath != "Dockerfile" {
		t.Fatalf("files = %+v, want Dockerfile only", files)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want one warning", warnings)
	}
	if !strings.Contains(warnings[0], "private") || !strings.Contains(warnings[0], "permission") {
		t.Fatalf("warning = %q, want relative permission warning", warnings[0])
	}
	if strings.Contains(warnings[0], filepath.ToSlash(root)) {
		t.Fatalf("warning leaks absolute root path: %q", warnings[0])
	}
}

func TestDiscoverFilesWithWarningsRejectsWalkerPathOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside", "Dockerfile")
	writeTestFile(t, outside, "FROM ghcr.io/acme/escaped:9.9.9\n")

	originalWalkDir := walkDockerInventoryDir
	t.Cleanup(func() { walkDockerInventoryDir = originalWalkDir })
	walkDockerInventoryDir = func(_ string, fn fs.WalkDirFunc) error {
		if err := fn(root, fakeDockerDirEntry{name: filepath.Base(root), dir: true}, nil); err != nil {
			return err
		}
		return fn(outside, fakeDockerDirEntry{name: "Dockerfile"}, nil)
	}

	files, warnings, err := DiscoverFilesWithWarnings(root, 5)
	if err != nil {
		t.Fatalf("DiscoverFilesWithWarnings: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("files = %+v, want no files outside root", files)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "escapes scan root") {
		t.Fatalf("warnings = %#v, want root escape warning", warnings)
	}
	if strings.Contains(warnings[0], filepath.ToSlash(filepath.Dir(outside))) {
		t.Fatalf("warning leaks external directory: %q", warnings[0])
	}
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

type fakeDockerDirEntry struct {
	name string
	dir  bool
}

func (d fakeDockerDirEntry) Name() string               { return d.name }
func (d fakeDockerDirEntry) IsDir() bool                { return d.dir }
func (d fakeDockerDirEntry) Type() fs.FileMode          { return 0 }
func (d fakeDockerDirEntry) Info() (fs.FileInfo, error) { return nil, nil }
