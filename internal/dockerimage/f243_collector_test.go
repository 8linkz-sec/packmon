package dockerimage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestF243CollectorReachableErrorBranches(t *testing.T) {
	t.Parallel()

	missingRootFile := filepath.Join(t.TempDir(), "missing", "Dockerfile")
	if _, err := parseFile(File{Path: missingRootFile, RelPath: "Dockerfile", Kind: KindDockerfile}); err == nil {
		t.Fatal("parseFile(missing root) error = nil")
	}

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()
	if _, err := parseFileFromRoot(root, File{RelPath: "..", Kind: KindDockerfile}); err == nil {
		t.Fatal("parseFileFromRoot(escape) error = nil")
	}

	path := filepath.Join(t.TempDir(), "Dockerfile")
	wantRoot, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	if gotRoot, err := impliedDockerInventoryRoot(path, "."); err != nil || gotRoot != wantRoot {
		t.Fatalf("impliedDockerInventoryRoot(dot) = %q, %v; want %q", gotRoot, err, wantRoot)
	}

	closed, err := os.CreateTemp(t.TempDir(), "closed-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	if _, err := parseOpenedFile(closed, File{RelPath: "Dockerfile", Kind: KindDockerfile}); err == nil {
		t.Fatal("parseOpenedFile(closed) error = nil")
	}

	if got := mergeStrings([]string{"", "build"}, []string{"build", ""}); len(got) != 1 || got[0] != "build" {
		t.Fatalf("mergeStrings(empty and duplicate values) = %#v, want [build]", got)
	}
}
