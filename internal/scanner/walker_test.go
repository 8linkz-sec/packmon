package scanner

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/parser"
)

// ---------------------------------------------------------------------------
// Walker tests
// ---------------------------------------------------------------------------

// createFile creates a file at the given path, creating parent directories as
// needed. The file contains minimal content to avoid empty-file edge cases.
func createFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // test fixture directories do not hold secrets
		t.Fatalf("failed to create dir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("# placeholder\n"), 0o644); err != nil { //nolint:gosec // test fixture file
		t.Fatalf("failed to create file %s: %v", path, err)
	}
}

func TestWalk_FindsLockFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a few lock files at various depths.
	createFile(t, filepath.Join(tmpDir, "package-lock.json"))
	createFile(t, filepath.Join(tmpDir, "subdir", "go.sum"))
	createFile(t, filepath.Join(tmpDir, "subdir", "nested", "Cargo.lock"))
	// Create a non-lock file that should be ignored.
	createFile(t, filepath.Join(tmpDir, "README.md"))

	reg := parser.NewRegistry()
	w := NewWalker(reg, 10, nil)
	files, err := w.Walk(tmpDir)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	if len(files) < 3 {
		t.Fatalf("Walk() found %d lock files, want at least 3", len(files))
	}

	// Verify each result has the expected fields populated.
	for _, lf := range files {
		if lf.Path == "" {
			t.Fatal("LockFile.Path must not be empty")
		}
		if lf.RelPath == "" {
			t.Fatal("LockFile.RelPath must not be empty")
		}
		if lf.Parser == nil {
			t.Fatal("LockFile.Parser must not be nil")
		}
	}
}

func TestWalk_RespectsMaxDepth(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create lock files at depth 1 and depth 3.
	createFile(t, filepath.Join(tmpDir, "a", "package-lock.json"))           // depth 1
	createFile(t, filepath.Join(tmpDir, "a", "b", "c", "package-lock.json")) // depth 3

	reg := parser.NewRegistry()

	// maxDepth=1 should find only the depth-1 file.
	w := NewWalker(reg, 1, nil)
	files, err := w.Walk(tmpDir)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Walk(maxDepth=1) found %d files, want 1", len(files))
	}
	if files[0].RelPath != "a/package-lock.json" {
		t.Fatalf("Walk(maxDepth=1) found %q, want %q", files[0].RelPath, "a/package-lock.json")
	}

	// maxDepth=3 should find both.
	w2 := NewWalker(reg, 3, nil)
	files2, err := w2.Walk(tmpDir)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	if len(files2) != 2 {
		t.Fatalf("Walk(maxDepth=3) found %d files, want 2", len(files2))
	}
}

func TestWalk_SkipsHiddenDirs(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Lock file inside a hidden directory should be skipped.
	createFile(t, filepath.Join(tmpDir, ".git", "package-lock.json"))
	createFile(t, filepath.Join(tmpDir, ".svn", "go.sum"))
	createFile(t, filepath.Join(tmpDir, ".hidden", "Cargo.lock"))
	// Non-hidden file at root should be found.
	createFile(t, filepath.Join(tmpDir, "go.sum"))

	reg := parser.NewRegistry()
	w := NewWalker(reg, 10, nil)
	files, err := w.Walk(tmpDir)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	if len(files) != 1 {
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = f.RelPath
		}
		t.Fatalf("Walk() found %d files %v, want exactly 1 (hidden dirs should be skipped)", len(files), names)
	}

	if files[0].RelPath != "go.sum" {
		t.Fatalf("Walk() found %q, want %q", files[0].RelPath, "go.sum")
	}
}

func TestWalk_IncludesGitHubWorkflowFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	createFile(t, filepath.Join(tmpDir, ".github", "workflows", "ci.yml"))
	createFile(t, filepath.Join(tmpDir, ".github", "dependabot.yml"))
	createFile(t, filepath.Join(tmpDir, ".hidden", "workflows", "ci.yml"))

	reg := parser.NewRegistry()
	w := NewWalker(reg, 10, nil)
	files, err := w.Walk(tmpDir)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	if len(files) != 1 {
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = f.RelPath
		}
		t.Fatalf("Walk() found %d files %v, want exactly the GitHub workflow", len(files), names)
	}
	if files[0].RelPath != ".github/workflows/ci.yml" {
		t.Fatalf("Walk() found %q, want .github/workflows/ci.yml", files[0].RelPath)
	}
}

func TestWalk_SkipsVendorDirs(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Lock files in vendor and node_modules should be skipped.
	createFile(t, filepath.Join(tmpDir, "node_modules", "package-lock.json"))
	createFile(t, filepath.Join(tmpDir, "vendor", "go.sum"))
	createFile(t, filepath.Join(tmpDir, "__pycache__", "requirements.txt"))
	// File outside vendor should be found.
	createFile(t, filepath.Join(tmpDir, "package-lock.json"))

	reg := parser.NewRegistry()
	w := NewWalker(reg, 10, nil)
	files, err := w.Walk(tmpDir)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	if len(files) != 1 {
		names := make([]string, len(files))
		for i, f := range files {
			names[i] = f.RelPath
		}
		t.Fatalf("Walk() found %d files %v, want exactly 1 (vendor dirs should be skipped)", len(files), names)
	}

	if files[0].RelPath != "package-lock.json" {
		t.Fatalf("Walk() found %q, want %q", files[0].RelPath, "package-lock.json")
	}
}

func TestWalk_EcosystemFilter(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	createFile(t, filepath.Join(tmpDir, "package-lock.json")) // npm
	createFile(t, filepath.Join(tmpDir, "go.sum"))            // go
	createFile(t, filepath.Join(tmpDir, "Cargo.lock"))        // cargo

	reg := parser.NewRegistry()

	// Filter to only go ecosystem.
	w := NewWalker(reg, 10, []string{"go"})
	files, err := w.Walk(tmpDir)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Walk(ecosystems=[go]) found %d files, want 1", len(files))
	}
	if files[0].RelPath != "go.sum" {
		t.Fatalf("Walk(ecosystems=[go]) found %q, want %q", files[0].RelPath, "go.sum")
	}
}

func TestWalk_EmptyDir(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	reg := parser.NewRegistry()
	w := NewWalker(reg, 10, nil)
	files, err := w.Walk(tmpDir)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	if len(files) != 0 {
		t.Fatalf("Walk() on empty dir found %d files, want 0", len(files))
	}
}

func TestWalk_NonExistentPath(t *testing.T) {
	t.Parallel()

	reg := parser.NewRegistry()
	w := NewWalker(reg, 10, nil)
	_, err := w.Walk(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Fatal("Walk() on non-existent path should return an error")
	}
}

func TestWalkInputErrorUsesRelativePath(t *testing.T) {
	t.Parallel()

	root := filepath.Join("repo")
	path := filepath.Join(root, "service", "package-lock.json")
	err := walkInputError(root, path, errors.New("permission denied"))
	if err == nil {
		t.Fatal("walkInputError() = nil")
	}
	got := err.Error()
	if !strings.Contains(got, "service/package-lock.json") || !strings.Contains(got, "permission denied") {
		t.Fatalf("walkInputError() = %q, want relative path and cause", got)
	}
	if strings.Contains(got, filepath.Clean(root)+string(filepath.Separator)) {
		t.Fatalf("walkInputError() leaked root prefix: %q", got)
	}
}

func TestWalkReportsUnexpectedWalkDirError(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	reg := parser.NewRegistry()
	w := NewWalker(reg, 10, nil)
	_, err := w.walk(root, func(root string, fn fs.WalkDirFunc) error {
		return fn(filepath.Join(root, "service", "package-lock.json"), nil, errors.New("permission denied"))
	})
	if err == nil {
		t.Fatal("Walk() error = nil, want propagated walk error")
	}
	got := err.Error()
	if !strings.Contains(got, "service/package-lock.json") || !strings.Contains(got, "permission denied") {
		t.Fatalf("Walk() error = %q, want relative path and cause", got)
	}
}
