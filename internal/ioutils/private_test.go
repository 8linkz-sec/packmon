package ioutils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenPrivateFileTightensExistingPermissions(t *testing.T) {
	baseDir := t.TempDir()
	skipIfPOSIXModesAreNotPreserved(t, baseDir)

	path := filepath.Join(baseDir, "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil { // #nosec G306 -- test seeds broad permissions to verify the helper tightens them.
		t.Fatalf("seed broad file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- test intentionally prepares a too-broad existing file.
		t.Fatalf("chmod broad file: %v", err)
	}

	file, err := OpenPrivateFile(path)
	if err != nil {
		t.Fatalf("OpenPrivateFile: %v", err)
	}
	if _, err := file.Write([]byte("new")); err != nil {
		CloseSilently(file)
		t.Fatalf("write private file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close private file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat private file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file permissions = %o, want 0600", got)
	}
}

func TestOpenPrivateFileCreatesAndTruncatesFile(t *testing.T) {
	baseDir := t.TempDir()
	path := filepath.Join(baseDir, "report.json")

	file, err := OpenPrivateFile(path)
	if err != nil {
		t.Fatalf("OpenPrivateFile(create): %v", err)
	}
	if _, err := file.Write([]byte("old-data")); err != nil {
		CloseSilently(file)
		t.Fatalf("write initial file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close initial file: %v", err)
	}

	file, err = OpenPrivateFile(path)
	if err != nil {
		t.Fatalf("OpenPrivateFile(truncate): %v", err)
	}
	if _, err := file.Write([]byte("new")); err != nil {
		CloseSilently(file)
		t.Fatalf("write truncated file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close truncated file: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read private file: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("file content = %q, want truncated new content", data)
	}
}

func TestOpenPrivateFileReturnsCreateError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "report.json")
	if file, err := OpenPrivateFile(path); err == nil {
		CloseSilently(file)
		t.Fatal("OpenPrivateFile(missing parent) error = nil")
	}
}

func skipIfPOSIXModesAreNotPreserved(t *testing.T, baseDir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not reliable on Windows")
	}

	probe := filepath.Join(baseDir, "mode-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		t.Fatalf("create mode probe file: %v", err)
	}
	if err := os.Chmod(probe, 0o600); err != nil {
		t.Fatalf("chmod mode probe file: %v", err)
	}
	info, err := os.Stat(probe)
	if err != nil {
		t.Fatalf("stat mode probe file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Skipf("filesystem does not preserve POSIX file mode bits: got %o after chmod 0600", got)
	}
}
