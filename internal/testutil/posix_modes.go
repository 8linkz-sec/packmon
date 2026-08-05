package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func SkipIfPOSIXModesAreNotPreserved(t *testing.T, baseDir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not reliable on Windows")
	}

	probeDir := filepath.Join(baseDir, "mode-probe")
	if err := os.Mkdir(probeDir, 0o750); err != nil {
		t.Fatalf("create mode probe directory: %v", err)
	}
	if err := os.Chmod(probeDir, 0o750); err != nil { // #nosec G302 -- test intentionally verifies POSIX directory mode preservation.
		t.Fatalf("chmod mode probe directory: %v", err)
	}
	probeInfo, err := os.Stat(probeDir)
	if err != nil {
		t.Fatalf("stat mode probe directory: %v", err)
	}
	if got := probeInfo.Mode().Perm(); got != 0o750 {
		t.Skipf("filesystem does not preserve POSIX directory mode bits: got %o after chmod 0750", got)
	}

	probeFile := filepath.Join(baseDir, "mode-probe.json")
	if err := os.WriteFile(probeFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("create mode probe file: %v", err)
	}
	if err := os.Chmod(probeFile, 0o600); err != nil {
		t.Fatalf("chmod mode probe file: %v", err)
	}
	fileInfo, err := os.Stat(probeFile)
	if err != nil {
		t.Fatalf("stat mode probe file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Skipf("filesystem does not preserve POSIX file mode bits: got %o after chmod 0600", got)
	}
}
