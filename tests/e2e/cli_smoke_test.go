//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPackmonVersionCommand(t *testing.T) {
	t.Parallel()

	cmd := exec.Command(packmonBinary(t), "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("packmon version failed: %v\n%s", err, string(out))
	}
	if !strings.HasPrefix(string(out), "packmon ") {
		t.Fatalf("version output = %q, want prefix %q", string(out), "packmon ")
	}
}

func TestPackmonScanListPackagesFromBuiltBinary(t *testing.T) {
	t.Parallel()

	projectDir := t.TempDir()
	lockContent := `{
  "name": "e2e-smoke",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "e2e-smoke",
      "version": "1.0.0"
    },
    "node_modules/left-pad": {
      "version": "1.3.0"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	cmd := exec.Command(packmonBinary(t), "scan", projectDir, "--list-packages")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("packmon scan --list-packages failed: %v\n%s", err, string(out))
	}
	output := string(out)
	if !strings.Contains(output, "left-pad") || !strings.Contains(output, "1.3.0") {
		t.Fatalf("list-packages output missing package:\n%s", output)
	}
}

func TestAutoSBOMOnlySmoke(t *testing.T) {
	if _, err := exec.LookPath("cyclonedx-gomod"); err != nil {
		t.Skip("cyclonedx-gomod not installed")
	}
	bin := packmonBinary(t)
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.test\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "sboms")

	cmd := exec.Command(bin, "scan", "--auto-sbom", "--sbom-only", "--keep-sbom", outDir, projectDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("auto-sbom --sbom-only failed: %v\n%s", err, output)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read SBOM output dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected at least one generated SBOM in %s", outDir)
	}
}

func packmonBinary(t *testing.T) string {
	t.Helper()

	for _, candidate := range binaryCandidates(testBinDir(t), "packmon") {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	path := binaryCandidates(testBinDir(t), "packmon")[0]
	t.Fatalf("packmon binary not found at %s; run make build first", path)
	return ""
}

func binaryCandidates(dir, name string) []string {
	if runtime.GOOS == "windows" {
		return []string{
			filepath.Join(dir, name+".exe"),
			filepath.Join(dir, name),
		}
	}
	return []string{filepath.Join(dir, name)}
}

func testBinDir(t *testing.T) string {
	t.Helper()

	dir := os.Getenv("PACKMON_TEST_BIN_DIR")
	if dir != "" {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(projectRoot(t), dir)
		}
		return dir
	}
	return projectRoot(t)
}

func projectRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine caller file")
	}
	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found in any parent directory")
		}
		dir = parent
	}
}
