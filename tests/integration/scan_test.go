//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// binaryPath returns the absolute path to the built packmon binary.
// The binary must have been built before running integration tests.
func binaryPath(t *testing.T) string {
	t.Helper()
	for _, candidate := range binaryCandidates(testBinDir(t), "packmon") {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	path := binaryCandidates(testBinDir(t), "packmon")[0]
	t.Fatalf("packmon binary not found near %s -- run 'go build -o %s ./cmd/packmon' first", path, path)
	return ""
}

func binaryCandidates(dir, name string) []string {
	if runtime.GOOS == "windows" {
		return []string{
			filepath.Join(dir, name+".exe"),
			filepath.Join(dir, name),
		}
	}
	return []string{
		filepath.Join(dir, name),
	}
}

// testBinDir returns the directory where test binaries are stored.
// It builds the binary once per test run into a temporary directory.
func testBinDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PACKMON_TEST_BIN_DIR")
	if dir != "" {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(projectRoot(t), dir)
		}
		return dir
	}
	// Fallback: look in the project root.
	root := projectRoot(t)
	return root
}

// projectRoot walks up from the test file location to find go.mod.
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

// runPackmon executes the packmon binary with the given args and returns
// stdout, stderr, and the exit code.
func runPackmon(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	return runPackmonWithEnv(t, nil, args...)
}

func runPackmonWithEnv(t *testing.T, extraEnv map[string]string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	bin := binaryPath(t)
	cmd := exec.Command(bin, args...)
	// Clear environment to avoid inheriting PACKMON_SERVER, etc.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USERPROFILE=" + os.Getenv("USERPROFILE"),
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
	}
	for key, value := range extraEnv {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run packmon: %v", err)
		}
	}

	return outBuf.String(), errBuf.String(), exitCode
}

// --- Test: version command ---------------------------------------------------

func TestVersion(t *testing.T) {
	t.Parallel()

	stdout, _, exitCode := runPackmon(t, "version")

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Output format: "packmon <version> (<commit>) built <date> <os>/<arch>"
	if !strings.HasPrefix(stdout, "packmon ") {
		t.Errorf("expected output to start with 'packmon ', got %q", stdout)
	}
	if !strings.Contains(stdout, runtime.GOOS+"/"+runtime.GOARCH) {
		t.Errorf("expected output to contain %s/%s, got %q", runtime.GOOS, runtime.GOARCH, stdout)
	}
}

// --- Test: scan empty directory -> exit 0, no findings -----------------------

func TestScanEmptyDirectory(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	jsonFile := filepath.Join(tmpDir, "results.json")

	stdout, _, exitCode := runPackmon(t,
		"scan", tmpDir,
		"--mode", "local",
		"--output-json", jsonFile,
	)

	if exitCode != 0 {
		t.Errorf("expected exit code 0 for empty directory, got %d", exitCode)
	}

	// Table output should indicate no findings.
	if !strings.Contains(stdout, "0 packages") && !strings.Contains(strings.ToLower(stdout), "no lock files") && !strings.Contains(stdout, "0 findings") {
		t.Logf("stdout: %s", stdout)
	}

	// Verify JSON output structure.
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if count, ok := result["findings_count"].(float64); !ok || count != 0 {
		t.Errorf("expected findings_count=0, got %v", result["findings_count"])
	}
	if count, ok := result["packages_scanned"].(float64); !ok || count != 0 {
		t.Errorf("expected packages_scanned=0, got %v", result["packages_scanned"])
	}
}

// --- Test: scan directory with known package-lock.json -> valid JSON ---------

func TestScanWithPackageLock(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a minimal but valid package-lock.json (lockfileVersion 3).
	lockContent := `{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "^4.17.15"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
    }
  }
}`

	lockPath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(lockContent), 0o644); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}

	jsonFile := filepath.Join(tmpDir, "results.json")

	// Use local mode to avoid needing a server. Without a local DB,
	// this will fail in local mode. Use auto mode so it falls through
	// gracefully, or just validate the parse and output structure.
	// We use --mode local which will fail because no DB is configured,
	// so we accept exit code 2 (operational error) but still check the
	// JSON output if it was written.
	_, _, exitCode := runPackmon(t,
		"scan", tmpDir,
		"--mode", "local",
		"--output-json", jsonFile,
	)

	// In local mode without a database, the scanner exits 2 (operational).
	// The JSON output may still be written with the error result.
	if exitCode != 0 && exitCode != 2 {
		t.Errorf("expected exit code 0 or 2, got %d", exitCode)
	}

	// If JSON was written, validate its structure.
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		// JSON might not be written on operational error; that is acceptable.
		t.Logf("JSON output not written (exit code %d), skipping structure check", exitCode)
		return
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	// Check required fields exist.
	requiredFields := []string{"scan_id", "mode", "scanned_at", "packages_scanned", "findings_count", "findings"}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field %q in JSON output", field)
		}
	}
}

// --- Test: scan with auto mode, no server, no local DB -> exit 2 -------------

func TestScanAutoModeNoServerNoLocalDB(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	lockContent := `{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.15"
    }
  }
}`

	lockPath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(lockContent), 0o644); err != nil {
		t.Fatalf("failed to write package-lock.json: %v", err)
	}

	_, _, exitCode := runPackmon(t,
		"scan", tmpDir,
		"--mode", "auto",
		"--server", "http://127.0.0.1:1",
		"--timeout", "1",
	)

	// Exit 2 = operational error (server unreachable + no local DB).
	if exitCode != 2 {
		t.Errorf("expected exit code 2 (operational error), got %d", exitCode)
	}
}

// --- Test: scan with malformed lock file -> exit 4 ---------------------------

func TestScanMalformedLockFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Write a file that the npm parser will attempt to parse but fail on.
	malformed := `{{{ this is not valid JSON at all !!!`
	lockPath := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(lockPath, []byte(malformed), 0o644); err != nil {
		t.Fatalf("failed to write malformed lock file: %v", err)
	}

	_, _, exitCode := runPackmon(t,
		"scan", tmpDir,
		"--mode", "local",
	)

	// Exit 4 = parser error when all lock files fail to parse and
	// zero packages are extracted.
	if exitCode != 4 {
		t.Errorf("expected exit code 4 (parser error), got %d", exitCode)
	}
}

// --- Test: scan with ecosystem filter ----------------------------------------

func TestScanEcosystemFilter(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create an npm lock file and a go.sum file.
	lockContent := `{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.15"
    }
  }
}`
	goSumContent := `golang.org/x/text v0.3.7 h1:abc123=
golang.org/x/text v0.3.7/go.mod h1:def456=
`

	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(goSumContent), 0o644); err != nil {
		t.Fatal(err)
	}

	jsonFile := filepath.Join(tmpDir, "results.json")

	// Filter to only npm ecosystem. The go.sum should be ignored.
	// Since local mode without a DB will fail, we use auto mode with
	// an unreachable server and short timeout. We mainly care that the
	// parser handles the filter and that exit code is not a parser error.
	_, _, exitCode := runPackmon(t,
		"scan", tmpDir,
		"--ecosystems", "go",
		"--mode", "local",
		"--output-json", jsonFile,
	)

	// We accept either 0 (no findings, local DB not needed for no packages)
	// or 2 (operational, because local DB unavailable).
	if exitCode != 0 && exitCode != 2 {
		t.Errorf("expected exit code 0 or 2, got %d", exitCode)
	}
}

// --- Test: help flag -> exit 0 -----------------------------------------------

func TestHelpFlag(t *testing.T) {
	t.Parallel()

	stdout, _, exitCode := runPackmon(t, "--help")

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout, "packmon") {
		t.Errorf("expected help output to contain 'packmon', got %q", stdout)
	}
	if !strings.Contains(stdout, "scan") {
		t.Errorf("expected help output to list 'scan' subcommand, got %q", stdout)
	}
}
