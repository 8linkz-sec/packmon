//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/scanner"
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
	cmd, ctx, cancel := integrationCommand(t, bin, args...)
	defer cancel()
	cmd.Env = hermeticPackmonEnv(t, extraEnv)

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	failIfIntegrationCommandTimedOut(t, ctx, integrationCommandTimeout, "packmon "+strings.Join(args, " "), []byte(outBuf.String()+errBuf.String()))
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

func hermeticPackmonEnv(t *testing.T, extraEnv map[string]string) []string {
	t.Helper()

	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("create hermetic home: %v", err)
	}
	dbDir := filepath.Join(t.TempDir(), "db")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatalf("create hermetic db dir: %v", err)
	}

	values := map[string]string{
		"APPDATA":         filepath.Join(home, "AppData", "Roaming"),
		"HOME":            home,
		"LOCALAPPDATA":    filepath.Join(home, "AppData", "Local"),
		"PACKMON_DB_PATH": dbDir,
		"USERPROFILE":     home,
		"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
	}
	for _, key := range []string{"PATH", "TEMP", "TMP", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"} {
		if value := os.Getenv(key); value != "" {
			values[key] = value
		}
	}
	for key, value := range extraEnv {
		values[key] = value
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

func seedLocalScanDB(t *testing.T, vulnerablePackages ...string) map[string]string {
	t.Helper()

	dbDir := filepath.Join(t.TempDir(), "db")
	store, err := sqlite.New(filepath.Join(dbDir, "packmon.db"))
	if err != nil {
		t.Fatalf("open local sqlite store: %v", err)
	}

	ctx := context.Background()
	if len(vulnerablePackages) == 0 {
		vulnerablePackages = []string{"unmatched-seed"}
	}
	for _, name := range vulnerablePackages {
		if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, severity, summary)
		VALUES(?, ?, 'npm', ?, 'HIGH', 'integration seed advisory')`,
			"GHSA-integration-seed|npm|"+name, "GHSA-integration-seed-"+name, name); err != nil {
			t.Fatalf("seed local sqlite advisory: %v", err)
		}
	}
	if err := store.SetSyncMeta(ctx, "last_sync_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed local sqlite sync time: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close local sqlite store: %v", err)
	}

	return map[string]string{"PACKMON_DB_PATH": dbDir}
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

	// Table output should indicate no packages were evaluated.
	if !strings.Contains(stdout, "No packages were evaluated") &&
		!strings.Contains(stdout, "0 packages") &&
		!strings.Contains(strings.ToLower(stdout), "no lock files") &&
		!strings.Contains(stdout, "0 findings") {
		t.Fatalf("expected empty-directory scan output to mention no evaluated packages, 0 packages, no lock files, or 0 findings; stdout=%q", stdout)
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
	if threshold, ok := result["block_threshold"].(string); !ok || threshold != "CRITICAL" {
		t.Errorf("expected block_threshold=CRITICAL, got %v", result["block_threshold"])
	}
	findings, ok := result["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings to be an array, got %T", result["findings"])
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
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

	stdout, stderr, exitCode := runPackmonWithEnv(t, seedLocalScanDB(t),
		"scan", tmpDir,
		"--mode", "local",
		"--output-json", jsonFile,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstdout:\n%s\nstderr:\n%s", exitCode, stdout, stderr)
	}

	data, err := os.ReadFile(jsonFile)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	// Check required fields exist.
	requiredFields := []string{
		"scan_id", "mode", "scanned_at", "duration_ms", "packages_scanned",
		"findings_count", "findings_blocking", "block_threshold", "feed_status",
		"db_age_days", "db_stale", "summary", "findings", "feed_versions",
		"manual_advisories_count",
	}
	for _, field := range requiredFields {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field %q in JSON output", field)
		}
	}
	if count, ok := result["packages_scanned"].(float64); !ok || count != 2 {
		t.Fatalf("packages_scanned = %v, want 2", result["packages_scanned"])
	}
	if count, ok := result["findings_count"].(float64); !ok || count != 0 {
		t.Fatalf("findings_count = %v, want 0", result["findings_count"])
	}
	if threshold, ok := result["block_threshold"].(string); !ok || threshold != "CRITICAL" {
		t.Fatalf("block_threshold = %v, want CRITICAL", result["block_threshold"])
	}
	if feedStatus, ok := result["feed_status"].(string); !ok || !allowedScanFeedStatus(feedStatus) {
		t.Fatalf("feed_status = %v, want machine-readable status", result["feed_status"])
	}
	findings, ok := result["findings"].([]any)
	if !ok {
		t.Fatalf("findings = %T %[1]v, want array", result["findings"])
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
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

	stdout, stderr, exitCode := runPackmonWithEnv(t, seedLocalScanDB(t, "lodash"),
		"scan", tmpDir,
		"--ecosystems", "npm",
		"--mode", "local",
		"--output-json", jsonFile,
	)

	if exitCode != scanner.ExitUnderThreshold {
		t.Fatalf("expected exit code %d, got %d\nstdout:\n%s\nstderr:\n%s", scanner.ExitUnderThreshold, exitCode, stdout, stderr)
	}

	data, err := os.ReadFile(jsonFile)
	if err != nil {
		t.Fatalf("failed to read JSON output: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}
	if mode, ok := result["mode"].(string); !ok || mode != "local" {
		t.Fatalf("mode = %v, want local", result["mode"])
	}
	if count, ok := result["packages_scanned"].(float64); !ok || count != 1 {
		t.Fatalf("packages_scanned = %v, want 1 npm package", result["packages_scanned"])
	}
	if count, ok := result["findings_count"].(float64); !ok || count != 1 {
		t.Fatalf("findings_count = %v, want 1 npm finding", result["findings_count"])
	}
	if threshold, ok := result["block_threshold"].(string); !ok || threshold != "CRITICAL" {
		t.Fatalf("block_threshold = %v, want CRITICAL", result["block_threshold"])
	}
	findings, ok := result["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings = %T %[1]v, want one finding", result["findings"])
	}
	finding, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("finding = %T %[1]v, want object", findings[0])
	}
	if finding["ecosystem"] != "npm" || finding["name"] != "lodash" {
		t.Fatalf("finding identity = ecosystem:%v name:%v, want npm lodash", finding["ecosystem"], finding["name"])
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
