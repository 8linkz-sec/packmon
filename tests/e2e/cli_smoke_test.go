//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const e2eCommandTimeout = 30 * time.Second

func TestPackmonVersionCommand(t *testing.T) {
	t.Parallel()

	cmd, ctx, cancel := packmonCommand(t, "version")
	defer cancel()
	out, err := cmd.CombinedOutput()
	failIfE2ECommandTimedOut(t, ctx, "packmon version", out)
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

	cmd, ctx, cancel := packmonCommand(t, "scan", projectDir, "--list-packages")
	defer cancel()
	out, err := cmd.CombinedOutput()
	failIfE2ECommandTimedOut(t, ctx, "packmon scan --list-packages", out)
	if err != nil {
		t.Fatalf("packmon scan --list-packages failed: %v\n%s", err, string(out))
	}
	output := string(out)
	if !strings.Contains(output, "left-pad") || !strings.Contains(output, "1.3.0") {
		t.Fatalf("list-packages output missing package:\n%s", output)
	}
}

func TestPackmonScanExplicitSBOMFromBuiltBinary(t *testing.T) {
	t.Parallel()

	projectDir := t.TempDir()
	sbomDir := t.TempDir()
	cycloneDXPath := filepath.Join(sbomDir, "bom.cdx.json")
	if err := os.WriteFile(cycloneDXPath, []byte(`{
  "bomFormat": "CycloneDX",
  "components": [
    {"type": "library", "name": "django", "version": "4.2.11", "purl": "pkg:pypi/django@4.2.11"}
  ]
}`), 0o600); err != nil {
		t.Fatalf("write CycloneDX SBOM: %v", err)
	}
	spdxPath := filepath.Join(sbomDir, "bom.spdx.json")
	if err := os.WriteFile(spdxPath, []byte(`{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "left-pad",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/left-pad@1.3.0"
        }
      ]
    }
  ]
}`), 0o600); err != nil {
		t.Fatalf("write SPDX SBOM: %v", err)
	}

	for _, tt := range []struct {
		name        string
		path        string
		packageName string
		version     string
	}{
		{name: "cyclonedx", path: cycloneDXPath, packageName: "django", version: "4.2.11"},
		{name: "spdx", path: spdxPath, packageName: "left-pad", version: "1.3.0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, ctx, cancel := packmonCommand(t, "scan", projectDir, "--list-packages", "--sbom", tt.path)
			defer cancel()
			out, err := cmd.CombinedOutput()
			failIfE2ECommandTimedOut(t, ctx, "packmon scan --list-packages --sbom", out)
			if err != nil {
				t.Fatalf("packmon scan --list-packages --sbom failed: %v\n%s", err, string(out))
			}
			output := string(out)
			if !strings.Contains(output, tt.packageName) || !strings.Contains(output, tt.version) {
				t.Fatalf("explicit SBOM output missing %s@%s:\n%s", tt.packageName, tt.version, output)
			}
		})
	}
}

func TestPackmonScanWritesReportOutputsFromBuiltBinary(t *testing.T) {
	t.Parallel()

	projectDir := t.TempDir()
	outDir := t.TempDir()
	jsonPath := filepath.Join(outDir, "results.json")
	sarifPath := filepath.Join(outDir, "results.sarif")
	junitPath := filepath.Join(outDir, "results.xml")
	htmlPath := filepath.Join(outDir, "results.html")

	cmd, ctx, cancel := packmonCommand(t,
		"scan", projectDir,
		"--mode", "local",
		"--output-json", jsonPath,
		"--output-sarif", sarifPath,
		"--output-junit", junitPath,
		"--html", htmlPath,
	)
	defer cancel()
	out, err := cmd.CombinedOutput()
	failIfE2ECommandTimedOut(t, ctx, "packmon scan report outputs", out)
	if err != nil {
		t.Fatalf("packmon scan report outputs failed: %v\n%s", err, string(out))
	}

	jsonBody := readNonEmptyFile(t, jsonPath)
	var result struct {
		PackagesScanned int `json:"packages_scanned"`
		FindingsCount   int `json:"findings_count"`
	}
	if err := json.Unmarshal(jsonBody, &result); err != nil {
		t.Fatalf("parse JSON report: %v\n%s", err, string(jsonBody))
	}
	if result.PackagesScanned != 0 || result.FindingsCount != 0 {
		t.Fatalf("JSON report = %+v, want clean empty scan", result)
	}

	sarifBody := readNonEmptyFile(t, sarifPath)
	var sarif struct {
		Version string `json:"version"`
		Runs    []any  `json:"runs"`
	}
	if err := json.Unmarshal(sarifBody, &sarif); err != nil {
		t.Fatalf("parse SARIF report: %v\n%s", err, string(sarifBody))
	}
	if sarif.Version != "2.1.0" || len(sarif.Runs) == 0 {
		t.Fatalf("SARIF report version/runs = %q/%d, want 2.1.0 with runs", sarif.Version, len(sarif.Runs))
	}

	junitBody := readNonEmptyFile(t, junitPath)
	var junit struct {
		XMLName xml.Name `xml:"testsuites"`
		Tests   int      `xml:"tests,attr"`
	}
	if err := xml.Unmarshal(junitBody, &junit); err != nil {
		t.Fatalf("parse JUnit report: %v\n%s", err, string(junitBody))
	}
	if junit.XMLName.Local != "testsuites" || junit.Tests == 0 {
		t.Fatalf("JUnit root/tests = %q/%d, want testsuites with tests", junit.XMLName.Local, junit.Tests)
	}

	htmlBody := readNonEmptyFile(t, htmlPath)
	html := string(htmlBody)
	if !strings.Contains(html, "<!DOCTYPE html>") || !strings.Contains(html, "No packages were evaluated") {
		t.Fatalf("HTML report missing expected markers:\n%s", html)
	}
}

func TestAutoSBOMOnlySmoke(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not installed")
	}
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.test\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "sboms")

	cmd, ctx, cancel := packmonCommand(t, "scan", "--auto-sbom", "--sbom-only", "--keep-sbom", outDir, projectDir)
	defer cancel()
	output, err := cmd.CombinedOutput()
	failIfE2ECommandTimedOut(t, ctx, "packmon scan --auto-sbom --sbom-only", output)
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

func readNonEmptyFile(t *testing.T, path string) []byte {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(body) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return body
}

func packmonCommand(t *testing.T, args ...string) (*exec.Cmd, context.Context, context.CancelFunc) {
	t.Helper()

	binary := packmonBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), e2eCommandTimeout)
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- e2e tests execute the built packmon binary with test-controlled arguments.
	cmd.Env = hermeticPackmonEnv(t, nil)
	return cmd, ctx, cancel
}

func failIfE2ECommandTimedOut(t *testing.T, ctx context.Context, description string, output []byte) {
	t.Helper()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("%s timed out after %s\n%s", description, e2eCommandTimeout, string(output))
	}
}

func hermeticPackmonEnv(t *testing.T, extra map[string]string) []string {
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
	for key, value := range extra {
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
