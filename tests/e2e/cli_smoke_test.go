//go:build e2e

package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestPackmonScanListAllOfflineReportFromBuiltBinary(t *testing.T) {
	t.Parallel()

	projectDir := t.TempDir()
	lockContent := `{
  "name": "e2e-list-all",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "e2e-list-all",
      "version": "1.0.0",
      "devDependencies": {
        "left-pad": "1.3.0"
      }
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "dev": true
    }
  }
}`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	outDir := t.TempDir()
	htmlPath := filepath.Join(outDir, "packmon-report.html")
	jsonPath := filepath.Join(outDir, "packmon-report.json")
	cmd, ctx, cancel := packmonCommandInDir(t,
		projectDir,
		hermeticPackmonEnv(t, nil),
		"scan",
		"--mode", "local",
		"--list-all",
		"--list-all-offline",
		"--html", htmlPath,
		"--output-json", jsonPath,
		".",
	)
	defer cancel()
	out, err := cmd.CombinedOutput()
	failIfE2ECommandTimedOut(t, ctx, "packmon scan --list-all --list-all-offline reports", out)
	if err != nil {
		t.Fatalf("packmon scan --list-all --list-all-offline reports failed: %v\n%s", err, string(out))
	}

	jsonBody := readNonEmptyFile(t, jsonPath)
	var result struct {
		Mode            string `json:"mode"`
		PackagesScanned int    `json:"packages_scanned"`
		FindingsCount   int    `json:"findings_count"`
		Findings        []any  `json:"findings"`
	}
	if err := json.Unmarshal(jsonBody, &result); err != nil {
		t.Fatalf("parse JSON report: %v\n%s", err, string(jsonBody))
	}
	if result.Mode != "local" || result.PackagesScanned != 0 || result.FindingsCount != 0 || len(result.Findings) != 0 {
		t.Fatalf("JSON report = %+v, want clean local scan result with dev-only package excluded from findings scan", result)
	}

	htmlBody := readNonEmptyFile(t, htmlPath)
	html := string(htmlBody)
	for _, want := range []string{
		"<!DOCTYPE html>",
		"Packmon List-All Report",
		"All Packages",
		"left-pad",
		"1.3.0",
		">dev<",
		"unknown",
		`aria-label="All packages table"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("list-all HTML report missing %q:\n%s", want, html)
		}
	}
}

func TestPackmonScanDeliversWebhookFromBuiltBinary(t *testing.T) {
	t.Parallel()

	projectDir := t.TempDir()
	lockContent := `{
  "name": "e2e-webhook",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "e2e-webhook",
      "version": "1.0.0"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	type webhookRequest struct {
		method string
		header http.Header
		body   []byte
	}
	requests := make(chan webhookRequest, 1)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read webhook body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		requests <- webhookRequest{
			method: r.Method,
			header: r.Header.Clone(),
			body:   body,
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()

	secret := "e2e-webhook-secret" //nolint:gosec // test fixture secret
	cmd, ctx, cancel := packmonCommandInDir(t, "", hermeticPackmonEnv(t, map[string]string{
		"PACKMON_WEBHOOK_SECRET": secret,
	}),
		"scan", projectDir,
		"--mode", "local",
		"--webhook-url", webhook.URL,
	)
	defer cancel()
	out, err := cmd.CombinedOutput()
	failIfE2ECommandTimedOut(t, ctx, "packmon scan --webhook-url", out)
	if err != nil {
		t.Fatalf("packmon scan --webhook-url failed: %v\n%s", err, string(out))
	}

	var got webhookRequest
	select {
	case got = <-requests:
	case <-time.After(5 * time.Second):
		t.Fatal("webhook request was not received")
	}

	if got.method != http.MethodPost {
		t.Fatalf("webhook method = %q, want POST", got.method)
	}
	if contentType := got.header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("webhook Content-Type = %q, want application/json", contentType)
	}
	if userAgent := got.header.Get("User-Agent"); !strings.HasPrefix(userAgent, "packmon-cli/") {
		t.Fatalf("webhook User-Agent = %q, want packmon-cli/", userAgent)
	}
	gotSignature := got.header.Get("X-Packmon-Signature")
	if gotSignature == "" {
		t.Fatal("webhook X-Packmon-Signature header is missing")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(got.body)
	wantSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotSignature), []byte(wantSignature)) {
		t.Fatalf("webhook signature = %q, want %q", gotSignature, wantSignature)
	}

	var envelope struct {
		Event   string `json:"event"`
		Version string `json:"version"`
		Source  string `json:"source"`
		Result  struct {
			Mode            string `json:"mode"`
			PackagesScanned int    `json:"packages_scanned"`
			FindingsCount   int    `json:"findings_count"`
			Findings        []any  `json:"findings"`
		} `json:"result"`
	}
	if err := json.Unmarshal(got.body, &envelope); err != nil {
		t.Fatalf("parse webhook JSON: %v\n%s", err, string(got.body))
	}
	if envelope.Event != "scan_completed" || envelope.Version != "1" || envelope.Source != "cli" {
		t.Fatalf("webhook envelope = %+v, want scan_completed v1 from cli", envelope)
	}
	if envelope.Result.Mode != "local" || envelope.Result.PackagesScanned != 0 || envelope.Result.FindingsCount != 0 || len(envelope.Result.Findings) != 0 {
		t.Fatalf("webhook result = %+v, want clean local scan from fixture lockfile", envelope.Result)
	}
}

func TestPackmonPreCommitHookBlocksGitCommit(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}

	repo := t.TempDir()
	gitEnv := hermeticPackmonEnv(t, nil)
	runGit(t, git, repo, gitEnv, "init")
	runGit(t, git, repo, gitEnv, "config", "user.email", "packmon-e2e@example.test")
	runGit(t, git, repo, gitEnv, "config", "user.name", "Packmon E2E")

	if err := os.WriteFile(filepath.Join(repo, "package-lock.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write malformed package-lock.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hook e2e\n"), 0o600); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	runGit(t, git, repo, gitEnv, "add", "package-lock.json", "README.md")

	binDir := filepath.Dir(packmonBinary(t))
	hookEnv := hermeticPackmonEnv(t, map[string]string{
		"PATH": binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	})
	cmd, ctx, cancel := packmonCommandInDir(t, repo, hookEnv, "hook", "install", "--type", "pre-commit")
	defer cancel()
	out, err := cmd.CombinedOutput()
	failIfE2ECommandTimedOut(t, ctx, "packmon hook install --type pre-commit", out)
	if err != nil {
		t.Fatalf("packmon hook install --type pre-commit failed: %v\n%s", err, string(out))
	}

	out, err = gitCommand(t, git, repo, hookEnv, "commit", "-m", "exercise packmon hook")
	if err == nil {
		t.Fatalf("git commit succeeded, want installed packmon pre-commit hook to block it\n%s", string(out))
	}
	output := string(out)
	if !strings.Contains(output, "parse error in package-lock.json") {
		t.Fatalf("git commit output did not show packmon hook scan failure:\n%s", output)
	}

	runGit(t, git, repo, hookEnv, "commit", "--no-verify", "-m", "bypass packmon hook for control")
}

func TestAutoSBOMOnlySmoke(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not installed")
	}
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.test\n\ngo 1.21\n\nrequire example.test/dep v0.0.0\n\nreplace example.test/dep => ./.dep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	depDir := filepath.Join(projectDir, ".dep")
	if err := os.MkdirAll(depDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(depDir, "go.mod"), []byte("module example.test/dep\n\ngo 1.21\n"), 0o600); err != nil {
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
	matches, err := filepath.Glob(filepath.Join(outDir, "*.cdx.json"))
	if err != nil {
		t.Fatalf("glob generated SBOMs: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("generated SBOM count = %d, want 1 in %s", len(matches), outDir)
	}

	body := readNonEmptyFile(t, matches[0])
	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &bom); err != nil {
		t.Fatalf("parse generated CycloneDX SBOM: %v\n%s", err, string(body))
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Fatalf("bomFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	foundDep := false
	for _, component := range bom.Components {
		if component.Name == "example.test/dep" && component.Version == "v0.0.0" && component.PURL == "pkg:golang/example.test/dep@v0.0.0" {
			foundDep = true
			break
		}
	}
	if !foundDep {
		t.Fatalf("generated SBOM missing example.test/dep component: %+v", bom.Components)
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

	return packmonCommandInDir(t, "", hermeticPackmonEnv(t, nil), args...)
}

func packmonCommandInDir(t *testing.T, dir string, env []string, args ...string) (*exec.Cmd, context.Context, context.CancelFunc) {
	t.Helper()

	binary := packmonBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), e2eCommandTimeout)
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- e2e tests execute the built packmon binary with test-controlled arguments.
	cmd.Dir = dir
	cmd.Env = env
	return cmd, ctx, cancel
}

func runGit(t *testing.T, git, dir string, env []string, args ...string) {
	t.Helper()

	out, err := gitCommand(t, git, dir, env, args...)
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(out))
	}
}

func gitCommand(t *testing.T, git, dir string, env []string, args ...string) ([]byte, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), e2eCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, git, args...) // #nosec G204 -- e2e tests execute git with test-controlled arguments.
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	failIfE2ECommandTimedOut(t, ctx, "git "+strings.Join(args, " "), out)
	return out, err
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
	t.Fatal("PACKMON_TEST_BIN_DIR is required for e2e tests; build first with: go build -o .build\\packmon.exe .\\cmd\\packmon and set PACKMON_TEST_BIN_DIR=.build")
	return ""
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
