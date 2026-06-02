package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/domain"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// stubLatestVersion swaps fetchLatestVersionFn for the duration of the test so
// the list-all package table never makes real network calls.
func stubLatestVersion(t *testing.T, fn func(ctx context.Context, eco domain.Ecosystem, name string) string) {
	t.Helper()
	orig := fetchLatestVersionFn
	fetchLatestVersionFn = fn
	t.Cleanup(func() { fetchLatestVersionFn = orig })
}

// isolatedListAllEnv isolates config discovery and points the local DB at a
// temp directory, mirroring the harness every other scan test uses. Without
// this the scan pipeline touches the real home directory.
func isolatedListAllEnv(t *testing.T) {
	t.Helper()
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}
}

// seedListAllAdvisory inserts a CRITICAL advisory for npm/vulnpkg@1.0.0 into
// the local SQLite advisory tables so the scanner reports a finding.
func seedListAllAdvisory(t *testing.T, dbDir string) {
	t.Helper()
	store, _ := newTestSQLiteStore(t, dbDir)
	ctx := context.Background()
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, summary)
		VALUES('GHSA-listall-test|npm|vulnpkg', 'GHSA-listall-test', 'npm', 'vulnpkg', '[{"introduced":"0.0.0"},{"fixed":"2.0.0"}]', 'CRITICAL', 'list-all test advisory')`); err != nil {
		t.Fatalf("insert vulnerability: %v", err)
	}
}

// listAllSettings builds a minimal local-mode settings struct for a temp dir.
func listAllSettings(dir string, quiet bool) scanSettings {
	return scanSettings{
		TargetName: "x",
		Path:       dir,
		Mode:       "local",
		FailOn:     "CRITICAL",
		MaxDepth:   10,
		Timeout:    30,
		Quiet:      quiet,
		NoColor:    true,
	}
}

func TestRunListAll_ListsAllPackagesWithUpdateInfo(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/leftpad": { "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.15" }
  }
}`)

	// leftpad has a newer version, lodash is up to date.
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "leftpad":
			return "2.0.0"
		case "lodash":
			return "4.17.15"
		default:
			return ""
		}
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	// Section 2 header + both packages present.
	for _, col := range []string{"PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "VULN", "LOCK FILE"} {
		if !contains(out, col) {
			t.Errorf("output missing section-2 column %q:\n%s", col, out)
		}
	}
	if !contains(out, "leftpad") {
		t.Errorf("output missing leftpad:\n%s", out)
	}
	if !contains(out, "lodash") {
		t.Errorf("output missing lodash:\n%s", out)
	}
	if !contains(out, "2.0.0") {
		t.Errorf("output missing leftpad latest version:\n%s", out)
	}
	if !contains(out, "packages (") {
		t.Errorf("output missing summary line:\n%s", out)
	}
}

func TestRunListAll_IncludesDevPackagesByDefault(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/prod": { "version": "1.0.0" },
    "node_modules/dev-only": { "version": "1.0.0", "dev": true }
  }
}`)

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "prod", "dev-only":
			return "1.0.0"
		default:
			return ""
		}
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	if !contains(out, "prod") {
		t.Fatalf("output missing prod package:\n%s", out)
	}
	if !contains(out, "dev-only") {
		t.Fatalf("list-all should include dev packages by default:\n%s", out)
	}
	if !contains(out, "2 packages (") {
		t.Fatalf("list-all package count should include dev packages:\n%s", out)
	}
}

func TestRunListAll_WritesHTMLReportWithFullPackageList(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/leftpad": { "version": "1.0.0" },
    "node_modules/dev-only": { "version": "1.0.0", "dev": true }
  }
}`)
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "leftpad":
			return "2.0.0"
		case "dev-only":
			return "1.0.0"
		default:
			return ""
		}
	})

	settings := listAllSettings(dir, false)
	settings.OutputHTML = htmlPath
	if _, err := runListAll(context.Background(), settings); err != nil {
		t.Fatalf("runListAll: %v", err)
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read list-all HTML report: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		"<!DOCTYPE html>",
		"Packmon List-All Report",
		"Findings",
		"All Packages",
		"leftpad",
		"dev-only",
		"1.0.0",
		"2.0.0",
		"<th class=\"version\">Installed</th>",
	} {
		if !contains(out, want) {
			t.Fatalf("list-all HTML missing %q:\n%s", want, out)
		}
	}
}

func TestScanCommandListAllHTMLFlagWritesFullReport(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/prod": { "version": "1.0.0" },
    "node_modules/dev-only": { "version": "1.0.0", "dev": true }
  }
}`)
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "prod", "dev-only":
			return "2.0.0"
		default:
			return ""
		}
	})

	checkRequests := make(chan domain.ScanRequest, 1)
	checkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer remote-key" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		var req domain.ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		checkRequests <- req
		writeJSONForTest(t, w, domain.ScanResult{
			ScanID:          "list-all-remote",
			Mode:            "remote",
			ScannedAt:       time.Now().UTC(),
			PackagesScanned: len(req.Packages),
			Findings:        []domain.Finding{},
			FeedStatus:      "healthy",
			FeedVersions:    map[string]string{"test": time.Now().UTC().Format(time.RFC3339)},
		})
	}))
	defer checkServer.Close()

	cmd := newScanCmd()
	cmd.SetArgs([]string{
		"--mode", "remote",
		"--server", checkServer.URL,
		"--api-key", "remote-key",
		"--insecure-allow-http",
		"--html", htmlPath,
		"--list-all",
		dir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan command execute: %v", err)
	}

	select {
	case req := <-checkRequests:
		if len(req.Packages) != 1 || req.Packages[0].Name != "prod" {
			t.Fatalf("remote list-all request packages = %#v, want only prod by default", req.Packages)
		}
	case <-time.After(time.Second):
		t.Fatal("remote list-all check request was not received")
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read list-all HTML report: %v", err)
	}
	out := string(data)
	for _, want := range []string{"Packmon List-All Report", "All Packages", "prod", "dev-only", "2 packages"} {
		if !contains(out, want) {
			t.Fatalf("list-all command HTML missing %q:\n%s", want, out)
		}
	}
}

func TestScanCommandListAllIncludeDevScansDevPackages(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/prod": { "version": "1.0.0" },
    "node_modules/dev-only": { "version": "1.0.0", "dev": true }
  }
}`)

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "prod", "dev-only":
			return "1.0.0"
		default:
			return ""
		}
	})

	checkRequests := make(chan domain.ScanRequest, 1)
	checkServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req domain.ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		checkRequests <- req
		writeJSONForTest(t, w, domain.ScanResult{ScanID: "include-dev", Mode: "remote"})
	}))
	defer checkServer.Close()

	cmd := newScanCmd()
	cmd.SetArgs([]string{
		"--mode", "remote",
		"--server", checkServer.URL,
		"--api-key", "remote-key",
		"--insecure-allow-http",
		"--list-all",
		"--include-dev",
		dir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan command execute: %v", err)
	}

	select {
	case req := <-checkRequests:
		if len(req.Packages) != 2 {
			t.Fatalf("remote list-all --include-dev request packages = %#v, want prod and dev-only", req.Packages)
		}
	case <-time.After(time.Second):
		t.Fatal("remote list-all check request was not received")
	}
}

func TestRunListAll_UnknownLatestWhenResolverReturnsEmpty(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	// Resolver failures or unsupported upstream metadata are rendered as
	// "unknown" instead of failing the list-all command.
	writeFile(t, filepath.Join(dir, "pubspec.lock"), `# Generated by pub
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "0.13.0"
sdks:
  dart: ">=2.12.0 <3.0.0"
`)

	called := false
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		called = true
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	if !contains(out, "http") {
		t.Errorf("output missing http package:\n%s", out)
	}
	if !contains(out, "unknown") {
		t.Errorf("expected LATEST=unknown when resolver returns empty:\n%s", out)
	}
	if !called {
		t.Errorf("expected fetchLatestVersionFn to be invoked (stub), got no call")
	}
}

func TestRunListAll_UpdateColumnLogic(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/old": { "version": "1.0.0" },
    "node_modules/current": { "version": "2.0.0" }
  }
}`)

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "old":
			return "9.9.9"
		case "current":
			return "2.0.0"
		default:
			return ""
		}
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	lines := strings.Split(out, "\n")
	var oldLine, currentLine string
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "old":
			oldLine = l
		case "current":
			currentLine = l
		}
	}
	if oldLine == "" || currentLine == "" {
		t.Fatalf("could not find package rows in output:\n%s", out)
	}
	// Columns: PACKAGE INSTALLED LATEST UPDATE ECOSYSTEM VULN LOCKFILE
	oldFields := strings.Fields(oldLine)
	if len(oldFields) < 4 || oldFields[3] != "yes" {
		t.Errorf("expected UPDATE=yes for old, got line: %q", oldLine)
	}
	currentFields := strings.Fields(currentLine)
	if len(currentFields) < 4 || currentFields[3] != "-" {
		t.Errorf("expected UPDATE=- for current, got line: %q", currentLine)
	}
}

func TestRunListAllDoesNotMarkNewerGoPseudoVersionAsUpdate(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/app

go 1.26

require github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
`)

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "github.com/davecgh/go-spew" {
			return "v1.1.1"
		}
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	lines := strings.Split(out, "\n")
	var spewLine string
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) > 0 && fields[0] == "github.com/davecgh/go-spew" {
			spewLine = l
			break
		}
	}
	if spewLine == "" {
		t.Fatalf("could not find go-spew row in output:\n%s", out)
	}
	fields := strings.Fields(spewLine)
	if len(fields) < 4 || fields[3] != "-" {
		t.Fatalf("expected UPDATE=- for newer Go pseudo-version, got line: %q", spewLine)
	}
	if !strings.Contains(out, "1 packages (0 with updates") {
		t.Fatalf("expected zero updates in summary:\n%s", out)
	}
}

func TestRunListAll_VulnerablePackageAppearsInBothSections(t *testing.T) {
	isolatedListAllEnv(t)
	dbDir := os.Getenv("PACKMON_DB_PATH")

	// Seed an advisory for vulnpkg@1.0.0 so the scanner reports a finding.
	seedListAllAdvisory(t, dbDir)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/vulnpkg": { "version": "1.0.0" },
    "node_modules/safe": { "version": "2.0.0" }
  }
}`)

	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "vulnpkg":
			return "1.0.1"
		case "safe":
			return "2.0.0"
		default:
			return ""
		}
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	// Section 1: finding for vulnpkg.
	if !contains(out, "GHSA-listall-test") && !contains(out, "vulnpkg") {
		t.Errorf("expected section-1 finding referencing vulnpkg:\n%s", out)
	}

	// Section 2: vulnpkg row with VULN=yes; safe row with VULN=-.
	lines := strings.Split(out, "\n")
	var vulnLine, safeLine string
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "vulnpkg":
			vulnLine = l
		case "safe":
			safeLine = l
		}
	}
	if vulnLine == "" || safeLine == "" {
		t.Fatalf("could not find package rows in section 2:\n%s", out)
	}
	// VULN is the field before LOCK FILE. Empty VIA/FLAGS columns collapse under
	// strings.Fields, so do not assert a fixed column index here.
	vf := strings.Fields(vulnLine)
	if len(vf) < 2 || vf[len(vf)-2] != "yes" {
		t.Errorf("expected VULN=yes for vulnpkg, got line: %q", vulnLine)
	}
	sf := strings.Fields(safeLine)
	if len(sf) < 2 || sf[len(sf)-2] != "-" {
		t.Errorf("expected VULN=- for safe, got line: %q", safeLine)
	}
}

func TestRunListAll_FindingsSectionRendersTable(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/leftpad": { "version": "1.0.0" }
  }
}`)
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	// Local mode with an empty advisory DB is operationally incomplete. The
	// normal scan section must not present it as a clean "No findings" scan.
	if !contains(out, "Scan did not complete") {
		t.Errorf("expected findings-section operational status line:\n%s", out)
	}
	if contains(out, "No findings") {
		t.Errorf("operational status must not be rendered as clean:\n%s", out)
	}
}

func TestRunListAll_QuietSuppressesHumanOutput(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/leftpad": { "version": "1.0.0" }
  }
}`)
	stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		return "2.0.0"
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, true)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	if strings.TrimSpace(out) != "" {
		t.Errorf("expected no stdout in quiet mode, got:\n%s", out)
	}
}

func TestBuildListAllPackageReportDockerUpdateStatus(t *testing.T) {
	old := resolveDockerImageStatusFn
	t.Cleanup(func() { resolveDockerImageStatusFn = old })
	resolveDockerImageStatusFn = func(_ context.Context, p listAllPackage) listAllLatest {
		if p.Name != "docker.io/library/postgres" || p.Version != "18-alpine" {
			t.Fatalf("docker status package = %#v", p)
		}
		return listAllLatest{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	report := buildListAllPackageReport([]listAllPackage{{
		Name:      "docker.io/library/postgres",
		Version:   "18-alpine",
		Ecosystem: domain.EcosystemDocker,
		LockFile:  "docker-compose.yml",
	}}, &domain.ScanResult{}, ".")

	if len(report.Rows) != 1 {
		t.Fatalf("Rows = %#v", report.Rows)
	}
	row := report.Rows[0]
	if row.Latest != "sha256:remote" || row.Update != "unknown" || report.Unknown != 1 {
		t.Fatalf("row=%#v report=%#v", row, report)
	}
}

func TestRunListAllIncludesDockerImages(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM golang:1.26-alpine AS build\nFROM alpine:3.23 AS server\n"), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services:\n  db:\n    image: postgres:18-alpine\n"), 0o600); err != nil {
		t.Fatalf("write compose: %v", err)
	}

	oldLatest := fetchLatestVersionFn
	oldDocker := resolveDockerImageStatusFn
	t.Cleanup(func() {
		fetchLatestVersionFn = oldLatest
		resolveDockerImageStatusFn = oldDocker
	})
	fetchLatestVersionFn = func(context.Context, domain.Ecosystem, string) string { return "" }
	resolveDockerImageStatusFn = func(context.Context, listAllPackage) listAllLatest {
		return listAllLatest{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	output := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	for _, want := range []string{
		"docker.io/library/golang",
		"docker.io/library/alpine",
		"docker.io/library/postgres",
		"docker",
		"Dockerfile",
		"docker-compose.yml",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("list-all output missing %q:\n%s", want, output)
		}
	}
}

func TestRunListAllHTMLIncludesDockerImages(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.23\n"), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	oldDocker := resolveDockerImageStatusFn
	t.Cleanup(func() { resolveDockerImageStatusFn = oldDocker })
	resolveDockerImageStatusFn = func(context.Context, listAllPackage) listAllLatest {
		return listAllLatest{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	settings := listAllSettings(dir, false)
	settings.OutputHTML = htmlPath
	if _, err := runListAll(context.Background(), settings); err != nil {
		t.Fatalf("runListAll: %v", err)
	}
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{"docker.io/library/alpine", "docker", "Dockerfile", "sha256:remote"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing %q:\n%s", want, out)
		}
	}
}

func TestPlainScanDoesNotSendDockerInventoryPackages(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.23\n"), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"node_modules/left-pad": {"version": "1.3.0"}
		}
	}`), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	var requestSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		requestSeen = true
		var req struct {
			Packages []domain.Package `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		var sawNPM bool
		for _, pkg := range req.Packages {
			if pkg.Ecosystem == domain.EcosystemNPM && pkg.Name == "left-pad" && pkg.Version == "1.3.0" {
				sawNPM = true
			}
			if pkg.Ecosystem == domain.EcosystemDocker {
				t.Fatalf("plain scan request included docker package: %#v", pkg)
			}
		}
		if !sawNPM {
			t.Fatalf("plain scan request packages = %#v, want npm left-pad and no docker packages", req.Packages)
		}
		writeJSONForTest(t, w, domain.ScanResult{ScanID: "scan", Mode: "remote"})
	}))
	defer server.Close()

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--mode", "remote", "--server", server.URL, "--api-key", "test", "--insecure-allow-http", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !requestSeen {
		t.Fatal("plain scan did not call remote check; test would not prove docker exclusion")
	}
}

func TestListAllDockerRowsRenderScopeRelationAndFlags(t *testing.T) {
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "docker.io/library/postgres",
			Installed: "18-alpine",
			Latest:    "sha256:remote",
			Update:    "unknown",
			Ecosystem: "docker",
			Vuln:      "-",
			Scope:     "runtime",
			Relation:  "compose",
			Flags:     "service=postgres",
			LockFile:  "docker-compose.yml",
		}},
		Unknown: 1,
	}
	output := captureStdout(t, func() {
		printListAllPackageReport(report)
	})
	for _, want := range []string{"SCOPE", "RELATION", "VIA", "FLAGS", "runtime", "compose", "service=postgres"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestListAllHTMLRendersScopeSummaryAndFindingMetadata(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{Name: "runtime", Installed: "1.0.0", Ecosystem: "npm", Scope: "runtime", Relation: "direct", Vuln: "-"},
			{Name: "postcss", Installed: "8.5.8", Ecosystem: "npm", Scope: "dev", Relation: "transitive", Via: "tailwindcss", Flags: "peer", Vuln: "yes"},
			{Name: "actions/checkout", Installed: "v6", Ecosystem: "actions", Scope: "ci", Relation: "workflow", Vuln: "-"},
		},
		Vulnerable: 1,
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:         "postcss",
			Version:      "8.5.8",
			Ecosystem:    domain.EcosystemNPM,
			Severity:     domain.SeverityMedium,
			AdvisoryID:   "GHSA-postcss-test",
			FixedVersion: "8.5.10",
			Source:       "osv",
		}},
	}
	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{"runtime 1", "dev 1", "ci 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing scope summary %q:\n%s", want, out)
		}
	}
	wantFinding := `<td class="finding-package">postcss@8.5.8</td><td class="short">npm</td><td>GHSA-postcss-test</td><td>8.5.10</td><td>osv</td><td class="short">dev</td><td class="short">transitive</td><td>tailwindcss</td><td class="short">peer</td>`
	if !strings.Contains(out, wantFinding) {
		t.Fatalf("HTML finding row missing package provenance:\n%s", out)
	}
}
