package main

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/dockerimage"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestRunListAllReusesScanPipelinePackageCollection(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), "list_all.go", nil, 0)
	if err != nil {
		t.Fatalf("parse list_all.go: %v", err)
	}
	var runListAll *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "runListAll" {
			runListAll = fn
			break
		}
	}
	if runListAll == nil {
		t.Fatal("runListAll not found")
	}

	ast.Inspect(runListAll.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if ident, ok := fun.X.(*ast.Ident); ok && ident.Name == "scanner" && fun.Sel.Name == "CollectPackages" {
				t.Fatalf("runListAll calls scanner.CollectPackages directly; reuse runScanPipeline collection instead")
			}
		case *ast.Ident:
			switch fun.Name {
			case "collectAllPackages", "collectAllPackagesWithWarnings":
				t.Fatalf("runListAll calls %s; reuse runScanPipeline collection instead", fun.Name)
			}
		}
		return true
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// stubLatestVersion returns a resolver that keeps package table tests off the
// network without mutating process-wide lookup state.
func stubLatestVersion(t *testing.T, fn func(ctx context.Context, eco domain.Ecosystem, name string) string) packageUpdateResolver {
	t.Helper()
	return packageUpdateResolver{fetchLatest: fn}
}

func stubLatestVersionContext(t *testing.T, fn func(ctx context.Context, eco domain.Ecosystem, name string) string) context.Context {
	t.Helper()
	return contextWithPackageUpdateResolver(context.Background(), stubLatestVersion(t, fn))
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

func TestCollectAllPackagesMalformedSBOMReturnsParserExit(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.cdx.json")
	writeFile(t, badPath, `{"bomFormat":"CycloneDX",`)

	_, err := collectAllPackages(scanSettings{
		Path:      dir,
		MaxDepth:  2,
		SBOMFiles: []string{badPath},
	})
	if err == nil {
		t.Fatal("collectAllPackages(malformed SBOM) error = nil")
	}
	if code := exitCodeForError(err); code != ExitParser {
		t.Fatalf("exitCodeForError = %d, want %d; err=%v", code, ExitParser, err)
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
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if _, err := runListAll(ctx, listAllSettings(dir, false)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	// Section 2 header + both packages present.
	for _, col := range []string{"PACKAGE", "INSTALLED", "LATEST", "UPDATE", "ECOSYSTEM", "SOURCE", "VULN", "SOURCE FILE"} {
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

func TestRunListAllOfflineSkipsExternalLookups(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/private-name": { "version": "1.0.0" }
  }
}`)
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM docker.io/library/nginx:1.25\n")

	var called atomic.Bool
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		called.Store(true)
		return "2.0.0"
	})
	oldDockerResolver := resolveDockerImageStatusFn
	var dockerCalled atomic.Bool
	resolveDockerImageStatusFn = func(context.Context, listAllPackage, map[string]string) packageLatestStatus {
		dockerCalled.Store(true)
		return packageLatestStatus{Latest: "sha256:remote", Update: "yes"}
	}
	t.Cleanup(func() { resolveDockerImageStatusFn = oldDockerResolver })

	out := captureStdout(t, func() {
		if _, err := runListAll(ctx, scanSettings{
			TargetName:     "x",
			Path:           dir,
			Mode:           "local",
			FailOn:         "CRITICAL",
			MaxDepth:       10,
			Timeout:        30,
			Quiet:          false,
			NoColor:        true,
			ListAllOffline: true,
		}); err != nil {
			t.Fatalf("runListAll offline: %v", err)
		}
	})

	if called.Load() {
		t.Fatal("offline list-all performed a latest-version lookup")
	}
	if dockerCalled.Load() {
		t.Fatal("offline list-all performed a Docker digest lookup")
	}
	for _, want := range []string{"private-name", "1.0.0", "unknown"} {
		if !strings.Contains(out, want) {
			t.Fatalf("offline list-all output missing %q:\n%s", want, out)
		}
	}
}

func TestScanCommandListAllOfflineFlagSkipsExternalLookups(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	seedListAllAdvisory(t, dbDir)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "test",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/private-name": { "version": "1.0.0" }
  }
}`)

	var called atomic.Bool
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		called.Store(true)
		return "2.0.0"
	})

	cmd := newScanCmd()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"--mode", "local", "--list-all", "--list-all-offline", dir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("scan --list-all --list-all-offline: %v", err)
		}
	})

	if called.Load() {
		t.Fatal("offline list-all flag performed a latest-version lookup")
	}
	if !strings.Contains(out, "private-name") || !strings.Contains(out, "unknown") {
		t.Fatalf("offline list-all flag output missing inventory/unknown latest:\n%s", out)
	}
}

func TestScanCommandListAllOfflineRequiresListAll(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--list-all-offline", t.TempDir()})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--list-all-offline can only be used with --list-all") {
		t.Fatalf("scan --list-all-offline error = %v, want list-all requirement", err)
	}
}

func TestPrintListAllPackageReportSanitizesTerminalControlText(t *testing.T) {
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "pkg\x1b]8;;https://evil.example\a\n::warning::pkg",
			Installed: "1.0.0\rspoof",
			Latest:    "2.0.0\tmasked",
			Update:    "yes",
			Ecosystem: "npm",
			Source:    "sbom",
			Scope:     "runtime",
			Relation:  "direct",
			Via:       "parent\x1b[31m",
			Flags:     "optional\n::error::flag",
			Vuln:      "yes",
			LockFile:  "sbom.cdx.json\x1b[0m",
		}},
		WithUpdates: 1,
		Vulnerable:  1,
	}

	output := captureStdout(t, func() {
		printListAllPackageReport(report)
	})

	for _, blocked := range []string{"\x1b", "\a", "\r", "\t", "\n::warning::", "\n::error::"} {
		if strings.Contains(output, blocked) {
			t.Fatalf("list-all output contains raw terminal control %q:\n%s", blocked, output)
		}
	}
	for _, want := range []string{`\x1B`, `\n::warning::pkg`, `\rspoof`, `\tmasked`, `\n::error::flag`} {
		if !strings.Contains(output, want) {
			t.Fatalf("list-all output missing sanitized text %q:\n%s", want, output)
		}
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

	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "prod", "dev-only":
			return "1.0.0"
		default:
			return ""
		}
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(ctx, listAllSettings(dir, false)); err != nil {
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

	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
	if _, err := runListAll(ctx, settings); err != nil {
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
		"<th class=\"installed\">Installed</th>",
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

	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if err := writeJSONResponseForTest(w, domain.ScanResult{
			ScanID:          "list-all-remote",
			Mode:            "remote",
			ScannedAt:       time.Now().UTC(),
			PackagesScanned: len(req.Packages),
			Findings:        []domain.Finding{},
			FeedStatus:      "healthy",
			FeedVersions:    map[string]string{"test": time.Now().UTC().Format(time.RFC3339)},
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer checkServer.Close()

	cmd := newScanCmd()
	cmd.SetContext(ctx)
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

	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if err := writeJSONResponseForTest(w, domain.ScanResult{ScanID: "include-dev", Mode: "remote"}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer checkServer.Close()

	cmd := newScanCmd()
	cmd.SetContext(ctx)
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
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		called = true
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(ctx, listAllSettings(dir, false)); err != nil {
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
		t.Errorf("expected latest-version resolver to be invoked, got no call")
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

	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if _, err := runListAll(ctx, listAllSettings(dir, false)); err != nil {
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

func TestResolveListAllLatestNPMTransitiveUsesParentWantedVersion(t *testing.T) {
	resolver := packageUpdateResolver{
		fetchLatest: func(_ context.Context, eco domain.Ecosystem, name string) string {
			if eco == domain.EcosystemNPM && name == "node-addon-api" {
				return "8.8.0"
			}
			return ""
		},
		fetchNPMMetadata: func(_ context.Context, name string) (npmRegistryMetadata, bool) {
			switch name {
			case "node-addon-api":
				return npmRegistryMetadata{
					DistTags: map[string]string{"latest": "8.8.0"},
					Versions: map[string]npmVersionManifest{
						"7.1.1": {Version: "7.1.1"},
						"8.8.0": {Version: "8.8.0"},
					},
				}, true
			case "@parcel/watcher":
				return npmRegistryMetadata{
					Versions: map[string]npmVersionManifest{
						"2.5.6": {
							Version:      "2.5.6",
							Dependencies: map[string]string{"node-addon-api": "^7.0.0"},
						},
					},
				}, true
			default:
				return npmRegistryMetadata{}, false
			}
		},
	}

	got := resolveListAllLatestWithLookup(context.Background(), listAllPackage{
		Name:      "node-addon-api",
		Version:   "7.1.1",
		Ecosystem: domain.EcosystemNPM,
		Indirect:  true,
		Parents: []domain.PackageParent{{
			Name:      "@parcel/watcher",
			Version:   "2.5.6",
			Ecosystem: domain.EcosystemNPM,
		}},
	}, directPackageUpdateLookupWithResolver(resolver), nil)
	if got.Latest != "7.1.1" || got.Update != "-" || got.Unknown {
		t.Fatalf("resolveListAllLatest() = %+v, want wanted 7.1.1 without update", got)
	}
}

func TestBuildListAllPackageReportCachesRegistryMetadata(t *testing.T) {
	var latestCalls atomic.Int32
	var metadataCalls atomic.Int32
	resolver := packageUpdateResolver{
		fetchLatest: func(_ context.Context, eco domain.Ecosystem, name string) string {
			if eco != domain.EcosystemNPM || name != "child" {
				t.Fatalf("fetchLatest(%s, %q)", eco, name)
			}
			latestCalls.Add(1)
			return "9.0.0"
		},
		fetchNPMMetadata: func(_ context.Context, name string) (npmRegistryMetadata, bool) {
			metadataCalls.Add(1)
			switch name {
			case "child":
				return npmRegistryMetadata{Versions: map[string]npmVersionManifest{
					"1.0.0": {},
					"1.1.0": {},
					"1.5.0": {},
					"9.0.0": {},
				}}, true
			case "parent":
				return npmRegistryMetadata{Versions: map[string]npmVersionManifest{
					"1.0.0": {Dependencies: map[string]string{"child": "^1.0.0"}},
				}}, true
			default:
				t.Fatalf("fetchNPMMetadata(%q)", name)
				return npmRegistryMetadata{}, false
			}
		},
	}

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{
		{
			Name:      "child",
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
			Indirect:  true,
			Parents:   []domain.PackageParent{{Name: "parent", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}},
		},
		{
			Name:      "child",
			Version:   "1.1.0",
			Ecosystem: domain.EcosystemNPM,
			Indirect:  true,
			Parents:   []domain.PackageParent{{Name: "parent", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}},
		},
	}, nil, "repo", 1, listAllPackageReportOptions{resolver: resolver})

	if report.WithUpdates != 2 {
		t.Fatalf("WithUpdates = %d, want 2", report.WithUpdates)
	}
	if got := latestCalls.Load(); got != 1 {
		t.Fatalf("latest-version lookups = %d, want 1 cached lookup", got)
	}
	if got := metadataCalls.Load(); got != 2 {
		t.Fatalf("npm metadata lookups = %d, want child and parent once", got)
	}
}

func TestResolveListAllLatestGitHubActionSHAAtLatestTagDoesNotReportUpdate(t *testing.T) {
	sha := "4a3601121dd01d1626a1e23e37211e3254c1c06c"
	resolver := packageUpdateResolver{
		fetchLatest: func(_ context.Context, eco domain.Ecosystem, name string) string {
			if eco != domain.EcosystemGitHubActions || name != "actions/setup-go" {
				t.Fatalf("fetchLatest(%s, %q)", eco, name)
			}
			return "v6.4.0"
		},
		gitRemoteTagCommit: func(_ context.Context, remote, tag string) (string, bool) {
			if remote != "https://github.com/actions/setup-go.git" || tag != "v6.4.0" {
				t.Fatalf("gitRemoteTagCommit(%q, %q)", remote, tag)
			}
			return sha, true
		},
	}

	got := resolveListAllLatestWithLookup(context.Background(), listAllPackage{
		Name:      "actions/setup-go",
		Version:   sha,
		Ecosystem: domain.EcosystemGitHubActions,
	}, directPackageUpdateLookupWithResolver(resolver), nil)
	if got.Latest != "v6.4.0" || got.Update != "-" || got.Unknown {
		t.Fatalf("resolveListAllLatest() = %+v, want latest tag without update for matching SHA", got)
	}
}

func TestRunListAllDoesNotMarkNewerGoPseudoVersionAsUpdate(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/app

go 1.26

require github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
`)

	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "github.com/davecgh/go-spew" {
			return "v1.1.1"
		}
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(ctx, listAllSettings(dir, false)); err != nil {
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
	if !strings.Contains(out, "1 package (0 with updates") {
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

	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if _, err := runListAll(ctx, listAllSettings(dir, false)); err != nil {
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
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(ctx, listAllSettings(dir, false)); err != nil {
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
	ctx := stubLatestVersionContext(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		return "2.0.0"
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(ctx, listAllSettings(dir, true)); err != nil {
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
	resolveDockerImageStatusFn = func(_ context.Context, p listAllPackage, _ map[string]string) packageLatestStatus {
		if p.Name != "docker.io/library/postgres" || p.Version != "18-alpine" {
			t.Fatalf("docker status package = %#v", p)
		}
		return packageLatestStatus{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	report := buildListAllPackageReport(context.Background(), []listAllPackage{{
		Name:      "docker.io/library/postgres",
		Version:   "18-alpine",
		Ecosystem: domain.EcosystemDocker,
		LockFile:  "docker-compose.yml",
	}}, &domain.ScanResult{}, ".", 30)

	if len(report.Rows) != 1 {
		t.Fatalf("Rows = %#v", report.Rows)
	}
	row := report.Rows[0]
	if row.Latest != "sha256:remote" || row.Update != "unknown" || report.Unknown != 1 {
		t.Fatalf("row=%#v report=%#v", row, report)
	}
}

func TestBuildListAllPackageReportBatchesDockerLocalDigests(t *testing.T) {
	oldInspect := inspectLocalDockerDigestsFn
	oldResolve := resolveDockerImageStatusFn
	t.Cleanup(func() {
		inspectLocalDockerDigestsFn = oldInspect
		resolveDockerImageStatusFn = oldResolve
	})

	var inspectCalls atomic.Int32
	inspectLocalDockerDigestsFn = func(_ context.Context, packages []listAllPackage) map[string]string {
		inspectCalls.Add(1)
		if len(packages) != 3 {
			t.Fatalf("inspect packages = %d, want full report package set", len(packages))
		}
		return map[string]string{
			"docker.io/library/postgres": "sha256:local-postgres",
			"docker.io/library/nginx":    "sha256:local-nginx",
		}
	}

	var dockerResolveCalls atomic.Int32
	resolveDockerImageStatusFn = func(_ context.Context, p listAllPackage, localDigests map[string]string) packageLatestStatus {
		dockerResolveCalls.Add(1)
		if localDigests == nil {
			t.Fatal("local Docker digest map was not passed to Docker resolver")
		}
		if _, ok := localDigests[p.Name]; !ok {
			t.Fatalf("local digest map missing %s: %#v", p.Name, localDigests)
		}
		return packageLatestStatus{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	report := buildListAllPackageReport(context.Background(), []listAllPackage{
		{Name: "docker.io/library/postgres", Version: "18-alpine", Ecosystem: domain.EcosystemDocker, LockFile: "docker-compose.yml"},
		{Name: "leftpad", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, LockFile: "package-lock.json"},
		{Name: "docker.io/library/nginx", Version: "1.25", Ecosystem: domain.EcosystemDocker, LockFile: "Dockerfile"},
	}, &domain.ScanResult{}, ".", 30)

	if got := inspectCalls.Load(); got != 1 {
		t.Fatalf("local Docker inspect calls = %d, want one batched call", got)
	}
	if got := dockerResolveCalls.Load(); got != 2 {
		t.Fatalf("Docker resolver calls = %d, want one per Docker row", got)
	}
	if len(report.Rows) != 3 {
		t.Fatalf("Rows = %d, want 3", len(report.Rows))
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

	oldDocker := resolveDockerImageStatusFn
	t.Cleanup(func() {
		resolveDockerImageStatusFn = oldDocker
	})
	ctx := stubLatestVersionContext(t, func(context.Context, domain.Ecosystem, string) string { return "" })
	resolveDockerImageStatusFn = func(context.Context, listAllPackage, map[string]string) packageLatestStatus {
		return packageLatestStatus{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	output := captureStdout(t, func() {
		if _, err := runListAll(ctx, listAllSettings(dir, false)); err != nil {
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
	resolveDockerImageStatusFn = func(context.Context, listAllPackage, map[string]string) packageLatestStatus {
		return packageLatestStatus{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	settings := listAllSettings(dir, false)
	settings.OutputHTML = htmlPath
	if _, err := runListAll(context.Background(), settings); err != nil {
		t.Fatalf("runListAll: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
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
	handlerErrors := make(chan string, 1)
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check" {
			reportHandlerError(w, handlerErrors, http.StatusNotFound, "unexpected path %s", r.URL.Path)
			return
		}
		select {
		case requests <- struct{}{}:
		default:
		}
		var req struct {
			Packages []domain.Package `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reportHandlerError(w, handlerErrors, http.StatusBadRequest, "decode request: %v", err)
			return
		}
		var sawNPM bool
		for _, pkg := range req.Packages {
			if pkg.Ecosystem == domain.EcosystemNPM && pkg.Name == "left-pad" && pkg.Version == "1.3.0" {
				sawNPM = true
			}
			if pkg.Ecosystem == domain.EcosystemDocker {
				reportHandlerError(w, handlerErrors, http.StatusBadRequest, "plain scan request included docker package: %#v", pkg)
				return
			}
		}
		if !sawNPM {
			reportHandlerError(w, handlerErrors, http.StatusBadRequest, "plain scan request packages = %#v, want npm left-pad and no docker packages", req.Packages)
			return
		}
		if err := writeJSONResponseForTest(w, domain.ScanResult{ScanID: "scan", Mode: "remote"}); err != nil {
			reportHandlerError(w, handlerErrors, http.StatusInternalServerError, "encode JSON response: %v", err)
			return
		}
	}))
	defer server.Close()

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--mode", "remote", "--server", server.URL, "--api-key", "test", "--insecure-allow-http", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assertNoHandlerError(t, handlerErrors)
	select {
	case <-requests:
	default:
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
			Title:        "PostCSS test advisory",
			FixedVersion: "8.5.10",
			Source:       "osv",
		}},
	}
	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{"runtime 1", "dev 1", "ci 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing scope summary %q:\n%s", want, out)
		}
	}
	wantFinding := `<td class="finding-package">postcss@8.5.8</td><td class="short">npm</td><td class="finding-advisory"><a href="https://github.com/advisories/GHSA-postcss-test" target="_blank" rel="noopener" aria-label="GHSA-postcss-test opens in a new tab">GHSA-postcss-test<span aria-hidden="true"> &#8599;</span><span class="sr-only"> (opens in a new tab)</span></a></td><td class="finding-title">PostCSS test advisory</td><td class="finding-fixed">8.5.10</td><td class="short">osv</td><td class="short">dev</td><td class="short">transitive</td>`
	if !strings.Contains(out, wantFinding) {
		t.Fatalf("HTML finding row missing package provenance:\n%s", out)
	}
	for _, removed := range []string{
		`<th class="text via">Via</th>`,
		`<th class="text flags">Flags</th>`,
		`<td class="text via">tailwindcss</td>`,
		`<td class="text flags">peer</td>`,
	} {
		if strings.Contains(out, removed) {
			t.Fatalf("HTML still contains noisy provenance column %q:\n%s", removed, out)
		}
	}
}

func TestListAllHTMLLinksSecurityFindingAdvisoryWithoutWrapping(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "github/codeql-action",
			Installed: "7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
			Latest:    "v4.36.2",
			Update:    "-",
			Ecosystem: "actions",
			Scope:     "ci",
			Relation:  "workflow",
			Vuln:      "yes",
		}},
		Vulnerable: 1,
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:       "github/codeql-action",
			Version:    "7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
			Ecosystem:  domain.EcosystemGitHubActions,
			Severity:   domain.SeverityHigh,
			AdvisoryID: "GHSA-vqf5-2xx6-9wfm",
			URL:        "https://nvd.nist.gov/vuln/detail/CVE-2025-24362",
			Source:     "ghsa",
		}},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	want := `<td class="finding-advisory"><a href="https://github.com/advisories/GHSA-vqf5-2xx6-9wfm" target="_blank" rel="noopener" aria-label="GHSA-vqf5-2xx6-9wfm opens in a new tab">GHSA-vqf5-2xx6-9wfm<span aria-hidden="true"> &#8599;</span><span class="sr-only"> (opens in a new tab)</span></a></td>`
	if !strings.Contains(out, want) {
		t.Fatalf("HTML finding advisory missing nowrap external link:\n%s", out)
	}
}

func TestListAllHTMLGroupsSecurityFindingsByOperationalPriority(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{Name: "evilpkg", Installed: "1.0.0", Ecosystem: "npm", Scope: "runtime", Relation: "direct", Vuln: "-"},
			{Name: "risky", Installed: "2.0.0", Ecosystem: "pypi", Scope: "runtime", Relation: "direct", Vuln: "-"},
			{Name: "vulnpkg", Installed: "3.0.0", Ecosystem: "go", Scope: "runtime", Relation: "direct", Vuln: "yes"},
			{Name: "oldpkg", Installed: "4.0.0", Ecosystem: "npm", Scope: "runtime", Relation: "direct", Vuln: "-"},
		},
		Vulnerable: 1,
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{
			{Name: "vulnpkg", Version: "3.0.0", Ecosystem: domain.EcosystemGo, Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh, AdvisoryID: "CVE-2026-0001", Title: "reachable vulnerability", RiskType: "known_vulnerability", Source: "osv"},
			{Name: "oldpkg", Version: "4.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeLifecycle, Severity: domain.SeverityMedium, AdvisoryID: "endoflife:oldpkg", Title: "security support ended", RiskType: "security_support_ended", Source: "endoflife.date"},
			{Name: "risky", Version: "2.0.0", Ecosystem: domain.EcosystemPyPI, Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityHigh, AdvisoryID: "reversinglabs:pypi/risky@2.0.0", Title: "incident history", RiskType: "malware_history", Source: "reversinglabs"},
			{Name: "evilpkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical, AdvisoryID: "MAL-evilpkg", Title: "malware detected", RiskType: "malware", Source: "openssf"},
		},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{"Malicious", "Supply-Chain / EOL", "Vulnerabilities", "Lifecycle warnings", "<th class=\"short\">Type</th>", "<th class=\"short\">Risk</th>", "malware_history", "known_vulnerability"} {
		if !strings.Contains(out, want) {
			t.Fatalf("grouped finding HTML missing %q:\n%s", want, out)
		}
	}
	assertInOrder(t, out, "Malicious", "Supply-Chain / EOL", "Vulnerabilities", "Lifecycle warnings")
}

func TestListAllHTMLDoesNotLinkUnsafeFindingURLs(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{Name: "badlink", Installed: "1.0.0", Ecosystem: "npm", Scope: "runtime", Relation: "direct", Vuln: "yes"}},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name: "badlink", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh,
			Title: "unsafe URL regression", URL: "javascript:alert(1)",
			Resources: []domain.ResourceLink{
				{Label: "data", URL: "data:text/html,owned"},
				{Label: "file", URL: "file:///etc/passwd"},
			},
		}},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, blocked := range []string{`href="javascript:`, `href="data:`, `href="file:`} {
		if strings.Contains(out, blocked) {
			t.Fatalf("list-all HTML emitted unsafe advisory link %q:\n%s", blocked, out)
		}
	}
}

func TestListAllHTMLSuppressesCleanEmptyStatesWhenInventoryWarningsExist(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Warnings: []string{"parse error in broken/package-lock.json"},
	}
	result := &domain.ScanResult{Mode: "local"}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "parse error in broken/package-lock.json") {
		t.Fatalf("HTML missing inventory warning:\n%s", out)
	}
	for _, clean := range []string{
		"No package status issues requiring attention.",
		"No security findings",
		"No packages found.",
	} {
		if strings.Contains(out, clean) {
			t.Fatalf("HTML rendered clean empty state %q despite inventory warning:\n%s", clean, out)
		}
	}
}

func TestListAllHTMLIncludesResponsivePrintAndLightThemePolicy(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "github.com/acme/" + strings.Repeat("very-long-module-name-", 6),
			Installed: strings.Repeat("abcdef0123456789", 4),
			Latest:    strings.Repeat("fedcba9876543210", 4),
			Ecosystem: "go",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "-",
			LockFile:  "go.sum",
		}},
	}
	result := &domain.ScanResult{Mode: "local"}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		"--success:",
		"--sev-low:",
		"overflow-wrap:anywhere",
		"word-break:break-word",
		"@media (prefers-color-scheme: light)",
		"@media print",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML CSS missing %q:\n%s", want, out)
		}
	}
}

func TestListAllHTMLTableScrollRegionsAreKeyboardFocusable(t *testing.T) {
	for _, want := range []string{
		".table-scroll:focus{",
		`<div class="table-scroll" tabindex="0" role="region" aria-label="Packages needing attention table">`,
		`<div class="table-scroll" tabindex="0" role="region" aria-label="Security findings table">`,
		`<div class="table-scroll" tabindex="0" role="region" aria-label="All packages table">`,
	} {
		if !strings.Contains(listAllHTML, want) {
			t.Fatalf("list-all HTML template missing keyboard-scroll contract %q", want)
		}
	}
}

func assertInOrder(t *testing.T, text string, values ...string) {
	t.Helper()

	last := -1
	for _, value := range values {
		idx := strings.Index(text, value)
		if idx < 0 {
			t.Fatalf("missing %q in output", value)
		}
		if idx <= last {
			t.Fatalf("%q appeared out of order in %q", value, values)
		}
		last = idx
	}
}

func TestListAllHTMLOmitsFindingBlockingSummaryBadge(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "github/codeql-action",
			Installed: "7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
			Latest:    "v4.36.2",
			Update:    "-",
			Ecosystem: "actions",
			Scope:     "ci",
			Relation:  "workflow",
			Vuln:      "yes",
		}},
		Vulnerable: 1,
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:       "github/codeql-action",
			Version:    "7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
			Ecosystem:  domain.EcosystemGitHubActions,
			Severity:   domain.SeverityHigh,
			AdvisoryID: "GHSA-vqf5-2xx6-9wfm",
			Source:     "ghsa",
		}},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	if strings.Contains(out, "findings &middot;") || strings.Contains(out, " blocking</span>") {
		t.Fatalf("HTML still renders findings/blocking summary badge:\n%s", out)
	}
	if !strings.Contains(out, "<h2>Security Findings</h2>") ||
		!strings.Contains(out, "GHSA-vqf5-2xx6-9wfm") {
		t.Fatalf("HTML should still render the Security Findings section:\n%s", out)
	}
}

func TestListAllHTMLKeepsUnknownOnlyPackagesOutOfAttention(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "docker.io/library/alpine",
			Installed: "3.23",
			Latest:    "sha256:5b10f432ef3d..",
			Update:    "unknown",
			Ecosystem: "docker",
			Source:    "dockerfile",
			Scope:     "runtime",
			Relation:  "base",
			Vuln:      "-",
			LockFile:  "Dockerfile",
		}},
		Unknown: 1,
	}
	result := &domain.ScanResult{Mode: "remote"}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	attentionStart := strings.Index(out, "<h2>Packages Needing Attention</h2>")
	securityStart := strings.Index(out, "<h2>Security Findings</h2>")
	if attentionStart < 0 || securityStart < 0 || securityStart <= attentionStart {
		t.Fatalf("HTML missing expected sections:\n%s", out)
	}
	attention := out[attentionStart:securityStart]
	if strings.Contains(attention, `<td class="name">docker.io/library/alpine</td>`) {
		t.Fatalf("unknown-only docker package should not be in attention section:\n%s", attention)
	}
	if !strings.Contains(attention, "No package status issues requiring attention.") {
		t.Fatalf("attention section should explain there are no actionable package issues:\n%s", attention)
	}
	allPackagesStart := strings.Index(out, "<h2>All Packages</h2>")
	if allPackagesStart < 0 {
		t.Fatalf("HTML missing All Packages section:\n%s", out)
	}
	allPackages := out[allPackagesStart:]
	if !strings.Contains(allPackages, `<td class="name">docker.io/library/alpine</td>`) ||
		!strings.Contains(allPackages, `<td class="package-status">Unknown</td>`) {
		t.Fatalf("unknown docker package should still be visible in All Packages:\n%s", allPackages)
	}
}

func TestListAllHTMLMarksMaliciousPackagesAsAttention(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "evilpkg",
			Installed: "2.0.0",
			Latest:    "2.0.0",
			Update:    "-",
			Ecosystem: "pypi",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "-",
			LockFile:  "requirements.txt",
		}},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:       "evilpkg",
			Version:    "2.0.0",
			Ecosystem:  domain.EcosystemPyPI,
			Type:       domain.FindingTypeMalicious,
			Severity:   domain.SeverityCritical,
			AdvisoryID: "reversinglabs:pypi/evilpkg@2.0.0",
			Title:      "ReversingLabs: malware detected",
			RiskType:   "malware",
			Source:     "reversinglabs",
		}},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	attentionStart := strings.Index(out, "<h2>Packages Needing Attention</h2>")
	securityStart := strings.Index(out, "<h2>Security Findings</h2>")
	if attentionStart < 0 || securityStart < 0 || securityStart <= attentionStart {
		t.Fatalf("HTML missing expected sections:\n%s", out)
	}
	attention := out[attentionStart:securityStart]
	wantRow := `<td class="name">evilpkg</td><td class="installed">2.0.0</td><td class="version">2.0.0</td><td class="package-status">Malicious</td>`
	if !strings.Contains(attention, wantRow) {
		t.Fatalf("malicious package should be explicit in attention section:\n%s", attention)
	}
	if !strings.Contains(out, `<td class="finding-advisory"><a href="https://secure.software/pypi/packages/evilpkg" target="_blank" rel="noopener" aria-label="reversinglabs:pypi/evilpkg@2.0.0 opens in a new tab">reversinglabs:pypi/evilpkg@2.0.0<span aria-hidden="true"> &#8599;</span><span class="sr-only"> (opens in a new tab)</span></a></td>`) {
		t.Fatalf("HTML missing ReversingLabs advisory link:\n%s", out)
	}
}

func TestListAllHTMLSurfacesHistoricalReputationRisk(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "polars-runtime-32",
			Installed: "1.40.1",
			Latest:    "1.40.1",
			Update:    "-",
			Ecosystem: "pypi",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "-",
			LockFile:  "requirements.txt",
		}},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:       "polars-runtime-32",
			Version:    "1.40.1",
			Ecosystem:  domain.EcosystemPyPI,
			Type:       domain.FindingTypeSupplyChainRisk,
			Severity:   domain.SeverityHigh,
			AdvisoryID: "reversinglabs:pypi/polars-runtime-32@1.40.1",
			Title:      "ReversingLabs: malware incident history",
			RiskType:   "malware_history",
			Source:     "reversinglabs",
		}},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	attentionStart := strings.Index(out, "<h2>Packages Needing Attention</h2>")
	securityStart := strings.Index(out, "<h2>Security Findings</h2>")
	if attentionStart < 0 || securityStart < 0 || securityStart <= attentionStart {
		t.Fatalf("HTML missing expected sections:\n%s", out)
	}
	attention := out[attentionStart:securityStart]
	if !strings.Contains(attention, "polars-runtime-32") || !strings.Contains(attention, "Supply-chain risk") {
		t.Fatalf("historical reputation risk should appear as package attention:\n%s", attention)
	}
	if !strings.Contains(strings.ToLower(out), "supply-chain incident history") {
		t.Fatalf("HTML should render historical reputation risk finding:\n%s", out)
	}
	if strings.Contains(out, "No security findings in 1 packages.") {
		t.Fatalf("historical reputation risk should create security finding rows:\n%s", out)
	}
	if !strings.Contains(out, `<span class="badge bad">0 vulnerabilities</span>`) {
		t.Fatalf("historical reputation risk should not be counted as a vulnerability badge:\n%s", out)
	}
}

func TestListAllHTMLDegradedFeedStatusIsWarningNotClean(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "safe",
			Installed: "1.0.0",
			Latest:    "1.0.0",
			Update:    "-",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "-",
		}},
	}
	result := &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		FeedStatus:      "degraded",
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "Server reports degraded feed status") {
		t.Fatalf("HTML missing degraded warning:\n%s", out)
	}
	for _, blocked := range []string{"No package status issues requiring attention.", "No security findings in 1 package."} {
		if strings.Contains(out, blocked) {
			t.Fatalf("HTML rendered all-clear %q despite degraded feed:\n%s", blocked, out)
		}
	}
}

func TestBuildListAllPackageReportOnlyVulnerabilityFindingsSetVuln(t *testing.T) {
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		return "12.2.0"
	})
	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{{
		Name:      "pillow",
		Version:   "12.2.0",
		Ecosystem: domain.EcosystemPyPI,
		LockFile:  "requirements.txt",
		Direct:    true,
	}}, &domain.ScanResult{Findings: []domain.Finding{{
		Name:      "pillow",
		Version:   "12.2.0",
		Ecosystem: domain.EcosystemPyPI,
		Type:      domain.FindingTypeSupplyChainRisk,
		RiskType:  "malware_history",
		Source:    "reversinglabs",
	}}}, "repo", 30, listAllPackageReportOptions{resolver: resolver})

	if len(report.Rows) != 1 {
		t.Fatalf("Rows = %d, want 1", len(report.Rows))
	}
	if report.Rows[0].Vuln != "-" {
		t.Fatalf("supply-chain risk Vuln = %q, want -", report.Rows[0].Vuln)
	}
	if report.Vulnerable != 0 {
		t.Fatalf("Vulnerable = %d, want 0", report.Vulnerable)
	}
}

func TestBuildListAllPackageReportSkipsLookupsAfterCallerCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var called atomic.Bool
	ctx = contextWithPackageUpdateResolver(ctx, packageUpdateResolver{fetchLatest: func(context.Context, domain.Ecosystem, string) string {
		called.Store(true)
		return "2.0.0"
	}})

	report := buildListAllPackageReport(ctx, []listAllPackage{{
		Name:      "leftpad",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}}, nil, ".", 1)
	if len(report.Rows) != 1 || report.Rows[0].Latest != "unknown" || report.Unknown != 1 {
		t.Fatalf("report rows = %+v, want one unknown row after canceled lookup", report.Rows)
	}
	if called.Load() {
		t.Fatal("latest-version lookup ran after caller context was canceled")
	}
}

func TestBuildListAllPackageReportUsesConfiguredTimeout(t *testing.T) {
	var sawDeadline atomic.Bool
	ctx := stubLatestVersionContext(t, func(ctx context.Context, _ domain.Ecosystem, _ string) string {
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= 2*time.Second {
			sawDeadline.Store(true)
		}
		return "2.0.0"
	})

	report := buildListAllPackageReport(ctx, []listAllPackage{{
		Name:      "leftpad",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}}, nil, ".", 1)
	if len(report.Rows) != 1 || report.Rows[0].Latest != "2.0.0" {
		t.Fatalf("report rows = %+v, want resolved latest version", report.Rows)
	}
	if !sawDeadline.Load() {
		t.Fatal("latest-version lookup did not receive configured lookup deadline")
	}
}

func TestListAllHTMLDoesNotMarkVulnerablePackageUpToDate(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{
				Name:      "github/codeql-action",
				Installed: "7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
				Latest:    "v4.36.2",
				Update:    "-",
				Ecosystem: "actions",
				Source:    "lockfile",
				Scope:     "ci",
				Relation:  "workflow",
				Vuln:      "-",
				LockFile:  ".github/workflows/codeql.yml",
			},
			{
				Name:      "lodash",
				Installed: "4.17.20",
				Latest:    "4.17.20",
				Update:    "-",
				Ecosystem: "npm",
				Source:    "lockfile",
				Scope:     "runtime",
				Relation:  "transitive",
				Vuln:      "-",
				LockFile:  "package-lock.json",
			},
			{
				Name:      "left-pad",
				Installed: "1.3.0",
				Latest:    "1.3.0",
				Update:    "-",
				Ecosystem: "npm",
				Source:    "lockfile",
				Scope:     "runtime",
				Relation:  "transitive",
				Vuln:      "-",
				LockFile:  "package-lock.json",
			},
		},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{
			{
				Name:         "github/codeql-action",
				Version:      "7211b7c8077ea37d8641b6271f6a365a22a5fbfa",
				Ecosystem:    domain.EcosystemGitHubActions,
				Type:         domain.FindingTypeVulnerability,
				Severity:     domain.SeverityHigh,
				AdvisoryID:   "GHSA-vqf5-2xx6-9wfm",
				FixedVersion: "3.28.3",
				Source:       "ghsa",
			},
			{
				Name:         "lodash",
				Version:      "4.17.20",
				Ecosystem:    domain.EcosystemNPM,
				Type:         domain.FindingTypeVulnerability,
				Severity:     domain.SeverityHigh,
				AdvisoryID:   "GHSA-35jh-r3h4-6jhm",
				FixedVersion: "4.17.21",
				Source:       "ghsa",
			},
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-left-pad-no-fix",
				Source:     "ghsa",
			},
		},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `<span class="badge bad">3 vulnerabilities</span>`) {
		t.Fatalf("HTML summary should count vulnerability findings:\n%s", out)
	}
	if !strings.Contains(out, `<span class="badge warn">2 with updates</span>`) {
		t.Fatalf("HTML summary should count vulnerability findings with update paths:\n%s", out)
	}
	for _, pkg := range []struct {
		name      string
		installed string
		latest    string
		status    string
	}{
		{name: "github/codeql-action", installed: "7211b7c8077ea37d8641b6271f6a365a22a5fbfa", latest: "v4.36.2", status: "Update available"},
		{name: "lodash", installed: "4.17.20", latest: "4.17.20", status: "Update available"},
		{name: "left-pad", installed: "1.3.0", latest: "1.3.0", status: "Vulnerable"},
	} {
		statusClass := ""
		if pkg.status == "Update available" {
			statusClass = " status-update"
		}
		want := `<td class="name">` + pkg.name + `</td><td class="installed">` + pkg.installed + `</td><td class="version">` + pkg.latest + `</td><td class="package-status` + statusClass + `">` + pkg.status + `</td>`
		if !strings.Contains(out, want) {
			t.Fatalf("vulnerable package should be marked %s, not Up-to-Date:\n%s", pkg.status, out)
		}
		bad := `<td class="name">` + pkg.name + `</td><td class="installed">` + pkg.installed + `</td><td class="version">` + pkg.latest + `</td><td class="package-status">Up-to-Date</td>`
		if strings.Contains(out, bad) {
			t.Fatalf("vulnerable package is still marked Up-to-Date:\n%s", out)
		}
	}
}

func TestListAllHTMLOmitsViaAndFlagsColumns(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	longVia := "github.com/jackc/pgx/v5, golang.org/x/crypto, modernc.org/sqlite"
	longFlags := "service=packmon-server, local-build, context=., dockerfile=Dockerfile, target=server"
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "golang.org/x/text",
			Installed: "v0.37.0",
			Latest:    "v0.37.0",
			Update:    "-",
			Ecosystem: "go",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "transitive",
			Via:       longVia,
			Flags:     longFlags,
			Vuln:      "-",
			LockFile:  "go.mod",
		}},
	}
	result := &domain.ScanResult{Mode: "remote"}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<th class="short">Relation</th>`,
		`<th class="vuln-col">Vulnerability</th>`,
		`<td class="short">transitive</td>`,
		`<td class="vuln-col">-</td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing retained package column %q:\n%s", want, out)
		}
	}
	for _, removed := range []string{
		`<th class="text via">Via</th>`,
		`<th class="text flags">Flags</th>`,
		`<td class="text via">`,
		`<td class="text flags">`,
		`.via{`,
		`.flags{`,
		longVia,
		longFlags,
	} {
		if strings.Contains(out, removed) {
			t.Fatalf("HTML still contains noisy Via/Flags content %q:\n%s", removed, out)
		}
	}
}

func TestListAllHTMLShortensDigestAndRendersCopyButton(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	const digest = "sha256:5b10f432ef3d1234567890abcdef1234567890abcdef1234567890abcdef12"
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:       "docker.io/library/alpine",
			Installed:  "3.23",
			Latest:     digest,
			LatestCopy: digest,
			Update:     "unknown",
			Ecosystem:  "docker",
			Source:     "dockerfile",
			Scope:      "runtime",
			Relation:   "base",
			Flags:      "stage=server",
			Vuln:       "-",
			LockFile:   "Dockerfile",
		}},
		Unknown: 1,
	}
	result := &domain.ScanResult{Mode: "remote"}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<span class="copy-value">sha256:5b10f432ef3d..</span>`,
		`data-copy="` + digest + `"`,
		`data-copy-label="Copy full latest value for docker.io/library/alpine 3.23"`,
		`data-copy-message="Copied full latest value for docker.io/library/alpine"`,
		`aria-label="Copy full latest value for docker.io/library/alpine 3.23"`,
		`id="copy-status" class="sr-only" role="status" aria-live="polite"`,
		`function fallbackCopy(value,button)`,
		`return document.execCommand('copy') === true`,
		`restoreFocus(button,previous)`,
		`Copy failed`,
		`copy-failed`,
		`navigator.clipboard.writeText`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `<td class="version">`+digest+`</td>`) {
		t.Fatalf("HTML renders full digest inline instead of shortened copy UI:\n%s", out)
	}
}

func TestListAllHTMLAppliesTableLayoutAndAttentionClasses(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	const installedDigest = "sha256:aaaaaaaaaaaa1234567890abcdef1234567890abcdef1234567890abcdef12"
	report := listAllPackageReport{
		Rows: []listAllRow{
			{Name: "postcss", Installed: "8.5.8", Latest: "8.5.10", Update: "yes", Ecosystem: "npm", Source: "lockfile", Scope: "runtime", Relation: "transitive", Vuln: "yes", LockFile: "package-lock.json"},
			{Name: "docker.io/library/nginx", Installed: installedDigest, Latest: "sha256:bbbbbbbbbbbb1234567890abcdef1234567890abcdef1234567890abcdef12", LatestCopy: "sha256:bbbbbbbbbbbb1234567890abcdef1234567890abcdef1234567890abcdef12", Update: "yes", Ecosystem: "docker", Source: "dockerfile", Scope: "runtime", Relation: "base", Vuln: "-", LockFile: "Dockerfile"},
		},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:         "postcss",
			Version:      "8.5.8",
			Ecosystem:    domain.EcosystemNPM,
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.SeverityHigh,
			AdvisoryID:   "GHSA-long-advisory",
			Title:        "A long finding title may wrap while package and advisory stay readable",
			FixedVersion: ">= 8.5.10",
			Source:       "osv",
		}},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`.status-update{color:var(--high);font-weight:700;}`,
		`.vuln-yes{color:var(--crit);font-weight:700;}`,
		`.sev-high{color:var(--high);border-color:var(--high);}`,
		`.copy-btn{margin-left:8px;border:1px solid var(--border);border-radius:4px;background:#21262d;color:var(--fg);font:inherit;font-size:12px;min-width:44px;min-height:32px;padding:5px 10px;cursor:pointer;}`,
		`.vuln-col{text-align:center;`,
		`.findings-table{table-layout:auto;min-width:0;}`,
		`.findings-table .finding-package{width:1%;min-width:0;overflow-wrap:anywhere;word-break:break-word;}`,
		`.findings-table .finding-advisory{width:1%;min-width:0;overflow-wrap:anywhere;word-break:break-word;}`,
		`.finding-title{white-space:normal;overflow-wrap:anywhere;}`,
		`.finding-fixed{overflow-wrap:anywhere;word-break:break-word;}`,
		`<td class="package-status status-update">Update available</td>`,
		`<td class="vuln-col vuln-yes">yes</td>`,
		`<span class="sev sev-high">HIGH</span>`,
		`<table class="findings-table">`,
		`<th class="finding-package">Package</th>`,
		`<th class="finding-advisory">Advisory</th>`,
		`<th class="finding-title">Finding</th>`,
		`<th class="finding-fixed">Fix Version</th>`,
		`<td class="finding-fixed">&gt;= 8.5.10</td>`,
		`<td class="installed"><span class="copy-value">sha256:aaaaaaaaaaaa..</span><button type="button" class="copy-btn" data-copy="` + installedDigest + `" data-copy-label="Copy full installed value for docker.io/library/nginx ` + installedDigest + `" data-copy-message="Copied full installed value for docker.io/library/nginx" aria-label="Copy full installed value for docker.io/library/nginx ` + installedDigest + `">Copy</button></td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing layout requirement %q:\n%s", want, out)
		}
	}
}

func TestListAllHTMLRendersStatusAndCheckedLockFiles(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	sharedLock := filepath.Join("repo", "package-lock.json")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{Name: "braces", Installed: "3.0.3", Latest: "3.0.3", Update: "-", Ecosystem: "npm", Scope: "sbom", Relation: "declared", Vuln: "yes", LockFile: sharedLock},
			{Name: "postcss", Installed: "8.5.8", Latest: "8.5.10", Update: "yes", Ecosystem: "npm", Scope: "sbom", Relation: "declared", Vuln: "yes", LockFile: sharedLock},
			{Name: "yaml", Installed: "2.8.3", Latest: "2.8.3", Update: "-", Ecosystem: "npm", Scope: "sbom", Relation: "declared", Vuln: "-", LockFile: filepath.Join("repo", "go.cdx.json")},
			{Name: "local/image", Installed: "latest", Latest: "-", Update: "local", Ecosystem: "docker", Scope: "runtime", Relation: "compose-build", Vuln: "-", LockFile: ""},
		},
		Vulnerable: 2,
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:       "braces",
			Version:    "3.0.3",
			Ecosystem:  domain.EcosystemNPM,
			Type:       domain.FindingTypeSupplyChainRisk,
			RiskType:   "removed_package",
			Severity:   domain.SeverityCritical,
			AdvisoryID: "reversinglabs:npm/braces@3.0.3",
			Source:     "reversinglabs",
		}},
	}
	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		"<h2>Packages Needing Attention</h2>",
		"<h2>Checked Inventory Sources</h2>",
		`<th class="package-status">Status</th>`,
		`<td class="package-status">Removed</td>`,
		`<td class="package-status status-update">Update available</td>`,
		`<td class="package-status">Up-to-Date</td>`,
		`<td class="package-status">Local build</td>`,
		`<td class="name">postcss</td><td class="installed">8.5.8</td><td class="version">8.5.10</td><td class="package-status status-update">Update available</td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing %q:\n%s", want, out)
		}
	}
	for _, removed := range []string{
		`<th class="short">Update</th>`,
		`<th class="lockfile">Lock File</th>`,
		`<td class="lockfile">`,
	} {
		if strings.Contains(out, removed) {
			t.Fatalf("HTML still contains removed table element %q:\n%s", removed, out)
		}
	}
	sharedLockDisplay := filepath.ToSlash(sharedLock)
	if strings.Count(out, sharedLockDisplay) != 1 {
		t.Fatalf("shared lock file should be rendered once, got %d occurrences:\n%s", strings.Count(out, sharedLockDisplay), out)
	}
	if !strings.Contains(out, filepath.ToSlash(filepath.Join("repo", "go.cdx.json"))) {
		t.Fatalf("HTML missing second checked lock file:\n%s", out)
	}
}

func TestListAllHTMLOmitsLongFlagsAndListsInventorySources(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	longFlags := "service=packmon-server, local-build, context=., dockerfile=Dockerfile, target=server"
	report := listAllPackageReport{
		Rows: []listAllRow{
			{Name: "docker.io/library/alpine", Installed: "3.23", Latest: "sha256:remote", Update: "unknown", Ecosystem: "docker", Scope: "runtime", Relation: "base", Flags: "stage=server", Vuln: "-", LockFile: "Dockerfile"},
			{Name: "local/packmon-server", Installed: "server", Latest: "unknown", Update: "unknown", Ecosystem: "docker", Scope: "runtime", Relation: "compose-build", Flags: longFlags, Vuln: "-", LockFile: "docker-compose.yml"},
			{Name: "left-pad", Installed: "1.3.0", Latest: "1.3.0", Update: "-", Ecosystem: "npm", Scope: "runtime", Relation: "direct", Vuln: "-", LockFile: "package-lock.json"},
		},
		Unknown: 2,
	}
	result := &domain.ScanResult{Mode: "remote"}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		"<h2>Checked Inventory Sources</h2>",
		`<span class="source-kind">docker</span><span class="source-path">Dockerfile</span>`,
		`<span class="source-kind">docker</span><span class="source-path">docker-compose.yml</span>`,
		`<span class="source-kind">lockfile</span><span class="source-path">package-lock.json</span>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing %q:\n%s", want, out)
		}
	}
	for _, removed := range []string{
		`<th class="text flags">Flags</th>`,
		`<td class="text flags">` + longFlags + `</td>`,
		`<td class="short">` + longFlags + `</td>`,
		longFlags,
	} {
		if strings.Contains(out, removed) {
			t.Fatalf("HTML still renders noisy flags content %q:\n%s", removed, out)
		}
	}
}

func TestListAllHTMLUsesReportInventorySources(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "left-pad",
			Installed: "1.3.0",
			Latest:    "1.3.0",
			Update:    "-",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "-",
			LockFile:  "package-lock.json",
		}},
		Sources: []listAllSourceRow{
			{Kind: "lockfile", Path: "package-lock.json"},
			{Kind: "sbom", Path: "sbom/package.cdx.json"},
		},
	}
	result := &domain.ScanResult{Mode: "remote"}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<span class="source-kind">lockfile</span><span class="source-path">package-lock.json</span>`,
		`<span class="source-kind">sbom</span><span class="source-path">sbom/package.cdx.json</span>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing source %q:\n%s", want, out)
		}
	}
}

func TestListAllExplicitSBOMSourcesNormalizeAndMinimizePaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sbom"), 0o700); err != nil {
		t.Fatalf("mkdir sbom dir: %v", err)
	}
	inRoot := filepath.Join(root, "sbom", "app.cdx.json")
	externalRoot := t.TempDir()
	external := filepath.Join(externalRoot, "external-team-bom.spdx.json")

	got := listAllExplicitSBOMSources(scanSettings{
		Path: root,
		SBOMFiles: []string{
			inRoot,
			" ",
			inRoot,
			external,
		},
	})

	want := []listAllSourceRow{
		{Kind: "sbom", Path: "external-team-bom.spdx.json"},
		{Kind: "sbom", Path: "sbom/app.cdx.json"},
	}
	if len(got) != len(want) {
		t.Fatalf("sources = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sources[%d] = %#v, want %#v; all=%#v", i, got[i], want[i], got)
		}
	}
	for _, source := range got {
		if strings.Contains(source.Path, root) || strings.Contains(source.Path, externalRoot) {
			t.Fatalf("source leaked absolute root in %#v", source)
		}
	}
}

func TestListAllHTMLMinimizesAbsoluteReportPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "student-123", "course-assignment")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	lockPath := filepath.Join(root, "package-lock.json")
	externalDir := filepath.Join(t.TempDir(), "student-456", "external-inventory")
	if err := os.MkdirAll(externalDir, 0o700); err != nil {
		t.Fatalf("mkdir external: %v", err)
	}
	externalSBOM := filepath.Join(externalDir, "student-bom.cdx.json")
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Target: root,
		Rows: []listAllRow{{
			Name:      "left-pad",
			Installed: "1.3.0",
			Latest:    "1.3.0",
			Update:    "-",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "-",
			LockFile:  lockPath,
		}},
		Sources: []listAllSourceRow{
			{Kind: "lockfile", Path: lockPath},
			{Kind: "sbom", Path: externalSBOM},
		},
	}

	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, &domain.ScanResult{Mode: "local"}, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, leaked := range []string{
		root,
		filepath.ToSlash(root),
		filepath.Dir(root),
		filepath.ToSlash(filepath.Dir(root)),
		externalDir,
		filepath.ToSlash(externalDir),
		externalSBOM,
		filepath.ToSlash(externalSBOM),
		"student-123",
		"student-456",
	} {
		if strings.Contains(out, leaked) {
			t.Fatalf("list-all HTML leaked local path fragment %q:\n%s", leaked, out)
		}
	}
	for _, want := range []string{
		"course-assignment",
		`<span class="source-kind">lockfile</span><span class="source-path">package-lock.json</span>`,
		`<span class="source-kind">sbom</span><span class="source-path">student-bom.cdx.json</span>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing minimized path %q:\n%s", want, out)
		}
	}
}

func TestListAllHTMLSurfacesUpdatesWithoutSecurityFindings(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "node-addon-api",
			Installed: "7.1.1",
			Latest:    "8.8.0",
			Update:    "yes",
			Ecosystem: "npm",
			Scope:     "sbom",
			Relation:  "declared",
			Vuln:      "-",
		}},
		WithUpdates: 1,
	}
	result := &domain.ScanResult{Mode: "remote"}
	if err := writeListAllHTML(htmlPath, "test", domain.SeverityCritical, result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		"No security findings in 1 package.",
		"<h2>Packages Needing Attention</h2>",
		"<h2>Security Findings</h2>",
		`<td class="name">node-addon-api</td><td class="installed">7.1.1</td><td class="version">8.8.0</td><td class="package-status status-update">Update available</td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing %q:\n%s", want, out)
		}
	}
}

func TestListAllHelperBranches(t *testing.T) {
	if !listAllAllowsDocker(nil) {
		t.Fatal("empty ecosystem filter should allow docker")
	}
	if !listAllAllowsDocker([]string{" NPM ", " docker "}) {
		t.Fatal("docker filter with whitespace should allow docker")
	}
	if listAllAllowsDocker([]string{"npm"}) {
		t.Fatal("npm-only filter should not allow docker")
	}

	local := resolveListAllLatest(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "local/image",
		Version:   "latest",
	})
	if local.Unknown || local.Latest != "-" || local.Update != "local" {
		t.Fatalf("local docker status = %+v, want local non-unknown", local)
	}
	invalidDocker := resolveListAllLatest(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "bad ref",
		Version:   "latest",
	})
	if !invalidDocker.Unknown {
		t.Fatalf("invalid docker status = %+v, want unknown", invalidDocker)
	}

	ref, ok := dockerRefFromListAllPackage(listAllPackage{Name: "docker.io/library/postgres", Version: "sha256:abcdef"})
	if !ok || ref.Name != "docker.io/library/postgres" || ref.Reference != "sha256:abcdef" {
		t.Fatalf("docker ref = %+v/%v", ref, ok)
	}
	if got := shortDigest("sha256:1234567890abcdef"); got != "sha256:1234567890ab.." {
		t.Fatalf("shortDigest = %q", got)
	}
	if got := shortDigest("not-a-digest"); got != "not-a-digest" {
		t.Fatalf("shortDigest(non digest) = %q", got)
	}

	summary := listAllScopeSummaries(listAllPackageReport{Rows: []listAllRow{
		{Scope: "custom"},
		{Scope: "runtime"},
		{Scope: ""},
	}})
	if len(summary) != 2 || summary[0].Scope != "runtime" || summary[1].Scope != "custom" {
		t.Fatalf("scope summary = %+v", summary)
	}
	for _, raw := range []string{"", "healthy", "degraded"} {
		if got := listAllOperationalStatus(raw); got != "" {
			t.Fatalf("operational status %q = %q, want empty", raw, got)
		}
	}
	if got := listAllOperationalStatus("parser_error"); got != "parser_error" {
		t.Fatalf("operational status parser_error = %q", got)
	}
	for _, tt := range []struct {
		f    domain.Finding
		want string
	}{
		{f: domain.Finding{AdvisoryID: "GHSA-x"}, want: "GHSA-x"},
		{f: domain.Finding{Type: domain.FindingTypeMalicious}, want: "MALWARE"},
		{f: domain.Finding{Type: domain.FindingTypeSupplyChainRisk}, want: "SUPPLY-CHAIN"},
		{f: domain.Finding{Type: domain.FindingTypeLifecycle}, want: "LIFECYCLE"},
		{f: domain.Finding{Type: domain.FindingTypeVulnerability}, want: ""},
	} {
		if got := listAllAdvisoryLabel(tt.f); got != tt.want {
			t.Fatalf("listAllAdvisoryLabel(%+v) = %q, want %q", tt.f, got, tt.want)
		}
	}
	if !domain.FindingBlocks(domain.Finding{Type: domain.FindingTypeMalicious}, domain.SeverityNone) {
		t.Fatal("malicious finding should always block")
	}
	if domain.FindingBlocks(domain.Finding{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityCritical}, domain.SeverityNone) {
		t.Fatal("vulnerability should not block when fail-on NONE")
	}

	parentFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	err := writeListAllHTML(filepath.Join(parentFile, "report.html"), "", domain.SeverityCritical, &domain.ScanResult{}, listAllPackageReport{})
	if err == nil || !strings.Contains(err.Error(), "prepare HTML output") {
		t.Fatalf("writeListAllHTML(parent file) = %v", err)
	}
}

func TestResolveDockerImageStatusLabelsMatchingPinnedTagDigestAsPinned(t *testing.T) {
	oldTransport := http.DefaultTransport
	oldRegistryClient := newDockerRegistryClientFunc
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
		newDockerRegistryClientFunc = oldRegistryClient
	})
	newDockerRegistryClientFunc = func(client *http.Client) *dockerimage.RegistryClient {
		registryClient := dockerimage.NewRegistryClient(client)
		registryClient.LookupIP = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return registryClient
	}

	const digest = "sha256:92cf5e2f488744c90d3df4378dfa3f0842704950cfa1353975d5510c945b072f"
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodHead {
			t.Fatalf("registry request method = %s, want HEAD", req.Method)
		}
		if req.URL.Host != "registry-1.docker.io" || !strings.Contains(req.URL.Path, "/v2/acme/app/manifests/stable") {
			t.Fatalf("registry request URL = %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Docker-Content-Digest": []string{digest}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})

	got := resolveDockerImageStatus(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "docker.io/acme/app",
		Version:   digest,
		DockerRef: "registry-1.docker.io/acme/app:stable@" + digest,
	})
	if got.Unknown || got.Update != "pinned" || got.Latest != shortDigest(digest) || got.LatestCopy != digest {
		t.Fatalf("resolveDockerImageStatus() = %+v, want pinned digest status", got)
	}
}

func TestResolveDockerImageStatusUsesRegistryDefaultHTTPTimeout(t *testing.T) {
	oldRegistryClient := newDockerRegistryClientFunc
	t.Cleanup(func() { newDockerRegistryClientFunc = oldRegistryClient })

	const digest = "sha256:92cf5e2f488744c90d3df4378dfa3f0842704950cfa1353975d5510c945b072f"
	newDockerRegistryClientFunc = func(client *http.Client) *dockerimage.RegistryClient {
		if client != nil {
			t.Fatalf("registry client argument = %#v, want nil so default timeout is installed", client)
		}
		registryClient := dockerimage.NewRegistryClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Docker-Content-Digest": []string{digest}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})})
		registryClient.LookupIP = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return registryClient
	}

	got := resolveDockerImageStatus(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "docker.io/acme/app",
		Version:   "stable",
		DockerRef: "registry-1.docker.io/acme/app:stable",
	})
	if got.Latest != shortDigest(digest) || got.LatestCopy != digest {
		t.Fatalf("resolveDockerImageStatus() = %+v, want digest from default-timeout client", got)
	}
}

func TestResolveDockerImageStatusMarksMovedPinnedTagAsUpdateAvailable(t *testing.T) {
	oldTransport := http.DefaultTransport
	oldRegistryClient := newDockerRegistryClientFunc
	t.Cleanup(func() {
		http.DefaultTransport = oldTransport
		newDockerRegistryClientFunc = oldRegistryClient
	})
	newDockerRegistryClientFunc = func(client *http.Client) *dockerimage.RegistryClient {
		registryClient := dockerimage.NewRegistryClient(client)
		registryClient.LookupIP = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return registryClient
	}

	const pinned = "sha256:92cf5e2f488744c90d3df4378dfa3f0842704950cfa1353975d5510c945b072f"
	const current = "sha256:c2d5ade763cacfb03fe9cb8e8af5d1be5041ff331921fa26a9b231ca3a4f780a"
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodHead {
			t.Fatalf("registry request method = %s, want HEAD", req.Method)
		}
		if req.URL.Host != "registry-1.docker.io" || !strings.Contains(req.URL.Path, "/v2/acme/app/manifests/stable") {
			t.Fatalf("registry request URL = %s", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Docker-Content-Digest": []string{current}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})

	got := resolveDockerImageStatus(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "docker.io/acme/app",
		Version:   pinned,
		DockerRef: "registry-1.docker.io/acme/app:stable@" + pinned,
	})
	if got.Unknown || got.Update != "yes" || got.Latest != shortDigest(current) || got.LatestCopy != current {
		t.Fatalf("resolveDockerImageStatus() = %+v, want update to current tag digest", got)
	}
}
