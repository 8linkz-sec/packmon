package main

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/dockerimage"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

func TestRunListAllUsesScanPipelineInventorySemantics(t *testing.T) {
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")
	dir := t.TempDir()
	writeListAllPackageLock(t, dir,
		listAllLockPackage{Name: "prod", Version: "1.0.0"},
		listAllLockPackage{Name: "dev-only", Version: "1.0.0", Dev: true},
	)

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
			ScanID:          "list-all-pipeline",
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

	settings := listAllSettings(dir, false)
	settings.Mode = "remote"
	settings.ServerURL = checkServer.URL
	settings.APIKey = "remote-key"
	settings.InsecureHTTP = true
	settings.ListAllOffline = true
	settings.Timeout = 2

	var exitCode int
	output := captureStdout(t, func() {
		var err error
		exitCode, err = runListAll(context.Background(), settings)
		if err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}

	select {
	case req := <-checkRequests:
		if len(req.Packages) != 1 || req.Packages[0].Name != "prod" {
			t.Fatalf("remote list-all check packages = %#v, want only prod by default", req.Packages)
		}
	case <-time.After(time.Second):
		t.Fatal("remote list-all check request was not received")
	}

	for _, want := range []string{"No findings in 1 package.", "prod", "dev-only", "2 packages ("} {
		if !strings.Contains(output, want) {
			t.Fatalf("list-all output missing %q:\n%s", want, output)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

type listAllLockPackage struct {
	Name    string
	Version string
	Dev     bool
}

func writeListAllPackageLock(t *testing.T, dir string, packages ...listAllLockPackage) {
	t.Helper()

	type lockPackage struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev,omitempty"`
	}
	lock := struct {
		Name            string                 `json:"name"`
		LockfileVersion int                    `json:"lockfileVersion"`
		Packages        map[string]lockPackage `json:"packages"`
	}{
		Name:            "test",
		LockfileVersion: 3,
		Packages:        make(map[string]lockPackage, len(packages)),
	}
	for _, pkg := range packages {
		lock.Packages["node_modules/"+pkg.Name] = lockPackage{
			Version: pkg.Version,
			Dev:     pkg.Dev,
		}
	}
	out, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatalf("marshal package-lock fixture: %v", err)
	}
	writeFile(t, filepath.Join(dir, "package-lock.json"), string(out))
}

func TestListAllHTMLExposesMachineReadableReportTimeAndLanguage(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		ScannedAt: "2026-05-30 10:00 UTC",
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
	}
	result := &domain.ScanResult{Mode: "remote"}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<html lang="en" dir="auto">`,
		`<time datetime="2026-05-30T10:00:00Z" data-report-time="scanned-at">2026-05-30 10:00 UTC</time>`,
		`Intl.DateTimeFormat`,
		`Intl.NumberFormat`,
		`querySelectorAll('time[data-report-time][datetime]')`,
		`querySelectorAll('[data-report-duration][data-duration-ms]')`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML timing/language hook missing %q:\n%s", want, out)
		}
	}
}

func TestListAllHTMLTemplateUsesMessageDataForStaticReportLabels(t *testing.T) {
	for _, want := range []string{
		`{{.Messages.ReportType}}`,
		`{{.Messages.ModeSuffix}}`,
		`{{.Messages.PackagesNeedingAttentionHeading}}`,
		`{{.Messages.SecurityFindingsHeading}}`,
		`{{.Messages.AllPackagesHeading}}`,
		`{{.Messages.CheckedInventorySourcesHeading}}`,
		`{{.Messages.CopyButton}}`,
		`{{printf $.Messages.OpenInNewTabAriaLabel .Advisory}}`,
		`{{$.Messages.OpenInNewTabScreenReader}}`,
	} {
		if !strings.Contains(listAllHTML, want) {
			t.Fatalf("list-all template missing message field %q", want)
		}
	}
	for _, scattered := range []string{
		"<h2>Packages Needing Attention</h2>",
		"<h2>Security Findings</h2>",
		"<summary>All Packages",
		"<h2>Checked Inventory Sources</h2>",
		">Copy</button>",
		"opens in a new tab",
		"<div class=\"footer\">fail-on",
	} {
		if strings.Contains(listAllHTML, scattered) {
			t.Fatalf("list-all template still has scattered label %q", scattered)
		}
	}
}

func TestListAllHTMLCollapsesFullPackageInventoryByDefault(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{
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
			},
			{
				Name:      "lodash",
				Installed: "4.17.21",
				Latest:    "4.17.21",
				Update:    "-",
				Ecosystem: "npm",
				Source:    "lockfile",
				Scope:     "runtime",
				Relation:  "direct",
				Vuln:      "-",
				LockFile:  "package-lock.json",
			},
		},
	}

	if err := writeListAllHTML(htmlPath, "test", &domain.ScanResult{Mode: "local"}, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, `<details class="inventory-details">`) {
		t.Fatalf("full package inventory should be in a closed details element:\n%s", out)
	}
	if strings.Contains(out, `<details class="inventory-details" open>`) {
		t.Fatalf("full package inventory details should not be open by default:\n%s", out)
	}
	if !strings.Contains(out, `<summary>All Packages <span class="count">(2 packages)</span></summary>`) {
		t.Fatalf("full package inventory summary should show package count:\n%s", out)
	}
	if strings.Index(out, `<details class="inventory-details">`) > strings.Index(out, `aria-label="All packages table"`) {
		t.Fatalf("all packages table should be nested inside the collapsed details element:\n%s", out)
	}
}

func TestListAllHTMLReportDoesNotRetainDuplicatePackageInventory(t *testing.T) {
	htmlSourceBytes, err := os.ReadFile("list_all_html.go") // #nosec G304 -- test inspects package source.
	if err != nil {
		t.Fatalf("read list_all_html.go: %v", err)
	}
	htmlSource := string(htmlSourceBytes)

	writeBody := goFunctionBodyForTest(t, htmlSource, "writeListAllHTML")
	for _, forbidden := range []string{
		"PackageRows   []listAllHTMLPackageRow",
		"listAllHTMLPackageRows(packages.Rows",
	} {
		if strings.Contains(writeBody, forbidden) {
			t.Fatalf("writeListAllHTML retains duplicate package inventory via %q:\n%s", forbidden, writeBody)
		}
	}

	listAllSourceBytes, err := os.ReadFile("list_all.go") // #nosec G304 -- test inspects package source.
	if err != nil {
		t.Fatalf("read list_all.go: %v", err)
	}
	findingRowsBody := goFunctionBodyForTest(t, string(listAllSourceBytes), "listAllFindingRows")
	if strings.Contains(findingRowsBody, "listAllRowsByPackage(") {
		t.Fatalf("listAllFindingRows builds a full package metadata map for HTML reports:\n%s", findingRowsBody)
	}
}

func TestListAllHTMLRendererDefinitionsStayInHTMLFile(t *testing.T) {
	listAllDecls := goTopLevelDeclarationNamesForTest(t, "list_all.go")
	htmlDecls := goTopLevelDeclarationNamesForTest(t, "list_all_html.go")

	var buried []string
	for name := range listAllDecls {
		if name == "writeListAllHTML" ||
			strings.HasPrefix(name, "listAllHTML") ||
			strings.HasPrefix(name, "maxListAllHTML") {
			buried = append(buried, name)
		}
	}
	if len(buried) > 0 {
		sort.Strings(buried)
		t.Fatalf("list-all HTML renderer declarations are buried in list_all.go: %v", buried)
	}

	for _, name := range []string{
		"writeListAllHTML",
		"listAllHTML",
		"listAllHTMLTemplate",
		"listAllHTMLMessages",
		"defaultListAllHTMLMessages",
		"listAllHTMLPackageRow",
		"listAllHTMLFindingState",
		"listAllHTMLPackageView",
		"listAllHTMLWarnings",
	} {
		if _, ok := htmlDecls[name]; !ok {
			t.Fatalf("list_all_html.go is missing list-all HTML renderer declaration %q", name)
		}
	}
}

func goFunctionBodyForTest(t *testing.T, source, name string) string {
	t.Helper()

	start := strings.Index(source, "func "+name+"(")
	if start == -1 {
		t.Fatalf("source missing function %s", name)
	}
	open := strings.Index(source[start:], "{")
	if open == -1 {
		t.Fatalf("source function %s missing opening brace", name)
	}
	open += start
	depth := 0
	for i := open; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[open+1 : i]
			}
		}
	}
	t.Fatalf("source function %s missing closing brace", name)
	return ""
}

func goTopLevelDeclarationNamesForTest(t *testing.T, path string) map[string]struct{} {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	names := make(map[string]struct{})
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			names[decl.Name.Name] = struct{}{}
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					names[spec.Name.Name] = struct{}{}
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						names[name.Name] = struct{}{}
					}
				}
			}
		}
	}
	return names
}

func TestListAllHTMLIncludesStandaloneCSPMeta(t *testing.T) {
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
	}

	if err := writeListAllHTML(htmlPath, "test", &domain.ScanResult{Mode: "local"}, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	want := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">`
	if !strings.Contains(out, want) {
		t.Fatalf("list-all HTML missing CSP meta %q:\n%s", want, out)
	}
	if strings.Index(out, want) > strings.Index(out, "<style>") {
		t.Fatalf("CSP meta should appear before inline styles:\n%s", out)
	}
}

func TestListAllHTMLUsesMainLandmark(t *testing.T) {
	out := renderListAllAccessibilityHTML(t)

	assertCLIHTMLUsesMainWrapLandmark(t, out)
}

func TestListAllHTMLTableHeadersUseColumnScope(t *testing.T) {
	out := renderListAllAccessibilityHTML(t)

	assertHTMLTableHeadersHaveColumnScope(t, out)
}

func TestListAllHTMLFindingSectionClassesHaveCSSRules(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "left-pad",
			Installed: "1.0.0",
			Latest:    "1.0.0",
			Update:    "-",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "yes",
			LockFile:  "package-lock.json",
		}},
	}
	result := &domain.ScanResult{
		Mode: "local",
		Findings: []domain.Finding{
			{Name: "badpkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical, Title: "malicious package"},
			{Name: "riskpkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityHigh, Title: "supply-chain risk"},
			{Name: "left-pad", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh, AdvisoryID: "GHSA-test", Title: "known vulnerability"},
			{Name: "oldpkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeLifecycle, Severity: domain.SeverityLow, Title: "lifecycle warning"},
			{Name: "unknownpkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingType("experimental"), Severity: domain.SeverityMedium, Title: "unknown finding type"},
		},
	}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	classes := emittedListAllFindingSectionClasses(out)
	if len(classes) == 0 {
		t.Fatalf("list-all HTML emitted no finding section classes:\n%s", out)
	}
	for class := range classes {
		if !strings.Contains(out, ".finding-section h3."+class+"{") {
			t.Errorf("finding section class %q was emitted without a matching CSS rule", class)
		}
	}
	if !classes["s-other"] {
		t.Errorf("unknown finding type did not emit fallback s-other section; classes=%v", classes)
	}
	if strings.Contains(out, ".ok{") {
		t.Errorf("list-all HTML still defines stale .ok CSS without emitting a success badge")
	}
	if strings.Contains(out, `class="badge ok"`) {
		t.Errorf("list-all HTML unexpectedly emits a success badge; update the .ok assertion if this becomes intentional")
	}
}

func renderListAllAccessibilityHTML(t *testing.T) string {
	t.Helper()

	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "left-pad",
			Installed: "1.0.0",
			Latest:    "1.3.0",
			Update:    "yes",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "yes",
			LockFile:  "package-lock.json",
		}},
		WithUpdates: 1,
		Vulnerable:  1,
	}
	result := &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		Findings: []domain.Finding{{
			Name:         "left-pad",
			Version:      "1.0.0",
			Ecosystem:    domain.EcosystemNPM,
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.SeverityHigh,
			AdvisoryID:   "GHSA-test",
			Title:        "test advisory",
			FixedVersion: "1.3.0",
			Source:       "osv",
			URL:          "https://osv.dev/vuln/GHSA-test",
		}},
	}
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	return string(data)
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

func assertCLIHTMLUsesMainWrapLandmark(t *testing.T, out string) {
	t.Helper()

	if strings.Count(out, `<main class="wrap">`) != 1 {
		t.Fatalf("HTML report should render one main wrap landmark:\n%s", out)
	}
	if !strings.Contains(out, "</main>") {
		t.Fatalf("HTML report should close the main landmark:\n%s", out)
	}
	if strings.Contains(out, `<div class="wrap">`) {
		t.Fatalf("HTML report still uses a top-level div wrapper:\n%s", out)
	}
}

func assertHTMLTableHeadersHaveColumnScope(t *testing.T, out string) {
	t.Helper()

	remaining := out
	for {
		idx := strings.Index(remaining, "<th")
		if idx == -1 {
			return
		}
		remaining = remaining[idx:]
		if len(remaining) > len("<th") && remaining[len("<th")] != ' ' && remaining[len("<th")] != '>' {
			remaining = remaining[len("<th"):]
			continue
		}
		end := strings.Index(remaining, ">")
		if end == -1 {
			t.Fatalf("HTML report contains an unterminated table header:\n%s", remaining)
		}
		tag := remaining[:end+1]
		if !strings.Contains(tag, `scope="col"`) {
			t.Fatalf("HTML table header missing scope=\"col\": %s\nFull HTML:\n%s", tag, out)
		}
		remaining = remaining[end+1:]
	}
}

func emittedListAllFindingSectionClasses(out string) map[string]bool {
	classes := make(map[string]bool)
	remaining := out
	for {
		idx := strings.Index(remaining, `<h3 class="`)
		if idx == -1 {
			return classes
		}
		remaining = remaining[idx+len(`<h3 class="`):]
		end := strings.Index(remaining, `"`)
		if end == -1 {
			return classes
		}
		for _, class := range strings.Fields(remaining[:end]) {
			if strings.HasPrefix(class, "s-") {
				classes[class] = true
			}
		}
		remaining = remaining[end+1:]
	}
}

// stubLatestVersion returns a resolver that keeps package table tests off the
// network without mutating process-wide lookup state.
func stubLatestVersion(t *testing.T, fn func(ctx context.Context, eco domain.Ecosystem, name string) string) packageUpdateResolver {
	t.Helper()
	return packageUpdateResolver{fetchLatest: fn}
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

func TestRunListAllMalformedSBOMReturnsParserExit(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad.cdx.json")
	writeFile(t, badPath, `{"bomFormat":"CycloneDX",`)

	var exitCode int
	var err error
	captureStdout(t, func() {
		exitCode, err = runListAll(context.Background(), scanSettings{
			Path:      dir,
			Mode:      "local",
			FailOn:    "CRITICAL",
			MaxDepth:  2,
			Timeout:   1,
			NoColor:   true,
			SBOMFiles: []string{badPath},
		})
	})
	if err == nil {
		t.Fatal("runListAll(malformed SBOM) error = nil")
	}
	if exitCode != ExitParser {
		t.Fatalf("exitCode = %d, want %d; err=%v", exitCode, ExitParser, err)
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

func listAllSettingsWithResolver(dir string, quiet bool, resolver packageUpdateResolver) scanSettings {
	settings := listAllSettings(dir, quiet)
	settings.resolver = resolver
	return settings
}

func TestRunListAll_ListsAllPackagesWithUpdateInfo(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeListAllPackageLock(t, dir,
		listAllLockPackage{Name: "leftpad", Version: "1.0.0"},
		listAllLockPackage{Name: "lodash", Version: "4.17.15"},
	)

	// leftpad has a newer version, lodash is up to date.
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
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
	writeListAllPackageLock(t, dir, listAllLockPackage{Name: "private-name", Version: "1.0.0"})
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM docker.io/library/nginx:1.25\n")

	var called atomic.Bool
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		called.Store(true)
		return "2.0.0"
	})
	oldDockerResolver := resolveDockerImageStatusFn
	var dockerCalled atomic.Bool
	resolveDockerImageStatusFn = func(context.Context, listAllPackage, map[string]string, dockerDigestResolver) packageLatestStatus {
		dockerCalled.Store(true)
		return packageLatestStatus{Latest: "sha256:remote", Update: "yes"}
	}
	t.Cleanup(func() { resolveDockerImageStatusFn = oldDockerResolver })

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), scanSettings{
			TargetName:     "x",
			Path:           dir,
			Mode:           "local",
			FailOn:         "CRITICAL",
			MaxDepth:       10,
			Timeout:        30,
			Quiet:          false,
			NoColor:        true,
			ListAllOffline: true,
			resolver:       resolver,
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
	writeListAllPackageLock(t, dir, listAllLockPackage{Name: "private-name", Version: "1.0.0"})
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM docker.io/library/nginx:1.25\n")

	oldDockerResolver := resolveDockerImageStatusFn
	var dockerCalled atomic.Bool
	resolveDockerImageStatusFn = func(context.Context, listAllPackage, map[string]string, dockerDigestResolver) packageLatestStatus {
		dockerCalled.Store(true)
		return packageLatestStatus{Latest: "sha256:remote", Update: "yes"}
	}
	t.Cleanup(func() { resolveDockerImageStatusFn = oldDockerResolver })

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--mode", "local", "--list-all", "--list-all-offline", dir})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("scan --list-all --list-all-offline: %v", err)
		}
	})

	if dockerCalled.Load() {
		t.Fatal("offline list-all flag performed a Docker digest lookup")
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
	writeListAllPackageLock(t, dir,
		listAllLockPackage{Name: "prod", Version: "1.0.0"},
		listAllLockPackage{Name: "dev-only", Version: "1.0.0", Dev: true},
	)

	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		switch name {
		case "prod", "dev-only":
			return "1.0.0"
		default:
			return ""
		}
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
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
	writeListAllPackageLock(t, dir,
		listAllLockPackage{Name: "leftpad", Version: "1.0.0"},
		listAllLockPackage{Name: "dev-only", Version: "1.0.0", Dev: true},
	)
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")

	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
	settings.resolver = resolver
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
		"<th scope=\"col\" class=\"installed\">Installed</th>",
	} {
		if !contains(out, want) {
			t.Fatalf("list-all HTML missing %q:\n%s", want, out)
		}
	}
}

func TestRunListAllWritesRequestedScanArtifacts(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	writeListAllPackageLock(t, dir, listAllLockPackage{Name: "prod", Version: "1.0.0"})
	outDir := t.TempDir()
	jsonPath := filepath.Join(outDir, "result.json")
	sarifPath := filepath.Join(outDir, "result.sarif")
	junitPath := filepath.Join(outDir, "result.xml")
	htmlPath := filepath.Join(outDir, "list-all.html")

	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "prod" {
			return "1.0.0"
		}
		return ""
	})

	settings := listAllSettings(dir, true)
	settings.OutputJSON = jsonPath
	settings.OutputSARIF = sarifPath
	settings.OutputJUnit = junitPath
	settings.OutputHTML = htmlPath
	settings.resolver = resolver
	if _, err := runListAll(context.Background(), settings); err != nil {
		t.Fatalf("runListAll: %v", err)
	}

	for _, path := range []string{jsonPath, sarifPath, junitPath, htmlPath} {
		data, err := os.ReadFile(path) // #nosec G304 -- test reads generated reports.
		if err != nil {
			t.Fatalf("read generated report %s: %v", path, err)
		}
		if len(data) == 0 {
			t.Fatalf("generated report %s is empty", path)
		}
	}
	html, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read list-all HTML: %v", err)
	}
	if !contains(string(html), "Packmon List-All Report") || !contains(string(html), "All Packages") {
		t.Fatalf("list-all HTML artifact should stay the combined report:\n%s", html)
	}
}

func TestWriteListAllOutputPhasePreservesExitCodeForEmptyInventory(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	settings := listAllSettings(t.TempDir(), false)
	settings.OutputHTML = htmlPath
	scan := listAllScanPhaseResult{
		result:   &domain.ScanResult{Mode: "local"},
		failOn:   domain.SeverityCritical,
		exitCode: ExitBlocking,
	}

	var exitCode int
	out := captureStdout(t, func() {
		var err error
		exitCode, err = writeListAllOutputPhase(context.Background(), settings, scan, listAllInventoryPhaseResult{})
		if err != nil {
			t.Fatalf("writeListAllOutputPhase: %v", err)
		}
	})

	if exitCode != ExitBlocking {
		t.Fatalf("exitCode = %d, want preserved scan exit %d", exitCode, ExitBlocking)
	}
	for _, want := range []string{"\n\n\n", "No packages found.", "HTML report written to: " + htmlPath} {
		if !strings.Contains(out, want) {
			t.Fatalf("empty list-all output missing %q:\n%s", want, out)
		}
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read list-all HTML report: %v", err)
	}
	if !strings.Contains(string(data), "No packages found.") {
		t.Fatalf("empty list-all HTML missing empty inventory message:\n%s", data)
	}
}

func TestWriteListAllOutputPhaseWritesHTMLBeforeReturningHistoryFailure(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	settings := listAllSettings(t.TempDir(), true)
	settings.OutputHTML = htmlPath
	settings.ListAllOffline = true
	historyErr := &scanHistoryRecordError{err: fmt.Errorf("store scan history for repo app: closed database")}
	scan := listAllScanPhaseResult{
		result: &domain.ScanResult{
			Mode:            "local",
			PackagesScanned: 1,
		},
		failOn:     domain.SeverityCritical,
		exitCode:   ExitOperational,
		collection: &scanner.PackageCollection{},
		historyErr: historyErr,
	}
	inventory := listAllInventoryPhaseResult{
		packages: []listAllPackage{{
			Name:       "prod",
			Version:    "1.0.0",
			Ecosystem:  domain.EcosystemNPM,
			LockFile:   "package-lock.json",
			SourceType: "lockfile",
			Scope:      "runtime",
			Relation:   "direct",
		}},
	}

	var exitCode int
	var err error
	captureStdout(t, func() {
		exitCode, err = writeListAllOutputPhase(context.Background(), settings, scan, inventory)
	})
	if err == nil {
		t.Fatal("writeListAllOutputPhase() error = nil, want scan history failure")
	}
	if !strings.Contains(err.Error(), "store scan history for repo app") {
		t.Fatalf("writeListAllOutputPhase() error = %v, want history failure", err)
	}
	if exitCode != ExitOperational {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOperational)
	}
	data, readErr := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if readErr != nil {
		t.Fatalf("read list-all HTML after history failure: %v", readErr)
	}
	if !strings.Contains(string(data), "Packmon List-All Report") || !strings.Contains(string(data), "prod") {
		t.Fatalf("list-all HTML was not written before returning history failure:\n%s", string(data))
	}
}

func TestWriteListAllOutputPhaseRendersCompactSecurityFindingDetails(t *testing.T) {
	settings := listAllSettings(t.TempDir(), false)
	settings.ListAllOffline = true
	scan := listAllScanPhaseResult{
		result: &domain.ScanResult{
			Mode:            "remote",
			PackagesScanned: 1,
			FindingsCount:   1,
			Findings: []domain.Finding{{
				Name:         "postcss",
				Version:      "8.5.8",
				Ecosystem:    domain.EcosystemNPM,
				Type:         domain.FindingTypeVulnerability,
				RiskType:     "known_vulnerability",
				Severity:     domain.SeverityHigh,
				AdvisoryID:   "GHSA-postcss-test",
				Title:        "PostCSS test advisory",
				FixedVersion: "8.5.10",
				Source:       "osv",
			}},
		},
		failOn:   domain.SeverityCritical,
		exitCode: ExitBlocking,
	}
	inventory := listAllInventoryPhaseResult{packages: []listAllPackage{{
		Name:       "postcss",
		Version:    "8.5.8",
		Ecosystem:  domain.EcosystemNPM,
		SourceType: "sbom",
		Scope:      "dev",
		Relation:   "transitive",
	}}}

	out := captureStdout(t, func() {
		if _, err := writeListAllOutputPhase(context.Background(), settings, scan, inventory); err != nil {
			t.Fatalf("writeListAllOutputPhase: %v", err)
		}
	})

	security := listAllTerminalSection(t, out, "Security Findings", "\n\n\nPACKAGE")
	header := firstLineContaining(t, security, "SEVERITY")
	if got := len(strings.Fields(header)); got >= 11 {
		t.Fatalf("security findings terminal header exposes %d visible columns, want fewer than 11: %q", got, header)
	}
	for _, noisyColumn := range []string{"TYPE", "RISK", "ECOSYSTEM", "SOURCE", "SCOPE", "RELATION", "FIXED VERSION"} {
		if strings.Contains(header, noisyColumn) {
			t.Fatalf("security findings primary header still exposes %q as a column: %q", noisyColumn, header)
		}
	}
	for _, want := range []string{
		"postcss",
		"GHSA-postcss-test",
		"PostCSS test advisory",
		"Action: Fix 8.5.10",
		"Type: Vulnerability",
		"Risk: Known vulnerability",
		"Ecosystem: npm",
		"Source: osv",
		"Scope: dev",
		"Relation: transitive",
		"Fixed Version: 8.5.10",
	} {
		if !strings.Contains(security, want) {
			t.Fatalf("compact security findings section missing %q:\n%s", want, security)
		}
	}
}

func TestScanCommandListAllHTMLFlagWritesFullReport(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_API_KEY", "remote-key")
	dir := t.TempDir()
	writeListAllPackageLock(t, dir,
		listAllLockPackage{Name: "prod", Version: "1.0.0"},
		listAllLockPackage{Name: "dev-only", Version: "1.0.0", Dev: true},
	)
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")

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
	cmd.SetArgs([]string{
		"--mode", "remote",
		"--server", checkServer.URL,
		"--insecure-allow-http",
		"--html", htmlPath,
		"--list-all",
		"--list-all-offline",
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
	t.Setenv("PACKMON_API_KEY", "remote-key")
	dir := t.TempDir()
	writeListAllPackageLock(t, dir,
		listAllLockPackage{Name: "prod", Version: "1.0.0"},
		listAllLockPackage{Name: "dev-only", Version: "1.0.0", Dev: true},
	)

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
	cmd.SetArgs([]string{
		"--mode", "remote",
		"--server", checkServer.URL,
		"--insecure-allow-http",
		"--list-all",
		"--list-all-offline",
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
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		called = true
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
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
	writeListAllPackageLock(t, dir,
		listAllLockPackage{Name: "old", Version: "1.0.0"},
		listAllLockPackage{Name: "current", Version: "2.0.0"},
	)

	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
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

	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "github.com/davecgh/go-spew" {
			return "v1.1.1"
		}
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
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
	writeListAllPackageLock(t, dir,
		listAllLockPackage{Name: "vulnpkg", Version: "1.0.0"},
		listAllLockPackage{Name: "safe", Version: "2.0.0"},
	)

	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
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
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
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
	writeListAllPackageLock(t, dir, listAllLockPackage{Name: "leftpad", Version: "1.0.0"})
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		return ""
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
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
	writeListAllPackageLock(t, dir, listAllLockPackage{Name: "leftpad", Version: "1.0.0"})
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, _ string) string {
		return "2.0.0"
	})

	out := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, true, resolver)); err != nil {
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
	resolveDockerImageStatusFn = func(_ context.Context, p listAllPackage, _ map[string]string, _ dockerDigestResolver) packageLatestStatus {
		if p.Name != "docker.io/library/postgres" || p.Version != "18-alpine" {
			t.Fatalf("docker status package = %#v", p)
		}
		return packageLatestStatus{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{{
		Name:      "docker.io/library/postgres",
		Version:   "18-alpine",
		Ecosystem: domain.EcosystemDocker,
		LockFile:  "docker-compose.yml",
	}}, &domain.ScanResult{}, ".", 30, listAllPackageReportOptions{})

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
	resolveDockerImageStatusFn = func(_ context.Context, p listAllPackage, localDigests map[string]string, _ dockerDigestResolver) packageLatestStatus {
		dockerResolveCalls.Add(1)
		if localDigests == nil {
			t.Fatal("local Docker digest map was not passed to Docker resolver")
		}
		if _, ok := localDigests[p.Name]; !ok {
			t.Fatalf("local digest map missing %s: %#v", p.Name, localDigests)
		}
		return packageLatestStatus{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{
		{Name: "docker.io/library/postgres", Version: "18-alpine", Ecosystem: domain.EcosystemDocker, LockFile: "docker-compose.yml"},
		{Name: "leftpad", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, LockFile: "package-lock.json"},
		{Name: "docker.io/library/nginx", Version: "1.25", Ecosystem: domain.EcosystemDocker, LockFile: "Dockerfile"},
	}, &domain.ScanResult{}, ".", 30, listAllPackageReportOptions{})

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

func TestBuildListAllPackageReportCachesDuplicateDockerDigestLookups(t *testing.T) {
	oldInspect := inspectLocalDockerDigestsFn
	oldRegistryClient := newDockerRegistryClientFunc
	t.Cleanup(func() {
		inspectLocalDockerDigestsFn = oldInspect
		newDockerRegistryClientFunc = oldRegistryClient
	})

	const digest = "sha256:92cf5e2f488744c90d3df4378dfa3f0842704950cfa1353975d5510c945b072f"
	inspectLocalDockerDigestsFn = func(context.Context, []listAllPackage) map[string]string {
		return map[string]string{"docker.io/library/postgres": digest}
	}

	var headRequests atomic.Int32
	newDockerRegistryClientFunc = func(*http.Client) *dockerimage.RegistryClient {
		registryClient := dockerimage.NewRegistryClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			headRequests.Add(1)
			if req.Method != http.MethodHead {
				t.Fatalf("registry request method = %s, want HEAD", req.Method)
			}
			if req.URL.Host != "registry-1.docker.io" || !strings.Contains(req.URL.Path, "/v2/library/postgres/manifests/18-alpine") {
				t.Fatalf("registry request URL = %s", req.URL.String())
			}
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

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{
		{Name: "docker.io/library/postgres", Version: "18-alpine", Ecosystem: domain.EcosystemDocker, LockFile: "Dockerfile", SourceType: "dockerfile"},
		{Name: "docker.io/library/postgres", Version: "18-alpine", Ecosystem: domain.EcosystemDocker, LockFile: "docker-compose.yml", SourceType: "compose"},
	}, nil, "repo", 30, listAllPackageReportOptions{})

	if got := headRequests.Load(); got != 1 {
		t.Fatalf("registry HEAD requests = %d, want 1 cached lookup for duplicate Docker refs", got)
	}
	if len(report.Rows) != 2 {
		t.Fatalf("rows = %d, want duplicate inventory rows preserved", len(report.Rows))
	}
	for _, row := range report.Rows {
		if row.LatestCopy != digest || row.Update != "-" {
			t.Fatalf("row = %+v, want shared resolved digest without update", row)
		}
	}
}

func TestBuildListAllPackageReportUsesConfiguredDockerRegistryMirror(t *testing.T) {
	oldInspect := inspectLocalDockerDigestsFn
	oldRegistryClient := newDockerRegistryClientFunc
	t.Cleanup(func() {
		inspectLocalDockerDigestsFn = oldInspect
		newDockerRegistryClientFunc = oldRegistryClient
	})

	const digest = "sha256:92cf5e2f488744c90d3df4378dfa3f0842704950cfa1353975d5510c945b072f"
	inspectLocalDockerDigestsFn = func(context.Context, []listAllPackage) map[string]string {
		return map[string]string{"docker.io/library/postgres": digest}
	}

	var sawMirrorRequest atomic.Bool
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMirrorRequest.Store(true)
		if r.Method != http.MethodHead {
			t.Fatalf("registry request method = %s, want HEAD", r.Method)
		}
		if r.URL.Path != "/dockerhub/v2/library/postgres/manifests/18-alpine" {
			t.Fatalf("registry mirror path = %s", r.URL.Path)
		}
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()

	newDockerRegistryClientFunc = func(client *http.Client) *dockerimage.RegistryClient {
		if client != nil {
			t.Fatalf("registry client argument = %#v, want nil", client)
		}
		return dockerimage.NewRegistryClient(mirror.Client())
	}

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{
		{Name: "docker.io/library/postgres", Version: "18-alpine", Ecosystem: domain.EcosystemDocker, LockFile: "Dockerfile", SourceType: "dockerfile"},
	}, nil, "repo", 30, listAllPackageReportOptions{resolver: packageUpdateResolver{latestRegistry: latestRegistryConfig{
		DockerRegistryMirrors: map[string]string{"registry-1.docker.io": mirror.URL + "/dockerhub"},
	}}})

	if !sawMirrorRequest.Load() {
		t.Fatal("configured Docker registry mirror was not used")
	}
	if len(report.Rows) != 1 || report.Rows[0].LatestCopy != digest || report.Rows[0].Update != "-" {
		t.Fatalf("rows = %+v, want digest resolved through mirror", report.Rows)
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
	resolver := stubLatestVersion(t, func(context.Context, domain.Ecosystem, string) string { return "" })
	resolveDockerImageStatusFn = func(context.Context, listAllPackage, map[string]string, dockerDigestResolver) packageLatestStatus {
		return packageLatestStatus{Latest: "sha256:remote", Update: "unknown", Unknown: true}
	}

	output := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
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
	resolveDockerImageStatusFn = func(context.Context, listAllPackage, map[string]string, dockerDigestResolver) packageLatestStatus {
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
	t.Setenv("PACKMON_API_KEY", "test")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.23\n"), 0o600); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	writeListAllPackageLock(t, dir, listAllLockPackage{Name: "left-pad", Version: "1.3.0"})
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
	cmd.SetArgs([]string{"--mode", "remote", "--server", server.URL, "--insecure-allow-http", dir})
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
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	securityTable := listAllHTMLSecurityFindingTable(t, out)
	if got := strings.Count(securityTable, "<th "); got >= 11 {
		t.Fatalf("security findings HTML table exposes %d visible columns, want fewer than 11:\n%s", got, securityTable)
	}
	for _, noisyColumn := range []string{"<th class=\"short\">Type</th>", "<th class=\"short\">Risk</th>", "<th class=\"short\">Ecosystem</th>", "<th class=\"short\">Source</th>", "<th class=\"short\">Scope</th>", "<th class=\"short\">Relation</th>", "<th class=\"finding-fixed\">Fixed Version</th>"} {
		if strings.Contains(securityTable, noisyColumn) {
			t.Fatalf("security findings HTML still exposes noisy primary column %q:\n%s", noisyColumn, securityTable)
		}
	}
	for _, want := range []string{"runtime 1", "dev 1", "ci 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing scope summary %q:\n%s", want, out)
		}
	}
	for _, want := range []string{
		`<td class="finding-package"><bdi dir="auto">postcss</bdi></td><td class="finding-advisory"><a class="external-link" href="https://github.com/advisories/GHSA-postcss-test" target="_blank" rel="noopener" aria-label="GHSA-postcss-test opens in a new tab"><bdi dir="auto">GHSA-postcss-test</bdi><span class="sr-only"> (opens in a new tab)</span></a></td><td class="finding-title"><bdi dir="auto">PostCSS test advisory</bdi></td><td class="finding-action"><bdi dir="auto">Fix 8.5.10</bdi></td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML finding row missing compact/detail data %q:\n%s", want, out)
		}
	}
	for _, removed := range []string{
		// The redundant per-finding detail row was removed; the summary row
		// already carries the advisory, title and fix action. (Package-scope
		// <dt>Scope</dt>/<dt>Relation</dt> still live in the inventory meta list.)
		`<tr class="finding-details-row"`,
		`<dl class="finding-details-list"`,
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	want := `<td class="finding-advisory"><a class="external-link" href="https://github.com/advisories/GHSA-vqf5-2xx6-9wfm" target="_blank" rel="noopener" aria-label="GHSA-vqf5-2xx6-9wfm opens in a new tab"><bdi dir="auto">GHSA-vqf5-2xx6-9wfm</bdi><span class="sr-only"> (opens in a new tab)</span></a></td>`
	if !strings.Contains(out, want) {
		t.Fatalf("HTML finding advisory missing nowrap external link:\n%s", out)
	}
	if !strings.Contains(out, `<td class="finding-package"><bdi dir="auto">github/codeql-action</bdi></td>`) {
		t.Fatalf("HTML finding package should omit the long @version suffix:\n%s", out)
	}
	if strings.Contains(out, `github/codeql-action@7211b7c8077ea37d8641b6271f6a365a22a5fbfa`) {
		t.Fatalf("HTML finding package still contains the long @version suffix:\n%s", out)
	}
}

func TestListAllHTMLNewTabTextUsesReorderableMessages(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("list_all_html.go") // #nosec G304 -- test reads package source.
	if err != nil {
		t.Fatalf("read list_all_html.go: %v", err)
	}
	body := string(source)
	for _, want := range []string{
		`OpenInNewTabAriaLabel`,
		`OpenInNewTabScreenReader`,
		`printf $.Messages.OpenInNewTabAriaLabel .Advisory`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("list_all_html.go missing reorderable new-tab marker %q", want)
		}
	}
	if strings.Contains(body, `aria-label="{{.Advisory}} `) {
		t.Fatalf("list_all_html.go still concatenates advisory before new-tab suffix:\n%s", body)
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
			{Name: "risky", Version: "2.0.0", Ecosystem: domain.EcosystemPyPI, Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityHigh, AdvisoryID: "reversinglabs:pypi/risky@2.0.0", Title: "incident history", RiskType: domain.RiskTypeMalwareHistory, Source: "reversinglabs"},
			{Name: "evilpkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical, AdvisoryID: "MAL-evilpkg", Title: "malware detected", RiskType: "malware", Source: "openssf"},
		},
	}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{"Malicious", "Vulnerabilities", "Lifecycle Findings", "Reputation info", "<th scope=\"col\" class=\"finding-action\">Action</th>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("grouped finding HTML missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Supply-Chain / EOL") {
		t.Fatalf("malware history should not create a Supply-Chain / EOL section:\n%s", out)
	}
	for _, raw := range []string{domain.RiskTypeMalwareHistory, "known_vulnerability", "security_support_ended"} {
		if strings.Contains(out, raw) {
			t.Fatalf("grouped finding HTML still contains raw risk token %q:\n%s", raw, out)
		}
	}
	securityStart := strings.Index(out, "<h2>Security Findings</h2>")
	if securityStart < 0 {
		t.Fatalf("HTML missing Security Findings section:\n%s", out)
	}
	assertInOrder(t, out[securityStart:], "Malicious", "Vulnerabilities", "Lifecycle Findings", "Reputation info")
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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

func TestListAllHTMLWarningOnlyReportExplainsEmptySections(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Warnings: []string{"parse error in broken/package-lock.json"},
	}
	result := &domain.ScanResult{Mode: "local"}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<div class="empty warning-empty">Package attention could not be fully evaluated because report warnings require review.</div>`,
		`<div class="empty warning-empty">Security findings could not be confirmed clean because report warnings require review.</div>`,
		`<div class="empty warning-empty">No package inventory rows were available; review the warnings above for coverage gaps.</div>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("warning-only HTML missing warning-aware empty state %q:\n%s", want, out)
		}
	}
}

func TestListAllHTMLSuppressesCleanEmptyStatesWhenInventoryWarningsExist(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Warnings: []string{"parse error in broken/package-lock.json"},
	}
	result := &domain.ScanResult{Mode: "local"}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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

func TestListAllHTMLFindingAdvisoryLinksAreTouchFriendly(t *testing.T) {
	out := renderListAllAccessibilityHTML(t)

	for _, want := range []string{
		`.finding-advisory a{display:inline-flex;align-items:center;min-height:var(--report-touch-target);padding:var(--report-space-1-5) var(--report-space-2);margin:calc(-1 * var(--report-space-1-5)) calc(-1 * var(--report-space-2));`,
		`.external-link::after{content:"";display:inline-block;inline-size:0.65em;block-size:0.65em;margin-inline-start:0.25em;border-block-start:1.5px solid currentColor;border-inline-end:1.5px solid currentColor;`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing touch-friendly advisory link style %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "&#8599;") {
		t.Fatalf("list-all HTML still renders raw external-link glyph:\n%s", out)
	}
}

func TestListAllHTMLSecurityFindingRegionsUseGroupSpecificLabels(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{Name: "evilpkg", Installed: "1.0.0", Ecosystem: "npm", Scope: "runtime", Relation: "direct", Vuln: "-"},
			{Name: "vulnpkg", Installed: "3.0.0", Ecosystem: "go", Scope: "runtime", Relation: "direct", Vuln: "yes"},
		},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{
			{Name: "evilpkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical, AdvisoryID: "MAL-evilpkg", Title: "malware detected", RiskType: "malware", Source: "openssf"},
			{Name: "vulnpkg", Version: "3.0.0", Ecosystem: domain.EcosystemGo, Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh, AdvisoryID: "CVE-2026-0001", Title: "reachable vulnerability", RiskType: "known_vulnerability", Source: "osv"},
		},
	}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`aria-label="Malicious security findings table"`,
		`aria-label="Vulnerabilities security findings table"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing group-specific region label %q:\n%s", want, out)
		}
	}
	if strings.Count(out, `aria-label="Security findings table"`) != 0 {
		t.Fatalf("list-all HTML still uses generic security findings region labels:\n%s", out)
	}
}

func TestCollectDockerPackagesWithWarningsRedactsInvalidImageRefs(t *testing.T) {
	//nolint:gosec // G101: fixture credential, deliberately fake.
	const raw = "https://user:token@example.internal/private/app"
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+raw+"\n")
	writeFile(t, filepath.Join(dir, "docker-compose.yml"), `
services:
  app:
    image: https://user:token@example.internal/private/app
`)

	rows, warnings, err := collectDockerPackagesWithWarnings(dir, scanSettings{MaxDepth: 1})
	if err != nil {
		t.Fatalf("collectDockerPackagesWithWarnings: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %#v, want no rows from invalid Docker inventory", rows)
	}
	joined := strings.Join(warnings, "\n")
	for _, leaked := range []string{"user", "token", "example.internal", "/private/app", raw} {
		if strings.Contains(joined, leaked) {
			t.Fatalf("Docker inventory warning leaked %q: %s", leaked, joined)
		}
	}
	for _, want := range []string{
		"docker parse error in Dockerfile:1: invalid FROM image",
		"docker parse error in docker-compose.yml:4",
		"invalid image for compose service",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Docker inventory warning missing %q: %s", want, joined)
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	assertStandaloneHTMLUsesRemTypography(t, out)
	for _, want := range []string{
		`<html lang="en" dir="auto">`,
		`<meta name="color-scheme" content="dark light">`,
		":root{color-scheme:dark;",
		"--success:",
		"--sev-low:",
		"overflow-wrap:anywhere",
		"word-break:break-word",
		"--button-bg:",
		"--button-fg:",
		"--status-bg:",
		".copy-btn{order:-1;margin-inline-end:var(--report-space-2);display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--border);border-radius:var(--report-radius-sm);background:var(--button-bg);color:var(--button-fg);",
		".status{margin:var(--report-space-5) 0;padding:var(--report-space-3) var(--report-space-4);background:var(--status-bg);",
		"@media (prefers-color-scheme: light)",
		"@media (prefers-color-scheme: light){:root{color-scheme:light;",
		"--warning:#8a4600;--warning-bg:#ffffff;--status-bg:#ffffff;--button-bg:#ffffff;",
		"--button-fg:#111827;--link:#0645ad;",
		"@media (prefers-contrast: more)",
		"@media (forced-colors: active)",
		"@media print",
		".package-table,.findings-table{min-width:0;}",
		".name,.installed,.version,.short,.source,.package-status,.vuln-col,.findings-table .finding-package,.findings-table .finding-advisory,.finding-action{min-width:0;white-space:normal;}",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML CSS missing %q:\n%s", want, out)
		}
	}
}

func TestListAllHTMLUsesReportTypeAndSpacingScales(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "github.com/acme/pkg",
			Installed: "sha256:" + strings.Repeat("a", 64),
			Latest:    "sha256:" + strings.Repeat("b", 64),
			Ecosystem: "docker",
			Source:    "dockerfile",
			Scope:     "runtime",
			Relation:  "base",
			Vuln:      "-",
			LockFile:  "Dockerfile",
		}},
	}
	result := &domain.ScanResult{Mode: "local"}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)

	assertGeneratedReportHTMLDefinesScales(t, out)
	for _, want := range []string{
		`body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--report-type-base);`,
		`h1{font-size:var(--report-type-xl);margin:0;color:var(--heading);`,
		`h2{font-size:var(--report-type-lg);margin:var(--report-space-6) 0 var(--report-space-2);`,
		`.badge{border:1px solid var(--border);border-radius:var(--report-radius-md);padding:var(--report-space-1) var(--report-space-3);font-size:var(--report-type-sm);`,
		`.sev{display:inline-block;border:1px solid var(--border);border-radius:var(--report-radius-sm);padding:var(--report-space-0-5) var(--report-space-1-5);font-size:var(--report-type-xs);font-weight:700;line-height:1.3;}`,
		`.copy-btn{order:-1;margin-inline-end:var(--report-space-2);display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--border);border-radius:var(--report-radius-sm);background:var(--button-bg);color:var(--button-fg);width:1.4rem;height:1.4rem;padding:0;cursor:pointer;}`,
		`.footer{border-top:1px solid var(--border);margin-top:var(--report-space-7);padding-top:var(--report-space-3);color:var(--dim);font-size:var(--report-type-xs);}`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing scaled CSS contract %q:\n%s", want, out)
		}
	}
	assertGeneratedReportHTMLAvoidsOffScaleMicroSpacing(t, out)
}

func assertGeneratedReportHTMLDefinesScales(t *testing.T, out string) {
	t.Helper()

	for _, want := range []string{
		`--report-type-2xs:0.6875rem;--report-type-xs:0.75rem;--report-type-sm:0.8125rem;--report-type-base:0.875rem;--report-type-md:0.9375rem;--report-type-lg:1rem;--report-type-xl:1.375rem;`,
		`--report-space-0-5:0.125rem;--report-space-1:0.25rem;--report-space-1-5:0.375rem;--report-space-2:0.5rem;--report-space-3:0.75rem;--report-space-4:1rem;--report-space-5:1.25rem;--report-space-6:1.5rem;--report-space-7:1.75rem;--report-space-8:3rem;`,
		`--report-radius-sm:0.25rem;--report-radius-md:0.375rem;--report-radius-pill:999px;--report-focus-ring:0.1875rem;--report-focus-offset:0.1875rem;--report-touch-target:2.75rem;`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML report missing local CSS scale %q:\n%s", want, out)
		}
	}
}

func assertGeneratedReportHTMLAvoidsOffScaleMicroSpacing(t *testing.T, out string) {
	t.Helper()

	for _, bad := range []string{
		`padding:3px 11px`,
		`padding:1px 7px`,
		`padding:5px 10px`,
		`padding:5px 8px`,
		`padding-bottom:5px`,
		`padding-top:10px`,
		`margin-top:10px`,
		`padding:10px 12px`,
		`gap:5px`,
		`outline:3px solid`,
	} {
		if strings.Contains(out, bad) {
			t.Fatalf("HTML report still uses off-scale micro-spacing %q:\n%s", bad, out)
		}
	}
}

func TestListAllHTMLTableScrollRegionsAreKeyboardFocusable(t *testing.T) {
	for _, want := range []string{
		".table-scroll:focus{",
		`<div class="table-scroll" tabindex="0" role="region" aria-label="{{.Messages.PackagesNeedingAttentionTableLabel}}">`,
		`<div class="table-scroll" tabindex="0" role="region" aria-label="{{.AriaLabel}}">`,
		`<div class="table-scroll" tabindex="0" role="region" aria-label="{{.Messages.AllPackagesTableLabel}}">`,
	} {
		if !strings.Contains(listAllHTML, want) {
			t.Fatalf("list-all HTML template missing keyboard-scroll contract %q", want)
		}
	}
}

func listAllTerminalSection(t *testing.T, out, startMarker, endMarker string) string {
	t.Helper()

	start := strings.Index(out, startMarker)
	if start < 0 {
		t.Fatalf("output missing %q:\n%s", startMarker, out)
	}
	section := out[start:]
	if end := strings.Index(section[len(startMarker):], endMarker); end >= 0 {
		section = section[:len(startMarker)+end]
	}
	return section
}

func firstLineContaining(t *testing.T, out, needle string) string {
	t.Helper()

	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("output missing line containing %q:\n%s", needle, out)
	return ""
}

func listAllHTMLSecurityFindingTable(t *testing.T, out string) string {
	t.Helper()

	securityStart := strings.Index(out, "<h2>Security Findings</h2>")
	if securityStart < 0 {
		t.Fatalf("HTML missing Security Findings section:\n%s", out)
	}
	tableStart := strings.Index(out[securityStart:], `<table class="findings-table">`)
	if tableStart < 0 {
		t.Fatalf("HTML missing security findings table:\n%s", out[securityStart:])
	}
	table := out[securityStart+tableStart:]
	tableEnd := strings.Index(table, "</table>")
	if tableEnd < 0 {
		t.Fatalf("HTML security findings table is not closed:\n%s", table)
	}
	return table[:tableEnd+len("</table>")]
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
	if strings.Contains(attention, `<td class="name"><bdi dir="auto">docker.io/library/alpine</bdi></td>`) {
		t.Fatalf("unknown-only docker package should not be in attention section:\n%s", attention)
	}
	if !strings.Contains(attention, "No package status issues requiring attention.") {
		t.Fatalf("attention section should explain there are no actionable package issues:\n%s", attention)
	}
	allPackagesStart := strings.Index(out, `<details class="inventory-details">`)
	if allPackagesStart < 0 {
		t.Fatalf("HTML missing All Packages section:\n%s", out)
	}
	allPackages := out[allPackagesStart:]
	if !strings.Contains(allPackages, `<td class="name"><bdi dir="auto">docker.io/library/alpine</bdi></td>`) ||
		!strings.Contains(allPackages, `<td class="package-status">Unknown</td>`) {
		t.Fatalf("unknown docker package should still be visible in All Packages:\n%s", allPackages)
	}
}

func TestListAllHTMLExcludesMerelyOutdatedPackagesFromAttention(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "left-pad",
			Installed: "1.0.0",
			Latest:    "1.3.0",
			Update:    "yes",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "direct",
			Vuln:      "-",
			LockFile:  "package-lock.json",
		}},
	}
	result := &domain.ScanResult{Mode: "remote"}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
	// A package that merely has an available update (no security or lifecycle
	// finding) must NOT be flagged as needing attention.
	attention := out[attentionStart:securityStart]
	if strings.Contains(attention, "left-pad") {
		t.Fatalf("merely-outdated package must not appear under Packages Needing Attention:\n%s", attention)
	}
	if !strings.Contains(attention, "No package status issues requiring attention.") {
		t.Fatalf("attention section should report no actionable issues:\n%s", attention)
	}
	// It must still be listed with its available update in All Packages.
	allStart := strings.Index(out, `<details class="inventory-details">`)
	if allStart < 0 || !strings.Contains(out[allStart:], "left-pad") {
		t.Fatalf("outdated package should still appear in All Packages:\n%s", out)
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
	wantRow := `<td class="name"><bdi dir="auto">evilpkg</bdi></td><td class="installed"><bdi dir="auto">2.0.0</bdi></td><td class="version"><bdi dir="auto">2.0.0</bdi></td><td class="package-status">Malicious</td>`
	if !strings.Contains(attention, wantRow) {
		t.Fatalf("malicious package should be explicit in attention section:\n%s", attention)
	}
	if !strings.Contains(out, `<td class="finding-advisory"><a class="external-link" href="https://secure.software/pypi/packages/evilpkg" target="_blank" rel="noopener" aria-label="reversinglabs:pypi/evilpkg@2.0.0 opens in a new tab"><bdi dir="auto">reversinglabs:pypi/evilpkg@2.0.0</bdi><span class="sr-only"> (opens in a new tab)</span></a></td>`) {
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
			RiskType:   domain.RiskTypeMalwareHistory,
			Source:     "reversinglabs",
		}},
	}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
	if !strings.Contains(attention, "polars-runtime-32") || !strings.Contains(attention, "Reputation info") {
		t.Fatalf("historical reputation risk should appear as package attention:\n%s", attention)
	}
	if !strings.Contains(strings.ToLower(out), "malware incident history") {
		t.Fatalf("HTML should render historical reputation risk finding:\n%s", out)
	}
	if !strings.Contains(out, `<span class="sev sev-low">LOW</span>`) {
		t.Fatalf("historical reputation risk should render as LOW severity:\n%s", out)
	}
	if strings.Contains(out, `<span class="sev sev-high">HIGH</span>`) {
		t.Fatalf("historical reputation risk should not render as HIGH severity:\n%s", out)
	}
	if strings.Contains(out, "Supply-Chain / EOL") {
		t.Fatalf("historical reputation risk should not be grouped as active supply-chain risk:\n%s", out)
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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

func TestListAllHTMLLocalDegradedFeedStatusMentionsSyncedDatabase(t *testing.T) {
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
		Mode:            "local",
		PackagesScanned: 1,
		FeedStatus:      "degraded",
	}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	if !strings.Contains(out, "local database was last synced from a server reporting degraded feed status") {
		t.Fatalf("HTML missing local degraded warning:\n%s", out)
	}
	if strings.Contains(out, "Server reports degraded feed status") {
		t.Fatalf("local warning should not read like a live remote check:\n%s", out)
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
		RiskType:  domain.RiskTypeMalwareHistory,
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
	resolver := packageUpdateResolver{fetchLatest: func(context.Context, domain.Ecosystem, string) string {
		called.Store(true)
		return "2.0.0"
	}}

	report := buildListAllPackageReportWithOptions(ctx, []listAllPackage{{
		Name:      "leftpad",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}}, nil, ".", 1, listAllPackageReportOptions{resolver: resolver})
	if len(report.Rows) != 1 || report.Rows[0].Latest != "unknown" || report.Unknown != 1 {
		t.Fatalf("report rows = %+v, want one unknown row after canceled lookup", report.Rows)
	}
	if called.Load() {
		t.Fatal("latest-version lookup ran after caller context was canceled")
	}
}

func TestBuildListAllPackageReportSetsNoPhaseDeadline(t *testing.T) {
	var sawNoDeadline, sawPerRequestTimeout atomic.Bool
	resolver := stubLatestVersion(t, func(ctx context.Context, _ domain.Ecosystem, _ string) string {
		if _, ok := ctx.Deadline(); !ok {
			sawNoDeadline.Store(true)
		}
		if phase := registryLookupPhaseFrom(ctx); phase != nil && phase.perRequestTimeout() == time.Second {
			sawPerRequestTimeout.Store(true)
		}
		return "2.0.0"
	})

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{{
		Name:      "leftpad",
		Version:   "1.0.0",
		Ecosystem: domain.EcosystemNPM,
	}}, nil, ".", 1, listAllPackageReportOptions{resolver: resolver})
	if len(report.Rows) != 1 || report.Rows[0].Latest != "2.0.0" {
		t.Fatalf("report rows = %+v, want resolved latest version", report.Rows)
	}
	if !sawNoDeadline.Load() {
		t.Fatal("lookup context has a deadline; the phase must not set one")
	}
	if !sawPerRequestTimeout.Load() {
		t.Fatal("phase per-request timeout was not set from the configured timeout")
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
		want := `<td class="name"><bdi dir="auto">` + pkg.name + `</bdi></td><td class="installed"><bdi dir="auto">` + pkg.installed + `</bdi></td><td class="version"><bdi dir="auto">` + pkg.latest + `</bdi></td><td class="package-status` + statusClass + `">` + pkg.status + `</td>`
		if !strings.Contains(out, want) {
			t.Fatalf("vulnerable package should be marked %s, not Up-to-Date:\n%s", pkg.status, out)
		}
		bad := `<td class="name"><bdi dir="auto">` + pkg.name + `</bdi></td><td class="installed"><bdi dir="auto">` + pkg.installed + `</bdi></td><td class="version"><bdi dir="auto">` + pkg.latest + `</bdi></td><td class="package-status">Up-to-Date</td>`
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<th scope="col" class="meta-cell">Inventory Details</th>`,
		`<th scope="col" class="vuln-col">Vulnerability</th>`,
		`<dt>Relation</dt><dd>transitive</dd>`,
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

func TestListAllHTMLUsesCompactActionAndInventoryLayouts(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{
				Name:      "@angular/core",
				Installed: "18.2.0",
				Latest:    "18.2.1",
				Update:    "yes",
				Ecosystem: "npm",
				Source:    "lockfile",
				Scope:     "runtime",
				Relation:  "transitive",
				Vuln:      "yes",
				LockFile:  "package-lock.json",
			},
			{
				Name:      "docker.io/library/postgres",
				Installed: "16",
				Latest:    "16",
				Update:    "-",
				Ecosystem: "docker",
				Source:    "compose",
				Scope:     "runtime",
				Relation:  "service-image",
				Vuln:      "-",
				LockFile:  "docker-compose.yml",
			},
		},
	}
	result := &domain.ScanResult{Mode: "remote"}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)

	for _, want := range []string{
		`<table class="package-table attention-table">`,
		`<th scope="col" class="package-status">Action</th>`,
		`<th scope="col" class="meta-cell">Triage</th>`,
		`<table class="package-table inventory-table">`,
		`<th scope="col" class="meta-cell">Inventory Details</th>`,
		`<dl class="package-meta-list"><div><dt>Ecosystem</dt><dd>npm</dd></div><div><dt>Source</dt><dd><bdi dir="auto">lockfile</bdi></dd></div><div><dt>Scope</dt><dd>runtime</dd></div><div><dt>Relation</dt><dd>transitive</dd></div></dl>`,
		`<td class="vuln-col vuln-yes">yes</td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing compact layout contract %q:\n%s", want, out)
		}
	}

	for _, old := range []string{
		`.package-table{min-width:1500px;`,
		`<th scope="col" class="installed">Installed</th><th scope="col" class="version">Latest</th><th scope="col" class="package-status">Status</th><th scope="col" class="short">Ecosystem</th><th scope="col" class="source">Source</th><th scope="col" class="short">Scope</th><th scope="col" class="short">Relation</th><th scope="col" class="vuln-col">Vulnerability</th>`,
	} {
		if strings.Contains(out, old) {
			t.Fatalf("list-all HTML still renders old 10-column inventory layout %q:\n%s", old, out)
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<span class="copy-value"><bdi dir="auto">5b10f432ef3d12345..</bdi></span>`,
		`<span class="print-copy-value"><bdi dir="auto">` + digest + `</bdi></span>`,
		`data-copy="` + digest + `"`,
		`data-copy-label="Copy full latest value for docker.io/library/alpine 3.23"`,
		`data-copy-message="Copied full latest value for docker.io/library/alpine"`,
		`aria-label="Copy full latest value for docker.io/library/alpine 3.23"`,
		`id="copy-status" class="sr-only" role="status" aria-live="polite"`,
		`function showManualCopy(value,button)`,
		`className='copy-fallback'`,
		`input.select()`,
		`Full value is selected for manual copy`,
		`Copy failed`,
		`copy-failed`,
		`navigator.clipboard.writeText`,
		`var copyConfirmationVisibleMs=5000;`,
		`window.setTimeout(function(){resetButton(button);},copyConfirmationVisibleMs);`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "execCommand") {
		t.Fatalf("HTML keeps deprecated execCommand copy fallback:\n%s", out)
	}
	if strings.Contains(out, `<td class="version">`+digest+`</td>`) {
		t.Fatalf("HTML renders full digest inline instead of shortened copy UI:\n%s", out)
	}
}

func TestListAllHTMLPrintsExternalHrefsFullDigestsAndIsolatesBidi(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	const digest = "sha256:5b10f432ef3d1234567890abcdef1234567890abcdef1234567890abcdef12"
	report := listAllPackageReport{
		Target: "repo-\u05d0",
		Rows: []listAllRow{{
			Name:       "docker.io/library/alpine-\u05d1",
			Installed:  "3.23-\u05d2",
			Latest:     shortDigest(digest),
			LatestCopy: digest,
			Update:     "yes",
			Ecosystem:  "docker",
			Source:     "dockerfile",
			Scope:      "runtime",
			Relation:   "base",
			Vuln:       "-",
			LockFile:   "Dockerfile-\u05d3",
		}},
		Sources: []listAllSourceRow{{Kind: "docker", Path: "Dockerfile-\u05d3"}},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:       "docker.io/library/alpine-\u05d1",
			Version:    "3.23-\u05d2",
			Ecosystem:  domain.EcosystemDocker,
			Type:       domain.FindingTypeVulnerability,
			Severity:   domain.SeverityHigh,
			AdvisoryID: "GHSA-test",
			Title:      "mixed bidi finding \u05d5",
			Source:     "ghsa-\u05d6",
			URL:        "https://github.com/advisories/GHSA-test",
		}},
	}

	if err := writeListAllHTML(htmlPath, "test-\u05d7", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<h1><bdi dir="auto">test-` + "\u05d7" + `</bdi></h1>`,
		`<bdi dir="auto">repo-` + "\u05d0" + `</bdi>`,
		`<td class="name"><bdi dir="auto">docker.io/library/alpine-` + "\u05d1" + `</bdi></td>`,
		`<span class="copy-value"><bdi dir="auto">5b10f432ef3d12345..</bdi></span>`,
		`<span class="print-copy-value"><bdi dir="auto">` + digest + `</bdi></span>`,
		`<td class="finding-advisory"><a class="external-link" href="https://github.com/advisories/GHSA-test" target="_blank" rel="noopener" aria-label="GHSA-test opens in a new tab"><bdi dir="auto">GHSA-test</bdi><span class="sr-only"> (opens in a new tab)</span></a></td>`,
		`<td class="finding-title"><bdi dir="auto">mixed bidi finding ` + "\u05d5" + `</bdi></td>`,
		`<span class="source-path"><bdi dir="auto">Dockerfile-` + "\u05d3" + `</bdi></span>`,
		`a[href]::after{content:" (" attr(href) ")";`,
		`.copy-btn{display:none;}`,
		`.print-copy-value{display:inline;`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("list-all HTML missing print/bidi contract %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{`<html lang="en" dir="ltr">`, "&#8599;", "text-align:left", "margin-left"} {
		if strings.Contains(out, bad) {
			t.Fatalf("list-all HTML still uses hardcoded direction-sensitive output %q:\n%s", bad, out)
		}
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
		`.copy-btn{order:-1;margin-inline-end:var(--report-space-2);display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--border);border-radius:var(--report-radius-sm);background:var(--button-bg);color:var(--button-fg);width:1.4rem;height:1.4rem;padding:0;cursor:pointer;}`,
		`.copy-btn:focus-visible{outline:var(--report-focus-ring) solid var(--link);outline-offset:var(--report-space-0-5);border-color:var(--link);}`,
		`.copy-btn:active{background:var(--link);border-color:var(--link);color:var(--bg);}`,
		`.vuln-col{text-align:center;`,
		`.findings-table{table-layout:auto;min-width:980px;}`,
		`.findings-table .finding-package{min-width:220px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}`,
		`.findings-table .finding-advisory{min-width:190px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}`,
		`.finding-advisory a{display:inline-flex;align-items:center;min-height:var(--report-touch-target);padding:var(--report-space-1-5) var(--report-space-2);margin:calc(-1 * var(--report-space-1-5)) calc(-1 * var(--report-space-2));white-space:nowrap;overflow-wrap:normal;word-break:normal;}`,
		`.finding-title{min-width:320px;white-space:normal;overflow-wrap:break-word;word-break:normal;}`,
		`.finding-action{min-width:150px;white-space:nowrap;overflow-wrap:normal;word-break:normal;}`,
		`<td class="package-status status-update">Update available</td>`,
		`<td class="vuln-col vuln-yes">yes</td>`,
		`<span class="sev sev-high">HIGH</span>`,
		`<table class="findings-table">`,
		`<th scope="col" class="finding-package">Package</th>`,
		`<th scope="col" class="finding-advisory">Advisory</th>`,
		`<th scope="col" class="finding-title">Finding</th>`,
		`<th scope="col" class="finding-action">Action</th>`,
		`<td class="finding-action"><bdi dir="auto">Fix &gt;= 8.5.10</bdi></td>`,
		`<td class="installed"><span class="copy-cell"><span class="copy-value"><bdi dir="auto">aaaaaaaaaaaa12345..</bdi></span><button type="button" class="copy-btn" data-copy="` + installedDigest + `" data-copy-label="Copy full installed value for docker.io/library/nginx ` + installedDigest + `" data-copy-message="Copied full installed value for docker.io/library/nginx" aria-label="Copy full installed value for docker.io/library/nginx ` + installedDigest + `"><svg class="copy-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg></button></span><span class="print-copy-value"><bdi dir="auto">` + installedDigest + `</bdi></span></td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing layout requirement %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{
		`.findings-table{table-layout:auto;min-width:0;}`,
		`.findings-table .finding-package{width:1%;`,
		`.findings-table .finding-advisory{width:1%;`,
		`.finding-fixed{`,
		`.finding-action{overflow-wrap:anywhere;word-break:break-word;}`,
		`min-height:32px`,
	} {
		if strings.Contains(out, bad) {
			t.Fatalf("HTML still contains cramped finding table layout %q:\n%s", bad, out)
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
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
		`<th scope="col" class="package-status">Status</th>`,
		`<td class="package-status">Removed</td>`,
		`<td class="package-status status-update">Update available</td>`,
		`<td class="package-status">Up-to-Date</td>`,
		`<td class="package-status">Local build</td>`,
		`<td class="name"><bdi dir="auto">postcss</bdi></td><td class="installed"><bdi dir="auto">8.5.8</bdi></td><td class="version"><bdi dir="auto">8.5.10</bdi></td><td class="package-status status-update">Update available</td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing %q:\n%s", want, out)
		}
	}
	for _, removed := range []string{
		`<th class="short">Update</th>`,
		`<th class="lockfile">Lockfile</th>`,
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		"<h2>Checked Inventory Sources</h2>",
		`<span class="source-kind">docker</span><span class="source-path"><bdi dir="auto">Dockerfile</bdi></span>`,
		`<span class="source-kind">docker</span><span class="source-path"><bdi dir="auto">docker-compose.yml</bdi></span>`,
		`<span class="source-kind">lockfile</span><span class="source-path"><bdi dir="auto">package-lock.json</bdi></span>`,
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

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<span class="source-kind">lockfile</span><span class="source-path"><bdi dir="auto">package-lock.json</bdi></span>`,
		`<span class="source-kind">sbom</span><span class="source-path"><bdi dir="auto">sbom/package.cdx.json</bdi></span>`,
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

	if err := writeListAllHTML(htmlPath, "test", &domain.ScanResult{Mode: "local"}, report); err != nil {
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
		`<span class="source-kind">lockfile</span><span class="source-path"><bdi dir="auto">package-lock.json</bdi></span>`,
		`<span class="source-kind">sbom</span><span class="source-path"><bdi dir="auto">student-bom.cdx.json</bdi></span>`,
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
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
		`<td class="name"><bdi dir="auto">node-addon-api</bdi></td><td class="installed"><bdi dir="auto">7.1.1</bdi></td><td class="version"><bdi dir="auto">8.8.0</bdi></td><td class="package-status status-update">Update available</td>`,
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

	local := resolveListAllLatestWithLookup(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "local/image",
		Version:   "latest",
	}, directPackageUpdateLookup(), nil)
	if local.Unknown || local.Latest != "-" || local.Update != "local" {
		t.Fatalf("local docker status = %+v, want local non-unknown", local)
	}
	invalidDocker := resolveListAllLatestWithLookup(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "bad ref",
		Version:   "latest",
	}, directPackageUpdateLookup(), nil)
	if !invalidDocker.Unknown {
		t.Fatalf("invalid docker status = %+v, want unknown", invalidDocker)
	}

	ref, ok := dockerRefFromListAllPackage(listAllPackage{Name: "docker.io/library/postgres", Version: "sha256:abcdef"})
	if !ok || ref.Name != "docker.io/library/postgres" || ref.Reference != "sha256:abcdef" {
		t.Fatalf("docker ref = %+v/%v", ref, ok)
	}
	if got := shortDigest("sha256:1234567890abcdef1234567890"); got != "1234567890abcdef1.." {
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
	err := writeListAllHTML(filepath.Join(parentFile, "report.html"), "", &domain.ScanResult{}, listAllPackageReport{})
	if err == nil || !strings.Contains(err.Error(), "prepare HTML output") {
		t.Fatalf("writeListAllHTML(parent file) = %v", err)
	}
}

func TestListAllFindingLabelsAndWarnings(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "blank", raw: "", want: "-"},
		{name: "known", raw: domain.RiskTypeMalwareHistory, want: "Malware history"},
		{name: "hyphen unknown", raw: "custom-risk_type", want: "Custom risk type"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := listAllRiskTypeLabel(tt.raw); got != tt.want {
				t.Fatalf("listAllRiskTypeLabel(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}

	for _, tt := range []struct {
		f    domain.Finding
		want string
	}{
		{f: domain.Finding{Name: "left-pad", Version: "1.0.0"}, want: "left-pad"},
		{f: domain.Finding{Version: "1.0.0"}, want: "1.0.0"},
		{f: domain.Finding{}, want: "-"},
	} {
		if got := listAllFindingPackageLabel(tt.f); got != tt.want {
			t.Fatalf("listAllFindingPackageLabel(%+v) = %q, want %q", tt.f, got, tt.want)
		}
	}

	for _, tt := range []struct {
		f    domain.Finding
		want string
	}{
		{f: domain.Finding{RiskType: "removed_package"}, want: "Removed package"},
		{f: domain.Finding{Type: domain.FindingTypeMalicious}, want: "Malware"},
		{f: domain.Finding{Type: domain.FindingTypeVulnerability}, want: "Known vulnerability"},
		{f: domain.Finding{Type: domain.FindingTypeLifecycle}, want: "Lifecycle"},
		{f: domain.Finding{Type: domain.FindingTypeSupplyChainRisk}, want: "Supply-chain risk"},
		{f: domain.Finding{}, want: "-"},
	} {
		if got := listAllFindingRiskType(tt.f); got != tt.want {
			t.Fatalf("listAllFindingRiskType(%+v) = %q, want %q", tt.f, got, tt.want)
		}
	}

	if got := listAllFindingTitle(domain.Finding{Title: "original", RiskType: domain.RiskTypeMalwareHistory}); got != "ReversingLabs: malware incident history" {
		t.Fatalf("listAllFindingTitle(malware_history) = %q", got)
	}
	if got := listAllFindingTitle(domain.Finding{Title: "original"}); got != "original" {
		t.Fatalf("listAllFindingTitle(default) = %q", got)
	}

	staleDays := 9
	warnings := listAllHTMLWarnings(&domain.ScanResult{
		Mode:        "local",
		FeedStatus:  "degraded",
		DBStale:     true,
		DBAgeDays:   &staleDays,
		ParseErrors: []string{" ", "bad lockfile"},
	}, []string{" ", "missing SBOM"})
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{
		"Local database last synced 9 days ago",
		"bad lockfile",
		"missing SBOM",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warnings missing %q: %+v", want, warnings)
		}
	}
	if got := listAllHTMLWarnings(nil, []string{"missing inventory"}); len(got) != 1 || !strings.Contains(got[0], "missing inventory") {
		t.Fatalf("listAllHTMLWarnings(nil) = %+v", got)
	}
}

func TestListAllHTMLWarningsUseSharedReportWarningsAndAppendInventoryWarnings(t *testing.T) {
	t.Parallel()

	result := &domain.ScanResult{
		Mode:        domain.ScanModeLocal,
		FeedStatus:  "degraded",
		DBStale:     true,
		ParseErrors: []string{" ", "bad lockfile"},
	}
	got := listAllHTMLWarnings(result, []string{" ", "missing SBOM"})
	common := scanner.ReportWarnings(result)
	if len(got) != len(common)+1 {
		t.Fatalf("warnings = %#v, want shared warnings %#v plus one inventory warning", got, common)
	}
	for i := range common {
		if got[i] != common[i] {
			t.Fatalf("warnings[%d] = %q, want shared warning %q\nall warnings: %#v", i, got[i], common[i], got)
		}
	}
	if want := "Some requested package inventory could not be listed: missing SBOM"; got[len(got)-1] != want {
		t.Fatalf("last warning = %q, want %q\nall warnings: %#v", got[len(got)-1], want, got)
	}
}

func TestListAllHTMLWarningsCollapseLargeWarningStacks(t *testing.T) {
	t.Parallel()

	var inventoryWarnings []string
	for i := 0; i < maxListAllHTMLReportWarnings+2; i++ {
		inventoryWarnings = append(inventoryWarnings, fmt.Sprintf("inventory-%d", i))
	}
	got := listAllHTMLWarnings(nil, inventoryWarnings)
	if len(got) != maxListAllHTMLReportWarnings+1 {
		t.Fatalf("warnings = %#v, want %d visible warnings plus summary", got, maxListAllHTMLReportWarnings)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "inventory-0") || strings.Contains(joined, "inventory-6") {
		t.Fatalf("warnings should keep first entries and omit overflow:\n%#v", got)
	}
	if !strings.Contains(got[len(got)-1], "additional warnings were omitted") {
		t.Fatalf("last warning = %q, want overflow summary", got[len(got)-1])
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

	got := resolveDockerImageStatusWithLocalDigests(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "docker.io/acme/app",
		Version:   digest,
		DockerRef: "registry-1.docker.io/acme/app:stable@" + digest,
	}, nil)
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

	got := resolveDockerImageStatusWithLocalDigests(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "docker.io/acme/app",
		Version:   "stable",
		DockerRef: "registry-1.docker.io/acme/app:stable",
	}, nil)
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

	got := resolveDockerImageStatusWithLocalDigests(context.Background(), listAllPackage{
		Ecosystem: domain.EcosystemDocker,
		Name:      "docker.io/acme/app",
		Version:   pinned,
		DockerRef: "registry-1.docker.io/acme/app:stable@" + pinned,
	}, nil)
	if got.Unknown || got.Update != "yes" || got.Latest != shortDigest(current) || got.LatestCopy != current {
		t.Fatalf("resolveDockerImageStatus() = %+v, want update to current tag digest", got)
	}
}

// --- DESIGN.md contract guards for the --list-all HTML report -------------
// These tests lock the documented behaviors of the list-all HTML report so a
// future refactor cannot silently regress them. See DESIGN.md, the "--list-all
// keeps the findings scan scope identical to a normal scan" bullet.

// TestListAllHTMLReportNeverImpliesFailOnFiltering locks the guarantee that the
// report never filters findings by the --fail-on threshold and therefore
// carries no fail-on footer and no per-finding detail row that could imply such
// filtering.
func TestListAllHTMLReportNeverImpliesFailOnFiltering(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "postcss",
			Installed: "8.5.8",
			Latest:    "8.5.10",
			Update:    "yes",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "transitive",
			Vuln:      "yes",
			LockFile:  "package-lock.json",
		}},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:         "postcss",
			Version:      "8.5.8",
			Ecosystem:    domain.EcosystemNPM,
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.SeverityHigh,
			AdvisoryID:   "GHSA-guard",
			Title:        "guard finding",
			FixedVersion: ">= 8.5.10",
			Source:       "osv",
		}},
	}

	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, banned := range []string{
		`class="footer"`,
		"fail-on",
		"Fail-on",
		"--fail-on",
		"finding-details-row",
		`class="finding-details"`,
	} {
		if strings.Contains(out, banned) {
			t.Fatalf("list-all HTML must not imply fail-on filtering; found %q:\n%s", banned, out)
		}
	}
}

// TestListAllHTMLOmitsTechnologyAnnotations locks the removal of the
// report-only "Technology" column/label from the list-all HTML report.
func TestListAllHTMLOmitsTechnologyAnnotations(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{
			{Name: "@angular/core", Installed: "17.0.0", Latest: "18.0.0", Update: "yes", Ecosystem: "npm", Source: "lockfile", Scope: "runtime", Relation: "direct", Vuln: "-", LockFile: "package-lock.json"},
			{Name: "org.apache.commons:commons-lang3", Installed: "3.12.0", Latest: "3.14.0", Update: "yes", Ecosystem: "maven", Source: "lockfile", Scope: "runtime", Relation: "direct", Vuln: "-", LockFile: "pom.xml"},
		},
	}
	result := &domain.ScanResult{Mode: "remote"}
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, banned := range []string{"Technology", "TECHNOLOGY"} {
		if strings.Contains(out, banned) {
			t.Fatalf("list-all HTML must not carry a Technology annotation; found %q", banned)
		}
	}
}

// TestListAllHTMLKeepsVulnerableWithFixInAttention locks the contract that a
// vulnerability finding still counts as needing attention even when a fix is
// available and its status therefore renders as "Update available".
func TestListAllHTMLKeepsVulnerableWithFixInAttention(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "postcss",
			Installed: "8.5.8",
			Latest:    "8.5.10",
			Update:    "yes",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "transitive",
			Vuln:      "yes",
			LockFile:  "package-lock.json",
		}},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:         "postcss",
			Version:      "8.5.8",
			Ecosystem:    domain.EcosystemNPM,
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.SeverityHigh,
			AdvisoryID:   "GHSA-fixable",
			Title:        "fixable vulnerability",
			FixedVersion: ">= 8.5.10",
			Source:       "osv",
		}},
	}
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
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
	if !strings.Contains(attention, "postcss") {
		t.Fatalf("vulnerable package with an available fix must appear under Packages Needing Attention:\n%s", attention)
	}
	// The status still renders as "Update available" (a fix exists), not "Vulnerable".
	if !strings.Contains(out, `<td class="package-status status-update">Update available</td>`) {
		t.Fatalf("fixable vulnerability should render status Update available:\n%s", out)
	}
}

// TestListAllHTMLDigestDisplayDropsAlgoAndTruncatesTo17 locks the digest
// presentation: the visible table shows the digest without its algorithm
// prefix, truncated to 17 characters plus "..", while the full "sha256:" digest
// stays available through the copy control and the print span.
func TestListAllHTMLDigestDisplayDropsAlgoAndTruncatesTo17(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
			Vuln:       "-",
			LockFile:   "Dockerfile",
		}},
		Unknown: 1,
	}
	result := &domain.ScanResult{Mode: "remote"}
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)

	// Visible display: exactly 17 hex chars + "..", with no algorithm prefix.
	const wantDisplay = `<span class="copy-value"><bdi dir="auto">0123456789abcdef0..</bdi></span>`
	if !strings.Contains(out, wantDisplay) {
		t.Fatalf("digest not shown as 17-char prefix without algo; want %q:\n%s", wantDisplay, out)
	}
	// Anchor on the full visible-span class so this does not match the hidden
	// print-copy-value span, which legitimately carries the full sha256: digest.
	if strings.Contains(out, `<span class="copy-value"><bdi dir="auto">sha256:`) {
		t.Fatalf("visible digest display must not keep the sha256: prefix:\n%s", out)
	}
	// Full digest remains available for copy and print.
	for _, want := range []string{
		`data-copy="` + digest + `"`,
		`<span class="print-copy-value"><bdi dir="auto">` + digest + `</bdi></span>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("full digest must remain copyable/printable; missing %q:\n%s", want, out)
		}
	}
}

// TestListAllHTMLCopyControlIsCompactIconBeforeValue locks the copy control
// design: a compact, icon-only copy button (no visible "Copy" text) rendered
// before the value and kept on one line with it.
func TestListAllHTMLCopyControlIsCompactIconBeforeValue(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
			Vuln:       "-",
			LockFile:   "Dockerfile",
		}},
		Unknown: 1,
	}
	result := &domain.ScanResult{Mode: "remote"}
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		// order:-1 renders the button before the value; the inline-flex/nowrap
		// wrapper keeps the button and shortened digest on a single line.
		`.copy-btn{order:-1;margin-inline-end:var(--report-space-2);`,
		`.copy-cell{display:inline-flex;align-items:center;white-space:nowrap;`,
		`<span class="copy-cell"><span class="copy-value">`,
		`<svg class="copy-icon"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("copy control missing compact/before-value markup %q:\n%s", want, out)
		}
	}
	// Icon-only: the button carries no visible "Copy" text label.
	if strings.Contains(out, ">Copy</button>") {
		t.Fatalf("copy button must be icon-only, not a text label:\n%s", out)
	}
}

// TestShortDigestDropsAlgoAndTruncatesAt17 locks the 17-character truncation
// boundary and algorithm-prefix removal used by both list-all tables.
func TestShortDigestDropsAlgoAndTruncatesAt17(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"long digest truncates to 17 and drops algo", "sha256:" + strings.Repeat("a", 64), strings.Repeat("a", 17) + ".."},
		{"exactly 17 kept whole", "sha256:" + strings.Repeat("b", 17), "sha256:" + strings.Repeat("b", 17)},
		{"eighteen truncates to 17", "sha256:" + strings.Repeat("c", 18), strings.Repeat("c", 17) + ".."},
		{"non digest unchanged", "not-a-digest", "not-a-digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shortDigest(tc.in); got != tc.want {
				t.Fatalf("shortDigest(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestListAllHTMLSeverityBadgeIsCompact locks the compact sizing of the
// Security-Findings severity badge (.sev): an explicit small font and tight
// horizontal padding, so a future change cannot silently enlarge it back.
func TestListAllHTMLSeverityBadgeIsCompact(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "list-all.html")
	report := listAllPackageReport{
		Rows: []listAllRow{{
			Name:      "postcss",
			Installed: "8.5.8",
			Latest:    "8.5.10",
			Update:    "yes",
			Ecosystem: "npm",
			Source:    "lockfile",
			Scope:     "runtime",
			Relation:  "transitive",
			Vuln:      "yes",
			LockFile:  "package-lock.json",
		}},
	}
	result := &domain.ScanResult{
		Mode: "remote",
		Findings: []domain.Finding{{
			Name:         "postcss",
			Version:      "8.5.8",
			Ecosystem:    domain.EcosystemNPM,
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.SeverityHigh,
			AdvisoryID:   "GHSA-sev",
			Title:        "severity badge finding",
			FixedVersion: ">= 8.5.10",
			Source:       "osv",
		}},
	}
	if err := writeListAllHTML(htmlPath, "test", result, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)

	// The badge renders with its severity class.
	if !strings.Contains(out, `<span class="sev sev-high">HIGH</span>`) {
		t.Fatalf("severity badge markup missing:\n%s", out)
	}
	// Compact sizing: small font + tight horizontal padding.
	const wantRule = `.sev{display:inline-block;border:1px solid var(--border);border-radius:var(--report-radius-sm);padding:var(--report-space-0-5) var(--report-space-1-5);font-size:var(--report-type-xs);font-weight:700;line-height:1.3;}`
	if !strings.Contains(out, wantRule) {
		t.Fatalf("severity badge not compact; missing rule %q:\n%s", wantRule, out)
	}
	// The badge must set an explicit small font-size rather than inherit the
	// (larger) table cell size.
	if !strings.Contains(out, `.sev{`) || !strings.Contains(out, `font-size:var(--report-type-xs)`) {
		t.Fatalf("severity badge must set an explicit small font-size:\n%s", out)
	}
	// Guard against regressing to the previous, larger horizontal padding.
	if strings.Contains(out, `.sev{display:inline-block;border:1px solid var(--border);border-radius:var(--report-radius-sm);padding:var(--report-space-0-5) var(--report-space-2);`) {
		t.Fatalf("severity badge regressed to the larger space-2 padding:\n%s", out)
	}
}

func TestListAllWarnsOnBreakerTrip(t *testing.T) {
	t.Parallel()
	parent := context.Background()
	report := listAllPackageReport{}
	phaseCtx, phase := withRegistryLookupPhase(parent, 0)
	_ = phaseCtx
	for i := 0; i < registryBreakerThreshold; i++ {
		phase.recordRefusal()
	}
	phase.recordSkipped()
	phase.recordSkipped()
	appendLookupPhaseWarnings(&report, phase, false)
	if report.RefusedRequests != registryBreakerThreshold || report.SkippedRequests != 2 || !report.BreakerTripped {
		t.Fatalf("counters = %+v", report)
	}
	joined := strings.Join(report.Warnings, "\n")
	if !strings.Contains(joined, "consecutive registry request failures") {
		t.Fatalf("missing breaker warning in %q", joined)
	}
	if !strings.Contains(joined, "refused or failed") {
		t.Fatalf("missing refusal warning in %q", joined)
	}
}

func TestListAllCanceledPhaseProducesNoWarnings(t *testing.T) {
	t.Parallel()
	report := listAllPackageReport{}
	_, phase := withRegistryLookupPhase(context.Background(), 0)
	phase.recordRefusal()
	phase.recordSkipped()
	appendLookupPhaseWarnings(&report, phase, true)
	if len(report.Warnings) != 0 {
		t.Fatalf("canceled phase produced warnings: %v", report.Warnings)
	}
	if report.RefusedRequests != 1 || report.SkippedRequests != 1 {
		t.Fatalf("counters must still be recorded, got %+v", report)
	}
}

func TestListAllRefusalWarningMentionsTimeout(t *testing.T) {
	t.Parallel()
	report := listAllPackageReport{}
	_, phase := withRegistryLookupPhase(context.Background(), 0)
	phase.recordRefusal()
	appendLookupPhaseWarnings(&report, phase, false)
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "--timeout") {
		t.Fatalf("warnings = %v, want one refusal warning mentioning --timeout", report.Warnings)
	}
}

func TestListAllUnknownStatusHintVariants(t *testing.T) {
	t.Parallel()
	clean := listAllPackageReport{}
	if hint := listAllUnknownStatusHint(clean); !strings.Contains(hint, "no action is needed") {
		t.Fatalf("clean hint = %q, want private/workspace explanation", hint)
	}

	refused := listAllPackageReport{RefusedRequests: 3}
	hint := listAllUnknownStatusHint(refused)
	if !strings.Contains(hint, "3 registry requests") || !strings.Contains(hint, "--timeout") {
		t.Fatalf("refused hint = %q", hint)
	}
	if strings.Contains(hint, "no action is needed") {
		t.Fatalf("refused hint claims no action needed: %q", hint)
	}

	tripped := listAllPackageReport{RefusedRequests: 20, SkippedRequests: 40, BreakerTripped: true}
	hint = listAllUnknownStatusHint(tripped)
	if !strings.Contains(hint, "consecutive registry failures") || !strings.Contains(hint, "40") {
		t.Fatalf("breaker hint = %q", hint)
	}

	offline := listAllPackageReport{Offline: true}
	if hint := listAllUnknownStatusHint(offline); !strings.Contains(hint, "offline") {
		t.Fatalf("offline hint = %q", hint)
	}

	for _, r := range []listAllPackageReport{clean, refused, tripped, offline} {
		if hint := listAllUnknownStatusHint(r); !strings.Contains(hint, "PACKMON_REVERSINGLABS_API_KEY") {
			t.Fatalf("hint lost the ReversingLabs note: %q", hint)
		}
		if hint := listAllUnknownStatusHint(r); !strings.Contains(hint, "security findings") {
			t.Fatalf("hint lost the findings-unaffected note: %q", hint)
		}
	}
}

// TestListAllLookupsOutliveTimeoutBudget is the regression pin for the phase
// deadline removal: many packages plus a small --timeout must still resolve
// every row, because --timeout now bounds only a single registry request, not
// the whole lookup phase.
func TestListAllLookupsOutliveTimeoutBudget(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		// registryEndpoint(base, name, "latest") hits GET /{name}/latest, which
		// fetchNPMLatestFromBase parses as {"version": "..."} -- the shape of the
		// real registry.npmjs.org/{pkg}/latest response, not the full metadata
		// document with dist-tags/versions.
		_, _ = w.Write([]byte(`{"version":"9.9.9"}`))
	}))
	defer server.Close()

	packages := make([]listAllPackage, 40)
	for i := range packages {
		packages[i] = listAllPackage{
			Name:      fmt.Sprintf("pkg-%02d", i),
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
		}
	}
	resolver := packageUpdateResolver{}
	resolver.latestRegistry.NPMRegistryBaseURL = server.URL

	// 40 packages x 50ms throttle interval = ~2s of lookups; timeoutSeconds=1
	// used to cut the phase short. Now it must only bound single requests.
	report := buildListAllPackageReportWithOptions(context.Background(), packages, nil, ".", 1, listAllPackageReportOptions{resolver: resolver, Quiet: true})
	if report.Unknown != 0 {
		t.Fatalf("report.Unknown = %d, want 0 -- the phase deadline is back", report.Unknown)
	}
	if report.RefusedRequests != 0 {
		t.Fatalf("RefusedRequests = %d, want 0", report.RefusedRequests)
	}
}
