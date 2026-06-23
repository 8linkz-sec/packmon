# HTML Scan Report (`--html`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `packmon scan --html <path>` that renders the scan result as a single self-contained, terminal-dark "mini report" HTML file, grouped by finding type with source links.

**Architecture:** A new `HTMLWriter` in `internal/scanner` mirrors the existing `SARIFWriter`/`JUnitWriter` pattern. Pure mapping logic (`buildReport`) converts a `*domain.ScanResult` into a view model (grouping, severity sort, link validation, counts, footer); a Go `html/template` with inline CSS renders it. The CLI wires a `--html` flag through `scanSettings` and writes the file after the scan, reusing `ensureOutputDir` and the single-target guard.

**Tech Stack:** Go, `html/template` (auto-escaping), Cobra CLI, existing Packmon scanner/domain packages.

**Spec:** `docs/superpowers/specs/2026-06-02-html-report-design.md`

---

## File Structure

### New files
- `internal/scanner/html.go` — `HTMLWriter`, view-model structs, `buildReport`, helpers, the inline-CSS template.
- `internal/scanner/html_test.go` — unit tests for `buildReport` and the rendered output.

### Modified files
- `cmd/packmon/scan.go` — add `--html` flag, `OutputHTML` fields, multi-target guard, write block.
- `cmd/packmon/scan_output_more_test.go` — CLI test that `--html` writes a report.
- `cmd/packmon/scan_command_more_test.go` — flag/settings plumbing and multi-target guard tests.
- `DESIGN.md` — document `--html` in the output-formats section.
- `README.md` — document the `--html` example.

### Conventions reused (already in the codebase)
- `domain.Finding` fields: `Name, Version, Ecosystem, Type, Severity, AdvisoryID, Title, URL, Resources []ResourceLink, FixedVersion, RiskType, Source` (`internal/domain/models.go`).
- `domain.Severity.Rank()` (4=Critical … 1=Low, 0=other) for sorting (`internal/domain/severity.go`).
- `isAlwaysBlockingFinding(domain.Finding) bool` (already defined in package `scanner`, used by `table.go`/`sarif.go`).
- `closeSilently(c any)` (`internal/scanner/closers.go`).
- `ensureOutputDir(path string) error` (`cmd/packmon/scan.go:727`).
- `scanSettings.TargetName` (`cmd/packmon/scan.go:181`, set from the scan target name at `:332`).

---

## Task 1: Report view model and `buildReport` mapping

**Files:**
- Create: `internal/scanner/html.go`
- Create: `internal/scanner/html_test.go`

- [ ] **Step 1: Write the failing tests for `buildReport`**

Create `internal/scanner/html_test.go`:

```go
package scanner

import (
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func sampleFindings() []domain.Finding {
	return []domain.Finding{
		{Name: "lodash", Version: "4.17.11", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityMedium,
			AdvisoryID: "CVE-2020-1", Title: "axios SSRF", FixedVersion: "0.21.1",
			Source: "ghsa", URL: "https://github.com/advisories/GHSA-x"},
		{Name: "lodash", Version: "4.17.11", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityCritical,
			AdvisoryID: "CVE-2021-23337", Title: "Prototype pollution", FixedVersion: "4.17.21",
			Source: "osv", URL: "https://osv.dev/GHSA-35jh",
			Resources: []domain.ResourceLink{{Label: "NVD", URL: "https://nvd.nist.gov/x"}}},
		{Name: "evil-pkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical,
			Title: "Known malware", Source: "openssf"},
		{Name: "django", Version: "3.2.25", Ecosystem: domain.EcosystemPyPI,
			Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityCritical,
			RiskType: "eol", Title: "Django 3.2 reached end of life",
			Source: "endoflife.date", URL: "https://endoflife.date/django"},
		{Name: "node", Version: "18.19.1", Ecosystem: domain.Ecosystem("runtime"),
			Type: domain.FindingTypeLifecycle, Severity: domain.SeverityMedium,
			RiskType: "eol_soon", Title: "Node 18 reaches EOL in 74 days",
			Source: "endoflife.date", URL: "https://endoflife.date/nodejs"},
	}
}

func TestBuildReportSectionOrderAndSeveritySort(t *testing.T) {
	r := buildReport("my-service", "v0.4.0", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 142, Findings: sampleFindings(),
	})

	wantTitles := []string{"Malicious", "Supply-Chain / EOL", "Vulnerabilities", "Lifecycle warnings"}
	if len(r.Sections) != len(wantTitles) {
		t.Fatalf("sections = %d, want %d", len(r.Sections), len(wantTitles))
	}
	for i, want := range wantTitles {
		if r.Sections[i].Title != want {
			t.Fatalf("section[%d] = %q, want %q", i, r.Sections[i].Title, want)
		}
	}
	// Vulnerabilities section: Critical must sort before Medium.
	vuln := r.Sections[2].Findings
	if len(vuln) != 2 || vuln[0].Severity != "CRITICAL" || vuln[1].Severity != "MEDIUM" {
		t.Fatalf("vuln order = %+v, want CRITICAL then MEDIUM", vuln)
	}
	if r.Clean {
		t.Fatal("Clean = true, want false when findings exist")
	}
}

func TestBuildReportCleanWhenNoFindings(t *testing.T) {
	r := buildReport("my-service", "v0.4.0", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 50,
	})
	if !r.Clean {
		t.Fatal("Clean = false, want true for zero findings")
	}
	if len(r.Sections) != 0 {
		t.Fatalf("sections = %d, want 0", len(r.Sections))
	}
}

func TestBuildReportLinkValidationAndAdvisoryFallback(t *testing.T) {
	r := buildReport("x", "dev", domain.SeverityCritical, &domain.ScanResult{
		Findings: []domain.Finding{
			{Name: "evil", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
				Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical,
				Source: "openssf", URL: "https://ok.example/a",
				Resources: []domain.ResourceLink{{Label: "bad", URL: "javascript:alert(1)"}}},
		},
	})
	f := r.Sections[0].Findings[0]
	if f.Advisory != "MALWARE" {
		t.Fatalf("Advisory = %q, want MALWARE (fallback)", f.Advisory)
	}
	if len(f.Links) != 1 || f.Links[0].URL != "https://ok.example/a" {
		t.Fatalf("Links = %+v, want one https link", f.Links)
	}
	if len(f.Plain) != 1 || f.Plain[0] != "javascript:alert(1)" {
		t.Fatalf("Plain = %+v, want the non-http value as plain text", f.Plain)
	}
}

func TestBuildReportBlockingCount(t *testing.T) {
	r := buildReport("x", "dev", domain.SeverityHigh, &domain.ScanResult{
		Findings: []domain.Finding{
			{Type: domain.FindingTypeMalicious, Severity: domain.SeverityLow},      // always blocks
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh}, // >= HIGH blocks
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow},  // does not block
		},
	})
	if r.Blocking != 2 {
		t.Fatalf("Blocking = %d, want 2", r.Blocking)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```powershell
go test -count=1 .\internal\scanner -run TestBuildReport
```

Expected: FAIL — `undefined: buildReport`.

- [ ] **Step 3: Implement the view model and `buildReport` in `internal/scanner/html.go`**

Create `internal/scanner/html.go` (template constant is added in Task 2; this step adds everything except the template and the `Write`/`WriteFile` methods):

```go
package scanner

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// HTMLWriter renders a scan result as a single self-contained HTML report.
type HTMLWriter struct {
	toolVersion string
}

// NewHTMLWriter creates an HTMLWriter. An empty version becomes "dev".
func NewHTMLWriter(toolVersion string) *HTMLWriter {
	if toolVersion == "" {
		toolVersion = "dev"
	}
	return &HTMLWriter{toolVersion: toolVersion}
}

type htmlReport struct {
	Title         string
	Mode          string
	Packages      int
	ScannedAt     string
	Duration      string
	Severity      []htmlBadge
	TypeCounts    []htmlBadge
	FindingsTotal int
	Blocking      int
	Clean         bool
	Sections      []htmlSection
	FooterParts   []string
}

type htmlBadge struct {
	Label string
	Class string
	Count int
}

type htmlSection struct {
	Title    string
	Class    string
	Findings []htmlFinding
}

type htmlFinding struct {
	Severity     string
	SevSlug      string
	Package      string
	Ecosystem    string
	Advisory     string
	Title        string
	FixedVersion string
	RiskType     string
	Source       string
	Links        []htmlLink
	Plain        []string
}

type htmlLink struct {
	Label string
	URL   string
}

// sectionDef declares the fixed order and styling of report sections.
type sectionDef struct {
	typ   domain.FindingType
	title string
	class string
}

var sectionDefs = []sectionDef{
	{domain.FindingTypeMalicious, "Malicious", "s-mal"},
	{domain.FindingTypeSupplyChainRisk, "Supply-Chain / EOL", "s-sce"},
	{domain.FindingTypeVulnerability, "Vulnerabilities", "s-vuln"},
	{domain.FindingTypeLifecycle, "Lifecycle warnings", "s-life"},
}

func buildReport(title, toolVersion string, failOn domain.Severity, result *domain.ScanResult) htmlReport {
	if strings.TrimSpace(title) == "" {
		title = "Packmon Security Report"
	}

	rep := htmlReport{
		Title:         title,
		Mode:          result.Mode,
		Packages:      result.PackagesScanned,
		Duration:      formatDurationMs(result.DurationMs),
		FindingsTotal: len(result.Findings),
		Clean:         len(result.Findings) == 0,
	}
	if !result.ScannedAt.IsZero() {
		rep.ScannedAt = result.ScannedAt.Format("2006-01-02 15:04")
	}

	// Severity badges (Critical..Low, only non-zero).
	sevOrder := []struct {
		sev   domain.Severity
		label string
		class string
	}{
		{domain.SeverityCritical, "Critical", "b-crit"},
		{domain.SeverityHigh, "High", "b-high"},
		{domain.SeverityMedium, "Medium", "b-med"},
		{domain.SeverityLow, "Low", "b-low"},
	}
	for _, s := range sevOrder {
		n := 0
		for _, f := range result.Findings {
			if f.Severity == s.sev {
				n++
			}
		}
		if n > 0 {
			rep.Severity = append(rep.Severity, htmlBadge{Label: s.label, Class: s.class, Count: n})
		}
	}

	// Type counts (only non-zero), same order as sections.
	for _, def := range sectionDefs {
		n := 0
		for _, f := range result.Findings {
			if f.Type == def.typ {
				n++
			}
		}
		if n > 0 {
			rep.TypeCounts = append(rep.TypeCounts, htmlBadge{Label: def.title, Class: "b-dim", Count: n})
		}
	}

	// Blocking count.
	for _, f := range result.Findings {
		if isAlwaysBlockingFinding(f) || (failOn != domain.SeverityNone && f.Severity.Blocks(failOn)) {
			rep.Blocking++
		}
	}

	// Sections in fixed order, only when non-empty, severity-sorted within.
	for _, def := range sectionDefs {
		var fs []htmlFinding
		for _, f := range result.Findings {
			if f.Type != def.typ {
				continue
			}
			links, plain := makeLinks(f)
			fs = append(fs, htmlFinding{
				Severity:     string(f.Severity),
				SevSlug:      sevSlug(f.Severity),
				Package:      fmt.Sprintf("%s@%s", f.Name, f.Version),
				Ecosystem:    string(f.Ecosystem),
				Advisory:     advisoryLabel(f),
				Title:        f.Title,
				FixedVersion: f.FixedVersion,
				RiskType:     f.RiskType,
				Source:       f.Source,
				Links:        links,
				Plain:        plain,
			})
		}
		if len(fs) == 0 {
			continue
		}
		sort.SliceStable(fs, func(i, j int) bool {
			return domain.Severity(fs[i].Severity).Rank() > domain.Severity(fs[j].Severity).Rank()
		})
		rep.Sections = append(rep.Sections, htmlSection{
			Title: def.title, Class: def.class, Findings: fs,
		})
	}

	rep.FooterParts = footerParts(toolVersion, result)
	return rep
}

func makeLinks(f domain.Finding) (links []htmlLink, plain []string) {
	add := func(label, raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if u, err := url.Parse(raw); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			lbl := strings.TrimSpace(label)
			if lbl == "" {
				lbl = u.Host + u.Path
			}
			links = append(links, htmlLink{Label: lbl, URL: raw})
			return
		}
		plain = append(plain, raw)
	}
	add("", f.URL)
	for _, r := range f.Resources {
		add(r.Label, r.URL)
	}
	return links, plain
}

func advisoryLabel(f domain.Finding) string {
	if f.AdvisoryID != "" {
		return f.AdvisoryID
	}
	switch f.Type {
	case domain.FindingTypeMalicious:
		return "MALWARE"
	case domain.FindingTypeSupplyChainRisk:
		return "SUPPLY-CHAIN"
	default:
		return ""
	}
}

func sevSlug(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical:
		return "crit"
	case domain.SeverityHigh:
		return "high"
	case domain.SeverityMedium:
		return "med"
	case domain.SeverityLow:
		return "low"
	default:
		return "none"
	}
}

func formatDurationMs(ms int64) string {
	if ms <= 0 {
		return ""
	}
	if ms >= 1000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dms", ms)
}

func footerParts(toolVersion string, result *domain.ScanResult) []string {
	var parts []string
	if d := formatDurationMs(result.DurationMs); d != "" {
		parts = append(parts, "Scan "+d)
	}
	if result.Mode == "local" && result.DBAgeDays != nil {
		note := fmt.Sprintf("DB synced %d days ago", *result.DBAgeDays)
		if result.DBStale {
			note += " (stale)"
		}
		parts = append(parts, note)
	}
	switch result.FeedStatus {
	case "":
		// Empty means no explicit feed warning/status was attached to the scan.
	case "healthy":
		parts = append(parts, "feeds: healthy")
	case "degraded":
		parts = append(parts, "feeds: degraded")
	default:
		parts = append(parts, result.FeedStatus)
	}
	parts = append(parts, "packmon "+toolVersion)
	if result.ScanID != "" {
		parts = append(parts, "scan_id "+result.ScanID)
	}
	if result.ManualCount > 0 {
		parts = append(parts, fmt.Sprintf("%d manual advisories", result.ManualCount))
	}
	return parts
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:

```powershell
go test -count=1 .\internal\scanner -run TestBuildReport
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal\scanner\html.go internal\scanner\html_test.go
git commit -m "feat: add HTML report view model and buildReport mapping"
```

---

## Task 2: HTML template and `Write`/`WriteFile`

**Files:**
- Modify: `internal/scanner/html.go`
- Modify: `internal/scanner/html_test.go`

- [ ] **Step 1: Write the failing rendering tests**

Update `internal/scanner/html_test.go` so the import block contains all
packages needed by Task 1 and Task 2, then append the rendering tests below.
The complete import block should be:

```go
import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)
```

Append these tests after the existing Task 1 tests:

```go

func TestHTMLWriteEscapesAndRendersStructure(t *testing.T) {
	findings := sampleFindings()
	findings = append(findings, domain.Finding{
		Name: "<script>evil</script>", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
		Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow,
		Title: "xss probe", Source: "osv",
	})
	var buf bytes.Buffer
	err := NewHTMLWriter("v0.4.0").Write(&buf, "my-service", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 142, Findings: findings,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()

	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatalf("output does not start with doctype:\n%.80s", out)
	}
	if !strings.Contains(out, "<h1>my-service</h1>") {
		t.Fatal("missing H1 repo title")
	}
	if !strings.Contains(out, "font-size:14px") || !strings.Contains(out, "font-size:22px") || !strings.Contains(out, "font-size:16px") {
		t.Fatal("missing required font sizes (14/16/22)")
	}
	// Escaping: raw <script> from the package name must not appear.
	if strings.Contains(out, "<script>evil</script>") {
		t.Fatal("package name was not HTML-escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;evil&lt;/script&gt;") {
		t.Fatal("escaped package name not found")
	}
	// Section order: Malicious before Vulnerabilities.
	if strings.Index(out, "Malicious") > strings.Index(out, "Vulnerabilities") {
		t.Fatal("Malicious section should appear before Vulnerabilities")
	}
	// Links: valid https advisory is an anchor.
	if !strings.Contains(out, `href="https://osv.dev/GHSA-35jh"`) {
		t.Fatal("expected https advisory link")
	}
}

func TestHTMLWriteNonHTTPURLNotLinked(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "x", domain.SeverityCritical, &domain.ScanResult{
		Findings: []domain.Finding{{
			Name: "p", Version: "1", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow,
			Title: "t", Source: "osv",
			Resources: []domain.ResourceLink{{Label: "bad", URL: "javascript:alert(1)"}},
		}},
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, `href="javascript:`) {
		t.Fatal("javascript: URL must not be emitted as a link")
	}
	if !strings.Contains(out, "javascript:alert(1)") {
		t.Fatal("non-http value should still appear as escaped text")
	}
}

func TestHTMLWriteCleanReport(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "empty", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 12,
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings in 12 packages") {
		t.Fatal("clean report missing all-clear message")
	}
}

func TestHTMLWriteTitleFallback(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "  ", domain.SeverityCritical, &domain.ScanResult{}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !strings.Contains(buf.String(), "<h1>Packmon Security Report</h1>") {
		t.Fatal("empty title should fall back to Packmon Security Report")
	}
}

func TestHTMLWriteFileCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	if err := NewHTMLWriter("dev").WriteFile(path, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 1,
	}); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.HasPrefix(string(data), "<!DOCTYPE html>") {
		t.Fatal("written file is not an HTML document")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```powershell
go test -count=1 .\internal\scanner -run TestHTMLWrite
```

Expected: FAIL — `NewHTMLWriter(...).Write` / `WriteFile` undefined (method not yet implemented) and `htmlTemplate` missing.

- [ ] **Step 3: Add the template and `Write`/`WriteFile` to `internal/scanner/html.go`**

Add these imports to the existing `import` block in `internal/scanner/html.go`:

```go
	"html/template"
	"io"
	"os"
```

Add the template constant and methods (the rest of the file stays as written in Task 1):

```go
var htmlReportTemplate = template.Must(template.New("report").Parse(htmlTemplate))

// Write renders the scan result as an HTML document to w. title is the report
// heading (repo name); failOn is the configured blocking threshold.
func (hw *HTMLWriter) Write(w io.Writer, title string, failOn domain.Severity, result *domain.ScanResult) error {
	rep := buildReport(title, hw.toolVersion, failOn, result)
	if err := htmlReportTemplate.Execute(w, rep); err != nil {
		return fmt.Errorf("html: render: %w", err)
	}
	return nil
}

// WriteFile renders the HTML report to the given file path.
func (hw *HTMLWriter) WriteFile(path, title string, failOn domain.Severity, result *domain.ScanResult) error {
	// #nosec G304 -- CLI output path is provided intentionally by the local user.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("html: create file %s: %w", path, err)
	}
	if err := hw.Write(f, title, failOn, result); err != nil {
		closeSilently(f)
		return err
	}
	return f.Close()
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} - Packmon Report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--dim:#8b949e;--crit:#ff7b72;--high:#ffa657;--med:#e3b341;--low:#56d4c4;--link:#58a6ff;--purple:#d2a8ff;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;line-height:1.6;}
.wrap{max-width:920px;margin:0 auto;padding:28px 24px 48px;}
h1{font-size:22px;font-weight:800;color:#e6edf3;margin:0;}
.meta{color:var(--dim);font-size:13px;margin-top:4px;}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 24px;}
.badge{border-radius:6px;padding:3px 11px;font-size:13px;border:1px solid var(--border);}
.b-crit{color:var(--crit);border-color:var(--crit);}
.b-high{color:var(--high);border-color:var(--high);}
.b-med{color:var(--med);border-color:var(--med);}
.b-low{color:var(--low);border-color:var(--low);}
.b-dim{color:var(--dim);}
h2{font-size:16px;font-weight:700;border-bottom:1px solid var(--border);padding-bottom:5px;margin:22px 0 0;}
.s-mal{color:var(--crit);}
.s-sce{color:var(--purple);}
.s-vuln{color:var(--high);}
.s-life{color:var(--low);}
.count{color:var(--dim);font-weight:400;font-size:13px;}
.finding{margin:10px 0;padding:10px 12px;background:var(--panel);border-left:3px solid var(--border);border-radius:5px;}
.f-crit{border-left-color:var(--crit);}
.f-high{border-left-color:var(--high);}
.f-med{border-left-color:var(--med);}
.f-low{border-left-color:var(--low);}
.sev{border-radius:4px;padding:1px 7px;font-size:12px;font-weight:700;color:#0d1117;}
.sev-crit{background:var(--crit);}
.sev-high{background:var(--high);}
.sev-med{background:var(--med);}
.sev-low{background:var(--low);}
.sev-none{background:#484f58;color:#fff;}
.pkg{color:#e6edf3;font-weight:700;}
.dim{color:var(--dim);}
.risk{color:var(--low);}
.fix{color:var(--low);}
.links{margin-top:4px;color:var(--dim);font-size:13px;}
.links a{color:var(--link);text-decoration:underline;}
.clean{margin:24px 0;padding:14px 16px;background:#0f2d2a;border:1px solid var(--low);border-radius:6px;color:var(--low);font-size:15px;}
.footer{border-top:1px solid var(--border);margin-top:28px;padding-top:10px;color:var(--dim);font-size:12px;}
</style>
</head>
<body>
<div class="wrap">
<h1>{{.Title}}</h1>
<div class="meta">Packmon Security Report &middot; {{.Mode}} mode &middot; {{.Packages}} packages{{if .ScannedAt}} &middot; {{.ScannedAt}}{{end}}{{if .Duration}} &middot; {{.Duration}}{{end}}</div>
<div class="badges">
{{range .Severity}}<span class="badge {{.Class}}">{{.Count}} {{.Label}}</span>{{end}}
{{range .TypeCounts}}<span class="badge {{.Class}}">{{.Count}} {{.Label}}</span>{{end}}
<span class="badge b-dim">{{.FindingsTotal}} findings &middot; {{.Blocking}} blocking</span>
</div>
{{if .Clean}}<div class="clean">&#10003; No findings in {{.Packages}} packages.</div>{{end}}
{{range .Sections}}
<h2 class="{{.Class}}">{{.Title}} <span class="count">({{len .Findings}})</span></h2>
{{range .Findings}}
<div class="finding f-{{.SevSlug}}">
<div><span class="sev sev-{{.SevSlug}}">{{.Severity}}</span> <span class="pkg">{{.Package}}</span> <span class="dim">&middot; {{.Ecosystem}}</span>{{if .RiskType}} <span class="risk">&middot; risk: {{.RiskType}}</span>{{end}}</div>
<div>{{if .Advisory}}{{.Advisory}}{{if .Title}} &mdash; {{end}}{{end}}{{.Title}}{{if .FixedVersion}} <span class="fix">Fix: {{.FixedVersion}}</span>{{end}}</div>
{{if or .Links .Plain}}<div class="links">Source: {{.Source}}{{range .Links}} &middot; <a href="{{.URL}}">{{.Label}} &#8599;</a>{{end}}{{range .Plain}} &middot; {{.}}{{end}}</div>{{else if .Source}}<div class="links">Source: {{.Source}}</div>{{end}}
</div>
{{end}}
{{end}}
<div class="footer">{{range $i, $p := .FooterParts}}{{if $i}} &middot; {{end}}{{$p}}{{end}}</div>
</div>
</body>
</html>`
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:

```powershell
go test -count=1 .\internal\scanner -run "TestHTMLWrite|TestBuildReport"
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add internal\scanner\html.go internal\scanner\html_test.go
git commit -m "feat: render HTML scan report from template"
```

---

## Task 3: Wire `--html` into the scan command

**Files:**
- Modify: `cmd/packmon/scan.go`
- Modify: `cmd/packmon/scan_output_more_test.go`
- Modify: `cmd/packmon/scan_command_more_test.go`

- [ ] **Step 1: Write the failing CLI test**

First extend `cmd/packmon/scan_command_more_test.go` so the real Cobra flag
and `resolveScanSettings` plumbing are covered. In
`TestResolveScanSettingsPrecedenceAndValidation`, add the HTML flag setup next
to the existing output/SBOM flag setup:

```go
	mustSetFlag(t, cmd, "html", "result.html")
```

In the `scanFlagValues{...}` literal in the same test, add:

```go
		OutputHTML:    "result.html",
```

Replace the existing output assertion:

```go
	if settings.OutputJSON != "result.json" || settings.OutputSARIF != "result.sarif" || settings.OutputJUnit != "result.xml" {
		t.Fatalf("output paths not applied: %+v", settings)
	}
```

with:

```go
	if settings.OutputJSON != "result.json" || settings.OutputSARIF != "result.sarif" ||
		settings.OutputJUnit != "result.xml" || settings.OutputHTML != "result.html" {
		t.Fatalf("output paths not applied: %+v", settings)
	}
```

Then append to `cmd/packmon/scan_output_more_test.go` (the file already imports `context`, `os`, `path/filepath`, `strings`, `testing`):

```go
func TestScanCommandHTMLFlagWritesReport(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	scanDir := filepath.Join(t.TempDir(), "empty-project")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}
	htmlPath := filepath.Join(t.TempDir(), "report.html")

	cmd := newScanCmd()
	// NOTE: --quiet / --no-color are persistent flags on the ROOT command
	// (cmd/packmon/root.go), not on the scan command. A standalone newScanCmd()
	// does not know them, so passing --quiet here would fail with
	// "unknown flag: --quiet". Only flags registered on the scan command itself
	// (--mode, --html, the scan target) may be used in this isolated execution.
	cmd.SetArgs([]string{"--mode", "local", "--html", htmlPath, scanDir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan command execute: %v", err)
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read HTML report: %v", err)
	}
	out := string(data)
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatalf("report is not HTML:\n%.80s", out)
	}
	if !strings.Contains(out, "<h1>empty-project</h1>") {
		t.Fatal("report missing repo-name H1 title")
	}
}

func TestRunSingleScanWritesHTMLReport(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	scanDir := filepath.Join(t.TempDir(), "empty-project")
	if err := os.MkdirAll(scanDir, 0o750); err != nil {
		t.Fatalf("mkdir scan dir: %v", err)
	}
	outDir := t.TempDir()
	htmlPath := filepath.Join(outDir, "html", "report.html")

	exitCode, err := runSingleScan(context.Background(), scanSettings{
		TargetName: "empty-project",
		Path:       scanDir,
		Mode:       "local",
		FailOn:     "CRITICAL",
		MaxDepth:   2,
		Timeout:    1,
		Quiet:      true,
		OutputHTML: htmlPath,
	})
	if err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if exitCode != ExitOK {
		t.Fatalf("exitCode = %d, want %d", exitCode, ExitOK)
	}

	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads a generated report path.
	if err != nil {
		t.Fatalf("read HTML report: %v", err)
	}
	out := string(data)
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatalf("report is not HTML:\n%.80s", out)
	}
	if !strings.Contains(out, "<h1>empty-project</h1>") {
		t.Fatal("report missing repo-name H1 title")
	}
}

func TestRunScanCommandRejectsHTMLForMultipleTargets(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	yaml := "repos:\n" +
		"  - name: a\n    path: .\n    mode: local\n" +
		"  - name: b\n    path: .\n    mode: local\n"
	if err := os.WriteFile(".packmon.yaml", []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cmd := newScanCmd()
	err := runScanCommand(cmd, nil, scanFlagValues{All: true, OutputHTML: "out.html"})
	if err == nil || !strings.Contains(err.Error(), "--html") {
		t.Fatalf("err = %v, want error mentioning --html", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestResolveScanSettingsPrecedenceAndValidation|TestScanCommandHTMLFlagWritesReport|TestRunSingleScanWritesHTMLReport|TestRunScanCommandRejectsHTMLForMultipleTargets"
```

Expected: FAIL — `newScanCmd` does not know the `--html` flag yet, and
`scanSettings` / `scanFlagValues` have no `OutputHTML` field.

- [ ] **Step 3: Add the `--html` flag and field plumbing in `cmd/packmon/scan.go`**

In `newScanCmd`, add the flag variable to the `var (...)` block (after `flagOutputJUnit`):

```go
		flagOutputHTML    string
```

Register the flag (after the `--output-junit` registration at line 134):

```go
	f.StringVar(&flagOutputHTML, "html", "", "write a self-contained HTML report to file")
```

Pass it into the `scanFlagValues` literal in the default `RunE` branch (after `OutputJUnit: flagOutputJUnit,`):

```go
				OutputHTML:    flagOutputHTML,
```

Add the field to `scanFlagValues` (after `OutputJUnit string`):

```go
	OutputHTML    string
```

Add the field to `scanSettings` (after `OutputJUnit string`):

```go
	OutputHTML    string
```

- [ ] **Step 4: Extend the multi-target guard and assign the setting**

Replace the guard at `cmd/packmon/scan.go:214-216`:

```go
	if len(targets) > 1 && (strings.TrimSpace(flags.OutputJSON) != "" || strings.TrimSpace(flags.OutputSARIF) != "" || strings.TrimSpace(flags.OutputJUnit) != "") {
		return fmt.Errorf("--output-json, --output-sarif, and --output-junit can only be used when scanning a single target, not multiple targets")
	}
```

with:

```go
	if len(targets) > 1 && (strings.TrimSpace(flags.OutputJSON) != "" || strings.TrimSpace(flags.OutputSARIF) != "" || strings.TrimSpace(flags.OutputJUnit) != "" || strings.TrimSpace(flags.OutputHTML) != "") {
		return fmt.Errorf("--output-json, --output-sarif, --output-junit, and --html can only be used when scanning a single target, not multiple targets")
	}
```

In `resolveScanSettings`, assign the setting next to the other outputs (after `settings.OutputJUnit = strings.TrimSpace(flags.OutputJUnit)` at line 495):

```go
	settings.OutputHTML = strings.TrimSpace(flags.OutputHTML)
```

- [ ] **Step 5: Add the HTML write block in `runSingleScan`**

In `runSingleScan`, after the JUnit block (which ends at `cmd/packmon/scan.go:699`), add:

```go
	if settings.OutputHTML != "" {
		if err := ensureOutputDir(settings.OutputHTML); err != nil {
			fmt.Fprintf(os.Stderr, "error preparing HTML output: %v\n", err)
			if exitCode == ExitOK {
				exitCode = ExitOperational
			}
		} else {
			hw := scanner.NewHTMLWriter(version)
			if err := hw.WriteFile(settings.OutputHTML, settings.TargetName, failOn, result); err != nil {
				fmt.Fprintf(os.Stderr, "error writing HTML output: %v\n", err)
				if exitCode == ExitOK {
					exitCode = ExitOperational
				}
			}
		}
	}
```

Note: `failOn` is already in scope in `runSingleScan` (returned by `runScanPipeline` at the top of the function and used for `NewTableWriter`).

- [ ] **Step 6: Run the tests to verify they pass**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestResolveScanSettingsPrecedenceAndValidation|TestScanCommandHTMLFlagWritesReport|TestRunSingleScanWritesHTMLReport|TestRunScanCommandRejectsHTMLForMultipleTargets"
```

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add cmd\packmon\scan.go cmd\packmon\scan_output_more_test.go cmd\packmon\scan_command_more_test.go
git commit -m "feat: add packmon scan --html flag"
```

---

## Task 4: Documentation

**Files:**
- Modify: `DESIGN.md`
- Modify: `README.md`

- [ ] **Step 1: Document `--html` in DESIGN.md**

In `DESIGN.md`, under `## CLI Behavior` -> `Important behavior`, replace:

```markdown
- JSON, SARIF, and JUnit are written with explicit output-file flags.
```

with:

```markdown
- JSON, SARIF, JUnit, and HTML reports are written with explicit output-file
  flags. `--html <path>` writes a single self-contained report with no external
  assets and no JavaScript. Findings are grouped by type (Malicious ->
  Supply-Chain/EOL -> Vulnerabilities -> Lifecycle), severity-sorted within
  each group, and each vulnerability/EOL finding links to its source. A scan
  with zero findings still produces a clean "all clear" report. Like the other
  file outputs, `--html` only works when scanning a single target.
```

- [ ] **Step 2: Document `--html` in README.md**

In `README.md`, under `## Common Commands`, add the HTML example after
`packmon scan .`:

```markdown
packmon scan --html report.html .
```

Then add this short note after the Common Commands block:

```markdown
`packmon scan --html report.html .` writes a colorful, self-contained mini
report grouped by finding type. It uses the repo name as its title and links
vulnerability and EOL findings back to their source.
```

- [ ] **Step 3: Verify docs build/tests (no code change)**

Run:

```powershell
go test -count=1 .\cmd\packmon -run "TestResolveScanSettingsPrecedenceAndValidation|TestScanCommandHTMLFlagWritesReport|TestRunSingleScanWritesHTMLReport|TestRunScanCommandRejectsHTMLForMultipleTargets"
```

Expected: PASS for the HTML flag and report-writing path.

- [ ] **Step 4: Commit**

```powershell
git add DESIGN.md README.md
git commit -m "docs: document packmon scan --html report"
```

---

## Task 5: Verification Gate

**Files:**
- No source changes expected unless verification reveals issues.

- [ ] **Step 1: Format**

```powershell
gofumpt -extra -w internal\scanner\html.go internal\scanner\html_test.go cmd\packmon\scan.go cmd\packmon\scan_output_more_test.go cmd\packmon\scan_command_more_test.go
gofumpt -extra -l internal\scanner\html.go internal\scanner\html_test.go cmd\packmon\scan.go cmd\packmon\scan_output_more_test.go cmd\packmon\scan_command_more_test.go
```

Expected: no command error and no file names printed by the `-l` check.

- [ ] **Step 2: Unit tests**

```powershell
$env:GOTMPDIR = Join-Path $env:TEMP 'packmon-go-tmp'
New-Item -ItemType Directory -Force $env:GOTMPDIR | Out-Null
go test -count=1 ./...
```

Expected: PASS.

- [ ] **Step 3: Race tests for the touched packages**

```powershell
$env:GOTMPDIR = Join-Path $env:TEMP 'packmon-go-tmp'
go test -race -count=1 .\internal\scanner .\cmd\packmon
```

Expected: PASS.

- [ ] **Step 4: Vet and lint**

```powershell
go vet ./...
golangci-lint run ./...
```

Expected: PASS.

- [ ] **Step 5: Security tooling**

```powershell
govulncheck ./...
gosec ./...
```

Expected: PASS or explicitly document missing local tool. `gosec` should not flag
`html.go` `os.OpenFile` (the `#nosec G304` annotation matches the SARIF/JUnit writers).

- [ ] **Step 6: Build and smoke-test the report**

```powershell
$env:GOTMPDIR = Join-Path $env:TEMP 'packmon-go-tmp'
New-Item -ItemType Directory -Force $env:GOTMPDIR | Out-Null
New-Item -ItemType Directory -Force .build | Out-Null
go build -o .build\packmon.exe .\cmd\packmon
$smokeDir = Join-Path $env:TEMP 'packmon-html-smoke-project'
$env:PACKMON_DB_PATH = Join-Path $env:TEMP 'packmon-html-smoke-db'
New-Item -ItemType Directory -Force $smokeDir | Out-Null
.\.build\packmon.exe scan --mode local --html .build\report.html $smokeDir
```

Expected: build PASS; the command exits 0; `.build\report.html` exists and
opens in a browser as a dark clean/all-clear report.

- [ ] **Step 7: Cleanup**

```powershell
Remove-Item -Recurse -Force .build
Remove-Item -Recurse -Force $smokeDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $env:PACKMON_DB_PATH -ErrorAction SilentlyContinue
```

Expected: `.build` and the smoke-test temp paths are removed.

---

## Acceptance Criteria

- `packmon scan --html out.html <target>` writes a single self-contained HTML file (no external/CDN assets, no JavaScript).
- The repo name appears as the `<h1>` title; body text is 14px, section headings 16px, title 22px.
- Findings are grouped by type in the order Malicious -> Supply-Chain/EOL -> Vulnerabilities -> Lifecycle, severity-sorted within each section, empty sections omitted.
- Every vulnerability and EOL finding shows a link to its source (primary `URL` plus any `Resources`).
- A scan with zero findings still produces a clean "all clear" report.
- `--html` is rejected for multi-target scans, consistent with the other file outputs.
- Dynamic values are HTML-escaped; non-`http(s)` URLs are rendered as text, not links.

## Self-Review

- **Spec coverage:** CLI flag + single-target guard (Task 3), self-contained writer with `html/template` escaping and http(s)-only links (Tasks 1-2), terminal-dark layout with required font sizes and section order (Task 2), clean "all clear" report (Tasks 1-2), footer meta incl. DB age/feed status/version/scan_id/manual count (Task 1), repo-name title with fallback (Tasks 1-2), lifecycle section via `domain.FindingTypeLifecycle` (Task 1), docs (Task 4). All spec requirements map to a task.
- **Placeholder scan:** every code step contains complete code; no TBD/TODO; no "add error handling" hand-waving.
- **Type consistency:** `buildReport(title, toolVersion string, failOn domain.Severity, result *domain.ScanResult) htmlReport`, `HTMLWriter.Write(io.Writer, string, domain.Severity, *domain.ScanResult)`, and `WriteFile(path, title string, failOn domain.Severity, *domain.ScanResult)` are used identically in the writer, tests, and the CLI call site. View-model field names (`SevSlug`, `Links`, `Plain`, `FooterParts`, `TypeCounts`) match between `buildReport`, the structs, and the template.
- **Reused symbols verified present:** `isAlwaysBlockingFinding` (package `scanner`), `closeSilently` (`internal/scanner/closers.go`), `ensureOutputDir` (`cmd/packmon/scan.go:727`), `scanSettings.TargetName` (`:181`/`:332`), `domain.Severity.Rank()` (`internal/domain/severity.go`).
