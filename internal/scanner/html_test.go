package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func sampleFindings() []domain.Finding {
	return []domain.Finding{
		{
			Name: "lodash", Version: "4.17.11", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityMedium,
			AdvisoryID: "CVE-2020-1", Title: "axios SSRF", FixedVersion: "0.21.1",
			Source: "ghsa", URL: "https://github.com/advisories/GHSA-x",
		},
		{
			Name: "lodash", Version: "4.17.11", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityCritical,
			AdvisoryID: "CVE-2021-23337", Title: "Prototype pollution", FixedVersion: "4.17.21",
			Source: "osv", URL: "https://osv.dev/GHSA-35jh",
			Resources: []domain.ResourceLink{{Label: "NVD", URL: "https://nvd.nist.gov/x"}},
		},
		{
			Name: "evil-pkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical,
			Title: "Known malware", Source: "openssf",
		},
		{
			Name: "django", Version: "3.2.25", Ecosystem: domain.EcosystemPyPI,
			Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityCritical,
			RiskType: "eol", Title: "Django 3.2 reached end of life",
			Source: "endoflife.date", URL: "https://endoflife.date/django",
		},
		{
			Name: "node", Version: "18.19.1", Ecosystem: domain.Ecosystem("runtime"),
			Type: domain.FindingTypeLifecycle, Severity: domain.SeverityMedium,
			RiskType: "eol_soon", Title: "Node 18 reaches EOL in 74 days",
			Source: "endoflife.date", URL: "https://endoflife.date/nodejs",
		},
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
			{
				Name: "evil", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
				Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical,
				Source: "openssf", URL: "https://ok.example/a",
				Resources: []domain.ResourceLink{{Label: "bad", URL: "javascript:alert(1)"}},
			},
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

func TestBuildReportUnknownSeverityBadgeCountsAllFindings(t *testing.T) {
	r := buildReport("svc", "dev", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 2,
		Findings: []domain.Finding{
			{
				Name: "a", Version: "1", Ecosystem: domain.EcosystemNPM,
				Type: domain.FindingTypeVulnerability, Severity: domain.SeverityCritical,
				Title: "crit", Source: "osv",
			},
			{
				Name: "b", Version: "1", Ecosystem: domain.EcosystemNPM,
				Type: domain.FindingTypeVulnerability, Severity: domain.SeverityUnknown,
				Title: "no severity", Source: "osv",
			},
		},
	})

	var total int
	var unknown *htmlBadge
	for i := range r.Severity {
		total += r.Severity[i].Count
		if r.Severity[i].Label == "Unknown" {
			unknown = &r.Severity[i]
		}
	}
	if unknown == nil {
		t.Fatal("expected an Unknown severity badge for the UNKNOWN finding")
	}
	if unknown.Count != 1 || unknown.Class != "b-none" {
		t.Fatalf("Unknown badge = %+v, want count 1 class b-none", *unknown)
	}
	// Severity badges must sum to the total finding count (no finding dropped).
	if total != r.FindingsTotal {
		t.Fatalf("severity badge counts sum = %d, want FindingsTotal %d", total, r.FindingsTotal)
	}
}

func TestHTMLWriteEmptyModeAndUnknownRendering(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		// Mode intentionally empty.
		PackagesScanned: 1,
		Findings: []domain.Finding{{
			Name: "a", Version: "1", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityUnknown,
			Title: "t", Source: "osv",
		}},
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()

	// Empty mode: the meta line must not render a " mode" segment or a doubled
	// separator; "Report" should be directly followed by the package count.
	if !strings.Contains(out, "Packmon Security Report &middot; 1 packages") {
		t.Fatal("empty mode should omit the mode segment from the meta line")
	}
	// Unknown-severity finding uses the f-none card class, which must be styled.
	if !strings.Contains(out, "finding f-none") {
		t.Fatal("unknown-severity finding should use the f-none card class")
	}
	if !strings.Contains(out, ".f-none{") {
		t.Fatal("missing .f-none CSS rule for unknown-severity findings")
	}
}
