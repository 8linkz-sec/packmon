package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
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

func TestBuildReportZeroPackagesIsNotClean(t *testing.T) {
	r := buildReport("my-service", "v0.4.0", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 0,
	})
	if r.Clean {
		t.Fatal("Clean = true, want false when zero packages were evaluated")
	}
	if len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "No packages were evaluated") {
		t.Fatalf("Warnings = %#v, want zero-package warning", r.Warnings)
	}
}

func TestBuildReportScannedAtIncludesUTC(t *testing.T) {
	r := buildReport("my-service", "v0.4.0", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 50,
		ScannedAt:       time.Date(2026, 5, 30, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60)),
	})

	if r.ScannedAt != "2026-05-30 10:00 UTC" {
		t.Fatalf("ScannedAt = %q, want explicit UTC timestamp", r.ScannedAt)
	}
}

func TestHTMLWriteZeroPackagesIsWarningNotClean(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 0,
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "No findings in 0 packages") {
		t.Fatal("zero-package report must not render a clean all-clear message")
	}
	if !strings.Contains(out, "No packages were evaluated") {
		t.Fatalf("zero-package warning missing from report:\n%s", out)
	}
}

func TestHTMLWriteDegradedFeedStatusIsWarningNotClean(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 23,
		FeedStatus:      "degraded",
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "No findings in 23 packages") {
		t.Fatal("degraded feed report must not render a clean all-clear message")
	}
	if !strings.Contains(out, "Server reports degraded feed status") {
		t.Fatalf("degraded warning missing from report:\n%s", out)
	}
}

func TestHTMLWriteLocalDegradedFeedStatusMentionsSyncedDatabase(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 23,
		FeedStatus:      "degraded",
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "local database was last synced from a server reporting degraded feed status") {
		t.Fatalf("local degraded warning should explain synced feed status:\n%s", out)
	}
	if strings.Contains(out, "Server reports degraded feed status") {
		t.Fatalf("local degraded warning should not read like a live remote check:\n%s", out)
	}
}

func TestHTMLWriteParseErrorsAreWarningNotClean(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 12,
		ParseErrors:     []string{"pnpm-lock.yaml: invalid lockfile"},
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "No findings in 12 packages") {
		t.Fatal("partial-parse report must not render a clean all-clear message")
	}
	if !strings.Contains(out, "Some dependency inventory could not be evaluated") || !strings.Contains(out, "pnpm-lock.yaml: invalid lockfile") {
		t.Fatalf("parse warning missing from report:\n%s", out)
	}
}

func TestHTMLWriteStaleLocalDBIsWarningNotClean(t *testing.T) {
	age := 1
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 7,
		DBAgeDays:       &age,
		DBStale:         true,
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "No findings in 7 packages") {
		t.Fatal("stale local DB report must not render a clean all-clear message")
	}
	if !strings.Contains(out, "Local database last synced 1 day ago") {
		t.Fatalf("stale local DB warning missing from report:\n%s", out)
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

func TestBuildReportLabelsMalwareHistoryRiskClearly(t *testing.T) {
	r := buildReport("x", "dev", domain.SeverityCritical, &domain.ScanResult{
		Findings: []domain.Finding{
			{
				Name: "polars-runtime-32", Version: "1.40.1", Ecosystem: domain.EcosystemPyPI,
				Type: domain.FindingTypeSupplyChainRisk, Severity: domain.SeverityHigh,
				RiskType: "malware_history", Title: "ReversingLabs: malware incident history",
				Source: "reversinglabs",
			},
		},
	})

	if len(r.Sections) != 1 || len(r.Sections[0].Findings) != 1 {
		t.Fatalf("sections = %+v, want one malware history finding", r.Sections)
	}
	if r.Sections[0].Title != "Reputation info" {
		t.Fatalf("section title = %q, want Reputation info", r.Sections[0].Title)
	}
	f := r.Sections[0].Findings[0]
	if f.Advisory != "MALWARE-HISTORY" {
		t.Fatalf("Advisory = %q, want MALWARE-HISTORY", f.Advisory)
	}
	if f.Severity != string(domain.SeverityLow) || f.SevSlug != "low" {
		t.Fatalf("Severity = %q/%q, want LOW/low", f.Severity, f.SevSlug)
	}
	if f.RiskType != "malware_history" || f.Title != "ReversingLabs: malware incident history" {
		t.Fatalf("finding = %+v, want explicit malware history risk", f)
	}
}

func TestBuildReportBlockingCount(t *testing.T) {
	r := buildReport("x", "dev", domain.SeverityHigh, &domain.ScanResult{
		Findings: []domain.Finding{
			{Type: domain.FindingTypeMalicious, Severity: domain.SeverityLow},      // always blocks
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh}, // >= HIGH blocks
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow},  // does not block
			{Type: domain.FindingTypeSupplyChainRisk, RiskType: "malware_history", Severity: domain.SeverityHigh},
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

func TestHTMLWriteResponsivePrintAndColorTokenPolicy(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 1,
		Findings: []domain.Finding{{
			Name:       "github.com/acme/" + strings.Repeat("very-long-module-name-", 6),
			Version:    strings.Repeat("abcdef0123456789", 4),
			Ecosystem:  domain.EcosystemGo,
			Type:       domain.FindingTypeVulnerability,
			Severity:   domain.SeverityLow,
			AdvisoryID: "CVE-2026-0001",
			Title:      "long value wrapping policy",
			Source:     "osv",
			Resources:  []domain.ResourceLink{{Label: "long", URL: "https://example.test/" + strings.Repeat("path-segment-", 10)}},
		}},
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"--sev-low:",
		"--success:",
		".pkg{color:",
		"overflow-wrap:anywhere",
		".links a{color:",
		"word-break:break-word",
		".footer{",
		"@media (prefers-color-scheme: light)",
		"@media print",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML CSS missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, ".clean{margin:24px 0;padding:14px 16px;background:#0f2d2a;border:1px solid var(--low);") {
		t.Fatalf("clean state still uses LOW severity token:\n%s", out)
	}
}

func TestHTMLWriteCleanReport(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "empty", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 1,
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings in 1 package") {
		t.Fatal("clean report missing all-clear message")
	}
	if strings.Contains(out, "No findings in 1 packages") {
		t.Fatalf("clean report still uses plural package for 1:\n%s", out)
	}
	if strings.Contains(out, "&#10003;") {
		t.Fatalf("clean report should not render a standalone checkmark icon:\n%s", out)
	}
}

func TestHTMLWriteOperationalStatusIsNotCleanReport(t *testing.T) {
	var buf bytes.Buffer
	if err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 23,
		FeedStatus:      "local advisory data unavailable (run 'packmon db sync' first)",
	}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "No findings in 23 packages") {
		t.Fatal("operational error report must not render a clean all-clear message")
	}
	if !strings.Contains(out, "Scan did not complete") || !strings.Contains(out, "local advisory data unavailable") {
		t.Fatalf("operational status message missing from report:\n%s", out)
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
	if !strings.Contains(out, "Packmon Security Report &middot; 1 package") {
		t.Fatal("empty mode should omit the mode segment from the meta line")
	}
	if !strings.Contains(out, "1 finding &middot; 0 blocking") {
		t.Fatalf("summary badge should use singular finding/blocking labels:\n%s", out)
	}
	if strings.Contains(out, "1 findings") || strings.Contains(out, "1 packages") {
		t.Fatalf("HTML report still uses plural label for singular counts:\n%s", out)
	}
	// Unknown-severity finding uses the f-none card class, which must be styled.
	if !strings.Contains(out, "finding f-none") {
		t.Fatal("unknown-severity finding should use the f-none card class")
	}
	if !strings.Contains(out, ".f-none{") {
		t.Fatal("missing .f-none CSS rule for unknown-severity findings")
	}
}

func TestHTMLHelperRemainingBranches(t *testing.T) {
	t.Parallel()

	if writer := NewHTMLWriter(""); writer.toolVersion != "dev" {
		t.Fatalf("NewHTMLWriter(empty).toolVersion = %q, want dev", writer.toolVersion)
	}
	if got := formatDurationMs(0); got != "" {
		t.Fatalf("formatDurationMs(0) = %q, want empty", got)
	}
	if got := formatDurationMs(999); got != "999ms" {
		t.Fatalf("formatDurationMs(999) = %q, want 999ms", got)
	}
	if got := formatDurationMs(1500); got != "1.5s" {
		t.Fatalf("formatDurationMs(1500) = %q, want 1.5s", got)
	}

	age := 1
	parts := footerParts("v1.2.3", &domain.ScanResult{
		DurationMs:  1500,
		Mode:        "local",
		DBAgeDays:   &age,
		DBStale:     true,
		FeedStatus:  "healthy",
		ScanID:      "scan-123",
		ManualCount: 1,
	})
	for _, want := range []string{"Scan 1.5s", "DB synced 1 day ago (stale)", "feeds: healthy", "packmon v1.2.3", "scan_id scan-123", "1 manual advisory"} {
		if !containsString(parts, want) {
			t.Fatalf("footerParts() = %+v, missing %q", parts, want)
		}
	}
	if parts := footerParts("dev", &domain.ScanResult{FeedStatus: "degraded"}); !containsString(parts, "feeds: degraded") {
		t.Fatalf("footerParts(degraded) = %+v", parts)
	}
	if parts := footerParts("dev", &domain.ScanResult{FeedStatus: "local-db-missing"}); !containsString(parts, "local-db-missing") {
		t.Fatalf("footerParts(custom status) = %+v", parts)
	}

	links, plain := makeLinks(domain.Finding{
		URL: "https://example.test/advisory",
		Resources: []domain.ResourceLink{
			{URL: "https://example.test/empty-label"},
			{Label: "bad", URL: "mailto:security@example.test"},
			{Label: "blank", URL: " "},
		},
	})
	if len(links) != 2 || links[1].Label != "example.test/empty-label" {
		t.Fatalf("links = %+v, want generated label for empty label URL", links)
	}
	if len(plain) != 1 || plain[0] != "mailto:security@example.test" {
		t.Fatalf("plain = %+v, want mailto as plain text", plain)
	}

	if got := advisoryLabel(domain.Finding{Type: domain.FindingTypeSupplyChainRisk}); got != "SUPPLY-CHAIN" {
		t.Fatalf("advisoryLabel(supply chain) = %q", got)
	}
	if got := sevSlug(domain.SeverityLow); got != "low" {
		t.Fatalf("sevSlug(LOW) = %q", got)
	}
}

func TestHTMLWriteFileCreateError(t *testing.T) {
	t.Parallel()

	parentFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	err := NewHTMLWriter("dev").WriteFile(filepath.Join(parentFile, "report.html"), "svc", domain.SeverityCritical, &domain.ScanResult{})
	if err == nil || !strings.Contains(err.Error(), "html: create file") {
		t.Fatalf("WriteFile(parent file) error = %v, want create error", err)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
