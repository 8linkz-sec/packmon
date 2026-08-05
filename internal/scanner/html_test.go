package scanner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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

	wantTitles := []string{"Malicious", "Supply-Chain / EOL", "Vulnerabilities", "Lifecycle Findings"}
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

func TestHTMLSectionBuildersComposeSummaryFindingsAndMetadata(t *testing.T) {
	age := 3
	findings := append(sampleFindings(), domain.Finding{
		Name: "mystery", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
		Type: domain.FindingTypeVulnerability, Severity: domain.SeverityUnknown,
		Title: "unknown severity", Source: "osv",
	})
	result := &domain.ScanResult{
		Mode:                  domain.ScanModeLocal,
		PackagesScanned:       142,
		ScannedAt:             time.Date(2026, 5, 30, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60)),
		DurationMs:            1500,
		DBAgeDays:             &age,
		DBStale:               true,
		ScanID:                "scan-123",
		ManualAdvisoriesCount: 1,
		Findings:              findings,
	}

	summary := buildReportSummary("my-service", domain.SeverityHigh, result)
	if summary.Title != "my-service" || summary.Mode != "local" || summary.Packages != 142 {
		t.Fatalf("summary identity = title %q mode %q packages %d", summary.Title, summary.Mode, summary.Packages)
	}
	if summary.ScannedAt != "2026-05-30 10:00 UTC" || summary.Duration != "1.5s" {
		t.Fatalf("summary timing = scanned_at %q duration %q", summary.ScannedAt, summary.Duration)
	}
	if summary.FindingsTotal != len(findings) || summary.Blocking != 3 || summary.Clean {
		t.Fatalf("summary counts = total %d blocking %d clean %v", summary.FindingsTotal, summary.Blocking, summary.Clean)
	}
	if badgeCount(summary.Severity, "Critical") != 3 || badgeCount(summary.Severity, "Medium") != 2 || badgeCount(summary.Severity, "Unknown") != 1 {
		t.Fatalf("severity badges = %+v", summary.Severity)
	}
	if len(summary.Warnings) != 1 || !strings.Contains(summary.Warnings[0], "Local database last synced 3 days ago") {
		t.Fatalf("warnings = %+v, want stale local DB warning", summary.Warnings)
	}

	sections := buildReportSections(result.Findings)
	wantTitles := []string{"Malicious", "Supply-Chain / EOL", "Vulnerabilities", "Lifecycle Findings"}
	if len(sections) != len(wantTitles) {
		t.Fatalf("sections = %d, want %d", len(sections), len(wantTitles))
	}
	for i, want := range wantTitles {
		if sections[i].Title != want {
			t.Fatalf("section[%d] = %q, want %q", i, sections[i].Title, want)
		}
	}
	vuln := sections[2].Findings
	if len(vuln) != 3 || vuln[0].Severity != "CRITICAL" || vuln[2].SevSlug != "none" {
		t.Fatalf("vulnerability section = %+v, want critical first and unknown last", vuln)
	}

	metadata := buildReportMetadata("v1.2.3", result)
	for _, want := range []string{"Scan 1.5s", "DB synced 3 days ago (stale)", "packmon v1.2.3", "scan_id scan-123", "1 manual advisory"} {
		if !containsString(metadata, want) {
			t.Fatalf("metadata = %+v, missing %q", metadata, want)
		}
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

func TestHTMLReportWarningsUseSharedReportWarnings(t *testing.T) {
	t.Parallel()

	result := &domain.ScanResult{
		Mode:            domain.ScanModeLocal,
		FeedStatus:      "degraded",
		PackagesScanned: 1,
		DBStale:         true,
		ParseErrors:     []string{"bad lockfile"},
	}
	if got, want := htmlReportWarnings(result), ReportWarnings(result); !reflect.DeepEqual(got, want) {
		t.Fatalf("htmlReportWarnings() = %#v, want shared ReportWarnings %#v", got, want)
	}
}

func TestHTMLReportWarningsCollapseLargeWarningStacks(t *testing.T) {
	t.Parallel()

	var parseErrors []string
	for i := 0; i < maxHTMLReportWarnings+2; i++ {
		parseErrors = append(parseErrors, fmt.Sprintf("bad-lock-%d", i))
	}
	got := htmlReportWarnings(&domain.ScanResult{
		PackagesScanned: 1,
		ParseErrors:     parseErrors,
	})
	if len(got) != maxHTMLReportWarnings+1 {
		t.Fatalf("warnings = %#v, want %d visible warnings plus summary", got, maxHTMLReportWarnings)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "bad-lock-0") || strings.Contains(joined, "bad-lock-6") {
		t.Fatalf("warnings should keep first entries and omit overflow:\n%#v", got)
	}
	if !strings.Contains(got[len(got)-1], "additional warnings were omitted") {
		t.Fatalf("last warning = %q, want overflow summary", got[len(got)-1])
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

func TestHTMLWriteExposesMachineReadableTimingHooks(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		ScannedAt:       time.Date(2026, 5, 30, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60)),
		DurationMs:      1500,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		`<html lang="en" dir="auto">`,
		`<time datetime="2026-05-30T10:00:00Z" data-report-time="scanned-at">2026-05-30 10:00 UTC</time>`,
		`<span data-duration-ms="1500" data-report-duration="scan">1.5s</span>`,
		`script-src 'unsafe-inline'`,
		`Intl.DateTimeFormat`,
		`Intl.NumberFormat`,
		`querySelectorAll('time[data-report-time][datetime]')`,
		`querySelectorAll('[data-report-duration][data-duration-ms]')`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML timing hooks missing %q:\n%s", want, out)
		}
	}
}

func TestHTMLTemplateUsesMessageDataForStaticReportLabels(t *testing.T) {
	for _, want := range []string{
		`{{.Messages.ReportType}}`,
		`{{.Messages.ModeSuffix}}`,
		`{{.Messages.StatusPrefix}}`,
		`{{.Messages.NoFindingsPrefix}}`,
		`{{.Messages.JumpTo}}`,
		`{{$.Messages.RiskLabel}}`,
		`{{$.Messages.FixedVersionLabel}}`,
		`{{$.Messages.SourceLabel}}`,
	} {
		if !strings.Contains(htmlTemplate, want) {
			t.Fatalf("HTML template missing message field %q", want)
		}
	}
	for _, scattered := range []string{
		"Packmon Security Report{{if .Mode}}",
		"Scan did not complete:",
		"No findings in {{count .Packages",
		">Jump to<",
		"Risk: {{if .RiskLabel}}",
		"Fixed Version: <bdi",
		"Source: <bdi",
	} {
		if strings.Contains(htmlTemplate, scattered) {
			t.Fatalf("HTML template still has scattered label %q", scattered)
		}
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
				RiskType: domain.RiskTypeMalwareHistory, Title: "ReversingLabs: malware incident history",
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
	if f.RiskType != domain.RiskTypeMalwareHistory || f.Title != "ReversingLabs: malware incident history" {
		t.Fatalf("finding = %+v, want explicit malware history risk", f)
	}
}

func TestHTMLWriteExplainsKnownRiskTypes(t *testing.T) {
	cases := []struct {
		riskType    string
		label       string
		description string
		findingType domain.FindingType
	}{
		{
			riskType:    "malware",
			label:       "Malware",
			description: "Confirmed malicious package or version.",
			findingType: domain.FindingTypeMalicious,
		},
		{
			riskType:    "removed_package",
			label:       "Removed package",
			description: "Package was removed from its registry and should be reviewed before use.",
			findingType: domain.FindingTypeSupplyChainRisk,
		},
		{
			riskType:    domain.RiskTypeMalwareHistory,
			label:       "Malware history",
			description: "Historical malware incident or reputation context; review before relying on it.",
			findingType: domain.FindingTypeSupplyChainRisk,
		},
		{
			riskType:    "eol",
			label:       "End of life",
			description: "Release line has reached end of life.",
			findingType: domain.FindingTypeLifecycle,
		},
		{
			riskType:    "eol_soon",
			label:       "End of life soon",
			description: "Release line is approaching end of life.",
			findingType: domain.FindingTypeLifecycle,
		},
		{
			riskType:    "security_support_only",
			label:       "Security support only",
			description: "Release line receives security fixes only; general support has ended.",
			findingType: domain.FindingTypeLifecycle,
		},
		{
			riskType:    "typosquatting",
			label:       "Typosquatting",
			description: "Package name appears intended to impersonate a known package.",
			findingType: domain.FindingTypeSupplyChainRisk,
		},
		{
			riskType:    "supply_chain",
			label:       "Supply-chain risk",
			description: "General package trust or supply-chain compromise signal.",
			findingType: domain.FindingTypeSupplyChainRisk,
		},
	}

	findings := make([]domain.Finding, 0, len(cases))
	for _, tc := range cases {
		findings = append(findings, domain.Finding{
			Name:      "pkg-" + strings.ReplaceAll(tc.label, " ", "-"),
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
			Type:      tc.findingType,
			Severity:  domain.SeverityHigh,
			RiskType:  tc.riskType,
			Title:     tc.label + " finding",
			Source:    "test",
		})
	}

	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		Findings:        findings,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()

	for _, tc := range cases {
		if !strings.Contains(out, "Risk: "+tc.label) {
			t.Fatalf("report does not label risk type %q:\n%s", tc.riskType, out)
		}
		if !strings.Contains(out, tc.description) {
			t.Fatalf("report does not describe risk type %q:\n%s", tc.riskType, out)
		}
		if strings.Contains(out, "("+tc.riskType+")") {
			t.Fatalf("report renders raw risk identifier %q:\n%s", tc.riskType, out)
		}
	}
}

func TestBuildReportBlockingCount(t *testing.T) {
	r := buildReport("x", "dev", domain.SeverityHigh, &domain.ScanResult{
		Findings: []domain.Finding{
			{Type: domain.FindingTypeMalicious, Severity: domain.SeverityLow},      // always blocks
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh}, // >= HIGH blocks
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow},  // does not block
			{Type: domain.FindingTypeSupplyChainRisk, RiskType: domain.RiskTypeMalwareHistory, Severity: domain.SeverityHigh},
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
	if !strings.Contains(out, `<h1><bdi dir="auto">my-service</bdi></h1>`) {
		t.Fatal("missing H1 repo title")
	}
	assertHTMLUsesRemTypography(t, out)
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

func TestHTMLWriteAddsSectionNavigationAndAnchors(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 5,
		Findings:        sampleFindings(),
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		`<nav class="report-nav" aria-label="Finding sections">`,
		`<span class="nav-label">Jump to</span>`,
		`<a href="#section-malicious">Malicious <span class="count">(1)</span></a>`,
		`<a href="#section-supply-chain-eol">Supply-Chain / EOL <span class="count">(1)</span></a>`,
		`<a href="#section-vulnerabilities">Vulnerabilities <span class="count">(2)</span></a>`,
		`<a href="#section-lifecycle-findings">Lifecycle Findings <span class="count">(1)</span></a>`,
		`<section id="section-malicious" class="report-section" aria-labelledby="section-malicious-heading">`,
		`<h2 id="section-malicious-heading" class="s-mal">Malicious <span class="count">(1)</span></h2>`,
		`<section id="section-vulnerabilities" class="report-section" aria-labelledby="section-vulnerabilities-heading">`,
		`<h2 id="section-vulnerabilities-heading" class="s-vuln">Vulnerabilities <span class="count">(2)</span></h2>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing navigable section structure %q:\n%s", want, out)
		}
	}
	if strings.Index(out, `<nav class="report-nav"`) > strings.Index(out, `<section id="section-malicious"`) {
		t.Fatalf("section navigation should render before finding sections:\n%s", out)
	}
	if strings.Contains(out, `<script src=`) {
		t.Fatalf("standard scan HTML report must not load external scripts:\n%s", out)
	}
	if got := strings.Count(out, `<script>`); got != 1 {
		t.Fatalf("standard scan HTML should include exactly one self-contained locale script, got %d:\n%s", got, out)
	}
}

func TestHTMLWriteFindingsRenderCollapsedByDefault(t *testing.T) {
	var findings []domain.Finding
	for i := 0; i < 4; i++ {
		findings = append(findings, domain.Finding{
			Name:       fmt.Sprintf("pkg-%d", i),
			Version:    "1.0.0",
			Ecosystem:  domain.EcosystemNPM,
			Type:       domain.FindingTypeVulnerability,
			Severity:   domain.SeverityHigh,
			AdvisoryID: fmt.Sprintf("GHSA-test-%d", i),
			Title:      "expanded detail",
			Source:     "osv",
		})
	}

	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityHigh, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 4,
		Findings:        findings,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	if got := strings.Count(out, `<details class="finding`); got != len(findings) {
		t.Fatalf("collapsed finding details = %d, want %d\n%s", got, len(findings), out)
	}
	if strings.Contains(out, `<details class="finding f-high" open`) {
		t.Fatalf("findings should be collapsed by default:\n%s", out)
	}
	for _, want := range []string{
		`<summary><span class="sev sev-high">HIGH</span>`,
		`<span class="pkg"><bdi dir="auto">pkg-0@1.0.0</bdi></span>`,
		`<div class="finding-body">`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing collapsed finding structure %q:\n%s", want, out)
		}
	}
}

func TestHTMLWriteIncludesStandaloneCSPMeta(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode: "local", PackagesScanned: 1,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	want := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">`
	if !strings.Contains(out, want) {
		t.Fatalf("HTML report missing CSP meta %q:\n%s", want, out)
	}
	if strings.Index(out, want) > strings.Index(out, "<style>") {
		t.Fatalf("CSP meta should appear before inline styles:\n%s", out)
	}
}

func TestHTMLWriteUsesMainLandmark(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode: "remote", PackagesScanned: 1,
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	assertHTMLUsesMainWrapLandmark(t, buf.String())
}

func TestHTMLWriteExternalLinkArrowNotInAccessibleText(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		Findings: []domain.Finding{{
			Name: "pkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh,
			Title:     "advisory with source link",
			Source:    "osv",
			Resources: []domain.ResourceLink{{Label: "OSV advisory", URL: "https://osv.dev/vuln/TEST-1"}},
		}},
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	want := `<a class="external-link" href="https://osv.dev/vuln/TEST-1"><bdi dir="auto">OSV advisory</bdi><svg class="external-link-icon" aria-hidden="true" viewBox="0 0 16 16" focusable="false">`
	if !strings.Contains(out, want) {
		t.Fatalf("source link should render a decorative SVG icon with aria-hidden, missing %q:\n%s", want, out)
	}
	for _, bad := range []string{
		`&#8599;`,
		"↗",
		`<span class="external-link-icon"`,
	} {
		if strings.Contains(out, bad) {
			t.Fatalf("source link exposes decorative icon as raw text/span markup %q:\n%s", bad, out)
		}
	}
}

func TestHTMLWriteSourceLinksUseTouchFriendlyStyles(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		Findings: []domain.Finding{{
			Name: "pkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh,
			Title:     "advisory with source link",
			Source:    "osv",
			Resources: []domain.ResourceLink{{Label: "OSV advisory", URL: "https://osv.dev/vuln/TEST-1"}},
		}},
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		".links a{display:inline-flex;align-items:center;gap:var(--space-1);",
		"min-block-size:var(--space-8)",
		"padding:var(--space-1) var(--space-2)",
		"margin-inline:calc(-1 * var(--space-2))",
		"border-radius:var(--radius-sm)",
		".links a:focus-visible{outline:var(--border-focus) solid var(--link);outline-offset:var(--space-1);}",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML source-link CSS missing touch-friendly rule %q:\n%s", want, out)
		}
	}
}

func TestHTMLWritePrintsExternalHrefsAndIsolatesDynamicValues(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc-\u05d0", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		Findings: []domain.Finding{{
			Name:         "pkg-\u05d0",
			Version:      "1.0.0-\u05d1",
			Ecosystem:    domain.EcosystemNPM,
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.SeverityHigh,
			AdvisoryID:   "GHSA-test-\u05d2",
			Title:        "mixed bidi advisory \u05d3",
			FixedVersion: "2.0.0-\u05d4",
			Source:       "osv-\u05d5",
			Resources:    []domain.ResourceLink{{Label: "OSV advisory", URL: "https://osv.dev/vuln/GHSA-test"}},
		}},
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`<h1><bdi dir="auto">svc-` + "\u05d0" + `</bdi></h1>`,
		`<span class="pkg"><bdi dir="auto">pkg-` + "\u05d0" + `@1.0.0-` + "\u05d1" + `</bdi></span>`,
		`<bdi dir="auto">GHSA-test-` + "\u05d2" + `</bdi>`,
		`<bdi dir="auto">mixed bidi advisory ` + "\u05d3" + `</bdi>`,
		`Fixed Version: <bdi dir="auto">2.0.0-` + "\u05d4" + `</bdi>`,
		`Source: <bdi dir="auto">osv-` + "\u05d5" + `</bdi>`,
		`a[href]::after{content:" (" attr(href) ")";`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing bidi/print contract %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{`<html lang="en" dir="ltr">`, "border-left", "text-align:left"} {
		if strings.Contains(out, bad) {
			t.Fatalf("HTML CSS still uses physical left-side rule %q:\n%s", bad, out)
		}
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
		`<html lang="en" dir="auto">`,
		`<meta name="color-scheme" content="dark light">`,
		":root{color-scheme:dark;",
		"--sev-low:",
		"--success:",
		"--warning-bg:",
		"--status-bg:",
		"--sev-fg:",
		"--sev-none-bg:",
		"--sev-none-fg:",
		"--space-1:4px",
		"--space-2:8px",
		"--space-3:12px",
		"--space-4:16px",
		"--space-6:24px",
		"--space-8:32px",
		"--space-12:48px",
		"--font-xs:0.75rem",
		"--font-sm:0.8125rem",
		"--font-base:0.875rem",
		"--font-md:0.9375rem",
		"--font-lg:1rem",
		"--font-xl:1.375rem",
		".pkg{color:",
		"overflow-wrap:anywhere",
		".links a{display:inline-flex;",
		"word-break:break-word",
		".footer{",
		".sev{border-radius:var(--radius-sm);padding:var(--space-1) var(--space-2);font-size:var(--font-xs);font-weight:700;color:var(--sev-fg);",
		".sev-none{background:var(--sev-none-bg);color:var(--sev-none-fg);}",
		".warning{margin:var(--space-4) 0;padding:var(--space-4);background:var(--warning-bg);",
		".status{margin:var(--space-6) 0;padding:var(--space-4);background:var(--status-bg);",
		"@media (prefers-color-scheme: light)",
		"@media (prefers-color-scheme: light){:root{color-scheme:light;",
		"--warning-bg:#fff8c5;",
		"--status-bg:#ffebe9;--sev-fg:#ffffff;",
		"@media (prefers-contrast: more)",
		"@media (forced-colors: active)",
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

func TestHTMLWriteUsesSelfContainedSpacingAndTypeScale(t *testing.T) {
	var buf bytes.Buffer
	err := NewHTMLWriter("dev").Write(&buf, "svc", domain.SeverityCritical, &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		Findings: []domain.Finding{{
			Name: "pkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
			Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh,
			Title: "scaled report chrome", Source: "osv",
		}},
	})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"--space-1:4px",
		"--space-2:8px",
		"--space-3:12px",
		"--space-4:16px",
		"--space-6:24px",
		"--space-8:32px",
		"--space-12:48px",
		"--font-xs:0.75rem",
		"--font-sm:0.8125rem",
		"--font-base:0.875rem",
		"--font-md:0.9375rem",
		"--font-lg:1rem",
		"--font-xl:1.375rem",
		"body{margin:0;background:var(--bg);color:var(--fg);font-family:",
		"font-size:var(--font-base);line-height:1.6;",
		".wrap{max-width:920px;margin:0 auto;padding:var(--space-8) var(--space-6) var(--space-12);}",
		".badge{border-radius:var(--radius-md);padding:var(--space-1) var(--space-3);font-size:var(--font-sm);",
		".finding{margin:var(--space-3) 0;padding:var(--space-3) var(--space-4);",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML report missing spacing/type scale rule %q:\n%s", want, out)
		}
	}

	for _, bad := range []string{
		"padding:3px 11px",
		"padding:1px 7px",
		"padding:3px 6px",
		"padding-bottom:5px",
		"margin:22px 0 0",
		"margin:18px 0 24px",
		"border-inline-start:3px",
		"border-radius:5px",
		"outline-offset:3px",
		"padding:14px 16px",
		"margin-top:28px",
	} {
		if strings.Contains(out, bad) {
			t.Fatalf("HTML report still uses off-scale spacing %q:\n%s", bad, out)
		}
	}
	if match := regexp.MustCompile(`font-size:\s*[0-9]+px`).FindString(out); match != "" {
		t.Fatalf("HTML report uses fixed pixel font size %q:\n%s", match, out)
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
		FeedStatus:      "error",
		ScanError:       "local advisory data unavailable (run 'packmon db sync' first)",
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
	if !strings.Contains(buf.String(), `<h1><bdi dir="auto">Packmon Security Report</bdi></h1>`) {
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
		DurationMs:            1500,
		Mode:                  "local",
		DBAgeDays:             &age,
		DBStale:               true,
		FeedStatus:            "healthy",
		ScanID:                "scan-123",
		ManualAdvisoriesCount: 1,
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

func badgeCount(badges []htmlBadge, label string) int {
	for _, badge := range badges {
		if badge.Label == label {
			return badge.Count
		}
	}
	return 0
}

func assertHTMLUsesRemTypography(t *testing.T, out string) {
	t.Helper()

	for _, want := range []string{
		"--font-xl:1.375rem",
		"--font-lg:1rem",
		"--font-md:0.9375rem",
		"--font-sm:0.8125rem",
		"--font-xs:0.75rem",
		"font-size:var(--font-base)",
		"font-size:var(--font-xl)",
		"font-size:var(--font-lg)",
		"font-size:var(--font-md)",
		"font-size:var(--font-sm)",
		"font-size:var(--font-xs)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML report missing rem typography %q:\n%s", want, out)
		}
	}
	if match := regexp.MustCompile(`font-size:\s*[0-9]+px`).FindString(out); match != "" {
		t.Fatalf("HTML report uses fixed pixel font size %q:\n%s", match, out)
	}
}

func assertHTMLUsesMainWrapLandmark(t *testing.T, out string) {
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
