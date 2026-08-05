package scanner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestTableWriterWriteShowsLocalStaleWarning(t *testing.T) {
	days := 1
	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 1,
		FindingsCount:   0,
		DBAgeDays:       &days,
		DBStale:         true,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	for _, expected := range []string{
		"Local database last synced 1 day ago",
		"Update with: packmon db sync",
		"No findings in 1 package.",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("table output missing %q\n%s", expected, output)
		}
	}
}

func TestTableWriterWriteShowsDegradedFeedWarning(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "remote",
		FeedStatus:      "degraded",
		PackagesScanned: 2,
		FindingsCount:   0,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	if !strings.Contains(out.String(), "Server reports degraded feed status") {
		t.Fatalf("expected degraded warning in table output\n%s", out.String())
	}
}

func TestTableWriterWriteShowsLocalSyncedFeedWarning(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "local",
		FeedStatus:      "degraded",
		PackagesScanned: 2,
		FindingsCount:   0,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "local database was last synced from a server reporting degraded feed status") {
		t.Fatalf("expected local synced feed warning in table output\n%s", output)
	}
	if strings.Contains(output, "Server reports degraded feed status") {
		t.Fatalf("local warning should not read like a live remote check\n%s", output)
	}
}

func TestTableWriterOperationalStatusIsNotCleanReport(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "local",
		FeedStatus:      "error",
		ScanError:       "local advisory data unavailable (run 'packmon db sync' first)",
		PackagesScanned: 43,
		FindingsCount:   0,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	if strings.Contains(output, "No findings in 43 packages") {
		t.Fatalf("operational error table must not render a clean all-clear message:\n%s", output)
	}
	if !strings.Contains(output, "Scan did not complete") || !strings.Contains(output, "43 packages") {
		t.Fatalf("expected operational status table message:\n%s", output)
	}
}

func TestTableWriterOperationalStatusUsesSingularPackage(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "local",
		FeedStatus:      "error",
		ScanError:       "local advisory data unavailable",
		PackagesScanned: 1,
		FindingsCount:   0,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "findings were not evaluated for 1 package") {
		t.Fatalf("expected singular package in operational status:\n%s", output)
	}
	if strings.Contains(output, "1 packages") {
		t.Fatalf("operational status still uses plural package for 1:\n%s", output)
	}
}

func TestTableWriterZeroPackagesIsNotAllClear(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 0,
		FindingsCount:   0,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	if strings.Contains(output, "No findings in 0 packages") {
		t.Fatalf("zero-package table must not render a clean all-clear message:\n%s", output)
	}
	if !strings.Contains(output, "No packages were evaluated") {
		t.Fatalf("zero-package table missing distinct warning:\n%s", output)
	}
}

func TestTableWriterSanitizesTerminalControlText(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "remote",
		FeedStatus:      "provider\x1b[2J\n::warning::feed",
		PackagesScanned: 1,
		FindingsCount:   1,
		Findings: []domain.Finding{{
			Name:         "pkg\x1b]8;;https://evil.example\a\n::warning::pkg",
			Version:      "1.0.0\rspoof",
			Ecosystem:    domain.EcosystemNPM,
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.SeverityHigh,
			AdvisoryID:   "GHSA-test\n::error::spoof",
			FixedVersion: "2.0.0\tmasked",
			Source:       "source\x1b[31m",
			URL:          "https://example.test/advisory\x1b[0m",
		}},
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	for _, blocked := range []string{"\x1b", "\a", "\r", "\t", "\n::warning::", "\n::error::"} {
		if strings.Contains(output, blocked) {
			t.Fatalf("table output contains raw terminal control %q:\n%s", blocked, output)
		}
	}
	for _, want := range []string{`\x1B`, `\n::warning::pkg`, `\rspoof`, `\tmasked`} {
		if !strings.Contains(output, want) {
			t.Fatalf("table output missing sanitized text %q:\n%s", want, output)
		}
	}
}

func TestTableWriterShowsSupplyChainRiskDistinctly(t *testing.T) {
	result := &domain.ScanResult{
		Mode:             "remote",
		PackagesScanned:  1,
		FindingsCount:    1,
		FindingsBlocking: false,
		Findings: []domain.Finding{
			{
				Name:      "left-pad",
				Version:   "1.3.0",
				Ecosystem: domain.EcosystemNPM,
				Type:      domain.FindingTypeSupplyChainRisk,
				Severity:  domain.SeverityCritical,
				Title:     "ReversingLabs: package version was removed",
				RiskType:  "removed_package",
				Source:    "reversinglabs",
			},
		},
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	for _, expected := range []string{"SUPPLY-CHAIN", "Review pkg", "reversinglabs", "Found 1 finding (1 blocking) in 1 package"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("table output missing %q\n%s", expected, output)
		}
	}
	if strings.Contains(output, "finding(s)") || strings.Contains(output, "1 packages") {
		t.Fatalf("table output still uses placeholder plural labels:\n%s", output)
	}
	if strings.Contains(output, "MALWARE") {
		t.Fatalf("supply-chain risk must not be labeled as malware\n%s", output)
	}
}

func TestTableWriterShowsMalwareHistoryRiskDistinctly(t *testing.T) {
	result := &domain.ScanResult{
		Mode:             "remote",
		PackagesScanned:  1,
		FindingsCount:    1,
		FindingsBlocking: false,
		Findings: []domain.Finding{
			{
				Name:      "polars-runtime-32",
				Version:   "1.40.1",
				Ecosystem: domain.EcosystemPyPI,
				Type:      domain.FindingTypeSupplyChainRisk,
				Severity:  domain.SeverityHigh,
				Title:     "ReversingLabs: malware incident history",
				RiskType:  domain.RiskTypeMalwareHistory,
				Source:    "reversinglabs",
			},
		},
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	for _, expected := range []string{"LOW", "MALWARE-HISTORY", "Review history", "reversinglabs", "(0 blocking)"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("table output missing %q\n%s", expected, output)
		}
	}
	if strings.Contains(output, "HIGH") {
		t.Fatalf("malware history should render as LOW, not HIGH:\n%s", output)
	}
	if strings.Contains(output, "(1 blocking)") {
		t.Fatalf("malware history should not be rendered as blocking:\n%s", output)
	}
}

func TestTableWriterShowsLifecycleDistinctly(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 1,
		FindingsCount:   1,
		Findings: []domain.Finding{
			{
				Name:      "django",
				Version:   "3.2.25",
				Ecosystem: domain.EcosystemPyPI,
				Type:      domain.FindingTypeLifecycle,
				Severity:  domain.SeverityMedium,
				Title:     "Django 3.2 reaches EOL soon",
				RiskType:  "eol_soon",
				Source:    "endoflife.date",
			},
		},
	}

	var out bytes.Buffer
	if err := NewTableWriter(true, domain.SeverityMedium).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	for _, expected := range []string{"FIXED VERSION", "LIFECYCLE", "Review lifecycle", "endoflife.date", "(1 blocking)"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("table output missing %q\n%s", expected, output)
		}
	}
}

func TestTableWriterCountsOnlyDefaultBlockingSeverity(t *testing.T) {
	findings := make([]domain.Finding, 0, 67)
	for i := 0; i < 11; i++ {
		findings = append(findings, domain.Finding{
			Name:      "critical-pkg",
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
			Type:      domain.FindingTypeVulnerability,
			Severity:  domain.SeverityCritical,
			Source:    "osv",
		})
	}
	for i := 0; i < 56; i++ {
		findings = append(findings, domain.Finding{
			Name:      "high-pkg",
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
			Type:      domain.FindingTypeVulnerability,
			Severity:  domain.SeverityHigh,
			Source:    "osv",
		})
	}

	result := &domain.ScanResult{
		Mode:             "remote",
		PackagesScanned:  67,
		FindingsCount:    len(findings),
		FindingsBlocking: true,
		Findings:         findings,
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "(11 blocking)") {
		t.Fatalf("table output should count only CRITICAL findings as blocking by default\n%s", output)
	}
	if strings.Contains(output, "(67 blocking)") {
		t.Fatalf("table output counted all findings as blocking\n%s", output)
	}
}

func TestTableWriterCountsConfiguredBlockingSeverity(t *testing.T) {
	result := &domain.ScanResult{
		Mode:             "remote",
		PackagesScanned:  4,
		FindingsCount:    4,
		FindingsBlocking: true,
		Findings: []domain.Finding{
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityCritical, Name: "critical", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Source: "osv"},
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh, Name: "high", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Source: "osv"},
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityMedium, Name: "medium", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Source: "osv"},
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow, Name: "low", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Source: "osv"},
		},
	}

	var out bytes.Buffer
	if err := NewTableWriter(true, domain.SeverityHigh).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "(2 blocking)") {
		t.Fatalf("table output should count CRITICAL and HIGH findings as blocking\n%s", output)
	}
}

func TestTableWriterDoesNotReportZeroBlockingForRemotePolicyBlock(t *testing.T) {
	result := &domain.ScanResult{
		Mode:             "remote",
		PackagesScanned:  1,
		FindingsCount:    1,
		FindingsBlocking: true,
		Findings: []domain.Finding{
			{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow, Name: "low", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Source: "osv"},
		},
	}

	var out bytes.Buffer
	if err := NewTableWriter(true, domain.SeverityCritical).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	output := out.String()
	if strings.Contains(output, "(0 blocking)") {
		t.Fatalf("table output contradicted remote blocking decision\n%s", output)
	}
	if !strings.Contains(output, "(1 blocking)") {
		t.Fatalf("table output should show at least one blocking finding for a remote policy block\n%s", output)
	}
}

func TestTableWriterShowsReferenceLinks(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "remote",
		PackagesScanned: 2,
		FindingsCount:   2,
		Findings: []domain.Finding{
			{
				Name: "lodash", Version: "4.17.0", Ecosystem: domain.EcosystemNPM,
				Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh,
				AdvisoryID: "GHSA-xxxx", Title: "Prototype pollution", Source: "ghsa",
				URL: "https://github.com/advisories/GHSA-xxxx",
			},
			{
				Name: "left-pad", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
				Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow,
				AdvisoryID: "CVE-2020-0001", Title: "Example", Source: "osv",
				Resources: []domain.ResourceLink{{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-0001"}},
			},
		},
	}

	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	output := out.String()
	for _, expected := range []string{
		"References:",
		"https://github.com/advisories/GHSA-xxxx",        // from f.URL
		"https://nvd.nist.gov/vuln/detail/CVE-2020-0001", // fallback from Resources
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("table output missing reference %q\n%s", expected, output)
		}
	}
}

func TestTableWriterOmitsReferenceSectionWhenNoLinks(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 1,
		FindingsCount:   1,
		Findings: []domain.Finding{
			{
				Name: "foo", Version: "1.0.0", Ecosystem: domain.EcosystemNPM,
				Type: domain.FindingTypeMalicious, Severity: domain.SeverityCritical,
				Title: "malware", Source: "openssf",
			},
		},
	}
	var out bytes.Buffer
	if err := NewTableWriter(true).Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if strings.Contains(out.String(), "References:") {
		t.Fatalf("unexpected References section when no finding has a link\n%s", out.String())
	}
}
