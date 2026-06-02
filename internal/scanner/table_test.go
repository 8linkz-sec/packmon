package scanner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestTableWriterWriteShowsLocalStaleWarning(t *testing.T) {
	days := 34
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
		"Local database last synced 34 days ago",
		"Update with: packmon db sync",
		"No findings in 1 packages.",
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

func TestTableWriterShowsSupplyChainRiskDistinctly(t *testing.T) {
	result := &domain.ScanResult{
		Mode:             "remote",
		PackagesScanned:  1,
		FindingsCount:    1,
		FindingsBlocking: true,
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
	for _, expected := range []string{"SUPPLY-CHAIN", "Review pkg", "reversinglabs", "(1 blocking)"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("table output missing %q\n%s", expected, output)
		}
	}
	if strings.Contains(output, "MALWARE") {
		t.Fatalf("supply-chain risk must not be labeled as malware\n%s", output)
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
	for _, expected := range []string{"LIFECYCLE", "Review lifecycle", "endoflife.date", "(1 blocking)"} {
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
