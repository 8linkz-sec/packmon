package scanner

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func sampleReportResult() *domain.ScanResult {
	return &domain.ScanResult{
		ScanID:          "scan-1",
		PackagesScanned: 2,
		FindingsCount:   3,
		DurationMs:      1234,
		Findings: []domain.Finding{
			{
				Name:         "lodash",
				Version:      "1.0.0",
				Ecosystem:    domain.EcosystemNPM,
				Type:         domain.FindingTypeVulnerability,
				Severity:     domain.SeverityHigh,
				AdvisoryID:   "GHSA-test-1234",
				Title:        "Prototype pollution",
				FixedVersion: "1.2.3",
				URL:          "https://github.com/advisories/GHSA-test-1234",
				Source:       "osv",
			},
			{
				Name:      "evil",
				Version:   "9.9.9",
				Ecosystem: domain.EcosystemPyPI,
				Type:      domain.FindingTypeMalicious,
				Severity:  domain.SeverityCritical,
				Title:     "Known malicious package",
				RiskType:  "malware",
				Source:    "openssf",
			},
			{
				Name:      "removed",
				Version:   "0.1.0",
				Ecosystem: domain.EcosystemNPM,
				Type:      domain.FindingTypeSupplyChainRisk,
				Severity:  domain.SeverityLow,
				Title:     "Removed package version",
				RiskType:  "removed_package",
				Source:    "reversinglabs",
			},
		},
	}
}

type failingReportWriter struct{}

func (failingReportWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestReportWritersPropagateWriteErrors(t *testing.T) {
	t.Parallel()

	if err := NewSARIFWriter("dev").Write(failingReportWriter{}, sampleReportResult()); err == nil {
		t.Fatal("SARIF Write() error = nil, want writer error")
	}
	if err := NewJUnitWriter().Write(failingReportWriter{}, sampleReportResult()); err == nil {
		t.Fatal("JUnit Write() error = nil, want writer error")
	}
}

func TestSARIFWriterSerializesFindingsAndRules(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	writer := NewSARIFWriter("1.2.3")
	if err := writer.Write(&out, sampleReportResult()); err != nil {
		t.Fatalf("SARIF Write() error = %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(out.Bytes(), &log); err != nil {
		t.Fatalf("unmarshal SARIF: %v\n%s", err, out.String())
	}
	if log.Version != "2.1.0" {
		t.Fatalf("SARIF version = %q, want 2.1.0", log.Version)
	}
	if got := log.Runs[0].Tool.Driver.Version; got != "1.2.3" {
		t.Fatalf("tool version = %q, want 1.2.3", got)
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(log.Runs[0].Tool.Driver.Rules))
	}
	if len(log.Runs[0].Results) != 3 {
		t.Fatalf("results = %d, want 3", len(log.Runs[0].Results))
	}
	if got := log.Runs[0].Results[0].RuleID; got != "GHSA-test-1234" {
		t.Fatalf("first rule id = %q, want advisory id", got)
	}
	if got := log.Runs[0].Results[1].Level; got != "error" {
		t.Fatalf("malicious SARIF level = %q, want error", got)
	}
	if !strings.Contains(log.Runs[0].Results[0].Message.Text, "[fix: 1.2.3]") {
		t.Fatalf("SARIF result missing fixed version: %#v", log.Runs[0].Results[0])
	}
}

func TestSARIFWriterDefaultsVersionAndWritesFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "result.sarif")
	if err := NewSARIFWriter("").WriteFile(path, sampleReportResult()); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test reads a generated temp-file path.
	if err != nil {
		t.Fatalf("read SARIF output: %v", err)
	}
	if !bytes.Contains(data, []byte(`"version": "dev"`)) {
		t.Fatalf("SARIF output missing default dev version:\n%s", data)
	}
	if err := NewSARIFWriter("dev").WriteFile(filepath.Join(t.TempDir(), "missing", "out.sarif"), sampleReportResult()); err == nil {
		t.Fatal("WriteFile to missing directory error = nil, want error")
	}
}

func TestSARIFLevelsCoverSeverityMapping(t *testing.T) {
	t.Parallel()

	writer := NewSARIFWriter("dev")
	tests := map[domain.Severity]string{
		domain.SeverityCritical: "error",
		domain.SeverityHigh:     "error",
		domain.SeverityMedium:   "warning",
		domain.SeverityLow:      "note",
		domain.SeverityUnknown:  "note",
	}
	for severity, want := range tests {
		got := writer.sarifLevel(domain.Finding{
			Type:     domain.FindingTypeVulnerability,
			Severity: severity,
		})
		if got != want {
			t.Fatalf("sarifLevel(%s) = %q, want %q", severity, got, want)
		}
	}
	if got := writer.ruleID(domain.Finding{}); got != "unknown" {
		t.Fatalf("ruleID(empty) = %q, want unknown", got)
	}
}

func TestSARIFLifecycleRuleIDFallback(t *testing.T) {
	t.Parallel()

	writer := NewSARIFWriter("dev")
	got := writer.ruleID(domain.Finding{
		Name:      "django",
		Ecosystem: domain.EcosystemPyPI,
		Type:      domain.FindingTypeLifecycle,
		RiskType:  "eol_soon",
	})
	if got != "lifecycle:pypi:django" {
		t.Fatalf("lifecycle ruleID = %q, want lifecycle:pypi:django", got)
	}
}

func TestJUnitWriterSerializesPassingAndFailingScans(t *testing.T) {
	t.Parallel()

	var clean bytes.Buffer
	cleanResult := &domain.ScanResult{PackagesScanned: 12, DurationMs: 2500}
	if err := NewJUnitWriter().Write(&clean, cleanResult); err != nil {
		t.Fatalf("JUnit Write(clean) error = %v", err)
	}
	if !strings.HasPrefix(clean.String(), xml.Header) {
		t.Fatalf("JUnit output missing XML header:\n%s", clean.String())
	}
	var cleanSuites junitTestsuites
	if err := xml.Unmarshal(clean.Bytes(), &cleanSuites); err != nil {
		t.Fatalf("unmarshal clean JUnit: %v", err)
	}
	if cleanSuites.Tests != 1 || cleanSuites.Failures != 0 {
		t.Fatalf("clean suites = tests %d failures %d, want 1/0", cleanSuites.Tests, cleanSuites.Failures)
	}
	if got := cleanSuites.Testsuites[0].Cases[0].Name; got != "scan (12 packages)" {
		t.Fatalf("clean testcase name = %q", got)
	}

	var failing bytes.Buffer
	if err := NewJUnitWriter().Write(&failing, sampleReportResult()); err != nil {
		t.Fatalf("JUnit Write(failing) error = %v", err)
	}
	var failingSuites junitTestsuites
	if err := xml.Unmarshal(failing.Bytes(), &failingSuites); err != nil {
		t.Fatalf("unmarshal failing JUnit: %v", err)
	}
	if failingSuites.Tests != 3 || failingSuites.Failures != 3 {
		t.Fatalf("failing suites = tests %d failures %d, want 3/3", failingSuites.Tests, failingSuites.Failures)
	}
	if got := failingSuites.Testsuites[0].Cases[0].Failure.Type; got != "vulnerability" {
		t.Fatalf("first failure type = %q, want vulnerability", got)
	}
	if got := failingSuites.Testsuites[0].Cases[1].Failure.Type; got != "malicious" {
		t.Fatalf("second failure type = %q, want malicious", got)
	}
	if got := failingSuites.Testsuites[0].Cases[2].Failure.Type; got != "supply_chain_risk" {
		t.Fatalf("third failure type = %q, want supply_chain_risk", got)
	}
	if !strings.Contains(failingSuites.Testsuites[0].Cases[0].Failure.Body, "Fixed Version: 1.2.3") {
		t.Fatalf("failure body missing fixed version: %q", failingSuites.Testsuites[0].Cases[0].Failure.Body)
	}
}

func TestJUnitWriterLabelsLifecycleFindings(t *testing.T) {
	t.Parallel()

	result := &domain.ScanResult{
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
	if err := NewJUnitWriter().Write(&out, result); err != nil {
		t.Fatalf("JUnit Write() error = %v", err)
	}
	var suites junitTestsuites
	if err := xml.Unmarshal(out.Bytes(), &suites); err != nil {
		t.Fatalf("unmarshal JUnit: %v", err)
	}
	failure := suites.Testsuites[0].Cases[0].Failure
	if failure.Type != "lifecycle" {
		t.Fatalf("failure type = %q, want lifecycle", failure.Type)
	}
	if !strings.Contains(failure.Body, "Risk Type: eol_soon") || !strings.Contains(failure.Body, "Source: endoflife.date") {
		t.Fatalf("failure body missing lifecycle context: %q", failure.Body)
	}
}

func TestJUnitWriterWritesFileAndReportsCreateErrors(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "junit.xml")
	if err := NewJUnitWriter().WriteFile(path, sampleReportResult()); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test reads a generated temp-file path.
	if err != nil {
		t.Fatalf("read JUnit output: %v", err)
	}
	if !bytes.Contains(data, []byte("<testsuites")) {
		t.Fatalf("JUnit file missing testsuites:\n%s", data)
	}
	if err := NewJUnitWriter().WriteFile(filepath.Join(t.TempDir(), "missing", "junit.xml"), sampleReportResult()); err == nil {
		t.Fatal("WriteFile to missing directory error = nil, want error")
	}
}
