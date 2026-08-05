package scanner

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestJUnitSurfacesParseErrorsAsErroredSuite(t *testing.T) {
	result := &domain.ScanResult{
		Mode:             "local",
		PackagesScanned:  3,
		FindingsCount:    1,
		FindingsBlocking: true,
		BlockThreshold:   domain.SeverityHigh,
		Findings: []domain.Finding{
			{
				Name: "lodash", Version: "4.17.0", Ecosystem: domain.EcosystemNPM,
				Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh,
				AdvisoryID: "GHSA-xxxx", Title: "Prototype pollution", Source: "ghsa",
			},
		},
		ParseErrors: []string{"requirements.txt: malformed line 5"},
	}

	var out bytes.Buffer
	if err := NewJUnitWriter().Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var suites struct {
		XMLName  xml.Name `xml:"testsuites"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
		Errors   int      `xml:"errors,attr"`
		Suites   []struct {
			Name   string `xml:"name,attr"`
			Errors int    `xml:"errors,attr"`
			Cases  []struct {
				Name  string `xml:"name,attr"`
				Error *struct {
					Type string `xml:"type,attr"`
					Body string `xml:",chardata"`
				} `xml:"error"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(out.Bytes(), &suites); err != nil {
		t.Fatalf("invalid JUnit XML: %v\n%s", err, out.String())
	}

	if suites.Errors != 1 {
		t.Fatalf("expected top-level errors=1, got %d", suites.Errors)
	}
	if suites.Failures != 1 {
		t.Fatalf("expected top-level failures=1 (the finding), got %d", suites.Failures)
	}

	var parseSuite *struct {
		Name   string `xml:"name,attr"`
		Errors int    `xml:"errors,attr"`
		Cases  []struct {
			Name  string `xml:"name,attr"`
			Error *struct {
				Type string `xml:"type,attr"`
				Body string `xml:",chardata"`
			} `xml:"error"`
		} `xml:"testcase"`
	}
	for i := range suites.Suites {
		if suites.Suites[i].Name == "packmon.parse-errors" {
			parseSuite = &suites.Suites[i]
		}
	}
	if parseSuite == nil {
		t.Fatalf("missing packmon.parse-errors suite\n%s", out.String())
	}
	if len(parseSuite.Cases) != 1 || parseSuite.Cases[0].Error == nil {
		t.Fatalf("expected one errored testcase, got %+v", parseSuite.Cases)
	}
	if parseSuite.Cases[0].Error.Type != "parse_error" {
		t.Fatalf("expected error type parse_error, got %q", parseSuite.Cases[0].Error.Type)
	}
	if !strings.Contains(parseSuite.Cases[0].Error.Body, "requirements.txt") {
		t.Fatalf("error body missing parse error text: %q", parseSuite.Cases[0].Error.Body)
	}
}

func TestJUnitCapsParseErrorCasesWithSummary(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 1,
		ParseErrors:     numberedScannerParseDiagnostics(23),
	}

	var out bytes.Buffer
	if err := NewJUnitWriter().Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var suites junitTestsuites
	if err := xml.Unmarshal(out.Bytes(), &suites); err != nil {
		t.Fatalf("invalid JUnit XML: %v\n%s", err, out.String())
	}
	if suites.Tests != 22 {
		t.Fatalf("top-level tests = %d, want 22\n%s", suites.Tests, out.String())
	}
	if suites.Errors != 21 {
		t.Fatalf("top-level errors = %d, want 21\n%s", suites.Errors, out.String())
	}
	var parseSuite *junitTestsuite
	for i := range suites.Testsuites {
		if suites.Testsuites[i].Name == "packmon.parse-errors" {
			parseSuite = &suites.Testsuites[i]
		}
	}
	if parseSuite == nil {
		t.Fatalf("missing packmon.parse-errors suite\n%s", out.String())
	}
	if parseSuite.Tests != 21 || parseSuite.Errors != 21 || len(parseSuite.Cases) != 21 {
		t.Fatalf("parse suite = %+v, want 21 bounded cases", parseSuite)
	}
	if !strings.Contains(parseSuite.Cases[19].Error.Body, "diagnostic-20") {
		t.Fatalf("last visible parse case = %q, want diagnostic-20", parseSuite.Cases[19].Error.Body)
	}
	for _, tc := range parseSuite.Cases {
		if tc.Error == nil {
			t.Fatalf("parse testcase missing error: %+v", tc)
		}
		if strings.Contains(tc.Error.Body, "diagnostic-21") || strings.Contains(tc.Error.Body, "diagnostic-23") {
			t.Fatalf("JUnit included omitted diagnostic: %+v", tc)
		}
	}
	summary := parseSuite.Cases[len(parseSuite.Cases)-1]
	if summary.Name != "parse diagnostics omitted" {
		t.Fatalf("summary testcase name = %q, want parse diagnostics omitted", summary.Name)
	}
	if !strings.Contains(summary.Error.Body, "3 additional parse diagnostics omitted; see JSON parse_errors for full detail") {
		t.Fatalf("summary testcase body = %q, want omitted summary", summary.Error.Body)
	}
	if len(result.ParseErrors) != 23 || result.ParseErrors[22] != "diagnostic-23" {
		t.Fatalf("JUnit write mutated raw parse errors: %#v", result.ParseErrors)
	}
}

func TestJUnitSurfacesScanWarningsAsErroredSuite(t *testing.T) {
	dbAgeDays := 8
	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 7,
		FeedStatus:      "degraded",
		DBAgeDays:       &dbAgeDays,
		DBStale:         true,
	}

	var out bytes.Buffer
	if err := NewJUnitWriter().Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var suites struct {
		XMLName  xml.Name `xml:"testsuites"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
		Errors   int      `xml:"errors,attr"`
		Suites   []struct {
			Name   string `xml:"name,attr"`
			Errors int    `xml:"errors,attr"`
			Cases  []struct {
				Name  string `xml:"name,attr"`
				Error *struct {
					Type string `xml:"type,attr"`
					Body string `xml:",chardata"`
				} `xml:"error"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(out.Bytes(), &suites); err != nil {
		t.Fatalf("invalid JUnit XML: %v\n%s", err, out.String())
	}

	if suites.Tests != 3 {
		t.Fatalf("expected top-level tests=3, got %d", suites.Tests)
	}
	if suites.Errors != 2 {
		t.Fatalf("expected top-level errors=2, got %d", suites.Errors)
	}
	if suites.Failures != 0 {
		t.Fatalf("expected no finding failures, got %d", suites.Failures)
	}

	var warningSuite *struct {
		Name   string `xml:"name,attr"`
		Errors int    `xml:"errors,attr"`
		Cases  []struct {
			Name  string `xml:"name,attr"`
			Error *struct {
				Type string `xml:"type,attr"`
				Body string `xml:",chardata"`
			} `xml:"error"`
		} `xml:"testcase"`
	}
	for i := range suites.Suites {
		if suites.Suites[i].Name == "packmon.scan-warnings" {
			warningSuite = &suites.Suites[i]
		}
	}
	if warningSuite == nil {
		t.Fatalf("missing packmon.scan-warnings suite\n%s", out.String())
	}
	if warningSuite.Errors != 2 || len(warningSuite.Cases) != 2 {
		t.Fatalf("warning suite = %+v, want 2 errored cases", warningSuite)
	}
	for _, tc := range warningSuite.Cases {
		if tc.Error == nil {
			t.Fatalf("warning testcase missing error: %+v", tc)
		}
		if tc.Error.Type != "scan_warning" {
			t.Fatalf("warning error type = %q, want scan_warning", tc.Error.Type)
		}
	}
	if !strings.Contains(warningSuite.Cases[0].Error.Body, "degraded feed status") {
		t.Fatalf("first warning missing degraded feed status: %q", warningSuite.Cases[0].Error.Body)
	}
	if !strings.Contains(warningSuite.Cases[1].Error.Body, "Local database last synced 8 days ago") {
		t.Fatalf("second warning missing stale DB warning: %q", warningSuite.Cases[1].Error.Body)
	}
}

func TestJUnitNonBlockingFindingsDoNotCreateFailures(t *testing.T) {
	result := &domain.ScanResult{
		Mode:             "local",
		PackagesScanned:  1,
		FindingsCount:    1,
		FindingsBlocking: false,
		BlockThreshold:   domain.SeverityCritical,
		Findings: []domain.Finding{
			{
				Name:      "under-threshold",
				Version:   "1.0.0",
				Ecosystem: domain.EcosystemNPM,
				Type:      domain.FindingTypeVulnerability,
				Severity:  domain.SeverityHigh,
				Title:     "Under threshold finding",
				Source:    "osv",
			},
		},
	}

	var out bytes.Buffer
	if err := NewJUnitWriter().Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var suites junitTestsuites
	if err := xml.Unmarshal(out.Bytes(), &suites); err != nil {
		t.Fatalf("invalid JUnit XML: %v\n%s", err, out.String())
	}
	if suites.Tests != 1 || suites.Failures != 0 {
		t.Fatalf("suites tests/failures = %d/%d, want 1/0\n%s", suites.Tests, suites.Failures, out.String())
	}
	if len(suites.Testsuites) != 1 || len(suites.Testsuites[0].Cases) != 1 {
		t.Fatalf("cases = %+v, want one finding testcase", suites.Testsuites)
	}
	if suites.Testsuites[0].Cases[0].Failure != nil {
		t.Fatalf("non-blocking finding emitted failure: %+v", suites.Testsuites[0].Cases[0].Failure)
	}
}

func TestJUnitNormalizesMalwareHistorySeverity(t *testing.T) {
	result := &domain.ScanResult{
		Mode:             "remote",
		PackagesScanned:  1,
		FindingsCount:    1,
		FindingsBlocking: false,
		BlockThreshold:   domain.SeverityCritical,
		Findings: []domain.Finding{
			{
				Name:      "debug",
				Version:   "4.4.3",
				Ecosystem: domain.EcosystemNPM,
				Type:      domain.FindingTypeSupplyChainRisk,
				Severity:  domain.SeverityHigh,
				Title:     "ReversingLabs: malware incident history",
				RiskType:  domain.RiskTypeMalwareHistory,
				Source:    "reversinglabs",
			},
		},
	}

	var out bytes.Buffer
	if err := NewJUnitWriter().Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var suites junitTestsuites
	if err := xml.Unmarshal(out.Bytes(), &suites); err != nil {
		t.Fatalf("invalid JUnit XML: %v\n%s", err, out.String())
	}
	if len(suites.Testsuites) != 1 || len(suites.Testsuites[0].Cases) != 1 {
		t.Fatalf("cases = %+v, want one finding testcase", suites.Testsuites)
	}
	name := suites.Testsuites[0].Cases[0].Name
	if !strings.Contains(name, "[LOW]") || strings.Contains(name, "[HIGH]") {
		t.Fatalf("testcase name = %q, want normalized LOW severity", name)
	}
}

func TestJUnitNoParseErrorSuiteWhenNone(t *testing.T) {
	result := &domain.ScanResult{Mode: "local", PackagesScanned: 1}
	var out bytes.Buffer
	if err := NewJUnitWriter().Write(&out, result); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if strings.Contains(out.String(), "packmon.parse-errors") {
		t.Fatalf("did not expect parse-errors suite\n%s", out.String())
	}
}
