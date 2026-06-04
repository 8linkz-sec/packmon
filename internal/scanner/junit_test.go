package scanner

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestJUnitSurfacesParseErrorsAsErroredSuite(t *testing.T) {
	result := &domain.ScanResult{
		Mode:            "local",
		PackagesScanned: 3,
		FindingsCount:   1,
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
