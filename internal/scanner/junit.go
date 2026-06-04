package scanner

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// JUnit XML types for CI/CD integration (GitLab Test Reports, Jenkins, etc.).

type junitTestsuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Errors     int              `xml:"errors,attr"`
	Time       string           `xml:"time,attr"`
	Testsuites []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	XMLName  xml.Name        `xml:"testsuite"`
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Errors   int             `xml:"errors,attr"`
	Time     string          `xml:"time,attr"`
	Cases    []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitError   `xml:"error,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// junitError represents a non-assertion problem (here: a partial parse error),
// distinct from a finding-based <failure>.
type junitError struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// JUnitWriter converts scan results to JUnit XML format.
type JUnitWriter struct{}

// NewJUnitWriter creates a JUnitWriter.
func NewJUnitWriter() *JUnitWriter {
	return &JUnitWriter{}
}

// Write serializes the scan result as JUnit XML and writes it to w.
func (jw *JUnitWriter) Write(w io.Writer, result *domain.ScanResult) error {
	suites := jw.buildJUnit(result)

	data, err := xml.MarshalIndent(suites, "", "  ")
	if err != nil {
		return fmt.Errorf("junit: marshal: %w", err)
	}

	if _, err := fmt.Fprintf(w, "%s\n", xml.Header); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// WriteFile writes the JUnit output to the given file path.
func (jw *JUnitWriter) WriteFile(path string, result *domain.ScanResult) error {
	// #nosec G304 -- CLI output path is provided intentionally by the local user.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("junit: create file %s: %w", path, err)
	}

	if err := jw.Write(f, result); err != nil {
		closeSilently(f)
		return err
	}
	return f.Close()
}

func (jw *JUnitWriter) buildJUnit(result *domain.ScanResult) junitTestsuites {
	durationStr := fmt.Sprintf("%.3f", float64(result.DurationMs)/1000.0)

	var (
		suites        []junitTestsuite
		totalTests    int
		totalFailures int
		totalErrors   int
	)

	// Findings suite. With no findings, emit a single passing case so CI shows a
	// green scan; otherwise one failing case per finding for fine granularity.
	if len(result.Findings) == 0 {
		suites = append(suites, junitTestsuite{
			Name:     "packmon",
			Tests:    1,
			Failures: 0,
			Time:     durationStr,
			Cases: []junitTestcase{
				{
					Name:      fmt.Sprintf("scan (%d packages)", result.PackagesScanned),
					Classname: "packmon",
					Time:      durationStr,
				},
			},
		})
		totalTests++
	} else {
		cases := make([]junitTestcase, 0, len(result.Findings))
		for _, f := range result.Findings {
			cases = append(cases, jw.buildTestcase(f))
		}
		suites = append(suites, junitTestsuite{
			Name:     "packmon",
			Tests:    len(cases),
			Failures: len(cases),
			Time:     durationStr,
			Cases:    cases,
		})
		totalTests += len(cases)
		totalFailures += len(cases)
	}

	// Surface partial parse errors as a dedicated errored suite so consumers
	// reading only the JUnit artifact still see that part of the dependency
	// graph was skipped.
	if len(result.ParseErrors) > 0 {
		cases := make([]junitTestcase, 0, len(result.ParseErrors))
		for i, pe := range result.ParseErrors {
			cases = append(cases, junitTestcase{
				Name:      fmt.Sprintf("parse error %d", i+1),
				Classname: "packmon.parse-errors",
				Time:      "0.000",
				Error: &junitError{
					Message: pe,
					Type:    "parse_error",
					Body:    pe,
				},
			})
		}
		suites = append(suites, junitTestsuite{
			Name:   "packmon.parse-errors",
			Tests:  len(cases),
			Errors: len(cases),
			Time:   "0.000",
			Cases:  cases,
		})
		totalTests += len(cases)
		totalErrors += len(cases)
	}

	return junitTestsuites{
		Tests:      totalTests,
		Failures:   totalFailures,
		Errors:     totalErrors,
		Time:       durationStr,
		Testsuites: suites,
	}
}

func (jw *JUnitWriter) buildTestcase(f domain.Finding) junitTestcase {
	pkg := fmt.Sprintf("%s@%s", f.Name, f.Version)
	name := fmt.Sprintf("[%s] %s (%s)", f.Severity, pkg, f.Ecosystem)
	classname := fmt.Sprintf("packmon.%s", f.Ecosystem)

	var failType string
	switch f.Type {
	case domain.FindingTypeMalicious:
		failType = "malicious"
	case domain.FindingTypeSupplyChainRisk:
		failType = "supply_chain_risk"
	case domain.FindingTypeLifecycle:
		failType = "lifecycle"
	default:
		failType = "vulnerability"
	}

	// Build failure body with relevant details.
	var body strings.Builder
	body.WriteString(f.Title)
	if f.AdvisoryID != "" {
		_, _ = fmt.Fprintf(&body, "\nAdvisory: %s", f.AdvisoryID)
	}
	if f.RiskType != "" {
		_, _ = fmt.Fprintf(&body, "\nRisk Type: %s", f.RiskType)
	}
	if f.FixedVersion != "" {
		_, _ = fmt.Fprintf(&body, "\nFixed Version: %s", f.FixedVersion)
	}
	if f.URL != "" {
		_, _ = fmt.Fprintf(&body, "\nURL: %s", f.URL)
	}
	_, _ = fmt.Fprintf(&body, "\nSource: %s", f.Source)

	// Build failure message (short summary for CI).
	message := f.Title
	if f.AdvisoryID != "" {
		message = fmt.Sprintf("%s (%s)", f.AdvisoryID, f.Title)
	}

	return junitTestcase{
		Name:      name,
		Classname: classname,
		Time:      "0.000",
		Failure: &junitFailure{
			Message: message,
			Type:    failType,
			Body:    body.String(),
		},
	}
}
