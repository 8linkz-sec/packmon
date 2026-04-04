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
	Time       string           `xml:"time,attr"`
	Testsuites []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	XMLName  xml.Name        `xml:"testsuite"`
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Time     string          `xml:"time,attr"`
	Cases    []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
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
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("junit: create file %s: %w", path, err)
	}
	defer f.Close()

	if err := jw.Write(f, result); err != nil {
		return err
	}
	return f.Close()
}

func (jw *JUnitWriter) buildJUnit(result *domain.ScanResult) junitTestsuites {
	// Group findings by ecosystem.
	findingsByEco := make(map[string][]domain.Finding)
	ecosystemsSeen := make(map[string]struct{})

	for _, f := range result.Findings {
		eco := string(f.Ecosystem)
		findingsByEco[eco] = append(findingsByEco[eco], f)
		ecosystemsSeen[eco] = struct{}{}
	}

	// Determine all ecosystems: those with findings plus those scanned
	// without findings. We approximate from the findings and summary.
	// If there are no findings at all, create a single passing suite.
	if len(result.Findings) == 0 {
		return junitTestsuites{
			Tests:    1,
			Failures: 0,
			Time:     fmt.Sprintf("%.3f", float64(result.DurationMs)/1000.0),
			Testsuites: []junitTestsuite{
				{
					Name:     "packmon",
					Tests:    1,
					Failures: 0,
					Time:     fmt.Sprintf("%.3f", float64(result.DurationMs)/1000.0),
					Cases: []junitTestcase{
						{
							Name:      fmt.Sprintf("scan (%d packages)", result.PackagesScanned),
							Classname: "packmon",
							Time:      fmt.Sprintf("%.3f", float64(result.DurationMs)/1000.0),
						},
					},
				},
			},
		}
	}

	// Build one testsuite with testcases per finding.
	// Each finding becomes a failing testcase. This gives CI the best
	// granularity for reporting individual issues.
	totalTests := len(result.Findings)
	totalFailures := len(result.Findings)
	durationStr := fmt.Sprintf("%.3f", float64(result.DurationMs)/1000.0)

	var cases []junitTestcase
	for _, f := range result.Findings {
		tc := jw.buildTestcase(f)
		cases = append(cases, tc)
	}

	return junitTestsuites{
		Tests:    totalTests,
		Failures: totalFailures,
		Time:     durationStr,
		Testsuites: []junitTestsuite{
			{
				Name:     "packmon",
				Tests:    totalTests,
				Failures: totalFailures,
				Time:     durationStr,
				Cases:    cases,
			},
		},
	}
}

func (jw *JUnitWriter) buildTestcase(f domain.Finding) junitTestcase {
	pkg := fmt.Sprintf("%s@%s", f.Name, f.Version)
	name := fmt.Sprintf("[%s] %s (%s)", f.Severity, pkg, f.Ecosystem)
	classname := fmt.Sprintf("packmon.%s", f.Ecosystem)

	var failType string
	if f.Type == domain.FindingTypeMalicious {
		failType = "malicious"
	} else {
		failType = "vulnerability"
	}

	// Build failure body with relevant details.
	var body strings.Builder
	body.WriteString(f.Title)
	if f.AdvisoryID != "" {
		body.WriteString(fmt.Sprintf("\nAdvisory: %s", f.AdvisoryID))
	}
	if f.RiskType != "" {
		body.WriteString(fmt.Sprintf("\nRisk Type: %s", f.RiskType))
	}
	if f.FixedVersion != "" {
		body.WriteString(fmt.Sprintf("\nFixed Version: %s", f.FixedVersion))
	}
	if f.URL != "" {
		body.WriteString(fmt.Sprintf("\nURL: %s", f.URL))
	}
	body.WriteString(fmt.Sprintf("\nSource: %s", f.Source))

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
