package scanner

import (
	"errors"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

var errTableOutput = errors.New("table output failed")

type failOnTableWrite struct {
	failAt int
	writes int
}

func (w *failOnTableWrite) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errTableOutput
	}
	return len(p), nil
}

func TestTableWriterWritePropagatesOutputFailures(t *testing.T) {
	t.Parallel()

	finding := domain.Finding{
		Name:       "package",
		Version:    "1.0.0",
		Ecosystem:  domain.EcosystemNPM,
		Type:       domain.FindingTypeVulnerability,
		Severity:   domain.SeverityHigh,
		AdvisoryID: "CVE-test",
		Source:     "osv",
	}
	withFinding := func(f domain.Finding) *domain.ScanResult {
		return &domain.ScanResult{
			PackagesScanned: 1,
			FindingsCount:   1,
			Findings:        []domain.Finding{f},
		}
	}

	tests := []struct {
		name   string
		writer *failOnTableWrite
		result *domain.ScanResult
	}{
		{
			name:   "operational status message",
			writer: &failOnTableWrite{failAt: 1},
			result: &domain.ScanResult{ScanError: "remote checker unavailable"},
		},
		{
			name:   "local freshness warning",
			writer: &failOnTableWrite{failAt: 1},
			result: &domain.ScanResult{Mode: domain.ScanModeLocal, DBStale: true},
		},
		{
			name:   "finding table header",
			writer: &failOnTableWrite{failAt: 1},
			result: withFinding(finding),
		},
		{
			name:   "finding table row",
			writer: &failOnTableWrite{failAt: 2},
			result: withFinding(finding),
		},
		{
			name:   "reference row",
			writer: &failOnTableWrite{failAt: 5},
			result: withFinding(func() domain.Finding {
				f := finding
				f.URL = "https://example.test/advisory"
				return f
			}()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewTableWriter(true).Write(tt.writer, tt.result)
			if !errors.Is(err, errTableOutput) {
				t.Fatalf("Write() error = %v, want %v", err, errTableOutput)
			}
		})
	}
}

func TestTableLayoutAndReferencesCoverLongAndDuplicateValues(t *testing.T) {
	t.Parallel()

	layout := tableLayout{maxPkg: 7, maxEco: 9, maxAdv: 8, maxFix: 13}
	layout.include(tableRow{
		pkg:      "a-package-name",
		eco:      "an-ecosystem",
		advisory: "an-advisory-id",
		fixVer:   "a-fixed-version",
	})
	if layout != (tableLayout{maxPkg: 14, maxEco: 12, maxAdv: 14, maxFix: 15}) {
		t.Fatalf("layout = %#v", layout)
	}

	findings := []domain.Finding{
		{URL: "https://example.test/advisory"},
		{URL: "https://example.test/advisory"},
		{},
	}
	refs := buildTableReferences([]tableRow{
		{advisory: "CVE-test"},
		{advisory: "CVE-test"},
		{advisory: "CVE-empty"},
	}, findings)
	if len(refs) != 1 || refs[0].advisory != "CVE-test" {
		t.Fatalf("references = %#v, want one deduplicated reference", refs)
	}
}

func TestWriteTableReferencesPropagatesHeadingError(t *testing.T) {
	t.Parallel()

	err := writeTableReferences(&failOnTableWrite{failAt: 1}, []tableReference{{
		advisory: "CVE-test",
		url:      "https://example.test/advisory",
	}}, tableLayout{maxAdv: 8})
	if !errors.Is(err, errTableOutput) {
		t.Fatalf("writeTableReferences() error = %v, want %v", err, errTableOutput)
	}
}

func TestWriteFindingTableAnnotatesRowWriteError(t *testing.T) {
	t.Parallel()

	writer := &failOnTableWrite{failAt: 2}
	err := writeFindingTable(writer, []tableRow{{severity: "HIGH", colored: "HIGH"}}, tableLayout{})
	if !errors.Is(err, errTableOutput) {
		t.Fatalf("writeFindingTable() error = %v, want %v", err, errTableOutput)
	}
	if strings.Contains(err.Error(), "<nil>") {
		t.Fatalf("writeFindingTable() error = %q, must retain the write error", err)
	}
}
