package scanner

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/termtext"
)

// ANSI color codes for severity levels.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

const (
	severityColumnWidth = 10 // "CRITICAL" = 8, padded to 10
	tableColumnGap      = "  "
)

// TableWriter writes scan results as a human-readable table.
type TableWriter struct {
	noColor bool
	failOn  domain.Severity
}

type tableRow struct {
	severity string
	colored  string
	pkg      string
	eco      string
	advisory string
	fixVer   string
	source   string
}

type tableLayout struct {
	maxPkg int
	maxEco int
	maxAdv int
	maxFix int
}

type tableReference struct {
	advisory string
	url      string
}

// NewTableWriter creates a TableWriter. When noColor is true, ANSI escape
// sequences are suppressed.
func NewTableWriter(noColor bool, failOn ...domain.Severity) *TableWriter {
	threshold := domain.SeverityCritical
	if len(failOn) > 0 {
		if parsed, ok := domain.ParseBlockThreshold(string(failOn[0])); ok {
			threshold = parsed
		}
	}
	return &TableWriter{noColor: noColor, failOn: threshold}
}

// Write formats the scan result as a table and writes it to w.
func (tw *TableWriter) Write(w io.Writer, result *domain.ScanResult) error {
	if statusMessage := scanOperationalStatusMessage(result); statusMessage != "" {
		if err := tw.writeStatusMessages(w, result, statusMessage); err != nil {
			return err
		}
		if handled, err := writeNoFindingResult(w, result, statusMessage); handled {
			return err
		}
	} else {
		if err := tw.writeStatusMessages(w, result, ""); err != nil {
			return err
		}
		if handled, err := writeNoFindingResult(w, result, ""); handled {
			return err
		}
	}

	rows, layout := tw.buildTableRows(result.Findings)
	if err := writeFindingTable(w, rows, layout); err != nil {
		return err
	}
	if err := writeTableReferences(w, buildTableReferences(rows, result.Findings), layout); err != nil {
		return err
	}
	return tw.writeSummary(w, result)
}

func (tw *TableWriter) writeStatusMessages(w io.Writer, result *domain.ScanResult, statusMessage string) error {
	if message := LocalDBStaleWarning(result); message != "" {
		if _, err := fmt.Fprintf(w, "\n!! ATTENTION: %s\n", message); err != nil {
			return err
		}
	}

	if statusMessage != "" {
		_, err := fmt.Fprintf(w, "\n%s\n", termtext.Sanitize(statusMessage))
		return err
	}
	if result.FeedStatus == string(domain.ScanFeedStatusDegraded) {
		_, err := fmt.Fprintln(w, "\nWARN  "+DegradedFeedStatusWarning(result.Mode))
		return err
	}
	return nil
}

func writeNoFindingResult(w io.Writer, result *domain.ScanResult, statusMessage string) (bool, error) {
	if len(result.Findings) > 0 {
		return false, nil
	}
	if statusMessage != "" {
		_, err := fmt.Fprintf(w, "\nScan did not complete; findings were not evaluated for %s.\n", plural.Count(result.PackagesScanned, "package", "packages"))
		return true, err
	}
	if message := zeroPackageScanDiagnostic(result); message != "" {
		_, err := fmt.Fprintf(w, "\n%s\n", message)
		return true, err
	}
	_, err := fmt.Fprintf(w, "\nNo findings in %s.\n", plural.Count(result.PackagesScanned, "package", "packages"))
	return true, err
}

func (tw *TableWriter) buildTableRows(findings []domain.Finding) ([]tableRow, tableLayout) {
	layout := tableLayout{maxPkg: 7, maxEco: 9, maxAdv: 8, maxFix: 13}
	rows := make([]tableRow, 0, len(findings))
	for _, finding := range findings {
		row := tw.buildTableRow(finding)
		rows = append(rows, row)
		layout.include(row)
	}
	return rows, layout
}

func (tw *TableWriter) buildTableRow(finding domain.Finding) tableRow {
	advisory := finding.AdvisoryID
	if advisory == "" {
		advisory = advisoryLabel(finding)
	}
	severity := domain.NormalizeFindingSeverity(finding)
	return tableRow{
		severity: string(severity),
		colored:  tw.colorSeverity(severity),
		pkg:      fmt.Sprintf("%s@%s", termtext.Sanitize(finding.Name), termtext.Sanitize(finding.Version)),
		eco:      termtext.Sanitize(string(finding.Ecosystem)),
		advisory: termtext.Sanitize(advisory),
		fixVer:   termtext.Sanitize(tableFixVersion(finding)),
		source:   termtext.Sanitize(finding.Source),
	}
}

func (layout *tableLayout) include(row tableRow) {
	if len(row.pkg) > layout.maxPkg {
		layout.maxPkg = len(row.pkg)
	}
	if len(row.eco) > layout.maxEco {
		layout.maxEco = len(row.eco)
	}
	if len(row.advisory) > layout.maxAdv {
		layout.maxAdv = len(row.advisory)
	}
	if len(row.fixVer) > layout.maxFix {
		layout.maxFix = len(row.fixVer)
	}
}

func tableFixVersion(finding domain.Finding) string {
	if finding.FixedVersion != "" {
		return finding.FixedVersion
	}
	switch finding.Type {
	case domain.FindingTypeMalicious:
		return "Remove pkg"
	case domain.FindingTypeSupplyChainRisk:
		if strings.EqualFold(strings.TrimSpace(finding.RiskType), domain.RiskTypeMalwareHistory) {
			return "Review history"
		}
		return "Review pkg"
	case domain.FindingTypeLifecycle:
		return "Review lifecycle"
	default:
		return "n/a"
	}
}

func writeFindingTable(w io.Writer, rows []tableRow, layout tableLayout) error {
	headerFormat := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		severityColumnWidth, tableColumnGap,
		layout.maxPkg, tableColumnGap,
		layout.maxEco, tableColumnGap,
		layout.maxAdv, tableColumnGap,
		layout.maxFix, tableColumnGap)
	if _, err := fmt.Fprintf(w, headerFormat, "SEVERITY", "PACKAGE", "ECOSYSTEM", "ADVISORY", "FIXED VERSION", "SOURCE"); err != nil {
		return err
	}

	rowFormat := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		layout.maxPkg, tableColumnGap,
		layout.maxEco, tableColumnGap,
		layout.maxAdv, tableColumnGap,
		layout.maxFix, tableColumnGap)
	for _, row := range rows {
		if err := writeFindingRow(w, row, rowFormat); err != nil {
			return err
		}
	}
	return nil
}

func writeFindingRow(w io.Writer, row tableRow, rowFormat string) error {
	pad := ""
	if diff := severityColumnWidth - len(row.severity); diff > 0 {
		pad = strings.Repeat(" ", diff)
	}
	if _, err := fmt.Fprintf(w, "%s%s%s", row.colored, pad, tableColumnGap); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, rowFormat, row.pkg, row.eco, row.advisory, row.fixVer, row.source)
	return err
}

func buildTableReferences(rows []tableRow, findings []domain.Finding) []tableReference {
	refs := make([]tableReference, 0, len(findings))
	seen := make(map[string]bool)
	for i, finding := range findings {
		url := termtext.Sanitize(referenceURL(finding))
		if url == "" {
			continue
		}
		key := rows[i].advisory + "\x00" + url
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, tableReference{advisory: rows[i].advisory, url: url})
	}
	return refs
}

func writeTableReferences(w io.Writer, refs []tableReference, layout tableLayout) error {
	if len(refs) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nReferences:"); err != nil {
		return err
	}
	for _, ref := range refs {
		if _, err := fmt.Fprintf(w, "  %-*s  %s\n", layout.maxAdv, ref.advisory, ref.url); err != nil {
			return err
		}
	}
	return nil
}

func (tw *TableWriter) writeSummary(w io.Writer, result *domain.ScanResult) error {
	blocking := tw.countBlocking(result)
	_, err := fmt.Fprintf(w, "\nFound %s (%s) in %s\n",
		plural.Count(result.FindingsCount, "finding", "findings"),
		plural.Count(blocking, "blocking", "blocking"),
		plural.Count(result.PackagesScanned, "package", "packages"))
	return err
}

func (tw *TableWriter) colorSeverity(s domain.Severity) string {
	if tw.noColor {
		return string(s)
	}
	text := string(s)
	switch s {
	case domain.SeverityCritical:
		return colorBold + colorRed + text + colorReset
	case domain.SeverityHigh:
		return colorRed + text + colorReset
	case domain.SeverityMedium:
		return colorYellow + text + colorReset
	case domain.SeverityLow:
		return colorCyan + text + colorReset
	default:
		return colorWhite + text + colorReset
	}
}

// referenceURL returns the best link for a finding: its primary URL, or the
// first resource link with a URL if no primary URL is set.
func referenceURL(f domain.Finding) string {
	if f.URL != "" {
		return f.URL
	}
	for _, r := range f.Resources {
		if r.URL != "" {
			return r.URL
		}
	}
	return ""
}

func (tw *TableWriter) countBlocking(result *domain.ScanResult) int {
	count := 0
	for _, f := range result.Findings {
		if domain.FindingBlocks(f, tw.failOn) {
			count++
		}
	}
	if count == 0 && result.FindingsBlocking && len(result.Findings) > 0 {
		return 1
	}
	return count
}
