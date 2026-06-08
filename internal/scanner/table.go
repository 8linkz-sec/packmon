package scanner

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
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

// TableWriter writes scan results as a human-readable table.
type TableWriter struct {
	noColor bool
	failOn  domain.Severity
}

// NewTableWriter creates a TableWriter. When noColor is true, ANSI escape
// sequences are suppressed.
func NewTableWriter(noColor bool, failOn ...domain.Severity) *TableWriter {
	threshold := domain.SeverityCritical
	if len(failOn) > 0 {
		if parsed, ok := SeverityFromString(string(failOn[0])); ok {
			threshold = parsed
		}
	}
	return &TableWriter{noColor: noColor, failOn: threshold}
}

// Write formats the scan result as a table and writes it to w.
func (tw *TableWriter) Write(w io.Writer, result *domain.ScanResult) error {
	if result.Mode == "local" && result.DBAgeDays != nil && result.DBStale {
		if _, err := fmt.Fprintf(w, "\n!! ATTENTION: Local database last synced %d days ago.\n", *result.DBAgeDays); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "!! Results may be incomplete. Update with: packmon db sync"); err != nil {
			return err
		}
	}

	switch result.FeedStatus {
	case "", "healthy":
	case "degraded":
		if _, err := fmt.Fprintln(w, "\nWARN  Server reports degraded feed status. Some feeds may be outdated."); err != nil {
			return err
		}
	default:
		if _, err := fmt.Fprintf(w, "\n%s\n", result.FeedStatus); err != nil {
			return err
		}
	}

	if len(result.Findings) == 0 && hasOperationalStatus(result.FeedStatus) {
		_, err := fmt.Fprintf(w, "\nScan did not complete; findings were not evaluated for %d packages.\n", result.PackagesScanned)
		return err
	}

	if len(result.Findings) == 0 {
		_, err := fmt.Fprintf(w, "\nNo findings in %d packages.\n", result.PackagesScanned)
		return err
	}

	// We avoid tabwriter for the table because ANSI escape codes break
	// its width calculation. Instead we compute column widths manually
	// and pad with spaces.
	const sevWidth = 10 // "CRITICAL" = 8, padded to 10

	type row struct {
		severity string // plain text for width, colored for output
		colored  string
		pkg      string
		eco      string
		advisory string
		fixVer   string
		source   string
	}

	rows := make([]row, 0, len(result.Findings))
	maxPkg, maxEco, maxAdv, maxFix, maxSrc := 7, 9, 8, 11, 6 // header widths

	for _, f := range result.Findings {
		pkg := fmt.Sprintf("%s@%s", f.Name, f.Version)
		advisory := f.AdvisoryID
		if advisory == "" {
			advisory = advisoryLabel(f)
		}
		fixVer := f.FixedVersion
		if fixVer == "" {
			switch f.Type {
			case domain.FindingTypeMalicious:
				fixVer = "Remove pkg"
			case domain.FindingTypeSupplyChainRisk:
				if strings.EqualFold(strings.TrimSpace(f.RiskType), "malware_history") {
					fixVer = "Review history"
				} else {
					fixVer = "Review pkg"
				}
			case domain.FindingTypeLifecycle:
				fixVer = "Review lifecycle"
			default:
				fixVer = "n/a"
			}
		}

		r := row{
			severity: string(f.Severity),
			colored:  tw.colorSeverity(f.Severity),
			pkg:      pkg,
			eco:      string(f.Ecosystem),
			advisory: advisory,
			fixVer:   fixVer,
			source:   f.Source,
		}
		rows = append(rows, r)

		if len(r.pkg) > maxPkg {
			maxPkg = len(r.pkg)
		}
		if len(r.eco) > maxEco {
			maxEco = len(r.eco)
		}
		if len(r.advisory) > maxAdv {
			maxAdv = len(r.advisory)
		}
		if len(r.fixVer) > maxFix {
			maxFix = len(r.fixVer)
		}
		if len(r.source) > maxSrc {
			maxSrc = len(r.source)
		}
	}

	gap := "  " // column gap
	fmtPlain := fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
		sevWidth, gap, maxPkg, gap, maxEco, gap, maxAdv, gap, maxFix, gap)

	// Header.
	if _, err := fmt.Fprintf(w, fmtPlain,
		"SEVERITY", "PACKAGE", "ECOSYSTEM", "ADVISORY", "FIX VERSION", "SOURCE"); err != nil {
		return err
	}

	// Rows -- severity uses colored string but is padded to sevWidth based
	// on the plain-text length so ANSI codes don't shift the columns.
	for _, r := range rows {
		pad := ""
		if diff := sevWidth - len(r.severity); diff > 0 {
			pad = strings.Repeat(" ", diff)
		}
		if _, err := fmt.Fprintf(w, "%s%s%s", r.colored, pad, gap); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, fmt.Sprintf("%%-%ds%s%%-%ds%s%%-%ds%s%%-%ds%s%%s\n",
			maxPkg, gap, maxEco, gap, maxAdv, gap, maxFix, gap),
			r.pkg, r.eco, r.advisory, r.fixVer, r.source); err != nil {
			return err
		}
	}

	// References -- show a resolvable link per finding so terminal users do not
	// have to look advisory IDs up manually (parity with the SARIF/JUnit/HTML
	// writers, which already render f.URL / f.Resources).
	type ref struct{ advisory, url string }
	refs := make([]ref, 0, len(result.Findings))
	seen := make(map[string]bool)
	for i, f := range result.Findings {
		url := referenceURL(f)
		if url == "" {
			continue
		}
		key := rows[i].advisory + "\x00" + url
		if seen[key] {
			continue
		}
		seen[key] = true
		refs = append(refs, ref{advisory: rows[i].advisory, url: url})
	}
	if len(refs) > 0 {
		if _, err := fmt.Fprintln(w, "\nReferences:"); err != nil {
			return err
		}
		for _, r := range refs {
			if _, err := fmt.Fprintf(w, "  %-*s  %s\n", maxAdv, r.advisory, r.url); err != nil {
				return err
			}
		}
	}

	// Summary line.
	blocking := tw.countBlocking(result)
	_, err := fmt.Fprintf(w, "\nFound %d finding(s) (%d blocking) in %d packages\n",
		result.FindingsCount, blocking, result.PackagesScanned)
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
		if isAlwaysBlockingFinding(f) {
			count++
			continue
		}
		if tw.failOn != domain.SeverityNone && f.Severity.Blocks(tw.failOn) {
			count++
		}
	}
	return count
}

// SeverityFromString parses a severity string, accepting common variations.
// Returns the severity and true if valid, or empty and false if not.
func SeverityFromString(s string) (domain.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return domain.SeverityCritical, true
	case "HIGH":
		return domain.SeverityHigh, true
	case "MEDIUM":
		return domain.SeverityMedium, true
	case "LOW":
		return domain.SeverityLow, true
	case "NONE":
		return domain.SeverityNone, true
	default:
		return "", false
	}
}
