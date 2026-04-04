package scanner

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

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
}

// NewTableWriter creates a TableWriter. When noColor is true, ANSI escape
// sequences are suppressed.
func NewTableWriter(noColor bool) *TableWriter {
	return &TableWriter{noColor: noColor}
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

	if len(result.Findings) == 0 {
		_, err := fmt.Fprintf(w, "\nNo findings in %d packages.\n", result.PackagesScanned)
		return err
	}

	tab := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	// Header.
	header := "SEVERITY\tPACKAGE\tECOSYSTEM\tADVISORY\tFIX VERSION\tSOURCE"
	if _, err := fmt.Fprintln(tab, header); err != nil {
		return err
	}

	// Rows.
	for _, f := range result.Findings {
		sev := tw.colorSeverity(f.Severity)
		pkg := fmt.Sprintf("%s@%s", f.Name, f.Version)
		advisory := f.AdvisoryID
		if f.Type == domain.FindingTypeMalicious && advisory == "" {
			advisory = "MALWARE"
		}
		fixVer := f.FixedVersion
		if fixVer == "" {
			if f.Type == domain.FindingTypeMalicious {
				fixVer = "Remove pkg"
			} else {
				fixVer = "n/a"
			}
		}

		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s",
			sev, pkg, f.Ecosystem, advisory, fixVer, f.Source)
		if _, err := fmt.Fprintln(tab, line); err != nil {
			return err
		}
	}

	if err := tab.Flush(); err != nil {
		return err
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

func (tw *TableWriter) countBlocking(result *domain.ScanResult) int {
	count := 0
	for _, f := range result.Findings {
		if f.Type == domain.FindingTypeMalicious {
			count++
			continue
		}
		// We cannot access the fail-on threshold here, so we count
		// based on the result's blocking flag.
		_ = f
	}
	// Use the result-level flag: if blocking, at least 1.
	// For a more accurate count we would need the threshold, but the
	// summary by_severity gives us enough info.
	if result.FindingsBlocking {
		// Count all malicious plus all above threshold (approximate).
		count = 0
		for _, f := range result.Findings {
			if f.Type == domain.FindingTypeMalicious {
				count++
			}
		}
		// If count is 0 but blocking is true, it must be severity-based.
		if count == 0 {
			count = result.FindingsCount
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
		return "NONE", true
	default:
		return "", false
	}
}
