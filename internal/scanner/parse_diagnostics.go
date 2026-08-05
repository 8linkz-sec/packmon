package scanner

import (
	"fmt"
	"strings"
)

// MaxUserFacingParseDiagnostics bounds terminal and CI-artifact parse
// diagnostics. Raw ScanResult.ParseErrors remains complete for JSON output.
const MaxUserFacingParseDiagnostics = 20

const parseDiagnosticsOmittedSuffix = "see JSON parse_errors for full detail"

// BoundedParseDiagnostics returns the visible parse diagnostics and the count
// omitted from user-facing output. Empty diagnostics are ignored.
func BoundedParseDiagnostics(parseErrors []string) ([]string, int) {
	if len(parseErrors) == 0 {
		return nil, 0
	}
	visible := make([]string, 0, min(len(parseErrors), MaxUserFacingParseDiagnostics))
	omitted := 0
	for _, parseErr := range parseErrors {
		parseErr = strings.TrimSpace(parseErr)
		if parseErr == "" {
			continue
		}
		if len(visible) < MaxUserFacingParseDiagnostics {
			visible = append(visible, parseErr)
			continue
		}
		omitted++
	}
	return visible, omitted
}

// ParseDiagnosticsOmittedSummary returns the summary text for omitted parse
// diagnostics, or an empty string when nothing was omitted.
func ParseDiagnosticsOmittedSummary(omitted int) string {
	if omitted <= 0 {
		return ""
	}
	return fmt.Sprintf("%d additional parse diagnostics omitted; %s", omitted, parseDiagnosticsOmittedSuffix)
}
