package scanner

import (
	"fmt"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/plural"
	"github.com/8linkz-sec/packmon/internal/termtext"
)

type scanArtifactDiagnostic struct {
	Message string
	Level   string
}

const zeroPackageScanWarning = "No packages were evaluated. Check the scan path, ecosystem filters, and supported lockfiles or SBOM inputs."
const parseErrorReportWarningPrefix = "Some dependency inventory could not be evaluated: "

// DegradedFeedStatusWarning returns the user-facing warning for a degraded feed
// state. Local scans surface the status that was persisted during the last DB
// sync, so the wording must not read like a live remote check.
func DegradedFeedStatusWarning(mode domain.ScanMode) string {
	if domain.ScanMode(strings.TrimSpace(string(mode))) == domain.ScanModeLocal {
		return "The local database was last synced from a server reporting degraded feed status. Some synced feed data may be outdated."
	}
	return "Server reports degraded feed status. Some feeds may be outdated."
}

// LocalDBStaleWarning returns the user-facing warning for stale or unverifiable
// local advisory data. Unknown freshness is treated as degraded coverage.
func LocalDBStaleWarning(result *domain.ScanResult) string {
	if result == nil || result.Mode != domain.ScanModeLocal || !result.DBStale {
		return ""
	}
	if result.DBAgeDays != nil {
		return fmt.Sprintf("Local database last synced %s ago. Results may be incomplete. Update with: packmon db sync.", plural.Count(*result.DBAgeDays, "day", "days"))
	}
	return "Local database freshness could not be verified. Results may be incomplete. Update with: packmon db sync."
}

// ReportWarnings returns the shared non-finding warning text used by
// human-readable report surfaces.
func ReportWarnings(result *domain.ScanResult) []string {
	if result == nil {
		return nil
	}
	diagnostics := scanArtifactDiagnostics(result)
	warnings := make([]string, 0, len(diagnostics)+len(result.ParseErrors))
	for _, diagnostic := range diagnostics {
		if diagnostic.Level != "warning" {
			continue
		}
		if diagnostic.Message == zeroPackageScanWarning {
			continue
		}
		warnings = append(warnings, diagnostic.Message)
	}
	for _, parseErr := range result.ParseErrors {
		parseErr = strings.TrimSpace(parseErr)
		if parseErr == "" {
			continue
		}
		warnings = append(warnings, parseErrorReportWarningPrefix+parseErr)
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

func scanArtifactWarnings(result *domain.ScanResult) []string {
	diagnostics := scanArtifactDiagnostics(result)
	if len(diagnostics) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		warnings = append(warnings, diagnostic.Message)
	}
	return warnings
}

func scanArtifactDiagnostics(result *domain.ScanResult) []scanArtifactDiagnostic {
	if result == nil {
		return nil
	}

	var diagnostics []scanArtifactDiagnostic
	if message := scanOperationalStatusMessage(result); message != "" {
		diagnostics = append(diagnostics, scanArtifactDiagnostic{
			Message: termtext.Sanitize(message),
			Level:   "error",
		})
	} else if strings.TrimSpace(result.FeedStatus) == string(domain.ScanFeedStatusDegraded) {
		diagnostics = append(diagnostics, scanArtifactDiagnostic{
			Message: DegradedFeedStatusWarning(result.Mode),
			Level:   "warning",
		})
	}

	if message := LocalDBStaleWarning(result); message != "" {
		diagnostics = append(diagnostics, scanArtifactDiagnostic{
			Message: message,
			Level:   "warning",
		})
	}
	if message := zeroPackageScanDiagnostic(result); message != "" {
		diagnostics = append(diagnostics, scanArtifactDiagnostic{
			Message: message,
			Level:   "warning",
		})
	}

	return diagnostics
}

func scanOperationalStatusMessage(result *domain.ScanResult) string {
	if result == nil {
		return ""
	}
	if message := strings.TrimSpace(result.ScanError); message != "" {
		return message
	}
	return operationalStatusMessage(result.FeedStatus)
}

func zeroPackageScanDiagnostic(result *domain.ScanResult) string {
	if result == nil || result.PackagesScanned != 0 || len(result.Findings) != 0 {
		return ""
	}
	if scanOperationalStatusMessage(result) != "" {
		return ""
	}
	return zeroPackageScanWarning
}
