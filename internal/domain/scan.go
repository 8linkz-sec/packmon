package domain

import (
	"strings"
	"time"
)

// ScanRequest is the input for a scan via API or CLI.
type ScanRequest struct {
	// Packages is the package inventory to check.
	Packages []Package `json:"packages"`
	// Repo is optional remote-safe repository metadata. It contains only the
	// repository name; branch and commit metadata are not accepted here.
	Repo *RemoteRepoInfo `json:"repo,omitempty"`
}

// RemoteRepoInfo contains repository metadata accepted by the remote API and
// webhook contract. Branch and commit are intentionally omitted.
type RemoteRepoInfo struct {
	// Name is a bounded, path-minimized repository name when the client chooses
	// to send repository metadata.
	Name string `json:"name"`
}

// RepoInfo contains optional local repository metadata used for CLI history.
type RepoInfo struct {
	// Name is the local repository name when detected.
	Name string `json:"name"`
	// Branch is local-only CLI history metadata and is not sent in remote scan
	// requests or webhook envelopes.
	Branch string `json:"branch,omitempty"`
	// Commit is local-only CLI history metadata and is not sent in remote scan
	// requests or webhook envelopes.
	Commit string `json:"commit,omitempty"`
}

// ScanMode is the externally visible scan-result mode vocabulary.
type ScanMode string

const (
	ScanModeAuto   ScanMode = "auto"
	ScanModeRemote ScanMode = "remote"
	ScanModeLocal  ScanMode = "local"
)

// ScanModeValues returns the stable public scan mode enum values.
func ScanModeValues() []ScanMode {
	return []ScanMode{ScanModeRemote, ScanModeLocal, ScanModeAuto}
}

// ScanFeedStatus is the externally visible ScanResult.feed_status vocabulary.
type ScanFeedStatus string

const (
	ScanFeedStatusHealthy  ScanFeedStatus = "healthy"
	ScanFeedStatusDegraded ScanFeedStatus = "degraded"
	ScanFeedStatusError    ScanFeedStatus = "error"
)

// ScanFeedStatusValues returns the stable public ScanResult.feed_status enum
// values.
func ScanFeedStatusValues() []ScanFeedStatus {
	return []ScanFeedStatus{ScanFeedStatusHealthy, ScanFeedStatusDegraded, ScanFeedStatusError}
}

// ScanResult is the canonical scan result schema.
// Used identically for CLI JSON output, API response, and webhook result.
type ScanResult struct {
	// ScanID is the per-scan identifier used to correlate server logs,
	// artifacts, and webhook delivery.
	ScanID string `json:"scan_id"`
	// Mode is the requested or effective mode: remote, local, or auto. Auto
	// mode results may report the actual execution path after fallback.
	Mode ScanMode `json:"mode"`
	// ScannedAt is the scan completion timestamp.
	ScannedAt time.Time `json:"scanned_at"`
	// DurationMs is the elapsed scan duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
	// PackagesScanned is the number of packages included in the security check.
	PackagesScanned int `json:"packages_scanned"`
	// FindingsCount is the total number of serialized findings.
	FindingsCount int `json:"findings_count"`
	// FindingsBlocking reports whether any finding fails the configured policy.
	FindingsBlocking bool `json:"findings_blocking"`
	// BlockThreshold is the effective vulnerability/lifecycle severity
	// threshold used for FindingsBlocking. NONE disables only severity-gated
	// vulnerability and lifecycle blocking; malicious and active supply-chain
	// risk findings still block.
	BlockThreshold Severity `json:"block_threshold"`
	// FeedStatus is a compact machine-readable status: healthy, degraded, or
	// error. Human-readable operational details belong in ScanError.
	FeedStatus string `json:"feed_status"`
	// ScanError carries optional human-readable parser or operational failure
	// detail for CLI, report, and webhook artifacts.
	ScanError string `json:"scan_error,omitempty"`
	// DBAgeDays is the local database age in whole days when local scan
	// freshness is known; nil means the age is not available.
	DBAgeDays *int `json:"db_age_days"`
	// DBStale reports whether local database freshness is stale or cannot be
	// verified. Remote results normally leave this false.
	DBStale bool `json:"db_stale"`
	// Summary aggregates serialized findings by severity, type, and source.
	Summary ScanSummary `json:"summary"`
	// Findings is the serialized finding list returned to CLI, API, and webhook
	// consumers.
	Findings []Finding `json:"findings"`
	// ParseErrors contains per-file partial inventory diagnostics. Fatal
	// operational or parser failure detail belongs in ScanError.
	ParseErrors []string `json:"parse_errors,omitempty"`
	// FindingsTruncated is true when the server had more findings than it
	// serialized in this result.
	FindingsTruncated bool `json:"findings_truncated,omitempty"`
	// FeedVersions maps feed source names to their advertised feed timestamps or
	// versions when known.
	FeedVersions map[string]string `json:"feed_versions"`
	// ManualAdvisoriesCount is the number of findings sourced from
	// operator-managed manual advisories.
	ManualAdvisoriesCount int `json:"manual_advisories_count"`
}

// ScanSummary aggregates findings by severity, type, and source.
type ScanSummary struct {
	// BySeverity counts findings by normalized public severity label.
	BySeverity map[string]int `json:"by_severity"`
	// ByType counts findings by public finding type.
	ByType map[string]int `json:"by_type"`
	// BySource counts findings by feed or manual advisory source.
	BySource map[string]int `json:"by_source"`
}

// EmptyScanSummary returns an initialized empty summary suitable for JSON output.
func EmptyScanSummary() ScanSummary {
	return ScanSummary{
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
		BySource:   map[string]int{},
	}
}

// BuildScanSummary aggregates findings by severity, type, and source.
func BuildScanSummary(findings []Finding) ScanSummary {
	summary := EmptyScanSummary()
	for _, finding := range findings {
		summary.BySeverity[string(NormalizeFindingSeverity(finding))]++
		summary.ByType[string(finding.Type)]++
		summary.BySource[finding.Source]++
	}
	return summary
}

// FindingAlwaysBlocks reports whether a finding blocks independently of the
// vulnerability severity threshold.
func FindingAlwaysBlocks(finding Finding) bool {
	if FindingIsInformational(finding) {
		return false
	}
	return finding.Type == FindingTypeMalicious || finding.Type == FindingTypeSupplyChainRisk
}

// FindingIsInformational reports whether a finding should be shown for operator
// context but must not fail a scan gate.
func FindingIsInformational(finding Finding) bool {
	return finding.Type == FindingTypeSupplyChainRisk &&
		strings.EqualFold(strings.TrimSpace(finding.RiskType), RiskTypeMalwareHistory)
}

// NormalizeFindingSeverity returns the policy severity that should be exposed
// for a finding. Historical reputation context is informational and is
// classified as LOW even when an upstream source reports a higher label.
func NormalizeFindingSeverity(finding Finding) Severity {
	if FindingIsInformational(finding) {
		return SeverityLow
	}
	return finding.Severity
}

// FindingBlocks reports whether one finding blocks under Packmon's scan policy.
// SeverityNone disables severity-gated vulnerability and lifecycle blocking
// only; malicious and active supply-chain risk findings still block.
// Informational reputation findings do not block.
func FindingBlocks(finding Finding, threshold Severity) bool {
	if FindingIsInformational(finding) {
		return false
	}
	if FindingAlwaysBlocks(finding) {
		return true
	}
	if threshold == SeverityNone {
		return false
	}
	return finding.Severity.Blocks(threshold)
}

// FindingsBlock reports whether any finding blocks under Packmon's scan policy.
func FindingsBlock(findings []Finding, threshold Severity) bool {
	for _, finding := range findings {
		if FindingBlocks(finding, threshold) {
			return true
		}
	}
	return false
}

// CountManualAdvisoryFindings counts findings sourced from operator-managed
// manual advisories.
func CountManualAdvisoryFindings(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.Source == ManualAdvisorySource {
			count++
		}
	}
	return count
}

// WebhookEnvelope wraps a ScanResult for webhook delivery.
type WebhookEnvelope struct {
	// Event is the webhook event name. Current scan webhooks use scan_completed.
	Event string `json:"event"`
	// Version is the webhook payload schema version.
	Version string `json:"version"`
	// Timestamp is the envelope creation timestamp.
	Timestamp time.Time `json:"timestamp"`
	// Source identifies the Packmon sender.
	Source string `json:"source"`
	// Repository carries optional remote-safe repository metadata and never
	// includes branch or commit values.
	Repository *RemoteRepoInfo `json:"repository,omitempty"`
	// Result is the canonical scan result payload.
	Result ScanResult `json:"result"`
}
