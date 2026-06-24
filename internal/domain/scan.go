package domain

import (
	"strings"
	"time"
)

// ScanRequest is the input for a scan via API or CLI.
type ScanRequest struct {
	Packages []Package `json:"packages"`
	Repo     *RepoInfo `json:"repo,omitempty"`
}

// RepoInfo contains optional repository metadata sent with a scan.
type RepoInfo struct {
	Name   string `json:"name"`
	Branch string `json:"branch,omitempty"`
	Commit string `json:"commit,omitempty"`
}

// ScanResult is the canonical scan result schema.
// Used identically for CLI JSON output, API response, and webhook result.
type ScanResult struct {
	ScanID            string            `json:"scan_id"`
	Mode              string            `json:"mode"`
	ScannedAt         time.Time         `json:"scanned_at"`
	DurationMs        int64             `json:"duration_ms"`
	PackagesScanned   int               `json:"packages_scanned"`
	FindingsCount     int               `json:"findings_count"`
	FindingsBlocking  bool              `json:"findings_blocking"`
	BlockThreshold    Severity          `json:"block_threshold"`
	FeedStatus        string            `json:"feed_status"`
	ScanError         string            `json:"scan_error,omitempty"`
	DBAgeDays         *int              `json:"db_age_days"`
	DBStale           bool              `json:"db_stale"`
	Summary           ScanSummary       `json:"summary"`
	Findings          []Finding         `json:"findings"`
	ParseErrors       []string          `json:"parse_errors,omitempty"`
	FindingsTruncated bool              `json:"findings_truncated,omitempty"`
	FeedVersions      map[string]string `json:"feed_versions"`
	ManualCount       int               `json:"manual_advisories_count"`
}

// ScanSummary aggregates findings by severity, type, and source.
type ScanSummary struct {
	BySeverity map[string]int `json:"by_severity"`
	ByType     map[string]int `json:"by_type"`
	BySource   map[string]int `json:"by_source"`
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
		strings.EqualFold(strings.TrimSpace(finding.RiskType), "malware_history")
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
// SeverityNone disables vulnerability blocking only; malicious and active
// supply-chain risk findings still block. Informational reputation findings do
// not block.
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
		if finding.Source == "manual" {
			count++
		}
	}
	return count
}

// WebhookEnvelope wraps a ScanResult for webhook delivery.
type WebhookEnvelope struct {
	Event      string     `json:"event"`
	Version    string     `json:"version"`
	Timestamp  time.Time  `json:"timestamp"`
	Source     string     `json:"source"`
	Repository *RepoInfo  `json:"repository,omitempty"`
	Result     ScanResult `json:"result"`
}
