package domain

import "time"

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
	FeedStatus        string            `json:"feed_status"`
	DBAgeDays         *int              `json:"db_age_days"`
	DBStale           bool              `json:"db_stale"`
	Summary           ScanSummary       `json:"summary"`
	Findings          []Finding         `json:"findings"`
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

// WebhookEnvelope wraps a ScanResult for webhook delivery.
type WebhookEnvelope struct {
	Event      string     `json:"event"`
	Version    string     `json:"version"`
	Timestamp  time.Time  `json:"timestamp"`
	Source     string     `json:"source"`
	Repository *RepoInfo  `json:"repository,omitempty"`
	Result     ScanResult `json:"result"`
}
