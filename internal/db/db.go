// Package db defines the Store interface for all database operations
// used by the Packmon server and feed sync pipeline.
package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/8linkz/packmon/internal/domain"
)

// Store is the central persistence interface. Both the PostgreSQL
// server-side implementation and the SQLite client-side implementation
// satisfy this interface (the client subset may leave some methods as
// no-ops).
type Store interface {
	// -- Vulnerability queries --------------------------------------------------

	// FindVulnerabilities returns all findings (CVE/advisory-based) that
	// affect the given package in the given ecosystem at the given version.
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)

	// FindMalicious returns all malicious-package findings that match the
	// given ecosystem and package name. When version is non-empty, only
	// findings whose versions list contains that version (or is NULL,
	// meaning all versions are affected) are returned.
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)

	// FindVulnerabilitiesBatch returns vulnerability findings for all
	// packages in a single batch query. Version matching is still done
	// in Go for each result. This avoids the N+1 query problem.
	FindVulnerabilitiesBatch(ctx context.Context, packages []PackageQuery) ([]domain.Finding, error)

	// FindMaliciousBatch returns malicious-package findings for all
	// packages in a single batch query.
	FindMaliciousBatch(ctx context.Context, packages []PackageQuery) ([]domain.Finding, error)

	// -- Vulnerability writes (feed sync) ---------------------------------------

	// UpsertVulnerability inserts or updates a vulnerability and its aliases,
	// sources, references, and affected packages in a single transaction.
	UpsertVulnerability(ctx context.Context, vuln *Vulnerability) error

	// UpsertMaliciousFinding inserts or updates a malicious finding.
	UpsertMaliciousFinding(ctx context.Context, mf *MaliciousFinding) error

	// PropagateSeverityViaAliases updates UNKNOWN-severity vulnerabilities
	// by copying the severity from a linked vulnerability (via shared alias)
	// that has a known severity. This handles cases where e.g. GO-2026-4856
	// is UNKNOWN but its alias GHSA-hxv8-4j4r-cqgv has MEDIUM.
	PropagateSeverityViaAliases(ctx context.Context) (int, error)

	// DeleteVulnerability removes a vulnerability and all related rows.
	DeleteVulnerability(ctx context.Context, id string) error

	// DeleteMaliciousFinding removes a malicious finding by id.
	DeleteMaliciousFinding(ctx context.Context, id string) error

	// ListMaliciousFindings returns malicious findings, optionally filtered
	// by source, newest first.
	ListMaliciousFindings(ctx context.Context, source string, limit int) ([]MaliciousFinding, error)

	// UpsertManualAdvisory creates or updates an operator-managed advisory.
	// Vulnerability advisories are stored in the vulnerability tables, while
	// malicious advisories are stored in malicious_findings.
	UpsertManualAdvisory(ctx context.Context, advisory *ManualAdvisory) error

	// DeleteManualAdvisory removes an operator-managed advisory from whichever
	// backing table owns it. Feed-sourced advisories must not be removed.
	DeleteManualAdvisory(ctx context.Context, id string) error

	// ListManualAdvisories returns operator-managed advisories across all
	// supported finding types, newest first.
	ListManualAdvisories(ctx context.Context, limit int) ([]ManualAdvisory, error)

	// -- Vulnerability enrichment (batch updates from enrichment feeds) ---------

	// SetCISAKEV marks the given CVE IDs as being in the CISA KEV catalog.
	// IDs not present in the vulnerabilities table are silently ignored.
	SetCISAKEV(ctx context.Context, cveIDs []string) (updated int, err error)

	// ClearCISAKEV resets the cisa_kev flag to false for all vulnerabilities
	// not in the provided set. Used during full-sync to remove stale flags.
	ClearCISAKEV(ctx context.Context, keepIDs []string) (cleared int, err error)

	// SetEPSSScores updates the epss_score and epss_percentile for the given
	// CVEs. Each entry in the slice maps a CVE ID to its scores. IDs not
	// present in the vulnerabilities table are silently ignored.
	SetEPSSScores(ctx context.Context, scores []EPSSEntry) (updated int, err error)

	// EnrichVulnCheck applies VulnCheck-sourced enrichment data to existing
	// vulnerabilities: CVSS scores, exploit-exists flags, and source records.
	EnrichVulnCheck(ctx context.Context, entries []VulnCheckEntry) (updated int, err error)

	// FindUnknownSeverityCVEAliases returns CVE aliases linked to
	// vulnerabilities with UNKNOWN severity. Used by the NVD syncer to
	// fetch CVSS scores for entries that lack severity information.
	FindUnknownSeverityCVEAliases(ctx context.Context) ([]UnknownCVEAlias, error)

	// UpdateSeverityByCVE updates the severity and CVSS score for a
	// vulnerability identified by its CVE alias. Only updates rows that
	// still have UNKNOWN severity to avoid overwriting richer data.
	UpdateSeverityByCVE(ctx context.Context, cveID, severity string, cvssScore float64) error

	// -- Feed sync status -------------------------------------------------------

	// GetFeedSyncStatus returns the sync state for the named feed.
	GetFeedSyncStatus(ctx context.Context, feedName string) (*FeedSyncStatus, error)

	// UpsertFeedSyncStatus creates or updates the sync state for a feed.
	UpsertFeedSyncStatus(ctx context.Context, status *FeedSyncStatus) error

	// ListFeedSyncStatuses returns sync state for all known feeds.
	ListFeedSyncStatuses(ctx context.Context) ([]FeedSyncStatus, error)

	// GetFeedConfig returns a persisted feed configuration override, or nil
	// if the feed uses the built-in runtime defaults.
	GetFeedConfig(ctx context.Context, feedName string) (*FeedConfig, error)

	// UpsertFeedConfig creates or updates a persisted feed configuration
	// override.
	UpsertFeedConfig(ctx context.Context, cfg *FeedConfig) error

	// DeleteFeedConfig removes a persisted feed configuration override so the
	// server falls back to runtime defaults again.
	DeleteFeedConfig(ctx context.Context, feedName string) error

	// ListFeedConfigs returns all persisted feed configuration overrides.
	ListFeedConfigs(ctx context.Context) ([]FeedConfig, error)

	// -- System settings -------------------------------------------------------

	// GetSystemSettings returns persisted server-level admin settings, or nil
	// if runtime defaults are still in use.
	GetSystemSettings(ctx context.Context) (*SystemSettings, error)

	// UpsertSystemSettings creates or updates persisted server-level admin
	// settings.
	UpsertSystemSettings(ctx context.Context, settings *SystemSettings) error

	// -- Refresh queue ----------------------------------------------------------

	// EnqueueRefresh adds a job to the refresh queue. If an identical
	// pending/processing job already exists, the priority is raised if the
	// new priority is higher (lower number). Returns whether a new job was
	// created and the current queue position.
	EnqueueRefresh(ctx context.Context, job *RefreshJob) (created bool, position int, err error)

	// DequeueRefresh claims the next pending job for the given source,
	// ordered by priority (ascending) then requested_at (ascending).
	// Returns nil if the queue is empty.
	DequeueRefresh(ctx context.Context, source string) (*RefreshJob, error)

	// CompleteRefresh marks a queued job as done or errored.
	CompleteRefresh(ctx context.Context, jobID int, jobErr error) error

	// ResetStuckJobs sets any job that has been in 'processing' state for
	// longer than the given duration back to 'pending'. Returns the number
	// of jobs reset.
	ResetStuckJobs(ctx context.Context, source string, stuckThreshold time.Duration) (int, error)

	// -- Package check status ---------------------------------------------------

	// GetPackageCheckStatus returns the check status for a package from a
	// specific source, or nil if none exists.
	GetPackageCheckStatus(ctx context.Context, ecosystem, name, source string) (*PackageCheckStatus, error)

	// UpsertPackageCheckStatus creates or updates a check status entry.
	UpsertPackageCheckStatus(ctx context.Context, status *PackageCheckStatus) error

	// -- Scan log ---------------------------------------------------------------

	// InsertScanLog records a completed scan.
	InsertScanLog(ctx context.Context, entry *ScanLogEntry) error

	// ListRecentScans returns the most recent scan log entries, newest first.
	// limit controls how many entries to return (max 100).
	ListRecentScans(ctx context.Context, limit int) ([]ScanLogEntry, error)

	// CountScansByDay returns the number of scans and total findings per day
	// for the last N days (including today). Results are ordered oldest to newest.
	CountScansByDay(ctx context.Context, days int) ([]DailyScanStats, error)

	// ListRecentVulnerabilities returns vulnerabilities published in the
	// last N days, newest first by advisory publication date. Limit caps
	// the result count.
	ListRecentVulnerabilities(ctx context.Context, days, limit int) ([]RecentVulnerability, error)

	// -- Search -----------------------------------------------------------------

	// SearchPackages searches the affected_packages and malicious_packages
	// tables for packages matching the optional name query and/or
	// severity filter. Returns a deduplicated list of matching packages
	// with their finding counts.
	SearchPackages(ctx context.Context, params PackageSearchParams) ([]PackageSearchResult, error)

	// -- API keys ---------------------------------------------------------------

	// FindAPIKeyByHash looks up an API key by its hash. Returns nil if not
	// found or if the key has been revoked.
	FindAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)

	// TouchAPIKeyLastUsed updates the last_used_at timestamp for a key.
	TouchAPIKeyLastUsed(ctx context.Context, keyID int) error

	// ListAPIKeys returns all API keys, including revoked ones.
	ListAPIKeys(ctx context.Context) ([]APIKey, error)

	// CreateAPIKey inserts a new API key and returns the assigned ID.
	CreateAPIKey(ctx context.Context, name, keyHash string) (int, error)

	// RevokeAPIKey marks an API key as revoked.
	RevokeAPIKey(ctx context.Context, keyID int) error

	// DeleteAPIKey permanently removes a revoked API key.
	DeleteAPIKey(ctx context.Context, keyID int) error

	// -- Admin auth -------------------------------------------------------------

	// GetAdminAuth returns the admin credentials row, or nil if no admin
	// has been bootstrapped yet.
	GetAdminAuth(ctx context.Context) (*AdminAuth, error)

	// UpsertAdminAuth creates or updates the admin password hash.
	// When isBootstrap is true, the password_is_bootstrap flag is set,
	// indicating that the initial environment-variable password is still
	// active. A manual password change should pass false to clear the flag.
	UpsertAdminAuth(ctx context.Context, passwordHash string, isBootstrap bool) error

	// InsertAdminAuditLog appends an entry to the admin audit log.
	InsertAdminAuditLog(ctx context.Context, entry *AdminAuditEntry) error

	// ListAdminAuditLog returns audit log entries, newest first.
	// limit controls how many entries to return (max 200).
	ListAdminAuditLog(ctx context.Context, limit int) ([]AdminAuditLogEntry, error)

	// -- Queue stats ------------------------------------------------------------

	// QueueStats returns summary counts for the refresh queue, grouped
	// by status.
	QueueStats(ctx context.Context) (*QueueStatsResult, error)

	// ListQueueJobs returns refresh queue jobs, newest first.
	ListQueueJobs(ctx context.Context, status string, limit int) ([]RefreshJob, error)

	// PurgeQueue removes all completed or errored jobs from the queue.
	PurgeQueue(ctx context.Context) (int, error)

	// UpdateQueueJobPriority changes the priority of a queued job.
	UpdateQueueJobPriority(ctx context.Context, jobID, priority int) error

	// RetryQueueJob moves a terminal or paused job back to pending.
	RetryQueueJob(ctx context.Context, jobID int) error

	// PauseQueueJob prevents a pending job from being dequeued.
	PauseQueueJob(ctx context.Context, jobID int) error

	// ResumeQueueJob moves a paused job back to pending.
	ResumeQueueJob(ctx context.Context, jobID int) error

	// ClearQueue removes queued jobs matching the given statuses.
	ClearQueue(ctx context.Context, statuses []string) (int, error)

	// -- Dashboard stats --------------------------------------------------------

	// DashboardStats returns aggregate counts for the dashboard:
	// total unique packages scanned, total findings in DB, counts by severity.
	DashboardStats(ctx context.Context) (*DashboardStatsResult, error)

	// -- Lifecycle --------------------------------------------------------------

	// Close releases all resources held by the store.
	Close() error
}

// ---------------------------------------------------------------------------
// Data transfer types used by the Store interface.
// These mirror the database tables and are distinct from the domain types
// that face outward (API, CLI).
// ---------------------------------------------------------------------------

// PackageQuery identifies a single package for batch lookup operations.
type PackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

// Vulnerability represents a full vulnerability record including related
// aliases, sources, references, and affected packages.
type Vulnerability struct {
	ID             string     `json:"id"`
	Summary        string     `json:"summary"`
	Details        string     `json:"details"`
	Severity       string     `json:"severity"`
	CVSSScore      *float64   `json:"cvss_score,omitempty"`
	EPSSScore      *float64   `json:"epss_score,omitempty"`
	EPSSPercentile *float64   `json:"epss_percentile,omitempty"`
	CISAKEV        bool       `json:"cisa_kev"`
	ExploitExists  bool       `json:"exploit_exists"`
	Published      time.Time  `json:"published"`
	Modified       time.Time  `json:"modified"`
	Withdrawn      *time.Time `json:"withdrawn,omitempty"`

	Aliases          []VulnerabilityAlias     `json:"aliases,omitempty"`
	Sources          []VulnerabilitySource    `json:"sources,omitempty"`
	References       []VulnerabilityReference `json:"references,omitempty"`
	AffectedPackages []AffectedPackage        `json:"affected_packages,omitempty"`
}

// VulnerabilityAlias is one alternate identifier for a vulnerability.
type VulnerabilityAlias struct {
	AliasID string `json:"alias_id"`
}

// VulnerabilitySource records where a vulnerability was ingested from.
type VulnerabilitySource struct {
	Source   string          `json:"source"`
	SourceID string          `json:"source_id"`
	URL      string          `json:"url"`
	RawJSON  json.RawMessage `json:"raw_json,omitempty"`
}

// VulnerabilityReference is a link associated with a vulnerability.
type VulnerabilityReference struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

// AffectedPackage identifies one ecosystem/name pair affected by a
// vulnerability, together with version constraints.
type AffectedPackage struct {
	Ecosystem        string          `json:"ecosystem"`
	Name             string          `json:"name"`
	VersionRanges    json.RawMessage `json:"version_ranges"`    // JSONB
	VersionsAffected json.RawMessage `json:"versions_affected"` // JSONB
}

// MaliciousFinding is a malicious package record (DE-14).
type MaliciousFinding struct {
	ID            string          `json:"id"`
	Ecosystem     string          `json:"ecosystem"`
	Name          string          `json:"name"`
	Versions      json.RawMessage `json:"versions,omitempty"` // JSONB, nil = all versions
	Source        string          `json:"source"`
	RiskType      string          `json:"risk_type"`
	Severity      string          `json:"severity"`
	Summary       string          `json:"summary"`
	Description   string          `json:"description"`
	ReferenceURLs json.RawMessage `json:"reference_urls,omitempty"` // JSONB
	OriginRef     string          `json:"origin_ref"`
	Published     *time.Time      `json:"published,omitempty"`
	CreatedBy     string          `json:"created_by"`
}

// ManualAdvisory is the admin-facing model for operator-managed advisories.
type ManualAdvisory struct {
	ID          string
	FindingType string
	Ecosystem   string
	Name        string
	Severity    string
	RiskType    string
	Summary     string
	Description string
	UpdatedAt   time.Time
}

// FeedSyncStatus records the sync state for one feed.
type FeedSyncStatus struct {
	FeedName         string          `json:"feed_name"`
	LastSyncAt       *time.Time      `json:"last_sync_at,omitempty"`
	LastSyncDuration *time.Duration  `json:"last_sync_duration,omitempty"`
	LastSyncStatus   string          `json:"last_sync_status"`
	LastError        string          `json:"last_error"`
	EntriesSynced    int             `json:"entries_synced"`
	EntriesTotal     int             `json:"entries_total"`
	LastEtag         string          `json:"last_etag"`
	LastCommitHash   string          `json:"last_commit_hash"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
}

// FeedConfig is one persisted admin override for a feed.
type FeedConfig struct {
	FeedName     string
	Enabled      bool
	Mode         string
	SyncInterval *time.Duration
	APIKey       string
	UpdatedAt    time.Time
}

// SystemSettings stores admin-managed server-level settings.
type SystemSettings struct {
	BlockThreshold     string
	RateLimitPerMinute int
	RateLimitBurst     int
	UpdatedAt          time.Time
}

// RefreshJob is one entry in the refresh queue.
type RefreshJob struct {
	ID          int
	Ecosystem   string
	Name        string
	Source      string
	Priority    int
	Status      string
	RequestedAt time.Time
	ProcessedAt *time.Time
	Error       string
}

// PackageCheckStatus tracks the last check for a package from an async
// source (e.g. socket.dev).
type PackageCheckStatus struct {
	Ecosystem     string
	Name          string
	Source        string
	LastCheckedAt *time.Time
	NextCheckAt   *time.Time
	CheckCount    int
	LastResult    json.RawMessage
}

// ScanLogEntry records metadata about a completed scan.
type ScanLogEntry struct {
	ScanID        string
	RepoName      string
	Branch        string
	Commit        string
	ScannedAt     time.Time
	PackagesCount int
	FindingsCount int
	DurationMs    int
	ClientIP      string
	UserAgent     string
}

// RecentVulnerability is a summary row for recently published vulnerabilities.
type RecentVulnerability struct {
	ID          string
	Summary     string
	Severity    string
	Ecosystem   string
	Name        string
	Affected    string
	PublishedAt time.Time
}

// APIKey represents a stored API key (DE-12).
type APIKey struct {
	ID         int
	Name       string
	KeyHash    string
	CreatedAt  time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

// AdminAuth is the single-row admin credentials.
type AdminAuth struct {
	PasswordHash        string
	PasswordIsBootstrap bool
	CreatedAt           time.Time
	PasswordChangedAt   *time.Time
	LastLoginAt         *time.Time
}

// AdminAuditEntry is one row in the admin audit log.
type AdminAuditEntry struct {
	Action  string
	Details json.RawMessage
	IP      string
}

// EPSSEntry holds EPSS score data for a single CVE, used by SetEPSSScores.
type EPSSEntry struct {
	CVEID      string  `json:"cve_id"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// VulnCheckEntry holds enrichment data from VulnCheck for a single CVE.
type VulnCheckEntry struct {
	CVEID         string          `json:"cve_id"`
	CVSSScore     *float64        `json:"cvss_score,omitempty"`
	ExploitExists bool            `json:"exploit_exists"`
	SourceURL     string          `json:"source_url"`
	RawJSON       json.RawMessage `json:"raw_json,omitempty"`
}

// DailyScanStats holds per-day aggregate counts for scan trends.
type DailyScanStats struct {
	Date          time.Time
	ScanCount     int
	FindingsCount int
}

// PackageSearchResult is one row from a package search query.
type PackageSearchResult struct {
	Ecosystem          string
	Name               string
	FindingsCount      int
	VulnerabilityCount int
	VulnerabilityIDs   string // comma-separated advisory IDs
	Sources            string // comma-separated list of feed sources
}

// PackageSearchParams describes the optional filters for package search.
type PackageSearchParams struct {
	Query       string
	Severity    string
	FindingType string
	Limit       int
}

// AdminAuditLogEntry is a read-model for audit log entries, including the
// auto-generated ID and timestamp.
type AdminAuditLogEntry struct {
	ID        int
	Action    string
	Details   json.RawMessage
	IP        string
	CreatedAt time.Time
}

// QueueStatsResult holds aggregate counts for the refresh queue.
type QueueStatsResult struct {
	Pending    int
	Processing int
	Done       int
	Error      int
	Paused     int
}

// DashboardStatsResult holds aggregate counts for the web dashboard.
type DashboardStatsResult struct {
	TotalPackages        int
	TotalVulnerabilities int
	TotalMalicious       int
	BySeverity           map[string]int
}

// ScanTotals holds cumulative scan-log counters used by telemetry.
type ScanTotals struct {
	PackagesScanned int
	Findings        int
}

// DBPoolStats holds PostgreSQL connection pool gauges used by telemetry.
type DBPoolStats struct {
	MaxConns          int32
	AcquiredConns     int32
	IdleConns         int32
	ConstructingConns int32
}

// UnknownCVEAlias pairs a vulnerability ID with one of its CVE aliases.
// Used by the NVD syncer to look up CVSS scores for vulnerabilities that
// have UNKNOWN severity.
type UnknownCVEAlias struct {
	VulnerabilityID string
	CVEID           string
}
