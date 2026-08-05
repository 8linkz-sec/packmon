// Package db defines the Store interface for all database operations
// used by the Packmon server and feed sync pipeline.
package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/logsafe"
)

// ErrAdminAuditLog marks failures that prevented a required admin audit row
// from being persisted.
var ErrAdminAuditLog = errors.New("admin audit log write failed")

// ErrAdminAuthConflict marks an admin password change whose checked password
// hash no longer matches the stored credential row.
var ErrAdminAuthConflict = errors.New("admin auth conflict")

// ErrConflict marks an optimistic-concurrency conflict where a write was based
// on an older row revision than the one currently stored.
var ErrConflict = errors.New("write conflict")

// ErrSourceScopedDeleteUnsupported marks stores that cannot safely delete one
// source's evidence without deleting another source's canonical finding.
var ErrSourceScopedDeleteUnsupported = errors.New("source-scoped delete unsupported")

// ErrSourceScopedDeleteSourceRequired marks source-scoped delete requests that
// omit the source and therefore cannot be safely scoped.
var ErrSourceScopedDeleteSourceRequired = errors.New("source-scoped delete requires source")

// Store is the central server-side persistence interface. It is implemented by
// the PostgreSQL store and the in-memory development noop store. The local
// SQLite client database intentionally uses smaller scanner/sync/history
// interfaces instead of satisfying this broad server boundary.
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

	// FindReputationFindingsBatch returns cached package reputation findings
	// for exact package versions from one reputation source.
	FindReputationFindingsBatch(ctx context.Context, packages []PackageQuery, source string) ([]domain.Finding, error)

	// FindLifecycleFindingsBatch returns lifecycle/EOL findings for all
	// packages using the cached lifecycle feed data.
	FindLifecycleFindingsBatch(ctx context.Context, packages []PackageQuery, now time.Time) ([]domain.Finding, error)

	// -- Vulnerability writes (feed sync) ---------------------------------------

	// UpsertVulnerability inserts or updates a vulnerability and its aliases,
	// sources, references, and affected packages in a single transaction.
	UpsertVulnerability(ctx context.Context, vuln *Vulnerability) error

	// UpsertMaliciousFinding inserts or updates a malicious finding.
	UpsertMaliciousFinding(ctx context.Context, mf *MaliciousFinding) error

	// ImportVulnerabilityFeedWithAudit atomically applies a vulnerability feed
	// import and writes the required admin audit row.
	ImportVulnerabilityFeedWithAudit(ctx context.Context, feed string, items []Vulnerability, deleteIDs []string, status *FeedSyncStatus, audit FeedImportAuditBuilder) (imported, deleted int, err error)

	// ImportMaliciousFeedWithAudit atomically applies a malicious-package feed
	// import and writes the required admin audit row.
	ImportMaliciousFeedWithAudit(ctx context.Context, feed string, items []MaliciousFinding, deleteIDs []string, status *FeedSyncStatus, audit FeedImportAuditBuilder) (imported, deleted int, err error)

	// MarkPackageReputationDue ensures a package version has a due reputation
	// cache row. It returns true when a worker should be queued.
	MarkPackageReputationDue(ctx context.Context, rep *PackageReputation) (queued bool, err error)

	// ListDuePackageReputations returns due reputation rows for one package.
	ListDuePackageReputations(ctx context.Context, ecosystem, name, source string, limit int) ([]PackageReputation, error)

	// UpsertPackageReputation inserts or updates a package reputation cache row.
	UpsertPackageReputation(ctx context.Context, rep *PackageReputation) error

	// ReplaceLifecycleProducts atomically applies a complete lifecycle product
	// snapshot and removes cached lifecycle products absent from that snapshot.
	ReplaceLifecycleProducts(ctx context.Context, products []LifecycleProduct) (deleted int, err error)

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

	// UpsertManualAdvisoryWithAudit creates or updates an operator-managed
	// advisory atomically with its admin audit entry.
	UpsertManualAdvisoryWithAudit(ctx context.Context, advisory *ManualAdvisory, audit *AdminAuditEntry) error

	// DeleteManualAdvisory removes an operator-managed advisory from whichever
	// backing table owns it. Feed-sourced advisories must not be removed.
	DeleteManualAdvisory(ctx context.Context, id string) error

	// DeleteManualAdvisoryWithAudit removes an operator-managed advisory
	// atomically with its admin audit entry.
	DeleteManualAdvisoryWithAudit(ctx context.Context, id string, audit *AdminAuditEntry) error

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

	// ReplaceCISAKEV atomically applies a complete CISA KEV snapshot and clears
	// flags for vulnerabilities not present in the snapshot.
	ReplaceCISAKEV(ctx context.Context, cveIDs []string) (updated, cleared int, err error)

	// SetEPSSScores updates the epss_score and epss_percentile for the given
	// CVEs. Each entry in the slice maps a CVE ID to its scores. IDs not
	// present in the vulnerabilities table are silently ignored.
	SetEPSSScores(ctx context.Context, scores []EPSSEntry) (updated int, err error)

	// ReplaceEPSSScores atomically applies a complete EPSS score snapshot and
	// clears EPSS values for vulnerabilities not present in the snapshot.
	ReplaceEPSSScores(ctx context.Context, scores []EPSSEntry) (updated, cleared int, err error)

	// EnrichVulnCheck applies VulnCheck-sourced enrichment data to existing
	// vulnerabilities: CVSS scores, exploit-exists flags, and source records.
	EnrichVulnCheck(ctx context.Context, entries []VulnCheckEntry) (updated int, err error)

	// ImportVulnCheckWithAudit applies VulnCheck enrichment data atomically
	// with feed status and the required admin audit row.
	ImportVulnCheckWithAudit(ctx context.Context, feed string, entries []VulnCheckEntry, status *FeedSyncStatus, audit FeedImportAuditBuilder) (updated int, err error)

	// ImportCISAKEVWithAudit applies incremental CISA KEV enrichment data
	// atomically with feed status and the required admin audit row.
	ImportCISAKEVWithAudit(ctx context.Context, feed string, cveIDs []string, status *FeedSyncStatus, audit FeedImportAuditBuilder) (updated int, err error)

	// ReplaceCISAKEVWithAudit applies a complete CISA KEV snapshot atomically
	// with feed status and the required admin audit row.
	ReplaceCISAKEVWithAudit(ctx context.Context, feed string, cveIDs []string, status *FeedSyncStatus, audit FeedImportAuditBuilder) (updated, cleared int, err error)

	// ImportEPSSWithAudit applies an EPSS score snapshot atomically with feed
	// status and the required admin audit row.
	ImportEPSSWithAudit(ctx context.Context, feed string, scores []EPSSEntry, status *FeedSyncStatus, audit FeedImportAuditBuilder) (updated, cleared int, err error)

	// FindUnknownSeverityCVEIDs returns a bounded page of distinct CVE IDs
	// linked to vulnerabilities whose severity still needs CVSS enrichment.
	// Results are ordered by CVE ID and use afterCVE as a keyset cursor.
	FindUnknownSeverityCVEIDs(ctx context.Context, afterCVE string, limit int) ([]string, error)

	// UpdateSeverityByCVE updates the severity and CVSS score for a
	// vulnerability identified by its CVE alias. Only unresolved rows are
	// updated to avoid overwriting richer data.
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

	// UpsertFeedConfigWithAudit creates or updates a persisted feed
	// configuration override atomically with its admin audit entry.
	UpsertFeedConfigWithAudit(ctx context.Context, cfg *FeedConfig, audit *AdminAuditEntry) error

	// DeleteFeedConfig removes a persisted feed configuration override so the
	// server falls back to runtime defaults again.
	DeleteFeedConfig(ctx context.Context, feedName string) error

	// DeleteFeedConfigWithAudit removes a persisted feed configuration
	// override atomically with its admin audit entry. When expectedUpdatedAt is
	// non-nil, the delete is rejected if the stored row revision differs.
	DeleteFeedConfigWithAudit(ctx context.Context, feedName string, expectedUpdatedAt *time.Time, audit *AdminAuditEntry) error

	// ListFeedConfigs returns all persisted feed configuration overrides.
	ListFeedConfigs(ctx context.Context) ([]FeedConfig, error)

	// -- System settings -------------------------------------------------------

	// GetSystemSettings returns persisted server-level admin settings, or nil
	// if runtime defaults are still in use.
	GetSystemSettings(ctx context.Context) (*SystemSettings, error)

	// UpsertSystemSettings creates or updates persisted server-level admin
	// settings.
	UpsertSystemSettings(ctx context.Context, settings *SystemSettings) error

	// UpsertSystemSettingsWithAudit creates or updates persisted server-level
	// admin settings atomically with its admin audit entry.
	UpsertSystemSettingsWithAudit(ctx context.Context, settings *SystemSettings, audit *AdminAuditEntry) error

	// -- Refresh queue ----------------------------------------------------------

	// EnqueueRefresh adds a job to the refresh queue. If an identical
	// pending/processing job already exists, the priority is raised if the
	// new priority is higher (lower number). Returns whether a new job was
	// created and the current queue position.
	EnqueueRefresh(ctx context.Context, job *RefreshJob) (created bool, position int, err error)

	// EnqueueRefreshWithAudit adds or reprioritizes a refresh job and writes
	// the required admin audit row in the same store operation.
	EnqueueRefreshWithAudit(ctx context.Context, job *RefreshJob, audit RefreshEnqueueAuditBuilder) (created bool, position int, err error)

	// DequeueRefresh claims the next pending job for the given source,
	// ordered by priority (ascending) then requested_at (ascending).
	// Returns nil if the queue is empty.
	DequeueRefresh(ctx context.Context, source string) (*RefreshJob, error)

	// CompleteRefresh marks a queued job as done or errored without validating
	// a processing claim. Async workers must use CompleteClaimedRefresh.
	CompleteRefresh(ctx context.Context, jobID int, jobErr error) error

	// CompleteClaimedRefresh marks a queued job as done or errored only when
	// the row is still processing under the dequeued processed_at claim.
	CompleteClaimedRefresh(ctx context.Context, jobID int, claimedAt *time.Time, jobErr error) error

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

	// -- Retention pruning -----------------------------------------------------

	// PruneScanLogs removes scan_log rows older than the retention duration.
	PruneScanLogs(ctx context.Context, retention time.Duration) (int, error)

	// PruneAdminAuditLogs removes admin_audit_log rows older than the retention duration.
	PruneAdminAuditLogs(ctx context.Context, retention time.Duration) (int, error)

	// PruneRefreshQueue removes terminal refresh_queue rows older than the retention duration.
	PruneRefreshQueue(ctx context.Context, retention time.Duration) (int, error)

	// PrunePackageCheckStatus removes package_check_status rows older than the retention duration.
	PrunePackageCheckStatus(ctx context.Context, retention time.Duration) (int, error)

	// PrunePackageReputation removes non-finding package reputation cache rows older than the retention duration.
	PrunePackageReputation(ctx context.Context, source string, retention time.Duration) (int, error)

	// -- Scan log ---------------------------------------------------------------

	// InsertScanLog records a completed scan.
	InsertScanLog(ctx context.Context, entry *ScanLogEntry) error

	// GetScanLogByIdempotencyKey returns the scan log entry for a previously
	// used API idempotency key, or nil when the key has not been seen.
	GetScanLogByIdempotencyKey(ctx context.Context, key string) (*ScanLogEntry, error)

	// ExportSync returns a flattened server snapshot for local CLI sync.
	ExportSync(ctx context.Context, opts SyncExportOptions) (*SyncExport, error)

	// ListRecentScans returns scan log entries newest first. Limit controls how
	// many entries to return (max 100); offset skips newer entries.
	ListRecentScans(ctx context.Context, limit, offset int) ([]ScanLogEntry, error)

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
	// found or if the key has been revoked or expired.
	FindAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)

	// TouchAPIKeyLastUsed updates the last_used_at timestamp for a key.
	TouchAPIKeyLastUsed(ctx context.Context, keyID int) error

	// ListAPIKeys returns all API keys, including revoked and soft-deleted ones.
	ListAPIKeys(ctx context.Context) ([]APIKey, error)

	// CreateAPIKey inserts a new API key and returns the assigned ID.
	CreateAPIKey(ctx context.Context, name, keyHash string, expiresAt *time.Time) (int, error)

	// CreateAPIKeyWithAudit inserts a new API key atomically with its admin
	// audit entry and returns the assigned ID.
	CreateAPIKeyWithAudit(ctx context.Context, name, keyHash string, expiresAt *time.Time, audit *AdminAuditEntry) (int, error)

	// RevokeAPIKey marks an API key as revoked.
	RevokeAPIKey(ctx context.Context, keyID int) error

	// RevokeAPIKeyWithAudit marks an API key as revoked atomically with its
	// admin audit entry.
	RevokeAPIKeyWithAudit(ctx context.Context, keyID int, audit *AdminAuditEntry) error

	// DeleteAPIKey permanently removes a revoked API key row; scan_log rows
	// keep their history with the key reference cleared.
	DeleteAPIKey(ctx context.Context, keyID int) error

	// DeleteAPIKeyWithAudit permanently removes a revoked API key row
	// atomically with its admin audit entry.
	DeleteAPIKeyWithAudit(ctx context.Context, keyID int, audit *AdminAuditEntry) error

	// -- Admin auth -------------------------------------------------------------

	// GetAdminAuth returns the admin credentials row, or nil if no admin
	// has been bootstrapped yet.
	GetAdminAuth(ctx context.Context) (*AdminAuth, error)

	// UpsertAdminAuth creates or updates the admin password hash.
	// When isBootstrap is true, the password_is_bootstrap flag is set,
	// indicating that the initial environment-variable password is still
	// active. A manual password change should pass false to clear the flag.
	UpsertAdminAuth(ctx context.Context, passwordHash string, isBootstrap bool) error

	// UpsertAdminAuthWithAudit creates or updates the admin password hash
	// atomically with its admin audit entry.
	UpsertAdminAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *AdminAuditEntry) error

	// ChangeAdminPasswordWithAudit changes the admin password only when the
	// stored hash still equals expectedOldHash, and writes the audit entry in
	// the same transaction.
	ChangeAdminPasswordWithAudit(ctx context.Context, newHash, expectedOldHash string, audit *AdminAuditEntry) error

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

	// PurgeQueueWithAudit removes all completed or errored jobs atomically with
	// its admin audit entry.
	PurgeQueueWithAudit(ctx context.Context, audit *AdminAuditEntry) (int, error)

	// UpdateQueueJobPriority changes the priority of a queued job.
	UpdateQueueJobPriority(ctx context.Context, jobID, priority int) error

	// UpdateQueueJobPriorityWithAudit changes the priority of a queued job
	// atomically with its admin audit entry.
	UpdateQueueJobPriorityWithAudit(ctx context.Context, jobID, priority int, audit *AdminAuditEntry) error

	// RetryQueueJob moves a terminal or paused job back to pending.
	RetryQueueJob(ctx context.Context, jobID int) error

	// RetryQueueJobWithAudit moves a terminal or paused job back to pending
	// atomically with its admin audit entry.
	RetryQueueJobWithAudit(ctx context.Context, jobID int, audit *AdminAuditEntry) error

	// PauseQueueJob prevents a pending job from being dequeued.
	PauseQueueJob(ctx context.Context, jobID int) error

	// PauseQueueJobWithAudit prevents a pending job from being dequeued
	// atomically with its admin audit entry.
	PauseQueueJobWithAudit(ctx context.Context, jobID int, audit *AdminAuditEntry) error

	// ResumeQueueJob moves a paused job back to pending.
	ResumeQueueJob(ctx context.Context, jobID int) error

	// ResumeQueueJobWithAudit moves a paused job back to pending atomically
	// with its admin audit entry.
	ResumeQueueJobWithAudit(ctx context.Context, jobID int, audit *AdminAuditEntry) error

	// ClearQueue removes queued jobs matching the given statuses.
	ClearQueue(ctx context.Context, statuses []string) (int, error)

	// ClearQueueWithAudit removes queued jobs matching the given statuses
	// atomically with its admin audit entry.
	ClearQueueWithAudit(ctx context.Context, statuses []string, audit *AdminAuditEntry) (int, error)

	// -- Dashboard stats --------------------------------------------------------

	// DashboardStats returns aggregate counts for the dashboard:
	// total unique packages scanned, total findings in DB, counts by severity.
	DashboardStats(ctx context.Context) (*DashboardStatsResult, error)

	// -- Lifecycle --------------------------------------------------------------

	// Close releases all resources held by the store.
	Close() error
}

// SourceVulnerabilityDeleter is implemented by stores that can withdraw one
// feed source without withdrawing the whole canonical advisory while another
// source still backs it.
type SourceVulnerabilityDeleter interface {
	DeleteVulnerabilityForSource(ctx context.Context, id, source string) error
}

// SourceMaliciousFindingDeleter is implemented by stores that can withdraw one
// feed source without touching malicious findings owned by another source.
type SourceMaliciousFindingDeleter interface {
	DeleteMaliciousFindingForSource(ctx context.Context, id, source string) error
}

// SourceMaliciousFindingStalePruner is implemented by stores that can withdraw
// active malicious findings for one source when they were not refreshed during
// a successful feed sync.
type SourceMaliciousFindingStalePruner interface {
	PruneMaliciousFindingsForSourceUpdatedBefore(ctx context.Context, source string, updatedBefore time.Time) (int, error)
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

const (
	// ReputationSourceReversingLabs identifies cached ReversingLabs package
	// reputation rows.
	ReputationSourceReversingLabs = "reversinglabs"
)

// ReputationReadSource describes a package reputation source included in
// stable API and web read paths.
type ReputationReadSource struct {
	Source string
	Label  string
}

var reputationReadSources = []ReputationReadSource{
	{Source: ReputationSourceReversingLabs, Label: "ReversingLabs"},
}

// ReputationReadSources returns the package reputation sources exposed by API
// and web read paths.
func ReputationReadSources() []ReputationReadSource {
	out := make([]ReputationReadSource, len(reputationReadSources))
	copy(out, reputationReadSources)
	return out
}

// ReputationReadSourceLabel returns the display label for a configured
// reputation read source.
func ReputationReadSourceLabel(source string) (string, bool) {
	source = strings.ToLower(strings.TrimSpace(source))
	for _, descriptor := range reputationReadSources {
		if source == strings.ToLower(descriptor.Source) {
			return descriptor.Label, true
		}
	}
	return "", false
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
	VersionRanges json.RawMessage `json:"version_ranges,omitempty"` // JSONB OSV ranges, nil = all versions when Versions is nil
	Versions      json.RawMessage `json:"versions,omitempty"`       // JSONB exact versions, nil = all versions when VersionRanges is nil
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

// PackageReputation is a normalized cache row from a package reputation source.
type PackageReputation struct {
	Ecosystem     string
	Name          string
	Version       string
	Source        string
	Status        string
	Severity      string
	Summary       string
	Description   string
	ReferenceURLs json.RawMessage
	Evidence      json.RawMessage
	LastCheckedAt *time.Time
	NextCheckAt   *time.Time
	LastError     string
	UpdatedAt     time.Time
}

// LifecycleProduct is one product from a package lifecycle feed.
type LifecycleProduct struct {
	ProductSlug string
	Name        string
	Category    string
	Identifiers json.RawMessage
	Raw         json.RawMessage
	Releases    []LifecycleRelease
	PackageMaps []LifecyclePackageMap
}

// LifecycleRelease is one support/lifecycle cycle for a lifecycle product.
type LifecycleRelease struct {
	ProductSlug      string
	Cycle            string
	Latest           string
	ReleaseDate      *time.Time
	IsLTS            bool
	LTSFrom          *time.Time
	IsEOAS           bool
	EOASFrom         *time.Time
	IsEOL            bool
	EOLFrom          *time.Time
	IsDiscontinued   bool
	DiscontinuedFrom *time.Time
	IsEOES           *bool
	EOESFrom         *time.Time
	IsMaintained     bool
	Raw              json.RawMessage
}

// LifecyclePackageMap links a package identity to a lifecycle product.
type LifecyclePackageMap struct {
	Ecosystem     string
	Name          string
	ProductSlug   string
	PURLType      string
	PURLNamespace string
	PURLName      string
	Source        string
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
	LastETag         string          `json:"last_etag"`
	LastCommitHash   string          `json:"last_commit_hash"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
	UpdatedAt        time.Time       `json:"updated_at,omitempty"`
}

// FeedConfig is one persisted admin override for a feed.
type FeedConfig struct {
	FeedName          string
	Enabled           bool
	Mode              string
	SyncInterval      *time.Duration
	APIKey            string
	APIKeyEncrypted   bool
	UpdatedAt         time.Time
	ExpectedUpdatedAt *time.Time
}

// SystemSettings stores admin-managed server-level settings.
type SystemSettings struct {
	BlockThreshold      string
	RateLimitPerMinute  int
	RateLimitBurst      int
	ScanLogRetention    time.Duration
	AdminAuditRetention time.Duration
	UpdatedAt           time.Time
	ExpectedUpdatedAt   *time.Time
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

const (
	RefreshPriorityManual         = 0
	RefreshPriorityUnknownPackage = 1
	RefreshPriorityKnownFinding   = 2
	RefreshPriorityNormal         = 3
)

// RefreshPriorityOption is one supported refresh queue priority value.
type RefreshPriorityOption struct {
	Value int
	Label string
}

// RefreshPriorityOptions returns the supported refresh priority scale ordered
// from highest priority to lowest priority. Labels name the urgency level
// first (what an operator selects) and keep the automatic assignment origin
// in parentheses, so the queue UI does not read like a package property such
// as severity.
func RefreshPriorityOptions() []RefreshPriorityOption {
	return []RefreshPriorityOption{
		{Value: RefreshPriorityManual, Label: "0 - Immediate (manual trigger)"},
		{Value: RefreshPriorityUnknownPackage, Label: "1 - High (unknown packages)"},
		{Value: RefreshPriorityKnownFinding, Label: "2 - Medium (known findings)"},
		{Value: RefreshPriorityNormal, Label: "3 - Normal (scheduled re-check)"},
	}
}

// ValidRefreshPriority reports whether priority is in the supported queue
// priority range.
func ValidRefreshPriority(priority int) bool {
	for _, option := range RefreshPriorityOptions() {
		if priority == option.Value {
			return true
		}
	}
	return false
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
	ScanID                string
	RepoName              string
	ScannedAt             time.Time
	PackagesCount         int
	FindingsCount         int
	DurationMs            int
	ClientIP              string
	ClientVersion         string
	APIKeyID              int
	APIKeyName            string
	CorrelationID         string
	IdempotencyKey        string
	RequestDigest         string
	ResultDigest          string
	FindingsBlocking      bool
	BlockThreshold        string
	FeedStatus            string
	FeedVersions          map[string]string
	FindingIDs            []string
	FindingSeverities     []string
	ManualAdvisoriesCount int
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
	ExpiresAt  *time.Time
	DeletedAt  *time.Time
}

// IsExpired reports whether the API key has an expiry timestamp at or before now.
func (k APIKey) IsExpired(now time.Time) bool {
	return k.ExpiresAt != nil && !k.ExpiresAt.After(now)
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
	Action        string
	Details       json.RawMessage
	IP            string
	CorrelationID string
}

// FeedImportAuditBuilder produces the audit entry for an audited feed import,
// given the counts that import produced.
//
// It returns a value, not a pointer, and that is the point: a builder cannot
// decline to produce an entry. "No audit wanted" is expressed by passing a nil
// builder, which every audited store method already checks -- so a non-nil
// builder yielding nothing was never a meaningful state, only a way to panic
// inside the import transaction. See TESTING.md watch-list item 3a.
type FeedImportAuditBuilder func(imported, deleted int) AdminAuditEntry

// RefreshEnqueueAuditBuilder is the same contract for an audited queue enqueue,
// which reports whether the job was newly created and at which queue position.
type RefreshEnqueueAuditBuilder func(created bool, position int) AdminAuditEntry

// SetAdminAuditDetail updates one string field in an admin audit entry's JSON
// details map.
func SetAdminAuditDetail(entry *AdminAuditEntry, key, value string) error {
	if entry == nil {
		return nil
	}
	details := map[string]string{}
	if len(entry.Details) > 0 {
		if err := json.Unmarshal(entry.Details, &details); err != nil {
			return err
		}
	}
	if details == nil {
		details = map[string]string{}
	}
	details[key] = value
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	entry.Details = raw
	return nil
}

type adminAuditQueueJob struct {
	ID          int    `json:"id"`
	Ecosystem   string `json:"ecosystem"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Priority    int    `json:"priority"`
	Status      string `json:"status"`
	RequestedAt string `json:"requested_at"`
	ProcessedAt string `json:"processed_at"`
	Error       string `json:"error"`
}

// SetAdminAuditQueueJobsDetail stores refresh queue job identities in a string
// audit detail value so destructive queue actions keep reviewable evidence.
func SetAdminAuditQueueJobsDetail(entry *AdminAuditEntry, key string, jobs []RefreshJob) error {
	rows := make([]adminAuditQueueJob, 0, len(jobs))
	for _, job := range jobs {
		row := adminAuditQueueJob{
			ID:        job.ID,
			Ecosystem: job.Ecosystem,
			Name:      job.Name,
			Source:    job.Source,
			Priority:  job.Priority,
			Status:    job.Status,
			Error:     logsafe.BoundedDiagnosticValue(job.Error, 512),
		}
		if !job.RequestedAt.IsZero() {
			row.RequestedAt = job.RequestedAt.UTC().Format(time.RFC3339Nano)
		}
		if job.ProcessedAt != nil && !job.ProcessedAt.IsZero() {
			row.ProcessedAt = job.ProcessedAt.UTC().Format(time.RFC3339Nano)
		}
		rows = append(rows, row)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	return SetAdminAuditDetail(entry, key, string(raw))
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
	Version            string
	FindingsCount      int
	VulnerabilityCount int
	VulnerabilityIDs   string // comma-separated advisory IDs
	FindingTypes       string // comma-separated finding type labels/keys
	Sources            string // comma-separated list of feed sources
}

// PackageSearchParams describes the optional filters for package search.
type PackageSearchParams struct {
	Query       string
	Severity    string
	FindingType string
	Limit       int
	Offset      int
}

// AdminAuditLogEntry is a read-model for audit log entries, including the
// auto-generated ID and timestamp.
type AdminAuditLogEntry struct {
	ID              int
	Action          string
	Details         json.RawMessage
	IP              string
	CorrelationID   string
	CreatedAt       time.Time
	PreviousDigest  string
	RowDigest       string
	IntegrityStatus string
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
	TotalSupplyChainRisk int
	TotalLifecycle       int
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
	AcquireCount      int64
	AcquireDuration   time.Duration
	CanceledAcquires  int64
	EmptyAcquires     int64
	EmptyAcquireWait  time.Duration
}
