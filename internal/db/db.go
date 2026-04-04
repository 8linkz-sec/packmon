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
	// given ecosystem and package name.
	FindMalicious(ctx context.Context, ecosystem, name string) ([]domain.Finding, error)

	// -- Vulnerability writes (feed sync) ---------------------------------------

	// UpsertVulnerability inserts or updates a vulnerability and its aliases,
	// sources, references, and affected packages in a single transaction.
	UpsertVulnerability(ctx context.Context, vuln *Vulnerability) error

	// UpsertMaliciousFinding inserts or updates a malicious finding.
	UpsertMaliciousFinding(ctx context.Context, mf *MaliciousFinding) error

	// DeleteVulnerability removes a vulnerability and all related rows.
	DeleteVulnerability(ctx context.Context, id string) error

	// DeleteMaliciousFinding removes a malicious finding by id.
	DeleteMaliciousFinding(ctx context.Context, id string) error

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

	// -- Feed sync status -------------------------------------------------------

	// GetFeedSyncStatus returns the sync state for the named feed.
	GetFeedSyncStatus(ctx context.Context, feedName string) (*FeedSyncStatus, error)

	// UpsertFeedSyncStatus creates or updates the sync state for a feed.
	UpsertFeedSyncStatus(ctx context.Context, status *FeedSyncStatus) error

	// ListFeedSyncStatuses returns sync state for all known feeds.
	ListFeedSyncStatuses(ctx context.Context) ([]FeedSyncStatus, error)

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

	// -- API keys ---------------------------------------------------------------

	// FindAPIKeyByHash looks up an API key by its hash. Returns nil if not
	// found or if the key has been revoked.
	FindAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)

	// TouchAPIKeyLastUsed updates the last_used_at timestamp for a key.
	TouchAPIKeyLastUsed(ctx context.Context, keyID int) error

	// -- Admin auth -------------------------------------------------------------

	// GetAdminAuth returns the admin credentials row, or nil if no admin
	// has been bootstrapped yet.
	GetAdminAuth(ctx context.Context) (*AdminAuth, error)

	// UpsertAdminAuth creates or updates the admin password hash.
	UpsertAdminAuth(ctx context.Context, passwordHash string) error

	// InsertAdminAuditLog appends an entry to the admin audit log.
	InsertAdminAuditLog(ctx context.Context, entry *AdminAuditEntry) error

	// -- Lifecycle --------------------------------------------------------------

	// Close releases all resources held by the store.
	Close() error
}

// ---------------------------------------------------------------------------
// Data transfer types used by the Store interface.
// These mirror the database tables and are distinct from the domain types
// that face outward (API, CLI).
// ---------------------------------------------------------------------------

// Vulnerability represents a full vulnerability record including related
// aliases, sources, references, and affected packages.
type Vulnerability struct {
	ID             string
	Summary        string
	Details        string
	Severity       string
	CVSSScore      *float64
	EPSSScore      *float64
	EPSSPercentile *float64
	CISAKEV        bool
	ExploitExists  bool
	Published      time.Time
	Modified       time.Time
	Withdrawn      *time.Time

	Aliases          []VulnerabilityAlias
	Sources          []VulnerabilitySource
	References       []VulnerabilityReference
	AffectedPackages []AffectedPackage
}

// VulnerabilityAlias is one alternate identifier for a vulnerability.
type VulnerabilityAlias struct {
	AliasID string
}

// VulnerabilitySource records where a vulnerability was ingested from.
type VulnerabilitySource struct {
	Source   string
	SourceID string
	URL      string
	RawJSON  json.RawMessage
}

// VulnerabilityReference is a link associated with a vulnerability.
type VulnerabilityReference struct {
	Type   string
	URL    string
	Source string
}

// AffectedPackage identifies one ecosystem/name pair affected by a
// vulnerability, together with version constraints.
type AffectedPackage struct {
	Ecosystem        string
	Name             string
	VersionRanges    json.RawMessage // JSONB
	VersionsAffected json.RawMessage // JSONB
}

// MaliciousFinding is a malicious package record (DE-14).
type MaliciousFinding struct {
	ID            string
	Ecosystem     string
	Name          string
	Versions      json.RawMessage // JSONB, nil = all versions
	Source        string
	RiskType      string
	Severity      string
	Summary       string
	Description   string
	ReferenceURLs json.RawMessage // JSONB
	OriginRef     string
	Published     *time.Time
	CreatedBy     string
}

// FeedSyncStatus records the sync state for one feed.
type FeedSyncStatus struct {
	FeedName         string
	LastSyncAt       *time.Time
	LastSyncDuration *time.Duration
	LastSyncStatus   string
	LastError        string
	EntriesSynced    int
	EntriesTotal     int
	LastEtag         string
	LastCommitHash   string
	Metadata         json.RawMessage
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
	PasswordHash      string
	CreatedAt         time.Time
	PasswordChangedAt *time.Time
	LastLoginAt       *time.Time
}

// AdminAuditEntry is one row in the admin audit log.
type AdminAuditEntry struct {
	Action  string
	Details json.RawMessage
	IP      string
}

// EPSSEntry holds EPSS score data for a single CVE, used by SetEPSSScores.
type EPSSEntry struct {
	CVEID      string
	Score      float64
	Percentile float64
}

// VulnCheckEntry holds enrichment data from VulnCheck for a single CVE.
type VulnCheckEntry struct {
	CVEID         string
	CVSSScore     *float64
	ExploitExists bool
	SourceURL     string
	RawJSON       json.RawMessage
}
