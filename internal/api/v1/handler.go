// Package v1 implements the HTTP handlers for the Packmon API v1.
package v1

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	feedhealth "github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/feed/reputation"
	"github.com/8linkz-sec/packmon/internal/feed/socket"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/packageid"
	"github.com/8linkz-sec/packmon/internal/requestctx"
	"github.com/8linkz-sec/packmon/internal/telemetry"
)

const (
	// maxPackagesPerCheck is the maximum number of packages in a single /check request.
	maxPackagesPerCheck = 5000

	// maxCheckPackageNameLength and maxCheckPackageVersionLength bound the
	// package coordinates accepted by /check and documented in OpenAPI.
	maxCheckPackageNameLength    = 512
	maxCheckPackageVersionLength = 256

	// maxRequestBody is derived from the /check contract so a valid
	// maxPackagesPerCheck request with maximum-size coordinates is not rejected
	// before package validation runs.
	maxRequestBody int64 = maxPackagesPerCheck*(maxCheckPackageNameLength+maxCheckPackageVersionLength+128) + 1024

	// scanLogInsertTimeout bounds audit logging in the response critical path
	// when the backing database is slow or locked.
	scanLogInsertTimeout = 500 * time.Millisecond

	idempotencyKeyHeader    = "Idempotency-Key"
	maxIdempotencyKeyLength = 128
)

// HeaderFeedImportSecret carries the dedicated feed-import secret required for
// mutating feed import requests in production.
const HeaderFeedImportSecret = "X-Packmon-Feed-Import-Secret" // #nosec G101 -- this is an HTTP header name, not a credential value.

// maxImportBody is the maximum allowed size for external feed import payloads.
const maxImportBody = 100 << 20

// maxImportStatusLastErrorLength bounds feed-import diagnostics persisted into
// the feed status row and reflected through status APIs.
const maxImportStatusLastErrorLength = 2048

const (
	maxImportStatusLastEtagLength       = 512
	maxImportStatusLastCommitHashLength = 128
	maxImportStatusMetadataLength       = 4096
)

// defaultBlockThreshold is the severity threshold above which findings block.
var defaultBlockThreshold = domain.SeverityCritical

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

type feedImportValidationError struct {
	message string
}

func (e *feedImportValidationError) Error() string {
	return e.message
}

func feedImportValidationErrorf(format string, args ...any) error {
	return &feedImportValidationError{message: fmt.Sprintf(format, args...)}
}

// Store is the API v1 persistence surface consumed by Handler.
type Store interface {
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)
	FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error)
	FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error)
	FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error)
	FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error)
	MarkPackageReputationDue(ctx context.Context, rep *db.PackageReputation) (bool, error)
	UpsertPackageReputation(ctx context.Context, rep *db.PackageReputation) error
	ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error)
	EnqueueRefresh(ctx context.Context, job *db.RefreshJob) (bool, int, error)
	InsertScanLog(ctx context.Context, entry *db.ScanLogEntry) error
}

type vulnerabilityFeedImporter interface {
	ImportVulnerabilityFeed(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus) (imported, deleted int, err error)
}

type maliciousFeedImporter interface {
	ImportMaliciousFeed(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus) (imported, deleted int, err error)
}

// Handler holds the dependencies for all API v1 HTTP handlers.
type Handler struct {
	store                Store
	logger               *slog.Logger
	blockThreshold       domain.Severity
	feedImportHandler    *FeedImportHandler
	reversingLabsEnabled atomic.Bool
	socketRefreshEnabled atomic.Bool
	reputationScheduler  *reputation.Scheduler
	backgroundCtx        context.Context
	// runtime, when set, supplies the block threshold dynamically so admin
	// changes take effect without a restart. It overrides blockThreshold.
	runtime *config.RuntimeSettings
}

type syncExporter interface {
	ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error)
}

type reputationPackageFinder interface {
	FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error)
}

type packageCheckStatusGetter interface {
	GetPackageCheckStatus(ctx context.Context, ecosystem, name, source string) (*db.PackageCheckStatus, error)
}

type scanLogIdempotencyLookup interface {
	GetScanLogByIdempotencyKey(ctx context.Context, key string) (*db.ScanLogEntry, error)
}

func deleteVulnerabilityForSource(ctx context.Context, store FeedImportStore, id, source string) error {
	if scoped, ok := store.(db.SourceVulnerabilityDeleter); ok {
		return scoped.DeleteVulnerabilityForSource(ctx, id, source)
	}
	return store.DeleteVulnerability(ctx, id)
}

func deleteMaliciousFindingForSource(ctx context.Context, store FeedImportStore, id, source string) error {
	if scoped, ok := store.(db.SourceMaliciousFindingDeleter); ok {
		return scoped.DeleteMaliciousFindingForSource(ctx, id, source)
	}
	return store.DeleteMaliciousFinding(ctx, id)
}

type feedSyncStatusInput struct {
	LastSyncAt         *time.Time      `json:"last_sync_at"`
	LastSyncDurationMs *int64          `json:"last_sync_duration_ms"`
	LastSyncStatus     string          `json:"last_sync_status"`
	LastError          string          `json:"last_error"`
	EntriesSynced      int             `json:"entries_synced"`
	EntriesTotal       int             `json:"entries_total"`
	LastEtag           string          `json:"last_etag"`
	LastCommitHash     string          `json:"last_commit_hash"`
	Metadata           json.RawMessage `json:"metadata"`
}

type vulnerabilityImportRequest struct {
	Vulnerabilities        []db.Vulnerability   `json:"vulnerabilities"`
	DeleteVulnerabilityIDs []string             `json:"delete_vulnerability_ids"`
	Status                 *feedSyncStatusInput `json:"status"`
}

type maliciousImportRequest struct {
	Malicious          []db.MaliciousFinding `json:"malicious"`
	DeleteMaliciousIDs []string              `json:"delete_malicious_ids"`
	Status             *feedSyncStatusInput  `json:"status"`
}

type epssImportRequest struct {
	Entries []db.EPSSEntry       `json:"entries"`
	Status  *feedSyncStatusInput `json:"status"`
}

type vulnCheckImportRequest struct {
	Entries []db.VulnCheckEntry  `json:"entries"`
	Status  *feedSyncStatusInput `json:"status"`
}

type cisaKEVImportRequest struct {
	CVEIDs       []string             `json:"cve_ids"`
	ClearMissing bool                 `json:"clear_missing"`
	Status       *feedSyncStatusInput `json:"status"`
}

type vulnerabilityImportVersionRange struct {
	Type   string                          `json:"type"`
	Events []vulnerabilityImportRangeEvent `json:"events"`
}

type vulnerabilityImportRangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type importResponse struct {
	Feed         string `json:"feed"`
	Imported     int    `json:"imported"`
	Deleted      int    `json:"deleted,omitempty"`
	EntriesTotal int    `json:"entries_total,omitempty"`
}

type syncVulnerabilityResponse struct {
	ID               string   `json:"id"`
	Ecosystem        string   `json:"ecosystem"`
	Name             string   `json:"name"`
	VersionRanges    string   `json:"version_ranges"`
	VersionsAffected string   `json:"versions_affected"`
	References       string   `json:"references"`
	Severity         string   `json:"severity"`
	CVSSScore        *float64 `json:"cvss_score"`
	EPSSScore        *float64 `json:"epss_score"`
	EPSSPercentile   *float64 `json:"epss_percentile"`
	CISAKEV          bool     `json:"cisa_kev"`
	Summary          string   `json:"summary"`
	Source           string   `json:"source"`
	Withdrawn        bool     `json:"withdrawn"`
}

type syncMaliciousResponse struct {
	ID            string `json:"id"`
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	VersionRanges string `json:"version_ranges"`
	Versions      string `json:"versions"`
	ReferenceURLs string `json:"reference_urls"`
	RiskType      string `json:"risk_type"`
	Severity      string `json:"severity"`
	Summary       string `json:"summary"`
	Source        string `json:"source"`
	Withdrawn     bool   `json:"withdrawn"`
}

type syncReputationResponse struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
	RiskType  string `json:"risk_type"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Withdrawn bool   `json:"withdrawn"`
}

type syncLifecycleResponse struct {
	ID               string  `json:"id"`
	Ecosystem        string  `json:"ecosystem"`
	Name             string  `json:"name"`
	ProductSlug      string  `json:"product_slug"`
	ProductLabel     string  `json:"product_label"`
	Cycle            string  `json:"cycle"`
	Latest           string  `json:"latest"`
	ReleaseDate      *string `json:"release_date"`
	IsLTS            bool    `json:"is_lts"`
	LTSFrom          *string `json:"lts_from"`
	IsEOAS           bool    `json:"is_eoas"`
	EOASFrom         *string `json:"eoas_from"`
	IsEOL            bool    `json:"is_eol"`
	EOLFrom          *string `json:"eol_from"`
	IsDiscontinued   bool    `json:"is_discontinued"`
	DiscontinuedFrom *string `json:"discontinued_from"`
	IsEOES           *bool   `json:"is_eoes"`
	EOESFrom         *string `json:"eoes_from"`
	IsMaintained     bool    `json:"is_maintained"`
	Withdrawn        bool    `json:"withdrawn"`
}

type syncResponsePayload struct {
	SyncedAt        string                      `json:"synced_at"`
	SyncedXID       uint64                      `json:"synced_xid,omitempty"`
	FeedStatus      string                      `json:"feed_status"`
	FeedVersions    map[string]string           `json:"feed_versions"`
	Vulnerabilities []syncVulnerabilityResponse `json:"vulnerabilities"`
	Malicious       []syncMaliciousResponse     `json:"malicious"`
	Reputation      []syncReputationResponse    `json:"reputation"`
	Lifecycle       []syncLifecycleResponse     `json:"lifecycle"`
	Truncated       bool                        `json:"truncated"`
	HasMore         bool                        `json:"has_more"`
	NextCursor      *db.SyncCursor              `json:"next_cursor,omitempty"`
}

// NewHandlerWithRuntime creates a Handler whose block threshold is read from
// the shared RuntimeSettings on every request, so admin changes apply without
// a restart. The initial value seeds the static fallback.
func NewHandlerWithRuntime(store Store, logger *slog.Logger, runtime *config.RuntimeSettings) *Handler {
	threshold := defaultBlockThreshold
	if runtime != nil {
		threshold = parseBlockThreshold(runtime.BlockThreshold())
	}
	h := NewHandlerWithBlockThreshold(store, logger, threshold)
	h.runtime = runtime
	return h
}

// effectiveBlockThreshold returns the threshold to apply right now, preferring
// the live RuntimeSettings value when configured.
func (h *Handler) effectiveBlockThreshold() domain.Severity {
	if h.runtime != nil {
		if t := parseBlockThreshold(h.runtime.BlockThreshold()); validBlockThreshold(t) {
			return t
		}
	}
	return h.blockThreshold
}

// NewHandlerWithBlockThreshold creates a Handler using an explicit block
// threshold. It is used by tests and by NewHandlerWithConfig.
func NewHandlerWithBlockThreshold(store Store, logger *slog.Logger, threshold domain.Severity) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if !validBlockThreshold(threshold) {
		threshold = defaultBlockThreshold
	}
	h := &Handler{
		store:               store,
		logger:              logger,
		blockThreshold:      threshold,
		reputationScheduler: reputation.NewScheduler(store, logger, reputation.Config{}),
		backgroundCtx:       context.Background(),
	}
	if feedStore, ok := store.(FeedImportStore); ok {
		h.feedImportHandler = NewFeedImportHandler(feedStore, logger)
	}
	return h
}

// ConfigureBackgroundContext sets the server lifecycle context used for
// request-detached background work such as async reputation scheduling.
func (h *Handler) ConfigureBackgroundContext(ctx context.Context) {
	if h == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	h.backgroundCtx = ctx
}

// ConfigureReversingLabs enables optional demand-driven ReversingLabs cache
// lookups for API checks. The handler only schedules work; the async worker
// performs external calls and refreshes the cache.
func (h *Handler) ConfigureReversingLabs(feeds config.FeedsConfig) {
	if h == nil {
		return
	}
	cacheEnabled := feeds.ReversingLabsEnabled && feeds.ReversingLabsMode == config.FeedModeSelf
	schedulingEnabled := cacheEnabled && strings.TrimSpace(feeds.ReversingLabsAPIKey) != ""
	h.reversingLabsEnabled.Store(cacheEnabled)
	h.socketRefreshEnabled.Store(feeds.SocketEnabled && feeds.SocketMode == config.FeedModeSelf && strings.TrimSpace(feeds.SocketAPIKey) != "")
	if h.reputationScheduler != nil {
		h.reputationScheduler.Configure(reputation.Config{
			ReversingLabsActive:              schedulingEnabled,
			ReversingLabsMaxSchedulePerCheck: feeds.ReversingLabsMaxSchedulePerCheck,
			ReversingLabsExcludedNamespaces:  feeds.ReversingLabsExcludedNamespaces,
		})
	}
}

// ConfigureFeedImportSecret configures the additional authorization required
// for feed imports. When required is true and no secret is configured, imports
// fail closed.
func (h *Handler) ConfigureFeedImportSecret(secret string, required bool) {
	if h == nil {
		return
	}
	if h.feedImportHandler != nil {
		h.feedImportHandler.ConfigureFeedImportSecret(secret, required)
	}
}

func parseBlockThreshold(raw string) domain.Severity {
	threshold := domain.Severity(strings.ToUpper(strings.TrimSpace(raw)))
	if validBlockThreshold(threshold) {
		return threshold
	}
	return defaultBlockThreshold
}

func validBlockThreshold(threshold domain.Severity) bool {
	switch threshold {
	case domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow, domain.SeverityNone:
		return true
	default:
		return false
	}
}

// ----------------------------------------------------------------------------
// POST /api/v1/check
// ----------------------------------------------------------------------------

// HandleCheck processes a scan request, looks up vulnerabilities and malicious
// findings for every package, and returns a ScanResult.
func (h *Handler) HandleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	start := time.Now()
	correlationID := requestCorrelationID(r)

	var req domain.ScanRequest
	if err := readJSON(r, &req); err != nil {
		h.logger.Warn("invalid check request body", "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	if len(req.Packages) == 0 {
		errorResponse(w, http.StatusBadRequest, "packages array is required and must not be empty")
		return
	}
	if len(req.Packages) > maxPackagesPerCheck {
		errorResponse(w, http.StatusBadRequest, fmt.Sprintf("too many packages: %d (max %d)", len(req.Packages), maxPackagesPerCheck))
		return
	}
	if err := validateCheckPackages(req.Packages); err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Packages = deduplicateCheckPackages(req.Packages)

	ctx := r.Context()
	idempotencyKey, err := checkIdempotencyKey(r)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	requestDigest, err := checkRequestDigest(&req)
	if err != nil {
		h.logger.Error("failed to digest check request", "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusInternalServerError, "internal error while checking packages")
		return
	}
	scanID := generateID()
	if idempotencyKey != "" {
		scanID = scanIDForIdempotencyKey(idempotencyKey, requestDigest)
		if existing, ok, err := h.existingIdempotentScan(ctx, idempotencyKey); err != nil {
			h.logger.Error("failed to check idempotency key", "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusInternalServerError, "internal error while checking packages")
			return
		} else if ok {
			if existing.RequestDigest != "" && existing.RequestDigest != requestDigest {
				errorResponse(w, http.StatusConflict, "idempotency key was already used for a different check request")
				return
			}
			if existing.ScanID != "" {
				scanID = existing.ScanID
			}
		}
	}

	findings, err := h.collectFindings(ctx, req.Packages)
	if err != nil {
		h.logger.Error("failed to collect findings", "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusInternalServerError, "internal error while checking packages")
		return
	}
	if findings == nil {
		findings = []domain.Finding{}
	}

	// Build summary maps.
	summary := domain.BuildScanSummary(findings)

	// Determine blocking status. Malicious findings always block.
	// Vulnerability findings block when their severity meets the threshold.
	blockThreshold := h.effectiveBlockThreshold()
	blocking := domain.FindingsBlock(findings, blockThreshold)

	// Assemble feed status and versions from sync state.
	feedStatus, feedVersions := h.feedState(ctx)
	if feedStatus == "degraded" {
		telemetry.Default().IncDegradedResponses()
	}

	durationMs := time.Since(start).Milliseconds()

	result := domain.ScanResult{
		ScanID:           scanID,
		Mode:             "remote",
		ScannedAt:        start.UTC(),
		DurationMs:       durationMs,
		PackagesScanned:  len(req.Packages),
		FindingsCount:    len(findings),
		FindingsBlocking: blocking,
		BlockThreshold:   blockThreshold,
		FeedStatus:       feedStatus,
		Summary:          summary,
		Findings:         findings,
		FeedVersions:     feedVersions,
		ManualCount:      domain.CountManualAdvisoryFindings(findings),
	}
	resultBody, err := encodeJSONResponse(result)
	if err != nil {
		h.logger.Error("failed to encode check response", "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusInternalServerError, "internal error while encoding scan result")
		return
	}

	logCtx, cancelLog := context.WithTimeout(context.WithoutCancel(ctx), scanLogInsertTimeout)
	if err := h.logScan(logCtx, &result, r, &req, correlationID, idempotencyKey, requestDigest, scanResultDigest(resultBody)); err != nil {
		cancelLog()
		h.logger.Error("failed to insert scan log", "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusInternalServerError, "internal error while recording scan")
		return
	}
	cancelLog()
	if idempotencyKey != "" {
		if existing, ok, err := h.existingIdempotentScan(ctx, idempotencyKey); err != nil {
			h.logger.Error("failed to verify idempotency key", "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusInternalServerError, "internal error while checking packages")
			return
		} else if ok && existing.RequestDigest != "" && existing.RequestDigest != requestDigest {
			errorResponse(w, http.StatusConflict, "idempotency key was already used for a different check request")
			return
		}
	}

	w.Header().Set(correlation.Header, correlationID)
	w.Header().Set("X-Scan-Duration-Ms", fmt.Sprintf("%d", durationMs))
	if idempotencyKey != "" {
		w.Header().Set(idempotencyKeyHeader, idempotencyKey)
	}
	writeJSONBytes(w, http.StatusOK, resultBody)
}

func validateCheckPackages(packages []domain.Package) error {
	for i := range packages {
		pkg := &packages[i]
		pkg.Name = strings.TrimSpace(pkg.Name)
		pkg.Version = strings.TrimSpace(pkg.Version)
		pkg.Ecosystem = domain.Ecosystem(strings.ToLower(strings.TrimSpace(string(pkg.Ecosystem))))
		pkg.Name = packageid.NormalizeName(string(pkg.Ecosystem), pkg.Name)

		position := i + 1
		if pkg.Name == "" {
			return fmt.Errorf("packages[%d].name is required", position)
		}
		if len(pkg.Name) > maxCheckPackageNameLength {
			return fmt.Errorf("packages[%d].name exceeds %d characters", position, maxCheckPackageNameLength)
		}
		if pkg.Version == "" {
			return fmt.Errorf("packages[%d].version is required", position)
		}
		if len(pkg.Version) > maxCheckPackageVersionLength {
			return fmt.Errorf("packages[%d].version exceeds %d characters", position, maxCheckPackageVersionLength)
		}
		if len(strings.Fields(pkg.Version)) != 1 {
			return fmt.Errorf("packages[%d].version is invalid", position)
		}
		if !validCheckPackageEcosystem(pkg.Ecosystem) {
			return fmt.Errorf("packages[%d].ecosystem is invalid", position)
		}
	}
	return nil
}

func validCheckPackageEcosystem(ecosystem domain.Ecosystem) bool {
	return ecosystem.Valid() && ecosystem != domain.EcosystemDocker
}

type checkPackageKey struct {
	ecosystem domain.Ecosystem
	name      string
	version   string
}

func deduplicateCheckPackages(packages []domain.Package) []domain.Package {
	if len(packages) < 2 {
		return packages
	}
	seen := make(map[checkPackageKey]struct{}, len(packages))
	unique := packages[:0]
	for _, pkg := range packages {
		key := checkPackageKey{
			ecosystem: pkg.Ecosystem,
			name:      pkg.Name,
			version:   pkg.Version,
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, pkg)
	}
	return unique
}

// collectFindings queries the store for vulnerabilities and malicious packages
// using batch queries to avoid the N+1 pattern. All findings are returned
// without truncation -- vulnerability data must never be silently discarded.
func (h *Handler) collectFindings(ctx context.Context, packages []domain.Package) ([]domain.Finding, error) {
	packages = deduplicateCheckPackages(packages)

	queries := make([]db.PackageQuery, len(packages))
	for i, pkg := range packages {
		queries[i] = db.PackageQuery{
			Ecosystem: string(pkg.Ecosystem),
			Name:      pkg.Name,
			Version:   pkg.Version,
		}
	}

	vulns, err := h.store.FindVulnerabilitiesBatch(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("FindVulnerabilitiesBatch: %w", err)
	}

	mal, err := h.store.FindMaliciousBatch(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("FindMaliciousBatch: %w", err)
	}

	var reputation []domain.Finding
	if h.reversingLabsEnabled.Load() {
		reputation, err = h.store.FindReputationFindingsBatch(ctx, queries, db.ReputationSourceReversingLabs)
		if err != nil {
			return nil, fmt.Errorf("FindReputationFindingsBatch: %w", err)
		}
	}

	lifecycle, err := h.store.FindLifecycleFindingsBatch(ctx, queries, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("FindLifecycleFindingsBatch: %w", err)
	}

	all := make([]domain.Finding, 0, len(vulns)+len(mal)+len(reputation)+len(lifecycle))
	all = append(all, vulns...)
	all = append(all, mal...)
	all = append(all, reputation...)
	all = append(all, lifecycle...)

	if h.reversingLabsEnabled.Load() {
		h.reputationScheduler.ScheduleReversingLabsAsync(h.backgroundContext(), packages, all)
	}

	return all, nil
}

func (h *Handler) backgroundContext() context.Context {
	if h == nil || h.backgroundCtx == nil {
		return context.Background()
	}
	return h.backgroundCtx
}

// feedState builds both the overall remote feed status and the per-feed versions.
func (h *Handler) feedState(ctx context.Context) (string, map[string]string) {
	statuses, err := h.store.ListFeedSyncStatuses(ctx)
	if err != nil {
		h.logger.Warn("failed to list feed sync statuses", "error", err)
		return "degraded", map[string]string{}
	}

	return overallFeedStatus(statuses), feedVersionsFromStatuses(statuses)
}

func feedVersionsFromStatuses(statuses []db.FeedSyncStatus) map[string]string {
	m := make(map[string]string, len(statuses))
	for _, s := range statuses {
		if s.LastSyncAt != nil {
			m[s.FeedName] = s.LastSyncAt.UTC().Format(time.RFC3339)
		}
	}
	return m
}

func overallFeedStatus(statuses []db.FeedSyncStatus) string {
	return feedhealth.OverallFeedStatus(statuses, feedhealth.HealthOptions{})
}

func feedHasFreshEntries(s db.FeedSyncStatus) bool {
	return feedhealth.HasFreshFeedEntries(s, feedhealth.HealthOptions{})
}

// logScan persists a scan log entry for a completed scan.
func (h *Handler) logScan(ctx context.Context, result *domain.ScanResult, r *http.Request, req *domain.ScanRequest, correlationID, idempotencyKey, requestDigest, resultDigest string) error {
	entry := &db.ScanLogEntry{
		ScanID:        result.ScanID,
		ScannedAt:     result.ScannedAt,
		PackagesCount: result.PackagesScanned,
		FindingsCount: result.FindingsCount,
		DurationMs:    int(result.DurationMs),
		ClientIP:      clientIP(r),
	}
	entry.CorrelationID = correlationID
	entry.IdempotencyKey = idempotencyKey
	entry.RequestDigest = requestDigest
	entry.ResultDigest = resultDigest
	entry.FindingsBlocking = result.FindingsBlocking
	entry.BlockThreshold = string(h.effectiveBlockThreshold())
	entry.FeedStatus = result.FeedStatus
	entry.FeedVersions = cloneStringMap(result.FeedVersions)
	entry.FindingIDs = scanLogFindingIDs(result.Findings)
	entry.FindingSeverities = scanLogFindingSeverities(result.Findings)
	entry.ManualAdvisoriesCount = result.ManualCount
	if req != nil && req.Repo != nil {
		entry.RepoName = scanLogRepoName(req.Repo.Name)
	}
	if identity, ok := requestctx.APIKeyIdentityFromContext(r.Context()); ok {
		entry.APIKeyID = identity.ID
		entry.APIKeyName = identity.Name
	}
	if err := h.store.InsertScanLog(ctx, entry); err != nil {
		return fmt.Errorf("insert scan log: %w", err)
	}
	return nil
}

func (h *Handler) existingIdempotentScan(ctx context.Context, key string) (*db.ScanLogEntry, bool, error) {
	lookup, ok := h.store.(scanLogIdempotencyLookup)
	if !ok {
		return nil, false, nil
	}
	entry, err := lookup.GetScanLogByIdempotencyKey(ctx, key)
	if err != nil {
		return nil, false, err
	}
	if entry == nil {
		return nil, false, nil
	}
	return entry, true, nil
}

func checkIdempotencyKey(r *http.Request) (string, error) {
	key := strings.TrimSpace(r.Header.Get(idempotencyKeyHeader))
	if key == "" {
		return "", nil
	}
	if len(key) > maxIdempotencyKeyLength {
		return "", fmt.Errorf("idempotency key exceeds %d characters", maxIdempotencyKeyLength)
	}
	for _, ch := range key {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '_' || ch == '-' || ch == '.' || ch == ':':
		default:
			return "", fmt.Errorf("idempotency key contains unsupported characters")
		}
	}
	return key, nil
}

func checkRequestDigest(req *domain.ScanRequest) (string, error) {
	body, err := json.Marshal(struct {
		Packages []domain.Package `json:"packages"`
		Repo     *domain.RepoInfo `json:"repo,omitempty"`
	}{
		Packages: req.Packages,
		Repo:     req.Repo,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func scanIDForIdempotencyKey(key, requestDigest string) string {
	sum := sha256.Sum256([]byte(key + "\x00" + requestDigest))
	return hex.EncodeToString(sum[:8])
}

func scanLogRepoName(raw string) string {
	value := strings.TrimSpace(raw)
	if looksLikeScanLogPath(value) {
		value = scanLogPathTail(value)
	}
	return logsafe.BoundedDiagnosticValue(value, 256)
}

func looksLikeScanLogPath(value string) bool {
	if strings.Contains(value, `\`) {
		return true
	}
	normalized := strings.ReplaceAll(value, `\`, "/")
	return strings.HasPrefix(normalized, "/") ||
		strings.HasPrefix(normalized, "~/") ||
		strings.HasPrefix(normalized, "./") ||
		strings.HasPrefix(normalized, "../") ||
		strings.Count(normalized, "/") >= 2
}

func scanLogPathTail(value string) string {
	normalized := strings.ReplaceAll(strings.TrimRight(value, `/\`), `\`, "/")
	if idx := strings.LastIndex(normalized, "/"); idx >= 0 {
		return normalized[idx+1:]
	}
	return normalized
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func scanLogFindingIDs(findings []domain.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.AdvisoryID)
	}
	return out
}

func scanLogFindingSeverities(findings []domain.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, string(finding.Severity))
	}
	return out
}

// ----------------------------------------------------------------------------
// GET /api/v1/feeds/status
// ----------------------------------------------------------------------------

// FeedStatusItem is the per-feed JSON shape returned by HandleFeedStatus.
type FeedStatusItem struct {
	Name         string  `json:"name"`
	Status       string  `json:"status"`
	LastSyncAt   *string `json:"last_sync_at"`
	EntriesCount int     `json:"entries_count"`
	Message      string  `json:"message,omitempty"`
}

// FeedStatusResponse is the top-level JSON returned by HandleFeedStatus.
type FeedStatusResponse struct {
	Status  string           `json:"status"`
	Message string           `json:"message,omitempty"`
	Feeds   []FeedStatusItem `json:"feeds"`
}

// HandleFeedStatus returns the sync status of all known feed sources.
func (h *Handler) HandleFeedStatus(w http.ResponseWriter, r *http.Request) {
	if !isGetOrHead(r.Method) {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	correlationID := requestCorrelationID(r)
	statuses, err := h.store.ListFeedSyncStatuses(r.Context())
	if err != nil {
		h.logger.Error("failed to list feed sync statuses", "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to retrieve feed statuses")
		return
	}

	items := make([]FeedStatusItem, 0, len(statuses))
	for _, s := range statuses {
		status := feedHealthStatus(s)
		item := FeedStatusItem{
			Name:         s.FeedName,
			Status:       status,
			EntriesCount: s.EntriesTotal,
		}
		if s.LastSyncAt != nil {
			ts := s.LastSyncAt.UTC().Format(time.RFC3339)
			item.LastSyncAt = &ts
		}
		if message := feedStatusMessage(status, s.LastError); message != "" {
			item.Message = message
		}
		items = append(items, item)
	}

	status := overallFeedStatus(statuses)
	message := ""
	if len(statuses) == 0 {
		message = "feed status unavailable: no feed sync rows have been recorded"
	} else if status != "healthy" {
		message = "one or more feeds are degraded"
	}
	writeJSONForRequest(w, r, http.StatusOK, FeedStatusResponse{Status: status, Message: message, Feeds: items})
}

// feedHealthStatus derives a health string from sync status.
// A feed is "error" if its last sync failed, "warning" if the last run was
// skipped, the last successful sync is more than 48 hours ago, or the feed
// holds zero entries, and "healthy" otherwise.
func feedHealthStatus(s db.FeedSyncStatus) string {
	return feedhealth.FeedStatusHealth(s, feedhealth.HealthOptions{}).Status
}

func feedStatusMessage(health, lastError string) string {
	if lastError == "" {
		return ""
	}
	switch health {
	case "healthy", "disabled", "pending", "configured":
		return ""
	default:
		return logsafe.RedactDiagnosticMessage(lastError)
	}
}

// ----------------------------------------------------------------------------
// POST /api/v1/feeds/{feed}/import
// ----------------------------------------------------------------------------

func (h *Handler) HandleFeedImport(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.feedImportHandler == nil {
		errorResponse(w, http.StatusNotImplemented, "feed import endpoint is not supported by this store")
		return
	}
	h.feedImportHandler.HandleImport(w, r)
}

func (h *FeedImportHandler) authorizeFeedImport(r *http.Request) bool {
	expected := strings.TrimSpace(h.feedImportSecret)
	if expected == "" && !h.feedImportRequired {
		return true
	}
	if expected == "" {
		h.logger.Warn("feed import authorization failed",
			"reason", "secret_not_configured",
			"correlation_id", requestCorrelationID(r),
		)
		return false
	}
	provided := strings.TrimSpace(r.Header.Get(HeaderFeedImportSecret))
	if provided == "" || !constantTimeStringEqual(provided, expected) {
		h.logger.Warn("feed import authorization failed",
			"reason", "missing_or_invalid_secret",
			"correlation_id", requestCorrelationID(r),
		)
		return false
	}
	return true
}

func constantTimeStringEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

func (h *FeedImportHandler) recordFeedImportAudit(r *http.Request, resp *importResponse) error {
	client := clientIP(r)
	details := struct {
		Feed          string `json:"feed"`
		Imported      int    `json:"imported"`
		Deleted       int    `json:"deleted"`
		EntriesTotal  int    `json:"entries_total"`
		ClientIP      string `json:"client_ip"`
		CorrelationID string `json:"correlation_id"`
		APIKeyID      int    `json:"api_key_id,omitempty"`
		APIKeyName    string `json:"api_key_name,omitempty"`
	}{
		Feed:          resp.Feed,
		Imported:      resp.Imported,
		Deleted:       resp.Deleted,
		EntriesTotal:  resp.EntriesTotal,
		ClientIP:      client,
		CorrelationID: requestCorrelationID(r),
	}
	if identity, ok := requestctx.APIKeyIdentityFromContext(r.Context()); ok {
		details.APIKeyID = identity.ID
		details.APIKeyName = identity.Name
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	return h.store.InsertAdminAuditLog(r.Context(), &db.AdminAuditEntry{
		Action:  "feed_import",
		Details: raw,
		IP:      client,
	})
}

// ----------------------------------------------------------------------------
// GET /api/v1/packages/{ecosystem}/{rest...}
// ----------------------------------------------------------------------------

// PackageDetailResponse is the JSON response for HandlePackageDetail.
type PackageDetailResponse struct {
	Ecosystem string           `json:"ecosystem"`
	Name      string           `json:"name"`
	Findings  []domain.Finding `json:"findings"`
}

// HandlePackageDetail returns all known findings for a package.
// The package name is extracted from the {rest...} wildcard.
func (h *Handler) HandlePackageDetail(w http.ResponseWriter, r *http.Request) {
	if !isGetOrHead(r.Method) {
		w.Header().Set("Allow", "GET, HEAD")
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	correlationID := requestCorrelationID(r)
	ecosystem := r.PathValue("ecosystem")
	name := r.PathValue("rest")
	if strings.HasSuffix(name, "/refresh") {
		w.Header().Set("Allow", http.MethodPost)
		errorResponseForRequest(w, r, http.StatusMethodNotAllowed, "method not allowed; use POST .../refresh")
		return
	}
	var err error
	ecosystem, name, err = normalizePackagePath(ecosystem, name)
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	version := strings.TrimSpace(r.URL.Query().Get("version"))

	// FindVulnerabilities with empty version returns all versions.
	vulns, err := h.store.FindVulnerabilities(ctx, ecosystem, name, version)
	if err != nil {
		h.logger.Error("failed to find vulnerabilities", "ecosystem", ecosystem, "name", name, "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to query vulnerabilities")
		return
	}

	mal, err := h.store.FindMalicious(ctx, ecosystem, name, version)
	if err != nil {
		h.logger.Error("failed to find malicious findings", "ecosystem", ecosystem, "name", name, "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to query malicious findings")
		return
	}

	var reputation []domain.Finding
	if h.reversingLabsEnabled.Load() {
		if version != "" {
			reputation, err = h.store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
			}}, db.ReputationSourceReversingLabs)
			if err != nil {
				h.logger.Error("failed to find reputation findings", "ecosystem", ecosystem, "name", name, "version", version, "error", err, "correlation_id", correlationID)
				errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to query reputation findings")
				return
			}
		} else if finder, ok := h.store.(reputationPackageFinder); ok {
			reputation, err = finder.FindReputationFindings(ctx, ecosystem, name, db.ReputationSourceReversingLabs)
			if err != nil {
				h.logger.Error("failed to find reputation findings", "ecosystem", ecosystem, "name", name, "error", err, "correlation_id", correlationID)
				errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to query reputation findings")
				return
			}
		}
	}

	var lifecycle []domain.Finding
	if version != "" {
		lifecycle, err = h.store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{
			Ecosystem: ecosystem,
			Name:      name,
			Version:   version,
		}}, time.Now().UTC())
		if err != nil {
			h.logger.Error("failed to find lifecycle findings", "ecosystem", ecosystem, "name", name, "version", version, "error", err, "correlation_id", correlationID)
			errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to query lifecycle findings")
			return
		}
	}

	findings := make([]domain.Finding, 0, len(vulns)+len(mal)+len(reputation)+len(lifecycle))
	findings = append(findings, vulns...)
	findings = append(findings, mal...)
	findings = append(findings, reputation...)
	findings = append(findings, lifecycle...)

	if len(findings) == 0 {
		errorResponseForRequest(w, r, http.StatusNotFound, fmt.Sprintf("no findings for %s/%s", ecosystem, name))
		return
	}

	writeJSONForRequest(w, r, http.StatusOK, PackageDetailResponse{
		Ecosystem: ecosystem,
		Name:      name,
		Findings:  findings,
	})
}

// ----------------------------------------------------------------------------
// POST /api/v1/packages/{ecosystem}/{rest...}
// Dispatches to handleRefresh when the rest path ends with "/refresh".
// ----------------------------------------------------------------------------

// HandlePackageOrRefresh is the dispatcher for POST requests on the
// packages resource. Since Go's ServeMux does not allow a {name...}
// wildcard in the middle of a pattern, we register a single catch-all
// for POST and split here: if {rest} ends with "/refresh", we strip
// the suffix and delegate to handleRefresh; otherwise we return 405.
func (h *Handler) HandlePackageOrRefresh(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	if strings.HasSuffix(rest, "/refresh") {
		// Inject the trimmed name back so HandleRefresh can read it.
		name := strings.TrimSuffix(rest, "/refresh")
		if name == "" {
			errorResponse(w, http.StatusBadRequest, "package name is required")
			return
		}
		h.handleRefresh(w, r, r.PathValue("ecosystem"), name)
		return
	}
	w.Header().Set("Allow", http.MethodGet)
	errorResponse(w, http.StatusMethodNotAllowed, "method not allowed; did you mean POST .../refresh?")
}

// RefreshResponse is the JSON response for HandleRefresh.
type RefreshResponse struct {
	Queued   bool   `json:"queued"`
	New      bool   `json:"new"`
	Position int    `json:"position"`
	Message  string `json:"message"`
}

// handleRefresh is the internal implementation used by HandlePackageOrRefresh.
func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request, ecosystem, name string) {
	ecosystem, name, err := normalizePackagePath(ecosystem, name)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	correlationID := requestCorrelationID(r)
	// Body is optional. If present, it must be an empty JSON object.
	if r.Body != nil && r.ContentLength != 0 {
		var req struct{}
		if err := readJSON(r, &req); err != nil {
			h.logger.Warn("invalid refresh request body", "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
	}
	if !h.socketRefreshEnabled.Load() {
		errorResponse(w, http.StatusConflict, "no active refresh worker is configured")
		return
	}
	if !socket.SupportsEcosystem(ecosystem) {
		errorResponse(w, http.StatusConflict, fmt.Sprintf("no active refresh worker supports ecosystem: %s", ecosystem))
		return
	}
	if getter, ok := h.store.(packageCheckStatusGetter); ok {
		status, err := getter.GetPackageCheckStatus(r.Context(), ecosystem, name, socket.FeedName)
		if err != nil {
			h.logger.Error("failed to check package refresh budget", "ecosystem", ecosystem, "name", name, "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusInternalServerError, "failed to check refresh budget")
			return
		}
		if status != nil && status.NextCheckAt != nil && status.NextCheckAt.After(time.Now().UTC()) {
			writeJSON(w, http.StatusOK, RefreshResponse{
				Queued:  false,
				New:     false,
				Message: fmt.Sprintf("refresh skipped for %s/%s; next check after %s", ecosystem, name, status.NextCheckAt.UTC().Format(time.RFC3339)),
			})
			return
		}
	}

	job := &db.RefreshJob{
		Ecosystem: ecosystem,
		Name:      name,
		Source:    socket.FeedName,
		Priority:  0, // manual trigger = highest priority
		Status:    "pending",
	}

	created, position, err := h.store.EnqueueRefresh(r.Context(), job)
	if err != nil {
		h.logger.Error("failed to enqueue refresh", "ecosystem", ecosystem, "name", name, "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusInternalServerError, "failed to enqueue refresh")
		return
	}

	msg := fmt.Sprintf("refresh queued for %s/%s at position %d", ecosystem, name, position)
	if !created {
		msg = fmt.Sprintf("refresh for %s/%s already queued at position %d", ecosystem, name, position)
	}

	writeJSON(w, http.StatusOK, RefreshResponse{
		Queued:   true,
		New:      created,
		Position: position,
		Message:  msg,
	})
}

func normalizePackagePath(ecosystem, name string) (string, string, error) {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	name = strings.TrimSpace(name)
	if ecosystem == "" || name == "" {
		return "", "", fmt.Errorf("ecosystem and package name are required")
	}
	if len(name) > maxCheckPackageNameLength {
		return "", "", fmt.Errorf("package name exceeds %d characters", maxCheckPackageNameLength)
	}
	if !domain.Ecosystem(ecosystem).Valid() {
		return "", "", fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
	return ecosystem, name, nil
}

// ----------------------------------------------------------------------------
// GET /api/v1/sync
// ----------------------------------------------------------------------------

// syncDefaultLimit is the default number of rows per page for /api/v1/sync.
const syncDefaultLimit = 1000

// syncMaxLimit is the maximum allowed limit for /api/v1/sync pagination.
const syncMaxLimit = 10000

// syncMaxOffset bounds legacy offset pagination. Modern clients should use the
// keyset cursor fields returned in next_cursor.
const syncMaxOffset = 1000000

func parseSyncCursor(r *http.Request) (db.SyncCursor, error) {
	var cursor db.SyncCursor
	query := r.URL.Query()
	params := []struct {
		name   string
		target *int
	}{
		{name: "vulnerabilities_offset", target: &cursor.Vulnerabilities},
		{name: "malicious_offset", target: &cursor.Malicious},
		{name: "reputation_offset", target: &cursor.Reputation},
		{name: "lifecycle_offset", target: &cursor.Lifecycle},
	}
	for _, param := range params {
		raw := strings.TrimSpace(query.Get(param.name))
		if raw == "" {
			continue
		}
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > syncMaxOffset {
			return db.SyncCursor{}, fmt.Errorf("invalid %s parameter", param.name)
		}
		*param.target = parsed
	}

	cursorParams := []struct {
		name   string
		target *string
	}{
		{name: "vulnerabilities_cursor", target: &cursor.VulnerabilitiesCursor},
		{name: "malicious_cursor", target: &cursor.MaliciousCursor},
		{name: "reputation_cursor", target: &cursor.ReputationCursor},
		{name: "lifecycle_cursor", target: &cursor.LifecycleCursor},
	}
	for _, param := range cursorParams {
		*param.target = strings.TrimSpace(query.Get(param.name))
	}

	doneParams := []struct {
		name   string
		target *bool
	}{
		{name: "vulnerabilities_done", target: &cursor.VulnerabilitiesDone},
		{name: "malicious_done", target: &cursor.MaliciousDone},
		{name: "reputation_done", target: &cursor.ReputationDone},
		{name: "lifecycle_done", target: &cursor.LifecycleDone},
	}
	for _, param := range doneParams {
		raw := strings.TrimSpace(query.Get(param.name))
		if raw == "" {
			continue
		}
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return db.SyncCursor{}, fmt.Errorf("invalid %s parameter", param.name)
		}
		*param.target = parsed
	}
	return cursor, nil
}

func parseOptionalUintQuery(r *http.Request, name string) (uint64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s parameter", name)
	}
	return parsed, nil
}

func (h *Handler) HandleSync(w http.ResponseWriter, r *http.Request) {
	if !isGetOrHead(r.Method) {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	correlationID := requestCorrelationID(r)
	exporter, ok := h.store.(syncExporter)
	if !ok {
		errorResponseForRequest(w, r, http.StatusNotImplemented, "sync endpoint is not supported by this store")
		return
	}

	var sincePtr *time.Time
	sinceRaw := strings.TrimSpace(r.URL.Query().Get("since"))
	if sinceRaw != "" {
		since, err := parseRFC3339Timestamp(sinceRaw)
		if err != nil {
			errorResponseForRequest(w, r, http.StatusBadRequest, "invalid since timestamp")
			return
		}
		sincePtr = &since
	}

	var snapshot time.Time
	if raw := strings.TrimSpace(r.URL.Query().Get("snapshot")); raw != "" {
		parsed, err := parseRFC3339Timestamp(raw)
		if err != nil {
			errorResponseForRequest(w, r, http.StatusBadRequest, "invalid snapshot parameter")
			return
		}
		snapshot = parsed.UTC()
	}
	sinceXID, err := parseOptionalUintQuery(r, "since_xid")
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}
	snapshotXID, err := parseOptionalUintQuery(r, "snapshot_xid")
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}

	limit := syncDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			errorResponseForRequest(w, r, http.StatusBadRequest, "invalid limit parameter")
			return
		}
		limit = parsed
		if limit > syncMaxLimit {
			limit = syncMaxLimit
		}
	}

	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > syncMaxOffset {
			errorResponseForRequest(w, r, http.StatusBadRequest, "invalid offset parameter")
			return
		}
		offset = parsed
	}
	cursor, err := parseSyncCursor(r)
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}
	ecosystems, err := parseSyncEcosystems(r.URL.Query().Get("ecosystem"))
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}

	exported, err := exporter.ExportSync(r.Context(), db.SyncExportOptions{
		Since:       sincePtr,
		SinceXID:    sinceXID,
		SnapshotAt:  snapshot,
		SnapshotXID: snapshotXID,
		Ecosystems:  ecosystems,
		Limit:       limit,
		Offset:      offset,
		Cursor:      cursor,
	})
	if err != nil {
		h.logger.Error("sync export failed", "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to export sync data")
		return
	}

	feedStatus, feedVersions := h.feedState(r.Context())
	resp := syncResponsePayload{
		SyncedAt:        exported.SyncedAt.UTC().Format(time.RFC3339Nano),
		SyncedXID:       exported.SyncedXID,
		FeedStatus:      feedStatus,
		FeedVersions:    feedVersions,
		Vulnerabilities: make([]syncVulnerabilityResponse, 0, len(exported.Vulnerabilities)),
		Malicious:       make([]syncMaliciousResponse, 0, len(exported.Malicious)),
		Reputation:      make([]syncReputationResponse, 0, len(exported.Reputation)),
		Lifecycle:       make([]syncLifecycleResponse, 0, len(exported.Lifecycle)),
		Truncated:       exported.Truncated,
		HasMore:         exported.Truncated,
		NextCursor:      exported.NextCursor,
	}

	for _, vuln := range exported.Vulnerabilities {
		resp.Vulnerabilities = append(resp.Vulnerabilities, syncVulnerabilityResponse{
			ID:               vuln.ID,
			Ecosystem:        vuln.Ecosystem,
			Name:             vuln.Name,
			VersionRanges:    vuln.VersionRanges,
			VersionsAffected: vuln.VersionsAffected,
			References:       vuln.References,
			Severity:         vuln.Severity,
			CVSSScore:        vuln.CVSSScore,
			EPSSScore:        vuln.EPSSScore,
			EPSSPercentile:   vuln.EPSSPercentile,
			CISAKEV:          vuln.CISAKEV,
			Summary:          vuln.Summary,
			Source:           vuln.Source,
			Withdrawn:        vuln.Withdrawn,
		})
	}

	for _, finding := range exported.Malicious {
		resp.Malicious = append(resp.Malicious, syncMaliciousResponse{
			ID:            finding.ID,
			Ecosystem:     finding.Ecosystem,
			Name:          finding.Name,
			VersionRanges: finding.VersionRanges,
			Versions:      finding.Versions,
			ReferenceURLs: finding.ReferenceURLs,
			RiskType:      finding.RiskType,
			Severity:      finding.Severity,
			Summary:       finding.Summary,
			Source:        finding.Source,
			Withdrawn:     finding.Withdrawn,
		})
	}

	for _, finding := range exported.Reputation {
		resp.Reputation = append(resp.Reputation, syncReputationResponse{
			ID:        finding.ID,
			Ecosystem: finding.Ecosystem,
			Name:      finding.Name,
			Version:   finding.Version,
			Type:      finding.Type,
			RiskType:  finding.RiskType,
			Severity:  finding.Severity,
			Summary:   finding.Summary,
			Withdrawn: finding.Withdrawn,
		})
	}

	for _, release := range exported.Lifecycle {
		resp.Lifecycle = append(resp.Lifecycle, syncLifecycleResponse{
			ID:               release.ID,
			Ecosystem:        release.Ecosystem,
			Name:             release.Name,
			ProductSlug:      release.ProductSlug,
			ProductLabel:     release.ProductLabel,
			Cycle:            release.Cycle,
			Latest:           release.Latest,
			ReleaseDate:      syncDateOnly(release.ReleaseDate),
			IsLTS:            release.IsLTS,
			LTSFrom:          syncDateOnly(release.LTSFrom),
			IsEOAS:           release.IsEOAS,
			EOASFrom:         syncDateOnly(release.EOASFrom),
			IsEOL:            release.IsEOL,
			EOLFrom:          syncDateOnly(release.EOLFrom),
			IsDiscontinued:   release.IsDiscontinued,
			DiscontinuedFrom: syncDateOnly(release.DiscontinuedFrom),
			IsEOES:           release.IsEOES,
			EOESFrom:         syncDateOnly(release.EOESFrom),
			IsMaintained:     release.IsMaintained,
			Withdrawn:        release.Withdrawn,
		})
	}

	resp.HasMore = exported.Truncated

	writeJSONForRequest(w, r, http.StatusOK, resp)
}

func syncDateOnly(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := value.UTC().Format(time.DateOnly)
	return &formatted
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func isKnownFeed(feed string) bool {
	switch feed {
	case "osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss", "socket":
		return true
	default:
		return false
	}
}

func normalizeFeedName(feed string) string {
	feed = strings.TrimSpace(strings.ToLower(feed))
	if feed == "malicious" {
		return "openssf"
	}
	return feed
}

type feedImportRecordOptions[T any] struct {
	deleteField   string
	normalize     func(feed string, index int, item T) (T, error)
	recordContext func(index int, item T) string
	upsert        func(context.Context, *T) error
	delete        func(context.Context, string) error
	atomicImport  func(context.Context, string, []T, []string, *db.FeedSyncStatus) (int, int, error)
}

func importFeedRecords[T any](ctx context.Context, h *FeedImportHandler, feed string, statusInput *feedSyncStatusInput, rawItems []T, rawDeleteIDs []string, opts feedImportRecordOptions[T]) (*importResponse, error) {
	if err := validateImportStatusInput(statusInput); err != nil {
		return nil, err
	}

	items := make([]T, 0, len(rawItems))
	for i := range rawItems {
		item, err := opts.normalize(feed, i, rawItems[i])
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	deleteIDs, err := normalizeImportDeleteIDs(opts.deleteField, rawDeleteIDs)
	if err != nil {
		return nil, err
	}

	if opts.atomicImport != nil {
		status, err := importStatusFromInput(feed, statusInput, len(items), len(items)+len(deleteIDs))
		if err != nil {
			return nil, err
		}
		imported, deleted, err := opts.atomicImport(ctx, feed, items, importDeleteIDValues(deleteIDs), status)
		if err != nil {
			return nil, err
		}
		return feedImportResponse(feed, imported, deleted), nil
	}

	imported := 0
	for i := range items {
		if err := opts.upsert(ctx, &items[i]); err != nil {
			return nil, contextualizeFeedImportError(opts.recordContext(i, items[i]), err)
		}
		imported++
	}

	deleted := 0
	for _, item := range deleteIDs {
		if err := opts.delete(ctx, item.ID); err != nil {
			return nil, contextualizeFeedImportError(importRecordContext(opts.deleteField, item.Index, importRecordValue("id", item.ID)), err)
		}
		deleted++
	}

	if err := h.applyImportStatus(ctx, feed, statusInput, imported, imported+deleted); err != nil {
		return nil, err
	}

	return feedImportResponse(feed, imported, deleted), nil
}

func feedImportResponse(feed string, imported, deleted int) *importResponse {
	return &importResponse{
		Feed:         feed,
		Imported:     imported,
		Deleted:      deleted,
		EntriesTotal: imported + deleted,
	}
}

func (h *FeedImportHandler) importVulnerabilities(ctx context.Context, feed string, req *vulnerabilityImportRequest) (*importResponse, error) {
	var atomicImport func(context.Context, string, []db.Vulnerability, []string, *db.FeedSyncStatus) (int, int, error)
	if importer, ok := h.store.(vulnerabilityFeedImporter); ok {
		atomicImport = importer.ImportVulnerabilityFeed
	}
	return importFeedRecords(ctx, h, feed, req.Status, req.Vulnerabilities, req.DeleteVulnerabilityIDs, feedImportRecordOptions[db.Vulnerability]{
		deleteField: "delete_vulnerability_ids",
		normalize: func(feed string, index int, item db.Vulnerability) (db.Vulnerability, error) {
			recordContext := vulnerabilityImportRecordContext(index, item)
			if isManualAdvisoryID(item.ID) {
				return item, feedImportValidationErrorf("%s: feed import cannot mutate manual advisory id %q", recordContext, strings.TrimSpace(item.ID))
			}
			if err := normalizeImportedVulnerability(feed, &item); err != nil {
				return item, contextualizeFeedImportError(recordContext, err)
			}
			return item, nil
		},
		recordContext: vulnerabilityImportRecordContext,
		upsert: func(ctx context.Context, item *db.Vulnerability) error {
			return h.store.UpsertVulnerability(ctx, item)
		},
		delete: func(ctx context.Context, id string) error {
			return deleteVulnerabilityForSource(ctx, h.store, id, feed)
		},
		atomicImport: atomicImport,
	})
}

func (h *FeedImportHandler) importMalicious(ctx context.Context, feed string, req *maliciousImportRequest) (*importResponse, error) {
	var atomicImport func(context.Context, string, []db.MaliciousFinding, []string, *db.FeedSyncStatus) (int, int, error)
	if importer, ok := h.store.(maliciousFeedImporter); ok {
		atomicImport = importer.ImportMaliciousFeed
	}
	return importFeedRecords(ctx, h, feed, req.Status, req.Malicious, req.DeleteMaliciousIDs, feedImportRecordOptions[db.MaliciousFinding]{
		deleteField: "delete_malicious_ids",
		normalize: func(feed string, index int, item db.MaliciousFinding) (db.MaliciousFinding, error) {
			recordContext := maliciousImportRecordContext(index, item)
			if isManualAdvisoryID(item.ID) {
				return item, feedImportValidationErrorf("%s: feed import cannot mutate manual advisory id %q", recordContext, strings.TrimSpace(item.ID))
			}
			if err := normalizeImportedMalicious(feed, &item); err != nil {
				return item, contextualizeFeedImportError(recordContext, err)
			}
			return item, nil
		},
		recordContext: maliciousImportRecordContext,
		upsert: func(ctx context.Context, item *db.MaliciousFinding) error {
			return h.store.UpsertMaliciousFinding(ctx, item)
		},
		delete: func(ctx context.Context, id string) error {
			return deleteMaliciousFindingForSource(ctx, h.store, id, feed)
		},
		atomicImport: atomicImport,
	})
}

func (h *FeedImportHandler) importVulnCheck(ctx context.Context, feed string, req *vulnCheckImportRequest) (*importResponse, error) {
	if err := validateImportStatusInput(req.Status); err != nil {
		return nil, err
	}
	if err := validateVulnCheckImportEntries(req.Entries); err != nil {
		return nil, err
	}

	updated, err := h.store.EnrichVulnCheck(ctx, req.Entries)
	if err != nil {
		return nil, err
	}
	if err := h.applyImportStatus(ctx, feed, req.Status, updated, len(req.Entries)); err != nil {
		return nil, err
	}
	return &importResponse{
		Feed:         feed,
		Imported:     updated,
		EntriesTotal: len(req.Entries),
	}, nil
}

func (h *FeedImportHandler) importCISAKEV(ctx context.Context, feed string, req *cisaKEVImportRequest) (*importResponse, error) {
	if err := validateImportStatusInput(req.Status); err != nil {
		return nil, err
	}
	cveIDs, err := normalizeCISAKEVImportIDs(req.CVEIDs, req.ClearMissing)
	if err != nil {
		return nil, err
	}

	updated, err := h.store.SetCISAKEV(ctx, cveIDs)
	if err != nil {
		return nil, err
	}

	cleared := 0
	if req.ClearMissing {
		cleared, err = h.store.ClearCISAKEV(ctx, cveIDs)
		if err != nil {
			return nil, err
		}
	}

	if err := h.applyImportStatus(ctx, feed, req.Status, updated, len(cveIDs)); err != nil {
		return nil, err
	}

	return &importResponse{
		Feed:         feed,
		Imported:     updated,
		Deleted:      cleared,
		EntriesTotal: len(cveIDs),
	}, nil
}

func (h *FeedImportHandler) importEPSS(ctx context.Context, feed string, req *epssImportRequest) (*importResponse, error) {
	if err := validateImportStatusInput(req.Status); err != nil {
		return nil, err
	}
	if err := validateEPSSImportEntries(req.Entries); err != nil {
		return nil, err
	}

	updated, cleared, err := h.store.ReplaceEPSSScores(ctx, req.Entries)
	if err != nil {
		return nil, err
	}
	if err := h.applyImportStatus(ctx, feed, req.Status, updated, len(req.Entries)); err != nil {
		return nil, err
	}
	return &importResponse{
		Feed:         feed,
		Imported:     updated,
		Deleted:      cleared,
		EntriesTotal: len(req.Entries),
	}, nil
}

func (h *FeedImportHandler) applyImportStatus(ctx context.Context, feed string, input *feedSyncStatusInput, entriesSynced, entriesTotal int) error {
	status, err := importStatusFromInput(feed, input, entriesSynced, entriesTotal)
	if err != nil {
		return err
	}
	if status == nil {
		return nil
	}
	return h.store.UpsertFeedSyncStatus(ctx, status)
}

func importStatusFromInput(feed string, input *feedSyncStatusInput, entriesSynced, entriesTotal int) (*db.FeedSyncStatus, error) {
	if input == nil {
		return nil, nil
	}
	if err := validateImportStatusInput(input); err != nil {
		return nil, err
	}

	status := &db.FeedSyncStatus{
		FeedName:       feed,
		LastSyncAt:     input.LastSyncAt,
		LastSyncStatus: strings.TrimSpace(input.LastSyncStatus),
		LastError:      logsafe.BoundedDiagnosticValue(input.LastError, maxImportStatusLastErrorLength),
		EntriesSynced:  input.EntriesSynced,
		EntriesTotal:   input.EntriesTotal,
		LastEtag:       truncateString(strings.TrimSpace(input.LastEtag), maxImportStatusLastEtagLength),
		LastCommitHash: truncateString(strings.TrimSpace(input.LastCommitHash), maxImportStatusLastCommitHashLength),
		Metadata:       append(json.RawMessage(nil), input.Metadata...),
	}

	if status.LastSyncAt == nil {
		now := time.Now().UTC()
		status.LastSyncAt = &now
	}
	if status.LastSyncStatus == "" {
		status.LastSyncStatus = "success"
	}
	if status.EntriesTotal == 0 {
		status.EntriesTotal = entriesTotal
	}
	if status.EntriesSynced == 0 {
		status.EntriesSynced = entriesSynced
	}
	if input.LastSyncDurationMs != nil {
		duration := time.Duration(*input.LastSyncDurationMs) * time.Millisecond
		status.LastSyncDuration = &duration
	}

	return status, nil
}

func normalizeImportedVulnerability(feed string, vuln *db.Vulnerability) error {
	if strings.TrimSpace(vuln.ID) == "" {
		return feedImportValidationErrorf("vulnerability import requires id")
	}

	now := time.Now().UTC()
	if vuln.Published.IsZero() {
		vuln.Published = now
	}
	if vuln.Modified.IsZero() {
		vuln.Modified = now
	}
	if strings.TrimSpace(vuln.Severity) == "" {
		vuln.Severity = "UNKNOWN"
	}
	vuln.Severity = strings.ToUpper(strings.TrimSpace(vuln.Severity))
	if !isImportVulnerabilitySeverity(vuln.Severity) {
		return feedImportValidationErrorf("vulnerability import severity %q is not supported", vuln.Severity)
	}
	for i := range vuln.AffectedPackages {
		pkg := &vuln.AffectedPackages[i]
		pkg.Ecosystem = strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
		if !domain.Ecosystem(pkg.Ecosystem).Valid() {
			return feedImportValidationErrorf("vulnerability import affected_packages[%d].ecosystem is not supported", i)
		}
		pkg.Name = packageid.NormalizeName(pkg.Ecosystem, pkg.Name)
		if strings.TrimSpace(pkg.Name) == "" {
			return feedImportValidationErrorf("vulnerability import affected_packages[%d].name is required", i)
		}
		if err := validateVersionRangesJSON(pkg.VersionRanges, fmt.Sprintf("vulnerability import affected_packages[%d].version_ranges", i)); err != nil {
			return err
		}
		if err := validateStringArrayJSON(pkg.VersionsAffected, fmt.Sprintf("vulnerability import affected_packages[%d].versions_affected", i)); err != nil {
			return err
		}
	}

	vuln.Sources = []db.VulnerabilitySource{{
		Source:   feed,
		SourceID: vuln.ID,
	}}

	return nil
}

func isImportVulnerabilitySeverity(severity string) bool {
	switch domain.Severity(severity) {
	case domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow, domain.SeverityUnknown:
		return true
	default:
		return false
	}
}

func normalizeImportedMalicious(feed string, finding *db.MaliciousFinding) error {
	if strings.TrimSpace(finding.ID) == "" {
		return feedImportValidationErrorf("malicious import requires id")
	}
	finding.Ecosystem = strings.ToLower(strings.TrimSpace(finding.Ecosystem))
	if !domain.Ecosystem(finding.Ecosystem).Valid() {
		return feedImportValidationErrorf("malicious import ecosystem is not supported")
	}
	finding.Name = packageid.NormalizeName(finding.Ecosystem, finding.Name)
	if strings.TrimSpace(finding.Name) == "" {
		return feedImportValidationErrorf("malicious import name is required")
	}
	finding.Source = feed
	if strings.TrimSpace(finding.Severity) == "" {
		finding.Severity = "CRITICAL"
	}
	finding.Severity = strings.ToUpper(strings.TrimSpace(finding.Severity))
	if !isImportVulnerabilitySeverity(finding.Severity) {
		return feedImportValidationErrorf("malicious import severity %q is not supported", finding.Severity)
	}
	if err := validateStringArrayJSON(finding.Versions, "malicious import versions"); err != nil {
		return err
	}
	return nil
}

func validateStringArrayJSON(raw json.RawMessage, field string) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return feedImportValidationErrorf("%s must be an array of strings", field)
	}
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return feedImportValidationErrorf("%s[%d] must not be empty", field, i)
		}
	}
	return nil
}

func validateVersionRangesJSON(raw json.RawMessage, field string) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var ranges []vulnerabilityImportVersionRange
	if err := json.Unmarshal(raw, &ranges); err != nil {
		return feedImportValidationErrorf("%s must be an array of range objects", field)
	}
	for i, versionRange := range ranges {
		if len(versionRange.Events) == 0 {
			return feedImportValidationErrorf("%s[%d].events must not be empty", field, i)
		}
		for j, event := range versionRange.Events {
			if strings.TrimSpace(event.Introduced) == "" &&
				strings.TrimSpace(event.Fixed) == "" &&
				strings.TrimSpace(event.LastAffected) == "" &&
				strings.TrimSpace(event.Limit) == "" {
				return feedImportValidationErrorf("%s[%d].events[%d] must set introduced, fixed, last_affected, or limit", field, i, j)
			}
		}
	}
	return nil
}

func isManualAdvisoryID(id string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(id)), "manual:")
}

type importDeleteID struct {
	Index int
	ID    string
}

func contextualizeFeedImportError(recordContext string, err error) error {
	if err == nil {
		return nil
	}
	var validationErr *feedImportValidationError
	if errors.As(err, &validationErr) {
		return feedImportValidationErrorf("%s: %s", recordContext, validationErr.Error())
	}
	return fmt.Errorf("%s: %w", recordContext, err)
}

func vulnerabilityImportRecordContext(index int, item db.Vulnerability) string {
	return importRecordContext("vulnerabilities", index, importRecordValue("id", item.ID))
}

func maliciousImportRecordContext(index int, item db.MaliciousFinding) string {
	return importRecordContext(
		"malicious",
		index,
		importRecordValue("id", item.ID),
		importPackageValue(item.Ecosystem, item.Name),
	)
}

func importRecordContext(field string, index int, values ...string) string {
	parts := []string{fmt.Sprintf("%s[%d]", field, index)}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, " ")
}

func importRecordValue(label, raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	return fmt.Sprintf("%s=%s", label, value)
}

func importPackageValue(ecosystem, name string) string {
	ecosystem = strings.TrimSpace(ecosystem)
	name = strings.TrimSpace(name)
	if ecosystem == "" || name == "" {
		return ""
	}
	return fmt.Sprintf("package=%s/%s", ecosystem, name)
}

func normalizeImportDeleteIDs(field string, ids []string) ([]importDeleteID, error) {
	normalized := make([]importDeleteID, 0, len(ids))
	for i, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if isManualAdvisoryID(id) {
			return nil, feedImportValidationErrorf("%s: feed import cannot delete manual advisory id %q", importRecordContext(field, i, importRecordValue("id", id)), id)
		}
		normalized = append(normalized, importDeleteID{Index: i, ID: id})
	}
	return normalized, nil
}

func importDeleteIDValues(items []importDeleteID) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}

func normalizeCISAKEVImportIDs(ids []string, clearMissing bool) ([]string, error) {
	normalized := make([]string, 0, len(ids))
	for i, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !cveIDPattern.MatchString(id) {
			return nil, feedImportValidationErrorf("cisa kev import cve_ids[%d] is invalid", i)
		}
		normalized = append(normalized, id)
	}
	if clearMissing && len(normalized) == 0 {
		return nil, feedImportValidationErrorf("cisa kev clear_missing requires at least one CVE ID")
	}
	return normalized, nil
}

func validateEPSSImportEntries(entries []db.EPSSEntry) error {
	for i, entry := range entries {
		if !validUnitInterval(entry.Score) {
			return feedImportValidationErrorf("epss import entries[%d].score must be between 0 and 1", i)
		}
		if !validUnitInterval(entry.Percentile) {
			return feedImportValidationErrorf("epss import entries[%d].percentile must be between 0 and 1", i)
		}
	}
	return nil
}

func validateVulnCheckImportEntries(entries []db.VulnCheckEntry) error {
	for i, entry := range entries {
		if entry.CVSSScore == nil {
			continue
		}
		if math.IsNaN(*entry.CVSSScore) || math.IsInf(*entry.CVSSScore, 0) || *entry.CVSSScore < 0 || *entry.CVSSScore > 10 {
			return feedImportValidationErrorf("vulncheck import entries[%d].cvss_score must be between 0 and 10", i)
		}
	}
	return nil
}

func validUnitInterval(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}

func validateImportStatusInput(input *feedSyncStatusInput) error {
	if input == nil {
		return nil
	}
	if input.LastSyncDurationMs != nil && *input.LastSyncDurationMs < 0 {
		return feedImportValidationErrorf("feed import status last_sync_duration_ms must not be negative")
	}
	if input.EntriesSynced < 0 {
		return feedImportValidationErrorf("feed import status entries_synced must not be negative")
	}
	if input.EntriesTotal < 0 {
		return feedImportValidationErrorf("feed import status entries_total must not be negative")
	}
	if input.EntriesTotal > 0 && input.EntriesSynced > input.EntriesTotal {
		return feedImportValidationErrorf("feed import status entries_synced must not exceed entries_total")
	}
	if len(input.Metadata) > maxImportStatusMetadataLength {
		return feedImportValidationErrorf("feed import status metadata exceeds %d bytes", maxImportStatusMetadataLength)
	}
	status := strings.TrimSpace(input.LastSyncStatus)
	if status == "" {
		return nil
	}
	switch status {
	case "success", "error", "running", "skipped", "disabled", "pending":
		return nil
	default:
		return feedImportValidationErrorf("feed import status %q is not supported", status)
	}
}

func truncateString(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseSyncEcosystems(raw string) ([]string, error) {
	ecosystems := splitCSV(raw)
	for i, ecosystem := range ecosystems {
		normalized := strings.ToLower(ecosystem)
		if !domain.Ecosystem(normalized).Valid() {
			return nil, fmt.Errorf("invalid ecosystem filter: %s", ecosystem)
		}
		ecosystems[i] = normalized
	}
	return ecosystems, nil
}

func parseRFC3339Timestamp(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid RFC3339 timestamp")
}

func requestCorrelationID(r *http.Request) string {
	// Prefer the value established by the Correlation middleware, which
	// validates/normalizes the incoming header to a canonical UUID. Only when
	// the middleware is not in the chain (e.g. direct handler unit tests) do we
	// generate a fresh ID. We deliberately do NOT echo a raw, unvalidated
	// client-supplied header here, to avoid log/response injection.
	if id := requestctx.CorrelationIDFromContext(r.Context()); id != "" {
		return id
	}
	id, err := correlation.NewID()
	if err != nil {
		return correlation.FallbackID()
	}
	return id
}

func isGetOrHead(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func writeJSONForRequest(w http.ResponseWriter, r *http.Request, status int, v any) {
	if r.Method == http.MethodHead {
		writeJSONHead(w, status)
		return
	}
	writeJSON(w, status, v)
}

func errorResponseForRequest(w http.ResponseWriter, r *http.Request, status int, message string) {
	writeJSONForRequest(w, r, status, errorJSON{Error: message})
}

// writeJSON encodes v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := encodeJSONResponse(v)
	if err != nil {
		slog.Warn("failed to encode JSON response", "error", err)
		writeJSONBytes(w, http.StatusInternalServerError, []byte(`{"error":"internal server error"}`+"\n"))
		return
	}
	writeJSONBytes(w, status, body)
}

func encodeJSONResponse(v any) ([]byte, error) {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func scanResultDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// generateID returns a random 8-byte hex string (16 characters) for scan IDs.
func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use timestamp-based ID. This should never happen with
		// crypto/rand, but we must not panic in a request handler.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func writeJSONHead(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
}

func writeJSONBytes(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil { // #nosec G705 -- body is produced by encodeJSONResponse with HTML escaping before reaching this writer.
		// At this point headers are already sent; we can only log.
		slog.Warn("failed to write JSON response", "error", err)
	}
}

// readJSON decodes the request body into v with the standard API size limit.
func readJSON(r *http.Request, v any) error {
	return readJSONWithLimit(r, v, maxRequestBody)
}

func readJSONWithLimit(r *http.Request, v any, limit int64) error {
	r.Body = http.MaxBytesReader(nil, r.Body, limit)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return sanitizedJSONDecodeError(err, limit)
	}

	// Reject trailing content after the first JSON value.
	var extra struct{}
	if err := dec.Decode(&extra); err == nil || !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected trailing data after JSON body")
	}

	return nil
}

func sanitizedJSONDecodeError(err error, limit int64) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "http: request body too large") {
		return fmt.Errorf("request body exceeds %d bytes", limit)
	}
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("empty JSON body")
	}
	if strings.HasPrefix(err.Error(), "json: unknown field ") {
		return fmt.Errorf("json body contains unknown field")
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("malformed JSON body")
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Errorf("json body has invalid field type")
	}

	return fmt.Errorf("invalid JSON body")
}

// errorJSON is the standard JSON error envelope.
type errorJSON struct {
	Error string `json:"error"`
}

// errorResponse sends a JSON error response with the given status and message.
func errorResponse(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorJSON{Error: message})
}

// clientIP delegates to the shared request-context helper.
func clientIP(r *http.Request) string {
	return requestctx.ClientIP(r)
}
