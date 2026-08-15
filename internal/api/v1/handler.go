// Package v1 implements the HTTP handlers for the Packmon API v1.
package v1

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/8linkz-sec/packmon/internal/checkcontract"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	feedhealth "github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/packageid"
	"github.com/8linkz-sec/packmon/internal/requestctx"
	"github.com/8linkz-sec/packmon/internal/telemetry"
)

const (
	// maxRequestBody is derived from the /check contract so a valid
	// MaxPackagesPerCheck request with maximum-size coordinates is not rejected
	// before package validation runs.
	maxRequestBody int64 = checkcontract.MaxPackagesPerCheck*(checkcontract.MaxPackageNameLength+checkcontract.MaxPackageVersionLength+128) + 1024

	// scanLogInsertTimeout bounds audit logging in the response critical path
	// when the backing database is slow or locked.
	scanLogInsertTimeout = 500 * time.Millisecond

	// checkLookupTimeout bounds the database lookup phase for /check so a
	// stalled store cannot consume the whole HTTP request lifetime.
	checkLookupTimeout = 10 * time.Second

	idempotencyKeyHeader          = "Idempotency-Key"
	maxIdempotencyKeyLength       = 128
	maxScanLogClientVersionLength = 64
)

// defaultBlockThreshold is the severity threshold above which findings block.
var defaultBlockThreshold = domain.SeverityCritical

// PackageLookup identifies a package version for API-owned batch lookup ports.
type PackageLookup struct {
	Ecosystem string
	Name      string
	Version   string
}

// Store is the API v1 persistence surface consumed by Handler.
type Store interface {
	// FindVulnerabilities looks up active vulnerability findings for one package
	// coordinate. Read/Write: read. Atomicity: no write transaction is required.
	// Side Effects: none.
	FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)

	// FindMalicious looks up active malicious-package findings for one package
	// coordinate. Read/Write: read. Atomicity: no write transaction is required.
	// Side Effects: none.
	FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error)

	// FindVulnerabilitiesBatch looks up active vulnerability findings for a
	// package batch. Read/Write: read. Atomicity: no write transaction is
	// required. Side Effects: none.
	FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error)

	// FindMaliciousBatch looks up active malicious-package findings for a
	// package batch. Read/Write: read. Atomicity: no write transaction is
	// required. Side Effects: none.
	FindMaliciousBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error)

	// FindReputationFindingsBatch looks up cached reputation findings for one
	// source. Read/Write: read. Atomicity: no write transaction is required.
	// Side Effects: none.
	FindReputationFindingsBatch(ctx context.Context, packages []PackageLookup, source string) ([]domain.Finding, error)

	// FindLifecycleFindingsBatch looks up cached lifecycle findings evaluated at
	// now. Read/Write: read. Atomicity: no write transaction is required.
	// Side Effects: none.
	FindLifecycleFindingsBatch(ctx context.Context, packages []PackageLookup, now time.Time) ([]domain.Finding, error)

	// ListFeedSyncStatuses lists feed status rows used for API feed health and
	// version metadata. Read/Write: read. Atomicity: no write transaction is
	// required. Side Effects: none.
	ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error)

	// EnqueueRefresh stores a package refresh queue request. Read/Write: write.
	// Atomicity: job creation/reprioritization and returned position describe
	// the same store operation. Side Effects: refresh queue only; no audit row.
	EnqueueRefresh(ctx context.Context, job *db.RefreshJob) (bool, int, error)

	// EnqueueRefreshWithAudit stores a refresh queue request and its audit row.
	// Read/Write: write. Atomicity: queue mutation and admin audit insert commit
	// or fail together. Side Effects: refresh queue plus admin audit log.
	EnqueueRefreshWithAudit(ctx context.Context, job *db.RefreshJob, audit db.RefreshEnqueueAuditBuilder) (bool, int, error)

	// InsertScanLog stores the completed /check scan-log record. Read/Write:
	// write. Atomicity: scan log/idempotency state is persisted as one store
	// operation. Scan-Log Semantics: no admin audit row is implied.
	InsertScanLog(ctx context.Context, entry *db.ScanLogEntry) error

	// InsertAdminAuditLog appends one admin audit record. Read/Write: write.
	// Atomicity: one audit entry is written or the call fails. Side Effects:
	// admin audit log only.
	InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error

	// GetScanLogByIdempotencyKey looks up prior /check scan-log/idempotency
	// state. Read/Write: read. Scan-Log Semantics: return nil when the key is
	// unknown. Side Effects: none.
	GetScanLogByIdempotencyKey(ctx context.Context, key string) (*db.ScanLogEntry, error)

	// ExportSync returns an export snapshot for CLI sync. Read/Write: read.
	// Atomicity: callers expect a consistent export cursor/snapshot from one
	// store call. Side Effects: none; sync export audit is recorded separately.
	ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error)
}

// ReputationSchedulerConfig is the API-owned scheduling configuration consumed
// by an injected reputation scheduler.
type ReputationSchedulerConfig struct {
	ReversingLabsActive              bool
	ReversingLabsMaxSchedulePerCheck int
	ReversingLabsExcludedNamespaces  []string
}

// ReputationScheduler is the optional API boundary for demand-driven package
// reputation scheduling.
type ReputationScheduler interface {
	Configure(ReputationSchedulerConfig)
	ScheduleReversingLabsAsync(ctx context.Context, packages []domain.Package, findings []domain.Finding)
}

// PackageRefreshProviderConfig is the API-owned runtime configuration for an
// injected package refresh provider.
type PackageRefreshProviderConfig struct {
	Active             bool
	ExcludedNamespaces []string
}

// PackageRefreshProvider describes the optional worker backing manual package
// refresh requests.
type PackageRefreshProvider interface {
	Configure(PackageRefreshProviderConfig)
	Active() bool
	Source() string
	SupportsEcosystem(ecosystem string) bool
}

type packageRefreshPolicyExcluder interface {
	ExcludedByPolicy(ecosystem, name string) bool
}

type packageRefreshAuditEnqueuer interface {
	EnqueueRefreshWithAudit(ctx context.Context, job *db.RefreshJob, audit db.RefreshEnqueueAuditBuilder) (bool, int, error)
}

type apiRequestLoggerKey struct{}

// Handler holds the dependencies for all API v1 HTTP handlers.
type Handler struct {
	store                Store
	logger               *slog.Logger
	blockThreshold       domain.Severity
	reversingLabsEnabled atomic.Bool
	reputationScheduler  ReputationScheduler
	packageRefresh       PackageRefreshProvider
	backgroundCtx        context.Context
	checkLookupTimeout   time.Duration
	checkResponseCache   *checkResponseCache
	scanLogIdentityMode  config.ScanLogIdentityMode
	// runtime, when set, supplies the block threshold dynamically so admin
	// changes take effect without a restart. It overrides blockThreshold.
	runtime *config.RuntimeSettings
}

type reputationPackageFinder interface {
	FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error)
}

type packageCheckStatusGetter interface {
	GetPackageCheckStatus(ctx context.Context, ecosystem, name, source string) (*db.PackageCheckStatus, error)
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
		backgroundCtx:       context.Background(),
		checkLookupTimeout:  checkLookupTimeout,
		checkResponseCache:  newCheckResponseCache(defaultCheckResponseCacheTTL, defaultCheckResponseCacheMaxEntries),
		scanLogIdentityMode: scanLogIdentityModeFromEnv(),
	}
	return h
}

// ConfigureScanLogIdentityMode sets which identity-adjacent fields are
// retained in server-side scan_log rows. Invalid values fail closed to full
// compatibility mode.
func (h *Handler) ConfigureScanLogIdentityMode(mode config.ScanLogIdentityMode) {
	if h == nil {
		return
	}
	if _, err := config.ParseScanLogIdentityMode(string(mode)); err != nil {
		mode = config.ScanLogIdentityModeFull
	}
	h.scanLogIdentityMode = mode
}

func scanLogIdentityModeFromEnv() config.ScanLogIdentityMode {
	mode, err := config.ScanLogIdentityModeFromEnv()
	if err != nil {
		return config.ScanLogIdentityModeFull
	}
	return mode
}

// ConfigureReputationScheduler injects the optional demand-driven reputation
// scheduling capability. Passing nil disables request-triggered scheduling.
func (h *Handler) ConfigureReputationScheduler(scheduler ReputationScheduler) {
	if h == nil {
		return
	}
	h.reputationScheduler = scheduler
}

// ConfigurePackageRefreshProvider injects the optional manual package refresh
// capability. Passing nil disables manual refresh.
func (h *Handler) ConfigurePackageRefreshProvider(provider PackageRefreshProvider) {
	if h == nil {
		return
	}
	h.packageRefresh = provider
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
	if h.reputationScheduler != nil {
		h.reputationScheduler.Configure(ReputationSchedulerConfig{
			ReversingLabsActive:              schedulingEnabled,
			ReversingLabsMaxSchedulePerCheck: feeds.ReversingLabsMaxSchedulePerCheck,
			ReversingLabsExcludedNamespaces:  feeds.ReversingLabsExcludedNamespaces,
		})
	}
}

func (h *Handler) reputationReadSources() []db.ReputationReadSource {
	if h == nil || !h.reversingLabsEnabled.Load() {
		return nil
	}
	return db.ReputationReadSources()
}

// ConfigureSocketRefresh enables optional manual Socket.dev package refresh
// queueing. The handler enqueues work only; the async worker performs external
// calls and persists the normalized check status.
func (h *Handler) ConfigureSocketRefresh(feeds config.FeedsConfig) {
	if h == nil || h.packageRefresh == nil {
		return
	}
	h.packageRefresh.Configure(PackageRefreshProviderConfig{
		Active:             feeds.SocketEnabled && feeds.SocketMode == config.FeedModeSelf && strings.TrimSpace(feeds.SocketAPIKey) != "",
		ExcludedNamespaces: feeds.SocketExcludedNamespaces,
	})
}

func parseBlockThreshold(raw string) domain.Severity {
	if threshold, ok := domain.ParseBlockThreshold(raw); ok {
		return threshold
	}
	return defaultBlockThreshold
}

func validBlockThreshold(threshold domain.Severity) bool {
	_, ok := domain.ParseBlockThreshold(string(threshold))
	return ok
}

// ----------------------------------------------------------------------------
// POST /api/v1/check
// ----------------------------------------------------------------------------

// HandleCheck processes a scan request, looks up vulnerability, malicious,
// reputation, and lifecycle findings for every package, and returns a
// ScanResult using domain.FindingsBlock as the blocking-policy source of truth.
func (h *Handler) HandleCheck(w http.ResponseWriter, r *http.Request) {
	r = requestWithLogger(r, h.logger)
	if r.Method != http.MethodPost {
		methodNotAllowedForRequest(w, r, http.MethodPost)
		return
	}

	start := time.Now()
	correlationID := requestCorrelationID(r)

	checkRequest, ok := h.parseCheckRequest(w, r, correlationID)
	if !ok {
		return
	}
	lookupCtx, cancelLookup := context.WithTimeout(r.Context(), h.effectiveCheckLookupTimeout())
	defer cancelLookup()

	idempotency, ok := h.resolveCheckIdempotency(w, r, lookupCtx, checkRequest.idempotencyKey, checkRequest.requestDigest, correlationID)
	if !ok {
		return
	}
	if idempotency.replay {
		if cached, ok := h.cachedCheckResponse(idempotency.storedKey, checkRequest.requestDigest); ok {
			writeCheckResponseHeaders(w, correlationID, cached.durationMs, checkRequest.idempotencyKey)
			writeJSONBytesForRequest(w, r, cached.statusCode, cached.body)
			return
		}
	}
	result, resultBody, ok := h.buildCheckResult(w, r, lookupCtx, start, idempotency.scanID, checkRequest.request.Packages, !idempotency.replay, correlationID)
	if !ok {
		return
	}
	if !h.persistCheckScanLog(w, r, lookupCtx, &checkRequest.request, &result, checkRequest.idempotencyKey, idempotency.storedKey, checkRequest.requestDigest, resultBody, idempotency.replay, correlationID) {
		return
	}
	h.cacheCheckResponse(idempotency.storedKey, checkRequest.requestDigest, http.StatusOK, result.DurationMs, resultBody)

	writeCheckResponseHeaders(w, correlationID, result.DurationMs, checkRequest.idempotencyKey)
	writeJSONBytesForRequest(w, r, http.StatusOK, resultBody)
}

func (h *Handler) cachedCheckResponse(storedIdempotencyKey, requestDigest string) (cachedCheckResponse, bool) {
	if h == nil || h.checkResponseCache == nil {
		return cachedCheckResponse{}, false
	}
	return h.checkResponseCache.Get(checkResponseCacheKey(storedIdempotencyKey, requestDigest))
}

func (h *Handler) cacheCheckResponse(storedIdempotencyKey, requestDigest string, statusCode int, durationMs int64, body []byte) {
	if h == nil || h.checkResponseCache == nil {
		return
	}
	h.checkResponseCache.Set(checkResponseCacheKey(storedIdempotencyKey, requestDigest), cachedCheckResponse{
		statusCode: statusCode,
		durationMs: durationMs,
		body:       body,
	})
}

func (h *Handler) effectiveCheckLookupTimeout() time.Duration {
	if h == nil || h.checkLookupTimeout <= 0 {
		return checkLookupTimeout
	}
	return h.checkLookupTimeout
}

type checkRequestParts struct {
	request        domain.ScanRequest
	idempotencyKey string
	requestDigest  string
}

type checkIdempotencyResolution struct {
	scanID    string
	replay    bool
	storedKey string
}

type checkRequest struct {
	Packages []checkPackage         `json:"packages"`
	Repo     *domain.RemoteRepoInfo `json:"repo,omitempty"`
}

type checkPackage struct {
	Name      string           `json:"name"`
	Version   string           `json:"version"`
	Ecosystem domain.Ecosystem `json:"ecosystem"`
}

func (h *Handler) parseCheckRequest(w http.ResponseWriter, r *http.Request, correlationID string) (checkRequestParts, bool) {
	var wireReq checkRequest
	if err := requireJSONContentType(r); err != nil {
		h.logger.Warn("invalid check request content type", "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusUnsupportedMediaType, err.Error())
		return checkRequestParts{}, false
	}
	if err := readJSON(r, &wireReq); err != nil {
		h.logger.Warn("invalid check request body", "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusBadRequest, "invalid request body: "+err.Error())
		return checkRequestParts{}, false
	}

	req := domain.ScanRequest{
		Packages: checkPackagesToDomain(wireReq.Packages),
		Repo:     wireReq.Repo,
	}
	if len(req.Packages) == 0 {
		errorResponseForRequest(w, r, http.StatusBadRequest, "packages array is required and must not be empty")
		return checkRequestParts{}, false
	}
	if len(req.Packages) > checkcontract.MaxPackagesPerCheck {
		errorResponseForRequest(w, r, http.StatusBadRequest, fmt.Sprintf("too many packages: %d (max %d)", len(req.Packages), checkcontract.MaxPackagesPerCheck))
		return checkRequestParts{}, false
	}
	if err := validateCheckPackages(req.Packages); err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return checkRequestParts{}, false
	}
	req.Packages = deduplicateCheckPackages(req.Packages)

	idempotencyKey, err := checkIdempotencyKey(r)
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return checkRequestParts{}, false
	}
	requestDigest, err := checkRequestDigest(&req)
	if err != nil {
		h.logger.Error("failed to digest check request", "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusInternalServerError, "internal error while checking packages")
		return checkRequestParts{}, false
	}

	return checkRequestParts{
		request:        req,
		idempotencyKey: idempotencyKey,
		requestDigest:  requestDigest,
	}, true
}

func checkPackagesToDomain(packages []checkPackage) []domain.Package {
	out := make([]domain.Package, len(packages))
	for i, pkg := range packages {
		out[i] = domain.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
		}
	}
	return out
}

func (h *Handler) resolveCheckIdempotency(w http.ResponseWriter, r *http.Request, ctx context.Context, idempotencyKey, requestDigest, correlationID string) (checkIdempotencyResolution, bool) {
	resolution := checkIdempotencyResolution{scanID: generateID()}
	if idempotencyKey != "" {
		resolution.storedKey = scanLogIdempotencyKey(idempotencyKey)
		resolution.scanID = scanIDForIdempotencyKey(resolution.storedKey, requestDigest)
		if existing, ok, err := h.existingIdempotentScan(ctx, resolution.storedKey, idempotencyKey); err != nil {
			h.logger.Error("failed to check idempotency key", "error", err, "correlation_id", correlationID)
			checkStoreErrorResponse(w, r, err)
			return checkIdempotencyResolution{}, false
		} else if ok {
			if existing.RequestDigest != "" && existing.RequestDigest != requestDigest {
				errorResponseForRequest(w, r, http.StatusConflict, "idempotency key was already used for a different check request")
				return checkIdempotencyResolution{}, false
			}
			if existing.ScanID != "" {
				resolution.scanID = existing.ScanID
			}
			resolution.replay = true
		}
	}
	return resolution, true
}

func (h *Handler) buildCheckResult(w http.ResponseWriter, r *http.Request, ctx context.Context, start time.Time, scanID string, packages []domain.Package, scheduleReversingLabs bool, correlationID string) (domain.ScanResult, []byte, bool) {
	collection, err := h.collectFindingsForCheck(ctx, packages, scheduleReversingLabs)
	if err != nil {
		h.logger.Error("failed to collect findings", "error", err, "correlation_id", correlationID)
		checkStoreErrorResponse(w, r, err)
		return domain.ScanResult{}, nil, false
	}
	for _, failure := range collection.optionalLookupFailures {
		h.logger.Warn("optional finding lookup failed", "lookup", failure.lookup, "error", failure.err, "correlation_id", correlationID)
	}
	findings := collection.findings
	if findings == nil {
		findings = []domain.Finding{}
	}

	// Build summary maps.
	summary := domain.BuildScanSummary(findings)

	// Determine blocking status through the shared scan policy:
	// malicious/active supply-chain risk always block, vulnerability and
	// lifecycle findings are severity-gated, and informational reputation
	// findings never block.
	blockThreshold := h.effectiveBlockThreshold()
	blocking := domain.FindingsBlock(findings, blockThreshold)

	// Assemble feed status and versions from sync state.
	feedStatus, feedVersions := h.feedState(ctx, correlationID)
	if collection.degraded {
		feedStatus = string(domain.ScanFeedStatusDegraded)
	}
	if feedStatus == string(domain.ScanFeedStatusDegraded) {
		telemetry.Default().IncDegradedResponses()
	}

	durationMs := time.Since(start).Milliseconds()

	result := domain.ScanResult{
		ScanID:                scanID,
		Mode:                  domain.ScanModeRemote,
		ScannedAt:             start.UTC(),
		DurationMs:            durationMs,
		PackagesScanned:       len(packages),
		FindingsCount:         len(findings),
		FindingsBlocking:      blocking,
		BlockThreshold:        blockThreshold,
		FeedStatus:            feedStatus,
		Summary:               summary,
		Findings:              findings,
		FeedVersions:          feedVersions,
		ManualAdvisoriesCount: domain.CountManualAdvisoryFindings(findings),
	}
	resultBody, err := encodeJSONResponse(result)
	if err != nil {
		h.logger.Error("failed to encode check response", "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusInternalServerError, "internal error while encoding scan result")
		return domain.ScanResult{}, nil, false
	}
	return result, resultBody, true
}

func (h *Handler) persistCheckScanLog(w http.ResponseWriter, r *http.Request, ctx context.Context, req *domain.ScanRequest, result *domain.ScanResult, rawIdempotencyKey, storedIdempotencyKey, requestDigest string, resultBody []byte, idempotencyReplay bool, correlationID string) bool {
	if idempotencyReplay {
		return true
	}
	logCtx, cancelLog := context.WithTimeout(context.WithoutCancel(r.Context()), scanLogInsertTimeout)
	defer cancelLog()
	if err := h.logScan(logCtx, result, r, req, correlationID, storedIdempotencyKey, requestDigest, scanResultDigest(resultBody)); err != nil {
		h.logger.Error("failed to insert scan log", "error", err, "correlation_id", correlationID, "idempotency_key_present", rawIdempotencyKey != "")
		if rawIdempotencyKey != "" {
			errorResponseForRequest(w, r, http.StatusInternalServerError, "internal error while recording idempotency state")
			return false
		}
		return true
	}
	return h.verifyCheckIdempotencyAfterLog(w, r, ctx, storedIdempotencyKey, rawIdempotencyKey, requestDigest, correlationID)
}

func (h *Handler) verifyCheckIdempotencyAfterLog(w http.ResponseWriter, r *http.Request, ctx context.Context, storedIdempotencyKey, rawIdempotencyKey, requestDigest, correlationID string) bool {
	if storedIdempotencyKey == "" {
		return true
	}
	if existing, ok, err := h.existingIdempotentScan(ctx, storedIdempotencyKey, rawIdempotencyKey); err != nil {
		h.logger.Error("failed to verify idempotency key", "error", err, "correlation_id", correlationID)
		checkStoreErrorResponse(w, r, err)
		return false
	} else if ok && existing.RequestDigest != "" && existing.RequestDigest != requestDigest {
		errorResponseForRequest(w, r, http.StatusConflict, "idempotency key was already used for a different check request")
		return false
	}
	return true
}

func checkStoreErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.DeadlineExceeded) && r.Context().Err() == nil {
		errorResponseForRequest(w, r, http.StatusServiceUnavailable, "check service temporarily unavailable")
		return
	}
	errorResponseForRequest(w, r, http.StatusInternalServerError, "internal error while checking packages")
}

func writeCheckResponseHeaders(w http.ResponseWriter, correlationID string, durationMs int64, idempotencyKey string) {
	w.Header().Set(correlation.Header, correlationID)
	w.Header().Set("X-Scan-Duration-Ms", fmt.Sprintf("%d", durationMs))
	if idempotencyKey != "" {
		w.Header().Set(idempotencyKeyHeader, idempotencyKey)
	}
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
		if len(pkg.Name) > checkcontract.MaxPackageNameLength {
			return fmt.Errorf("packages[%d].name exceeds %d characters", position, checkcontract.MaxPackageNameLength)
		}
		if pkg.Version == "" {
			return fmt.Errorf("packages[%d].version is required", position)
		}
		if len(pkg.Version) > checkcontract.MaxPackageVersionLength {
			return fmt.Errorf("packages[%d].version exceeds %d characters", position, checkcontract.MaxPackageVersionLength)
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
	return ecosystem.ScanInput()
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

// collectFindings queries the store for all check-path finding classes using
// batch queries to avoid the N+1 pattern. Required vulnerability and malicious
// lookup failures abort the check; optional reputation and lifecycle lookup
// failures return the core findings with degraded coverage metadata.
func (h *Handler) collectFindings(ctx context.Context, packages []domain.Package) ([]domain.Finding, error) {
	collection, err := h.collectFindingsForCheck(ctx, packages, true)
	return collection.findings, err
}

type findingCollection struct {
	findings               []domain.Finding
	degraded               bool
	optionalLookupFailures []optionalLookupFailure
}

type optionalLookupFailure struct {
	lookup string
	err    error
}

func (h *Handler) collectFindingsForCheck(ctx context.Context, packages []domain.Package, scheduleReversingLabs bool) (findingCollection, error) {
	packages = deduplicateCheckPackages(packages)

	queries := make([]PackageLookup, len(packages))
	for i, pkg := range packages {
		queries[i] = PackageLookup{
			Ecosystem: string(pkg.Ecosystem),
			Name:      pkg.Name,
			Version:   pkg.Version,
		}
	}

	lookupCtx, cancelLookup := context.WithCancel(ctx)
	defer cancelLookup()

	var wg sync.WaitGroup
	var vulns, mal, reputation, lifecycle []domain.Finding
	var vulnErr, malErr, reputationErr, lifecycleErr error
	reputationSources := h.reputationReadSources()
	lifecycleNow := time.Now().UTC()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		vulns, err = h.store.FindVulnerabilitiesBatch(lookupCtx, queries)
		if err != nil {
			vulnErr = fmt.Errorf("FindVulnerabilitiesBatch: %w", err)
			cancelLookup()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		mal, err = h.store.FindMaliciousBatch(lookupCtx, queries)
		if err != nil {
			malErr = fmt.Errorf("FindMaliciousBatch: %w", err)
			cancelLookup()
		}
	}()

	if len(reputationSources) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, source := range reputationSources {
				findings, err := h.store.FindReputationFindingsBatch(lookupCtx, queries, source.Source)
				if err != nil {
					reputationErr = fmt.Errorf("FindReputationFindingsBatch(%s): %w", source.Source, err)
					return
				}
				reputation = append(reputation, findings...)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		lifecycle, lifecycleErr = h.store.FindLifecycleFindingsBatch(lookupCtx, queries, lifecycleNow)
	}()

	wg.Wait()
	if vulnErr != nil {
		return findingCollection{}, vulnErr
	}
	if malErr != nil {
		return findingCollection{}, malErr
	}

	var collection findingCollection
	if reputationErr != nil {
		collection.degraded = true
		collection.optionalLookupFailures = append(collection.optionalLookupFailures, optionalLookupFailure{
			lookup: "reputation",
			err:    reputationErr,
		})
		reputation = nil
	}
	if lifecycleErr != nil {
		collection.degraded = true
		collection.optionalLookupFailures = append(collection.optionalLookupFailures, optionalLookupFailure{
			lookup: "lifecycle",
			err:    lifecycleErr,
		})
		lifecycle = nil
	}

	all := make([]domain.Finding, 0, len(vulns)+len(mal)+len(reputation)+len(lifecycle))
	all = append(all, vulns...)
	all = append(all, mal...)
	all = append(all, reputation...)
	all = append(all, lifecycle...)

	if scheduleReversingLabs && h.reversingLabsEnabled.Load() && h.reputationScheduler != nil {
		h.reputationScheduler.ScheduleReversingLabsAsync(h.backgroundContext(), packages, all)
	}

	collection.findings = all
	return collection, nil
}

func (h *Handler) backgroundContext() context.Context {
	if h == nil || h.backgroundCtx == nil {
		return context.Background()
	}
	return h.backgroundCtx
}

// feedState builds both the overall remote feed status and the per-feed versions.
func (h *Handler) feedState(ctx context.Context, correlationID string) (string, map[string]string) {
	statuses, err := h.store.ListFeedSyncStatuses(ctx)
	if err != nil {
		if correlationID == "" {
			correlationID = requestctx.CorrelationIDFromContext(ctx)
		}
		attrs := []any{"error", err}
		if correlationID != "" {
			attrs = append(attrs, "correlation_id", correlationID)
		}
		h.logger.Warn("failed to list feed sync statuses", attrs...)
		return string(domain.ScanFeedStatusDegraded), map[string]string{}
	}

	return overallFeedStatus(statuses), feedVersionsFromStatuses(statuses)
}

func feedVersionsFromStatuses(statuses []db.FeedSyncStatus) map[string]string {
	m := make(map[string]string, len(statuses))
	for _, s := range statuses {
		if s.LastSyncAt != nil {
			m[s.FeedName] = formatAPIDateTime(*s.LastSyncAt)
		}
	}
	return m
}

func overallFeedStatus(statuses []db.FeedSyncStatus) string {
	return feedhealth.OverallFeedStatus(statuses, feedhealth.HealthOptions{})
}

// logScan persists a scan log entry for a completed scan.
func (h *Handler) logScan(ctx context.Context, result *domain.ScanResult, r *http.Request, req *domain.ScanRequest, correlationID, idempotencyKey, requestDigest, resultDigest string) error {
	identityMode := h.scanLogIdentityMode
	if identityMode == "" {
		identityMode = config.ScanLogIdentityModeFull
	}
	entry := &db.ScanLogEntry{
		ScanID:        result.ScanID,
		ScannedAt:     result.ScannedAt,
		PackagesCount: result.PackagesScanned,
		FindingsCount: result.FindingsCount,
		DurationMs:    int(result.DurationMs),
	}
	if identityMode == config.ScanLogIdentityModeFull {
		entry.ClientIP = clientIP(r)
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
	entry.ManualAdvisoriesCount = result.ManualAdvisoriesCount
	if identityMode != config.ScanLogIdentityModeNone && req != nil && req.Repo != nil {
		entry.RepoName = scanLogRepoName(req.Repo.Name)
	}
	if identity, ok := requestctx.APIKeyIdentityFromContext(r.Context()); ok {
		if identityMode == config.ScanLogIdentityModeFull {
			entry.APIKeyID = identity.ID
			entry.APIKeyName = identity.Name
		}
		if identityMode != config.ScanLogIdentityModeNone {
			entry.ClientVersion = scanLogClientVersion(r.Header.Get("User-Agent"))
		}
	}
	if err := h.store.InsertScanLog(ctx, entry); err != nil {
		return fmt.Errorf("insert scan log: %w", err)
	}
	return nil
}

func scanLogClientVersion(userAgent string) string {
	for _, field := range strings.Fields(userAgent) {
		for _, prefix := range []string{"packmon-cli/", "packmon/"} {
			if strings.HasPrefix(field, prefix) {
				version := strings.TrimSpace(strings.TrimPrefix(field, prefix))
				if validScanLogClientVersion(version) {
					return version
				}
				return ""
			}
		}
	}
	return ""
}

func validScanLogClientVersion(version string) bool {
	if version == "" || len(version) > maxScanLogClientVersionLength {
		return false
	}
	parts := strings.SplitN(version, "+", 2)
	core := parts[0]
	if len(parts) == 2 && !validSemVerIdentifierList(parts[1]) {
		return false
	}
	coreParts := strings.SplitN(core, "-", 2)
	if len(coreParts) == 2 && !validSemVerIdentifierList(coreParts[1]) {
		return false
	}
	nums := strings.Split(coreParts[0], ".")
	if len(nums) != 3 {
		return false
	}
	for _, n := range nums {
		if !validSemVerNumber(n) {
			return false
		}
	}
	return true
}

func validSemVerNumber(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return len(value) == 1 || value[0] != '0'
}

func validSemVerIdentifierList(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, ch := range part {
			switch {
			case ch >= 'a' && ch <= 'z':
			case ch >= 'A' && ch <= 'Z':
			case ch >= '0' && ch <= '9':
			case ch == '-':
			default:
				return false
			}
		}
	}
	return true
}

func (h *Handler) existingIdempotentScan(ctx context.Context, storedKey, rawKey string) (*db.ScanLogEntry, bool, error) {
	for _, key := range scanLogIdempotencyLookupKeys(storedKey, rawKey) {
		entry, err := h.store.GetScanLogByIdempotencyKey(ctx, key)
		if err != nil {
			return nil, false, err
		}
		if entry != nil {
			return entry, true, nil
		}
	}
	return nil, false, nil
}

func scanLogIdempotencyLookupKeys(storedKey, rawKey string) []string {
	storedKey = strings.TrimSpace(storedKey)
	rawKey = strings.TrimSpace(rawKey)
	if storedKey == "" {
		return nil
	}
	if rawKey == "" || rawKey == storedKey {
		return []string{storedKey}
	}
	return []string{storedKey, rawKey}
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

func scanLogIdempotencyKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("packmon scan-log idempotency key v1\x00" + raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func checkRequestDigest(req *domain.ScanRequest) (string, error) {
	body, err := json.Marshal(struct {
		Packages []domain.Package       `json:"packages"`
		Repo     *domain.RemoteRepoInfo `json:"repo,omitempty"`
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
	r = requestWithLogger(r, h.logger)
	if !isGetOrHead(r.Method) {
		methodNotAllowedForRequest(w, r, http.MethodGet, http.MethodHead)
		return
	}
	if r.Method == http.MethodHead {
		writeJSONHead(w, http.StatusOK)
		return
	}

	correlationID := requestCorrelationID(r)
	statuses, err := h.store.ListFeedSyncStatuses(r.Context())
	if err != nil {
		h.logger.Error("failed to list feed sync statuses", "error", err, "correlation_id", correlationID)
		writeJSONForRequest(w, r, http.StatusOK, FeedStatusResponse{
			Status:  string(domain.ScanFeedStatusDegraded),
			Message: "feed status unavailable: feed sync status rows could not be read",
			Feeds:   []FeedStatusItem{},
		})
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
			ts := formatAPIDateTime(*s.LastSyncAt)
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
	} else if status != string(domain.ScanFeedStatusHealthy) {
		message = "one or more feeds are degraded"
	}
	writeJSONForRequest(w, r, http.StatusOK, FeedStatusResponse{Status: status, Message: message, Feeds: items})
}

// feedHealthStatus delegates to feed.FeedStatusHealth, the shared source of
// truth for API, web, admin, and startup feed health labels. The returned value
// may be healthy, warning, error, disabled, configured, or pending.
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
	r = requestWithLogger(r, h.logger)
	if !isGetOrHead(r.Method) {
		methodNotAllowedForRequest(w, r, http.MethodGet, http.MethodHead)
		return
	}

	correlationID := requestCorrelationID(r)
	ecosystem := r.PathValue("ecosystem")
	name := r.PathValue("rest")
	var err error
	ecosystem, name, err = normalizePackagePath(ecosystem, name)
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	version, err := normalizePackageVersionQuery(r.URL.Query().Get("version"))
	if err != nil {
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if r.Method == http.MethodHead {
		writeJSONHead(w, http.StatusOK)
		return
	}

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
	for _, source := range h.reputationReadSources() {
		if version != "" {
			findings, err := h.store.FindReputationFindingsBatch(ctx, []PackageLookup{{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
			}}, source.Source)
			if err != nil {
				h.logger.Warn("optional reputation lookup failed", "ecosystem", ecosystem, "name", name, "version", version, "error", err, "correlation_id", correlationID)
				continue
			}
			reputation = append(reputation, findings...)
		} else if finder, ok := h.store.(reputationPackageFinder); ok {
			findings, err := finder.FindReputationFindings(ctx, ecosystem, name, source.Source)
			if err != nil {
				h.logger.Warn("optional reputation lookup failed", "ecosystem", ecosystem, "name", name, "error", err, "correlation_id", correlationID)
				continue
			}
			reputation = append(reputation, findings...)
		}
	}

	var lifecycle []domain.Finding
	if version != "" {
		lifecycle, err = h.store.FindLifecycleFindingsBatch(ctx, []PackageLookup{{
			Ecosystem: ecosystem,
			Name:      name,
			Version:   version,
		}}, time.Now().UTC())
		if err != nil {
			h.logger.Warn("optional lifecycle lookup failed", "ecosystem", ecosystem, "name", name, "version", version, "error", err, "correlation_id", correlationID)
			lifecycle = nil
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
	r = requestWithLogger(r, h.logger)
	rest := r.PathValue("rest")
	if strings.HasSuffix(rest, "/refresh") {
		// Inject the trimmed name back so HandleRefresh can read it.
		name := strings.TrimSuffix(rest, "/refresh")
		if name == "" {
			errorResponseForRequest(w, r, http.StatusBadRequest, "package name is required")
			return
		}
		h.handleRefresh(w, r, r.PathValue("ecosystem"), name)
		return
	}
	methodNotAllowedWithMessageForRequest(w, r, "method not allowed; did you mean POST .../refresh?", http.MethodGet, http.MethodHead)
}

// HandlePackage dispatches all methods for package API paths so router
// fallbacks can keep the API JSON error envelope for unsupported methods.
func (h *Handler) HandlePackage(w http.ResponseWriter, r *http.Request) {
	r = requestWithLogger(r, h.logger)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.HandlePackageDetail(w, r)
	case http.MethodPost:
		h.HandlePackageOrRefresh(w, r)
	default:
		methodNotAllowedForRequest(w, r, http.MethodGet, http.MethodHead, http.MethodPost)
	}
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
		errorResponseForRequest(w, r, http.StatusBadRequest, err.Error())
		return
	}

	correlationID := requestCorrelationID(r)
	// Body is optional. If present, it must be an empty JSON object.
	if r.Body != nil && r.ContentLength != 0 {
		if err := requireJSONContentType(r); err != nil {
			h.logger.Warn("invalid refresh request content type", "error", err, "correlation_id", correlationID)
			errorResponseForRequest(w, r, http.StatusUnsupportedMediaType, err.Error())
			return
		}
		var req struct{}
		if err := readJSON(r, &req); err != nil {
			h.logger.Warn("invalid refresh request body", "error", err, "correlation_id", correlationID)
			errorResponseForRequest(w, r, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
	}
	refreshProvider := h.packageRefresh
	if refreshProvider == nil || !refreshProvider.Active() {
		errorResponseForRequest(w, r, http.StatusConflict, "no active refresh worker is configured")
		return
	}
	if !refreshProvider.SupportsEcosystem(ecosystem) {
		errorResponseForRequest(w, r, http.StatusConflict, fmt.Sprintf("no active refresh worker supports ecosystem: %s", ecosystem))
		return
	}
	if excluder, ok := refreshProvider.(packageRefreshPolicyExcluder); ok && excluder.ExcludedByPolicy(ecosystem, name) {
		errorResponseForRequest(w, r, http.StatusConflict, fmt.Sprintf("refresh skipped for %s/%s; package excluded by private namespace policy", ecosystem, name))
		return
	}
	source := refreshProvider.Source()
	if strings.TrimSpace(source) == "" {
		errorResponseForRequest(w, r, http.StatusConflict, "no active refresh worker is configured")
		return
	}
	if getter, ok := h.store.(packageCheckStatusGetter); ok {
		status, err := getter.GetPackageCheckStatus(r.Context(), ecosystem, name, source)
		if err != nil {
			h.logger.Error("failed to check package refresh budget", "ecosystem", ecosystem, "name", name, "error", err, "correlation_id", correlationID)
			errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to check refresh budget")
			return
		}
		if status != nil && status.NextCheckAt != nil && status.NextCheckAt.After(time.Now().UTC()) {
			writeJSONForRequest(w, r, http.StatusAccepted, RefreshResponse{
				Queued:  false,
				New:     false,
				Message: fmt.Sprintf("refresh skipped for %s/%s; next check after %s", ecosystem, name, formatAPIDateTime(*status.NextCheckAt)),
			})
			return
		}
	}

	job := &db.RefreshJob{
		Ecosystem: ecosystem,
		Name:      name,
		Source:    source,
		Priority:  db.RefreshPriorityManual,
		Status:    "pending",
	}

	created, position, err := h.enqueuePackageRefreshWithAudit(r.Context(), job, h.packageRefreshAuditBuilder(r, ecosystem, name, source))
	if err != nil {
		h.logger.Error("failed to enqueue refresh", "ecosystem", ecosystem, "name", name, "error", err, "correlation_id", correlationID)
		if errors.Is(err, db.ErrAdminAuditLog) {
			errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to record audit log")
			return
		}
		errorResponseForRequest(w, r, http.StatusInternalServerError, "failed to enqueue refresh")
		return
	}

	msg := fmt.Sprintf("refresh queued for %s/%s at position %d", ecosystem, name, position)
	if !created {
		msg = fmt.Sprintf("refresh for %s/%s already queued at position %d", ecosystem, name, position)
	}

	writeJSONForRequest(w, r, http.StatusAccepted, RefreshResponse{
		Queued:   true,
		New:      created,
		Position: position,
		Message:  msg,
	})
}

func (h *Handler) enqueuePackageRefreshWithAudit(ctx context.Context, job *db.RefreshJob, audit db.RefreshEnqueueAuditBuilder) (bool, int, error) {
	enqueuer, ok := h.store.(packageRefreshAuditEnqueuer)
	if !ok {
		return false, 0, fmt.Errorf("%w: package refresh audit store does not support audited enqueue", db.ErrAdminAuditLog)
	}
	return enqueuer.EnqueueRefreshWithAudit(ctx, job, audit)
}

func (h *Handler) packageRefreshAuditBuilder(r *http.Request, ecosystem, name, source string) db.RefreshEnqueueAuditBuilder {
	return func(created bool, position int) db.AdminAuditEntry {
		client := clientIP(r)
		details := struct {
			Ecosystem     string `json:"ecosystem"`
			Name          string `json:"name"`
			Source        string `json:"source"`
			New           bool   `json:"new"`
			Position      int    `json:"position"`
			CorrelationID string `json:"correlation_id"`
			APIKeyID      int    `json:"api_key_id,omitempty"`
			APIKeyName    string `json:"api_key_name,omitempty"`
		}{
			Ecosystem:     ecosystem,
			Name:          name,
			Source:        source,
			New:           created,
			Position:      position,
			CorrelationID: requestCorrelationID(r),
		}
		if identity, ok := requestctx.APIKeyIdentityFromContext(r.Context()); ok {
			details.APIKeyID = identity.ID
			details.APIKeyName = identity.Name
		}
		raw, err := json.Marshal(details)
		if err != nil {
			raw = json.RawMessage(`{}`)
		}
		return db.AdminAuditEntry{
			Action:  "package_refresh_enqueue",
			Details: raw,
			IP:      client,
		}
	}
}

func normalizePackagePath(ecosystem, name string) (string, string, error) {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	name = packageid.NormalizeName(ecosystem, name)
	if ecosystem == "" || name == "" {
		return "", "", fmt.Errorf("ecosystem and package name are required")
	}
	if len(name) > checkcontract.MaxPackageNameLength {
		return "", "", fmt.Errorf("package name exceeds %d characters", checkcontract.MaxPackageNameLength)
	}
	if !domain.Ecosystem(ecosystem).Valid() {
		return "", "", fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
	return ecosystem, name, nil
}

func normalizePackageVersionQuery(version string) (string, error) {
	version = strings.TrimSpace(version)
	if len(version) > checkcontract.MaxPackageVersionLength {
		return "", fmt.Errorf("package version exceeds %d characters", checkcontract.MaxPackageVersionLength)
	}
	return version, nil
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

func formatAPIDateTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
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

func requestWithLogger(r *http.Request, logger *slog.Logger) *http.Request {
	if r == nil || logger == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), apiRequestLoggerKey{}, logger))
}

func requestLogger(r *http.Request) *slog.Logger {
	if r != nil {
		if logger, ok := r.Context().Value(apiRequestLoggerKey{}).(*slog.Logger); ok && logger != nil {
			return logger
		}
	}
	return slog.Default()
}

func isGetOrHead(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func writeJSONForRequest(w http.ResponseWriter, r *http.Request, status int, v any) {
	if r.Method == http.MethodHead {
		writeJSONHead(w, status)
		return
	}
	writeJSONWithRequest(w, r, status, v)
}

func writeStreamingJSONForRequest(w http.ResponseWriter, r *http.Request, status int, v any) {
	if r.Method == http.MethodHead {
		writeJSONHead(w, status)
		return
	}
	setJSONResponseHeaders(w)
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		logJSONResponseFailure(r, "failed to stream JSON response", err)
	}
}

func errorResponseForRequest(w http.ResponseWriter, r *http.Request, status int, message string) {
	writeJSONForRequest(w, r, status, errorJSON{Error: message, Code: errorCodeForStatus(status)})
}

func writeJSONWithRequest(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := encodeJSONResponse(v)
	if err != nil {
		logJSONResponseFailure(r, "failed to encode JSON response", err)
		writeJSONBytesForRequest(w, r, http.StatusInternalServerError, []byte(`{"error":"internal server error","code":"internal_error"}`+"\n"))
		return
	}
	writeJSONBytesForRequest(w, r, status, body)
}

// writeJSON encodes v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := encodeJSONResponse(v)
	if err != nil {
		slog.Warn("failed to encode JSON response", "error", err)
		writeJSONBytes(w, http.StatusInternalServerError, []byte(`{"error":"internal server error","code":"internal_error"}`+"\n"))
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
	setJSONResponseHeaders(w)
	w.WriteHeader(status)
}

func writeJSONBytes(w http.ResponseWriter, status int, body []byte) {
	setJSONResponseHeaders(w)
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil { // #nosec G705 -- body is produced by encodeJSONResponse with HTML escaping before reaching this writer.
		// At this point headers are already sent; we can only log.
		slog.Warn("failed to write JSON response", "error", err)
	}
}

func writeJSONBytesForRequest(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	setJSONResponseHeaders(w)
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil { // #nosec G705 -- body is produced by encodeJSONResponse with HTML escaping before reaching this writer.
		// At this point headers are already sent; we can only log.
		logJSONResponseFailure(r, "failed to write JSON response", err)
	}
}

func logJSONResponseFailure(r *http.Request, message string, err error) {
	attrs := []any{"error", err}
	if r != nil {
		attrs = append(attrs,
			"correlation_id", requestCorrelationID(r),
			"path", logsafe.RequestPathLabel(r.URL.Path),
		)
	}
	requestLogger(r).Warn(message, attrs...)
}

func setJSONResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func requireJSONContentType(r *http.Request) error {
	raw := strings.TrimSpace(r.Header.Get("Content-Type"))
	if raw == "" {
		return fmt.Errorf("Content-Type must be application/json")
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return fmt.Errorf("Content-Type must be application/json")
	}
	return nil
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
	Code  string `json:"code"`
}

// errorResponse sends a JSON error response with the given status and message.
func errorResponse(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorJSON{Error: message, Code: errorCodeForStatus(status)})
}

func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	methodNotAllowedWithMessage(w, "method not allowed", allowed...)
}

func methodNotAllowedForRequest(w http.ResponseWriter, r *http.Request, allowed ...string) {
	methodNotAllowedWithMessageForRequest(w, r, "method not allowed", allowed...)
}

func methodNotAllowedWithMessage(w http.ResponseWriter, message string, allowed ...string) {
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	errorResponse(w, http.StatusMethodNotAllowed, message)
}

func methodNotAllowedWithMessageForRequest(w http.ResponseWriter, r *http.Request, message string, allowed ...string) {
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	errorResponseForRequest(w, r, http.StatusMethodNotAllowed, message)
}

// HandleNotFound writes the standard API JSON error envelope for API router
// fallbacks.
func HandleNotFound(w http.ResponseWriter, r *http.Request) {
	errorResponseForRequest(w, r, http.StatusNotFound, "not found")
}

func errorCodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "auth_failed"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusConflict:
		return "conflict"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed, http.StatusUnsupportedMediaType, http.StatusNotImplemented:
		return "unsupported"
	default:
		return "internal_error"
	}
}

// clientIP delegates to the shared request-context helper.
func clientIP(r *http.Request) string {
	return requestctx.ClientIP(r)
}
