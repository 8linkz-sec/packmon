// Package v1 implements the HTTP handlers for the Packmon API v1.
package v1

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/telemetry"
)

// maxRequestBody is the maximum allowed size for standard JSON request bodies.
const maxRequestBody = 1 << 20

// maxImportBody is the maximum allowed size for external feed import payloads.
const maxImportBody = 100 << 20

// maxPackagesPerCheck is the maximum number of packages in a single /check request.
const maxPackagesPerCheck = 5000

// defaultBlockThreshold is the severity threshold above which findings block.
// TODO: make configurable via server config.
var defaultBlockThreshold = domain.SeverityCritical

// Handler holds the dependencies for all API v1 HTTP handlers.
type Handler struct {
	store  db.Store
	logger *slog.Logger
}

type syncExporter interface {
	ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error)
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

type importResponse struct {
	Feed         string `json:"feed"`
	Imported     int    `json:"imported"`
	Deleted      int    `json:"deleted,omitempty"`
	EntriesTotal int    `json:"entries_total,omitempty"`
}

type syncVulnerabilityResponse struct {
	ID            string   `json:"id"`
	Ecosystem     string   `json:"ecosystem"`
	Name          string   `json:"name"`
	VersionRanges string   `json:"version_ranges"`
	Severity      string   `json:"severity"`
	CVSSScore     *float64 `json:"cvss_score"`
	EPSSScore     *float64 `json:"epss_score"`
	CISAKEV       bool     `json:"cisa_kev"`
	Summary       string   `json:"summary"`
	Withdrawn     bool     `json:"withdrawn"`
}

type syncMaliciousResponse struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Versions  string `json:"versions"`
	RiskType  string `json:"risk_type"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Withdrawn bool   `json:"withdrawn"`
}

type syncResponsePayload struct {
	SyncedAt        string                      `json:"synced_at"`
	Vulnerabilities []syncVulnerabilityResponse `json:"vulnerabilities"`
	Malicious       []syncMaliciousResponse     `json:"malicious"`
	Truncated       bool                        `json:"truncated"`
}

// NewHandler creates a Handler with the given store and logger.
// If logger is nil, slog.Default() is used.
func NewHandler(store db.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		store:  store,
		logger: logger,
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
	correlationID := generateID()

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

	ctx := r.Context()
	scanID := generateID()

	findings, err := h.collectFindings(ctx, req.Packages)
	if err != nil {
		h.logger.Error("failed to collect findings", "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusInternalServerError, "internal error while checking packages")
		return
	}

	// Build summary maps.
	summary := buildSummary(findings)

	// Determine blocking status. Malicious findings always block.
	// Vulnerability findings block when their severity meets the threshold.
	blocking := isBlocking(findings, defaultBlockThreshold)

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
		FeedStatus:       feedStatus,
		Summary:          summary,
		Findings:         findings,
		FeedVersions:     feedVersions,
	}

	// Persist scan log (best-effort).
	h.logScan(ctx, &result, r, correlationID)

	w.Header().Set("X-Correlation-ID", correlationID)
	w.Header().Set("X-Scan-Duration-Ms", fmt.Sprintf("%d", durationMs))
	writeJSON(w, http.StatusOK, result)
}

// collectFindings queries the store for vulnerabilities and malicious packages
// for every package in the request.
func (h *Handler) collectFindings(ctx context.Context, packages []domain.Package) ([]domain.Finding, error) {
	var all []domain.Finding

	for _, pkg := range packages {
		eco := string(pkg.Ecosystem)

		vulns, err := h.store.FindVulnerabilities(ctx, eco, pkg.Name, pkg.Version)
		if err != nil {
			return nil, fmt.Errorf("FindVulnerabilities(%s/%s@%s): %w", eco, pkg.Name, pkg.Version, err)
		}
		all = append(all, vulns...)

		mal, err := h.store.FindMalicious(ctx, eco, pkg.Name)
		if err != nil {
			return nil, fmt.Errorf("FindMalicious(%s/%s): %w", eco, pkg.Name, err)
		}
		all = append(all, mal...)
	}

	return all, nil
}

// buildSummary aggregates findings by severity, type, and source.
func buildSummary(findings []domain.Finding) domain.ScanSummary {
	bySeverity := make(map[string]int)
	byType := make(map[string]int)
	bySource := make(map[string]int)

	for _, f := range findings {
		bySeverity[string(f.Severity)]++
		byType[string(f.Type)]++
		bySource[f.Source]++
	}

	return domain.ScanSummary{
		BySeverity: bySeverity,
		ByType:     byType,
		BySource:   bySource,
	}
}

// isBlocking returns true when at least one finding should block the pipeline.
// Malicious findings always block. Vulnerability findings block when their
// severity is at or above the given threshold.
func isBlocking(findings []domain.Finding, threshold domain.Severity) bool {
	for _, f := range findings {
		if f.Type == domain.FindingTypeMalicious {
			return true
		}
		if f.Severity.Blocks(threshold) {
			return true
		}
	}
	return false
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
	if len(statuses) == 0 {
		return "degraded"
	}

	for _, status := range statuses {
		if feedHealthStatus(status) != "healthy" {
			return "degraded"
		}
	}
	return "healthy"
}

// logScan persists a scan log entry. Failures are logged but do not affect the response.
func (h *Handler) logScan(ctx context.Context, result *domain.ScanResult, r *http.Request, correlationID string) {
	entry := &db.ScanLogEntry{
		ScanID:        result.ScanID,
		ScannedAt:     result.ScannedAt,
		PackagesCount: result.PackagesScanned,
		FindingsCount: result.FindingsCount,
		DurationMs:    int(result.DurationMs),
		ClientIP:      clientIP(r),
		UserAgent:     r.UserAgent(),
	}
	if err := h.store.InsertScanLog(ctx, entry); err != nil {
		h.logger.Warn("failed to insert scan log", "error", err, "correlation_id", correlationID)
	}
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
	Feeds []FeedStatusItem `json:"feeds"`
}

// HandleFeedStatus returns the sync status of all known feed sources.
func (h *Handler) HandleFeedStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	statuses, err := h.store.ListFeedSyncStatuses(r.Context())
	if err != nil {
		h.logger.Error("failed to list feed sync statuses", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to retrieve feed statuses")
		return
	}

	items := make([]FeedStatusItem, 0, len(statuses))
	for _, s := range statuses {
		item := FeedStatusItem{
			Name:         s.FeedName,
			Status:       feedHealthStatus(s),
			EntriesCount: s.EntriesTotal,
		}
		if s.LastSyncAt != nil {
			ts := s.LastSyncAt.UTC().Format(time.RFC3339)
			item.LastSyncAt = &ts
		}
		if (s.LastSyncStatus == "error" || s.LastSyncStatus == "skipped") && s.LastError != "" {
			item.Message = s.LastError
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, FeedStatusResponse{Feeds: items})
}

// feedHealthStatus derives a health string from sync status.
// A feed is "error" if its last sync failed, "warning" if the last run was
// skipped or the last successful sync is more than 48 hours ago, and
// "healthy" otherwise.
func feedHealthStatus(s db.FeedSyncStatus) string {
	if s.LastSyncStatus == "error" {
		return "error"
	}
	if s.LastSyncStatus == "running" {
		return "pending"
	}
	if s.LastSyncStatus == "skipped" {
		return "warning"
	}
	if s.LastSyncAt == nil {
		return "error"
	}
	if time.Since(*s.LastSyncAt) > 48*time.Hour {
		return "warning"
	}
	return "healthy"
}

// ----------------------------------------------------------------------------
// POST /api/v1/feeds/{feed}/import
// ----------------------------------------------------------------------------

func (h *Handler) HandleFeedImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	feed := r.PathValue("feed")
	if feed == "" {
		errorResponse(w, http.StatusBadRequest, "feed name is required")
		return
	}

	if !isKnownFeed(feed) {
		errorResponse(w, http.StatusBadRequest, fmt.Sprintf("unknown feed: %s", feed))
		return
	}

	var (
		resp *importResponse
		err  error
	)

	switch feed {
	case "osv", "ghsa":
		var req vulnerabilityImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid vulnerability body", "feed", feed, "error", err)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importVulnerabilities(r.Context(), feed, &req)
	case "openssf", "socket":
		var req maliciousImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid malicious body", "feed", feed, "error", err)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importMalicious(r.Context(), feed, &req)
	case "vulncheck":
		var req vulnCheckImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid vulncheck body", "feed", feed, "error", err)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importVulnCheck(r.Context(), feed, &req)
	case "cisakev":
		var req cisaKEVImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid cisakev body", "feed", feed, "error", err)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importCISAKEV(r.Context(), feed, &req)
	case "epss":
		var req epssImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid epss body", "feed", feed, "error", err)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importEPSS(r.Context(), feed, &req)
	default:
		errorResponse(w, http.StatusBadRequest, fmt.Sprintf("unsupported feed: %s", feed))
		return
	}

	if err != nil {
		h.logger.Error("feed import failed", "feed", feed, "error", err)
		errorResponse(w, http.StatusInternalServerError, "feed import failed")
		return
	}

	h.logger.Info("feed import completed",
		"feed", feed,
		"imported", resp.Imported,
		"deleted", resp.Deleted,
		"entries_total", resp.EntriesTotal,
	)
	writeJSON(w, http.StatusOK, resp)
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
	if r.Method != http.MethodGet {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ecosystem := r.PathValue("ecosystem")
	name := r.PathValue("rest")
	if ecosystem == "" || name == "" {
		errorResponse(w, http.StatusBadRequest, "ecosystem and package name are required")
		return
	}

	ctx := r.Context()

	// FindVulnerabilities with empty version returns all versions.
	vulns, err := h.store.FindVulnerabilities(ctx, ecosystem, name, "")
	if err != nil {
		h.logger.Error("failed to find vulnerabilities", "ecosystem", ecosystem, "name", name, "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to query vulnerabilities")
		return
	}

	mal, err := h.store.FindMalicious(ctx, ecosystem, name)
	if err != nil {
		h.logger.Error("failed to find malicious findings", "ecosystem", ecosystem, "name", name, "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to query malicious findings")
		return
	}

	findings := make([]domain.Finding, 0, len(vulns)+len(mal))
	findings = append(findings, vulns...)
	findings = append(findings, mal...)

	if len(findings) == 0 {
		errorResponse(w, http.StatusNotFound, fmt.Sprintf("no findings for %s/%s", ecosystem, name))
		return
	}

	writeJSON(w, http.StatusOK, PackageDetailResponse{
		Ecosystem: ecosystem,
		Name:      name,
		Findings:  findings,
	})
}

// ----------------------------------------------------------------------------
// POST /api/v1/packages/{ecosystem}/{rest...}
// Dispatches to HandleRefresh when the rest path ends with "/refresh".
// ----------------------------------------------------------------------------

// HandlePackageOrRefresh is the dispatcher for POST requests on the
// packages resource. Since Go's ServeMux does not allow a {name...}
// wildcard in the middle of a pattern, we register a single catch-all
// for POST and split here: if {rest} ends with "/refresh", we strip
// the suffix and delegate to HandleRefresh; otherwise we return 405.
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
	errorResponse(w, http.StatusMethodNotAllowed, "method not allowed; did you mean POST .../refresh?")
}

// RefreshRequest is the optional JSON body for HandleRefresh.
type RefreshRequest struct {
	Version string `json:"version,omitempty"`
}

// RefreshResponse is the JSON response for HandleRefresh.
type RefreshResponse struct {
	Queued   bool   `json:"queued"`
	New      bool   `json:"new"`
	Position int    `json:"position"`
	Message  string `json:"message"`
}

// HandleRefresh enqueues an async re-check for a package.
// It is kept exported for direct route registration in alternative setups.
func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ecosystem := r.PathValue("ecosystem")
	name := r.PathValue("rest")
	if name != "" {
		name = strings.TrimSuffix(name, "/refresh")
	}
	if ecosystem == "" || name == "" {
		errorResponse(w, http.StatusBadRequest, "ecosystem and package name are required")
		return
	}

	h.handleRefresh(w, r, ecosystem, name)
}

// handleRefresh is the internal implementation shared by both HandleRefresh
// and HandlePackageOrRefresh.
func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request, ecosystem, name string) {
	// Body is optional. If present, it may contain a version filter.
	var req RefreshRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			h.logger.Warn("invalid refresh request body", "error", err)
			errorResponse(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
	}

	job := &db.RefreshJob{
		Ecosystem: ecosystem,
		Name:      name,
		Source:    "socket",
		Priority:  0, // manual trigger = highest priority
		Status:    "pending",
	}

	created, position, err := h.store.EnqueueRefresh(r.Context(), job)
	if err != nil {
		h.logger.Error("failed to enqueue refresh", "ecosystem", ecosystem, "name", name, "error", err)
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

// ----------------------------------------------------------------------------
// GET /api/v1/sync
// ----------------------------------------------------------------------------

func (h *Handler) HandleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	exporter, ok := h.store.(syncExporter)
	if !ok {
		errorResponse(w, http.StatusNotImplemented, "sync endpoint is not supported by this store")
		return
	}

	var sincePtr *time.Time
	sinceRaw := strings.TrimSpace(r.URL.Query().Get("since"))
	if sinceRaw != "" {
		since, err := parseRFC3339Timestamp(sinceRaw)
		if err != nil {
			errorResponse(w, http.StatusBadRequest, "invalid since timestamp")
			return
		}
		sincePtr = &since
	}

	exported, err := exporter.ExportSync(r.Context(), db.SyncExportOptions{
		Since:      sincePtr,
		SnapshotAt: time.Now().UTC(),
		Ecosystems: splitCSV(r.URL.Query().Get("ecosystem")),
	})
	if err != nil {
		h.logger.Error("sync export failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "failed to export sync data")
		return
	}

	resp := syncResponsePayload{
		SyncedAt:        exported.SyncedAt.UTC().Format(time.RFC3339Nano),
		Vulnerabilities: make([]syncVulnerabilityResponse, 0, len(exported.Vulnerabilities)),
		Malicious:       make([]syncMaliciousResponse, 0, len(exported.Malicious)),
		Truncated:       exported.Truncated,
	}

	for _, vuln := range exported.Vulnerabilities {
		resp.Vulnerabilities = append(resp.Vulnerabilities, syncVulnerabilityResponse{
			ID:            vuln.ID,
			Ecosystem:     vuln.Ecosystem,
			Name:          vuln.Name,
			VersionRanges: vuln.VersionRanges,
			Severity:      vuln.Severity,
			CVSSScore:     vuln.CVSSScore,
			EPSSScore:     vuln.EPSSScore,
			CISAKEV:       vuln.CISAKEV,
			Summary:       vuln.Summary,
			Withdrawn:     vuln.Withdrawn,
		})
	}

	for _, finding := range exported.Malicious {
		resp.Malicious = append(resp.Malicious, syncMaliciousResponse{
			ID:        finding.ID,
			Ecosystem: finding.Ecosystem,
			Name:      finding.Name,
			Versions:  finding.Versions,
			RiskType:  finding.RiskType,
			Severity:  finding.Severity,
			Summary:   finding.Summary,
			Withdrawn: finding.Withdrawn,
		})
	}

	writeJSON(w, http.StatusOK, resp)
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

func (h *Handler) importVulnerabilities(ctx context.Context, feed string, req *vulnerabilityImportRequest) (*importResponse, error) {
	imported := 0
	for i := range req.Vulnerabilities {
		item := req.Vulnerabilities[i]
		if err := normalizeImportedVulnerability(feed, &item); err != nil {
			return nil, err
		}
		if err := h.store.UpsertVulnerability(ctx, &item); err != nil {
			return nil, err
		}
		imported++
	}

	deleted := 0
	for _, id := range req.DeleteVulnerabilityIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if err := h.store.DeleteVulnerability(ctx, id); err != nil {
			return nil, err
		}
		deleted++
	}

	if err := h.applyImportStatus(ctx, feed, req.Status, imported, imported+deleted); err != nil {
		return nil, err
	}

	return &importResponse{
		Feed:         feed,
		Imported:     imported,
		Deleted:      deleted,
		EntriesTotal: imported + deleted,
	}, nil
}

func (h *Handler) importMalicious(ctx context.Context, feed string, req *maliciousImportRequest) (*importResponse, error) {
	imported := 0
	for i := range req.Malicious {
		item := req.Malicious[i]
		if err := normalizeImportedMalicious(feed, &item); err != nil {
			return nil, err
		}
		if err := h.store.UpsertMaliciousFinding(ctx, &item); err != nil {
			return nil, err
		}
		imported++
	}

	deleted := 0
	for _, id := range req.DeleteMaliciousIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if err := h.store.DeleteMaliciousFinding(ctx, id); err != nil {
			return nil, err
		}
		deleted++
	}

	if err := h.applyImportStatus(ctx, feed, req.Status, imported, imported+deleted); err != nil {
		return nil, err
	}

	return &importResponse{
		Feed:         feed,
		Imported:     imported,
		Deleted:      deleted,
		EntriesTotal: imported + deleted,
	}, nil
}

func (h *Handler) importVulnCheck(ctx context.Context, feed string, req *vulnCheckImportRequest) (*importResponse, error) {
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

func (h *Handler) importCISAKEV(ctx context.Context, feed string, req *cisaKEVImportRequest) (*importResponse, error) {
	updated, err := h.store.SetCISAKEV(ctx, req.CVEIDs)
	if err != nil {
		return nil, err
	}

	if req.ClearMissing {
		if _, err := h.store.ClearCISAKEV(ctx, req.CVEIDs); err != nil {
			return nil, err
		}
	}

	if err := h.applyImportStatus(ctx, feed, req.Status, updated, len(req.CVEIDs)); err != nil {
		return nil, err
	}

	return &importResponse{
		Feed:         feed,
		Imported:     updated,
		EntriesTotal: len(req.CVEIDs),
	}, nil
}

func (h *Handler) importEPSS(ctx context.Context, feed string, req *epssImportRequest) (*importResponse, error) {
	updated, err := h.store.SetEPSSScores(ctx, req.Entries)
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

func (h *Handler) applyImportStatus(ctx context.Context, feed string, input *feedSyncStatusInput, entriesSynced, entriesTotal int) error {
	if input == nil {
		return nil
	}

	status := &db.FeedSyncStatus{
		FeedName:       feed,
		LastSyncAt:     input.LastSyncAt,
		LastSyncStatus: strings.TrimSpace(input.LastSyncStatus),
		LastError:      strings.TrimSpace(input.LastError),
		EntriesSynced:  input.EntriesSynced,
		EntriesTotal:   input.EntriesTotal,
		LastEtag:       strings.TrimSpace(input.LastEtag),
		LastCommitHash: strings.TrimSpace(input.LastCommitHash),
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

	return h.store.UpsertFeedSyncStatus(ctx, status)
}

func normalizeImportedVulnerability(feed string, vuln *db.Vulnerability) error {
	if strings.TrimSpace(vuln.ID) == "" {
		return fmt.Errorf("vulnerability import requires id")
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

	if len(vuln.Sources) == 0 {
		vuln.Sources = []db.VulnerabilitySource{{
			Source:   feed,
			SourceID: vuln.ID,
		}}
	}
	for i := range vuln.Sources {
		if strings.TrimSpace(vuln.Sources[i].Source) == "" {
			vuln.Sources[i].Source = feed
		}
		if strings.TrimSpace(vuln.Sources[i].SourceID) == "" {
			vuln.Sources[i].SourceID = vuln.ID
		}
	}

	return nil
}

func normalizeImportedMalicious(feed string, finding *db.MaliciousFinding) error {
	if strings.TrimSpace(finding.ID) == "" {
		return fmt.Errorf("malicious import requires id")
	}
	if strings.TrimSpace(finding.Source) == "" {
		finding.Source = feed
	}
	if strings.TrimSpace(finding.Severity) == "" {
		finding.Severity = "CRITICAL"
	}
	return nil
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

func parseRFC3339Timestamp(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid RFC3339 timestamp")
}

// writeJSON encodes v as JSON and writes it with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// At this point headers are already sent; we can only log.
		slog.Warn("failed to encode JSON response", "error", err)
	}
}

// readJSON decodes the request body into v with a 1 MB size limit.
func readJSON(r *http.Request, v any) error {
	return readJSONWithLimit(r, v, maxRequestBody)
}

func readJSONWithLimit(r *http.Request, v any, limit int64) error {
	r.Body = http.MaxBytesReader(nil, r.Body, limit)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if strings.Contains(err.Error(), "http: request body too large") {
			return fmt.Errorf("request body exceeds %d bytes", limit)
		}
		return err
	}

	// Reject trailing content after the first JSON value.
	if dec.More() {
		return fmt.Errorf("unexpected trailing data after JSON body")
	}

	return nil
}

// errorJSON is the standard JSON error envelope.
type errorJSON struct {
	Error string `json:"error"`
}

// errorResponse sends a JSON error response with the given status and message.
func errorResponse(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorJSON{Error: message})
}

// generateID returns a random 8-byte hex string (16 characters).
func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use timestamp-based ID. This should never happen with
		// crypto/rand, but we must not panic in a request handler.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// clientIP extracts the client IP from the request, preferring
// X-Forwarded-For when set (first entry only).
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	// RemoteAddr is "host:port"; strip port.
	if i := strings.LastIndex(r.RemoteAddr, ":"); i != -1 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
