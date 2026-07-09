package v1

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/packageid"
	"github.com/8linkz-sec/packmon/internal/requestctx"
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
	maxImportStatusLastETagLength       = 512
	maxImportStatusLastCommitHashLength = 128
	maxImportStatusMetadataLength       = 4096
	maxImportDiagnosticValueLength      = 128
	epssImportStreamBatchSize           = 5000
	vulnCheckImportStreamBatchSize      = 1000
)

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

type feedSyncStatusInput struct {
	LastSyncAt         *time.Time      `json:"last_sync_at"`
	LastSyncDurationMs *int64          `json:"last_sync_duration_ms"`
	LastSyncStatus     string          `json:"last_sync_status"`
	LastError          string          `json:"last_error"`
	EntriesSynced      int             `json:"entries_synced"`
	EntriesTotal       int             `json:"entries_total"`
	LastETag           string          `json:"last_etag"`
	LastCommitHash     string          `json:"last_commit_hash"`
	Metadata           json.RawMessage `json:"metadata"`
}

type vulnerabilityImportRequest struct {
	Vulnerabilities        []vulnerabilityImportItem `json:"vulnerabilities"`
	DeleteVulnerabilityIDs []string                  `json:"delete_vulnerability_ids"`
	Status                 *feedSyncStatusInput      `json:"status"`
}

type vulnerabilityImportItem struct {
	ID               string                         `json:"id"`
	Summary          string                         `json:"summary"`
	Details          string                         `json:"details"`
	Severity         string                         `json:"severity"`
	CVSSScore        *float64                       `json:"cvss_score,omitempty"`
	EPSSScore        *float64                       `json:"epss_score,omitempty"`
	EPSSPercentile   *float64                       `json:"epss_percentile,omitempty"`
	CISAKEV          bool                           `json:"cisa_kev"`
	ExploitExists    bool                           `json:"exploit_exists"`
	Published        time.Time                      `json:"published"`
	Modified         time.Time                      `json:"modified"`
	Withdrawn        *time.Time                     `json:"withdrawn,omitempty"`
	Aliases          []vulnerabilityImportAlias     `json:"aliases,omitempty"`
	Sources          []vulnerabilityImportSource    `json:"sources,omitempty"`
	References       []vulnerabilityImportReference `json:"references,omitempty"`
	AffectedPackages []vulnerabilityImportPackage   `json:"affected_packages,omitempty"`
}

type vulnerabilityImportAlias struct {
	AliasID string `json:"alias_id"`
}

type vulnerabilityImportSource struct {
	Source   string          `json:"source"`
	SourceID string          `json:"source_id"`
	URL      string          `json:"url"`
	RawJSON  json.RawMessage `json:"raw_json,omitempty"`
}

type vulnerabilityImportReference struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Source string `json:"source"`
}

type vulnerabilityImportPackage struct {
	Ecosystem        string          `json:"ecosystem"`
	Name             string          `json:"name"`
	VersionRanges    json.RawMessage `json:"version_ranges"`
	VersionsAffected json.RawMessage `json:"versions_affected"`
}

type maliciousImportRequest struct {
	Malicious          []maliciousImportItem `json:"malicious"`
	DeleteMaliciousIDs []string              `json:"delete_malicious_ids"`
	Status             *feedSyncStatusInput  `json:"status"`
}

type maliciousImportItem struct {
	ID            string          `json:"id"`
	Ecosystem     string          `json:"ecosystem"`
	Name          string          `json:"name"`
	VersionRanges json.RawMessage `json:"version_ranges,omitempty"`
	Versions      json.RawMessage `json:"versions,omitempty"`
	Source        string          `json:"source"`
	RiskType      string          `json:"risk_type"`
	Severity      string          `json:"severity"`
	Summary       string          `json:"summary"`
	Description   string          `json:"description"`
	ReferenceURLs json.RawMessage `json:"reference_urls,omitempty"`
	OriginRef     string          `json:"origin_ref"`
	Published     *time.Time      `json:"published,omitempty"`
	CreatedBy     string          `json:"created_by"`
}

type epssImportRequest struct {
	Entries []epssImportEntry    `json:"entries"`
	Status  *feedSyncStatusInput `json:"status"`
}

type epssImportEntry struct {
	CVEID      string   `json:"cve_id"`
	Score      *float64 `json:"score"`
	Percentile *float64 `json:"percentile"`
}

type vulnCheckImportRequest struct {
	Entries []vulnCheckImportEntry `json:"entries"`
	Status  *feedSyncStatusInput   `json:"status"`
}

type vulnCheckImportEntry struct {
	CVEID         string          `json:"cve_id"`
	CVSSScore     *float64        `json:"cvss_score,omitempty"`
	ExploitExists bool            `json:"exploit_exists"`
	SourceURL     string          `json:"source_url"`
	RawJSON       json.RawMessage `json:"raw_json,omitempty"`
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
	Feed          string `json:"feed"`
	Imported      int    `json:"imported"`
	Deleted       int    `json:"deleted"`
	EntriesTotal  int    `json:"entries_total"`
	AuditRecorded bool   `json:"-"`
}

type feedImportAuditFunc func(imported, deleted int) *db.AdminAuditEntry

type feedImportDispatch interface {
	newRequest() any
	decodeAndImport(ctx context.Context, h *FeedImportHandler, r *http.Request, feed string, audit feedImportAuditFunc) (*importResponse, int, error)
}

type feedImportRequestDispatch[T any] struct {
	bodyName      string
	allocate      func() *T
	entriesTotal  func(*T) int
	importRequest func(context.Context, *FeedImportHandler, string, *T, feedImportAuditFunc) (*importResponse, error)
}

type feedImportStreamingDispatch struct {
	bodyName      string
	allocate      func() any
	importRequest func(context.Context, *FeedImportHandler, *http.Request, string, feedImportAuditFunc) (*importResponse, int, error)
}

type feedImportDispatchFactory func() feedImportDispatch

type feedImportCapability struct {
	name     string
	dispatch feedImportDispatch
}

type feedImportDecodeError struct {
	bodyName string
	err      error
}

func (e *feedImportDecodeError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *feedImportDecodeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func (d feedImportRequestDispatch[T]) newRequest() any {
	if d.allocate == nil {
		return (*T)(nil)
	}
	return d.allocate()
}

func (d feedImportRequestDispatch[T]) decodeAndImport(ctx context.Context, h *FeedImportHandler, r *http.Request, feed string, audit feedImportAuditFunc) (*importResponse, int, error) {
	if d.allocate == nil || d.importRequest == nil {
		return nil, 0, errors.New("feed import dispatch is not configured")
	}

	req := d.allocate()
	if err := readJSONWithLimit(r, req, maxImportBody); err != nil {
		return nil, 0, &feedImportDecodeError{bodyName: d.bodyName, err: err}
	}

	entriesTotal := 0
	if d.entriesTotal != nil {
		entriesTotal = d.entriesTotal(req)
	}
	resp, err := d.importRequest(ctx, h, feed, req, audit)
	return resp, entriesTotal, err
}

func (d feedImportStreamingDispatch) newRequest() any {
	if d.allocate == nil {
		return nil
	}
	return d.allocate()
}

func (d feedImportStreamingDispatch) decodeAndImport(ctx context.Context, h *FeedImportHandler, r *http.Request, feed string, audit feedImportAuditFunc) (*importResponse, int, error) {
	if d.importRequest == nil {
		return nil, 0, errors.New("feed import streaming dispatch is not configured")
	}
	return d.importRequest(ctx, h, r, feed, audit)
}

var feedImportDispatchFactories = map[string]feedImportDispatchFactory{
	"osv":       func() feedImportDispatch { return vulnerabilityFeedImportDispatch() },
	"ghsa":      func() feedImportDispatch { return vulnerabilityFeedImportDispatch() },
	"openssf":   func() feedImportDispatch { return maliciousFeedImportDispatch() },
	"socket":    func() feedImportDispatch { return maliciousFeedImportDispatch() },
	"vulncheck": vulnCheckFeedImportDispatch,
	"cisakev":   func() feedImportDispatch { return cisaKEVFeedImportDispatch() },
	"epss":      epssFeedImportDispatch,
}

var feedImportCapabilitiesByName = buildFeedImportCapabilitiesByName()

func buildFeedImportCapabilitiesByName() map[string]feedImportCapability {
	externalFeeds := config.FeedExternalModeNames()
	out := make(map[string]feedImportCapability, len(externalFeeds))
	for _, feed := range externalFeeds {
		if !config.FeedSupportsExternalMode(feed) {
			panic(fmt.Sprintf("feed import capability %q is not backed by config external-mode metadata", feed))
		}
		factory, ok := feedImportDispatchFactories[feed]
		if !ok {
			panic(fmt.Sprintf("feed import capability %q has no request dispatch", feed))
		}
		out[feed] = feedImportCapability{name: feed, dispatch: factory()}
	}
	for feed := range feedImportDispatchFactories {
		if _, ok := out[feed]; !ok {
			panic(fmt.Sprintf("feed import dispatch %q is not backed by config external-mode metadata", feed))
		}
	}
	return out
}

func feedImportCapabilityForFeed(feed string) (feedImportCapability, bool) {
	capability, ok := feedImportCapabilitiesByName[feed]
	return capability, ok
}

// FeedImportCanonicalFeedNames returns the canonical feed names accepted by the
// external feed import endpoint.
func FeedImportCanonicalFeedNames() []string {
	names := config.FeedExternalModeNames()
	out := make([]string, 0, len(names))
	for _, name := range names {
		if _, ok := feedImportCapabilitiesByName[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

// FeedImportPathFeedNames returns all documented path values for the import
// endpoint, including the legacy malicious alias.
func FeedImportPathFeedNames() []string {
	canonical := FeedImportCanonicalFeedNames()
	out := make([]string, 0, len(canonical)+1)
	for _, name := range canonical {
		out = append(out, name)
		if name == "openssf" {
			out = append(out, "malicious")
		}
	}
	return out
}

func vulnerabilityFeedImportDispatch() feedImportRequestDispatch[vulnerabilityImportRequest] {
	return feedImportRequestDispatch[vulnerabilityImportRequest]{
		bodyName: "vulnerability",
		allocate: func() *vulnerabilityImportRequest {
			return &vulnerabilityImportRequest{}
		},
		entriesTotal: func(req *vulnerabilityImportRequest) int {
			return len(req.Vulnerabilities) + len(req.DeleteVulnerabilityIDs)
		},
		importRequest: func(ctx context.Context, h *FeedImportHandler, feed string, req *vulnerabilityImportRequest, audit feedImportAuditFunc) (*importResponse, error) {
			return h.importVulnerabilities(ctx, feed, req, audit)
		},
	}
}

func maliciousFeedImportDispatch() feedImportRequestDispatch[maliciousImportRequest] {
	return feedImportRequestDispatch[maliciousImportRequest]{
		bodyName: "malicious",
		allocate: func() *maliciousImportRequest {
			return &maliciousImportRequest{}
		},
		entriesTotal: func(req *maliciousImportRequest) int {
			return len(req.Malicious) + len(req.DeleteMaliciousIDs)
		},
		importRequest: func(ctx context.Context, h *FeedImportHandler, feed string, req *maliciousImportRequest, audit feedImportAuditFunc) (*importResponse, error) {
			return h.importMalicious(ctx, feed, req, audit)
		},
	}
}

func vulnCheckFeedImportDispatch() feedImportDispatch {
	return feedImportStreamingDispatch{
		bodyName: "vulncheck",
		allocate: func() any {
			return &vulnCheckImportRequest{}
		},
		importRequest: func(ctx context.Context, h *FeedImportHandler, r *http.Request, feed string, audit feedImportAuditFunc) (*importResponse, int, error) {
			return h.importVulnCheckRequest(ctx, feed, r, audit)
		},
	}
}

func cisaKEVFeedImportDispatch() feedImportRequestDispatch[cisaKEVImportRequest] {
	return feedImportRequestDispatch[cisaKEVImportRequest]{
		bodyName: "cisakev",
		allocate: func() *cisaKEVImportRequest {
			return &cisaKEVImportRequest{}
		},
		entriesTotal: func(req *cisaKEVImportRequest) int {
			return len(req.CVEIDs)
		},
		importRequest: func(ctx context.Context, h *FeedImportHandler, feed string, req *cisaKEVImportRequest, audit feedImportAuditFunc) (*importResponse, error) {
			return h.importCISAKEV(ctx, feed, req, audit)
		},
	}
}

func epssFeedImportDispatch() feedImportDispatch {
	return feedImportStreamingDispatch{
		bodyName: "epss",
		allocate: func() any {
			return &epssImportRequest{}
		},
		importRequest: func(ctx context.Context, h *FeedImportHandler, r *http.Request, feed string, audit feedImportAuditFunc) (*importResponse, int, error) {
			return h.importEPSSRequest(ctx, feed, r, audit)
		},
	}
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
			"client_ip", clientIP(r),
		)
		return false
	}
	provided := strings.TrimSpace(r.Header.Get(HeaderFeedImportSecret))
	if provided == "" || !constantTimeStringEqual(provided, expected) {
		h.logger.Warn("feed import authorization failed",
			"reason", "missing_or_invalid_secret",
			"correlation_id", requestCorrelationID(r),
			"client_ip", clientIP(r),
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
	entry, err := h.feedImportAuditEntry(r, resp)
	if err != nil {
		return err
	}
	return h.store.InsertAdminAuditLog(r.Context(), entry)
}

func (h *FeedImportHandler) feedImportAuditEntry(r *http.Request, resp *importResponse) (*db.AdminAuditEntry, error) {
	client := clientIP(r)
	details := struct {
		Feed          string `json:"feed"`
		Imported      int    `json:"imported"`
		Deleted       int    `json:"deleted"`
		EntriesTotal  int    `json:"entries_total"`
		CorrelationID string `json:"correlation_id"`
		APIKeyID      int    `json:"api_key_id,omitempty"`
		APIKeyName    string `json:"api_key_name,omitempty"`
	}{
		Feed:          resp.Feed,
		Imported:      resp.Imported,
		Deleted:       resp.Deleted,
		EntriesTotal:  resp.EntriesTotal,
		CorrelationID: requestCorrelationID(r),
	}
	if identity, ok := requestctx.APIKeyIdentityFromContext(r.Context()); ok {
		details.APIKeyID = identity.ID
		details.APIKeyName = identity.Name
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return nil, err
	}
	return &db.AdminAuditEntry{
		Action:  "feed_import",
		Details: raw,
		IP:      client,
	}, nil
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
	auditedImport func(context.Context, string, []T, []string, *db.FeedSyncStatus, func(imported, deleted int) *db.AdminAuditEntry) (int, int, error)
}

func importFeedRecords[T any](ctx context.Context, h *FeedImportHandler, feed string, statusInput *feedSyncStatusInput, rawItems []T, rawDeleteIDs []string, audit func(imported, deleted int) *db.AdminAuditEntry, opts feedImportRecordOptions[T]) (*importResponse, error) {
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

	if opts.auditedImport == nil {
		return nil, errors.New("feed import audited atomic import is not configured")
	}
	if audit == nil {
		return nil, errors.New("feed import audit builder is not configured")
	}

	status, err := importStatusFromInput(feed, statusInput, len(items), len(items)+len(deleteIDs))
	if err != nil {
		return nil, err
	}
	imported, deleted, err := opts.auditedImport(ctx, feed, items, importDeleteIDValues(deleteIDs), status, audit)
	if err != nil {
		return nil, err
	}
	resp := feedImportResponse(feed, imported, deleted)
	resp.AuditRecorded = true
	return resp, nil
}

func feedImportResponse(feed string, imported, deleted int) *importResponse {
	return &importResponse{
		Feed:         feed,
		Imported:     imported,
		Deleted:      deleted,
		EntriesTotal: imported + deleted,
	}
}

func (h *FeedImportHandler) importVulnerabilities(ctx context.Context, feed string, req *vulnerabilityImportRequest, audit func(imported, deleted int) *db.AdminAuditEntry) (*importResponse, error) {
	return importFeedRecords(ctx, h, feed, req.Status, vulnerabilityImportItemsToDB(req.Vulnerabilities), req.DeleteVulnerabilityIDs, audit, feedImportRecordOptions[db.Vulnerability]{
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
		auditedImport: h.store.ImportVulnerabilityFeedWithAudit,
	})
}

func (h *FeedImportHandler) importMalicious(ctx context.Context, feed string, req *maliciousImportRequest, audit func(imported, deleted int) *db.AdminAuditEntry) (*importResponse, error) {
	return importFeedRecords(ctx, h, feed, req.Status, maliciousImportItemsToDB(req.Malicious), req.DeleteMaliciousIDs, audit, feedImportRecordOptions[db.MaliciousFinding]{
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
		auditedImport: h.store.ImportMaliciousFeedWithAudit,
	})
}

func (h *FeedImportHandler) importVulnCheck(ctx context.Context, feed string, req *vulnCheckImportRequest, audit func(imported, deleted int) *db.AdminAuditEntry) (*importResponse, error) {
	if err := validateImportStatusInput(req.Status); err != nil {
		return nil, err
	}
	entries, err := normalizeVulnCheckImportEntries(req.Entries)
	if err != nil {
		return nil, err
	}

	status, err := importStatusFromInput(feed, req.Status, len(entries), len(entries))
	if err != nil {
		return nil, err
	}
	updated, err := h.store.ImportVulnCheckWithAudit(ctx, feed, entries, status, audit)
	if err != nil {
		return nil, err
	}
	resp := &importResponse{
		Feed:          feed,
		Imported:      updated,
		EntriesTotal:  len(entries),
		AuditRecorded: true,
	}
	return resp, nil
}

type vulnCheckStreamImporter interface {
	ImportVulnCheckStreamWithAudit(ctx context.Context, feed string, stream func(func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error), audit func(imported, deleted int) *db.AdminAuditEntry) (updated, total int, err error)
}

func (h *FeedImportHandler) importVulnCheckRequest(ctx context.Context, feed string, r *http.Request, audit feedImportAuditFunc) (*importResponse, int, error) {
	importer, ok := vulnCheckStreamImporterFor(h.store)
	if !ok {
		req := &vulnCheckImportRequest{}
		if err := readJSONWithLimit(r, req, maxImportBody); err != nil {
			return nil, 0, &feedImportDecodeError{bodyName: "vulncheck", err: err}
		}
		resp, err := h.importVulnCheck(ctx, feed, req, audit)
		return resp, len(req.Entries), err
	}

	entriesTotal := 0
	updated, streamTotal, err := importer.ImportVulnCheckStreamWithAudit(ctx, feed, func(yield func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error) {
		var statusInput *feedSyncStatusInput
		var streamErr error
		statusInput, entriesTotal, streamErr = streamImportEntriesObject[vulnCheckImportEntry, db.VulnCheckEntry](
			r,
			"vulncheck",
			vulnCheckImportStreamBatchSize,
			normalizeVulnCheckImportEntriesBatch,
			yield,
		)
		if streamErr != nil {
			return nil, entriesTotal, streamErr
		}
		status, statusErr := importStatusFromInput(feed, statusInput, entriesTotal, entriesTotal)
		if statusErr != nil {
			return nil, entriesTotal, statusErr
		}
		return status, entriesTotal, nil
	}, audit)
	if err != nil {
		return nil, entriesTotal, err
	}
	if streamTotal != 0 {
		entriesTotal = streamTotal
	}
	return &importResponse{
		Feed:          feed,
		Imported:      updated,
		EntriesTotal:  entriesTotal,
		AuditRecorded: true,
	}, entriesTotal, nil
}

func (h *FeedImportHandler) importCISAKEV(ctx context.Context, feed string, req *cisaKEVImportRequest, audit func(imported, deleted int) *db.AdminAuditEntry) (*importResponse, error) {
	if err := validateImportStatusInput(req.Status); err != nil {
		return nil, err
	}
	cveIDs, err := normalizeCISAKEVImportIDs(req.CVEIDs, req.ClearMissing)
	if err != nil {
		return nil, err
	}

	status, err := importStatusFromInput(feed, req.Status, len(cveIDs), len(cveIDs))
	if err != nil {
		return nil, err
	}
	var (
		updated int
		cleared int
	)
	if req.ClearMissing {
		updated, cleared, err = h.store.ReplaceCISAKEVWithAudit(ctx, feed, cveIDs, status, audit)
	} else {
		updated, err = h.store.ImportCISAKEVWithAudit(ctx, feed, cveIDs, status, audit)
	}
	if err != nil {
		return nil, err
	}

	return &importResponse{
		Feed:          feed,
		Imported:      updated,
		Deleted:       cleared,
		EntriesTotal:  len(cveIDs),
		AuditRecorded: true,
	}, nil
}

type epssScoreStreamReplacer interface {
	ReplaceEPSSScoresStream(ctx context.Context, stream func(func([]db.EPSSEntry) error) error) (updated, cleared, total int, err error)
}

func (h *FeedImportHandler) importEPSS(ctx context.Context, feed string, req *epssImportRequest, audit func(imported, deleted int) *db.AdminAuditEntry) (*importResponse, error) {
	if err := validateImportStatusInput(req.Status); err != nil {
		return nil, err
	}
	entries, err := normalizeEPSSImportEntries(req.Entries)
	if err != nil {
		return nil, err
	}

	status, err := importStatusFromInput(feed, req.Status, len(entries), len(entries))
	if err != nil {
		return nil, err
	}
	updated, cleared, err := h.store.ImportEPSSWithAudit(ctx, feed, entries, status, audit)
	if err != nil {
		return nil, err
	}
	return &importResponse{
		Feed:          feed,
		Imported:      updated,
		Deleted:       cleared,
		EntriesTotal:  len(entries),
		AuditRecorded: true,
	}, nil
}

func (h *FeedImportHandler) importEPSSRequest(ctx context.Context, feed string, r *http.Request, audit feedImportAuditFunc) (*importResponse, int, error) {
	replacer, ok := epssStreamReplacerFor(h.store)
	if !ok {
		req := &epssImportRequest{}
		if err := readJSONWithLimit(r, req, maxImportBody); err != nil {
			return nil, 0, &feedImportDecodeError{bodyName: "epss", err: err}
		}
		resp, err := h.importEPSS(ctx, feed, req, audit)
		return resp, len(req.Entries), err
	}

	var (
		statusInput  *feedSyncStatusInput
		entriesTotal int
	)
	updated, cleared, streamTotal, err := replacer.ReplaceEPSSScoresStream(ctx, func(yield func([]db.EPSSEntry) error) error {
		var streamErr error
		statusInput, entriesTotal, streamErr = streamImportEntriesObject[epssImportEntry, db.EPSSEntry](
			r,
			"epss",
			epssImportStreamBatchSize,
			normalizeEPSSImportEntriesBatch,
			yield,
		)
		if streamErr != nil {
			return streamErr
		}
		if entriesTotal == 0 {
			return feedImportValidationErrorf("epss import entries must contain at least one score")
		}
		return nil
	})
	if err != nil {
		return nil, entriesTotal, err
	}
	if streamTotal != 0 {
		entriesTotal = streamTotal
	}
	if err := h.applyImportStatus(ctx, feed, statusInput, entriesTotal, entriesTotal); err != nil {
		return nil, entriesTotal, err
	}
	return &importResponse{
		Feed:         feed,
		Imported:     updated,
		Deleted:      cleared,
		EntriesTotal: entriesTotal,
	}, entriesTotal, nil
}

func vulnCheckStreamImporterFor(store FeedImportStore) (vulnCheckStreamImporter, bool) {
	if importer, ok := store.(vulnCheckStreamImporter); ok {
		return importer, true
	}
	if adapter, ok := store.(*DBStoreAdapter); ok {
		importer, ok := any(adapter.store).(vulnCheckStreamImporter)
		return importer, ok
	}
	return nil, false
}

func epssStreamReplacerFor(store FeedImportStore) (epssScoreStreamReplacer, bool) {
	if replacer, ok := store.(epssScoreStreamReplacer); ok {
		return replacer, true
	}
	if adapter, ok := store.(*DBStoreAdapter); ok {
		replacer, ok := any(adapter.store).(epssScoreStreamReplacer)
		return replacer, ok
	}
	return nil, false
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
		LastETag:       truncateString(strings.TrimSpace(input.LastETag), maxImportStatusLastETagLength),
		LastCommitHash: truncateString(strings.TrimSpace(input.LastCommitHash), maxImportStatusLastCommitHashLength),
		Metadata:       append(json.RawMessage(nil), input.Metadata...),
	}

	if status.LastSyncStatus == "" {
		status.LastSyncStatus = db.FeedSyncStatusSuccess
	}
	if status.LastSyncAt == nil && status.LastSyncStatus == db.FeedSyncStatusSuccess {
		now := time.Now().UTC()
		status.LastSyncAt = &now
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
	if status.EntriesSynced > status.EntriesTotal {
		return nil, feedImportValidationErrorf("feed import status entries_synced must not exceed entries_total")
	}

	return status, nil
}

func vulnerabilityImportItemsToDB(items []vulnerabilityImportItem) []db.Vulnerability {
	if len(items) == 0 {
		return nil
	}
	out := make([]db.Vulnerability, 0, len(items))
	for _, item := range items {
		out = append(out, item.toDB())
	}
	return out
}

func (item vulnerabilityImportItem) toDB() db.Vulnerability {
	return db.Vulnerability{
		ID:               item.ID,
		Summary:          item.Summary,
		Details:          item.Details,
		Severity:         item.Severity,
		CVSSScore:        item.CVSSScore,
		EPSSScore:        item.EPSSScore,
		EPSSPercentile:   item.EPSSPercentile,
		CISAKEV:          item.CISAKEV,
		ExploitExists:    item.ExploitExists,
		Published:        item.Published,
		Modified:         item.Modified,
		Withdrawn:        item.Withdrawn,
		Aliases:          vulnerabilityImportAliasesToDB(item.Aliases),
		Sources:          vulnerabilityImportSourcesToDB(item.Sources),
		References:       vulnerabilityImportReferencesToDB(item.References),
		AffectedPackages: vulnerabilityImportPackagesToDB(item.AffectedPackages),
	}
}

func vulnerabilityImportAliasesToDB(items []vulnerabilityImportAlias) []db.VulnerabilityAlias {
	if len(items) == 0 {
		return nil
	}
	out := make([]db.VulnerabilityAlias, 0, len(items))
	for _, item := range items {
		out = append(out, db.VulnerabilityAlias{
			AliasID: item.AliasID,
		})
	}
	return out
}

func vulnerabilityImportSourcesToDB(items []vulnerabilityImportSource) []db.VulnerabilitySource {
	if len(items) == 0 {
		return nil
	}
	out := make([]db.VulnerabilitySource, 0, len(items))
	for _, item := range items {
		out = append(out, db.VulnerabilitySource{
			Source:   item.Source,
			SourceID: item.SourceID,
			URL:      item.URL,
			RawJSON:  cloneRawJSON(item.RawJSON),
		})
	}
	return out
}

func vulnerabilityImportReferencesToDB(items []vulnerabilityImportReference) []db.VulnerabilityReference {
	if len(items) == 0 {
		return nil
	}
	out := make([]db.VulnerabilityReference, 0, len(items))
	for _, item := range items {
		out = append(out, db.VulnerabilityReference{
			Type:   item.Type,
			URL:    item.URL,
			Source: item.Source,
		})
	}
	return out
}

func vulnerabilityImportPackagesToDB(items []vulnerabilityImportPackage) []db.AffectedPackage {
	if len(items) == 0 {
		return nil
	}
	out := make([]db.AffectedPackage, 0, len(items))
	for _, item := range items {
		out = append(out, db.AffectedPackage{
			Ecosystem:        item.Ecosystem,
			Name:             item.Name,
			VersionRanges:    cloneRawJSON(item.VersionRanges),
			VersionsAffected: cloneRawJSON(item.VersionsAffected),
		})
	}
	return out
}

func maliciousImportItemsToDB(items []maliciousImportItem) []db.MaliciousFinding {
	if len(items) == 0 {
		return nil
	}
	out := make([]db.MaliciousFinding, 0, len(items))
	for _, item := range items {
		out = append(out, db.MaliciousFinding{
			ID:            item.ID,
			Ecosystem:     item.Ecosystem,
			Name:          item.Name,
			VersionRanges: cloneRawJSON(item.VersionRanges),
			Versions:      cloneRawJSON(item.Versions),
			Source:        item.Source,
			RiskType:      item.RiskType,
			Severity:      item.Severity,
			Summary:       item.Summary,
			Description:   item.Description,
			ReferenceURLs: cloneRawJSON(item.ReferenceURLs),
			OriginRef:     item.OriginRef,
			Published:     item.Published,
			CreatedBy:     item.CreatedBy,
		})
	}
	return out
}

func cloneRawJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	return append(json.RawMessage(nil), raw...)
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
	if vuln.CVSSScore != nil && (math.IsNaN(*vuln.CVSSScore) || math.IsInf(*vuln.CVSSScore, 0) || *vuln.CVSSScore < 0 || *vuln.CVSSScore > 10) {
		return feedImportValidationErrorf("vulnerability import cvss_score must be between 0 and 10")
	}
	if vuln.EPSSScore != nil && !validUnitInterval(*vuln.EPSSScore) {
		return feedImportValidationErrorf("vulnerability import epss_score must be between 0 and 1")
	}
	if vuln.EPSSPercentile != nil && !validUnitInterval(*vuln.EPSSPercentile) {
		return feedImportValidationErrorf("vulnerability import epss_percentile must be between 0 and 1")
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
	if err := validateVersionRangesJSON(finding.VersionRanges, "malicious import version_ranges"); err != nil {
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
	return domain.IsManualAdvisoryID(id)
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
	value = logsafe.BoundedDiagnosticValue(value, maxImportDiagnosticValueLength)
	return fmt.Sprintf("%s=%s", label, value)
}

func importPackageValue(ecosystem, name string) string {
	ecosystem = strings.TrimSpace(ecosystem)
	name = strings.TrimSpace(name)
	if ecosystem == "" || name == "" {
		return ""
	}
	ecosystem = logsafe.BoundedDiagnosticValue(ecosystem, maxImportDiagnosticValueLength)
	name = logsafe.BoundedDiagnosticValue(name, maxImportDiagnosticValueLength)
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

func streamImportEntriesObject[Raw any, Normalized any](r *http.Request, bodyName string, batchSize int, normalize func([]Raw, int) ([]Normalized, error), emit func([]Normalized) error) (*feedSyncStatusInput, int, error) {
	if batchSize <= 0 {
		return nil, 0, errors.New("feed import stream batch size is not configured")
	}
	if normalize == nil || emit == nil {
		return nil, 0, errors.New("feed import stream is not configured")
	}

	r.Body = http.MaxBytesReader(nil, r.Body, maxImportBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	tok, err := dec.Token()
	if err != nil {
		return nil, 0, feedImportJSONDecodeError(bodyName, err)
	}
	if tok == nil {
		return nil, 0, requireNoTrailingImportJSON(dec, bodyName)
	}
	open, ok := tok.(json.Delim)
	if !ok || open != '{' {
		return nil, 0, feedImportControlledDecodeError(bodyName, "json body has invalid field type")
	}

	var statusInput *feedSyncStatusInput
	entriesTotal := 0
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, entriesTotal, feedImportJSONDecodeError(bodyName, err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, entriesTotal, feedImportControlledDecodeError(bodyName, "malformed JSON body")
		}
		switch key {
		case "entries":
			count, err := streamImportEntriesArray(dec, bodyName, entriesTotal, batchSize, normalize, emit)
			entriesTotal += count
			if err != nil {
				return statusInput, entriesTotal, err
			}
		case "status":
			var input *feedSyncStatusInput
			if err := dec.Decode(&input); err != nil {
				return nil, entriesTotal, feedImportJSONDecodeError(bodyName, err)
			}
			if err := validateImportStatusInput(input); err != nil {
				return nil, entriesTotal, err
			}
			statusInput = input
		default:
			return nil, entriesTotal, feedImportControlledDecodeError(bodyName, "json body contains unknown field")
		}
	}

	closeToken, err := dec.Token()
	if err != nil {
		return nil, entriesTotal, feedImportJSONDecodeError(bodyName, err)
	}
	closeDelim, ok := closeToken.(json.Delim)
	if !ok || closeDelim != '}' {
		return nil, entriesTotal, feedImportControlledDecodeError(bodyName, "malformed JSON body")
	}
	if err := requireNoTrailingImportJSON(dec, bodyName); err != nil {
		return nil, entriesTotal, err
	}
	return statusInput, entriesTotal, nil
}

func streamImportEntriesArray[Raw any, Normalized any](dec *json.Decoder, bodyName string, offset, batchSize int, normalize func([]Raw, int) ([]Normalized, error), emit func([]Normalized) error) (int, error) {
	tok, err := dec.Token()
	if err != nil {
		return 0, feedImportJSONDecodeError(bodyName, err)
	}
	if tok == nil {
		return 0, nil
	}
	open, ok := tok.(json.Delim)
	if !ok || open != '[' {
		return 0, feedImportControlledDecodeError(bodyName, "json body has invalid field type")
	}

	total := 0
	batch := make([]Raw, 0, batchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		batchStart := offset + total - len(batch)
		normalized, err := normalize(batch, batchStart)
		if err != nil {
			return err
		}
		if len(normalized) == 0 {
			batch = batch[:0]
			return nil
		}
		if err := emit(normalized); err != nil {
			return err
		}
		batch = make([]Raw, 0, batchSize)
		return nil
	}

	for dec.More() {
		var entry Raw
		if err := dec.Decode(&entry); err != nil {
			return total, feedImportJSONDecodeError(bodyName, err)
		}
		batch = append(batch, entry)
		total++
		if len(batch) == batchSize {
			if err := flush(); err != nil {
				return total, err
			}
		}
	}
	closeToken, err := dec.Token()
	if err != nil {
		return total, feedImportJSONDecodeError(bodyName, err)
	}
	closeDelim, ok := closeToken.(json.Delim)
	if !ok || closeDelim != ']' {
		return total, feedImportControlledDecodeError(bodyName, "malformed JSON body")
	}
	if err := flush(); err != nil {
		return total, err
	}
	return total, nil
}

func requireNoTrailingImportJSON(dec *json.Decoder, bodyName string) error {
	var extra struct{}
	if err := dec.Decode(&extra); err == nil || !errors.Is(err, io.EOF) {
		return feedImportControlledDecodeError(bodyName, "unexpected trailing data after JSON body")
	}
	return nil
}

func feedImportJSONDecodeError(bodyName string, err error) error {
	if err == nil {
		return nil
	}
	return &feedImportDecodeError{bodyName: bodyName, err: sanitizedJSONDecodeError(err, maxImportBody)}
}

func feedImportControlledDecodeError(bodyName, message string) error {
	return &feedImportDecodeError{bodyName: bodyName, err: errors.New(message)}
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

func normalizeEPSSImportEntries(entries []epssImportEntry) ([]db.EPSSEntry, error) {
	if len(entries) == 0 {
		return nil, feedImportValidationErrorf("epss import entries must contain at least one score")
	}
	return normalizeEPSSImportEntriesBatch(entries, 0)
}

func normalizeEPSSImportEntriesBatch(entries []epssImportEntry, offset int) ([]db.EPSSEntry, error) {
	normalized := make([]db.EPSSEntry, 0, len(entries))
	for i, entry := range entries {
		index := offset + i
		cveID := strings.ToUpper(strings.TrimSpace(entry.CVEID))
		if !cveIDPattern.MatchString(cveID) {
			return nil, feedImportValidationErrorf("epss import entries[%d].cve_id is invalid", index)
		}
		if entry.Score == nil {
			return nil, feedImportValidationErrorf("epss import entries[%d].score is required", index)
		}
		if entry.Percentile == nil {
			return nil, feedImportValidationErrorf("epss import entries[%d].percentile is required", index)
		}
		if !validUnitInterval(*entry.Score) {
			return nil, feedImportValidationErrorf("epss import entries[%d].score must be between 0 and 1", index)
		}
		if !validUnitInterval(*entry.Percentile) {
			return nil, feedImportValidationErrorf("epss import entries[%d].percentile must be between 0 and 1", index)
		}
		normalized = append(normalized, db.EPSSEntry{
			CVEID:      cveID,
			Score:      *entry.Score,
			Percentile: *entry.Percentile,
		})
	}
	return normalized, nil
}

func normalizeVulnCheckImportEntries(entries []vulnCheckImportEntry) ([]db.VulnCheckEntry, error) {
	return normalizeVulnCheckImportEntriesBatch(entries, 0)
}

func normalizeVulnCheckImportEntriesBatch(entries []vulnCheckImportEntry, offset int) ([]db.VulnCheckEntry, error) {
	normalized := make([]db.VulnCheckEntry, 0, len(entries))
	for i, entry := range entries {
		index := offset + i
		cveID := strings.ToUpper(strings.TrimSpace(entry.CVEID))
		if !cveIDPattern.MatchString(cveID) {
			return nil, feedImportValidationErrorf("vulncheck import entries[%d].cve_id is invalid", index)
		}
		if entry.CVSSScore != nil && (math.IsNaN(*entry.CVSSScore) || math.IsInf(*entry.CVSSScore, 0) || *entry.CVSSScore < 0 || *entry.CVSSScore > 10) {
			return nil, feedImportValidationErrorf("vulncheck import entries[%d].cvss_score must be between 0 and 10", index)
		}
		normalized = append(normalized, db.VulnCheckEntry{
			CVEID:         cveID,
			CVSSScore:     entry.CVSSScore,
			ExploitExists: entry.ExploitExists,
			SourceURL:     entry.SourceURL,
			RawJSON:       cloneRawJSON(entry.RawJSON),
		})
	}
	return normalized, nil
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
	if db.IsImportableFeedSyncStatus(status) {
		return nil
	}
	return feedImportValidationErrorf("feed import status %q is not supported", status)
}

func truncateString(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	return value[:max]
}
