package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/8linkz-sec/packmon/internal/db"
	feedstatus "github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

// FeedImportStore is the write-side persistence surface for external feed
// imports. It is intentionally separate from Store so scan/read API handlers do
// not depend on feed-ingestion mutations.
type FeedImportStore interface {
	// ImportVulnerabilityFeedWithAudit stores vulnerability feed records,
	// source-scoped deletions, optional feed status, and the required audit row.
	// Read/Write: write. Atomicity: all import mutations and audit insertion
	// commit or fail together. Feed-Source-Deletion Scope: deleteIDs apply only
	// to the feed argument. Import-Audit Semantics: audit receives returned
	// imported/deleted counts.
	ImportVulnerabilityFeedWithAudit(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (imported, deleted int, err error)

	// ImportMaliciousFeedWithAudit stores malicious-package feed records,
	// source-scoped deletions, optional feed status, and the required audit row.
	// Read/Write: write. Atomicity: all import mutations and audit insertion
	// commit or fail together. Feed-Source-Deletion Scope: deleteIDs apply only
	// to records whose source is the feed argument. Import-Audit Semantics:
	// audit receives returned imported/deleted counts.
	ImportMaliciousFeedWithAudit(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (imported, deleted int, err error)

	// ImportVulnCheckWithAudit stores additive VulnCheck enrichment, optional
	// feed status, and the required audit row. Read/Write: write. Atomicity:
	// enrichment, status, and audit insertion commit or fail together. Side
	// Effects: existing vulnerability enrichment fields/sources only.
	// Import-Audit Semantics: audit receives updated as imported and 0 deleted.
	ImportVulnCheckWithAudit(ctx context.Context, feed string, entries []db.VulnCheckEntry, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (updated int, err error)

	// ImportCISAKEVWithAudit stores incremental CISA KEV flags, optional feed
	// status, and the required audit row. Read/Write: write. Atomicity: flag
	// updates, status, and audit insertion commit or fail together. Side
	// Effects: no clearing of CVEs absent from cveIDs.
	// Import-Audit Semantics: audit receives updated as imported and 0 deleted.
	ImportCISAKEVWithAudit(ctx context.Context, feed string, cveIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (updated int, err error)

	// ReplaceCISAKEVWithAudit stores a complete CISA KEV snapshot, optional
	// feed status, and the required audit row. Read/Write: write. Atomicity:
	// set, clear, status, and audit insertion commit or fail together. Side
	// Effects: CVEs absent from cveIDs have KEV flags cleared.
	// Import-Audit Semantics: audit receives updated/imported and cleared/deleted.
	ReplaceCISAKEVWithAudit(ctx context.Context, feed string, cveIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (updated, cleared int, err error)

	// ImportEPSSWithAudit stores a complete EPSS snapshot, optional feed status,
	// and the required audit row. Read/Write: write. Atomicity: score updates,
	// stale-score clearing, status, and audit insertion commit or fail together.
	// Side Effects: CVEs absent from entries have EPSS values cleared.
	// Import-Audit Semantics: audit receives updated/imported and cleared/deleted.
	ImportEPSSWithAudit(ctx context.Context, feed string, entries []db.EPSSEntry, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (updated, cleared int, err error)

	// EnrichVulnCheck stores VulnCheck enrichment without import audit/status.
	// Read/Write: write. Atomicity: enrichment changes from one call commit or
	// fail together. Side Effects: existing vulnerability enrichment
	// fields/sources only.
	EnrichVulnCheck(ctx context.Context, entries []db.VulnCheckEntry) (int, error)

	// ReplaceEPSSScores stores a complete EPSS snapshot without import
	// audit/status. Read/Write: write. Atomicity: score updates and stale-score
	// clearing commit or fail together. Side Effects: CVEs absent from entries
	// have EPSS values cleared.
	ReplaceEPSSScores(ctx context.Context, entries []db.EPSSEntry) (int, int, error)

	// UpsertFeedSyncStatus stores feed import status only. Read/Write: write.
	// Atomicity: one status row is created or updated, or the call fails. Side
	// Effects: feed sync status only; no import audit row is written.
	UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error

	// InsertAdminAuditLog appends one feed-import audit record when an import
	// path did not record it atomically. Read/Write: write. Import-Audit
	// Semantics: this must not mutate feed data or feed status.
	InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error
}

// FeedImportHandler handles POST /api/v1/feeds/{feed}/import.
type FeedImportHandler struct {
	store              FeedImportStore
	logger             *slog.Logger
	feedImportSecret   string
	feedImportRequired bool
}

// NewFeedImportHandler creates a feed-import handler with a narrow write-side
// store contract.
func NewFeedImportHandler(store FeedImportStore, logger *slog.Logger) *FeedImportHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &FeedImportHandler{
		store:  store,
		logger: logger,
	}
}

// ConfigureFeedImportSecret configures the additional authorization required
// for feed imports. When required is true and no secret is configured, imports
// fail closed.
func (h *FeedImportHandler) ConfigureFeedImportSecret(secret string, required bool) {
	if h == nil {
		return
	}
	h.feedImportSecret = strings.TrimSpace(secret)
	h.feedImportRequired = required
}

// HandleImport handles POST /api/v1/feeds/{feed}/import.
func (h *FeedImportHandler) HandleImport(w http.ResponseWriter, r *http.Request) {
	r = requestWithLogger(r, h.logger)
	if r.Method != http.MethodPost {
		methodNotAllowedForRequest(w, r, http.MethodPost)
		return
	}

	correlationID := requestCorrelationID(r)
	if !h.authorizeFeedImport(r) {
		errorResponseForRequest(w, r, http.StatusForbidden, "feed import authorization required")
		return
	}
	if h.store == nil {
		errorResponseForRequest(w, r, http.StatusNotImplemented, "feed import endpoint is not supported by this store")
		return
	}

	feed := normalizeFeedName(r.PathValue("feed"))
	if feed == "" {
		errorResponseForRequest(w, r, http.StatusBadRequest, "feed name is required")
		return
	}

	capability, ok := feedImportCapabilityForFeed(feed)
	if !ok {
		errorResponseForRequest(w, r, http.StatusNotFound, fmt.Sprintf("unknown feed: %s", feed))
		return
	}
	dispatch := capability.dispatch
	if err := requireJSONContentType(r); err != nil {
		h.logger.Warn("feed import: invalid content type", "feed", feed, "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusUnsupportedMediaType, err.Error())
		return
	}
	auditBuilder := h.feedImportAuditBuilder(r, feed)

	resp, entriesTotal, err := dispatch.decodeAndImport(r.Context(), h, r, feed, auditBuilder)

	if err != nil {
		var decodeErr *feedImportDecodeError
		if errors.As(err, &decodeErr) {
			bodyName := decodeErr.bodyName
			if bodyName == "" {
				bodyName = "request"
			}
			message := "invalid JSON body: " + decodeErr.Error()
			h.logger.Warn("feed import: invalid "+bodyName+" body", "feed", feed, "error", decodeErr.Unwrap(), "correlation_id", correlationID)
			if statusErr := h.recordRejectedFeedImportStatus(r, feed, message, 1, correlationID); statusErr != nil {
				h.logger.Error("feed import reject status failed", "feed", feed, "error", statusErr, "correlation_id", correlationID)
				errorResponseForRequest(w, r, http.StatusInternalServerError, "feed import rejected but reject status could not be recorded")
				return
			}
			errorResponseForRequest(w, r, http.StatusBadRequest, message)
			return
		}

		var validationErr *feedImportValidationError
		if errors.As(err, &validationErr) {
			h.logger.Warn("feed import validation failed", "feed", feed, "error", validationErr, "correlation_id", correlationID)
			if statusErr := h.recordRejectedFeedImportStatus(r, feed, validationErr.Error(), entriesTotal, correlationID); statusErr != nil {
				h.logger.Error("feed import reject status failed", "feed", feed, "error", statusErr, "correlation_id", correlationID)
				errorResponseForRequest(w, r, http.StatusInternalServerError, "feed import rejected but reject status could not be recorded")
				return
			}
			errorResponseForRequest(w, r, http.StatusBadRequest, validationErr.Error())
			return
		}
		h.logger.Error("feed import failed", "feed", feed, "error", err, "correlation_id", correlationID)
		errorResponseForRequest(w, r, http.StatusInternalServerError, "feed import failed")
		return
	}

	if !resp.AuditRecorded {
		if err := h.recordFeedImportAudit(r, resp); err != nil {
			h.logger.Error("feed import audit failed", "feed", feed, "error", err, "correlation_id", correlationID)
			errorResponseForRequest(w, r, http.StatusInternalServerError, "feed import audit failed")
			return
		}
	}

	h.logger.Info("feed import completed",
		"feed", feed,
		"imported", resp.Imported,
		"deleted", resp.Deleted,
		"entries_total", resp.EntriesTotal,
		"correlation_id", correlationID,
	)
	writeJSONForRequest(w, r, http.StatusOK, resp)
}

func (h *FeedImportHandler) recordRejectedFeedImportStatus(r *http.Request, feed, reason string, entriesTotal int, correlationID string) error {
	if entriesTotal <= 0 {
		entriesTotal = 1
	}
	reason = logsafe.BoundedDiagnosticValue(reason, maxImportStatusLastErrorLength)
	statusMetadata := feedstatus.StatusMetadata{
		RejectedCount:   entriesTotal,
		RejectionReason: reason,
		CorrelationID:   correlationID,
		ClientIP:        logsafe.BoundedDiagnosticValue(clientIP(r), maxImportDiagnosticValueLength),
	}
	if identity, ok := requestctx.APIKeyIdentityFromContext(r.Context()); ok {
		statusMetadata.APIKeyID = identity.ID
		statusMetadata.APIKeyName = logsafe.BoundedDiagnosticValue(identity.Name, maxImportDiagnosticValueLength)
	}
	metadata, err := json.Marshal(statusMetadata)
	if err != nil {
		return err
	}
	return h.store.UpsertFeedSyncStatus(r.Context(), &db.FeedSyncStatus{
		FeedName:       feed,
		LastSyncStatus: db.FeedSyncStatusRejected,
		LastError:      reason,
		EntriesSynced:  0,
		EntriesTotal:   entriesTotal,
		Metadata:       metadata,
	})
}

func (h *FeedImportHandler) feedImportAuditBuilder(r *http.Request, feed string) func(imported, deleted int) *db.AdminAuditEntry {
	return func(imported, deleted int) *db.AdminAuditEntry {
		resp := feedImportResponse(feed, imported, deleted)
		entry, err := h.feedImportAuditEntry(r, resp)
		if err != nil {
			return &db.AdminAuditEntry{
				Action: "feed_import",
				IP:     clientIP(r),
			}
		}
		return entry
	}
}
