package v1

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

// FeedImportStore is the write-side persistence surface for external feed
// imports. It is intentionally separate from Store so scan/read API handlers do
// not depend on feed-ingestion mutations.
type FeedImportStore interface {
	UpsertVulnerability(ctx context.Context, vuln *db.Vulnerability) error
	DeleteVulnerability(ctx context.Context, id string) error
	UpsertMaliciousFinding(ctx context.Context, finding *db.MaliciousFinding) error
	DeleteMaliciousFinding(ctx context.Context, id string) error
	EnrichVulnCheck(ctx context.Context, entries []db.VulnCheckEntry) (int, error)
	SetCISAKEV(ctx context.Context, cveIDs []string) (int, error)
	ClearCISAKEV(ctx context.Context, cveIDs []string) (int, error)
	ReplaceEPSSScores(ctx context.Context, entries []db.EPSSEntry) (int, int, error)
	UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error
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

// NewFeedImportHandlerWithConfig creates a feed-import handler using server
// feed-import secret settings.
func NewFeedImportHandlerWithConfig(store FeedImportStore, logger *slog.Logger, cfg *config.Config) *FeedImportHandler {
	h := NewFeedImportHandler(store, logger)
	if cfg != nil {
		feeds := cfg.FeedsSnapshot()
		h.ConfigureFeedImportSecret(feeds.FeedImportSecret, cfg.Server.Mode == config.ModeProduction)
	}
	return h
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
	if r.Method != http.MethodPost {
		errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	correlationID := requestCorrelationID(r)
	if !h.authorizeFeedImport(r) {
		errorResponse(w, http.StatusForbidden, "feed import authorization required")
		return
	}

	feed := normalizeFeedName(r.PathValue("feed"))
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
			h.logger.Warn("feed import: invalid vulnerability body", "feed", feed, "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importVulnerabilities(r.Context(), feed, &req)
	case "openssf", "socket":
		var req maliciousImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid malicious body", "feed", feed, "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importMalicious(r.Context(), feed, &req)
	case "vulncheck":
		var req vulnCheckImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid vulncheck body", "feed", feed, "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importVulnCheck(r.Context(), feed, &req)
	case "cisakev":
		var req cisaKEVImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid cisakev body", "feed", feed, "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importCISAKEV(r.Context(), feed, &req)
	case "epss":
		var req epssImportRequest
		if err := readJSONWithLimit(r, &req, maxImportBody); err != nil {
			h.logger.Warn("feed import: invalid epss body", "feed", feed, "error", err, "correlation_id", correlationID)
			errorResponse(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		resp, err = h.importEPSS(r.Context(), feed, &req)
	default:
		errorResponse(w, http.StatusBadRequest, fmt.Sprintf("unsupported feed: %s", feed))
		return
	}

	if err != nil {
		var validationErr *feedImportValidationError
		if errors.As(err, &validationErr) {
			h.logger.Warn("feed import validation failed", "feed", feed, "error", validationErr, "correlation_id", correlationID)
			errorResponse(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		h.logger.Error("feed import failed", "feed", feed, "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusInternalServerError, "feed import failed")
		return
	}

	if err := h.recordFeedImportAudit(r, resp); err != nil {
		h.logger.Error("feed import audit failed", "feed", feed, "error", err, "correlation_id", correlationID)
		errorResponse(w, http.StatusInternalServerError, "feed import audit failed")
		return
	}

	h.logger.Info("feed import completed",
		"feed", feed,
		"imported", resp.Imported,
		"deleted", resp.Deleted,
		"entries_total", resp.EntriesTotal,
		"correlation_id", correlationID,
	)
	writeJSON(w, http.StatusOK, resp)
}
