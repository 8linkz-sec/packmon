package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestFeedImportHandlerNilConfigurationAndStoreBehavior(t *testing.T) {
	t.Parallel()

	var nilHandler *FeedImportHandler
	nilHandler.ConfigureFeedImportSecret("ignored", true)

	h := newTestFeedImportHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/epss/import", strings.NewReader(`{"entries":[]}`))
	req.SetPathValue("feed", "epss")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501: %s", rr.Code, rr.Body.String())
	}
	var body errorJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v; body=%q", err, rr.Body.String())
	}
	if body.Error != "feed import endpoint is not supported by this store" {
		t.Fatalf("error = %q, want unsupported-store diagnostic", body.Error)
	}
}

type rejectedStatusFailureStore struct {
	stubStore
	statusErr   error
	statusCalls int
	importCalls int
}

func (s *rejectedStatusFailureStore) UpsertFeedSyncStatus(_ context.Context, _ *db.FeedSyncStatus) error {
	s.statusCalls++
	return s.statusErr
}

func (s *rejectedStatusFailureStore) ImportEPSSWithAudit(context.Context, string, []db.EPSSEntry, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, int, error) {
	s.importCalls++
	return 0, 0, fmt.Errorf("internal-store-detail: %w", db.ErrInvalidFeedImportData)
}

func TestHandleFeedImportRejectedStatusPersistenceFailures(t *testing.T) {
	t.Parallel()

	errStatus := errors.New("status persistence unavailable")
	tests := []struct {
		name        string
		feed        string
		body        string
		wantImports int
	}{
		{
			name: "malformed JSON",
			feed: "epss",
			body: `{"entries":[{"cve_id":"RAW-BODY-MARKER"}`,
		},
		{
			name: "semantic manual mutation",
			feed: "osv",
			body: `{"vulnerabilities":[{"id":"GHSA-safe","summary":"RAW-BODY-MARKER"}],"delete_vulnerability_ids":["manual:owned"]}`,
		},
		{
			name:        "store validation",
			feed:        "epss",
			body:        `{"entries":[{"cve_id":"CVE-2026-7401","score":0.2,"percentile":0.3}]}`,
			wantImports: 1,
		},
	}
	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &rejectedStatusFailureStore{statusErr: errStatus}
			var logs bytes.Buffer
			h := newLogCaptureFeedImportHandler(store, &logs)
			correlationID := fmt.Sprintf("corr-reject-status-%d", index)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			req = withCorrelationID(req, correlationID)
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500: %s", rr.Code, rr.Body.String())
			}
			var body errorJSON
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode error response: %v; body=%q", err, rr.Body.String())
			}
			if body.Error != "feed import rejected but reject status could not be recorded" {
				t.Fatalf("error = %q, want fixed status-recording diagnostic", body.Error)
			}
			for _, forbidden := range []string{"RAW-BODY-MARKER", "internal-store-detail", errStatus.Error()} {
				if strings.Contains(rr.Body.String(), forbidden) {
					t.Fatalf("client response leaked %q: %s", forbidden, rr.Body.String())
				}
			}
			if store.statusCalls != 1 || store.importCalls != tt.wantImports {
				t.Fatalf("store calls status/import = %d/%d, want 1/%d", store.statusCalls, store.importCalls, tt.wantImports)
			}
			if len(store.upsertedVulns) != 0 || len(store.upsertedMalicious) != 0 || len(store.deletedVulnIDs) != 0 || len(store.deletedMaliciousIDs) != 0 || len(store.auditEntries) != 0 {
				t.Fatalf("rejected request mutated state or audit: vulns=%d malicious=%d deleteV=%d deleteM=%d audits=%d",
					len(store.upsertedVulns), len(store.upsertedMalicious), len(store.deletedVulnIDs), len(store.deletedMaliciousIDs), len(store.auditEntries))
			}
			logText := logs.String()
			if !strings.Contains(logText, "feed import reject status failed") || !strings.Contains(logText, correlationID) || !strings.Contains(logText, errStatus.Error()) {
				t.Fatalf("logs do not identify the safe persistence failure and correlation ID: %s", logText)
			}
			if strings.Contains(logText, "RAW-BODY-MARKER") {
				t.Fatalf("logs leaked raw request data: %s", logText)
			}
		})
	}
}

type fallbackAuditFailureStore struct {
	stubStore
	replacedEPSS []db.EPSSEntry
	auditCalls   int
	auditErr     error
}

func (s *fallbackAuditFailureStore) ReplaceEPSSScores(_ context.Context, entries []db.EPSSEntry) (int, int, error) {
	s.replacedEPSS = append([]db.EPSSEntry(nil), entries...)
	return len(entries), 0, nil
}

func (s *fallbackAuditFailureStore) InsertAdminAuditLog(_ context.Context, _ *db.AdminAuditEntry) error {
	s.auditCalls++
	return s.auditErr
}

type fallbackAuditEPSSDispatch struct{}

func (fallbackAuditEPSSDispatch) newRequest() any {
	return &epssImportRequest{}
}

func (fallbackAuditEPSSDispatch) decodeAndImport(ctx context.Context, h *FeedImportHandler, _ *http.Request, feed string, _ feedImportAuditFunc) (*importResponse, int, error) {
	entries := []db.EPSSEntry{{CVEID: "CVE-2026-7402", Score: 0.41, Percentile: 0.73}}
	updated, cleared, err := h.store.ReplaceEPSSScores(ctx, entries)
	if err != nil {
		return nil, 0, err
	}
	status := &db.FeedSyncStatus{
		FeedName:       feed,
		LastSyncStatus: "success",
		EntriesSynced:  len(entries),
		EntriesTotal:   len(entries),
	}
	if err := h.store.UpsertFeedSyncStatus(ctx, status); err != nil {
		return nil, 0, err
	}
	return &importResponse{
		Feed:          feed,
		Imported:      updated,
		Deleted:       cleared,
		EntriesTotal:  len(entries),
		AuditRecorded: false,
	}, len(entries), nil
}

func TestHandleFeedImportFallbackAuditFailurePreservesAppliedState(t *testing.T) {
	// This test temporarily replaces a package-global dispatch capability. It is
	// deliberately sequential, has no parallel subtests, and restores the exact
	// prior map state before returning.
	original, existed := feedImportCapabilitiesByName["epss"]
	feedImportCapabilitiesByName["epss"] = feedImportCapability{name: "epss", dispatch: fallbackAuditEPSSDispatch{}}
	defer func() {
		if existed {
			feedImportCapabilitiesByName["epss"] = original
			return
		}
		delete(feedImportCapabilitiesByName, "epss")
	}()

	errAudit := errors.New("audit persistence unavailable")
	store := &fallbackAuditFailureStore{auditErr: errAudit}
	var logs bytes.Buffer
	h := newLogCaptureFeedImportHandler(store, &logs)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/epss/import", strings.NewReader(`{"ignored":"request-body-marker"}`))
	req.SetPathValue("feed", "epss")
	req.Header.Set("Content-Type", "application/json")
	req = withCorrelationID(req, "corr-fallback-audit")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rr.Code, rr.Body.String())
	}
	var body errorJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v; body=%q", err, rr.Body.String())
	}
	if body.Error != "feed import audit failed" {
		t.Fatalf("error = %q, want fixed audit diagnostic", body.Error)
	}
	if strings.Contains(rr.Body.String(), errAudit.Error()) || strings.Contains(rr.Body.String(), "request-body-marker") {
		t.Fatalf("client response leaked internal or request data: %s", rr.Body.String())
	}
	if store.auditCalls != 1 || len(store.auditEntries) != 0 {
		t.Fatalf("audit attempts/rows = %d/%d, want one failed attempt and no row", store.auditCalls, len(store.auditEntries))
	}
	if len(store.replacedEPSS) != 1 || store.replacedEPSS[0].CVEID != "CVE-2026-7402" || store.replacedEPSS[0].Score != 0.41 || store.replacedEPSS[0].Percentile != 0.73 {
		t.Fatalf("applied EPSS state = %+v, want the complete replacement", store.replacedEPSS)
	}
	if len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].FeedName != "epss" || store.upsertedStatuses[0].LastSyncStatus != "success" || store.upsertedStatuses[0].EntriesSynced != 1 || store.upsertedStatuses[0].EntriesTotal != 1 {
		t.Fatalf("applied feed status = %+v, want one successful 1/1 status", store.upsertedStatuses)
	}
	logText := logs.String()
	if !strings.Contains(logText, "feed import audit failed") || !strings.Contains(logText, "corr-fallback-audit") || !strings.Contains(logText, errAudit.Error()) {
		t.Fatalf("logs do not identify the failed audit and correlation ID: %s", logText)
	}
	if strings.Contains(logText, "request-body-marker") {
		t.Fatalf("logs leaked request body data: %s", logText)
	}
	// A retry is therefore not a clean first attempt: it will replace the same
	// already-applied snapshot/status again before making a new audit attempt.
}
