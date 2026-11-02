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
	replacedEPSS  []db.EPSSEntry
	currentStatus *db.FeedSyncStatus
	replaceCalls  int
	statusCalls   int
	auditCalls    int
	auditErr      error
}

func (s *fallbackAuditFailureStore) ReplaceEPSSScores(_ context.Context, entries []db.EPSSEntry) (int, int, error) {
	s.replaceCalls++
	s.replacedEPSS = append([]db.EPSSEntry(nil), entries...)
	return len(entries), 0, nil
}

func (s *fallbackAuditFailureStore) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.statusCalls++
	if status == nil {
		s.currentStatus = nil
		return nil
	}
	copyValue := *status
	s.currentStatus = &copyValue
	return nil
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
	const (
		importSecret  = "retry-secret"
		requestBody   = `{"ignored":"request-body-marker"}`
		requestMarker = "request-body-marker"
	)
	run := func(correlationID string) (*httptest.ResponseRecorder, string) {
		t.Helper()
		var logs bytes.Buffer
		h := newLogCaptureFeedImportHandler(store, &logs)
		h.ConfigureFeedImportSecret(importSecret, true)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/epss/import", strings.NewReader(requestBody))
		req.SetPathValue("feed", "epss")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(HeaderFeedImportSecret, importSecret)
		req = withCorrelationID(req, correlationID)
		rr := httptest.NewRecorder()

		h.HandleImport(rr, req)

		responseText := rr.Body.String()
		if strings.Contains(responseText, importSecret) {
			t.Fatal("client response leaked the configured import secret")
		}
		for name, values := range rr.Header() {
			if strings.Contains(name, importSecret) {
				t.Fatal("response header name leaked the configured import secret")
			}
			for _, value := range values {
				if strings.Contains(value, importSecret) {
					t.Fatal("response header value leaked the configured import secret")
				}
			}
		}
		logText := logs.String()
		if strings.Contains(logText, importSecret) {
			t.Fatal("request logs leaked the configured import secret")
		}
		if strings.Contains(responseText, requestMarker) {
			t.Fatal("client response leaked request data")
		}
		if strings.Contains(logText, requestMarker) {
			t.Fatal("logs leaked request body data")
		}
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500: %s", rr.Code, responseText)
		}
		var body errorJSON
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode error response: %v; body=%q", err, responseText)
		}
		if body.Error != "feed import audit failed" {
			t.Fatalf("error = %q, want fixed audit diagnostic", body.Error)
		}
		if strings.Contains(responseText, errAudit.Error()) {
			t.Fatal("client response leaked internal audit data")
		}
		if !strings.Contains(logText, "feed import audit failed") || !strings.Contains(logText, correlationID) || !strings.Contains(logText, errAudit.Error()) {
			t.Fatalf("logs do not identify the failed audit and correlation ID: %s", logText)
		}
		return rr, logText
	}

	firstResponse, firstLogs := run("corr-fallback-audit-first")
	if store.replaceCalls != 1 || store.statusCalls != 1 || store.auditCalls != 1 {
		t.Fatalf("first attempt apply/status/audit calls = %d/%d/%d, want 1/1/1", store.replaceCalls, store.statusCalls, store.auditCalls)
	}
	secondResponse, secondLogs := run("corr-fallback-audit-second")
	if store.replaceCalls != 2 || store.statusCalls != 2 || store.auditCalls != 2 {
		t.Fatalf("retry apply/status/audit calls = %d/%d/%d, want 2/2/2", store.replaceCalls, store.statusCalls, store.auditCalls)
	}
	if firstResponse.Body.String() != secondResponse.Body.String() {
		t.Fatalf("retry response = %q, want the same generic response as first attempt %q", secondResponse.Body.String(), firstResponse.Body.String())
	}
	if strings.Contains(firstLogs, "corr-fallback-audit-second") || strings.Contains(secondLogs, "corr-fallback-audit-first") {
		t.Fatalf("request logs mixed correlation IDs: first=%s second=%s", firstLogs, secondLogs)
	}
	if len(store.auditEntries) != 0 {
		t.Fatalf("persisted audit rows = %d, want none after two failed attempts", len(store.auditEntries))
	}
	if len(store.replacedEPSS) != 1 || store.replacedEPSS[0].CVEID != "CVE-2026-7402" || store.replacedEPSS[0].Score != 0.41 || store.replacedEPSS[0].Percentile != 0.73 {
		t.Fatalf("EPSS state after retry = %+v, want one complete replacement without duplicates", store.replacedEPSS)
	}
	if store.currentStatus == nil || store.currentStatus.FeedName != "epss" || store.currentStatus.LastSyncStatus != "success" || store.currentStatus.EntriesSynced != 1 || store.currentStatus.EntriesTotal != 1 {
		t.Fatalf("feed status after retry = %+v, want one valid successful 1/1 current status", store.currentStatus)
	}
}
