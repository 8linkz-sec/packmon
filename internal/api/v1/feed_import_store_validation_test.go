package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// errStoreRejectedImportData is what a store returns when the imported values
// pass the handler checks but the store's own validation or the database
// rejects them, for example an EPSS score PostgreSQL cannot store as real.
var errStoreRejectedImportData = fmt.Errorf("postgres: import EPSS stream: postgres: EPSS snapshot entries[0].score must be between 0 and 1: %w", db.ErrInvalidFeedImportData)

// dataRejectingImportStore consumes every buffered feed import and then fails
// it with a store-side data error, before any status or audit row is written.
type dataRejectingImportStore struct {
	stubStore
}

func (s *dataRejectingImportStore) ImportVulnerabilityFeedWithAudit(context.Context, string, []db.Vulnerability, []string, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, int, error) {
	return 0, 0, fmt.Errorf("postgres: import vulnerability GHSA-store: insert affected package npm/left-pad: GHSA-store version_ranges[0].events must not be empty: %w", db.ErrInvalidFeedImportData)
}

func (s *dataRejectingImportStore) ImportMaliciousFeedWithAudit(context.Context, string, []db.MaliciousFinding, []string, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, int, error) {
	return 0, 0, fmt.Errorf("postgres: import malicious finding MAL-store: %w", db.ErrInvalidFeedImportData)
}

func (s *dataRejectingImportStore) ImportVulnCheckWithAudit(context.Context, string, []db.VulnCheckEntry, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, error) {
	return 0, errStoreRejectedImportData
}

func (s *dataRejectingImportStore) ImportCISAKEVWithAudit(context.Context, string, []string, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, error) {
	return 0, errStoreRejectedImportData
}

func (s *dataRejectingImportStore) ReplaceCISAKEVWithAudit(context.Context, string, []string, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, int, error) {
	return 0, 0, errStoreRejectedImportData
}

func (s *dataRejectingImportStore) ImportEPSSWithAudit(context.Context, string, []db.EPSSEntry, *db.FeedSyncStatus, db.FeedImportAuditBuilder) (int, int, error) {
	return 0, 0, errStoreRejectedImportData
}

// dataRejectingStreamImportStore is the streaming variant: it drains the
// handler's stream (so the handler-side normalization really runs) and then
// rejects the data the way the PostgreSQL store does.
type dataRejectingStreamImportStore struct {
	dataRejectingImportStore
	streamedEntries int
}

func (s *dataRejectingStreamImportStore) ImportEPSSStreamWithAudit(_ context.Context, _ string, stream func(func([]db.EPSSEntry) error) (*db.FeedSyncStatus, error), _ db.FeedImportAuditBuilder) (int, int, int, error) {
	if _, err := stream(func(batch []db.EPSSEntry) error {
		s.streamedEntries += len(batch)
		return nil
	}); err != nil {
		return 0, 0, s.streamedEntries, err
	}
	return 0, 0, s.streamedEntries, errStoreRejectedImportData
}

func (s *dataRejectingStreamImportStore) ImportVulnCheckStreamWithAudit(_ context.Context, _ string, stream func(func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error), _ db.FeedImportAuditBuilder) (int, int, error) {
	_, total, err := stream(func(batch []db.VulnCheckEntry) error {
		s.streamedEntries += len(batch)
		return nil
	})
	if err != nil {
		return 0, total, err
	}
	return 0, total, errStoreRejectedImportData
}

// TestHandleFeedImportMapsStoreDataRejectionToBadRequest covers every feed
// import path: a store-side data rejection is the client's fault, so it must be
// a 400 with a generic message and a recorded rejected status, never a 500 and
// never the store's internal error text.
func TestHandleFeedImportMapsStoreDataRejectionToBadRequest(t *testing.T) {
	t.Parallel()

	const (
		epssBody      = `{"entries":[{"cve_id":"CVE-2026-1000","score":0.5,"percentile":0.9}]}`
		vulnCheckBody = `{"entries":[{"cve_id":"CVE-2026-1000","cvss_score":5}]}`
	)
	tests := []struct {
		name      string
		feed      string
		body      string
		streaming bool
	}{
		{name: "epss buffered", feed: "epss", body: epssBody},
		{name: "epss streamed", feed: "epss", body: epssBody, streaming: true},
		{name: "vulncheck buffered", feed: "vulncheck", body: vulnCheckBody},
		{name: "vulncheck streamed", feed: "vulncheck", body: vulnCheckBody, streaming: true},
		{name: "cisakev incremental", feed: "cisakev", body: `{"cve_ids":["CVE-2026-1000"]}`},
		{name: "cisakev replace", feed: "cisakev", body: `{"cve_ids":["CVE-2026-1000"],"clear_missing":true}`},
		{name: "osv vulnerabilities", feed: "osv", body: `{"vulnerabilities":[{"id":"GHSA-store","summary":"s","severity":"HIGH","affected_packages":[{"ecosystem":"npm","name":"left-pad"}]}]}`},
		{name: "openssf malicious", feed: "openssf", body: `{"malicious":[{"id":"MAL-store","ecosystem":"npm","name":"evil"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var (
				store    FeedImportStore
				statuses func() []db.FeedSyncStatus
				audits   func() int
			)
			if tt.streaming {
				s := &dataRejectingStreamImportStore{}
				store = s
				statuses = func() []db.FeedSyncStatus { return s.upsertedStatuses }
				audits = func() int { return len(s.auditEntries) }
			} else {
				s := &dataRejectingImportStore{}
				store = s
				statuses = func() []db.FeedSyncStatus { return s.upsertedStatuses }
				audits = func() int { return len(s.auditEntries) }
			}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			var body errorJSON
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("error response body is not JSON: %v; body=%q", err, rr.Body.String())
			}
			if body.Error != feedImportStoreRejectedMessage {
				t.Fatalf("error = %q, want %q", body.Error, feedImportStoreRejectedMessage)
			}
			for _, internal := range []string{"postgres", "entries[0]", "insert affected package", "GHSA-store", "MAL-store"} {
				if strings.Contains(rr.Body.String(), internal) {
					t.Fatalf("error response leaks store internals %q: %s", internal, rr.Body.String())
				}
			}
			if audits() != 0 {
				t.Fatalf("audit entries = %d, want none for a rejected import", audits())
			}
			assertSingleRejectedFeedStatus(t, statuses(), tt.feed)
			if got := statuses()[0].LastError; got != feedImportStoreRejectedMessage {
				t.Fatalf("rejected LastError = %q, want the generic message", got)
			}
		})
	}
}

// TestHandleFeedImportKeepsStoreOutageAsServerError pins the other side of the
// mapping: an ordinary store failure stays a 500.
func TestHandleFeedImportKeepsStoreOutageAsServerError(t *testing.T) {
	t.Parallel()

	store := &importErrorStore{epssErr: fmt.Errorf("postgres: import EPSS: connection refused")}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/epss/import", strings.NewReader(`{"entries":[{"cve_id":"CVE-2026-1000","score":0.5,"percentile":0.9}]}`))
	req.SetPathValue("feed", "epss")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rr.Code, rr.Body.String())
	}
}
