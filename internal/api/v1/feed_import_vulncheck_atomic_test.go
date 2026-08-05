package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

var errVulnCheckStreamBatch = errors.New("vulncheck stream batch failed")

func (s *streamingVulnCheckImportStore) ImportVulnCheckStreamWithAudit(ctx context.Context, _ string, stream func(func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error), audit db.FeedImportAuditBuilder) (int, int, error) {
	updated := 0
	status, total, err := stream(func(entries []db.VulnCheckEntry) error {
		if len(s.upsertedStatuses) > 0 {
			s.statusSeenDuringEnrich = true
		}
		if len(s.auditEntries) > 0 {
			s.auditSeenDuringEnrich = true
		}
		s.enrichBatchLengths = append(s.enrichBatchLengths, len(entries))
		if len(entries) > 1000 {
			return errors.New("vulncheck batch exceeded streaming limit")
		}
		updated += len(entries)
		return nil
	})
	if err != nil {
		return updated, total, err
	}
	if status != nil {
		if err := s.UpsertFeedSyncStatus(ctx, status); err != nil {
			return updated, total, err
		}
	}
	if audit != nil {
		auditEntry := audit(updated, 0)
		if err := s.InsertAdminAuditLog(ctx, &auditEntry); err != nil {
			return updated, total, err
		}
	}
	return updated, total, nil
}

type atomicFailingVulnCheckStore struct {
	stubStore
	streamCalls      int
	enrichCalls      int
	batchesSeen      int
	failOnBatch      int
	streamBatchSizes []int
	committed        []db.VulnCheckEntry
}

func (s *atomicFailingVulnCheckStore) ImportVulnCheckStreamWithAudit(ctx context.Context, _ string, stream func(func([]db.VulnCheckEntry) error) (*db.FeedSyncStatus, int, error), audit db.FeedImportAuditBuilder) (int, int, error) {
	s.streamCalls++
	pending := make([]db.VulnCheckEntry, 0)
	updated := 0
	status, total, err := stream(func(entries []db.VulnCheckEntry) error {
		s.batchesSeen++
		s.streamBatchSizes = append(s.streamBatchSizes, len(entries))
		if s.failOnBatch > 0 && s.batchesSeen == s.failOnBatch {
			return errVulnCheckStreamBatch
		}
		pending = append(pending, entries...)
		updated += len(entries)
		return nil
	})
	if err != nil {
		return updated, total, err
	}
	s.committed = append(s.committed, pending...)
	if status != nil {
		if err := s.UpsertFeedSyncStatus(ctx, status); err != nil {
			return updated, total, err
		}
	}
	if audit != nil {
		auditEntry := audit(updated, 0)
		if err := s.InsertAdminAuditLog(ctx, &auditEntry); err != nil {
			return updated, total, err
		}
	}
	return updated, total, nil
}

func (s *atomicFailingVulnCheckStore) EnrichVulnCheck(_ context.Context, entries []db.VulnCheckEntry) (int, error) {
	s.enrichCalls++
	s.batchesSeen++
	if s.failOnBatch > 0 && s.batchesSeen == s.failOnBatch {
		return 0, errVulnCheckStreamBatch
	}
	s.committed = append(s.committed, entries...)
	return len(entries), nil
}

func TestHandleFeedImportVulnCheckBatchFailureDoesNotCommitEarlierBatches(t *testing.T) {
	store := &atomicFailingVulnCheckStore{failOnBatch: 2}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/vulncheck/import", strings.NewReader(vulnCheckStreamingImportBody(2001)))
	req.SetPathValue("feed", "vulncheck")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rr.Code, rr.Body.String())
	}
	if store.streamCalls != 1 {
		t.Fatalf("VulnCheck stream import calls = %d, want 1", store.streamCalls)
	}
	if store.enrichCalls != 0 {
		t.Fatalf("VulnCheck import called non-atomic EnrichVulnCheck %d time(s)", store.enrichCalls)
	}
	if len(store.committed) != 0 {
		t.Fatalf("committed VulnCheck entries after failed request = %d, want 0", len(store.committed))
	}
	if len(store.upsertedStatuses) != 0 || len(store.auditEntries) != 0 {
		t.Fatalf("status/audit written for failed VulnCheck request: statuses=%d audits=%d", len(store.upsertedStatuses), len(store.auditEntries))
	}
	if want := []int{1000, 1000}; !reflect.DeepEqual(store.streamBatchSizes, want) {
		t.Fatalf("VulnCheck stream batch sizes = %+v, want %+v", store.streamBatchSizes, want)
	}
}

func TestHandleFeedImportVulnCheckStreamCommitsStatusAndAuditAtomically(t *testing.T) {
	store := &atomicFailingVulnCheckStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/vulncheck/import", strings.NewReader(vulnCheckStreamingImportBody(2005)))
	req.SetPathValue("feed", "vulncheck")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp importResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if resp.Imported != 2005 || resp.Deleted != 0 || resp.EntriesTotal != 2005 {
		t.Fatalf("response = %+v, want imported=2005 deleted=0 entries_total=2005", resp)
	}
	if store.streamCalls != 1 || store.enrichCalls != 0 {
		t.Fatalf("VulnCheck import calls stream=%d enrich=%d, want 1/0", store.streamCalls, store.enrichCalls)
	}
	if len(store.committed) != 2005 {
		t.Fatalf("committed VulnCheck entries = %d, want 2005", len(store.committed))
	}
	if len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].EntriesSynced != 2005 || store.upsertedStatuses[0].EntriesTotal != 2005 {
		t.Fatalf("VulnCheck status = %+v, want one success status with 2005/2005", store.upsertedStatuses)
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("VulnCheck audit entries = %d, want 1", len(store.auditEntries))
	}
	if want := []int{1000, 1000, 5}; !reflect.DeepEqual(store.streamBatchSizes, want) {
		t.Fatalf("VulnCheck stream batch sizes = %+v, want %+v", store.streamBatchSizes, want)
	}
}
