package feed

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// recordingStatusStore is a minimal FeedSyncStatusStore that captures what the
// preservation logic decided to write.
type recordingStatusStore struct {
	current   *db.FeedSyncStatus
	getErr    error
	upsertErr error
	written   *db.FeedSyncStatus
	upserts   int
}

func (s *recordingStatusStore) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.current, nil
}

func (s *recordingStatusStore) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.upserts++
	s.written = status
	return s.upsertErr
}

// TestUpsertFeedSyncStatusPreservingDataKeepsTheLastGoodEvidence covers the whole
// point of the preservation write: a failed sync must not erase the record of
// the last successful one. Losing LastSyncAt would make a feed that failed once
// look as if it had never synced, and losing the ETag/commit hash would force a
// full re-download on the next attempt.
func TestUpsertFeedSyncStatusPreservingDataKeepsTheLastGoodEvidence(t *testing.T) {
	t.Parallel()

	lastSync := time.Date(2026, 8, 3, 6, 0, 0, 0, time.UTC)
	store := &recordingStatusStore{current: &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncAt:     &lastSync,
		EntriesSynced:  1200,
		EntriesTotal:   1200,
		LastETag:       `W/"abc"`,
		LastCommitHash: "deadbeef",
		Metadata:       json.RawMessage(`{"rejected_count":2}`),
	}}

	// The failing sync reports an error and carries no evidence of its own.
	status := &db.FeedSyncStatus{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusError}
	if err := UpsertFeedSyncStatusPreservingData(context.Background(), store, status); err != nil {
		t.Fatalf("UpsertFeedSyncStatusPreservingData: %v", err)
	}

	written := store.written
	if written == nil {
		t.Fatal("nothing was written")
	}
	if written.LastSyncStatus != db.FeedSyncStatusError {
		t.Errorf("LastSyncStatus = %q, want the new error status kept", written.LastSyncStatus)
	}
	if written.LastSyncAt == nil || !written.LastSyncAt.Equal(lastSync) {
		t.Errorf("LastSyncAt = %v, want the previous successful timestamp preserved", written.LastSyncAt)
	}
	if written.EntriesSynced != 1200 || written.EntriesTotal != 1200 {
		t.Errorf("entries = %d/%d, want the previous counts preserved",
			written.EntriesSynced, written.EntriesTotal)
	}
	if written.LastETag != `W/"abc"` || written.LastCommitHash != "deadbeef" {
		t.Errorf("etag/commit = %q/%q, want the previous values preserved",
			written.LastETag, written.LastCommitHash)
	}
	if string(written.Metadata) != `{"rejected_count":2}` {
		t.Errorf("metadata = %s, want the previous metadata preserved", written.Metadata)
	}
}

// TestUpsertFeedSyncStatusPreservingDataRefusesToWriteBlind is the fail-closed
// half: if the previous row cannot be read, writing anyway would destroy the
// evidence the read was supposed to carry over.
func TestUpsertFeedSyncStatusPreservingDataRefusesToWriteBlind(t *testing.T) {
	t.Parallel()

	readErr := errors.New("status read failed")
	store := &recordingStatusStore{getErr: readErr}

	err := UpsertFeedSyncStatusPreservingData(context.Background(), store,
		&db.FeedSyncStatus{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusError})
	if !errors.Is(err, readErr) {
		t.Fatalf("error = %v, want the read failure", err)
	}
	if store.upserts != 0 {
		t.Fatalf("a status row was written after %d failed reads", store.upserts)
	}
}

// TestUpsertFeedSyncStatusPreservingDataHandlesAFirstSync covers the bootstrap
// case: with no previous row there is nothing to preserve, and the new status
// must still be written.
func TestUpsertFeedSyncStatusPreservingDataHandlesAFirstSync(t *testing.T) {
	t.Parallel()

	store := &recordingStatusStore{current: nil}
	now := time.Now().UTC()

	status := &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: db.FeedSyncStatusSuccess,
		LastSyncAt:     &now,
		EntriesSynced:  10,
	}
	if err := UpsertFeedSyncStatusPreservingData(context.Background(), store, status); err != nil {
		t.Fatalf("UpsertFeedSyncStatusPreservingData: %v", err)
	}
	if store.written == nil {
		t.Fatal("the first sync wrote nothing")
	}
	if store.written.EntriesSynced != 10 {
		t.Fatalf("EntriesSynced = %d, want the new value kept", store.written.EntriesSynced)
	}
}

// TestUpsertFeedSyncStatusPreservingDataBoundedAppliesItsOwnDeadline covers the
// bounded wrapper used by the manager. It exists so a status write cannot hang a
// shutting-down sync loop, and it must otherwise behave like the plain call.
func TestUpsertFeedSyncStatusPreservingDataBoundedAppliesItsOwnDeadline(t *testing.T) {
	t.Parallel()

	store := &deadlineObservingStatusStore{}
	err := UpsertFeedSyncStatusPreservingDataBounded(store,
		&db.FeedSyncStatus{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusSuccess})
	if err != nil {
		t.Fatalf("UpsertFeedSyncStatusPreservingDataBounded: %v", err)
	}
	if !store.sawDeadline {
		t.Fatal("the bounded call passed a context without a deadline")
	}
	if store.upserts != 1 {
		t.Fatalf("upserts = %d, want exactly one write", store.upserts)
	}
}

type deadlineObservingStatusStore struct {
	sawDeadline bool
	upserts     int
}

func (s *deadlineObservingStatusStore) GetFeedSyncStatus(ctx context.Context, _ string) (*db.FeedSyncStatus, error) {
	_, ok := ctx.Deadline()
	s.sawDeadline = ok
	return nil, nil
}

func (s *deadlineObservingStatusStore) UpsertFeedSyncStatus(context.Context, *db.FeedSyncStatus) error {
	s.upserts++
	return nil
}

// TestPreserveFeedStatusDataClonesMetadata guards against the preserved row and
// the source row sharing a metadata buffer, which would let one mutation rewrite
// both.
func TestPreserveFeedStatusDataClonesMetadata(t *testing.T) {
	t.Parallel()

	metadata := json.RawMessage(`{"a":1}`)
	src := &db.FeedSyncStatus{Metadata: metadata}
	dst := &db.FeedSyncStatus{}

	PreserveFeedStatusData(dst, src)
	if string(dst.Metadata) != `{"a":1}` {
		t.Fatalf("metadata = %s, want it copied", dst.Metadata)
	}
	metadata[2] = 'X'
	if string(dst.Metadata) == string(metadata) {
		t.Fatal("preserved metadata still aliases the source buffer")
	}

	// Nil arguments are a no-op rather than a panic; the caller may have no
	// previous row at all.
	PreserveFeedStatusData(nil, src)
	PreserveFeedStatusData(dst, nil)
}

// TestRejectedRecordCountDerivesACountWithoutMetadata covers the fallback used
// when a rejected sync recorded no metadata: the operator still has to see that
// something was rejected, so the count must never be zero for a rejected row.
func TestRejectedRecordCountDerivesACountWithoutMetadata(t *testing.T) {
	t.Parallel()

	if got := RejectedRecordCount(db.FeedSyncStatus{
		Metadata: json.RawMessage(`{"rejected_count":7}`),
	}); got != 7 {
		t.Errorf("count with metadata = %d, want 7", got)
	}
	if got := RejectedRecordCount(db.FeedSyncStatus{
		LastSyncStatus: db.FeedSyncStatusRejected,
		EntriesTotal:   42,
	}); got != 42 {
		t.Errorf("rejected row with a total = %d, want 42", got)
	}
	if got := RejectedRecordCount(db.FeedSyncStatus{
		LastSyncStatus: db.FeedSyncStatusRejected,
	}); got != 1 {
		t.Errorf("rejected row without a total = %d, want at least 1", got)
	}
	if got := RejectedRecordCount(db.FeedSyncStatus{
		LastSyncStatus: db.FeedSyncStatusSuccess,
	}); got != 0 {
		t.Errorf("successful row = %d, want 0", got)
	}
}

// TestParseStatusMetadataIgnoresUnusableJSON keeps the feed page renderable when
// a status row carries malformed metadata -- an operator needs the page most
// when something is broken.
func TestParseStatusMetadataIgnoresUnusableJSON(t *testing.T) {
	t.Parallel()

	if got := ParseStatusMetadata(nil); got != (StatusMetadata{}) {
		t.Errorf("ParseStatusMetadata(nil) = %+v, want the zero value", got)
	}
	if got := ParseStatusMetadata(json.RawMessage(`{`)); got != (StatusMetadata{}) {
		t.Errorf("ParseStatusMetadata(malformed) = %+v, want the zero value", got)
	}
	got := ParseStatusMetadata(json.RawMessage(`{"rejected_count":3,"rejection_reason":"schema"}`))
	if got.RejectedCount != 3 || got.RejectionReason != "schema" {
		t.Errorf("ParseStatusMetadata = %+v, want the decoded fields", got)
	}
}

// TestMetricsRecorderOrNoopNeverReturnsNil covers the guard that lets every call
// site record metrics unconditionally. A nil recorder reaching a call site would
// panic inside a sync loop.
func TestMetricsRecorderOrNoopNeverReturnsNil(t *testing.T) {
	t.Parallel()

	recorder := MetricsRecorderOrNoop(nil)
	if recorder == nil {
		t.Fatal("MetricsRecorderOrNoop(nil) = nil")
	}
	// The no-op must accept every call without panicking.
	recorder.AddQueueStuckRecovered(3)
	recorder.IncFeedSyncTimeout("osv")
	recorder.IncQueueError("osv")
	recorder.IncQueueJobCompleted("osv", "done")

	custom := NoopMetricsRecorder()
	if got := MetricsRecorderOrNoop(custom); got != custom {
		t.Fatal("MetricsRecorderOrNoop replaced a non-nil recorder")
	}
}
