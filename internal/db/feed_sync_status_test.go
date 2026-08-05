package db

import (
	"reflect"
	"testing"
)

func TestFeedSyncStatusHelpers(t *testing.T) {
	t.Parallel()

	wantAll := []string{
		FeedSyncStatusPending,
		FeedSyncStatusRunning,
		FeedSyncStatusSuccess,
		FeedSyncStatusError,
		FeedSyncStatusSkipped,
		FeedSyncStatusDisabled,
		FeedSyncStatusExternal,
		FeedSyncStatusRejected,
		FeedSyncStatusPermanentError,
	}
	if got := FeedSyncStatusValues(); !reflect.DeepEqual(got, wantAll) {
		t.Fatalf("FeedSyncStatusValues() = %#v, want %#v", got, wantAll)
	}

	if got := NormalizeFeedSyncStatus(" SUCCESS "); got != FeedSyncStatusSuccess {
		t.Fatalf("NormalizeFeedSyncStatus() = %q, want %q", got, FeedSyncStatusSuccess)
	}
	if got := NormalizeFeedSyncStatus(""); got != FeedSyncStatusPending {
		t.Fatalf("NormalizeFeedSyncStatus(empty) = %q, want %q", got, FeedSyncStatusPending)
	}
	if !IsValidFeedSyncStatus(" Permanent_Error ") {
		t.Fatal("IsValidFeedSyncStatus() rejected normalized permanent_error status")
	}
	if IsValidFeedSyncStatus("failed") {
		t.Fatal("IsValidFeedSyncStatus() accepted unsupported failed status")
	}
}

func TestFeedSyncStatusUsesETagInitialismButKeepsJSONName(t *testing.T) {
	t.Parallel()

	statusType := reflect.TypeOf(FeedSyncStatus{})
	if _, ok := statusType.FieldByName("LastEtag"); ok {
		t.Fatal("FeedSyncStatus still exposes LastEtag; use LastETag for the Go identifier")
	}
	lastETag, ok := statusType.FieldByName("LastETag")
	if !ok {
		t.Fatal("FeedSyncStatus missing LastETag field")
	}
	if got := lastETag.Tag.Get("json"); got != "last_etag" {
		t.Fatalf("FeedSyncStatus.LastETag json tag = %q, want last_etag", got)
	}
}

func TestImportableFeedSyncStatusHelpers(t *testing.T) {
	t.Parallel()

	wantImportable := []string{
		FeedSyncStatusSuccess,
		FeedSyncStatusError,
		FeedSyncStatusRunning,
		FeedSyncStatusSkipped,
		FeedSyncStatusDisabled,
		FeedSyncStatusPending,
		FeedSyncStatusRejected,
	}
	if got := ImportableFeedSyncStatusValues(); !reflect.DeepEqual(got, wantImportable) {
		t.Fatalf("ImportableFeedSyncStatusValues() = %#v, want %#v", got, wantImportable)
	}

	for _, status := range wantImportable {
		if !IsImportableFeedSyncStatus(status) {
			t.Fatalf("IsImportableFeedSyncStatus(%q) = false, want true", status)
		}
	}
	for _, status := range []string{FeedSyncStatusExternal, FeedSyncStatusPermanentError, "Success", " failed "} {
		if IsImportableFeedSyncStatus(status) {
			t.Fatalf("IsImportableFeedSyncStatus(%q) = true, want false", status)
		}
	}
}
