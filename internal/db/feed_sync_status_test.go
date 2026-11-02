package db

import (
	"reflect"
	"strings"
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

func TestFeedSyncStatusValueSlicesAreDefensiveCopies(t *testing.T) {
	t.Parallel()

	all := FeedSyncStatusValues()
	importable := ImportableFeedSyncStatusValues()
	all[0] = "mutated"
	importable[0] = "mutated"

	if got := FeedSyncStatusValues()[0]; got != FeedSyncStatusPending {
		t.Fatalf("FeedSyncStatusValues()[0] after caller mutation = %q, want %q", got, FeedSyncStatusPending)
	}
	if got := ImportableFeedSyncStatusValues()[0]; got != FeedSyncStatusSuccess {
		t.Fatalf("ImportableFeedSyncStatusValues()[0] after caller mutation = %q, want %q", got, FeedSyncStatusSuccess)
	}
	if &all[0] == &FeedSyncStatusValues()[0] || &importable[0] == &ImportableFeedSyncStatusValues()[0] {
		t.Fatal("status value helper returned shared backing storage")
	}
}

func TestFeedSyncStatusValidationVocabulary(t *testing.T) {
	t.Parallel()

	want := []string{
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
	if got := FeedSyncStatusValues(); !reflect.DeepEqual(got, want) {
		t.Fatalf("FeedSyncStatusValues() = %#v, want %#v", got, want)
	}
	for _, status := range want {
		for _, input := range []string{status, " " + status + " ", "\t" + status + "\n"} {
			if !IsValidFeedSyncStatus(input) {
				t.Errorf("IsValidFeedSyncStatus(%q) = false", input)
			}
		}
		upper := " " + strings.ToUpper(status) + " "
		if got := NormalizeFeedSyncStatus(upper); got != status {
			t.Errorf("NormalizeFeedSyncStatus(%q) = %q, want %q", upper, got, status)
		}
	}
	for _, input := range []string{"", " ", "failed", "ok", "permanent-error", "success\x00"} {
		wantValid := strings.TrimSpace(input) == ""
		if got := IsValidFeedSyncStatus(input); got != wantValid {
			t.Errorf("IsValidFeedSyncStatus(%q) = %t, want %t", input, got, wantValid)
		}
	}
	if got := NormalizeFeedSyncStatus("\t\n"); got != FeedSyncStatusPending {
		t.Fatalf("NormalizeFeedSyncStatus(whitespace) = %q, want pending", got)
	}
}

func TestImportableFeedSyncStatusValidationVocabulary(t *testing.T) {
	t.Parallel()

	want := []string{
		FeedSyncStatusSuccess,
		FeedSyncStatusError,
		FeedSyncStatusRunning,
		FeedSyncStatusSkipped,
		FeedSyncStatusDisabled,
		FeedSyncStatusPending,
		FeedSyncStatusRejected,
	}
	if got := ImportableFeedSyncStatusValues(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ImportableFeedSyncStatusValues() = %#v, want %#v", got, want)
	}
	for _, status := range want {
		for _, input := range []string{status, " " + status + " ", "\t" + status + "\n"} {
			if !IsImportableFeedSyncStatus(input) {
				t.Errorf("IsImportableFeedSyncStatus(%q) = false", input)
			}
		}
	}
	for _, input := range []string{
		"", " ", FeedSyncStatusExternal, FeedSyncStatusPermanentError,
		"SUCCESS", "Success", "failed", "success\x00",
	} {
		if IsImportableFeedSyncStatus(input) {
			t.Errorf("IsImportableFeedSyncStatus(%q) = true", input)
		}
	}
}
