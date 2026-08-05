package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestFeedRowStatusReasonExplainsEveryUnhealthyState covers the text under a
// non-green feed badge. It is the only place the admin page says *why* a feed is
// not healthy, so an unmapped state leaves the operator with a colour and no
// explanation.
func TestFeedRowStatusReasonExplainsEveryUnhealthyState(t *testing.T) {
	t.Parallel()

	recent := time.Now().UTC().Add(-time.Hour)

	for _, tc := range []struct {
		name string
		row  adminFeedRow
		want string
	}{
		{
			name: "disabled by configuration",
			row:  adminFeedRow{ConfigEnabled: false},
			want: "feed disabled",
		},
		{
			name: "disabled by sync status",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusDisabled},
			want: "feed disabled",
		},
		{
			name: "missing API key",
			row:  adminFeedRow{ConfigEnabled: true, APIKeyStateCode: adminFeedAPIKeyStateMissingCode},
			want: "required API key not configured",
		},
		{
			name: "running by row status",
			row:  adminFeedRow{ConfigEnabled: true, Status: "running"},
			want: "sync running",
		},
		{
			name: "running by sync status",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusRunning},
			want: "sync running",
		},
		{
			name: "failed sync",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusError},
			want: "last sync failed",
		},
		{
			name: "permanent error",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusPermanentError},
			want: "permanent feed error",
		},
		{
			name: "external feed",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusExternal},
			want: "external feed managed outside Packmon",
		},
		{
			name: "pending",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusPending},
			want: "sync pending",
		},
		{
			name: "skipped",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusSkipped},
			want: "last sync skipped",
		},
		{
			name: "rejected import",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusRejected},
			want: "feed import rejected",
		},
		{
			name: "never synced",
			row:  adminFeedRow{ConfigEnabled: true, LastSyncStatus: db.FeedSyncStatusSuccess},
			want: "never synced",
		},
	} {
		if got := tc.row.StatusReason(); got != tc.want {
			t.Errorf("%s: StatusReason = %q, want %q", tc.name, got, tc.want)
		}
	}

	// Casing and padding must not defeat the lookup.
	padded := adminFeedRow{ConfigEnabled: true, LastSyncStatus: "  ERROR  "}
	if got := padded.StatusReason(); got != "last sync failed" {
		t.Errorf("padded status = %q, want the normalised reason", got)
	}

	// A healthy, recently synced feed needs no explanation at all.
	healthy := adminFeedRow{
		ConfigEnabled:  true,
		LastSyncStatus: db.FeedSyncStatusSuccess,
		LastSyncAt:     &recent,
		LastSyncAtTime: recent,
		EntriesSynced:  100,
		EntriesTotal:   100,
	}
	if got := healthy.StatusReason(); got != "" {
		t.Errorf("healthy feed reason = %q, want none", got)
	}
}

// TestFeedRowStatusReasonFlagsStaleAndImpossibleTimestamps covers the freshness
// checks. A feed that stopped syncing still reports its last success, so without
// these the row would look healthy indefinitely.
func TestFeedRowStatusReasonFlagsStaleAndImpossibleTimestamps(t *testing.T) {
	t.Parallel()

	stale := time.Now().UTC().Add(-72 * time.Hour)
	row := adminFeedRow{
		ConfigEnabled:  true,
		LastSyncStatus: db.FeedSyncStatusSuccess,
		LastSyncAt:     &stale,
		LastSyncAtTime: stale,
	}
	if got := row.StatusReason(); !strings.Contains(got, "stale") {
		t.Errorf("stale feed reason = %q, want it flagged as stale", got)
	}

	// A timestamp in the future means clock skew or a corrupt row; either way it
	// must not be read as "just synced".
	future := time.Now().UTC().Add(2 * time.Hour)
	row = adminFeedRow{
		ConfigEnabled:  true,
		LastSyncStatus: db.FeedSyncStatusSuccess,
		LastSyncAt:     &future,
		LastSyncAtTime: future,
	}
	if got := row.StatusReason(); got != "last sync timestamp is in the future" {
		t.Errorf("future timestamp reason = %q, want it called out", got)
	}
}

// TestFeedRowStatusReasonFlagsAnEmptySync covers the warning case where a sync
// completed but moved no data -- a silently empty feed is worse than a failing
// one because nothing else reports it.
func TestFeedRowStatusReasonFlagsAnEmptySync(t *testing.T) {
	t.Parallel()

	recent := time.Now().UTC().Add(-time.Minute)
	row := adminFeedRow{
		ConfigEnabled:  true,
		Status:         "warning",
		LastSyncStatus: db.FeedSyncStatusSuccess,
		LastSyncAt:     &recent,
		LastSyncAtTime: recent,
	}
	if got := row.StatusReason(); got != "no entries synced yet" {
		t.Errorf("empty sync reason = %q, want it called out", got)
	}
}

// TestFeedRowStatusReasonNamesAnUnknownStatus keeps a status the UI does not know
// visible rather than silently healthy.
func TestFeedRowStatusReasonNamesAnUnknownStatus(t *testing.T) {
	t.Parallel()

	row := adminFeedRow{ConfigEnabled: true, LastSyncStatus: "brand-new-state"}
	got := row.StatusReason()
	if !strings.Contains(got, "unknown feed status") || !strings.Contains(got, "brand-new-state") {
		t.Fatalf("unknown status reason = %q, want it named", got)
	}
}

// TestCleanupExpiredLoginAttemptsReleasesOnlyElapsedLockouts covers the janitor
// on the login-lockout map. Dropping a still-active lockout would hand an
// attacker their attempts back; keeping expired ones leaks memory and locks out
// a legitimate operator forever.
func TestCleanupExpiredLoginAttemptsReleasesOnlyElapsedLockouts(t *testing.T) {
	t.Parallel()

	now := time.Now()
	handler := &AdminHandler{loginAttempts: map[string]*loginAttempt{
		"nil-entry": nil,
		"expired-lockout": {
			count:    loginMaxAttempts,
			lockedAt: now.Add(-loginLockoutDuration - time.Minute),
		},
		"active-lockout": {
			count:    loginMaxAttempts,
			lockedAt: now.Add(-time.Minute),
		},
		"below-threshold": {
			count:        loginMaxAttempts - 1,
			lastFailedAt: now.Add(-time.Minute),
		},
	}}

	handler.cleanupExpiredLoginAttempts(now)

	handler.loginMu.Lock()
	defer handler.loginMu.Unlock()

	if _, ok := handler.loginAttempts["nil-entry"]; ok {
		t.Error("a nil attempt entry survived the cleanup")
	}
	if _, ok := handler.loginAttempts["expired-lockout"]; ok {
		t.Error("an elapsed lockout was not released")
	}
	if _, ok := handler.loginAttempts["active-lockout"]; !ok {
		t.Error("an active lockout was released early")
	}
}

// TestAdminRequestCorrelationIDToleratesAMissingRequest keeps the log-attribute
// helper safe on the paths that build attributes without a request in hand.
func TestAdminRequestCorrelationIDToleratesAMissingRequest(t *testing.T) {
	t.Parallel()

	if got := adminRequestCorrelationID(nil); got != "" {
		t.Fatalf("adminRequestCorrelationID(nil) = %q, want empty", got)
	}
	if got := adminRequestCorrelationID(httptest.NewRequest(http.MethodGet, "/admin/", nil)); got != "" {
		t.Fatalf("adminRequestCorrelationID(no correlation) = %q, want empty", got)
	}
}

// TestAdminLogAttrsForCorrelationIDAlwaysAppendsTheCorrelationID pins the log
// shape. Every admin log line has to carry the correlation ID, otherwise an
// audit entry cannot be tied to the request that produced it.
func TestAdminLogAttrsForCorrelationIDAlwaysAppendsTheCorrelationID(t *testing.T) {
	t.Parallel()

	attrs := adminLogAttrsForCorrelationID("cid-1", "client_ip", "127.0.0.1")
	if len(attrs)%2 != 0 && len(attrs) != 3 {
		t.Fatalf("attrs = %v, want the supplied pairs plus the correlation ID", attrs)
	}
	found := false
	for _, attr := range attrs {
		if text, ok := attr.(interface{ String() string }); ok &&
			strings.Contains(text.String(), "cid-1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("attrs = %v, want the correlation ID appended", attrs)
	}

	// With no extra attributes the correlation ID is still present.
	if got := adminLogAttrsForCorrelationID("cid-2"); len(got) != 1 {
		t.Fatalf("attrs = %v, want exactly the correlation ID", got)
	}
}

// TestAdvisoryReturnOffsetReadsTheFormsPagingState covers the hidden field that
// returns the operator to the page they submitted from. A wrong value silently
// jumps them to a different page of advisories.
func TestAdvisoryReturnOffsetReadsTheFormsPagingState(t *testing.T) {
	t.Parallel()

	if got := advisoryReturnOffset(nil); got != 0 {
		t.Fatalf("advisoryReturnOffset(nil) = %d, want 0", got)
	}

	for value, want := range map[string]int{
		"":       0,
		"0":      0,
		"25":     25,
		"-5":     0,
		"abc":    0,
		"999999": 999999,
	} {
		req := httptest.NewRequest(http.MethodPost, "/admin/advisories/save", nil)
		req.PostForm = url.Values{"return_offset": {value}}
		if got := advisoryReturnOffset(req); got != want {
			t.Errorf("advisoryReturnOffset(%q) = %d, want %d", value, got, want)
		}
	}
}

// TestQueueReturnStateDropsAnUnusableStatusFilter covers the queue equivalent.
// An unrecognised status must fall back to "no filter" rather than be echoed
// into the redirect, where it would produce an empty queue page.
func TestQueueReturnStateDropsAnUnusableStatusFilter(t *testing.T) {
	t.Parallel()

	status, offset := queueReturnState(nil)
	if status != "" || offset != 0 {
		t.Fatalf("queueReturnState(nil) = %q, %d; want the zero state", status, offset)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/queue/retry", nil)
	req.PostForm = url.Values{"return_status": {"not-a-status"}, "return_offset": {"40"}}
	status, offset = queueReturnState(req)
	if status != "" {
		t.Errorf("status = %q, want an unusable filter dropped", status)
	}
	if offset != 40 {
		t.Errorf("offset = %d, want the paging state preserved", offset)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/queue/retry", nil)
	req.PostForm = url.Values{"return_status": {"pending"}, "return_offset": {"-1"}}
	status, offset = queueReturnState(req)
	if status != "pending" {
		t.Errorf("status = %q, want the valid filter kept", status)
	}
	if offset != 0 {
		t.Errorf("offset = %d, want a negative offset clamped", offset)
	}
}

// TestAPIKeyNameValidationMessageCapitalisesTheSentence covers the small
// presentation fix applied before a validation error reaches the form.
func TestAPIKeyNameValidationMessageCapitalisesTheSentence(t *testing.T) {
	t.Parallel()

	if got := apiKeyNameValidationMessage(nil); got != "" {
		t.Fatalf("apiKeyNameValidationMessage(nil) = %q, want empty", got)
	}

	got := apiKeyNameValidationMessage(errTestKeyName("key name must not be empty"))
	if got != "Key name must not be empty" {
		t.Errorf("message = %q, want the sentence capitalised", got)
	}

	// A message that does not start with the prefix is passed through unchanged.
	got = apiKeyNameValidationMessage(errTestKeyName("Something else went wrong"))
	if got != "Something else went wrong" {
		t.Errorf("message = %q, want it passed through", got)
	}
}

type errTestKeyName string

func (e errTestKeyName) Error() string { return string(e) }
