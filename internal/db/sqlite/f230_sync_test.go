package sqlite

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestF230SetSyncCursorQueryMapsEveryCursorField(t *testing.T) {
	query := url.Values{}
	setSyncCursorQuery(query, syncCursor{
		Vulnerabilities:       1,
		Malicious:             2,
		Reputation:            3,
		Lifecycle:             4,
		VulnerabilitiesCursor: "vuln-row",
		MaliciousCursor:       "mal-row",
		ReputationCursor:      "rep-row",
		LifecycleCursor:       "life-row",
		VulnerabilitiesDone:   true,
		MaliciousDone:         true,
		ReputationDone:        true,
		LifecycleDone:         true,
	})

	want := map[string]string{
		"vulnerabilities_offset": "1",
		"malicious_offset":       "2",
		"reputation_offset":      "3",
		"lifecycle_offset":       "4",
		"vulnerabilities_cursor": "vuln-row",
		"malicious_cursor":       "mal-row",
		"reputation_cursor":      "rep-row",
		"lifecycle_cursor":       "life-row",
		"vulnerabilities_done":   "true",
		"malicious_done":         "true",
		"reputation_done":        "true",
		"lifecycle_done":         "true",
	}
	if len(query) != len(want) {
		t.Fatalf("setSyncCursorQuery() keys = %v, want %v", query, want)
	}
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Errorf("setSyncCursorQuery() %s = %q, want %q", key, got, value)
		}
	}
}

func TestF230FreshSyncMetadataAndFeedStateEdges(t *testing.T) {
	now := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)

	metadata, err := freshSyncApplyMetadata(syncPageSnapshot{}, &syncResponse{FeedStatus: "healthy"}, now)
	if err != nil || metadata != (syncApplyMetadata{}) {
		t.Fatalf("freshSyncApplyMetadata(empty) = %+v, %v, want zero metadata", metadata, err)
	}
	if _, err := freshSyncApplyMetadata(syncPageSnapshot{SyncedAt: "not-a-timestamp"}, nil, now); err == nil {
		t.Fatal("freshSyncApplyMetadata(malformed timestamp) error = nil")
	}

	destination := &syncResponse{FeedStatus: "degraded", FeedVersions: map[string]string{"osv": "old"}}
	mergeSyncFeedState(destination, nil)
	mergeSyncFeedState(nil, &syncResponse{FeedStatus: "healthy"})
	mergeSyncFeedState(destination, &syncResponse{
		FeedStatus:   "healthy",
		FeedVersions: map[string]string{"osv": "new", "epss": "2026-11-05"},
	})
	if destination.FeedStatus != "degraded" {
		t.Fatalf("mergeSyncFeedState() status = %q, want first non-empty status", destination.FeedStatus)
	}
	if destination.FeedVersions["osv"] != "new" || destination.FeedVersions["epss"] != "2026-11-05" {
		t.Fatalf("mergeSyncFeedState() versions = %#v, want merged latest values", destination.FeedVersions)
	}
}

func TestF230SyncHTTPClientRejectsInvalidCABundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(path, []byte("not a PEM certificate"), 0o600); err != nil {
		t.Fatalf("write invalid CA bundle: %v", err)
	}

	client, err := newSyncHTTPClientWithCA(time.Second, path)
	if err == nil {
		t.Fatalf("newSyncHTTPClientWithCA() = %#v, nil; want invalid bundle error", client)
	}
	if client != nil {
		t.Fatalf("newSyncHTTPClientWithCA() client = %#v, want nil on error", client)
	}
}

func TestF230ApplySyncLifecycleRejectsEveryMalformedDate(t *testing.T) {
	store := newSQLiteTestStore(t)
	setters := []struct {
		field string
		set   func(*syncLifecycleRelease, *string)
	}{
		{field: "release_date", set: func(row *syncLifecycleRelease, value *string) { row.ReleaseDate = value }},
		{field: "lts_from", set: func(row *syncLifecycleRelease, value *string) { row.LTSFrom = value }},
		{field: "eoas_from", set: func(row *syncLifecycleRelease, value *string) { row.EOASFrom = value }},
		{field: "eol_from", set: func(row *syncLifecycleRelease, value *string) { row.EOLFrom = value }},
		{field: "discontinued_from", set: func(row *syncLifecycleRelease, value *string) { row.DiscontinuedFrom = value }},
		{field: "eoes_from", set: func(row *syncLifecycleRelease, value *string) { row.EOESFrom = value }},
	}

	for _, tc := range setters {
		t.Run(tc.field, func(t *testing.T) {
			bad := "not-a-date"
			row := syncLifecycleRelease{
				ID:          "lifecycle-invalid-" + tc.field,
				Ecosystem:   "npm",
				Name:        "fixture",
				ProductSlug: "fixture",
				Cycle:       "1",
			}
			tc.set(&row, &bad)

			_, err := applySync(context.Background(), store, false, &syncResponse{Lifecycle: []syncLifecycleRelease{row}})
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("applySync() error = %v, want malformed %s context", err, tc.field)
			}

			var count int
			if queryErr := store.DB().QueryRow(`SELECT COUNT(*) FROM lifecycle_releases_local`).Scan(&count); queryErr != nil {
				t.Fatalf("count lifecycle rows: %v", queryErr)
			}
			if count != 0 {
				t.Fatalf("lifecycle rows = %d, want rollback after malformed %s", count, tc.field)
			}
		})
	}
}

func TestF230TruncateUnicodeAndNonPositiveLimits(t *testing.T) {
	if got := truncate("abcdef", -1); got != "..." {
		t.Fatalf("truncate(negative) = %q, want ellipsis", got)
	}
	if got := truncate("abcdef", 0); got != "..." {
		t.Fatalf("truncate(zero) = %q, want ellipsis", got)
	}
	if got := truncate("ä", 1); got != "ä" {
		t.Fatalf("truncate(single rune) = %q, want complete rune", got)
	}
	if got := truncate("äöü", 2); got != "äö..." {
		t.Fatalf("truncate(UTF-8) = %q, want rune-safe truncation", got)
	}
}
