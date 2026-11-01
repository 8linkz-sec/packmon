package sqlite

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

const syncReplaceRanges = `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`

func syncReplaceVulnerability(id, ecosystem, name string) syncVulnerability {
	return syncVulnerability{
		ID:               id,
		Ecosystem:        ecosystem,
		Name:             name,
		VersionRanges:    syncReplaceRanges,
		VersionsAffected: `[]`,
		Severity:         "HIGH",
		Summary:          "coverage move fixture",
	}
}

// seedSyncReplaceRows stores the pre-move state: GHSA-move affects npm
// left-pad and pypi requests, GHSA-other affects npm other. With since set,
// the next non-full sync is a delta with a since window.
func seedSyncReplaceRows(t *testing.T, store *Store, since string) {
	t.Helper()
	ctx := context.Background()
	if _, err := applySync(ctx, store, true, &syncResponse{
		SyncedAt: "2026-05-30T09:00:00Z",
		Vulnerabilities: []syncVulnerability{
			syncReplaceVulnerability("GHSA-move", "npm", "left-pad"),
			syncReplaceVulnerability("GHSA-move", "pypi", "requests"),
			syncReplaceVulnerability("GHSA-other", "npm", "other"),
		},
	}); err != nil {
		t.Fatalf("seed full sync: %v", err)
	}
	if since != "" {
		if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, since); err != nil {
			t.Fatalf("seed last sync: %v", err)
		}
	}
}

func localVulnerabilityRowKeys(t *testing.T, store *Store) []string {
	t.Helper()
	rows, err := store.DB().QueryContext(context.Background(), `SELECT row_key FROM vulnerabilities_local ORDER BY row_key`)
	if err != nil {
		t.Fatalf("query local vulnerability rows: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatalf("scan local vulnerability row: %v", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate local vulnerability rows: %v", err)
	}
	return keys
}

// newSyncReplaceServer serves the given pages in order, keyed by the
// vulnerabilities_cursor the client echoes; a nil page answers 500.
func newSyncReplaceServer(t *testing.T, pages map[string]*syncResponse) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, ok := pages[r.URL.Query().Get("vulnerabilities_cursor")]
		if !ok || page == nil {
			http.Error(w, "page unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(page); err != nil {
			t.Errorf("encode sync page: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func truncatedSyncReplacePage(complete bool, cursor string, vulnerabilities ...syncVulnerability) *syncResponse {
	return &syncResponse{
		SyncedAt:                      "2026-05-30T10:00:00Z",
		Vulnerabilities:               vulnerabilities,
		Truncated:                     true,
		NextCursor:                    &syncCursor{VulnerabilitiesCursor: cursor, MaliciousDone: true, ReputationDone: true, LifecycleDone: true},
		VulnerabilityAffectedComplete: complete,
	}
}

func finalSyncReplacePage(complete bool, vulnerabilities ...syncVulnerability) *syncResponse {
	return &syncResponse{
		SyncedAt:                      "2026-05-30T10:00:00Z",
		Vulnerabilities:               vulnerabilities,
		VulnerabilityAffectedComplete: complete,
	}
}

// TestDeltaSyncReplacesAffectedPackagesOfChangedVulnerabilities covers a
// server-side coverage move (GHSA-move: npm left-pad -> npm right-pad). A delta
// page with a since window that the server marks with
// vulnerability_affected_complete carries every vulnerability on it with its
// complete current affected set, so the client drops the moved-away package in
// that page's transaction -- on a single page and on every flagged page of a
// multi-page delta. Unflagged pages (older servers, full exports, legacy
// paging) stay upsert-only.
func TestDeltaSyncReplacesAffectedPackagesOfChangedVulnerabilities(t *testing.T) {
	t.Parallel()

	const since = "2026-05-30T09:00:00Z"
	moved := []syncVulnerability{
		syncReplaceVulnerability("GHSA-move", "npm", "right-pad"),
		syncReplaceVulnerability("GHSA-move", "pypi", "requests"),
	}
	otherMoved := syncReplaceVulnerability("GHSA-other", "npm", "other-new")
	replaced := []string{"GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other"}
	upserted := []string{"GHSA-move|npm|left-pad", "GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other"}
	tests := []struct {
		name       string
		since      string
		pages      map[string]*syncResponse
		ecosystems []string
		wantErr    bool
		want       []string
		// wantSince is the durable since window after the sync; empty means
		// the sync advanced it to the pages' synced_at.
		wantSince string
	}{
		{
			name:  "multi-page delta replaces on every flagged page",
			since: since,
			pages: map[string]*syncResponse{
				"":   truncatedSyncReplacePage(true, "c1", moved...),
				"c1": finalSyncReplacePage(true, otherMoved),
			},
			want: []string{"GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other-new"},
		},
		{
			name:  "multi-page delta replaces only on flagged pages",
			since: since,
			pages: map[string]*syncResponse{
				"":   truncatedSyncReplacePage(true, "c1", moved...),
				"c1": finalSyncReplacePage(false, otherMoved),
			},
			want: []string{"GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other", "GHSA-other|npm|other-new"},
		},
		{
			name:  "older server multi-page delta without the flag stays upsert-only",
			since: since,
			pages: map[string]*syncResponse{
				"":   truncatedSyncReplacePage(false, "c1", moved[0]),
				"c1": finalSyncReplacePage(false, moved[1]),
			},
			want: upserted,
		},
		{
			// The committed first page replaced GHSA-move with the complete
			// set the server delivered; GHSA-other, which the failed page would
			// have carried, keeps every local row, and the since window does
			// not advance, so the next delta repeats the whole sequence.
			name:  "failed multi-page delta keeps every vulnerability no committed page delivered",
			since: since,
			pages: map[string]*syncResponse{
				"":   truncatedSyncReplacePage(true, "c1", moved...),
				"c1": nil,
			},
			wantErr:   true,
			want:      replaced,
			wantSince: since,
		},
		{
			name:  "single complete page with since",
			since: since,
			pages: map[string]*syncResponse{"": finalSyncReplacePage(true, moved...)},
			want:  replaced,
		},
		{
			name:  "single complete page without since stays upsert-only",
			pages: map[string]*syncResponse{"": finalSyncReplacePage(true, moved...)},
			want:  upserted,
		},
		{
			name:  "older server without the completeness flag keeps upsert-only behavior",
			since: since,
			pages: map[string]*syncResponse{"": finalSyncReplacePage(false, moved...)},
			want:  upserted,
		},
		{
			name:  "failed sequence of unflagged pages deletes nothing",
			since: since,
			pages: map[string]*syncResponse{
				"":   truncatedSyncReplacePage(false, "c1", moved[0]),
				"c1": nil,
			},
			wantErr:   true,
			want:      upserted,
			wantSince: since,
		},
		{
			name:       "ecosystem-filtered sync replaces only filtered ecosystems",
			since:      since,
			pages:      map[string]*syncResponse{"": finalSyncReplacePage(true, moved[0])},
			ecosystems: []string{" NPM "},
			want:       replaced,
		},
		{
			name:  "withdrawn vulnerability is deleted, not replaced",
			since: since,
			pages: map[string]*syncResponse{"": finalSyncReplacePage(true, syncVulnerability{
				ID: "GHSA-move", Ecosystem: "npm", Name: "right-pad", Withdrawn: true,
			})},
			want: []string{"GHSA-other|npm|other"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newSQLiteTestStore(t)
			seedSyncReplaceRows(t, store, tt.since)
			server := newSyncReplaceServer(t, tt.pages)

			err := Sync(context.Background(), store, SyncConfig{
				ServerURL:         server.URL,
				Ecosystems:        tt.ecosystems,
				AllowInsecureHTTP: true,
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Sync() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := localVulnerabilityRowKeys(t, store); !slices.Equal(got, tt.want) {
				t.Fatalf("local vulnerability rows = %q, want %q", got, tt.want)
			}
			if tt.wantSince != "" {
				got, err := store.GetSyncMeta(context.Background(), syncMetaKeyLastSync)
				if err != nil || got != tt.wantSince {
					t.Fatalf("last sync after the sequence = %q, %v; want %q", got, err, tt.wantSince)
				}
			}
		})
	}
}

// TestDeltaSyncDropsVulnerabilitiesWithoutAffectedPackages covers an advisory
// that lost every affected package on the server (within the requested
// ecosystems). It has no row to deliver, so a flagged delta page lists its ID
// in vulnerabilities_without_affected and the client drops its local rows in
// the requested ecosystems -- never rows of other ecosystems, never on an
// unflagged page, and never rows the same page delivers for that advisory.
func TestDeltaSyncDropsVulnerabilitiesWithoutAffectedPackages(t *testing.T) {
	t.Parallel()

	const since = "2026-05-30T09:00:00Z"
	withoutAffected := func(page *syncResponse, ids ...string) *syncResponse {
		page.VulnerabilitiesWithoutAffected = ids
		return page
	}
	tests := []struct {
		name       string
		since      string
		pages      map[string]*syncResponse
		ecosystems []string
		want       []string
		// wantReplaced is the AffectedReplaced count the sync reports.
		wantReplaced int64
	}{
		{
			name:         "flagged page drops every local row of the listed advisory",
			since:        since,
			pages:        map[string]*syncResponse{"": withoutAffected(finalSyncReplacePage(true), "GHSA-move")},
			want:         []string{"GHSA-other|npm|other"},
			wantReplaced: 2,
		},
		{
			name:  "flagged pages of a multi-page delta drop the listed advisories",
			since: since,
			pages: map[string]*syncResponse{
				"":   withoutAffected(truncatedSyncReplacePage(true, "c1"), "GHSA-move"),
				"c1": finalSyncReplacePage(true, syncReplaceVulnerability("GHSA-other", "npm", "other-new")),
			},
			want:         []string{"GHSA-other|npm|other-new"},
			wantReplaced: 3,
		},
		{
			name:         "ecosystem-filtered sync drops only rows in its ecosystems",
			since:        since,
			pages:        map[string]*syncResponse{"": withoutAffected(finalSyncReplacePage(true), "GHSA-move")},
			ecosystems:   []string{"npm"},
			want:         []string{"GHSA-move|pypi|requests", "GHSA-other|npm|other"},
			wantReplaced: 1,
		},
		{
			name:  "unflagged page ignores the list",
			since: since,
			pages: map[string]*syncResponse{"": withoutAffected(finalSyncReplacePage(false), "GHSA-move")},
			want:  []string{"GHSA-move|npm|left-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other"},
		},
		{
			name:  "sync without a since window ignores the list",
			pages: map[string]*syncResponse{"": withoutAffected(finalSyncReplacePage(true), "GHSA-move")},
			want:  []string{"GHSA-move|npm|left-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other"},
		},
		{
			name:  "rows the page delivers win over a contradicting list entry",
			since: since,
			pages: map[string]*syncResponse{"": withoutAffected(
				finalSyncReplacePage(true, syncReplaceVulnerability("GHSA-move", "npm", "left-pad")), "GHSA-move", " ",
			)},
			want:         []string{"GHSA-move|npm|left-pad", "GHSA-other|npm|other"},
			wantReplaced: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := newSQLiteTestStore(t)
			seedSyncReplaceRows(t, store, tt.since)
			server := newSyncReplaceServer(t, tt.pages)

			var stats SyncStats
			if err := Sync(context.Background(), store, SyncConfig{
				ServerURL:         server.URL,
				Ecosystems:        tt.ecosystems,
				AllowInsecureHTTP: true,
				Stats:             &stats,
			}); err != nil {
				t.Fatalf("Sync() error = %v", err)
			}
			if got := localVulnerabilityRowKeys(t, store); !slices.Equal(got, tt.want) {
				t.Fatalf("local vulnerability rows = %q, want %q", got, tt.want)
			}
			if stats.AffectedReplaced.Vulnerabilities != tt.wantReplaced {
				t.Fatalf("AffectedReplaced.Vulnerabilities = %d, want %d", stats.AffectedReplaced.Vulnerabilities, tt.wantReplaced)
			}
		})
	}
}

// TestDeltaSyncReplacementUsesCanonicalPackageNames guards the received-row
// bookkeeping against raw server names: rows are stored under the canonical
// package name, so a non-canonical spelling of a kept package must not delete
// its local row.
func TestDeltaSyncReplacementUsesCanonicalPackageNames(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newSQLiteTestStore(t)
	if _, err := applySync(ctx, store, true, &syncResponse{
		SyncedAt:        "2026-05-30T09:00:00Z",
		Vulnerabilities: []syncVulnerability{syncReplaceVulnerability("GHSA-pypi", "pypi", "My.Pkg")},
	}); err != nil {
		t.Fatalf("seed full sync: %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-05-30T09:00:00Z"); err != nil {
		t.Fatalf("seed last sync: %v", err)
	}
	server := newSyncReplaceServer(t, map[string]*syncResponse{
		"": finalSyncReplacePage(true, syncReplaceVulnerability("GHSA-pypi", "pypi", "my_pkg")),
	})
	if err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got, want := localVulnerabilityRowKeys(t, store), []string{"GHSA-pypi|pypi|my-pkg"}; !slices.Equal(got, want) {
		t.Fatalf("local vulnerability rows = %q, want %q", got, want)
	}
}
