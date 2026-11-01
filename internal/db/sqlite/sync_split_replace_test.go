package sqlite

import (
	"context"
	"slices"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// splitSyncReplacePage returns a page of the advisory the server split over
// several pages (vulnerability_split_advisory); start marks the page that
// started the split, and complete the last page of a split that delivered
// every current affected row of it.
func splitSyncReplacePage(advisory string, start, complete bool, cursor string, vulnerabilities ...syncVulnerability) *syncResponse {
	page := truncatedSyncReplacePage(false, cursor, vulnerabilities...)
	page.VulnerabilitySplitAdvisory = advisory
	page.VulnerabilitySplitStart = start
	page.VulnerabilitySplitComplete = complete
	return page
}

// TestDeltaSyncReplacesASplitAdvisoryOnItsCompleteLastPage covers an advisory
// whose rows alone exceed the server's page byte budget, so the server splits
// it over several unflagged pages. The client collects the rows the split
// pages of one sequence delivered for it and, when the last split page
// reports the split complete, drops its local rows (within the requested
// ecosystems) that no split page delivered, in that page's transaction. It
// replaces nothing unless it received the page that started the split
// (marked as the start and not requested with an advisory row cursor) and
// every later page of the split, each naming the advisory: a split that an
// older server started or continued during a rolling upgrade, a split
// without completeness, an interrupted sequence, or a split page that
// carries another advisory's row stays upsert-only.
func TestDeltaSyncReplacesASplitAdvisoryOnItsCompleteLastPage(t *testing.T) {
	t.Parallel()

	const since = "2026-05-30T09:00:00Z"
	rightPad := syncReplaceVulnerability("GHSA-move", "npm", "right-pad")
	requests := syncReplaceVulnerability("GHSA-move", "pypi", "requests")
	otherNew := syncReplaceVulnerability("GHSA-other", "npm", "other-new")
	// Real advisory row cursors, as a server returns them while it splits
	// GHSA-move.
	rowCursor1 := db.EncodeSyncAdvisoryRowCursor("GHSA-move", "npm", "right-pad")
	rowCursor2 := db.EncodeSyncAdvisoryRowCursor("GHSA-move", "pypi", "requests")
	rowCursor3 := db.EncodeSyncAdvisoryRowCursor("GHSA-move", "pypi", "zz-last")
	upserted := []string{"GHSA-move|npm|left-pad", "GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other"}
	replaced := []string{"GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other"}
	tests := []struct {
		name       string
		since      string
		pages      map[string]*syncResponse
		ecosystems []string
		wantErr    bool
		want       []string
		wantSince  string
	}{
		{
			name:  "complete split replaces the split advisory only",
			since: since,
			pages: map[string]*syncResponse{
				"":         splitSyncReplacePage("GHSA-move", true, false, rowCursor1, rightPad),
				rowCursor1: splitSyncReplacePage("GHSA-move", false, true, "c2", requests),
				"c2":       finalSyncReplacePage(false),
			},
			want: replaced,
		},
		{
			name:  "complete split whose last page holds no row",
			since: since,
			pages: map[string]*syncResponse{
				"":         splitSyncReplacePage("GHSA-move", true, false, rowCursor1, rightPad),
				rowCursor1: splitSyncReplacePage("GHSA-move", false, false, rowCursor2, requests),
				rowCursor2: splitSyncReplacePage("GHSA-move", false, true, "c3"),
				"c3":       finalSyncReplacePage(false),
			},
			want: replaced,
		},
		{
			name:  "consecutive splits replace each advisory with its own rows",
			since: since,
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, false, "c1", rightPad),
				"c1": splitSyncReplacePage("GHSA-move", false, true, "c2", requests),
				"c2": splitSyncReplacePage("GHSA-other", true, false, "c3", otherNew),
				"c3": splitSyncReplacePage("GHSA-other", false, true, "c4"),
				"c4": finalSyncReplacePage(false),
			},
			want: []string{"GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other-new"},
		},
		{
			name:  "split without completeness stays upsert-only",
			since: since,
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, false, "c1", rightPad),
				"c1": splitSyncReplacePage("GHSA-move", false, false, "c2", requests),
				"c2": finalSyncReplacePage(false),
			},
			want: upserted,
		},
		{
			// The rows of the committed first split page stay; nothing is
			// dropped and the since window does not advance, so the next delta
			// delivers the advisory again.
			name:  "interrupted split deletes nothing",
			since: since,
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, false, "c1", rightPad),
				"c1": nil,
			},
			wantErr:   true,
			want:      upserted,
			wantSince: since,
		},
		{
			// An older server started the split without markers; after an
			// upgrade between two requests, the new server continues and
			// completes it. The client never saw the start, so the rows of
			// the first page would be missing from its collection.
			name:  "split an older server started is not replaced",
			since: since,
			pages: map[string]*syncResponse{
				"":         truncatedSyncReplacePage(false, rowCursor1, rightPad),
				rowCursor1: splitSyncReplacePage("GHSA-move", false, false, rowCursor2, requests),
				rowCursor2: splitSyncReplacePage("GHSA-move", false, true, "c3"),
				"c3":       finalSyncReplacePage(false),
			},
			want: upserted,
		},
		{
			// new -> old -> new: the older server's page in the middle carries
			// no marker and ends the split on the client.
			name:  "split an older server continued mid-way is not replaced",
			since: since,
			pages: map[string]*syncResponse{
				"":         splitSyncReplacePage("GHSA-move", true, false, rowCursor1, rightPad),
				rowCursor1: truncatedSyncReplacePage(false, rowCursor2, requests),
				rowCursor2: splitSyncReplacePage("GHSA-move", false, false, rowCursor3),
				rowCursor3: splitSyncReplacePage("GHSA-move", false, true, "c4"),
				"c4":       finalSyncReplacePage(false),
			},
			want: upserted,
		},
		{
			// A page requested with an advisory row cursor continues a split
			// and can never start one, whatever it claims.
			name:  "start marker on a page requested with an advisory row cursor is ignored",
			since: since,
			pages: map[string]*syncResponse{
				"":         truncatedSyncReplacePage(false, rowCursor1, rightPad),
				rowCursor1: splitSyncReplacePage("GHSA-move", true, false, rowCursor2, requests),
				rowCursor2: splitSyncReplacePage("GHSA-move", false, true, "c3"),
				"c3":       finalSyncReplacePage(false),
			},
			want: upserted,
		},
		{
			name:  "second start marker of the same split replaces nothing",
			since: since,
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, false, "c1", rightPad),
				"c1": splitSyncReplacePage("GHSA-move", true, false, "c2", requests),
				"c2": splitSyncReplacePage("GHSA-move", false, true, "c3"),
				"c3": finalSyncReplacePage(false),
			},
			want: upserted,
		},
		{
			name:  "complete marker on the start page replaces nothing",
			since: since,
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, true, "c1", rightPad, requests),
				"c1": finalSyncReplacePage(false),
			},
			want: upserted,
		},
		{
			name:  "complete marker of another advisory replaces nothing",
			since: since,
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, false, "c1", rightPad),
				"c1": splitSyncReplacePage("GHSA-other", false, true, "c2", requests),
				"c2": finalSyncReplacePage(false),
			},
			want: upserted,
		},
		{
			name:  "split page carrying another advisory's row replaces nothing",
			since: since,
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, false, "c1", rightPad),
				"c1": splitSyncReplacePage("GHSA-move", false, true, "c2", requests, otherNew),
				"c2": finalSyncReplacePage(false),
			},
			want: []string{"GHSA-move|npm|left-pad", "GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other", "GHSA-other|npm|other-new"},
		},
		{
			name:       "ecosystem-filtered split replaces only filtered ecosystems",
			since:      since,
			ecosystems: []string{" NPM "},
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, false, "c1", rightPad),
				"c1": splitSyncReplacePage("GHSA-move", false, true, "c2"),
				"c2": finalSyncReplacePage(false),
			},
			want: replaced,
		},
		{
			name: "split without since stays upsert-only",
			pages: map[string]*syncResponse{
				"":   splitSyncReplacePage("GHSA-move", true, false, "c1", rightPad),
				"c1": splitSyncReplacePage("GHSA-move", false, true, "c2", requests),
				"c2": finalSyncReplacePage(false),
			},
			want: upserted,
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

// TestSyncSplitAdvisoryReplacementCountsDroppedRows reports the rows a
// complete split dropped as replaced affected rows, not as removals.
func TestSyncSplitAdvisoryReplacementCountsDroppedRows(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	seedSyncReplaceRows(t, store, "2026-05-30T09:00:00Z")
	server := newSyncReplaceServer(t, map[string]*syncResponse{
		"":   splitSyncReplacePage("GHSA-move", true, false, "c1", syncReplaceVulnerability("GHSA-move", "npm", "right-pad")),
		"c1": splitSyncReplacePage("GHSA-move", false, true, "c2"),
		"c2": finalSyncReplacePage(false),
	})
	var stats SyncStats
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true, Stats: &stats}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if stats.AffectedReplaced.Vulnerabilities != 2 || stats.AnyRemoved() {
		t.Fatalf("stats = %+v, want two replaced affected rows (npm left-pad, pypi requests) and no removals", stats)
	}
}
