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
// server-side coverage move (GHSA-move: npm left-pad -> npm right-pad). Only a
// single-page delta with a since window that the server marks with
// vulnerability_affected_complete lets the client drop the moved-away package.
// Every other sequence stays upsert-only: pages of a multi-page delta are
// separate statements, so a vulnerability changed between them can arrive
// incomplete, even when a (buggy or older) server flags every page.
func TestDeltaSyncReplacesAffectedPackagesOfChangedVulnerabilities(t *testing.T) {
	t.Parallel()

	const since = "2026-05-30T09:00:00Z"
	moved := []syncVulnerability{
		syncReplaceVulnerability("GHSA-move", "npm", "right-pad"),
		syncReplaceVulnerability("GHSA-move", "pypi", "requests"),
	}
	replaced := []string{"GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other"}
	upserted := []string{"GHSA-move|npm|left-pad", "GHSA-move|npm|right-pad", "GHSA-move|pypi|requests", "GHSA-other|npm|other"}
	tests := []struct {
		name       string
		since      string
		pages      map[string]*syncResponse
		ecosystems []string
		wantErr    bool
		want       []string
	}{
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
			name:  "multi-page sequence stays upsert-only even when every page is flagged",
			since: since,
			pages: map[string]*syncResponse{
				"":   truncatedSyncReplacePage(true, "c1", moved[0]),
				"c1": finalSyncReplacePage(true, moved[1]),
			},
			want: upserted,
		},
		{
			name:  "older server without the completeness flag keeps upsert-only behavior",
			since: since,
			pages: map[string]*syncResponse{"": finalSyncReplacePage(false, moved...)},
			want:  upserted,
		},
		{
			name:  "failed sequence deletes nothing",
			since: since,
			pages: map[string]*syncResponse{
				"":   truncatedSyncReplacePage(true, "c1", moved[0]),
				"c1": nil,
			},
			wantErr: true,
			want:    upserted,
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
