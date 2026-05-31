package postgres

import (
	"encoding/json"
	"testing"

	"github.com/8linkz/packmon/internal/db"
)

func TestStoreHelpersNormalizeValues(t *testing.T) {
	t.Parallel()

	if got := normalizeJSON(nil, nil); got != nil {
		t.Fatalf("normalizeJSON(nil, nil) = %#v, want nil", got)
	}
	if got := string(normalizeJSON(nil, []byte("[]")).([]byte)); got != "[]" {
		t.Fatalf("normalizeJSON(nil, fallback) = %q, want []", got)
	}
	raw := json.RawMessage(`{"ok":true}`)
	if got := string(normalizeJSON(raw, []byte("[]")).([]byte)); got != `{"ok":true}` {
		t.Fatalf("normalizeJSON(raw) = %q", got)
	}

	if got := nullableString("  "); got != nil {
		t.Fatalf("nullableString(blank) = %#v, want nil", got)
	}
	if got := nullableString(" value "); got != " value " {
		t.Fatalf("nullableString(value) = %#v, want original string", got)
	}
}

func TestStoreHelpersClampAndCSV(t *testing.T) {
	t.Parallel()

	if got := clampLimit(0, 50, 100); got != 50 {
		t.Fatalf("clampLimit(default) = %d, want 50", got)
	}
	if got := clampLimit(250, 50, 100); got != 100 {
		t.Fatalf("clampLimit(max) = %d, want 100", got)
	}
	if got := clampLimit(25, 50, 100); got != 25 {
		t.Fatalf("clampLimit(pass through) = %d, want 25", got)
	}

	if got := mergeCSV("osv, ghsa", "ghsa, vulncheck, "); got != "ghsa, osv, vulncheck" {
		t.Fatalf("mergeCSV() = %q, want sorted unique CSV", got)
	}
	if got := joinSortedCSV("vulncheck, osv, osv, ghsa"); got != "ghsa, osv, vulncheck" {
		t.Fatalf("joinSortedCSV() = %q, want sorted unique CSV", got)
	}
	if got := joinSortedCSV(""); got != "" {
		t.Fatalf("joinSortedCSV(empty) = %q, want empty", got)
	}
}

func TestSortSearchResultsOrdersByNameThenEcosystem(t *testing.T) {
	t.Parallel()

	results := []db.PackageSearchResult{
		{Name: "zlib", Ecosystem: "npm"},
		{Name: "left-pad", Ecosystem: "pypi"},
		{Name: "left-pad", Ecosystem: "npm"},
	}
	sortSearchResults(results)

	want := []db.PackageSearchResult{
		{Name: "left-pad", Ecosystem: "npm"},
		{Name: "left-pad", Ecosystem: "pypi"},
		{Name: "zlib", Ecosystem: "npm"},
	}
	for i := range want {
		if results[i].Name != want[i].Name || results[i].Ecosystem != want[i].Ecosystem {
			t.Fatalf("results[%d] = %+v, want %+v", i, results[i], want[i])
		}
	}
}
