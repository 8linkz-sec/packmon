package postgres

import (
	"encoding/json"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
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

func TestFinishPackageSearchResultsFormatsSortsAndLimits(t *testing.T) {
	t.Parallel()

	results := map[string]*db.PackageSearchResult{
		"npm\x00zlib\x00": {
			Ecosystem:     "npm",
			Name:          "zlib",
			FindingsCount: 1,
			Sources:       "osv",
			FindingTypes:  "vulnerability",
		},
		"npm\x00left-pad\x00": {
			Ecosystem:          "npm",
			Name:               "left-pad",
			FindingsCount:      7,
			VulnerabilityCount: 7,
			VulnerabilityIDs:   "GHSA-003, GHSA-001, GHSA-002, GHSA-004, GHSA-005, GHSA-006, GHSA-007",
			Sources:            "osv, ghsa, osv",
			FindingTypes:       "vulnerability, malicious, vulnerability",
		},
		"pypi\x00django\x003.2.25": {
			Ecosystem:     "pypi",
			Name:          "django",
			Version:       "3.2.25",
			FindingsCount: 1,
			Sources:       "endoflife.date",
			FindingTypes:  "supply_chain_risk",
		},
	}

	got := finishPackageSearchResults(results, 2, 0)
	if len(got) != 2 {
		t.Fatalf("len(finishPackageSearchResults) = %d, want 2: %+v", len(got), got)
	}
	if got[0].Ecosystem != "pypi" || got[0].Name != "django" || got[0].Version != "3.2.25" {
		t.Fatalf("got[0] = %+v, want django first", got[0])
	}
	if got[1].Ecosystem != "npm" || got[1].Name != "left-pad" {
		t.Fatalf("got[1] = %+v, want left-pad second", got[1])
	}
	if got[1].VulnerabilityIDs != "GHSA-001, GHSA-002, GHSA-003, GHSA-004, GHSA-005, +2 more" {
		t.Fatalf("left-pad vulnerability preview = %q", got[1].VulnerabilityIDs)
	}
	if got[1].Sources != "ghsa, osv" {
		t.Fatalf("left-pad sources = %q, want sorted unique sources", got[1].Sources)
	}
	if got[1].FindingTypes != "malicious, vulnerability" {
		t.Fatalf("left-pad finding types = %q, want sorted unique finding types", got[1].FindingTypes)
	}

	got = finishPackageSearchResults(results, 1, 1)
	if len(got) != 1 {
		t.Fatalf("len(finishPackageSearchResults offset) = %d, want 1: %+v", len(got), got)
	}
	if got[0].Ecosystem != "npm" || got[0].Name != "left-pad" {
		t.Fatalf("finishPackageSearchResults offset result = %+v, want left-pad", got[0])
	}
}
