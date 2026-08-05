package postgres

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// privacySelectorTypes lists every selector the privacy export accepts. Both
// predicate builders must cover all of them: a selector that falls through to
// the default branch turns a GDPR export request into an error.
var privacySelectorTypes = []string{
	db.PrivacySelectorClientIP,
	db.PrivacySelectorRepoName,
	db.PrivacySelectorAPIKeyID,
	db.PrivacySelectorAPIKeyName,
	db.PrivacySelectorCorrelationID,
}

// TestPrivacyScanLogPredicateCoversEverySelector pins the scan-log side of the
// privacy export. Each selector must produce a parameterised predicate -- an
// inlined value would make the export injectable through a subject identifier.
func TestPrivacyScanLogPredicateCoversEverySelector(t *testing.T) {
	t.Parallel()

	for _, selectorType := range privacySelectorTypes {
		predicate, args, err := privacyScanLogPredicate(db.PrivacyExportSelector{
			Type:  selectorType,
			Value: "subject-value",
		})
		if err != nil {
			t.Fatalf("privacyScanLogPredicate(%s) error = %v", selectorType, err)
		}
		if predicate == "" {
			t.Fatalf("privacyScanLogPredicate(%s) returned an empty predicate", selectorType)
		}
		if len(args) == 0 {
			t.Fatalf("privacyScanLogPredicate(%s) returned no bind arguments", selectorType)
		}
		if !strings.Contains(predicate, "$1") {
			t.Fatalf("privacyScanLogPredicate(%s) = %q, want a bound parameter", selectorType, predicate)
		}
		if strings.Contains(predicate, "subject-value") {
			t.Fatalf("privacyScanLogPredicate(%s) inlined the subject value: %q", selectorType, predicate)
		}
	}
}

// TestPrivacyAdminAuditPredicateCoversEverySelector is the audit-log counterpart.
// The audit table keeps some identifiers in a JSON details column, so each
// selector has to search both the column and the JSON field -- missing one would
// return an incomplete export while still reporting success.
func TestPrivacyAdminAuditPredicateCoversEverySelector(t *testing.T) {
	t.Parallel()

	for _, selectorType := range privacySelectorTypes {
		predicate, args, err := privacyAdminAuditPredicate(db.PrivacyExportSelector{
			Type:  selectorType,
			Value: "subject-value",
		})
		if err != nil {
			t.Fatalf("privacyAdminAuditPredicate(%s) error = %v", selectorType, err)
		}
		if len(args) == 0 {
			t.Fatalf("privacyAdminAuditPredicate(%s) returned no bind arguments", selectorType)
		}
		if !strings.Contains(predicate, "$1") {
			t.Fatalf("privacyAdminAuditPredicate(%s) = %q, want a bound parameter", selectorType, predicate)
		}
		if strings.Contains(predicate, "subject-value") {
			t.Fatalf("privacyAdminAuditPredicate(%s) inlined the subject value: %q", selectorType, predicate)
		}
		// Every selector but the IP one is stored inside the details JSON.
		if selectorType != db.PrivacySelectorClientIP && !strings.Contains(predicate, "details->>") {
			t.Fatalf("privacyAdminAuditPredicate(%s) = %q, want the details column searched too",
				selectorType, predicate)
		}
	}
}

// TestPrivacyPredicatesRejectUnknownSelectors keeps an unrecognised selector from
// producing an empty predicate, which would export every row instead of none.
func TestPrivacyPredicatesRejectUnknownSelectors(t *testing.T) {
	t.Parallel()

	selector := db.PrivacyExportSelector{Type: "not-a-selector", Value: "x"}

	if predicate, _, err := privacyScanLogPredicate(selector); err == nil {
		t.Fatalf("privacyScanLogPredicate(unknown) = %q, nil; want an error", predicate)
	}
	if predicate, _, err := privacyAdminAuditPredicate(selector); err == nil {
		t.Fatalf("privacyAdminAuditPredicate(unknown) = %q, nil; want an error", predicate)
	}
}

// TestPackageSearchCollectorLimitSaturatesInsteadOfOverflowing mirrors the SQLite
// guard: each collector fetches limit+offset rows so the merged, re-sorted set
// can still serve a later page, and that sum must never wrap negative.
func TestPackageSearchCollectorLimitSaturatesInsteadOfOverflowing(t *testing.T) {
	t.Parallel()

	maxInt := int(^uint(0) >> 1)

	if got := packageSearchCollectorLimit(50, 0); got != 50 {
		t.Errorf("packageSearchCollectorLimit(50, 0) = %d, want 50", got)
	}
	if got := packageSearchCollectorLimit(50, -5); got != 50 {
		t.Errorf("packageSearchCollectorLimit(50, -5) = %d, want 50 for a negative offset", got)
	}
	if got := packageSearchCollectorLimit(50, 100); got != 150 {
		t.Errorf("packageSearchCollectorLimit(50, 100) = %d, want 150", got)
	}
	if got := packageSearchCollectorLimit(maxInt, 1); got != maxInt {
		t.Errorf("packageSearchCollectorLimit(maxInt, 1) = %d, want saturation at maxInt", got)
	}
	if got := packageSearchCollectorLimit(maxInt-1, 10); got != maxInt {
		t.Errorf("packageSearchCollectorLimit(maxInt-1, 10) = %d, want saturation at maxInt", got)
	}
}

// TestMergePackageSearchResultMapsAccumulatesOverlappingRows covers the merge of
// the per-source search collectors. A package found by two collectors must have
// its counts added and its identifier lists unioned, not overwritten -- otherwise
// the search hides findings that a second source contributed.
func TestMergePackageSearchResultMapsAccumulatesOverlappingRows(t *testing.T) {
	t.Parallel()

	dst := map[string]*db.PackageSearchResult{
		"npm|left-pad": {
			Ecosystem:          "npm",
			Name:               "left-pad",
			FindingsCount:      1,
			VulnerabilityCount: 1,
			VulnerabilityIDs:   "GHSA-1",
			Sources:            "osv",
			FindingTypes:       "vulnerability",
		},
	}
	src := map[string]*db.PackageSearchResult{
		"npm|left-pad": {
			Ecosystem:          "npm",
			Name:               "left-pad",
			FindingsCount:      2,
			VulnerabilityCount: 1,
			VulnerabilityIDs:   "GHSA-2",
			Sources:            "ghsa",
			FindingTypes:       "malicious",
		},
	}

	mergePackageSearchResultMaps(dst, src)

	merged := dst["npm|left-pad"]
	if merged.FindingsCount != 3 {
		t.Errorf("FindingsCount = %d, want the two collectors added up", merged.FindingsCount)
	}
	if merged.VulnerabilityCount != 2 {
		t.Errorf("VulnerabilityCount = %d, want 2", merged.VulnerabilityCount)
	}
	for _, want := range []string{"GHSA-1", "GHSA-2"} {
		if !strings.Contains(merged.VulnerabilityIDs, want) {
			t.Errorf("VulnerabilityIDs = %q, want %s retained", merged.VulnerabilityIDs, want)
		}
	}
	if !strings.Contains(merged.Sources, "osv") || !strings.Contains(merged.Sources, "ghsa") {
		t.Errorf("Sources = %q, want both collectors' sources", merged.Sources)
	}
	if !strings.Contains(merged.FindingTypes, "vulnerability") || !strings.Contains(merged.FindingTypes, "malicious") {
		t.Errorf("FindingTypes = %q, want both finding types", merged.FindingTypes)
	}
}

// TestMergePackageSearchResultMapsClonesNewEntries guards against the merged map
// aliasing the source map: a later mutation of one would otherwise silently
// change the other collector's result.
func TestMergePackageSearchResultMapsClonesNewEntries(t *testing.T) {
	t.Parallel()

	source := &db.PackageSearchResult{Ecosystem: "npm", Name: "fresh", FindingsCount: 1}
	dst := map[string]*db.PackageSearchResult{}

	mergePackageSearchResultMaps(dst, map[string]*db.PackageSearchResult{"npm|fresh": source})

	merged, ok := dst["npm|fresh"]
	if !ok {
		t.Fatal("merge dropped a package that only one collector found")
	}
	if merged == source {
		t.Fatal("merged entry aliases the source result")
	}
	source.FindingsCount = 99
	if merged.FindingsCount != 1 {
		t.Fatalf("FindingsCount = %d, want the clone to stay at 1", merged.FindingsCount)
	}
}

// TestMergePackageSearchResultMapsSkipsNilResults keeps a nil row out of the
// merged map, where it would panic on the next access.
func TestMergePackageSearchResultMapsSkipsNilResults(t *testing.T) {
	t.Parallel()

	dst := map[string]*db.PackageSearchResult{}
	mergePackageSearchResultMaps(dst, map[string]*db.PackageSearchResult{"npm|nil": nil})

	if len(dst) != 0 {
		t.Fatalf("merged map holds %d entries, want the nil result skipped", len(dst))
	}
}

// TestVulnerabilityReferenceSourceFallsBackToTheSoleSource covers the attribution
// of advisory references. A reference without its own source can only be
// attributed when the advisory has exactly one -- guessing with several would put
// the wrong feed name on a link in the report.
func TestVulnerabilityReferenceSourceFallsBackToTheSoleSource(t *testing.T) {
	t.Parallel()

	single := &db.Vulnerability{Sources: []db.VulnerabilitySource{{Source: "osv"}}}
	multiple := &db.Vulnerability{Sources: []db.VulnerabilitySource{{Source: "osv"}, {Source: "ghsa"}}}

	if got := vulnerabilityReferenceSource(single, db.VulnerabilityReference{Source: " ghsa "}); got != "ghsa" {
		t.Errorf("explicit source = %q, want the trimmed ghsa", got)
	}
	if got := vulnerabilityReferenceSource(single, db.VulnerabilityReference{}); got != "osv" {
		t.Errorf("fallback with one source = %q, want osv", got)
	}
	if got := vulnerabilityReferenceSource(multiple, db.VulnerabilityReference{}); got != "" {
		t.Errorf("fallback with two sources = %q, want no attribution", got)
	}
	if got := vulnerabilityReferenceSource(&db.Vulnerability{}, db.VulnerabilityReference{}); got != "" {
		t.Errorf("fallback without sources = %q, want no attribution", got)
	}
}
