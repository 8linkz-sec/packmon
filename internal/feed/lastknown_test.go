package feed

import "testing"

// TestParseLastKnownAffectedClosureClosesOpenEndedRanges covers the reason the
// function exists. GHSA/OSV sometimes record a range's upper bound only in
// `database_specific.last_known_affected_version_range`; without closing the
// range there, every later release of the package would keep matching as
// affected. The two operators map to different OSV events, and mixing them up
// would shift the boundary by one release.
func TestParseLastKnownAffectedClosureClosesOpenEndedRanges(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		expr             string
		wantFixed        string
		wantLastAffected string
	}{
		// "< X" means X is already fixed.
		{expr: "< 4.1.3", wantFixed: "4.1.3"},
		{expr: "<4.1.3", wantFixed: "4.1.3"},
		{expr: "   <   4.1.3   ", wantFixed: "4.1.3"},
		// "<= X" means X is the last affected release, not the fix.
		{expr: "<= 2.0.0", wantLastAffected: "2.0.0"},
		{expr: "<=2.0.0", wantLastAffected: "2.0.0"},
	} {
		fixed, lastAffected, ok := ParseLastKnownAffectedClosure(tc.expr)
		if !ok {
			t.Errorf("ParseLastKnownAffectedClosure(%q) reported no closure", tc.expr)
			continue
		}
		if fixed != tc.wantFixed {
			t.Errorf("ParseLastKnownAffectedClosure(%q) fixed = %q, want %q", tc.expr, fixed, tc.wantFixed)
		}
		if lastAffected != tc.wantLastAffected {
			t.Errorf("ParseLastKnownAffectedClosure(%q) lastAffected = %q, want %q",
				tc.expr, lastAffected, tc.wantLastAffected)
		}
	}
}

// TestParseLastKnownAffectedClosurePrefersTheInclusiveOperator guards the
// operator ordering. "<=" starts with "<", so a naive prefix check would classify
// "<= 2.0.0" as a fix at 2.0.0 and wrongly declare the last affected release
// clean.
func TestParseLastKnownAffectedClosurePrefersTheInclusiveOperator(t *testing.T) {
	t.Parallel()

	fixed, lastAffected, ok := ParseLastKnownAffectedClosure("<= 2.0.0")
	if !ok {
		t.Fatal("ParseLastKnownAffectedClosure reported no closure")
	}
	if fixed != "" {
		t.Fatalf("fixed = %q, want the inclusive bound to produce no fix", fixed)
	}
	if lastAffected != "2.0.0" {
		t.Fatalf("lastAffected = %q, want 2.0.0", lastAffected)
	}
}

// TestParseLastKnownAffectedClosureReadsCommaSeparatedConstraints covers the
// multi-constraint form. Only the upper bound closes the range; a lower bound
// alone carries no closure information.
func TestParseLastKnownAffectedClosureReadsCommaSeparatedConstraints(t *testing.T) {
	t.Parallel()

	fixed, lastAffected, ok := ParseLastKnownAffectedClosure(">= 1.0.0, < 4.1.3")
	if !ok {
		t.Fatal("ParseLastKnownAffectedClosure reported no closure for a bounded range")
	}
	if fixed != "4.1.3" || lastAffected != "" {
		t.Fatalf("fixed, lastAffected = %q, %q; want 4.1.3, \"\"", fixed, lastAffected)
	}

	if _, _, ok := ParseLastKnownAffectedClosure(">= 1.0.0"); ok {
		t.Error("a lower bound alone was treated as a closure")
	}
}

// TestParseLastKnownAffectedClosureStripsQuotingArtefacts covers the cleanup of
// values that arrive wrapped in backticks or quotes from advisory prose. A
// version string of "`4.1.3`" would never compare equal to a real version.
func TestParseLastKnownAffectedClosureStripsQuotingArtefacts(t *testing.T) {
	t.Parallel()

	for _, expr := range []string{"< `4.1.3`", `< "4.1.3"`, "< '4.1.3'"} {
		fixed, _, ok := ParseLastKnownAffectedClosure(expr)
		if !ok {
			t.Errorf("ParseLastKnownAffectedClosure(%q) reported no closure", expr)
			continue
		}
		if fixed != "4.1.3" {
			t.Errorf("ParseLastKnownAffectedClosure(%q) fixed = %q, want the bare version", expr, fixed)
		}
	}
}

// TestParseLastKnownAffectedClosureRejectsUnusableInput keeps a malformed
// expression from producing an empty boundary that would close a range at
// version "" and match nothing.
func TestParseLastKnownAffectedClosureRejectsUnusableInput(t *testing.T) {
	t.Parallel()

	for _, expr := range []string{"", "   ", "not a constraint", "<", "<=", "< ", "<= ``", "> 1.0.0"} {
		fixed, lastAffected, ok := ParseLastKnownAffectedClosure(expr)
		if ok {
			t.Errorf("ParseLastKnownAffectedClosure(%q) = %q, %q, true; want no closure",
				expr, fixed, lastAffected)
		}
	}
}

// TestIsSyntheticStatusHidesPipelineRows covers the filter that keeps
// maintenance rows out of the feed list. The alias-severity propagation row is
// recorded for observability; shown as a feed it would read as one that has only
// ever synced a single entry.
func TestIsSyntheticStatusHidesPipelineRows(t *testing.T) {
	t.Parallel()

	if !IsSyntheticStatus(AliasSeverityPropagationStatusName) {
		t.Errorf("IsSyntheticStatus(%q) = false, want it hidden", AliasSeverityPropagationStatusName)
	}
	for _, name := range []string{"osv", "ghsa", "nvd", "", "alias-severity-propagation-2"} {
		if IsSyntheticStatus(name) {
			t.Errorf("IsSyntheticStatus(%q) = true, want a real feed", name)
		}
	}
}
