package version

import "testing"

// brace-expansion is the case that exposed this: the advisory lists a separate
// affected range per major line, each with its own fix. Reporting the lowest fix
// across all of them told a user on 5.0.7 that the fix was ">= 1.1.18" -- a
// version far below what they already had, which reads as "you are fine".
const braceExpansionRanges = `[
  {"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.1.18"}]},
  {"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"fixed":"2.0.2"}]},
  {"type":"ECOSYSTEM","events":[{"introduced":"3.0.0"},{"fixed":"3.0.1"}]},
  {"type":"ECOSYSTEM","events":[{"introduced":"4.0.0"},{"fixed":"4.0.1"}]},
  {"type":"ECOSYSTEM","events":[{"introduced":"5.0.0"},{"fixed":"5.0.9"}]}
]`

// TestFixedVersionForInstalledPicksTheMatchingRange is the core correction: the
// fix reported to a user must come from the range their version actually falls
// into, not from the lowest range in the advisory.
func TestFixedVersionForInstalledPicksTheMatchingRange(t *testing.T) {
	t.Parallel()

	for installed, want := range map[string]string{
		"5.0.7": "5.0.9",
		"5.0.8": "5.0.9",
		"4.0.0": "4.0.1",
		"2.0.1": "2.0.2",
		"1.0.0": "1.1.18",
	} {
		if got := ExtractFixedVersionFor(installed, braceExpansionRanges, "npm"); got != want {
			t.Errorf("ExtractFixedVersionFor(%q) = %q, want %q", installed, got, want)
		}
	}
}

// TestFixedVersionConstraintForInstalledNeverUndercutsTheInstalledVersion is the
// user-visible guarantee. A constraint at or below the installed version is
// worse than none: it invites the reader to conclude they are already patched.
func TestFixedVersionConstraintForInstalledNeverUndercutsTheInstalledVersion(t *testing.T) {
	t.Parallel()

	got := ExtractFixedVersionConstraintFor("5.0.7", braceExpansionRanges, "npm")
	if got != ">= 5.0.9" {
		t.Fatalf("ExtractFixedVersionConstraintFor(5.0.7) = %q, want %q", got, ">= 5.0.9")
	}
}

// TestFixedVersionForInstalledFallsBackWhenNoRangeMatches keeps the previous
// behaviour for advisories whose ranges do not cover the installed version, so
// a finding never loses its fix hint entirely.
func TestFixedVersionForInstalledFallsBackWhenNoRangeMatches(t *testing.T) {
	t.Parallel()

	if got := ExtractFixedVersionFor("9.9.9", braceExpansionRanges, "npm"); got != "1.1.18" {
		t.Fatalf("ExtractFixedVersionFor(unmatched) = %q, want the lowest fix as fallback", got)
	}
	if got := ExtractFixedVersionFor("", braceExpansionRanges, "npm"); got != "1.1.18" {
		t.Fatalf("ExtractFixedVersionFor(empty installed) = %q, want the lowest fix as fallback", got)
	}
}

// TestFixedVersionForInstalledHandlesSingleRangeAdvisories covers the common
// case, where the version-aware lookup must agree with the old behaviour.
func TestFixedVersionForInstalledHandlesSingleRangeAdvisories(t *testing.T) {
	t.Parallel()

	const single = `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"7.29.0"}]}]`
	if got := ExtractFixedVersionFor("7.28.0", single, "npm"); got != "7.29.0" {
		t.Fatalf("ExtractFixedVersionFor(single range) = %q, want 7.29.0", got)
	}
}

// TestFixedVersionForInstalledToleratesMissingRanges keeps the empty cases quiet.
func TestFixedVersionForInstalledToleratesMissingRanges(t *testing.T) {
	t.Parallel()

	for _, ranges := range []string{"", "null", "[]", "not json"} {
		if got := ExtractFixedVersionFor("1.0.0", ranges, "npm"); got != "" {
			t.Errorf("ExtractFixedVersionFor(%q) = %q, want empty", ranges, got)
		}
		if got := ExtractFixedVersionConstraintFor("1.0.0", ranges, "npm"); got != "" {
			t.Errorf("ExtractFixedVersionConstraintFor(%q) = %q, want empty", ranges, got)
		}
	}
}
