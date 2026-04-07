package postgres

import "testing"

// ---------------------------------------------------------------------------
// compareVersions
// ---------------------------------------------------------------------------

func TestCompareVersions_BasicComparison(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "major less", a: "1.0.0", b: "2.0.0", want: -1},
		{name: "major greater", a: "2.0.0", b: "1.0.0", want: 1},
		{name: "minor less", a: "1.2.0", b: "1.3.0", want: -1},
		{name: "minor greater", a: "1.3.0", b: "1.2.0", want: 1},
		{name: "patch less", a: "1.2.3", b: "1.2.4", want: -1},
		{name: "patch greater", a: "1.2.4", b: "1.2.3", want: 1},
		{name: "multi digit major", a: "10.0.0", b: "9.0.0", want: 1},
		{name: "multi digit minor", a: "1.20.0", b: "1.9.0", want: 1},
		{name: "multi digit patch", a: "1.0.100", b: "1.0.99", want: 1},
		{name: "large versions", a: "100.200.300", b: "100.200.299", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareVersions_Equal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
	}{
		{name: "simple equal", a: "1.0.0", b: "1.0.0"},
		{name: "two segment equal", a: "1.0", b: "1.0"},
		{name: "single segment equal", a: "5", b: "5"},
		{name: "long equal", a: "1.2.3.4.5", b: "1.2.3.4.5"},
		{name: "prerelease equal", a: "1.0.0-rc1", b: "1.0.0-rc1"},
		{name: "prerelease dotted equal", a: "1.0.0-alpha.1", b: "1.0.0-alpha.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != 0 {
				t.Fatalf("compareVersions(%q, %q) = %d, want 0", tt.a, tt.b, got)
			}
		})
	}
}

func TestCompareVersions_DifferentSegmentCounts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "1.0 vs 1.0.0 equal", a: "1.0", b: "1.0.0", want: 0},
		{name: "1.0.0 vs 1.0 equal", a: "1.0.0", b: "1.0", want: 0},
		{name: "1.0 vs 1.0.1 less", a: "1.0", b: "1.0.1", want: -1},
		{name: "1 vs 1.0.0 equal", a: "1", b: "1.0.0", want: 0},
		{name: "1.0.0.0 vs 1.0.0 equal", a: "1.0.0.0", b: "1.0.0", want: 0},
		{name: "1.0.0.1 vs 1.0.0 greater", a: "1.0.0.1", b: "1.0.0", want: 1},
		{name: "two vs four segments", a: "1.2", b: "1.2.0.0", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareVersions_Prerelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		// Core semver rule: pre-release < release
		{name: "rc less than release", a: "1.0.0-rc1", b: "1.0.0", want: -1},
		{name: "release greater than rc", a: "1.0.0", b: "1.0.0-rc1", want: 1},
		{name: "alpha less than release", a: "1.0.0-alpha", b: "1.0.0", want: -1},
		{name: "beta less than release", a: "1.0.0-beta", b: "1.0.0", want: -1},

		// Pre-release ordering (lexicographic for strings)
		{name: "alpha < beta", a: "1.0.0-alpha", b: "1.0.0-beta", want: -1},
		{name: "beta < rc", a: "1.0.0-beta", b: "1.0.0-rc", want: -1},
		{name: "alpha < rc1", a: "1.0.0-alpha", b: "1.0.0-rc1", want: -1},

		// Numeric pre-release comparison
		{name: "numeric prerelease 1 < 2", a: "1.0.0-1", b: "1.0.0-2", want: -1},
		{name: "numeric prerelease 2 > 1", a: "1.0.0-2", b: "1.0.0-1", want: 1},
		{name: "numeric prerelease 9 < 10", a: "1.0.0-9", b: "1.0.0-10", want: -1},
		{name: "numeric prerelease equal", a: "1.0.0-1", b: "1.0.0-1", want: 0},

		// Semver rule: numeric identifiers sort before string identifiers
		{name: "numeric < string identifier", a: "1.0.0-1", b: "1.0.0-alpha", want: -1},
		{name: "string > numeric identifier", a: "1.0.0-alpha", b: "1.0.0-1", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareVersions_PrereleaseDotted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "alpha.1 < alpha.2", a: "1.0.0-alpha.1", b: "1.0.0-alpha.2", want: -1},
		{name: "alpha.2 > alpha.1", a: "1.0.0-alpha.2", b: "1.0.0-alpha.1", want: 1},
		{name: "alpha.1 == alpha.1", a: "1.0.0-alpha.1", b: "1.0.0-alpha.1", want: 0},
		{name: "alpha.9 < alpha.10", a: "1.0.0-alpha.9", b: "1.0.0-alpha.10", want: -1},
		{name: "alpha < alpha.1 (fewer identifiers)", a: "1.0.0-alpha", b: "1.0.0-alpha.1", want: -1},
		{name: "alpha.1 > alpha (more identifiers)", a: "1.0.0-alpha.1", b: "1.0.0-alpha", want: 1},
		{name: "alpha.beta < alpha.gamma", a: "1.0.0-alpha.beta", b: "1.0.0-alpha.gamma", want: -1},
		{name: "rc.1 < rc.2", a: "1.0.0-rc.1", b: "1.0.0-rc.2", want: -1},
		{name: "beta.2 < beta.11", a: "1.0.0-beta.2", b: "1.0.0-beta.11", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareVersions_BuildMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "build metadata ignored equal", a: "1.0.0+build", b: "1.0.0", want: 0},
		{name: "build metadata ignored reverse", a: "1.0.0", b: "1.0.0+build", want: 0},
		{name: "different build metadata equal", a: "1.0.0+build1", b: "1.0.0+build2", want: 0},
		{name: "build metadata with prerelease", a: "1.0.0-rc1+build", b: "1.0.0-rc1", want: 0},
		{name: "build metadata does not change ordering", a: "1.0.0+build", b: "2.0.0+build", want: -1},
		{name: "prerelease with build vs release", a: "1.0.0-rc1+build", b: "1.0.0", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareVersions_NumericNotLexicographic(t *testing.T) {
	t.Parallel()

	// Ensure comparison is numeric, not lexicographic.
	// Lexicographic: "9" > "10" -- that would be WRONG.
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "10 > 9 major", a: "10.0.0", b: "9.0.0", want: 1},
		{name: "9 < 10 major", a: "9.0.0", b: "10.0.0", want: -1},
		{name: "2 < 11 minor", a: "1.2.0", b: "1.11.0", want: -1},
		{name: "99 < 100 patch", a: "0.0.99", b: "0.0.100", want: -1},
		{name: "21 > 3 patch", a: "0.0.21", b: "0.0.3", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareVersions_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "empty strings equal", a: "", b: "", want: 0},
		{name: "empty vs zero", a: "", b: "0", want: 0},
		{name: "zero vs empty", a: "0", b: "", want: 0},
		{name: "zero vs zero", a: "0", b: "0", want: 0},
		{name: "0.0.0 vs 0.0.0", a: "0.0.0", b: "0.0.0", want: 0},
		{name: "single segment comparison", a: "3", b: "5", want: -1},
		{name: "leading zeros handled", a: "1.02.3", b: "1.2.3", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareVersions_RealWorldVersions(t *testing.T) {
	t.Parallel()

	// Real packages from npm, Go, Python, etc.
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "lodash 4.17.15 < 4.17.21", a: "4.17.15", b: "4.17.21", want: -1},
		{name: "requests 2.28.0 < 2.31.0", a: "2.28.0", b: "2.31.0", want: -1},
		{name: "go stdlib 1.21.0 < 1.22.0", a: "1.21.0", b: "1.22.0", want: -1},
		{name: "django 3.2.14 < 4.0.0", a: "3.2.14", b: "4.0.0", want: -1},
		{name: "express 4.18.2 < 4.19.0", a: "4.18.2", b: "4.19.0", want: -1},
		{name: "spring 5.3.20 > 5.3.19", a: "5.3.20", b: "5.3.19", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// splitPrerelease
// ---------------------------------------------------------------------------

func TestSplitPrerelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantRel string
		wantPre string
	}{
		{name: "no prerelease", input: "1.2.3", wantRel: "1.2.3", wantPre: ""},
		{name: "simple prerelease", input: "1.2.3-rc1", wantRel: "1.2.3", wantPre: "rc1"},
		{name: "dotted prerelease", input: "1.2.3-alpha.1", wantRel: "1.2.3", wantPre: "alpha.1"},
		{name: "multiple hyphens", input: "1.2.3-beta-2", wantRel: "1.2.3", wantPre: "beta-2"},
		{name: "empty input", input: "", wantRel: "", wantPre: ""},
		{name: "no dots just hyphen", input: "1-rc1", wantRel: "1", wantPre: "rc1"},
		{name: "leading hyphen no split", input: "-rc1", wantRel: "-rc1", wantPre: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, pre := splitPrerelease(tt.input)
			if rel != tt.wantRel || pre != tt.wantPre {
				t.Fatalf("splitPrerelease(%q) = (%q, %q), want (%q, %q)",
					tt.input, rel, pre, tt.wantRel, tt.wantPre)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// comparePrerelease
// ---------------------------------------------------------------------------

func TestComparePrerelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "equal strings", a: "alpha", b: "alpha", want: 0},
		{name: "alpha < beta", a: "alpha", b: "beta", want: -1},
		{name: "beta > alpha", a: "beta", b: "alpha", want: 1},
		{name: "numeric 1 < 2", a: "1", b: "2", want: -1},
		{name: "numeric 10 > 9", a: "10", b: "9", want: 1},
		{name: "numeric < string", a: "1", b: "alpha", want: -1},
		{name: "string > numeric", a: "alpha", b: "1", want: 1},
		{name: "dotted alpha.1 < alpha.2", a: "alpha.1", b: "alpha.2", want: -1},
		{name: "fewer segments lower", a: "alpha", b: "alpha.1", want: -1},
		{name: "more segments higher", a: "alpha.1", b: "alpha", want: 1},
		{name: "three segments equal", a: "alpha.1.2", b: "alpha.1.2", want: 0},
		{name: "three segments differ last", a: "alpha.1.2", b: "alpha.1.3", want: -1},
		{name: "mixed segments", a: "alpha.1", b: "alpha.beta", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := comparePrerelease(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("comparePrerelease(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isNumeric
// ---------------------------------------------------------------------------

func TestIsNumeric(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantVal int
	}{
		{name: "empty", input: "", wantOK: false, wantVal: 0},
		{name: "zero", input: "0", wantOK: true, wantVal: 0},
		{name: "simple number", input: "42", wantOK: true, wantVal: 42},
		{name: "large number", input: "12345", wantOK: true, wantVal: 12345},
		{name: "alpha string", input: "alpha", wantOK: false, wantVal: 0},
		{name: "mixed", input: "1a", wantOK: false, wantVal: 0},
		{name: "starts with letter", input: "a1", wantOK: false, wantVal: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, val := isNumeric(tt.input)
			if ok != tt.wantOK || val != tt.wantVal {
				t.Fatalf("isNumeric(%q) = (%v, %d), want (%v, %d)",
					tt.input, ok, val, tt.wantOK, tt.wantVal)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseVersionSegment
// ---------------------------------------------------------------------------

func TestParseVersionSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  int
	}{
		{name: "empty", input: "", want: 0},
		{name: "zero", input: "0", want: 0},
		{name: "simple", input: "17", want: 17},
		{name: "with suffix", input: "21beta", want: 21},
		{name: "letters only", input: "abc", want: 0},
		{name: "leading zeros", input: "007", want: 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVersionSegment(tt.input)
			if got != tt.want {
				t.Fatalf("parseVersionSegment(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// versionInRange
// ---------------------------------------------------------------------------

func TestVersionInRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		version      string
		introduced   string
		fixed        string
		lastAffected string
		want         bool
	}{
		// Inside range
		{name: "inside introduced-fixed range", version: "1.5.0", introduced: "1.0.0", fixed: "2.0.0", lastAffected: "", want: true},
		{name: "at introduced boundary included", version: "1.0.0", introduced: "1.0.0", fixed: "2.0.0", lastAffected: "", want: true},

		// Outside range
		{name: "before introduced", version: "0.9.0", introduced: "1.0.0", fixed: "2.0.0", lastAffected: "", want: false},
		{name: "after fixed", version: "2.0.1", introduced: "1.0.0", fixed: "2.0.0", lastAffected: "", want: false},

		// Fixed boundary (exclusive)
		{name: "at fixed boundary excluded", version: "2.0.0", introduced: "1.0.0", fixed: "2.0.0", lastAffected: "", want: false},

		// lastAffected boundary (inclusive)
		{name: "at lastAffected boundary included", version: "2.1.0", introduced: "1.0.0", fixed: "", lastAffected: "2.1.0", want: true},
		{name: "after lastAffected excluded", version: "2.1.1", introduced: "1.0.0", fixed: "", lastAffected: "2.1.0", want: false},
		{name: "inside lastAffected range", version: "1.5.0", introduced: "1.0.0", fixed: "", lastAffected: "2.1.0", want: true},

		// Open-ended range (no fixed, no lastAffected)
		{name: "open-ended range everything after introduced", version: "99.0.0", introduced: "1.0.0", fixed: "", lastAffected: "", want: true},

		// Empty introduced (matches from start)
		{name: "empty introduced matches from start", version: "0.0.1", introduced: "", fixed: "1.0.0", lastAffected: "", want: true},
		{name: "empty introduced at fixed boundary", version: "1.0.0", introduced: "", fixed: "1.0.0", lastAffected: "", want: false},

		// Pre-release versions
		{name: "prerelease inside range", version: "1.5.0-rc1", introduced: "1.0.0", fixed: "2.0.0", lastAffected: "", want: true},
		{name: "prerelease at fixed boundary excluded", version: "2.0.0-rc1", introduced: "1.0.0", fixed: "2.0.0", lastAffected: "", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := versionInRange(tt.version, tt.introduced, tt.fixed, tt.lastAffected)
			if got != tt.want {
				t.Fatalf("versionInRange(%q, %q, %q, %q) = %v, want %v",
					tt.version, tt.introduced, tt.fixed, tt.lastAffected, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// versionAffected
// ---------------------------------------------------------------------------

func TestVersionAffected_SimpleRange(t *testing.T) {
	t.Parallel()

	// Single range: introduced=1.0.0, fixed=2.0.0
	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "before introduced", version: "0.9.0", want: false},
		{name: "at introduced", version: "1.0.0", want: true},
		{name: "inside range", version: "1.5.0", want: true},
		{name: "just below fixed", version: "1.99.99", want: true},
		{name: "at fixed boundary excluded", version: "2.0.0", want: false},
		{name: "after fixed", version: "2.0.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, `[]`)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_ZeroIntroduced(t *testing.T) {
	t.Parallel()

	// introduced="0" means from the very beginning
	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "very old version", version: "0.0.1", want: true},
		{name: "zero version", version: "0.1.0", want: true},
		{name: "just below fixed", version: "1.2.2", want: true},
		{name: "at fixed boundary", version: "1.2.3", want: false},
		{name: "after fixed", version: "1.3.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, `[]`)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_MultipleRanges(t *testing.T) {
	t.Parallel()

	// Two ranges: [1.0.0, 1.5.0) and [2.0.0, 2.1.0]
	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"},{"introduced":"2.0.0"},{"last_affected":"2.1.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "zero introduced includes older", version: "0.9.0", want: true},
		{name: "inside first range", version: "1.2.2", want: true},
		{name: "fixed boundary excluded", version: "1.2.3", want: false},
		{name: "between ranges not affected", version: "1.5.0", want: false},
		{name: "at second introduced", version: "2.0.0", want: true},
		{name: "inside second range", version: "2.0.5", want: true},
		{name: "at last_affected boundary included", version: "2.1.0", want: true},
		{name: "after last_affected excluded", version: "2.1.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, `[]`)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_OpenEndedRange(t *testing.T) {
	t.Parallel()

	// introduced=1.0.0 with no fixed and no last_affected -> everything >= 1.0.0
	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "before introduced", version: "0.9.0", want: false},
		{name: "at introduced", version: "1.0.0", want: true},
		{name: "well after introduced", version: "99.99.99", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, `[]`)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_EmptyRangesAndVersions(t *testing.T) {
	t.Parallel()

	// Empty ranges + empty versions should conservatively return true
	// (was a false-positive bug, now the code returns true when both are empty
	//  because we cannot determine safety).
	tests := []struct {
		name     string
		ranges   string
		versions string
		want     bool
	}{
		{name: "both empty arrays", ranges: `[]`, versions: `[]`, want: true},
		{name: "both empty strings", ranges: ``, versions: ``, want: true},
		{name: "ranges null versions empty", ranges: `null`, versions: `[]`, want: true},
		{name: "ranges empty versions null", ranges: `[]`, versions: `null`, want: true},
		{name: "both null", ranges: `null`, versions: `null`, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected("1.0.0", tt.ranges, tt.versions)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(1.0.0, %q, %q) = %v, want %v",
					tt.ranges, tt.versions, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_ExplicitVersionsList(t *testing.T) {
	t.Parallel()

	// No ranges, only explicit versions
	ranges := `[]`
	versions := `["1.0.0","1.0.1","2.0.0"]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "exact match first", version: "1.0.0", want: true},
		{name: "exact match middle", version: "1.0.1", want: true},
		{name: "exact match last", version: "2.0.0", want: true},
		{name: "not in list", version: "1.0.2", want: false},
		{name: "not in list higher", version: "3.0.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, versions)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_BothRangesAndVersions(t *testing.T) {
	t.Parallel()

	// Range covers 1.0.0-2.0.0, explicit versions add 3.0.0
	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`
	versions := `["3.0.0"]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "in range", version: "1.5.0", want: true},
		{name: "at fixed boundary", version: "2.0.0", want: false},
		{name: "in explicit list", version: "3.0.0", want: true},
		{name: "not in range or list", version: "2.5.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, versions)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_LastAffectedBoundary(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"1.5.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "before introduced", version: "0.9.0", want: false},
		{name: "at introduced", version: "1.0.0", want: true},
		{name: "inside range", version: "1.3.0", want: true},
		{name: "at last_affected included", version: "1.5.0", want: true},
		{name: "after last_affected excluded", version: "1.5.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, `[]`)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_PrereleaseInRange(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "prerelease inside range", version: "1.5.0-rc1", want: true},
		// 2.0.0-rc1 < 2.0.0 so it IS affected (not yet fixed)
		{name: "prerelease at fixed is still affected", version: "2.0.0-rc1", want: true},
		{name: "prerelease before introduced", version: "0.9.0-beta", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, `[]`)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_InvalidJSON(t *testing.T) {
	t.Parallel()

	// Invalid JSON should return true (fail-safe: assume affected) and an error.
	got, err := versionAffected("1.0.0", `{not valid json}`, `[]`)
	if err == nil {
		t.Fatal("expected error for invalid ranges JSON, got nil")
	}
	if !got {
		t.Fatal("expected true (fail-safe) for invalid JSON, got false")
	}

	got, err = versionAffected("1.0.0", `[]`, `{not valid json}`)
	if err == nil {
		t.Fatal("expected error for invalid versions JSON, got nil")
	}
	if !got {
		t.Fatal("expected true (fail-safe) for invalid JSON, got false")
	}
}

func TestVersionAffected_MultipleSeparateRangeObjects(t *testing.T) {
	t.Parallel()

	// Multiple range objects (not just multiple events in one object)
	ranges := `[
		{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]},
		{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"fixed":"2.5.0"}]}
	]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "in first range", version: "1.2.0", want: true},
		{name: "between ranges", version: "1.7.0", want: false},
		{name: "in second range", version: "2.2.0", want: true},
		{name: "after second range", version: "2.5.0", want: false},
		{name: "before all", version: "0.5.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := versionAffected(tt.version, ranges, `[]`)
			if err != nil {
				t.Fatalf("versionAffected() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("versionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractFixedVersion
// ---------------------------------------------------------------------------

func TestExtractFixedVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ranges string
		want   string
	}{
		{
			name:   "single fixed version",
			ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`,
			want:   ">= 1.2.3",
		},
		{
			name:   "multiple fixed returns lowest",
			ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.5.0"},{"introduced":"5.0.0"},{"fixed":"5.1.0"}]}]`,
			want:   ">= 4.5.0",
		},
		{
			name:   "multiple range objects returns lowest",
			ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"fixed":"2.5.0"}]},{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.3.0"}]}]`,
			want:   ">= 1.3.0",
		},
		{
			name:   "no fixed version",
			ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"}]}]`,
			want:   "",
		},
		{
			name:   "only last_affected no fixed",
			ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"2.0.0"}]}]`,
			want:   "",
		},
		{
			name:   "empty input",
			ranges: ``,
			want:   "",
		},
		{
			name:   "null input",
			ranges: `null`,
			want:   "",
		},
		{
			name:   "empty array",
			ranges: `[]`,
			want:   "",
		},
		{
			name:   "invalid json",
			ranges: `{broken`,
			want:   "",
		},
		{
			name:   "whitespace only",
			ranges: `   `,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFixedVersion(tt.ranges)
			if got != tt.want {
				t.Fatalf("extractFixedVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeIntroduced
// ---------------------------------------------------------------------------

func TestNormalizeIntroduced(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "zero becomes empty", input: "0", want: ""},
		{name: "version preserved", input: "1.0.0", want: "1.0.0"},
		{name: "empty stays empty", input: "", want: ""},
		{name: "non-zero number preserved", input: "2", want: "2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeIntroduced(tt.input)
			if got != tt.want {
				t.Fatalf("normalizeIntroduced(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Symmetry / antisymmetry property test for compareVersions
// ---------------------------------------------------------------------------

func TestCompareVersions_Symmetry(t *testing.T) {
	t.Parallel()

	// If compareVersions(a, b) = X then compareVersions(b, a) must = -X.
	pairs := [][2]string{
		{"1.0.0", "2.0.0"},
		{"1.0.0-alpha", "1.0.0"},
		{"1.0.0-alpha", "1.0.0-beta"},
		{"1.0.0-1", "1.0.0-2"},
		{"1.0.0", "1.0.0+build"},
		{"0.0.1", "0.0.2"},
		{"10.0.0", "9.0.0"},
		{"1.0.0-alpha.1", "1.0.0-alpha.2"},
	}

	for _, p := range pairs {
		ab := compareVersions(p[0], p[1])
		ba := compareVersions(p[1], p[0])
		if ab != -ba {
			t.Fatalf("antisymmetry violated: compareVersions(%q,%q)=%d but compareVersions(%q,%q)=%d (expected %d)",
				p[0], p[1], ab, p[1], p[0], ba, -ab)
		}
	}
}

// ---------------------------------------------------------------------------
// Transitivity property test for compareVersions
// ---------------------------------------------------------------------------

func TestCompareVersions_Transitivity(t *testing.T) {
	t.Parallel()

	// If a < b and b < c then a < c.
	triples := [][3]string{
		{"1.0.0-alpha", "1.0.0-beta", "1.0.0"},
		{"0.9.0", "1.0.0", "2.0.0"},
		{"1.0.0-alpha", "1.0.0-rc1", "1.0.0"},
		{"1.0.0-1", "1.0.0-2", "1.0.0-10"},
	}

	for _, triple := range triples {
		ab := compareVersions(triple[0], triple[1])
		bc := compareVersions(triple[1], triple[2])
		ac := compareVersions(triple[0], triple[2])

		if ab >= 0 {
			t.Fatalf("expected %q < %q but got %d", triple[0], triple[1], ab)
		}
		if bc >= 0 {
			t.Fatalf("expected %q < %q but got %d", triple[1], triple[2], bc)
		}
		if ac >= 0 {
			t.Fatalf("transitivity violated: %q < %q < %q but compareVersions(%q,%q)=%d",
				triple[0], triple[1], triple[2], triple[0], triple[2], ac)
		}
	}
}
