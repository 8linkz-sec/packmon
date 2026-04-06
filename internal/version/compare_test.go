package version

import "testing"

// ---------------------------------------------------------------------------
// Compare -- semver mode (default)
// ---------------------------------------------------------------------------

func TestCompare_Semver_Basic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "major less", a: "1.0.0", b: "2.0.0", want: -1},
		{name: "major greater", a: "2.0.0", b: "1.0.0", want: 1},
		{name: "minor less", a: "1.2.0", b: "1.3.0", want: -1},
		{name: "patch less", a: "1.2.3", b: "1.2.4", want: -1},
		{name: "equal", a: "1.0.0", b: "1.0.0", want: 0},
		{name: "multi digit", a: "10.0.0", b: "9.0.0", want: 1},
		{name: "different segments", a: "1.0", b: "1.0.0", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "SEMVER", "")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, SEMVER) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompare_Semver_Prerelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "rc < release", a: "1.0.0-rc1", b: "1.0.0", want: -1},
		{name: "release > rc", a: "1.0.0", b: "1.0.0-rc1", want: 1},
		{name: "alpha < beta", a: "1.0.0-alpha", b: "1.0.0-beta", want: -1},
		{name: "numeric pre 1 < 2", a: "1.0.0-1", b: "1.0.0-2", want: -1},
		{name: "numeric < string", a: "1.0.0-1", b: "1.0.0-alpha", want: -1},
		{name: "dotted alpha.1 < alpha.2", a: "1.0.0-alpha.1", b: "1.0.0-alpha.2", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "SEMVER", "")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, SEMVER) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompare_Semver_BuildMeta(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "build ignored", a: "1.0.0+build", b: "1.0.0", want: 0},
		{name: "different build equal", a: "1.0.0+b1", b: "1.0.0+b2", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "SEMVER", "")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, SEMVER) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompare_EmptyType_UsesSemver(t *testing.T) {
	t.Parallel()

	got := Compare("1.0.0-rc1", "1.0.0", "", "")
	if got != -1 {
		t.Fatalf("Compare with empty type should use semver: got %d, want -1", got)
	}
}

// ---------------------------------------------------------------------------
// Compare -- GIT type
// ---------------------------------------------------------------------------

func TestCompare_Git_AlwaysZero(t *testing.T) {
	t.Parallel()

	got := Compare("abc123", "def456", "GIT", "")
	if got != 0 {
		t.Fatalf("Compare with GIT type should return 0, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Compare -- ECOSYSTEM type, Python PEP 440
// ---------------------------------------------------------------------------

func TestCompare_PEP440_Basic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "simple less", a: "1.0.0", b: "2.0.0", want: -1},
		{name: "simple equal", a: "1.0.0", b: "1.0.0", want: 0},
		{name: "simple greater", a: "2.0.0", b: "1.0.0", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "ECOSYSTEM", "PyPI")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, ECOSYSTEM, PyPI) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompare_PEP440_InlinePrerelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "alpha < release", a: "1.0a1", b: "1.0.0", want: -1},
		{name: "beta < release", a: "1.0b2", b: "1.0.0", want: -1},
		{name: "rc < release", a: "1.0rc1", b: "1.0.0", want: -1},
		{name: "dev < alpha", a: "1.0.dev1", b: "1.0a1", want: -1},
		{name: "alpha < beta", a: "1.0a1", b: "1.0b1", want: -1},
		{name: "beta < rc", a: "1.0b1", b: "1.0rc1", want: -1},
		{name: "release < post", a: "1.0.0", b: "1.0.0.post1", want: -1},
		{name: "a1 < a2", a: "1.0a1", b: "1.0a2", want: -1},
		{name: "b1 < b2", a: "1.0b1", b: "1.0b2", want: -1},
		{name: "rc1 < rc2", a: "1.0rc1", b: "1.0rc2", want: -1},
		{name: "post1 < post2", a: "1.0.post1", b: "1.0.post2", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "ECOSYSTEM", "pypi")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, ECOSYSTEM, pypi) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompare_PEP440_LeadingV(t *testing.T) {
	t.Parallel()

	got := Compare("v1.0.0", "1.0.0", "ECOSYSTEM", "pypi")
	if got != 0 {
		t.Fatalf("Compare(v1.0.0, 1.0.0, pypi) = %d, want 0", got)
	}
}

func TestCompare_PEP440_Epoch(t *testing.T) {
	t.Parallel()

	got := Compare("1!1.0.0", "2.0.0", "ECOSYSTEM", "pypi")
	if got != 1 {
		t.Fatalf("Compare(1!1.0.0, 2.0.0, pypi) = %d, want 1 (epoch wins)", got)
	}
}

func TestCompare_PEP440_DotSeparatedSuffix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: ".dev < .a", a: "1.0.0.dev1", b: "1.0.0a1", want: -1},
		{name: ".a < .b", a: "1.0.0.a1", b: "1.0.0.b1", want: -1},
		{name: ".rc < release", a: "1.0.0.rc1", b: "1.0.0", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "ECOSYSTEM", "pypi")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, ECOSYSTEM, pypi) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompare_PEP440_RealWorldPython(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "django 3.2.14 < 4.0.0", a: "3.2.14", b: "4.0.0", want: -1},
		{name: "requests 2.28.0 < 2.31.0", a: "2.28.0", b: "2.31.0", want: -1},
		{name: "flask 2.0.0rc1 < 2.0.0", a: "2.0.0rc1", b: "2.0.0", want: -1},
		{name: "setuptools 67.0.0 < 67.1.0", a: "67.0.0", b: "67.1.0", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "ECOSYSTEM", "pypi")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, ECOSYSTEM, pypi) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Compare -- ECOSYSTEM type, Maven
// ---------------------------------------------------------------------------

func TestCompare_Maven_Basic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "equal", a: "1.0.0", b: "1.0.0", want: 0},
		{name: "less", a: "1.0.0", b: "2.0.0", want: -1},
		{name: "SNAPSHOT < release", a: "1.0.0-SNAPSHOT", b: "1.0.0", want: -1},
		{name: "RC < release", a: "1.0.0-RC1", b: "1.0.0", want: -1},
		{name: "alpha < beta", a: "1.0.0-alpha1", b: "1.0.0-beta1", want: -1},
		{name: "beta < rc", a: "1.0.0-beta1", b: "1.0.0-rc1", want: -1},
		{name: "rc < snapshot", a: "1.0.0-rc1", b: "1.0.0-SNAPSHOT", want: -1},
		{name: "rc1 < rc2", a: "1.0.0-rc1", b: "1.0.0-rc2", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "ECOSYSTEM", "Maven")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, ECOSYSTEM, Maven) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompare_Maven_RealWorld(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{name: "spring 5.3.19 < 5.3.20", a: "5.3.19", b: "5.3.20", want: -1},
		{name: "log4j 2.17.0 < 2.17.1", a: "2.17.0", b: "2.17.1", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.a, tt.b, "ECOSYSTEM", "maven")
			if got != tt.want {
				t.Fatalf("Compare(%q, %q, ECOSYSTEM, maven) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Compare -- ECOSYSTEM type, fallback to semver
// ---------------------------------------------------------------------------

func TestCompare_Ecosystem_DefaultSemver(t *testing.T) {
	t.Parallel()

	// npm, go, cargo, etc. should fall back to semver.
	ecosystems := []string{"npm", "Go", "crates.io", "NuGet", "Packagist"}
	for _, eco := range ecosystems {
		got := Compare("1.0.0-rc1", "1.0.0", "ECOSYSTEM", eco)
		if got != -1 {
			t.Errorf("Compare(1.0.0-rc1, 1.0.0, ECOSYSTEM, %s) = %d, want -1", eco, got)
		}
	}
}

// ---------------------------------------------------------------------------
// VersionAffected -- full OSV format
// ---------------------------------------------------------------------------

func TestVersionAffected_FullOSV_SimpleRange(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "before introduced", version: "0.9.0", want: false},
		{name: "at introduced", version: "1.0.0", want: true},
		{name: "inside", version: "1.5.0", want: true},
		{name: "at fixed excluded", version: "2.0.0", want: false},
		{name: "after fixed", version: "2.0.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, ranges, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_FullOSV_ZeroIntroduced(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "very old", version: "0.0.1", want: true},
		{name: "just below fixed", version: "1.2.2", want: true},
		{name: "at fixed", version: "1.2.3", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, ranges, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_FullOSV_LastAffected(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"1.5.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "at last_affected included", version: "1.5.0", want: true},
		{name: "after last_affected", version: "1.5.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, ranges, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_FullOSV_OpenEnded(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "before", version: "0.9.0", want: false},
		{name: "at introduced", version: "1.0.0", want: true},
		{name: "way after", version: "99.0.0", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, ranges, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_FullOSV_OpenEndedZeroIntroduced(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "zero style introduced matches early version", version: "0.0.1", want: true},
		{name: "zero style introduced matches later version", version: "99.0.0", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, ranges, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_FullOSV_MultipleRanges(t *testing.T) {
	t.Parallel()

	ranges := `[
		{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.5.0"}]},
		{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"fixed":"2.5.0"}]}
	]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "in first", version: "1.2.0", want: true},
		{name: "between", version: "1.7.0", want: false},
		{name: "in second", version: "2.2.0", want: true},
		{name: "after second", version: "2.5.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, ranges, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_FullOSV_MultipleEventsInOneRange(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"},{"introduced":"2.0.0"},{"last_affected":"2.1.0"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "in first range", version: "1.2.2", want: true},
		{name: "fixed boundary", version: "1.2.3", want: false},
		{name: "between ranges", version: "1.5.0", want: false},
		{name: "in second range", version: "2.0.5", want: true},
		{name: "at last_affected", version: "2.1.0", want: true},
		{name: "after last_affected", version: "2.1.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, ranges, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_ExplicitVersionsList(t *testing.T) {
	t.Parallel()

	got, err := VersionAffected("1.0.1", `[]`, `["1.0.0","1.0.1","2.0.0"]`, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true for version in explicit list")
	}

	got, err = VersionAffected("1.0.2", `[]`, `["1.0.0","1.0.1","2.0.0"]`, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false for version not in explicit list")
	}
}

func TestVersionAffected_BothRangesAndVersions(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`
	versions := `["3.0.0"]`

	// In range.
	got, err := VersionAffected("1.5.0", ranges, versions, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true for version in range")
	}

	// In explicit list.
	got, err = VersionAffected("3.0.0", ranges, versions, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true for version in explicit list")
	}

	// Neither.
	got, err = VersionAffected("2.5.0", ranges, versions, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false for version not in range or list")
	}
}

func TestVersionAffected_EmptyRangesAndVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ranges   string
		versions string
	}{
		{name: "both empty arrays", ranges: `[]`, versions: `[]`},
		{name: "both empty strings", ranges: ``, versions: ``},
		{name: "both null", ranges: `null`, versions: `null`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected("1.0.0", tt.ranges, tt.versions, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got {
				t.Fatalf("expected true (fail-safe) for empty ranges and versions")
			}
		})
	}
}

func TestVersionAffected_InvalidJSON(t *testing.T) {
	t.Parallel()

	got, err := VersionAffected("1.0.0", `{not valid}`, `[]`, "npm")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !got {
		t.Fatal("expected true (fail-safe) for invalid JSON")
	}
}

// ---------------------------------------------------------------------------
// VersionAffected -- flat format (local sync)
// ---------------------------------------------------------------------------

func TestVersionAffected_FlatFormat(t *testing.T) {
	t.Parallel()

	// Flat format as sent by the server sync export.
	flat := `[{"introduced":"1.0.0","fixed":"2.0.0"}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "before", version: "0.9.0", want: false},
		{name: "at introduced", version: "1.0.0", want: true},
		{name: "inside", version: "1.5.0", want: true},
		{name: "at fixed excluded", version: "2.0.0", want: false},
		{name: "after fixed", version: "2.1.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, flat, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q, flat) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_FlatFormat_MultipleRanges(t *testing.T) {
	t.Parallel()

	flat := `[{"introduced":"1.0.0","fixed":"1.5.0"},{"introduced":"2.0.0","fixed":"2.5.0"}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "in first", version: "1.2.0", want: true},
		{name: "between", version: "1.7.0", want: false},
		{name: "in second", version: "2.2.0", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, flat, `[]`, "npm")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q, flat) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestVersionAffected_FlatFormat_ZeroIntroduced(t *testing.T) {
	t.Parallel()

	flat := `[{"introduced":"0","fixed":"1.0.0"}]`

	got, err := VersionAffected("0.5.0", flat, `[]`, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true for version in flat range with introduced=0")
	}
}

// ---------------------------------------------------------------------------
// VersionAffected -- GIT range type skips range matching
// ---------------------------------------------------------------------------

func TestVersionAffected_GitRange_UsesExplicitList(t *testing.T) {
	t.Parallel()

	// GIT ranges should be skipped; only explicit versions list matters.
	ranges := `[{"type":"GIT","events":[{"introduced":"abc123"},{"fixed":"def456"}]}]`

	// Not in versions list -- should not match (ranges skipped).
	got, err := VersionAffected("abc123", ranges, `["xyz789"]`, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: GIT range should be skipped and version not in list")
	}

	// In versions list.
	got, err = VersionAffected("xyz789", ranges, `["xyz789"]`, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: version is in explicit list")
	}
}

// ---------------------------------------------------------------------------
// VersionAffected -- ECOSYSTEM type with Python versions
// ---------------------------------------------------------------------------

func TestVersionAffected_PythonEcosystem(t *testing.T) {
	t.Parallel()

	// Python advisory: affected 1.0a1 through 1.0.0 (fixed at 1.0.1).
	ranges := `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0a1"},{"fixed":"1.0.1"}]}]`

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "pre-release in range", version: "1.0b1", want: true},
		{name: "release in range", version: "1.0.0", want: true},
		{name: "fixed version", version: "1.0.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VersionAffected(tt.version, ranges, `[]`, "PyPI")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("VersionAffected(%q, pypi) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// VersionAffected -- prerelease at fixed boundary
// ---------------------------------------------------------------------------

func TestVersionAffected_PrereleaseAtFixed(t *testing.T) {
	t.Parallel()

	ranges := `[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]`

	// 2.0.0-rc1 < 2.0.0, so it IS affected (not yet fixed).
	got, err := VersionAffected("2.0.0-rc1", ranges, `[]`, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: 2.0.0-rc1 < 2.0.0 so still affected")
	}
}

// ---------------------------------------------------------------------------
// ExtractFixedVersion
// ---------------------------------------------------------------------------

func TestExtractFixedVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ranges string
		want   string
	}{
		{
			name:   "single fixed",
			ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]`,
			want:   "1.2.3",
		},
		{
			name:   "multiple fixed returns lowest",
			ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.5.0"},{"introduced":"5.0.0"},{"fixed":"5.1.0"}]}]`,
			want:   "4.5.0",
		},
		{
			name:   "no fixed",
			ranges: `[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"}]}]`,
			want:   "",
		},
		{
			name:   "empty input",
			ranges: ``,
			want:   "",
		},
		{
			name:   "null",
			ranges: `null`,
			want:   "",
		},
		{
			name:   "flat format",
			ranges: `[{"introduced":"0","fixed":"1.0.5"}]`,
			want:   "1.0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFixedVersion(tt.ranges)
			if got != tt.want {
				t.Fatalf("ExtractFixedVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Symmetry and transitivity
// ---------------------------------------------------------------------------

func TestCompare_Symmetry(t *testing.T) {
	t.Parallel()

	pairs := [][2]string{
		{"1.0.0", "2.0.0"},
		{"1.0.0-alpha", "1.0.0"},
		{"1.0.0-alpha", "1.0.0-beta"},
		{"0.0.1", "0.0.2"},
	}

	for _, p := range pairs {
		ab := Compare(p[0], p[1], "SEMVER", "")
		ba := Compare(p[1], p[0], "SEMVER", "")
		if ab != -ba {
			t.Fatalf("antisymmetry violated: Compare(%q,%q)=%d but Compare(%q,%q)=%d",
				p[0], p[1], ab, p[1], p[0], ba)
		}
	}
}

func TestCompare_PEP440_Symmetry(t *testing.T) {
	t.Parallel()

	pairs := [][2]string{
		{"1.0a1", "1.0.0"},
		{"1.0b1", "1.0rc1"},
		{"1.0.0", "1.0.0.post1"},
		{"1.0.dev1", "1.0a1"},
	}

	for _, p := range pairs {
		ab := Compare(p[0], p[1], "ECOSYSTEM", "pypi")
		ba := Compare(p[1], p[0], "ECOSYSTEM", "pypi")
		if ab != -ba {
			t.Fatalf("PEP440 antisymmetry violated: Compare(%q,%q)=%d but Compare(%q,%q)=%d",
				p[0], p[1], ab, p[1], p[0], ba)
		}
	}
}

func TestCompare_PEP440_Transitivity(t *testing.T) {
	t.Parallel()

	// dev < alpha < beta < rc < release < post
	chain := []string{"1.0.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0.0", "1.0.0.post1"}

	for i := 0; i < len(chain)-1; i++ {
		for j := i + 1; j < len(chain); j++ {
			cmp := Compare(chain[i], chain[j], "ECOSYSTEM", "pypi")
			if cmp >= 0 {
				t.Fatalf("expected %q < %q but got Compare=%d", chain[i], chain[j], cmp)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func TestParseRanges_FlatDetection(t *testing.T) {
	t.Parallel()

	// Full format should parse normally.
	full := `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]`
	ranges, err := parseRanges(full)
	if err != nil {
		t.Fatalf("parseRanges full: %v", err)
	}
	if len(ranges) != 1 || len(ranges[0].Events) != 2 {
		t.Fatalf("expected 1 range with 2 events, got %d ranges", len(ranges))
	}

	// Flat format should be auto-detected.
	flat := `[{"introduced":"1.0.0","fixed":"2.0.0"}]`
	ranges, err = parseRanges(flat)
	if err != nil {
		t.Fatalf("parseRanges flat: %v", err)
	}
	if len(ranges) != 1 || len(ranges[0].Events) != 2 {
		t.Fatalf("expected 1 range with 2 events after flat conversion, got %d ranges with %d events",
			len(ranges), func() int {
				if len(ranges) > 0 {
					return len(ranges[0].Events)
				}
				return 0
			}())
	}
	if ranges[0].Type != "SEMVER" {
		t.Fatalf("expected SEMVER type for converted flat range, got %q", ranges[0].Type)
	}
}
