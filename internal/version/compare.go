// Package version provides ecosystem-aware version comparison and range
// matching. It is the single source of truth for version logic used by
// both the PostgreSQL server store and the SQLite client store.
//
// Supported range types (per OSV schema):
//
//   - SEMVER: Standard semver 2.0 comparison with pre-release handling.
//   - ECOSYSTEM: Dispatches to an ecosystem-specific comparator (Python
//     PEP 440, Maven, or falls back to generic semver).
//   - GIT: Cannot meaningfully compare commit hashes; returns 0 so that
//     the explicit versions_affected list is used instead.
//
// The package also handles two JSON range formats transparently:
//   - Full OSV format: [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.5"}]}]
//   - Flat format:     [{"introduced":"0","fixed":"1.0.5"}]
package version

import (
	"encoding/json"
	"strings"
	"unicode"
)

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Compare returns -1, 0, or +1 comparing version a to version b using
// the given rangeType and ecosystem to select the appropriate strategy.
//
// rangeType values (OSV spec): "SEMVER", "ECOSYSTEM", "GIT", or empty.
// When rangeType is empty, SEMVER rules are applied.
//
// ecosystem is only consulted when rangeType is "ECOSYSTEM".
func Compare(a, b, rangeType, ecosystem string) int {
	switch strings.ToUpper(rangeType) {
	case "GIT":
		// Git commit hashes cannot be compared by ordering.
		// Return 0 so callers fall through to explicit version lists.
		return 0
	case "ECOSYSTEM":
		return compareEcosystem(a, b, strings.ToLower(ecosystem))
	default:
		// "SEMVER" or empty: standard semver comparison.
		return compareSemver(a, b)
	}
}

// VersionAffected returns true if the given version is affected according
// to the OSV-format ranges JSON and/or the explicit versions list JSON.
//
// It transparently handles both:
//   - Full OSV format with nested events: [{"type":"SEMVER","events":[...]}]
//   - Flat shorthand used by the local sync: [{"introduced":"0","fixed":"1.0.5"}]
//
// When both ranges and versions are empty or absent, the function returns
// true as a fail-safe (we cannot determine that the version is safe).
//
// ecosystem is used to select the comparator when range type is ECOSYSTEM.
func VersionAffected(version, versionRangesJSON, versionsJSON, ecosystem string) (bool, error) {
	rangesJSON := strings.TrimSpace(versionRangesJSON)
	versJSON := strings.TrimSpace(versionsJSON)

	// Try to parse ranges.
	var hasRanges bool
	if rangesJSON != "" && rangesJSON != "null" {
		affected, count, err := matchRanges(version, rangesJSON, ecosystem)
		if err != nil {
			return true, err
		}
		if affected {
			return true, nil
		}
		// Only consider ranges as meaningfully processed if there was
		// at least one non-empty, non-GIT range to evaluate.
		hasRanges = count > 0
	}

	// Check explicit versions list.
	var hasVersions bool
	if versJSON != "" && versJSON != "null" {
		var versions []string
		if err := json.Unmarshal([]byte(versJSON), &versions); err != nil {
			return true, err
		}
		for _, candidate := range versions {
			if candidate == version {
				return true, nil
			}
		}
		hasVersions = len(versions) > 0
	}

	// If we had actual ranges or explicit versions to check and none
	// matched, the version is not affected.
	if hasRanges || hasVersions {
		return false, nil
	}

	// Neither ranges nor versions provided any data to evaluate.
	// Conservatively return true (fail-safe: cannot determine safety).
	return true, nil
}

// ExtractFixedVersion returns the lowest fixed version found across all
// ranges in the given OSV-format JSON. Returns "" if no fixed version
// exists. Supports both full and flat range formats.
func ExtractFixedVersion(versionRangesJSON string) string {
	rangesJSON := strings.TrimSpace(versionRangesJSON)
	if rangesJSON == "" || rangesJSON == "null" {
		return ""
	}

	ranges, err := parseRanges(rangesJSON)
	if err != nil {
		return ""
	}

	best := ""
	for _, r := range ranges {
		for _, event := range r.Events {
			if event.Fixed == "" {
				continue
			}
			if best == "" || compareSemver(event.Fixed, best) < 0 {
				best = event.Fixed
			}
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Range parsing (handles both full OSV and flat formats)
// ---------------------------------------------------------------------------

// osvRange is the full OSV range format with a type discriminator.
type osvRange struct {
	Type   string          `json:"type"`
	Events []osvRangeEvent `json:"events"`
}

// osvRangeEvent represents a single event in an OSV range.
type osvRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// flatRange is the simplified flat format used by the local sync wire
// format: [{"introduced":"0","fixed":"1.0.5"}].
type flatRange struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

// parseRanges attempts to unmarshal the JSON as full OSV ranges first.
// If the result has no events but the flat fields are populated, it
// re-parses as flat ranges and converts them to full format.
func parseRanges(rangesJSON string) ([]osvRange, error) {
	var full []osvRange
	if err := json.Unmarshal([]byte(rangesJSON), &full); err != nil {
		return nil, err
	}

	// Detect flat format: if any range has no events but the top-level
	// object might have introduced/fixed fields, try flat parse.
	if isFlatFormat(full, rangesJSON) {
		var flat []flatRange
		if err := json.Unmarshal([]byte(rangesJSON), &flat); err != nil {
			return full, nil // fall back to what we already parsed
		}
		return flatToFull(flat), nil
	}

	return full, nil
}

// isFlatFormat returns true when the parsed ranges look like flat format
// (no events populated in any range entry, but the raw JSON contains
// "introduced" at the top level of array elements).
func isFlatFormat(ranges []osvRange, raw string) bool {
	if len(ranges) == 0 {
		return false
	}
	for _, r := range ranges {
		if len(r.Events) > 0 {
			return false
		}
	}
	// Check if the raw JSON has "introduced" at the object level,
	// which would indicate flat format rather than just empty ranges.
	return strings.Contains(raw, `"introduced"`)
}

// flatToFull converts flat ranges to full OSV ranges with SEMVER type.
func flatToFull(flat []flatRange) []osvRange {
	result := make([]osvRange, 0, len(flat))
	for _, f := range flat {
		events := make([]osvRangeEvent, 0, 2)
		if f.Introduced != "" {
			events = append(events, osvRangeEvent{Introduced: f.Introduced})
		}
		if f.Fixed != "" {
			events = append(events, osvRangeEvent{Fixed: f.Fixed})
		}
		if f.LastAffected != "" {
			events = append(events, osvRangeEvent{LastAffected: f.LastAffected})
		}
		if len(events) == 0 {
			continue
		}
		result = append(result, osvRange{
			Type:   "SEMVER",
			Events: events,
		})
	}
	return result
}

// ---------------------------------------------------------------------------
// Range matching
// ---------------------------------------------------------------------------

// matchRanges checks whether the given version falls within any of the
// parsed OSV ranges. It returns whether the version is affected, how many
// non-GIT ranges were evaluated, and any parse error.
func matchRanges(version, rangesJSON, ecosystem string) (affected bool, evaluated int, err error) {
	ranges, err := parseRanges(rangesJSON)
	if err != nil {
		return true, 0, err
	}

	if len(ranges) == 0 {
		return false, 0, nil
	}

	for _, item := range ranges {
		rangeType := item.Type

		// For GIT ranges, we cannot do range comparison -- skip them.
		// Affected versions should be captured in the explicit list.
		if strings.EqualFold(rangeType, "GIT") {
			continue
		}

		evaluated++

		cmp := func(a, b string) int {
			return Compare(a, b, rangeType, ecosystem)
		}

		introduced := ""
		hadIntroduced := false
		for _, event := range item.Events {
			if event.Introduced != "" {
				introduced = normalizeIntroduced(event.Introduced)
				hadIntroduced = true
			}
			if event.Fixed == "" && event.LastAffected == "" && event.Limit == "" {
				continue
			}
			if versionInRange(version, introduced, event.Fixed, event.LastAffected, cmp) {
				return true, evaluated, nil
			}
			introduced = ""
			hadIntroduced = false
		}
		// Open-ended: introduced with no fixed/lastAffected means
		// everything >= introduced is affected.
		if hadIntroduced && (introduced == "" || cmp(version, introduced) >= 0) {
			return true, evaluated, nil
		}
	}

	return false, evaluated, nil
}

func versionInRange(version, introduced, fixed, lastAffected string, cmp func(a, b string) int) bool {
	if introduced != "" && cmp(version, introduced) < 0 {
		return false
	}
	if fixed != "" && cmp(version, fixed) >= 0 {
		return false
	}
	if lastAffected != "" && cmp(version, lastAffected) > 0 {
		return false
	}
	return true
}

func normalizeIntroduced(introduced string) string {
	if introduced == "0" {
		return ""
	}
	return introduced
}

// ---------------------------------------------------------------------------
// Ecosystem dispatch
// ---------------------------------------------------------------------------

func compareEcosystem(a, b, ecosystem string) int {
	switch ecosystem {
	case "pypi", "pip":
		return comparePEP440(a, b)
	case "maven":
		return compareMaven(a, b)
	default:
		// Most ecosystems (npm, Go, Cargo, NuGet, Composer, Gem, etc.)
		// use semver or semver-like versioning.
		return compareSemver(a, b)
	}
}

// ---------------------------------------------------------------------------
// Semver comparison (standard)
// ---------------------------------------------------------------------------

// compareSemver compares two version strings with semver 2.0 rules.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
//
// Rules applied:
//   - Build metadata (after '+') is ignored.
//   - A pre-release version (1.0.0-rc1) is LESS than its release (1.0.0).
//   - Pre-release identifiers are compared per semver 2.0 spec.
//   - Python-style inline pre-release suffixes (1.0a1, 1.0b2) are NOT
//     recognized in semver mode; use PEP 440 mode for those.
func compareSemver(a, b string) int {
	a = stripBuildMeta(a)
	b = stripBuildMeta(b)

	releaseA, preA := splitPrerelease(a)
	releaseB, preB := splitPrerelease(b)

	if cmp := compareRelease(releaseA, releaseB); cmp != 0 {
		return cmp
	}

	return comparePrereleaseStrings(preA, preB)
}

func stripBuildMeta(v string) string {
	if idx := strings.IndexByte(v, '+'); idx >= 0 {
		return v[:idx]
	}
	return v
}

// splitPrerelease splits a version string into its release and
// pre-release parts at the first hyphen after at least one character.
func splitPrerelease(version string) (string, string) {
	if idx := strings.IndexByte(version, '-'); idx > 0 {
		return version[:idx], version[idx+1:]
	}
	return version, ""
}

func compareRelease(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		var segA, segB string
		if i < len(partsA) {
			segA = partsA[i]
		}
		if i < len(partsB) {
			segB = partsB[i]
		}

		numA := parseLeadingInt(segA)
		numB := parseLeadingInt(segB)
		if numA < numB {
			return -1
		}
		if numA > numB {
			return 1
		}
	}
	return 0
}

// comparePrereleaseStrings applies semver pre-release precedence rules.
func comparePrereleaseStrings(preA, preB string) int {
	if preA == "" && preB == "" {
		return 0
	}
	if preA == "" {
		return 1 // no pre-release > has pre-release
	}
	if preB == "" {
		return -1
	}
	return comparePrereleaseIdentifiers(preA, preB)
}

// comparePrereleaseIdentifiers compares two pre-release strings per
// semver 2.0 rules: identifiers are compared left to right, numeric
// identifiers are compared as integers, string identifiers lexicographically,
// and numeric identifiers sort before string identifiers.
func comparePrereleaseIdentifiers(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")

	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}

	for i := 0; i < maxLen; i++ {
		if i >= len(partsA) {
			return -1 // fewer identifiers = lower precedence
		}
		if i >= len(partsB) {
			return 1
		}

		sa, sb := partsA[i], partsB[i]
		isNumA, numA := isNumeric(sa)
		isNumB, numB := isNumeric(sb)

		switch {
		case isNumA && isNumB:
			if numA < numB {
				return -1
			}
			if numA > numB {
				return 1
			}
		case isNumA:
			return -1 // numeric < string
		case isNumB:
			return 1
		default:
			if sa < sb {
				return -1
			}
			if sa > sb {
				return 1
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// PEP 440 comparison (Python)
// ---------------------------------------------------------------------------

// pep440Phase maps pre-release/post-release suffixes to an ordering value.
// The canonical ordering is: dev < alpha < beta < rc < release < post.
var pep440Phase = map[string]int{
	"dev":   -5,
	"a":     -4,
	"alpha": -4,
	"b":     -3,
	"beta":  -3,
	"c":     -2, // PEP 440: "c" is an alias for "rc"
	"rc":    -2,
	// release = 0 (implicit)
	"post": 1,
	"rev":  1, // alias for post
	"r":    1, // alias for post
}

// comparePEP440 compares two Python version strings per a simplified
// PEP 440 implementation that covers the vast majority of real-world
// Python packages. It handles:
//   - Numeric release segments (1.2.3)
//   - Pre-release suffixes: .devN, aN, alphaN, bN, betaN, cN, rcN
//   - Post-release suffixes: .postN
//   - Leading 'v' prefix stripping
//   - Epoch stripping (1!2.0 -> 2.0 with epoch=1)
func comparePEP440(a, b string) int {
	pa := parsePEP440(a)
	pb := parsePEP440(b)

	// Compare epochs.
	if pa.epoch != pb.epoch {
		if pa.epoch < pb.epoch {
			return -1
		}
		return 1
	}

	// Compare release segments.
	if cmp := compareIntSlices(pa.release, pb.release); cmp != 0 {
		return cmp
	}

	// Compare phase (dev < alpha < beta < rc < release < post).
	if pa.phase != pb.phase {
		if pa.phase < pb.phase {
			return -1
		}
		return 1
	}

	// Compare phase number (e.g., rc1 vs rc2).
	if pa.phaseNum != pb.phaseNum {
		if pa.phaseNum < pb.phaseNum {
			return -1
		}
		return 1
	}

	// Compare dev suffix (post1.dev2 < post1.dev3).
	if pa.devNum != pb.devNum {
		if pa.devNum < pb.devNum {
			return -1
		}
		return 1
	}

	return 0
}

type pep440Version struct {
	epoch    int
	release  []int
	phase    int // see pep440Phase; 0 = release
	phaseNum int
	devNum   int // -1 = no dev suffix
}

func parsePEP440(v string) pep440Version {
	v = strings.TrimSpace(v)
	v = strings.ToLower(v)
	v = strings.TrimPrefix(v, "v")

	result := pep440Version{devNum: -1}

	// Extract epoch (e.g., "1!2.0.0").
	if idx := strings.IndexByte(v, '!'); idx >= 0 {
		result.epoch = parseInt(v[:idx])
		v = v[idx+1:]
	}

	// Split off any trailing pre/post/dev suffix.
	// PEP 440 uses both dot-separated (.rc1) and inline (1.0rc1) forms.
	relStr, phase, phaseNum := splitPEP440Suffix(v)

	result.phase = phase
	result.phaseNum = phaseNum

	// Parse release segments.
	for _, seg := range strings.Split(relStr, ".") {
		if seg == "" {
			continue
		}
		// A segment might be "1a1" style (inline suffix) -- splitPEP440Suffix
		// already handled that, but if we still see mixed segments in the
		// release part, just parse the leading integer.
		result.release = append(result.release, parseLeadingInt(seg))
	}

	return result
}

// splitPEP440Suffix separates the release string from any PEP 440
// pre/post/dev suffix. It handles both dot-separated and inline forms.
//
// Examples:
//
//	"1.0.0"       -> ("1.0.0", 0, 0)
//	"1.0.0a1"     -> ("1.0.0", -4, 1)
//	"1.0.0.rc2"   -> ("1.0.0", -2, 2)
//	"1.0.0.post1" -> ("1.0.0", 1, 1)
//	"1.0.0.dev3"  -> ("1.0.0", -5, 3)
//	"1.0.0b2"     -> ("1.0.0", -3, 2)
//
// pep440DotSuffixes lists dot-separated PEP 440 suffixes in order of
// decreasing length so that ".alpha" matches before ".a", ".beta" before
// ".b", ".post" before ".p", and ".rc" before ".r".
var pep440DotSuffixes = []struct {
	suffix string
	phase  int
}{
	{".alpha", -4},
	{".beta", -3},
	{".post", 1},
	{".dev", -5},
	{".rev", 1},
	{".rc", -2},
	{".a", -4},
	{".b", -3},
	{".c", -2},
	{".r", 1},
}

func splitPEP440Suffix(v string) (release string, phase int, phaseNum int) {
	// First try dot-separated suffixes: ".dev3", ".post1", ".rc2", ".a1", ".b2", etc.
	// Use a fixed-order slice instead of map iteration to avoid non-determinism.
	for _, s := range pep440DotSuffixes {
		if idx := strings.LastIndex(v, s.suffix); idx >= 0 {
			rest := v[idx+len(s.suffix):]
			num := 0
			if rest != "" {
				num = parseInt(rest)
			}
			return v[:idx], s.phase, num
		}
	}

	// Then try inline suffixes: scan the last segment for an alpha boundary.
	// E.g., "1.0.0a1" -> release="1.0.0", suffix="a", num=1.
	// We work on the last dot-separated segment to avoid matching "alpha"
	// inside package names.
	lastDot := strings.LastIndexByte(v, '.')
	var prefix, lastSeg string
	if lastDot >= 0 {
		prefix = v[:lastDot]
		lastSeg = v[lastDot+1:]
	} else {
		prefix = ""
		lastSeg = v
	}

	rel, p, num := splitInlineSuffix(lastSeg)
	if p != 0 || rel != lastSeg {
		if prefix != "" {
			return prefix + "." + rel, p, num
		}
		return rel, p, num
	}

	return v, 0, 0
}

// splitInlineSuffix extracts an inline PEP 440 suffix from a version
// segment like "0a1", "2b3", "1rc2", "5alpha1", "3beta2".
func splitInlineSuffix(seg string) (release string, phase int, num int) {
	// Try longest suffixes first to match "alpha" before "a", "beta" before "b".
	suffixes := []struct {
		name  string
		phase int
	}{
		{"alpha", -4},
		{"beta", -3},
		{"dev", -5},
		{"post", 1},
		{"rev", 1},
		{"rc", -2},
		{"a", -4},
		{"b", -3},
		{"c", -2},
		{"r", 1},
	}

	lower := strings.ToLower(seg)
	for _, s := range suffixes {
		idx := strings.Index(lower, s.name)
		if idx < 0 {
			continue
		}
		// The suffix must be preceded by a digit (or be at position 0
		// for bare suffix like "a1").
		if idx > 0 && !isDigit(rune(lower[idx-1])) {
			continue
		}
		relPart := seg[:idx]
		numPart := seg[idx+len(s.name):]
		n := 0
		if numPart != "" {
			n = parseInt(numPart)
		}
		if relPart == "" {
			relPart = "0"
		}
		return relPart, s.phase, n
	}

	return seg, 0, 0
}

// ---------------------------------------------------------------------------
// Maven comparison
// ---------------------------------------------------------------------------

// compareMaven compares two Maven version strings. Maven versions are
// generally numeric segments separated by dots, with optional qualifiers
// like -SNAPSHOT, -RC1, -alpha-1, -beta-2.
//
// Ordering: alpha < beta < milestone < rc/cr < snapshot < release < sp.
func compareMaven(a, b string) int {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)

	// Separate qualifier from numeric part.
	relA, qualA := splitMavenQualifier(a)
	relB, qualB := splitMavenQualifier(b)

	// Compare numeric release segments.
	if cmp := compareRelease(relA, relB); cmp != 0 {
		return cmp
	}

	// Compare qualifiers.
	return compareMavenQualifiers(qualA, qualB)
}

var mavenQualifierOrder = map[string]int{
	"alpha":     -5,
	"a":         -5,
	"beta":      -4,
	"b":         -4,
	"milestone": -3,
	"m":         -3,
	"rc":        -2,
	"cr":        -2,
	"snapshot":  -1,
	// release = 0 (implicit, no qualifier)
	"sp": 1, // service pack
	"ga": 0, // general availability = release
	"":   0,
}

func splitMavenQualifier(v string) (release, qualifier string) {
	if idx := strings.IndexByte(v, '-'); idx > 0 {
		return v[:idx], strings.ToLower(v[idx+1:])
	}
	return v, ""
}

func compareMavenQualifiers(a, b string) int {
	phaseA, numA := parseMavenQualifier(a)
	phaseB, numB := parseMavenQualifier(b)

	if phaseA != phaseB {
		if phaseA < phaseB {
			return -1
		}
		return 1
	}

	if numA != numB {
		if numA < numB {
			return -1
		}
		return 1
	}

	return 0
}

func parseMavenQualifier(q string) (phase, num int) {
	if q == "" {
		return 0, 0
	}

	// Split qualifier into text and trailing number: "rc1" -> ("rc", 1)
	textEnd := len(q)
	for textEnd > 0 && isDigit(rune(q[textEnd-1])) {
		textEnd--
	}
	text := strings.ToLower(q[:textEnd])
	numStr := q[textEnd:]

	// Strip leading hyphen or dot from the text part.
	text = strings.TrimLeft(text, "-.")

	if p, ok := mavenQualifierOrder[text]; ok {
		phase = p
	} else {
		// Unknown qualifier: treat as between snapshot and release.
		phase = -1
	}

	if numStr != "" {
		num = parseInt(numStr)
	}

	return phase, num
}

// ---------------------------------------------------------------------------
// Exported helpers (used by the postgres and sqlite packages for backward
// compatibility with their existing test suites)
// ---------------------------------------------------------------------------

// SplitPrerelease splits a version string into release and pre-release
// parts. Exported for use by dependent packages.
func SplitPrerelease(v string) (string, string) {
	return splitPrerelease(v)
}

// ComparePrerelease compares two pre-release strings per semver 2.0 rules.
// Exported for use by dependent packages.
func ComparePrerelease(a, b string) int {
	return comparePrereleaseIdentifiers(a, b)
}

// IsNumeric returns true and the parsed integer value if s is composed
// entirely of ASCII digits. Exported for use by dependent packages.
func IsNumeric(s string) (bool, int) {
	return isNumeric(s)
}

// ParseLeadingInt extracts the leading integer from a string.
// Exported for use by dependent packages.
func ParseLeadingInt(s string) int {
	return parseLeadingInt(s)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func isNumeric(s string) (bool, int) {
	if s == "" {
		return false, 0
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false, 0
		}
		n = n*10 + int(ch-'0')
	}
	return true, n
}

func parseLeadingInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

// Ensure isDigit uses the same notion as unicode for safety.
var _ = unicode.IsDigit

func compareIntSlices(a, b []int) int {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for i := 0; i < maxLen; i++ {
		var va, vb int
		if i < len(a) {
			va = a[i]
		}
		if i < len(b) {
			vb = b[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}
