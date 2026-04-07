package postgres

import (
	"github.com/8linkz/packmon/internal/version"
)

// versionAffected checks whether the given version is affected by the
// vulnerability described by the given range and explicit-versions JSON.
// It delegates to the shared version package which handles both full OSV
// and flat range formats, and dispatches to ecosystem-specific comparators.
//
// The ecosystem parameter is extracted from the affected_packages row and
// used when the range type is ECOSYSTEM.
func versionAffectedWithEcosystem(ver, versionRangesJSON, versionsJSON, ecosystem string) (bool, error) {
	return version.VersionAffected(ver, versionRangesJSON, versionsJSON, ecosystem)
}

// versionAffected is the legacy signature without ecosystem context.
// It is kept for backward compatibility with existing call sites that do
// not pass an ecosystem. An empty ecosystem causes SEMVER comparison to
// be used as the default for ECOSYSTEM-typed ranges.
func versionAffected(ver, versionRangesJSON, versionsJSON string) (bool, error) {
	return version.VersionAffected(ver, versionRangesJSON, versionsJSON, "")
}

// extractFixedVersion returns a user-facing fixed-version constraint derived
// from the lowest fixed version found across all OSV ranges.
func extractFixedVersion(versionRangesJSON string) string {
	return version.ExtractFixedVersionConstraint(versionRangesJSON)
}

// normalizeIntroduced maps "0" to "" (beginning of time) and passes all
// other values through unchanged. Exposed for use by test code.
func normalizeIntroduced(introduced string) string {
	if introduced == "0" {
		return ""
	}
	return introduced
}

// compareVersions compares two version strings with semver 2.0 rules.
// Delegates to the shared version package.
func compareVersions(a, b string) int {
	return version.Compare(a, b, "SEMVER", "")
}

// splitPrerelease splits a version string into release and pre-release
// parts at the first hyphen after at least one character.
func splitPrerelease(ver string) (string, string) {
	return version.SplitPrerelease(ver)
}

// versionInRange checks whether a version falls within the range defined
// by introduced/fixed/lastAffected using semver comparison.
func versionInRange(ver, introduced, fixed, lastAffected string) bool {
	cmp := func(a, b string) int {
		return version.Compare(a, b, "SEMVER", "")
	}
	if introduced != "" && cmp(ver, introduced) < 0 {
		return false
	}
	if fixed != "" && cmp(ver, fixed) >= 0 {
		return false
	}
	if lastAffected != "" && cmp(ver, lastAffected) > 0 {
		return false
	}
	return true
}

// comparePrerelease compares two pre-release strings per semver 2.0 rules.
func comparePrerelease(a, b string) int {
	return version.ComparePrerelease(a, b)
}

// isNumeric returns true and the parsed value if s is entirely ASCII digits.
func isNumeric(s string) (bool, int) {
	return version.IsNumeric(s)
}

// parseVersionSegment extracts the leading integer from a version segment.
func parseVersionSegment(segment string) int {
	return version.ParseLeadingInt(segment)
}
