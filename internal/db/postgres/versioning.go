package postgres

import (
	dbpkg "github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/version"
)

// versionAffected checks whether the given version is affected by the
// vulnerability described by the given range and explicit-versions JSON.
// It delegates to the shared version package which handles both full OSV
// and flat range formats, and dispatches to ecosystem-specific comparators.
//
// The ecosystem parameter is extracted from the affected_packages row and
// used when the range type is ECOSYSTEM.
func versionAffectedWithEcosystem(ver, versionRangesJSON, versionsJSON, ecosystem string) (bool, error) {
	versionRangesJSON, versionsJSON = dbpkg.NormalizeVersionConstraintJSON(versionRangesJSON, versionsJSON)
	return version.VersionAffected(ver, versionRangesJSON, versionsJSON, ecosystem)
}

// extractFixedVersion returns a user-facing fixed-version constraint for the
// range the installed version actually falls into. Advisories that patched a
// flaw on several major lines carry one range per line, and reporting the
// lowest fix across all of them would name a version below the installed one.
func extractFixedVersion(installed, versionRangesJSON, ecosystem string) string {
	return version.ExtractFixedVersionConstraintFor(installed, versionRangesJSON, ecosystem)
}

// normalizeIntroduced maps "0" to "" (beginning of time) and passes all
// other values through unchanged. Exposed for use by test code.
func normalizeIntroduced(introduced string) string {
	if introduced == "0" {
		return ""
	}
	return introduced
}
