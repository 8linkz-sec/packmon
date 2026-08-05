package feed

import "strings"

// ParseLastKnownAffectedClosure parses a GHSA/OSV
// database_specific.last_known_affected_version_range expression (e.g.
// "< 4.1.3" or "<= 2.0.0") and returns the range-closure boundary it
// implies: "< X" closes the range with fixed=X, "<= X" with
// lastAffected=X. Feeds use it to close open-ended ranges whose fix
// boundary is only recorded in database_specific, so version matching and
// fixed-version display do not treat every later release as affected.
func ParseLastKnownAffectedClosure(rangeExpr string) (fixed, lastAffected string, ok bool) {
	for _, part := range strings.Split(rangeExpr, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "<="):
			if version := cleanLastKnownConstraintVersion(strings.TrimPrefix(part, "<=")); version != "" {
				return "", version, true
			}
		case strings.HasPrefix(part, "<"):
			if version := cleanLastKnownConstraintVersion(strings.TrimPrefix(part, "<")); version != "" {
				return version, "", true
			}
		}
	}
	return "", "", false
}

func cleanLastKnownConstraintVersion(version string) string {
	return strings.Trim(strings.TrimSpace(version), "`\"'")
}
