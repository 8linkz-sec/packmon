package version

import "strings"

// ExtractFixedVersionFor returns the fixed version of the affected range that
// actually contains installed.
//
// ExtractFixedVersion answers a different question: the lowest fix anywhere in
// the advisory. For an advisory that lists one range per major line -- the
// common shape for a flaw that was patched on several branches -- that answer is
// not merely imprecise, it inverts the advice. A user on 5.0.7 told the fix is
// ">= 1.1.18" reads a version far below the one they already run and concludes
// they are patched.
//
// When installed is empty or falls outside every range, this falls back to the
// lowest fix so a finding never loses its hint entirely.
func ExtractFixedVersionFor(installed, versionRangesJSON, ecosystem string) string {
	fallback := ExtractFixedVersion(versionRangesJSON)

	installed = strings.TrimSpace(installed)
	if installed == "" {
		return fallback
	}

	rangesJSON := strings.TrimSpace(versionRangesJSON)
	if rangesJSON == "" || rangesJSON == "null" {
		return fallback
	}
	ranges, err := parseRanges(rangesJSON)
	if err != nil {
		return fallback
	}

	for _, item := range ranges {
		rangeType := item.Type
		// GIT ranges carry commit identifiers, not comparable versions.
		if strings.EqualFold(rangeType, "GIT") {
			continue
		}
		if skipRangeComparisonForVersion(installed, rangeType, ecosystem) {
			continue
		}

		cmp := func(a, b string) int {
			return Compare(a, b, rangeType, ecosystem)
		}

		introduced := ""
		for _, event := range item.Events {
			if event.Introduced != "" {
				introduced = normalizeIntroduced(event.Introduced)
			}
			if event.Fixed == "" && event.LastAffected == "" && event.Limit == "" {
				continue
			}
			if versionInRange(installed, introduced, event.Fixed, event.LastAffected, cmp) && event.Fixed != "" {
				return event.Fixed
			}
			introduced = ""
		}
	}

	return fallback
}

// ExtractFixedVersionConstraintFor formats the version-aware fix as an inclusive
// lower bound, matching ExtractFixedVersionConstraint's output shape.
func ExtractFixedVersionConstraintFor(installed, versionRangesJSON, ecosystem string) string {
	fixed := ExtractFixedVersionFor(installed, versionRangesJSON, ecosystem)
	if fixed == "" {
		return ""
	}
	return ">= " + fixed
}
