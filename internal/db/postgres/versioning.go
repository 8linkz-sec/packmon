package postgres

import (
	"encoding/json"
	"strings"
)

type osvRange struct {
	Type   string          `json:"type"`
	Events []osvRangeEvent `json:"events"`
}

type osvRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

func versionAffected(version, versionRangesJSON, versionsJSON string) (bool, error) {
	var ranges []osvRange
	if strings.TrimSpace(versionRangesJSON) != "" && strings.TrimSpace(versionRangesJSON) != "null" {
		if err := json.Unmarshal([]byte(versionRangesJSON), &ranges); err != nil {
			return true, err
		}
	}

	if len(ranges) > 0 {
		for _, item := range ranges {
			introduced := ""
			for _, event := range item.Events {
				if event.Introduced != "" {
					introduced = normalizeIntroduced(event.Introduced)
				}
				if event.Fixed == "" && event.LastAffected == "" {
					continue
				}
				if versionInRange(version, introduced, event.Fixed, event.LastAffected) {
					return true, nil
				}
				introduced = ""
			}
			if introduced != "" && compareVersions(version, introduced) >= 0 {
				return true, nil
			}
		}
	}

	var versions []string
	if strings.TrimSpace(versionsJSON) != "" && strings.TrimSpace(versionsJSON) != "null" {
		if err := json.Unmarshal([]byte(versionsJSON), &versions); err != nil {
			return true, err
		}
		for _, candidate := range versions {
			if candidate == version {
				return true, nil
			}
		}
	}

	if len(ranges) == 0 && len(versions) == 0 {
		return true, nil
	}

	return false, nil
}

func versionInRange(version, introduced, fixed, lastAffected string) bool {
	if introduced != "" && compareVersions(version, introduced) < 0 {
		return false
	}
	if fixed != "" && compareVersions(version, fixed) >= 0 {
		return false
	}
	if lastAffected != "" && compareVersions(version, lastAffected) > 0 {
		return false
	}
	return true
}

func extractFixedVersion(versionRangesJSON string) string {
	if strings.TrimSpace(versionRangesJSON) == "" || strings.TrimSpace(versionRangesJSON) == "null" {
		return ""
	}

	var ranges []osvRange
	if err := json.Unmarshal([]byte(versionRangesJSON), &ranges); err != nil {
		return ""
	}

	best := ""
	for _, item := range ranges {
		for _, event := range item.Events {
			if event.Fixed == "" {
				continue
			}
			if best == "" || compareVersions(event.Fixed, best) < 0 {
				best = event.Fixed
			}
		}
	}
	return best
}

func normalizeIntroduced(introduced string) string {
	if introduced == "0" {
		return ""
	}
	return introduced
}

func compareVersions(a, b string) int {
	// Strip build metadata (semver: everything after '+' is ignored).
	if idx := strings.IndexByte(a, '+'); idx >= 0 {
		a = a[:idx]
	}
	if idx := strings.IndexByte(b, '+'); idx >= 0 {
		b = b[:idx]
	}

	// Separate release from pre-release at the first hyphen that follows
	// at least one dot-separated segment. For "1.2.3-rc1" this yields
	// release="1.2.3", pre="rc1".
	releaseA, preA := splitPrerelease(a)
	releaseB, preB := splitPrerelease(b)

	// Compare release segments numerically.
	partsA := strings.Split(releaseA, ".")
	partsB := strings.Split(releaseB, ".")

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

		numA := parseVersionSegment(segA)
		numB := parseVersionSegment(segB)
		if numA < numB {
			return -1
		}
		if numA > numB {
			return 1
		}
	}

	// Release parts are equal. Apply semver pre-release rules:
	// a version WITHOUT a pre-release tag is GREATER than one WITH.
	if preA == "" && preB == "" {
		return 0
	}
	if preA == "" {
		return 1 // 1.0.0 > 1.0.0-rc1
	}
	if preB == "" {
		return -1 // 1.0.0-rc1 < 1.0.0
	}

	// Both have pre-release identifiers: compare dot-separated sub-segments.
	return comparePrerelease(preA, preB)
}

// splitPrerelease splits a version string into its release and pre-release
// parts. The first hyphen that appears after at least one character is used
// as the separator. Returns (release, prerelease) where prerelease is ""
// if there is no pre-release suffix.
func splitPrerelease(version string) (string, string) {
	if idx := strings.IndexByte(version, '-'); idx > 0 {
		return version[:idx], version[idx+1:]
	}
	return version, ""
}

// comparePrerelease compares two pre-release strings per semver 2.0
// rules: identifiers are compared left to right, numeric identifiers
// are compared as integers, string identifiers are compared
// lexicographically, and numeric identifiers always sort before string
// identifiers.
func comparePrerelease(a, b string) int {
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

// isNumeric returns true and the parsed value if s is composed entirely
// of ASCII digits.
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

func parseVersionSegment(segment string) int {
	value := 0
	for _, ch := range segment {
		if ch < '0' || ch > '9' {
			break
		}
		value = value*10 + int(ch-'0')
	}
	return value
}
