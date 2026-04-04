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

		numA := parseVersionSegment(segA)
		numB := parseVersionSegment(segB)
		if numA < numB {
			return -1
		}
		if numA > numB {
			return 1
		}
		if segA < segB {
			return -1
		}
		if segA > segB {
			return 1
		}
	}
	return 0
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
