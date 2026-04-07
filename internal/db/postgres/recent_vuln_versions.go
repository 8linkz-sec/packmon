package postgres

import (
	"encoding/json"
	"fmt"
	"strings"
)

type recentRange struct {
	Type         string             `json:"type"`
	Events       []recentRangeEvent `json:"events"`
	Introduced   string             `json:"introduced"`
	Fixed        string             `json:"fixed"`
	LastAffected string             `json:"last_affected"`
}

type recentRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

func summarizeAffectedVersions(versionRangesJSON, versionsJSON string) string {
	if summary := summarizeRangeClauses(versionRangesJSON); summary != "" {
		return summary
	}
	return summarizeExplicitVersions(versionsJSON)
}

func summarizeRangeClauses(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || raw == "[]" {
		return ""
	}

	var ranges []recentRange
	if err := json.Unmarshal([]byte(raw), &ranges); err != nil {
		return ""
	}

	var clauses []string
	for _, r := range ranges {
		events := r.Events
		if len(events) == 0 && (r.Introduced != "" || r.Fixed != "" || r.LastAffected != "") {
			if r.Introduced != "" {
				events = append(events, recentRangeEvent{Introduced: r.Introduced})
			}
			if r.Fixed != "" {
				events = append(events, recentRangeEvent{Fixed: r.Fixed})
			}
			if r.LastAffected != "" {
				events = append(events, recentRangeEvent{LastAffected: r.LastAffected})
			}
		}

		introduced := ""
		hadIntroduced := false
		for _, event := range events {
			if event.Introduced != "" {
				introduced = normalizeIntroduced(event.Introduced)
				hadIntroduced = true
			}
			if event.Fixed != "" {
				if clause := formatAffectedClause(introduced, event.Fixed, "", hadIntroduced); clause != "" {
					clauses = append(clauses, clause)
				}
				introduced = ""
				hadIntroduced = false
			}
			if event.LastAffected != "" {
				if clause := formatAffectedClause(introduced, "", event.LastAffected, hadIntroduced); clause != "" {
					clauses = append(clauses, clause)
				}
				introduced = ""
				hadIntroduced = false
			}
		}
		if hadIntroduced {
			if clause := formatAffectedClause(introduced, "", "", true); clause != "" {
				clauses = append(clauses, clause)
			}
		}
	}

	if len(clauses) == 0 {
		return ""
	}
	if len(clauses) == 1 {
		return clauses[0]
	}
	return strings.Join(clauses, " or ")
}

func summarizeExplicitVersions(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || raw == "[]" {
		return ""
	}

	var versions []string
	if err := json.Unmarshal([]byte(raw), &versions); err != nil {
		return ""
	}

	out := make([]string, 0, len(versions))
	for _, version := range versions {
		version = strings.TrimSpace(version)
		if version != "" {
			out = append(out, version)
		}
	}
	if len(out) == 0 {
		return ""
	}
	if len(out) <= 3 {
		return strings.Join(out, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(out[:3], ", "), len(out)-3)
}

func formatAffectedClause(introduced, fixed, lastAffected string, hadIntroduced bool) string {
	switch {
	case fixed != "":
		if introduced == "" {
			return "< " + fixed
		}
		return ">= " + introduced + ", < " + fixed
	case lastAffected != "":
		if introduced == "" {
			return "<= " + lastAffected
		}
		return ">= " + introduced + ", <= " + lastAffected
	case hadIntroduced && introduced != "":
		return ">= " + introduced
	default:
		return ""
	}
}
