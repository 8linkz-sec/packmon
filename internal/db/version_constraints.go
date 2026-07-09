package db

import "strings"

const emptyVersionConstraintJSON = "[]"

// NormalizeVersionConstraintJSON canonicalizes blank and JSON null version
// constraint fields to empty JSON arrays before version matching.
func NormalizeVersionConstraintJSON(versionRangesJSON, versionsJSON string) (string, string) {
	return normalizeVersionConstraintJSONField(versionRangesJSON), normalizeVersionConstraintJSONField(versionsJSON)
}

func normalizeVersionConstraintJSONField(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return emptyVersionConstraintJSON
	}
	return trimmed
}
