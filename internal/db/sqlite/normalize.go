package sqlite

import "strings"

// normalizePackageName lowercases package names for ecosystems whose package
// identities are case-insensitive. It mirrors the server-side normalization
// used before sync export.
func normalizePackageName(ecosystem, name string) string {
	if strings.EqualFold(ecosystem, "nuget") {
		return strings.ToLower(name)
	}
	return name
}
