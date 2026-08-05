package sqlite

import pkgid "github.com/8linkz-sec/packmon/internal/packageid"

// normalizePackageName canonicalizes package names for ecosystems whose
// package identities are case-insensitive. It mirrors server-side storage
// normalization used before sync export.
func normalizePackageName(ecosystem, name string) string {
	return pkgid.NormalizeName(ecosystem, name)
}
