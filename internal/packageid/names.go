package packageid

import (
	"regexp"
	"strings"
)

var pypiSeparatorRun = regexp.MustCompile(`[-_.]+`)

// NormalizeName returns Packmon's canonical package identity for ecosystems
// whose package registries define case-insensitive names.
func NormalizeName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "actions", "github actions":
		return strings.ToLower(name)
	case "nuget":
		return strings.ToLower(name)
	case "pypi":
		return pypiSeparatorRun.ReplaceAllString(strings.ToLower(name), "-")
	default:
		return name
	}
}
