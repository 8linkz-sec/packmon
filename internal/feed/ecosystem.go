package feed

import (
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// MapOSVEcosystem maps an OSV ecosystem string to our canonical Ecosystem
// enum. OSV uses title-case names like "npm", "PyPI", "Go", etc.
// Returns the mapped ecosystem and true if recognised, or "" and false
// if the ecosystem is not supported by Packmon.
func MapOSVEcosystem(osv string) (domain.Ecosystem, bool) {
	eco, ok := osvEcosystemMap[strings.ToLower(osv)]
	return eco, ok
}

// osvEcosystemMap maps lowercased OSV ecosystem names to Packmon canonical
// ecosystem values. OSV sometimes appends a scope suffix (e.g. "Maven:org.apache")
// which callers should strip before looking up.
var osvEcosystemMap = map[string]domain.Ecosystem{
	"npm":            domain.EcosystemNPM,
	"pypi":           domain.EcosystemPyPI,
	"go":             domain.EcosystemGo,
	"maven":          domain.EcosystemMaven,
	"crates.io":      domain.EcosystemCargo,
	"nuget":          domain.EcosystemNuGet,
	"packagist":      domain.EcosystemComposer,
	"rubygems":       domain.EcosystemGem,
	"pub":            domain.EcosystemPub,
	"cocoapods":      domain.EcosystemCocoaPods,
	"swifturl":       domain.EcosystemSwiftPM,
	"hex":            domain.EcosystemHex,
	"cran":           domain.EcosystemCRAN,
	"github actions": domain.EcosystemGitHubActions,
	"cargo":          domain.EcosystemCargo, // alias used by some sources
	"composer":       domain.EcosystemComposer,
	"gem":            domain.EcosystemGem,
}

// MapGHSAEcosystem maps a GHSA ecosystem string (from the advisory JSON
// "ecosystem" field) to our canonical Ecosystem enum. GHSA uses names
// like "npm", "pip", "go", "maven", "nuget", "composer", "rubygems",
// "crates.io", "pub", "hex", and now also "GitHub Actions".
func MapGHSAEcosystem(ghsa string) (domain.Ecosystem, bool) {
	eco, ok := ghsaEcosystemMap[strings.ToLower(ghsa)]
	return eco, ok
}

var ghsaEcosystemMap = map[string]domain.Ecosystem{
	"npm":            domain.EcosystemNPM,
	"pip":            domain.EcosystemPyPI,
	"pypi":           domain.EcosystemPyPI,
	"go":             domain.EcosystemGo,
	"maven":          domain.EcosystemMaven,
	"nuget":          domain.EcosystemNuGet,
	"composer":       domain.EcosystemComposer,
	"packagist":      domain.EcosystemComposer,
	"rubygems":       domain.EcosystemGem,
	"crates.io":      domain.EcosystemCargo,
	"pub":            domain.EcosystemPub,
	"swifturl":       domain.EcosystemSwiftPM,
	"hex":            domain.EcosystemHex,
	"actions":        domain.EcosystemGitHubActions,
	"github actions": domain.EcosystemGitHubActions,
	"rust":           domain.EcosystemCargo,
	"cargo":          domain.EcosystemCargo,
}

// MapOpenSSFEcosystem maps an OpenSSF malicious-packages ecosystem string
// to our canonical Ecosystem enum. OpenSSF commonly uses directory names like
// "npm", "pypi", "crates.io", and "nuget"; aliases are accepted when entries
// use OSV/GHSA-style names.
func MapOpenSSFEcosystem(openssf string) (domain.Ecosystem, bool) {
	eco, ok := openssfEcosystemMap[strings.ToLower(openssf)]
	return eco, ok
}

var openssfEcosystemMap = map[string]domain.Ecosystem{
	"npm":            domain.EcosystemNPM,
	"pypi":           domain.EcosystemPyPI,
	"pip":            domain.EcosystemPyPI,
	"go":             domain.EcosystemGo,
	"maven":          domain.EcosystemMaven,
	"crates.io":      domain.EcosystemCargo,
	"cargo":          domain.EcosystemCargo,
	"rust":           domain.EcosystemCargo,
	"nuget":          domain.EcosystemNuGet,
	"packagist":      domain.EcosystemComposer,
	"composer":       domain.EcosystemComposer,
	"rubygems":       domain.EcosystemGem,
	"gem":            domain.EcosystemGem,
	"pub":            domain.EcosystemPub,
	"hex":            domain.EcosystemHex,
	"cocoapods":      domain.EcosystemCocoaPods,
	"swifturl":       domain.EcosystemSwiftPM,
	"cran":           domain.EcosystemCRAN,
	"actions":        domain.EcosystemGitHubActions,
	"github actions": domain.EcosystemGitHubActions,
}

// OSVBucketEcosystems returns the list of OSV ecosystem names (as used
// in the GCS bucket path) that Packmon supports. These are the directory
// names under gs://osv-vulnerabilities/.
func OSVBucketEcosystems() []string {
	return []string{
		"npm",
		"PyPI",
		"Go",
		"Maven",
		"crates.io",
		"NuGet",
		"Packagist",
		"RubyGems",
		"Pub",
		"CocoaPods",
		"SwiftURL",
		"Hex",
		"CRAN",
		"GitHub Actions",
	}
}
