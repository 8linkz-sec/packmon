package domain

import "strings"

// Ecosystem represents a canonical package ecosystem identifier.
// The constants below are the supported ecosystem values accepted across parser,
// scanner, API, and database boundaries.
type Ecosystem string

const (
	EcosystemNPM           Ecosystem = "npm"
	EcosystemPyPI          Ecosystem = "pypi"
	EcosystemGo            Ecosystem = "go"
	EcosystemMaven         Ecosystem = "maven"
	EcosystemCargo         Ecosystem = "cargo"
	EcosystemNuGet         Ecosystem = "nuget"
	EcosystemComposer      Ecosystem = "composer"
	EcosystemGem           Ecosystem = "gem"
	EcosystemPub           Ecosystem = "pub"
	EcosystemGitHubActions Ecosystem = "actions"
	EcosystemCocoaPods     Ecosystem = "cocoapods"
	EcosystemSwiftPM       Ecosystem = "swiftpm"
	EcosystemHex           Ecosystem = "hex"
	EcosystemCRAN          Ecosystem = "cran"
	EcosystemDocker        Ecosystem = "docker"
)

// Valid reports whether e is one of the canonical supported ecosystems.
func (e Ecosystem) Valid() bool {
	switch e {
	case EcosystemNPM, EcosystemPyPI, EcosystemGo, EcosystemMaven, EcosystemCargo,
		EcosystemNuGet, EcosystemComposer, EcosystemGem, EcosystemPub, EcosystemGitHubActions,
		EcosystemCocoaPods, EcosystemSwiftPM, EcosystemHex, EcosystemCRAN, EcosystemDocker:
		return true
	}
	return false
}

// Package represents a dependency found in a lock file.
type Package struct {
	// Name is the package name or package coordinate in its ecosystem's
	// canonical form.
	Name string `json:"name"`
	// Version is the resolved installed version from the lockfile, SBOM, or
	// inventory source.
	Version string `json:"version"`
	// Ecosystem is the canonical package ecosystem identifier.
	Ecosystem Ecosystem `json:"ecosystem"`
	// Dev marks packages that belong to a development or test dependency scope.
	Dev bool `json:"dev,omitempty"`
	// Direct marks packages that are direct/root dependencies.
	Direct bool `json:"direct,omitempty"`
	// Indirect marks packages that are transitive dependencies.
	Indirect bool `json:"indirect,omitempty"`
	// Optional marks packages reached through optional dependency edges.
	Optional bool `json:"optional,omitempty"`
	// Peer marks packages reached through peer dependency edges.
	Peer bool `json:"peer,omitempty"`
	// Via contains root or ancestor package names that explain how this package
	// was reached in graph-aware inventories.
	Via []string `json:"via,omitempty"`
	// Parents identifies immediate dependency parents when the source provides
	// graph metadata.
	Parents []PackageParent `json:"parents,omitempty"`
	// SourceRefs records lockfile/SBOM source provenance used for local egress
	// decisions such as outdated checks. It is intentionally not serialized in
	// scan requests, scan results, or webhooks.
	SourceRefs []string `json:"-"`
}

// PackageParent identifies an immediate dependency parent for graph-aware
// package metadata such as npm wanted-version range evaluation.
type PackageParent struct {
	// Name is the immediate parent package name.
	Name string `json:"name"`
	// Version is the immediate parent version when the source provides it.
	Version string `json:"version,omitempty"`
	// Ecosystem is the immediate parent ecosystem when known.
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
}

// FindingType distinguishes vulnerability, malicious, supply-chain, and lifecycle findings.
type FindingType string

const (
	FindingTypeVulnerability   FindingType = "vulnerability"
	FindingTypeMalicious       FindingType = "malicious"
	FindingTypeSupplyChainRisk FindingType = "supply_chain_risk"
	FindingTypeLifecycle       FindingType = "lifecycle"
)

const (
	// RiskTypeMalwareHistory is the stable public risk_type for historical
	// malware reputation evidence.
	RiskTypeMalwareHistory = "malware_history"
)

const (
	// ManualAdvisorySource is the canonical source value for operator-managed
	// manual advisories in findings and persistence records.
	ManualAdvisorySource = "manual"
	// ManualAdvisoryIDPrefix is the reserved namespace for operator-managed
	// manual advisory IDs.
	ManualAdvisoryIDPrefix = ManualAdvisorySource + ":"
)

// ParseManualAdvisoryFindingType normalizes the operator-managed advisory
// finding types accepted by admin forms and store mutation boundaries.
func ParseManualAdvisoryFindingType(raw string) (FindingType, bool) {
	switch value := strings.ToLower(strings.TrimSpace(raw)); value {
	case "", string(FindingTypeVulnerability):
		return FindingTypeVulnerability, true
	case string(FindingTypeMalicious):
		return FindingTypeMalicious, true
	default:
		return "", false
	}
}

// NormalizeManualAdvisoryID trims an operator-managed advisory ID and reports
// whether it is in the reserved manual advisory namespace. The original ID
// casing is preserved for compatibility with existing store behavior.
func NormalizeManualAdvisoryID(raw string) (string, bool) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" || !strings.HasPrefix(strings.ToLower(normalized), ManualAdvisoryIDPrefix) {
		return "", false
	}
	return normalized, true
}

// IsManualAdvisoryID reports whether raw is in the reserved manual advisory
// namespace.
func IsManualAdvisoryID(raw string) bool {
	_, ok := NormalizeManualAdvisoryID(raw)
	return ok
}

// ResourceLink is an external reference associated with a finding.
type ResourceLink struct {
	// Label is the human-readable link label.
	Label string `json:"label"`
	// URL is the external reference URL.
	URL string `json:"url"`
}

// FindingLocation identifies a local input artifact that produced a finding.
// It is intentionally not serialized in the public scan-result JSON contract.
type FindingLocation struct {
	// URI is a local artifact URI/path used by local report formats. It is
	// privacy-sensitive and must not be serialized in public scan-result JSON.
	URI string
}

// Finding represents a security finding for a package.
type Finding struct {
	// Name is the affected package name or coordinate.
	Name string `json:"name"`
	// Version is the affected installed package version.
	Version string `json:"version"`
	// Ecosystem is the affected package ecosystem.
	Ecosystem Ecosystem `json:"ecosystem"`
	// Type is the public finding category: vulnerability, malicious,
	// supply_chain_risk, or lifecycle.
	Type FindingType `json:"type"`
	// Severity is the normalized policy severity exposed to clients.
	Severity Severity `json:"severity"`
	// AdvisoryID is the source advisory or finding identifier when available.
	AdvisoryID string `json:"advisory_id,omitempty"`
	// Title is the short user-facing finding title or summary.
	Title string `json:"title"`
	// URL is the primary external advisory/reference URL when available.
	URL string `json:"url,omitempty"`
	// Resources are additional source references associated with the finding.
	Resources []ResourceLink `json:"resources,omitempty"`
	// FixedVersion is the vulnerability fix constraint when the source provides
	// one, for example ">= 1.2.3".
	FixedVersion string `json:"fixed_version,omitempty"`
	// RiskType is the source-specific threat or lifecycle category. Known public
	// values include malware, typosquatting, supply_chain, removed_package,
	// malware_history (RiskTypeMalwareHistory), eol, eol_soon,
	// security_support_only, and other.
	RiskType string `json:"risk_type,omitempty"`
	// Source is the finding source such as osv, ghsa, vulncheck, openssf,
	// socket, reversinglabs, endoflife.date, or manual.
	Source string `json:"source"`
	// Locations contains local artifact locations for report formats. It is
	// intentionally not serialized in public scan-result JSON.
	Locations []FindingLocation `json:"-"`
}
