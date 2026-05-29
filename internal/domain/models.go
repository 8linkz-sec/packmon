package domain

// Ecosystem represents a canonical package ecosystem identifier.
// See Phase 0, DE-6 for the full list.
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
)

// Valid reports whether e is one of the canonical supported ecosystems.
func (e Ecosystem) Valid() bool {
	switch e {
	case EcosystemNPM, EcosystemPyPI, EcosystemGo, EcosystemMaven, EcosystemCargo,
		EcosystemNuGet, EcosystemComposer, EcosystemGem, EcosystemPub, EcosystemGitHubActions,
		EcosystemCocoaPods, EcosystemSwiftPM, EcosystemHex, EcosystemCRAN:
		return true
	}
	return false
}

// Package represents a dependency found in a lock file.
type Package struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Dev       bool      `json:"dev,omitempty"`
}

// FindingType distinguishes vulnerability findings from malicious package findings.
type FindingType string

const (
	FindingTypeVulnerability FindingType = "vulnerability"
	FindingTypeMalicious     FindingType = "malicious"
)

// ResourceLink is an external reference associated with a finding.
type ResourceLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// Finding represents a security finding for a package.
type Finding struct {
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Ecosystem    Ecosystem      `json:"ecosystem"`
	Type         FindingType    `json:"type"`
	Severity     Severity       `json:"severity"`
	AdvisoryID   string         `json:"advisory_id,omitempty"`
	Title        string         `json:"title"`
	URL          string         `json:"url,omitempty"`
	Resources    []ResourceLink `json:"resources,omitempty"`
	FixedVersion string         `json:"fixed_version,omitempty"`
	RiskType     string         `json:"risk_type,omitempty"`
	Source       string         `json:"source"`
}
