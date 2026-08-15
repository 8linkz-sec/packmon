// Package chocolatey collects a metadata-only inventory of Chocolatey packages
// declared in a repository: FLARE-VM / VM-Packages style `config.xml`
// package lists and `choco install|upgrade` command lines in Windows scripts.
//
// The inventory feeds `packmon scan --list-all` reports only. Chocolatey rows
// are never sent to /api/v1/check and never take part in vulnerability or
// malicious-package matching (see domain.Ecosystem.InventoryOnly).
package chocolatey

import "github.com/8linkz-sec/packmon/internal/domain"

// SourceType identifies the repository file type that contributed a
// Chocolatey inventory row.
type SourceType string

const (
	// SourceConfigXML marks packages declared in a `<config><packages>`
	// XML package list (FLARE-VM / VM-Packages format).
	SourceConfigXML SourceType = "config.xml"
	// SourceChocoInstall marks packages named on a `choco install|upgrade`
	// (or `cinst`/`cup`) command line inside a script.
	SourceChocoInstall SourceType = "choco-install"
)

// FlagUnpinned marks inventory rows without a declared version.
const FlagUnpinned = "unpinned"

// Package is a report-only Chocolatey inventory row.
type Package struct {
	// Name is the lowercase Chocolatey package ID.
	Name string
	// Version is the declared version, or "" when the source installs latest.
	Version string
	// SourceFile is the repository-relative source path (slash separated).
	SourceFile string
	// SourceType records which kind of source declared the package.
	SourceType SourceType
	// Flags carries display-only annotations for reports.
	Flags []string
}

// Package converts the inventory row into a domain package for local report
// aggregation only. It must not be submitted to /api/v1/check.
func (p Package) Package() domain.Package {
	return domain.Package{
		Name:      p.Name,
		Version:   p.Version,
		Ecosystem: domain.EcosystemChocolatey,
		Direct:    true,
	}
}
