package dockerimage

import "github.com/8linkz-sec/packmon/internal/domain"

// SourceType identifies the repository file type that contributed a Docker
// inventory row.
type SourceType string

const (
	// SourceDockerfile marks image references parsed from Dockerfile FROM lines.
	SourceDockerfile SourceType = "dockerfile"
	// SourceCompose marks image references parsed from Compose services.
	SourceCompose SourceType = "compose"
)

// Image is a report-only Docker image inventory row. Packmon represents it as
// domain.EcosystemDocker for list-all output, but normal server scan requests do
// not accept Docker packages for vulnerability or malware checks.
type Image struct {
	// Ref is the normalized image reference parsed from the source file.
	Ref Ref
	// SourceFile is the repository-relative Dockerfile or Compose file path.
	SourceFile string
	// SourceType records whether the row came from a Dockerfile or Compose file.
	SourceType SourceType
	// Scope names the Docker stage or Compose service that referenced the image.
	Scope string
	// Relation describes how the image is used, such as base image or service image.
	Relation string
	// Direct marks images referenced directly in scanned source files.
	Direct bool
	// Indirect marks images inferred from related Docker metadata.
	Indirect bool
	// LocalBuild marks Compose services that build locally instead of pulling by ref.
	LocalBuild bool
	// Flags carries display-only annotations for reports.
	Flags []string
}

// Package converts the Docker inventory row into a domain package for local
// report aggregation only. The returned Docker package must not be submitted to
// /api/v1/check as a server-side vulnerability-scan input.
func (i Image) Package() domain.Package {
	return domain.Package{
		Name:      i.Ref.Name,
		Version:   i.Ref.Reference,
		Ecosystem: domain.EcosystemDocker,
		Direct:    i.Direct,
		Indirect:  i.Indirect,
	}
}
