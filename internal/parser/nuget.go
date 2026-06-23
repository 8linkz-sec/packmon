package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// NuGetParser parses packages.lock.json files (NuGet/.NET ecosystem).
type NuGetParser struct{}

// nugetLockFile represents the top-level structure of packages.lock.json.
// The "dependencies" key maps target framework monikers (e.g. "net8.0") to
// a map of package name -> package metadata.
type nugetLockFile struct {
	Version      int                                     `json:"version"`
	Dependencies map[string]map[string]nugetPackageEntry `json:"dependencies"`
}

// nugetPackageEntry represents a single package entry inside a framework group.
type nugetPackageEntry struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

func NewNuGetParser() *NuGetParser {
	return &NuGetParser{}
}

func (p *NuGetParser) CanParse(filename string) bool {
	return strings.EqualFold(baseFilename(filename), "packages.lock.json")
}

func (p *NuGetParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemNuGet
}

func (p *NuGetParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("nuget: reading input: %w", err)
	}

	var lockFile nugetLockFile
	if err := json.Unmarshal(data, &lockFile); err != nil {
		return nil, fmt.Errorf("nuget: parsing JSON: %w", err)
	}

	// Use a set to deduplicate packages that appear across multiple target frameworks.
	type pkgKey struct {
		name    string
		version string
	}
	seen := make(map[pkgKey]struct{})

	var (
		packages []domain.Package
		errs     []string
	)

	for framework, deps := range lockFile.Dependencies {
		for name, entry := range deps {
			if name == "" {
				errs = append(errs, fmt.Sprintf("framework %s: empty package name", framework))
				continue
			}
			if nugetEntryIsProjectReference(entry.Type) {
				continue
			}
			if entry.Resolved == "" {
				errs = append(errs, fmt.Sprintf("framework %s: missing resolved version", framework))
				continue
			}

			key := pkgKey{name: strings.ToLower(name), version: entry.Resolved}
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			packages = append(packages, domain.Package{
				Name:      name,
				Version:   entry.Resolved,
				Ecosystem: domain.EcosystemNuGet,
			})
		}
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("nuget: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}

func nugetEntryIsProjectReference(entryType string) bool {
	entryType = strings.ToLower(strings.TrimSpace(entryType))
	return entryType == "project" || entryType == "projectreference"
}
