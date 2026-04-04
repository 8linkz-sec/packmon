package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// SwiftPMParser parses Swift Package Manager Package.resolved files (v1 and v2 formats).
type SwiftPMParser struct{}

// swiftResolvedV2 is the v2 format (version field == 2 or 3).
type swiftResolvedV2 struct {
	Version int          `json:"version"`
	Pins    []swiftPinV2 `json:"pins"`
}

type swiftPinV2 struct {
	Identity string       `json:"identity"`
	Location string       `json:"location"`
	State    swiftStateV2 `json:"state"`
}

type swiftStateV2 struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
	Branch   string `json:"branch"`
}

// swiftResolvedV1 is the v1 format (version field == 1).
type swiftResolvedV1 struct {
	Version int           `json:"version"`
	Object  swiftObjectV1 `json:"object"`
}

type swiftObjectV1 struct {
	Pins []swiftPinV1 `json:"pins"`
}

type swiftPinV1 struct {
	Package       string       `json:"package"`
	RepositoryURL string       `json:"repositoryURL"`
	State         swiftStateV1 `json:"state"`
}

type swiftStateV1 struct {
	Version  *string `json:"version"`
	Revision string  `json:"revision"`
	Branch   *string `json:"branch"`
}

// NewSwiftPMParser creates a new SwiftPMParser.
func NewSwiftPMParser() *SwiftPMParser {
	return &SwiftPMParser{}
}

func (p *SwiftPMParser) CanParse(filename string) bool {
	return baseFilename(filename) == "Package.resolved"
}

func (p *SwiftPMParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("swiftpm: reading input: %w", err)
	}

	// Peek at the version field to decide the format.
	var versionProbe struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &versionProbe); err != nil {
		return nil, fmt.Errorf("swiftpm: parsing JSON: %w", err)
	}

	switch versionProbe.Version {
	case 2, 3:
		return parseSwiftV2(data)
	case 1:
		return parseSwiftV1(data)
	default:
		// Attempt v2 as a reasonable default.
		pkgs, v2Err := parseSwiftV2(data)
		if v2Err != nil || len(pkgs) == 0 {
			return pkgs, fmt.Errorf("swiftpm: unsupported Package.resolved version %d", versionProbe.Version)
		}
		return pkgs, nil
	}
}

func parseSwiftV2(data []byte) ([]domain.Package, error) {
	var resolved swiftResolvedV2
	if err := json.Unmarshal(data, &resolved); err != nil {
		return nil, fmt.Errorf("swiftpm v2: parsing JSON: %w", err)
	}

	var (
		packages []domain.Package
		errs     []string
	)

	for _, pin := range resolved.Pins {
		name := pin.Identity
		if name == "" {
			errs = append(errs, fmt.Sprintf("pin with empty identity (location: %s)", pin.Location))
			continue
		}

		version := pin.State.Version
		if version == "" {
			// Branch-based or revision-only pins have no semver version; skip them.
			continue
		}

		packages = append(packages, domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemSwiftPM,
		})
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("swiftpm v2: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}

func parseSwiftV1(data []byte) ([]domain.Package, error) {
	var resolved swiftResolvedV1
	if err := json.Unmarshal(data, &resolved); err != nil {
		return nil, fmt.Errorf("swiftpm v1: parsing JSON: %w", err)
	}

	var (
		packages []domain.Package
		errs     []string
	)

	for _, pin := range resolved.Object.Pins {
		name := pin.Package
		if name == "" {
			errs = append(errs, fmt.Sprintf("pin with empty package name (repo: %s)", pin.RepositoryURL))
			continue
		}

		if pin.State.Version == nil || *pin.State.Version == "" {
			// Branch-based or revision-only pins; skip.
			continue
		}

		packages = append(packages, domain.Package{
			Name:      name,
			Version:   *pin.State.Version,
			Ecosystem: domain.EcosystemSwiftPM,
		})
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("swiftpm v1: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}

func (p *SwiftPMParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemSwiftPM
}
