package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// PubParser parses Dart/Flutter pubspec.lock files.
type PubParser struct{}

// pubspecLock represents the top-level structure of a pubspec.lock file.
type pubspecLock struct {
	Packages map[string]pubspecPackage `yaml:"packages"`
}

// pubspecPackage represents a single package entry in pubspec.lock.
type pubspecPackage struct {
	Version string `yaml:"version"`
}

// NewPubParser creates a new PubParser.
func NewPubParser() *PubParser {
	return &PubParser{}
}

func (p *PubParser) CanParse(filename string) bool {
	return baseFilename(filename) == "pubspec.lock"
}

func (p *PubParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("pub: reading input: %w", err)
	}

	var lock pubspecLock
	if err := yamlUnmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("pub: parsing YAML: %w", err)
	}

	if len(lock.Packages) == 0 {
		return nil, nil
	}

	var (
		packages []domain.Package
		errs     []string
	)

	for name, pkg := range lock.Packages {
		version := strings.TrimSpace(pkg.Version)
		if version == "" {
			errs = append(errs, fmt.Sprintf("package %q: empty version", name))
			continue
		}

		packages = append(packages, domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemPub,
		})
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("pub: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}

func (p *PubParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemPub
}
