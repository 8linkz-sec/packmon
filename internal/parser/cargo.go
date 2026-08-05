package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/BurntSushi/toml"
)

// CargoParser parses Cargo.lock files (Rust/Cargo ecosystem).
type CargoParser struct{}

// cargoLockFile represents the top-level structure of a Cargo.lock file.
type cargoLockFile struct {
	Package []cargoPackageEntry `toml:"package"`
}

// cargoPackageEntry represents a single [[package]] entry in Cargo.lock.
type cargoPackageEntry struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Source  string `toml:"source"`
}

func NewCargoParser() *CargoParser {
	return &CargoParser{}
}

func (p *CargoParser) CanParse(filename string) bool {
	return strings.EqualFold(baseFilename(filename), "Cargo.lock")
}

func (p *CargoParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemCargo
}

func (p *CargoParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("cargo: reading input: %w", err)
	}

	var lockFile cargoLockFile
	if err := toml.Unmarshal(data, &lockFile); err != nil {
		return nil, fmt.Errorf("cargo: parsing TOML: %w", err)
	}

	var (
		packages []domain.Package
		errs     []string
	)

	for i, entry := range lockFile.Package {
		if entry.Name == "" {
			errs = append(errs, fmt.Sprintf("entry %d: missing name", i))
			continue
		}
		if entry.Version == "" {
			errs = append(errs, fmt.Sprintf("entry %d: missing version", i))
			continue
		}

		packages = append(packages, domain.Package{
			Name:       entry.Name,
			Version:    entry.Version,
			Ecosystem:  domain.EcosystemCargo,
			SourceRefs: cleanSourceRefs(entry.Source),
		})
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("cargo: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}
