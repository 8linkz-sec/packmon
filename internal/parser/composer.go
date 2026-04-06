package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// ComposerParser parses composer.lock files (PHP/Composer ecosystem).
type ComposerParser struct{}

// composerLockFile represents the top-level structure of a composer.lock file.
type composerLockFile struct {
	Packages    []composerPackageEntry `json:"packages"`
	PackagesDev []composerPackageEntry `json:"packages-dev"`
}

// composerPackageEntry represents a single entry in the packages array.
type composerPackageEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func NewComposerParser() *ComposerParser {
	return &ComposerParser{}
}

func (p *ComposerParser) CanParse(filename string) bool {
	return strings.EqualFold(baseFilename(filename), "composer.lock")
}

func (p *ComposerParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemComposer
}

func (p *ComposerParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("composer: reading input: %w", err)
	}

	var lockFile composerLockFile
	if err := json.Unmarshal(data, &lockFile); err != nil {
		return nil, fmt.Errorf("composer: parsing JSON: %w", err)
	}

	var (
		packages []domain.Package
		errs     []string
	)

	allEntries := make([]composerPackageEntry, 0, len(lockFile.Packages)+len(lockFile.PackagesDev))
	allEntries = append(allEntries, lockFile.Packages...)
	allEntries = append(allEntries, lockFile.PackagesDev...)

	seen := make(map[string]struct{})

	for i, entry := range allEntries {
		if entry.Name == "" {
			errs = append(errs, fmt.Sprintf("entry %d: missing name", i))
			continue
		}
		if entry.Version == "" {
			errs = append(errs, fmt.Sprintf("entry %d (%s): missing version", i, entry.Name))
			continue
		}

		// Keep the version exactly as declared in composer.lock. Advisory
		// databases (OSV, GHSA) store Composer versions with the v-prefix,
		// so stripping it would cause mismatches.
		version := entry.Version

		key := strings.ToLower(entry.Name) + "@" + version
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		packages = append(packages, domain.Package{
			Name:      entry.Name,
			Version:   version,
			Ecosystem: domain.EcosystemComposer,
		})
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("composer: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}
