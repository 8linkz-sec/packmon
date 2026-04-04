package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// CRANParser parses R renv.lock files.
//
// The file is JSON with a top-level "Packages" object where each key is a
// package name and the value has a "Version" field:
//
//	{
//	  "R": { "Version": "4.3.1" },
//	  "Packages": {
//	    "dplyr": { "Package": "dplyr", "Version": "1.1.4", ... },
//	    "ggplot2": { "Package": "ggplot2", "Version": "3.4.4", ... }
//	  }
//	}
type CRANParser struct{}

// renvLock represents the top-level structure of an renv.lock file.
type renvLock struct {
	Packages map[string]renvPackage `json:"Packages"`
}

// renvPackage represents a single package entry in renv.lock.
type renvPackage struct {
	Package    string `json:"Package"`
	Version    string `json:"Version"`
	Source     string `json:"Source"`
	Repository string `json:"Repository"`
}

// NewCRANParser creates a new CRANParser.
func NewCRANParser() *CRANParser {
	return &CRANParser{}
}

func (p *CRANParser) CanParse(filename string) bool {
	return baseFilename(filename) == "renv.lock"
}

func (p *CRANParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("cran: reading input: %w", err)
	}

	var lock renvLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("cran: parsing JSON: %w", err)
	}

	if len(lock.Packages) == 0 {
		return nil, nil
	}

	var (
		packages []domain.Package
		errs     []string
	)

	for name, pkg := range lock.Packages {
		version := pkg.Version
		if version == "" {
			errs = append(errs, fmt.Sprintf("package %q: empty version", name))
			continue
		}

		packages = append(packages, domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemCRAN,
		})
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("cran: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}

func (p *CRANParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemCRAN
}
