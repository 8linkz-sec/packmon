package parser

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// GemParser parses Gemfile.lock files (Ruby/Gem ecosystem).
type GemParser struct{}

// gemSpecLine matches lines like "    nokogiri (1.16.5)" in the GEM > specs section.
// The package name is captured in group 1, the version in group 2.
var gemSpecLine = regexp.MustCompile(`^\s{4}(\S+)\s+\(([^)]+)\)$`)

func NewGemParser() *GemParser {
	return &GemParser{}
}

func (p *GemParser) CanParse(filename string) bool {
	return strings.EqualFold(baseFilename(filename), "Gemfile.lock")
}

func (p *GemParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemGem
}

// Parse reads a Gemfile.lock and extracts packages from the GEM > specs section.
//
// Gemfile.lock structure (simplified):
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    actioncable (7.1.3)
//	      actionpack (= 7.1.3)
//	    actionpack (7.1.3)
//	      ...
//	PATH
//	  ...
//	PLATFORMS
//	  ...
//	DEPENDENCIES
//	  ...
//
// Only top-level entries under "specs:" are extracted (4-space indent, not 6+).
func (p *GemParser) Parse(r io.Reader) ([]domain.Package, error) {
	scanner := bufio.NewScanner(r)

	var (
		packages   []domain.Package
		errs       []string
		inGEM      bool
		inSpecs    bool
		lineNumber int
	)

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Detect section boundaries. Sections in Gemfile.lock start at column 0
		// with an uppercase identifier (GEM, PATH, GIT, PLATFORMS, DEPENDENCIES, etc.).
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			// Blank line can appear between sections; reset state.
			inGEM = false
			inSpecs = false
			continue
		}

		// Top-level section header (no leading whitespace).
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inGEM = strings.TrimSpace(line) == "GEM"
			inSpecs = false
			continue
		}

		if inGEM && strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}

		if !inSpecs {
			continue
		}

		// Inside GEM > specs. Only match 4-space-indented lines (top-level gems),
		// not 6+ space lines (which are sub-dependencies).
		matches := gemSpecLine.FindStringSubmatch(line)
		if matches == nil {
			// Could be a sub-dependency line (6-space indent) or other content; skip.
			continue
		}

		name := matches[1]
		version := matches[2]

		if name == "" {
			errs = append(errs, fmt.Sprintf("line %d: empty package name", lineNumber))
			continue
		}
		if version == "" {
			errs = append(errs, fmt.Sprintf("line %d (%s): empty version", lineNumber, name))
			continue
		}

		packages = append(packages, domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemGem,
		})
	}

	if err := scanner.Err(); err != nil {
		scanErr := fmt.Errorf("gem: reading input: %w", err)
		if len(packages) > 0 {
			// Return partial results along with the error.
			return packages, scanErr
		}
		return nil, scanErr
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("gem: %d entries skipped: %s", len(errs), strings.Join(errs, "; "))
	}

	return packages, retErr
}
