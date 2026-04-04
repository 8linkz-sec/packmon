package parser

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// HexParser parses Elixir/Erlang mix.lock files.
//
// Each dependency line looks like:
//
//	"package_name": {:hex, :package_name, "1.2.3", "hash", [:mix], [...], "hexpm", "hash"},
//
// We extract the quoted package name key and the version string.
type HexParser struct{}

// mixLockLineRe matches a dependency line in mix.lock.
// It captures the package name (first quoted string) and the version (third quoted string after :hex, :name).
var mixLockLineRe = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)"`)

// NewHexParser creates a new HexParser.
func NewHexParser() *HexParser {
	return &HexParser{}
}

func (p *HexParser) CanParse(filename string) bool {
	return baseFilename(filename) == "mix.lock"
}

func (p *HexParser) Parse(r io.Reader) ([]domain.Package, error) {
	scanner := bufio.NewScanner(r)

	var (
		packages []domain.Package
		errs     []string
	)

	for scanner.Scan() {
		line := scanner.Text()

		matches := mixLockLineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		version := matches[2]

		if name == "" || version == "" {
			errs = append(errs, fmt.Sprintf("empty name or version in line: %.80s", line))
			continue
		}

		packages = append(packages, domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemHex,
		})
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("reading input: %v", err))
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("hex: %s", strings.Join(errs, "; "))
	}

	return packages, retErr
}

func (p *HexParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemHex
}
