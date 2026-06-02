package parser

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// Parser is the interface for lock-file parsers. Each implementation handles
// one or more lock-file formats for a specific ecosystem.
type Parser interface {
	// CanParse reports whether this parser handles the given filename.
	// The filename should be the base name of the file (no directory prefix).
	CanParse(filename string) bool

	// Parse reads a lock file from r and returns the packages it contains.
	// Implementations should return partial results together with an error
	// when parts of the input are malformed.
	Parse(r io.Reader) ([]domain.Package, error)

	// Ecosystem returns the canonical ecosystem identifier for this parser.
	Ecosystem() domain.Ecosystem
}

// Registry holds registered parsers and resolves the correct parser for a
// given filename.
type Registry struct {
	parsers []Parser
}

// NewRegistry creates a Registry pre-loaded with all built-in parsers.
func NewRegistry() *Registry {
	return &Registry{
		parsers: []Parser{
			NewNPMParser(),
			NewActionsParser(),
			NewYarnParser(),
			NewPnpmParser(),
			NewPipfileParser(),
			NewPoetryParser(),
			NewUVParser(),
			NewRequirementsParser(),
			NewGoSumParser(),
			NewGoModParser(),
			NewCargoParser(),
			NewNuGetParser(),
			NewComposerParser(),
			NewGemParser(),
			NewPubParser(),
			NewCocoaPodsParser(),
			NewSwiftPMParser(),
			NewHexParser(),
			NewCRANParser(),
			NewMavenParser(),
			NewGradleParser(),
		},
	}
}

// Register adds a custom parser to the registry. It is appended after the
// built-in parsers, so built-in parsers take precedence.
func (r *Registry) Register(p Parser) {
	r.parsers = append(r.parsers, p)
}

// ParserFor returns the first parser whose CanParse returns true for the
// given path. Path-aware parsers can inspect directories; legacy filename
// parsers still receive the base name as a fallback.
// Returns nil if no parser matches.
func (r *Registry) ParserFor(path string) Parser {
	base := filepath.Base(path)
	for _, p := range r.parsers {
		if p.CanParse(path) || (base != path && p.CanParse(base)) {
			return p
		}
	}
	return nil
}

// AllParsers returns a copy of the registered parsers slice.
func (r *Registry) AllParsers() []Parser {
	out := make([]Parser, len(r.parsers))
	copy(out, r.parsers)
	return out
}

// SupportedFiles returns a deduplicated list of file names that the registry
// can parse. Useful for FileWalker configuration.
func (r *Registry) SupportedFiles() []string {
	known := []string{
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"Pipfile.lock",
		"poetry.lock",
		"uv.lock",
		"requirements.txt",
		"go.sum",
		"go.mod",
		"Cargo.lock",
		"packages.lock.json",
		"composer.lock",
		"Gemfile.lock",
		"pubspec.lock",
		"Podfile.lock",
		"Package.resolved",
		"mix.lock",
		"renv.lock",
		"pom.xml",
		"gradle.lockfile",
		".github/workflows/*.yml",
		".github/workflows/*.yaml",
	}
	return known
}

// dedup returns a new slice with duplicate packages removed. Two packages are
// considered duplicates when name, version, and ecosystem all match. If a
// package appears as both production and development dependency, keep the
// production classification.
func dedup(pkgs []domain.Package) []domain.Package {
	type key struct {
		name      string
		version   string
		ecosystem domain.Ecosystem
	}
	seen := make(map[key]int, len(pkgs))
	out := make([]domain.Package, 0, len(pkgs))
	for _, p := range pkgs {
		k := key{p.Name, p.Version, p.Ecosystem}
		if idx, ok := seen[k]; ok {
			mergePackageMetadata(&out[idx], p)
			continue
		}
		seen[k] = len(out)
		out = append(out, p)
	}
	return out
}

func mergePackageMetadata(dst *domain.Package, src domain.Package) {
	if dst.Dev && !src.Dev {
		dst.Dev = false
	}
	dst.Direct = dst.Direct || src.Direct
	dst.Indirect = dst.Indirect || src.Indirect
	dst.Optional = dst.Optional || src.Optional
	dst.Peer = dst.Peer || src.Peer
	dst.Via = mergeStringSet(dst.Via, src.Via)
}

func mergeStringSet(left, right []string) []string {
	if len(left) == 0 && len(right) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range left {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	for _, value := range right {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// joinErrors combines multiple errors into a single error. Returns nil when
// the slice is empty.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return fmt.Errorf("%s", strings.Join(msgs, "; "))
}
