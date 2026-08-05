package parser

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
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

// ParserDescriptor describes a parser factory that can be registered in a
// Registry.
type ParserDescriptor struct {
	Name string
	New  func() Parser
}

var builtInParserDescriptors = []ParserDescriptor{
	{Name: "npm-package-lock", New: func() Parser { return NewNPMParser() }},
	{Name: "github-actions", New: func() Parser { return NewActionsParser() }},
	{Name: "yarn-lock", New: func() Parser { return NewYarnParser() }},
	{Name: "pnpm-lock", New: func() Parser { return NewPnpmParser() }},
	{Name: "pipfile-lock", New: func() Parser { return NewPipfileParser() }},
	{Name: "poetry-lock", New: func() Parser { return NewPoetryParser() }},
	{Name: "uv-lock", New: func() Parser { return NewUVParser() }},
	{Name: "requirements", New: func() Parser { return NewRequirementsParser() }},
	{Name: "go-sum", New: func() Parser { return NewGoSumParser() }},
	{Name: "go-mod", New: func() Parser { return NewGoModParser() }},
	{Name: "cargo-lock", New: func() Parser { return NewCargoParser() }},
	{Name: "nuget-packages-lock", New: func() Parser { return NewNuGetParser() }},
	{Name: "composer-lock", New: func() Parser { return NewComposerParser() }},
	{Name: "gemfile-lock", New: func() Parser { return NewGemParser() }},
	{Name: "pubspec-lock", New: func() Parser { return NewPubParser() }},
	{Name: "cocoapods-lock", New: func() Parser { return NewCocoaPodsParser() }},
	{Name: "swiftpm-resolved", New: func() Parser { return NewSwiftPMParser() }},
	{Name: "hex-lock", New: func() Parser { return NewHexParser() }},
	{Name: "cran-renv-lock", New: func() Parser { return NewCRANParser() }},
	{Name: "maven-pom", New: func() Parser { return NewMavenParser() }},
	{Name: "gradle-lockfile", New: func() Parser { return NewGradleParser() }},
}

// BuiltInParserDescriptors returns a copy of the built-in parser descriptors.
func BuiltInParserDescriptors() []ParserDescriptor {
	return append([]ParserDescriptor(nil), builtInParserDescriptors...)
}

// Registry holds registered parsers and resolves the correct parser for a
// given filename.
type Registry struct {
	parsers []Parser
}

// NewRegistry creates a Registry pre-loaded with all built-in parsers and any
// additional parser descriptors passed by the caller.
func NewRegistry(extra ...ParserDescriptor) *Registry {
	r := &Registry{}
	r.RegisterDescriptors(BuiltInParserDescriptors()...)
	r.RegisterDescriptors(extra...)
	return r
}

// RegisterDescriptor instantiates and registers descriptor's parser.
func (r *Registry) RegisterDescriptor(descriptor ParserDescriptor) {
	if descriptor.New == nil {
		return
	}
	parser := descriptor.New()
	if parser == nil {
		return
	}
	r.parsers = append(r.parsers, parser)
}

// RegisterDescriptors instantiates and registers parser descriptors in order.
func (r *Registry) RegisterDescriptors(descriptors ...ParserDescriptor) {
	for _, descriptor := range descriptors {
		r.RegisterDescriptor(descriptor)
	}
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
			domain.MergePackageMetadata(&out[idx], p)
			continue
		}
		seen[k] = len(out)
		out = append(out, p)
	}
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
