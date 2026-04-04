package parser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/BurntSushi/toml"
)

// ---------------------------------------------------------------------------
// Pipfile.lock (pipenv)
// ---------------------------------------------------------------------------

// PipfileParser handles Pipfile.lock files.
type PipfileParser struct{}

// NewPipfileParser returns a parser for Pipfile.lock.
func NewPipfileParser() *PipfileParser { return &PipfileParser{} }

func (p *PipfileParser) CanParse(filename string) bool {
	return filename == "Pipfile.lock"
}

func (p *PipfileParser) Ecosystem() domain.Ecosystem { return domain.EcosystemPyPI }

// pipfileLock models the JSON structure of Pipfile.lock.
type pipfileLock struct {
	Default map[string]pipfilePkg `json:"default"`
	Develop map[string]pipfilePkg `json:"develop"`
}

type pipfilePkg struct {
	Version string `json:"version"`
}

func (p *PipfileParser) Parse(r io.Reader) ([]domain.Package, error) {
	var lock pipfileLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("pipfile: invalid JSON: %w", err)
	}

	var pkgs []domain.Package

	for name, entry := range lock.Default {
		v := normalizePyVersion(entry.Version)
		if v == "" {
			continue
		}
		pkgs = append(pkgs, domain.Package{
			Name:      normalizePyName(name),
			Version:   v,
			Ecosystem: domain.EcosystemPyPI,
		})
	}

	for name, entry := range lock.Develop {
		v := normalizePyVersion(entry.Version)
		if v == "" {
			continue
		}
		pkgs = append(pkgs, domain.Package{
			Name:      normalizePyName(name),
			Version:   v,
			Ecosystem: domain.EcosystemPyPI,
		})
	}

	return dedup(pkgs), nil
}

// ---------------------------------------------------------------------------
// poetry.lock (Poetry)
// ---------------------------------------------------------------------------

// PoetryParser handles poetry.lock files (TOML).
type PoetryParser struct{}

// NewPoetryParser returns a parser for poetry.lock.
func NewPoetryParser() *PoetryParser { return &PoetryParser{} }

func (p *PoetryParser) CanParse(filename string) bool {
	return filename == "poetry.lock"
}

func (p *PoetryParser) Ecosystem() domain.Ecosystem { return domain.EcosystemPyPI }

// poetryLock is the top-level TOML structure of poetry.lock.
type poetryLock struct {
	Package []poetryPkg `toml:"package"`
}

type poetryPkg struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

func (p *PoetryParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("poetry: read error: %w", err)
	}

	var lock poetryLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("poetry: invalid TOML: %w", err)
	}

	pkgs := make([]domain.Package, 0, len(lock.Package))
	for _, entry := range lock.Package {
		if entry.Name == "" || entry.Version == "" {
			continue
		}
		pkgs = append(pkgs, domain.Package{
			Name:      normalizePyName(entry.Name),
			Version:   entry.Version,
			Ecosystem: domain.EcosystemPyPI,
		})
	}

	return dedup(pkgs), nil
}

// ---------------------------------------------------------------------------
// uv.lock
// ---------------------------------------------------------------------------

// UVParser handles uv.lock files (TOML).
type UVParser struct{}

// NewUVParser returns a parser for uv.lock.
func NewUVParser() *UVParser { return &UVParser{} }

func (p *UVParser) CanParse(filename string) bool {
	return filename == "uv.lock"
}

func (p *UVParser) Ecosystem() domain.Ecosystem { return domain.EcosystemPyPI }

// uvLock is the top-level TOML structure of uv.lock.
type uvLock struct {
	Package []uvPkg `toml:"package"`
}

type uvPkg struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

func (p *UVParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("uv: read error: %w", err)
	}

	var lock uvLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("uv: invalid TOML: %w", err)
	}

	pkgs := make([]domain.Package, 0, len(lock.Package))
	for _, entry := range lock.Package {
		if entry.Name == "" || entry.Version == "" {
			continue
		}
		pkgs = append(pkgs, domain.Package{
			Name:      normalizePyName(entry.Name),
			Version:   entry.Version,
			Ecosystem: domain.EcosystemPyPI,
		})
	}

	return dedup(pkgs), nil
}

// ---------------------------------------------------------------------------
// requirements.txt (pip)
// ---------------------------------------------------------------------------

// RequirementsParser handles requirements.txt files.
type RequirementsParser struct{}

// NewRequirementsParser returns a parser for requirements.txt.
func NewRequirementsParser() *RequirementsParser { return &RequirementsParser{} }

func (p *RequirementsParser) CanParse(filename string) bool {
	return filename == "requirements.txt"
}

func (p *RequirementsParser) Ecosystem() domain.Ecosystem { return domain.EcosystemPyPI }

func (p *RequirementsParser) Parse(r io.Reader) ([]domain.Package, error) {
	var (
		pkgs []domain.Package
		errs []error
	)

	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines, comments, and pip options (-i, --index-url, etc.).
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments.
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip environment markers (e.g. ; python_version >= "3.6").
		if idx := strings.Index(line, ";"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip extras (e.g. requests[security]).
		if idx := strings.Index(line, "["); idx >= 0 {
			bracket := strings.Index(line, "]")
			if bracket > idx {
				line = line[:idx] + line[bracket+1:]
			}
		}

		name, version, pinned := parseRequirementLine(line)
		if name == "" {
			continue
		}

		if !pinned {
			errs = append(errs, fmt.Errorf("requirements.txt:%d: unpinned dependency %q", lineNo, name))
			continue
		}

		pkgs = append(pkgs, domain.Package{
			Name:      normalizePyName(name),
			Version:   version,
			Ecosystem: domain.EcosystemPyPI,
		})
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Errorf("requirements.txt: read error: %w", err))
	}

	return dedup(pkgs), joinErrors(errs)
}

// parseRequirementLine parses a single requirements line like "requests==2.28.0".
// Returns name, version, and whether the version is pinned (==).
func parseRequirementLine(line string) (name, version string, pinned bool) {
	// Pinned: name==version
	if idx := strings.Index(line, "=="); idx > 0 {
		return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+2:]), true
	}

	// Not pinned but has a version specifier (>=, <=, ~=, !=, etc.).
	for _, op := range []string{">=", "<=", "~=", "!=", ">", "<"} {
		if idx := strings.Index(line, op); idx > 0 {
			return strings.TrimSpace(line[:idx]), "", false
		}
	}

	// Bare name without any version specifier.
	return strings.TrimSpace(line), "", false
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// normalizePyVersion strips the leading "==" from Pipfile-style versions.
func normalizePyVersion(v string) string {
	v = strings.TrimPrefix(v, "==")
	return strings.TrimSpace(v)
}

// normalizePyName normalizes a Python package name to lowercase with hyphens
// replaced by dashes, following PEP 503.
func normalizePyName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
