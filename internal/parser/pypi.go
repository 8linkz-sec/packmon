package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/packageid"
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
	if err := decodeStrictJSON(r, &lock); err != nil {
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
			Dev:       true,
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
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Category string   `toml:"category"`
	Groups   []string `toml:"groups"`
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
			Dev:       pythonLockEntryDev(entry.Category, entry.Groups, false),
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
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Category string   `toml:"category"`
	Groups   []string `toml:"groups"`
	Dev      bool     `toml:"dev"`
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
			Dev:       pythonLockEntryDev(entry.Category, entry.Groups, entry.Dev),
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
		pkgs             []domain.Package
		errs             []error
		activeSourceRefs []string
	)

	lines, scanErr := readRequirementLogicalLines(r)
	for _, logical := range lines {
		lineNo := logical.lineNo
		line := strings.TrimSpace(logical.text)

		// Skip blank lines, comments, include/constraint directives, and pip
		// options (-i, --index-url, etc.).
		if shouldSkipRequirementLine(line) {
			activeSourceRefs = updateRequirementSourceRefs(line, activeSourceRefs)
			continue
		}
		if editable := parseEditableRequirement(line); editable != "" {
			line = editable
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
			errs = append(errs, fmt.Errorf("requirements.txt:%d: unpinned dependency", lineNo))
			continue
		}

		pkgs = append(pkgs, domain.Package{
			Name:       normalizePyName(name),
			Version:    version,
			Ecosystem:  domain.EcosystemPyPI,
			SourceRefs: cleanSourceRefs(activeSourceRefs...),
		})
	}

	if scanErr != nil {
		errs = append(errs, fmt.Errorf("requirements.txt: read error: %w", scanErr))
	}

	return dedup(pkgs), joinErrors(errs)
}

type requirementLogicalLine struct {
	lineNo int
	text   string
}

func readRequirementLogicalLines(r io.Reader) ([]requirementLogicalLine, error) {
	scanner := newLineScanner(r)
	var (
		lines       []requirementLogicalLine
		pending     strings.Builder
		pendingLine int
		lineNo      int
	)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if pending.Len() == 0 {
			pendingLine = lineNo
		}
		continued := strings.HasSuffix(line, "\\")
		if continued {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		}
		if pending.Len() > 0 && line != "" {
			pending.WriteByte(' ')
		}
		pending.WriteString(line)
		if continued {
			continue
		}
		lines = append(lines, requirementLogicalLine{lineNo: pendingLine, text: pending.String()})
		pending.Reset()
	}
	if pending.Len() > 0 {
		lines = append(lines, requirementLogicalLine{lineNo: pendingLine, text: pending.String()})
	}
	return lines, scanner.Err()
}

func shouldSkipRequirementLine(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") {
		return true
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return true
	}
	switch fields[0] {
	case "-r", "--requirement", "-c", "--constraint", "-i", "--index-url",
		"--extra-index-url", "--find-links", "-f", "--trusted-host",
		"--no-index", "--pre":
		return true
	}
	return strings.HasPrefix(fields[0], "--") && fields[0] != "--editable"
}

func updateRequirementSourceRefs(line string, current []string) []string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return current
	}
	switch fields[0] {
	case "-i", "--index-url":
		if len(fields) > 1 {
			return cleanSourceRefs(fields[1])
		}
	case "--extra-index-url", "-f", "--find-links":
		if len(fields) > 1 {
			return cleanSourceRefs(append(append([]string(nil), current...), fields[1])...)
		}
	case "--no-index":
		return []string{"no-index"}
	}
	for _, prefix := range []string{"--index-url=", "-i=", "--extra-index-url=", "--find-links=", "-f="} {
		if strings.HasPrefix(fields[0], prefix) {
			value := strings.TrimSpace(strings.TrimPrefix(fields[0], prefix))
			if value == "" {
				return current
			}
			if strings.HasPrefix(prefix, "--index-url") || strings.HasPrefix(prefix, "-i") {
				return cleanSourceRefs(value)
			}
			return cleanSourceRefs(append(append([]string(nil), current...), value)...)
		}
	}
	return current
}

func parseEditableRequirement(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	if fields[0] != "-e" && fields[0] != "--editable" {
		return ""
	}
	spec := strings.TrimSpace(strings.Join(fields[1:], " "))
	if strings.Contains(spec, "==") {
		return spec
	}
	name := ""
	if marker := "#egg="; strings.Contains(spec, marker) {
		name = spec[strings.LastIndex(spec, marker)+len(marker):]
		if idx := strings.IndexAny(name, "&?"); idx >= 0 {
			name = name[:idx]
		}
	}
	version := ""
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		version = spec[at+1:]
		if idx := strings.IndexAny(version, "#?&"); idx >= 0 {
			version = version[:idx]
		}
		version = strings.TrimPrefix(version, "v")
	}
	if name == "" || version == "" {
		return ""
	}
	return name + "==" + version
}

// parseRequirementLine parses a single requirements line like "requests==2.28.0".
// Returns name, version, and whether the version is pinned (==).
func parseRequirementLine(line string) (name, version string, pinned bool) {
	// Pinned: name==version
	if idx := strings.Index(line, "=="); idx > 0 {
		version := strings.TrimSpace(line[idx+2:])
		if fields := strings.Fields(version); len(fields) > 0 {
			version = fields[0]
		}
		return strings.TrimSpace(line[:idx]), version, true
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
// replacing . _ - runs, following PEP 503.
func normalizePyName(name string) string {
	return packageid.NormalizeName(string(domain.EcosystemPyPI), name)
}

func pythonLockEntryDev(category string, groups []string, explicitDev bool) bool {
	if explicitDev {
		return true
	}
	category = strings.ToLower(strings.TrimSpace(category))
	if category != "" && category != "main" {
		return true
	}
	for _, group := range groups {
		group = strings.ToLower(strings.TrimSpace(group))
		if group != "" && group != "main" && group != "default" {
			return true
		}
	}
	return false
}
