package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// ---------------------------------------------------------------------------
// go.sum
// ---------------------------------------------------------------------------

// GoSumParser handles go.sum files.
type GoSumParser struct{}

// NewGoSumParser returns a parser for go.sum.
func NewGoSumParser() *GoSumParser { return &GoSumParser{} }

func (p *GoSumParser) CanParse(filename string) bool {
	return filename == "go.sum"
}

func (p *GoSumParser) Ecosystem() domain.Ecosystem { return domain.EcosystemGo }

// Parse reads a go.sum file. Each line has the format:
//
//	module version hash
//	module version/go.mod hash
//
// Lines ending in /go.mod are deduplicated against the plain module line.
func (p *GoSumParser) Parse(r io.Reader) ([]domain.Package, error) {
	var (
		pkgs []domain.Package
		errs []error
	)

	scanner := newLineScanner(r)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			errs = append(errs, fmt.Errorf("go.sum:%d: malformed line (expected 3 fields, got %d)", lineNo, len(fields)))
			continue
		}

		module := fields[0]
		version := fields[1]

		// Skip /go.mod entries; the plain module entry is authoritative.
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}

		// Strip the +incompatible suffix and /go.mod suffix.
		version = strings.TrimSuffix(version, "+incompatible")

		// Strip leading "v" -- Go uses semver with "v" prefix; the ecosystem
		// convention for OSV and vulnerability databases keeps the "v".
		// We keep it as-is for Go to match how advisories reference Go modules.

		if module == "" || version == "" {
			continue
		}

		pkgs = append(pkgs, domain.Package{
			Name:      module,
			Version:   version,
			Ecosystem: domain.EcosystemGo,
		})
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Errorf("go.sum: read error: %w", err))
	}

	return dedup(pkgs), joinErrors(errs)
}

// ---------------------------------------------------------------------------
// go.mod
// ---------------------------------------------------------------------------

// GoModParser handles go.mod files. It extracts packages from the require
// block(s).
type GoModParser struct{}

// NewGoModParser returns a parser for go.mod.
func NewGoModParser() *GoModParser { return &GoModParser{} }

func (p *GoModParser) CanParse(filename string) bool {
	return filename == "go.mod"
}

func (p *GoModParser) Ecosystem() domain.Ecosystem { return domain.EcosystemGo }

func (p *GoModParser) Parse(r io.Reader) ([]domain.Package, error) {
	var (
		pkgs    []domain.Package
		errs    []error
		inBlock bool
	)

	scanner := newLineScanner(r)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// code drops any inline comment and is used only for structural
		// decisions, so a '(' or ')' inside a comment (e.g. "// see (note)")
		// cannot open or close the require block. The original line is passed
		// to parseGoRequireLine, which detects "// indirect" itself.
		code := line
		if idx := strings.Index(code, "//"); idx >= 0 {
			code = strings.TrimSpace(code[:idx])
		}

		// Detect start/end of require block.
		if strings.HasPrefix(code, "require") && strings.Contains(code, "(") {
			inBlock = true
			// A require ( on the same line as a package is unusual but handle it.
			rest := strings.TrimPrefix(code, "require")
			rest = strings.TrimSpace(rest)
			rest = strings.TrimSpace(strings.TrimPrefix(rest, "("))
			if rest != "" && rest != ")" {
				if pkg, err := parseGoRequireLine(rest, lineNo); err == nil {
					pkgs = append(pkgs, pkg)
				} else {
					errs = append(errs, err)
				}
			}
			continue
		}

		if inBlock && strings.Contains(code, ")") {
			inBlock = false
			continue
		}

		if inBlock {
			pkg, err := parseGoRequireLine(line, lineNo)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			pkgs = append(pkgs, pkg)
			continue
		}

		// Single-line require without parentheses: require module version
		if strings.HasPrefix(code, "require ") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "require "))
			pkg, err := parseGoRequireLine(rest, lineNo)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			pkgs = append(pkgs, pkg)
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Errorf("go.mod: read error: %w", err))
	}

	return dedup(pkgs), joinErrors(errs)
}

// parseGoRequireLine parses a single require directive like
// "golang.org/x/text v0.3.7".
func parseGoRequireLine(line string, lineNo int) (domain.Package, error) {
	indirect := false
	if idx := strings.Index(line, "//"); idx >= 0 {
		comment := line[idx+len("//"):]
		for _, field := range strings.Fields(comment) {
			if field == "indirect" {
				indirect = true
				break
			}
		}
		line = strings.TrimSpace(line[:idx])
	}

	fields := strings.Fields(line)
	if len(fields) < 2 {
		return domain.Package{}, fmt.Errorf("go.mod:%d: malformed require line", lineNo)
	}

	module := fields[0]
	version := fields[1]

	// Clean up version.
	version = strings.TrimSuffix(version, "+incompatible")

	return domain.Package{
		Name:      module,
		Version:   version,
		Ecosystem: domain.EcosystemGo,
		Direct:    !indirect,
		Indirect:  indirect,
	}, nil
}
