package parser

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// HexParser parses Elixir/Erlang mix.lock files.
//
// Each dependency line looks like:
//
//	"package_name": {:hex, :package_name, "1.2.3", "hash", [:mix], [...], "hexpm", "hash"},
//
// We extract the quoted package name key and the version string.
type HexParser struct{}

// mixLockLineRe matches a Hex dependency line in mix.lock. It captures the map
// key as the package name and the version string after the Hex package field.
// Mix can render the package field as :name, :"quoted-name", or "name".
var mixLockLineRe = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:hex,\s*(?::"[^"]+"|:[^,]+|"[^"]+"),\s*"([^"]+)"`)

// NewHexParser creates a new HexParser.
func NewHexParser() *HexParser {
	return &HexParser{}
}

func (p *HexParser) CanParse(filename string) bool {
	return baseFilename(filename) == "mix.lock"
}

func (p *HexParser) Parse(r io.Reader) ([]domain.Package, error) {
	scanner := newLineScanner(r)

	var (
		packages []domain.Package
		errs     []string
	)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		matches := mixLockLineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		version := matches[2]
		repository := hexRepositoryFromLockLine(line)

		if name == "" || version == "" {
			errs = append(errs, fmt.Sprintf("line %d: empty name or version", lineNum))
			continue
		}

		pkg := domain.Package{
			Name:      name,
			Version:   version,
			Ecosystem: domain.EcosystemHex,
		}
		if repository != "" {
			pkg.SourceRefs = []string{"repo=" + repository}
		}
		packages = append(packages, pkg)
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

func hexRepositoryFromLockLine(line string) string {
	fields := hexTupleFields(line)
	if len(fields) < 6 {
		return ""
	}
	return hexStringFieldValue(fields[5])
}

func hexTupleFields(line string) []string {
	start := strings.Index(line, "{:hex,")
	if start < 0 {
		return nil
	}
	input := line[start+len("{:hex,"):]
	var (
		fields   []string
		field    strings.Builder
		depth    int
		inString bool
		escaped  bool
	)
	for _, r := range input {
		if inString {
			field.WriteRune(r)
			if escaped {
				escaped = false
				continue
			}
			switch r {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}

		switch r {
		case '"':
			inString = true
			field.WriteRune(r)
		case '[', '{', '(':
			depth++
			field.WriteRune(r)
		case ']', ')':
			if depth > 0 {
				depth--
			}
			field.WriteRune(r)
		case '}':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(field.String()))
				return fields
			}
			depth--
			field.WriteRune(r)
		case ',':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(field.String()))
				field.Reset()
				continue
			}
			field.WriteRune(r)
		default:
			field.WriteRune(r)
		}
	}
	return fields
}

func hexStringFieldValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if value, err := strconv.Unquote(raw); err == nil {
		return strings.TrimSpace(value)
	}
	return ""
}
