package parser

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// CocoaPodsParser parses Podfile.lock files.
//
// The PODS section has a custom indentation-based format:
//
//	PODS:
//	  - PodName (1.2.3)
//	  - PodName (1.2.3):
//	    - SubDep (>= 1.0)
//
// Only top-level pods (indented by exactly two spaces + "- ") are extracted.
type CocoaPodsParser struct{}

// podLineRe matches a top-level pod entry: "  - Name (version)" or "  - Name (version):".
// The name may contain slashes (subspecs) such as "Firebase/Core".
var podLineRe = regexp.MustCompile(`^  - ([^\s(]+)\s+\(([^)]+)\):?$`)

// NewCocoaPodsParser creates a new CocoaPodsParser.
func NewCocoaPodsParser() *CocoaPodsParser {
	return &CocoaPodsParser{}
}

func (p *CocoaPodsParser) CanParse(filename string) bool {
	return baseFilename(filename) == "Podfile.lock"
}

func (p *CocoaPodsParser) Parse(r io.Reader) ([]domain.Package, error) {
	scanner := bufio.NewScanner(r)

	// Find the PODS: section first.
	inPods := false
	var (
		packages []domain.Package
		errs     []string
		seen     = make(map[string]bool)
	)

	for scanner.Scan() {
		line := scanner.Text()

		if !inPods {
			if strings.TrimSpace(line) == "PODS:" {
				inPods = true
			}
			continue
		}

		// An empty line or a new top-level section header ends the PODS block.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		// A new section starts with a non-indented, non-dash line ending with ":"
		// (e.g., "DEPENDENCIES:", "SPEC REPOS:", etc.).
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			break
		}

		matches := podLineRe.FindStringSubmatch(line)
		if matches == nil {
			// This is either a sub-dependency line or a malformed line; skip it.
			continue
		}

		name := matches[1]
		version := matches[2]

		// For subspecs like "Firebase/Core", use the root pod name.
		rootName := name
		if idx := strings.Index(name, "/"); idx > 0 {
			rootName = name[:idx]
		}

		key := rootName + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		packages = append(packages, domain.Package{
			Name:      rootName,
			Version:   version,
			Ecosystem: domain.EcosystemCocoaPods,
		})
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("reading input: %v", err))
	}

	if !inPods && len(packages) == 0 {
		errs = append(errs, "no PODS section found")
	}

	var retErr error
	if len(errs) > 0 {
		retErr = fmt.Errorf("cocoapods: %s", strings.Join(errs, "; "))
	}

	return packages, retErr
}

func (p *CocoaPodsParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemCocoaPods
}
