package parser

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
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
	scanner := newLineScanner(r)

	// Find the PODS: section first and keep SPEC REPOS provenance when present.
	inPods := false
	inSpecRepos := false
	currentSpecRepo := ""
	var (
		packages           []domain.Package
		errs               []string
		seen               = make(map[string]bool)
		packageIndexes     = make(map[string][]int)
		specRepoSourceRefs = make(map[string][]string)
	)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			inPods = trimmed == "PODS:"
			inSpecRepos = trimmed == "SPEC REPOS:"
			currentSpecRepo = ""
			if inPods {
				continue
			}
			if inSpecRepos {
				continue
			}
		}

		if inSpecRepos {
			if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
				currentSpecRepo = strings.TrimSuffix(trimmed, ":")
				continue
			}
			if currentSpecRepo != "" && strings.HasPrefix(line, "    - ") {
				podName := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
				if idx := strings.Index(podName, "/"); idx > 0 {
					podName = podName[:idx]
				}
				specRepoSourceRefs[podName] = append(specRepoSourceRefs[podName], currentSpecRepo)
			}
			continue
		}

		if inPods {
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
			packageIndexes[rootName] = append(packageIndexes[rootName], len(packages)-1)
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("reading input: %v", err))
	}

	if !inPods && len(packages) == 0 {
		errs = append(errs, "no PODS section found")
	}

	for podName, refs := range specRepoSourceRefs {
		for _, idx := range packageIndexes[podName] {
			packages[idx].SourceRefs = cleanSourceRefs(refs...)
		}
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
