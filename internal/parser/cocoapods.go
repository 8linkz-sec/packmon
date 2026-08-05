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

type cocoaPodsSection int

const (
	cocoaPodsSectionOther cocoaPodsSection = iota
	cocoaPodsSectionPods
	cocoaPodsSectionSpecRepos
)

type cocoaPodsParseState struct {
	section         cocoaPodsSection
	currentSpecRepo string
}

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
	state := cocoaPodsParseState{}
	var (
		packages           []domain.Package
		errs               []string
		seen               = make(map[string]bool)
		packageIndexes     = make(map[string][]int)
		specRepoSourceRefs = make(map[string][]string)
	)

	for scanner.Scan() {
		line := scanner.Text()

		var handled bool
		state, handled = advanceCocoaPodsParseState(state, line)
		if handled {
			continue
		}

		if state.section == cocoaPodsSectionSpecRepos {
			if podName, ok := parseCocoaPodsSpecRepoPackageLine(state.currentSpecRepo, line); ok {
				specRepoSourceRefs[podName] = append(specRepoSourceRefs[podName], state.currentSpecRepo)
			}
			continue
		}

		if state.section == cocoaPodsSectionPods {
			name, version, ok := parseCocoaPodsPodLine(line)
			if !ok {
				// This is either a sub-dependency line or a malformed line; skip it.
				continue
			}

			key := name + "@" + version
			if seen[key] {
				continue
			}
			seen[key] = true

			packages = append(packages, domain.Package{
				Name:      name,
				Version:   version,
				Ecosystem: domain.EcosystemCocoaPods,
			})
			packageIndexes[name] = append(packageIndexes[name], len(packages)-1)
		}
	}

	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Sprintf("reading input: %v", err))
	}

	if state.section != cocoaPodsSectionPods && len(packages) == 0 {
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

func advanceCocoaPodsParseState(state cocoaPodsParseState, line string) (cocoaPodsParseState, bool) {
	trimmed := strings.TrimSpace(line)
	if isCocoaPodsTopLevelSection(line, trimmed) {
		state.currentSpecRepo = ""
		switch trimmed {
		case "PODS:":
			state.section = cocoaPodsSectionPods
		case "SPEC REPOS:":
			state.section = cocoaPodsSectionSpecRepos
		default:
			state.section = cocoaPodsSectionOther
		}
		return state, true
	}

	if state.section == cocoaPodsSectionSpecRepos {
		if repo, ok := parseCocoaPodsSpecRepoHeader(line, trimmed); ok {
			state.currentSpecRepo = repo
			return state, true
		}
	}

	return state, false
}

func isCocoaPodsTopLevelSection(line, trimmed string) bool {
	return !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":")
}

func parseCocoaPodsSpecRepoHeader(line, trimmed string) (string, bool) {
	if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
		return strings.TrimSuffix(trimmed, ":"), true
	}
	return "", false
}

func parseCocoaPodsPodLine(line string) (string, string, bool) {
	matches := podLineRe.FindStringSubmatch(line)
	if matches == nil {
		return "", "", false
	}
	return cocoaPodsRootName(matches[1]), matches[2], true
}

func parseCocoaPodsSpecRepoPackageLine(currentSpecRepo, line string) (string, bool) {
	if currentSpecRepo == "" || !strings.HasPrefix(line, "    - ") {
		return "", false
	}

	podName := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
	return cocoaPodsRootName(podName), true
}

func cocoaPodsRootName(name string) string {
	if idx := strings.Index(name, "/"); idx > 0 {
		return name[:idx]
	}
	return name
}

func (p *CocoaPodsParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemCocoaPods
}
