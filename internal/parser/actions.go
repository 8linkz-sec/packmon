package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/packageid"
	versioncmp "github.com/8linkz-sec/packmon/internal/version"
)

// ActionsParser parses GitHub Actions workflow files under .github/workflows.
type ActionsParser struct{}

type actionsWorkflow struct {
	Jobs map[string]actionsJob `yaml:"jobs"`
}

type actionsJob struct {
	Uses  string        `yaml:"uses"`
	Steps []actionsStep `yaml:"steps"`
}

type actionsStep struct {
	Uses string `yaml:"uses"`
}

func NewActionsParser() *ActionsParser {
	return &ActionsParser{}
}

func (p *ActionsParser) CanParse(filename string) bool {
	path := strings.TrimPrefix(strings.ReplaceAll(filename, `\`, "/"), "./")
	lower := strings.ToLower(path)
	if !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".yaml") {
		return false
	}
	return strings.Contains("/"+lower, "/.github/workflows/")
}

func (p *ActionsParser) Ecosystem() domain.Ecosystem {
	return domain.EcosystemGitHubActions
}

func (p *ActionsParser) Parse(r io.Reader) ([]domain.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("actions: reading input: %w", err)
	}

	var root yamlNode
	if err := yamlUnmarshalNode(data, &root); err != nil {
		return nil, fmt.Errorf("actions: parsing YAML: %w", err)
	}
	var workflow actionsWorkflow
	if err := root.Decode(&workflow); err != nil {
		return nil, fmt.Errorf("actions: parsing YAML: %w", err)
	}
	hints := actionsVersionCommentHints(&root)

	var packages []domain.Package
	seen := make(map[string]int)
	for _, job := range workflow.Jobs {
		addActionPackage(&packages, seen, job.Uses, hints)
		for _, step := range job.Steps {
			addActionPackage(&packages, seen, step.Uses, hints)
		}
	}
	return packages, nil
}

func addActionPackage(packages *[]domain.Package, seen map[string]int, uses string, hints map[string]string) {
	name, version, ok := parseActionUses(uses)
	if !ok {
		return
	}
	declared := ""
	if versioncmp.IsGitCommitSHA(version) {
		declared = hints[strings.TrimSpace(uses)]
	}
	key := name + "@" + version
	if idx, exists := seen[key]; exists {
		if (*packages)[idx].DeclaredVersion == "" {
			(*packages)[idx].DeclaredVersion = declared
		}
		return
	}
	seen[key] = len(*packages)
	*packages = append(*packages, domain.Package{
		Name:            name,
		Version:         version,
		Ecosystem:       domain.EcosystemGitHubActions,
		DeclaredVersion: declared,
	})
}

// actionsVersionCommentHints walks the workflow node tree and collects the
// version-like line comment that follows each `uses:` reference (the
// Dependabot/Renovate/pinact convention `uses: owner/repo@<sha> # v1.2.3`).
// The map is keyed by the raw `uses` scalar value; the first version-like
// comment for a given reference wins. Only job-level and step-level `uses`
// scalars are considered, so text inside `run:` blocks is never matched.
func actionsVersionCommentHints(root *yamlNode) map[string]string {
	hints := make(map[string]string)
	doc := root
	if doc.Kind == yamlDocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	jobs := yamlMappingValue(doc, "jobs")
	if jobs == nil || jobs.Kind != yamlMappingNode {
		return hints
	}
	record := func(node *yamlNode) {
		if node == nil || node.Kind != yamlScalarNode {
			return
		}
		version := parseActionsVersionComment(node.LineComment)
		if version == "" {
			return
		}
		key := strings.TrimSpace(node.Value)
		if _, exists := hints[key]; !exists {
			hints[key] = version
		}
	}
	for i := 1; i < len(jobs.Content); i += 2 {
		job := jobs.Content[i]
		if job.Kind != yamlMappingNode {
			continue
		}
		record(yamlMappingValue(job, "uses"))
		steps := yamlMappingValue(job, "steps")
		if steps == nil || steps.Kind != yamlSequenceNode {
			continue
		}
		for _, step := range steps.Content {
			if step.Kind == yamlMappingNode {
				record(yamlMappingValue(step, "uses"))
			}
		}
	}
	return hints
}

// yamlMappingValue returns the value node for key in a mapping node, or nil.
func yamlMappingValue(mapping *yamlNode, key string) *yamlNode {
	if mapping == nil || mapping.Kind != yamlMappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Kind == yamlScalarNode && mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

// parseActionsVersionComment extracts a version from a `uses:` line comment.
// Accepted shapes are `# v1.2.3`, `# 1.2.3`, `# v1`, `# tag=v1.2.3`, each
// optionally followed by further words. The version must be a lowercase-`v`
// or bare dotted number with an optional semver prerelease/build suffix.
// Anything else (free text, `pin@v1`, `ratchet:...`) yields "".
func parseActionsVersionComment(comment string) string {
	comment = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(comment), "#"))
	if comment == "" {
		return ""
	}
	token := strings.Fields(comment)[0]
	token = strings.TrimPrefix(token, "tag=")
	if !isActionsVersionToken(token) {
		return ""
	}
	return token
}

func isActionsVersionToken(token string) bool {
	core := strings.TrimPrefix(token, "v")
	if idx := strings.IndexAny(core, "-+"); idx >= 0 {
		suffix := core[idx+1:]
		core = core[:idx]
		if suffix == "" {
			return false
		}
		for _, ch := range suffix {
			if !isActionsVersionSuffixRune(ch) {
				return false
			}
		}
	}
	if core == "" {
		return false
	}
	for _, part := range strings.Split(core, ".") {
		if part == "" {
			return false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

func parseActionUses(uses string) (name, version string, ok bool) {
	uses = strings.TrimSpace(uses)
	if uses == "" ||
		strings.HasPrefix(uses, "./") ||
		strings.HasPrefix(uses, "../") ||
		strings.HasPrefix(strings.ToLower(uses), "docker://") {
		return "", "", false
	}

	at := strings.LastIndex(uses, "@")
	if at <= 0 || at == len(uses)-1 {
		return "", "", false
	}
	repo := strings.TrimSpace(uses[:at])
	version = strings.TrimSpace(uses[at+1:])
	parts := strings.Split(repo, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" || version == "" {
		return "", "", false
	}
	return packageid.NormalizeName(string(domain.EcosystemGitHubActions), parts[0]+"/"+parts[1]), version, true
}

func isActionsVersionSuffixRune(ch rune) bool {
	switch {
	case ch >= '0' && ch <= '9', ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z':
		return true
	case ch == '.', ch == '-', ch == '+':
		return true
	}
	return false
}
