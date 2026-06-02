package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
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

	var workflow actionsWorkflow
	if err := yamlUnmarshal(data, &workflow); err != nil {
		return nil, fmt.Errorf("actions: parsing YAML: %w", err)
	}

	var packages []domain.Package
	seen := make(map[string]struct{})
	for _, job := range workflow.Jobs {
		addActionPackage(&packages, seen, job.Uses)
		for _, step := range job.Steps {
			addActionPackage(&packages, seen, step.Uses)
		}
	}
	return packages, nil
}

func addActionPackage(packages *[]domain.Package, seen map[string]struct{}, uses string) {
	name, version, ok := parseActionUses(uses)
	if !ok {
		return
	}
	key := name + "\x00" + version
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*packages = append(*packages, domain.Package{
		Name:      name,
		Version:   version,
		Ecosystem: domain.EcosystemGitHubActions,
	})
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
	return parts[0] + "/" + parts[1], version, true
}
