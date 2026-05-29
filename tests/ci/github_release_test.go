package ci

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestGitHubReleaseWorkflowHasTagTrigger verifies the release workflow fires on
// a "v*" tag push (and not only on manual dispatch), per the documented
// release policy.
func TestGitHubReleaseWorkflowHasTagTrigger(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	// Bind the "on" key explicitly via the struct tag so the YAML boolean
	// handling of the bare word "on" cannot interfere with key lookup.
	var wf struct {
		On struct {
			Push struct {
				Tags []string `yaml:"tags"`
			} `yaml:"push"`
			WorkflowDispatch map[string]any `yaml:"workflow_dispatch"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}

	if !slices.Contains(wf.On.Push.Tags, "v*") {
		t.Fatalf("release workflow on.push.tags = %v, want it to include \"v*\"", wf.On.Push.Tags)
	}

	if wf.On.WorkflowDispatch == nil {
		t.Fatal("release workflow should also keep the manual workflow_dispatch trigger")
	}
}
