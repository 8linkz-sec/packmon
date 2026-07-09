package ci

import (
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const pinnedGitleaksVersion = "v8.30.1"

func TestGitHubWorkflowsRunPinnedGitleaksSecretScanning(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		rel  string
		job  string
	}{
		{
			name: "CI",
			rel:  filepath.Join(".github", "workflows", "ci.yml"),
			job:  "security",
		},
		{
			name: "Release",
			rel:  filepath.Join(".github", "workflows", "release.yml"),
			job:  "verify",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var wf struct {
				Jobs map[string]workflowJob `yaml:"jobs"`
			}
			if err := yaml.Unmarshal([]byte(readRepoFile(t, tc.rel)), &wf); err != nil {
				t.Fatalf("parse %s: %v", tc.rel, err)
			}

			job, ok := wf.Jobs[tc.job]
			if !ok {
				t.Fatalf("%s has no job %q", tc.rel, tc.job)
			}
			runs := joinedStepRuns(job.Steps)
			for _, want := range []string{
				"go install github.com/gitleaks/gitleaks/v8@" + pinnedGitleaksVersion,
				"gitleaks detect --source . --redact --no-banner --verbose",
			} {
				if !strings.Contains(runs, want) {
					t.Fatalf("%s job %q missing Gitleaks gate marker %q", tc.rel, tc.job, want)
				}
			}
			for _, forbidden := range []string{
				"github.com/gitleaks/gitleaks/v8@latest",
				"gitleaks/gitleaks-action@",
			} {
				if strings.Contains(runs, forbidden) {
					t.Fatalf("%s job %q uses forbidden unowned or mutable Gitleaks marker %q", tc.rel, tc.job, forbidden)
				}
			}
		})
	}
}
