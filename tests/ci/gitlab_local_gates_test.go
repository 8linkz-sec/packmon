package ci

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

// The GitLab jobs that repeat a `make verify` gate (lint-shell, lint-docker, lint-powershell, lint-nongo,
// security, the coverage check of `make test`) must use the Makefile's pins and flags, so the local gate and
// the pipeline cannot drift apart.
func TestGitLabLocalGateJobsMatchMakefilePins(t *testing.T) {
	t.Parallel()

	pins := makefileAssignments(t, "SHELLCHECK_IMAGE", "HADOLINT_IMAGE", "PSSCRIPTANALYZER_VERSION", "COVERAGE_MIN")
	jobs := gitLabJobs(t)
	for _, tc := range []struct {
		job   string
		image string
		wants []string
	}{
		{job: "shellcheck", image: pins["SHELLCHECK_IMAGE"], wants: []string{"shellcheck scripts/*.sh scripts/lib/*.sh deploy/n8n/*.sh"}},
		{job: "hadolint", image: pins["HADOLINT_IMAGE"], wants: []string{"hadolint - < Dockerfile"}},
		{job: "psscriptanalyzer", wants: []string{
			"$ErrorActionPreference = 'Stop'",
			"Install-Module -Name PSScriptAnalyzer -RequiredVersion " + pins["PSSCRIPTANALYZER_VERSION"],
			"Invoke-ScriptAnalyzer -Path scripts -Recurse -Severity Error",
		}},
		{job: "non-go-format", wants: []string{"make lint-nongo"}},
		{job: "gosec", wants: []string{"gosec", "-nosec-require-rules -nosec-require-justification"}},
		{job: "trivy-fs", wants: []string{"trivy fs --scanners vuln --pkg-types library --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1"}},
		{job: "npm-audit", wants: []string{"npm audit --audit-level=high"}},
		{job: "go-coverage-gate", wants: []string{"go run ./tools/checkcoverage -profile=coverage.out -min=" + pins["COVERAGE_MIN"]}},
	} {
		job, ok := jobs[tc.job]
		if !ok {
			t.Fatalf(".gitlab-ci.yml has no job %s", tc.job)
		}
		if tc.image != "" && job.Image != tc.image {
			t.Fatalf(".gitlab-ci.yml job %s image = %q, want the Makefile pin %q", tc.job, job.Image, tc.image)
		}
		script := strings.Join(job.Script, "\n")
		for _, want := range tc.wants {
			if !strings.Contains(script, want) {
				t.Fatalf(".gitlab-ci.yml job %s script misses %q:\n%s", tc.job, want, script)
			}
		}
	}
	if script := strings.Join(jobs["npm-audit"].Script, "\n"); strings.Contains(script, "--omit=dev") {
		t.Fatalf(".gitlab-ci.yml npm-audit omits dev dependencies, unlike make security:\n%s", script)
	}
}

type gitLabJob struct {
	Image  string
	Script []string
}

// gitLabJobs decodes the repository's own job definitions; an image may be a string or a {name: ...} map.
func gitLabJobs(t *testing.T) map[string]gitLabJob {
	t.Helper()
	var pipeline map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".gitlab-ci.yml")), &pipeline); err != nil {
		t.Fatalf("parse .gitlab-ci.yml: %v", err)
	}
	jobs := make(map[string]gitLabJob)
	for name, node := range pipeline {
		if node.Kind != yaml.MappingNode {
			continue
		}
		var raw struct {
			Image  yaml.Node `yaml:"image"`
			Script []string  `yaml:"script"`
		}
		if err := node.Decode(&raw); err != nil {
			t.Fatalf("decode .gitlab-ci.yml job %s: %v", name, err)
		}
		job := gitLabJob{Script: raw.Script}
		switch raw.Image.Kind {
		case yaml.ScalarNode:
			job.Image = raw.Image.Value
		case yaml.MappingNode:
			var image struct {
				Name string `yaml:"name"`
			}
			if err := raw.Image.Decode(&image); err != nil {
				t.Fatalf("decode .gitlab-ci.yml job %s image: %v", name, err)
			}
			job.Image = image.Name
		}
		jobs[name] = job
	}
	return jobs
}

func makefileAssignments(t *testing.T, names ...string) map[string]string {
	t.Helper()
	values := make(map[string]string, len(names))
	for _, line := range strings.Split(readRepoFile(t, "Makefile"), "\n") {
		for _, name := range names {
			if value, ok := strings.CutPrefix(line, name+" ?= "); ok {
				values[name] = strings.TrimSpace(value)
			}
		}
	}
	for _, name := range names {
		if values[name] == "" {
			t.Fatalf("Makefile has no %s ?= assignment", name)
		}
	}
	return values
}
