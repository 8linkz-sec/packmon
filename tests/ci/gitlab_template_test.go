package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGitLabPackmonTemplateDownloadsReleaseBinaryAtRuntime(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	variables := yamlMap(t, template["variables"], "variables")
	if _, ok := variables["PACKMON_BINARY_URL"]; ok {
		t.Fatal("PACKMON_BINARY_URL must not be precomputed in GitLab variables; shell defaults are not recursively expanded")
	}

	job := yamlMap(t, template["packmon"], "packmon")
	beforeScript := yamlStringList(t, job["before_script"], "packmon.before_script")
	joinedBeforeScript := strings.Join(beforeScript, "\n")
	if !strings.Contains(joinedBeforeScript, "set -e") {
		t.Fatal("before_script must fail on the first download or checksum error")
	}
	wantDefault := `BINARY_BASE_URL="${PACKMON_BINARY_MIRROR:-https://github.com/8linkz-sec/packmon/releases/latest/download}"`
	if !strings.Contains(joinedBeforeScript, wantDefault) {
		t.Fatalf("before_script missing runtime binary mirror default %q", wantDefault)
	}
	for _, want := range []string{
		`BINARY_BASE_URL="${BINARY_BASE_URL%/}"`,
		`BINARY_NAME="packmon-linux-${ARCH}"`,
		`BINARY_URL="${BINARY_BASE_URL}/${BINARY_NAME}"`,
		`CHECKSUM_URL="${BINARY_BASE_URL}/checksums.txt"`,
	} {
		if !strings.Contains(joinedBeforeScript, want) {
			t.Fatalf("before_script missing %q", want)
		}
	}
	if !strings.Contains(joinedBeforeScript, `curl -sfL "${BINARY_URL}" -o "/tmp/${BINARY_NAME}"`) {
		t.Fatal("before_script must fail fast when downloading the release binary fails")
	}
	if !strings.Contains(joinedBeforeScript, `sha256sum -c "${BINARY_NAME}.sha256"`) {
		t.Fatal("before_script must verify the downloaded binary checksum before installing it")
	}
	if !strings.Contains(joinedBeforeScript, "packmon version") {
		t.Fatal("before_script must execute the downloaded binary before scanning")
	}
}

func TestGitLabPackmonTemplatePublishesExpectedReports(t *testing.T) {
	t.Parallel()

	template := loadGitLabTemplate(t)
	job := yamlMap(t, template["packmon"], "packmon")

	script := strings.Join(yamlStringList(t, job["script"], "packmon.script"), "\n")
	for _, want := range []string{
		`--mode remote`,
		`--server "$PACKMON_SERVER"`,
		`--output-json results.json`,
		`--output-junit results.xml`,
		`--output-sarif results.sarif`,
		`exit $EXIT_CODE`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("packmon.script missing %q", want)
		}
	}

	artifacts := yamlMap(t, job["artifacts"], "packmon.artifacts")
	if got := yamlString(t, artifacts["when"], "packmon.artifacts.when"); got != "always" {
		t.Fatalf("artifacts.when = %q, want always", got)
	}
	paths := yamlStringList(t, artifacts["paths"], "packmon.artifacts.paths")
	for _, want := range []string{"results.json", "results.sarif"} {
		if !contains(paths, want) {
			t.Fatalf("artifacts.paths missing %q", want)
		}
	}
	reports := yamlMap(t, artifacts["reports"], "packmon.artifacts.reports")
	if got := yamlString(t, reports["junit"], "packmon.artifacts.reports.junit"); got != "results.xml" {
		t.Fatalf("junit report = %q, want results.xml", got)
	}
}

func loadGitLabTemplate(t *testing.T) map[string]any {
	t.Helper()

	path := filepath.Join("..", "..", "ci", "gitlab", ".packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read GitLab template: %v", err)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse GitLab template YAML: %v", err)
	}
	return doc
}

func yamlMap(t *testing.T, value any, name string) map[string]any {
	t.Helper()

	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s has type %T, want map", name, value)
	}
	return m
}

func yamlString(t *testing.T, value any, name string) string {
	t.Helper()

	s, ok := value.(string)
	if !ok {
		t.Fatalf("%s has type %T, want string", name, value)
	}
	return s
}

func yamlStringList(t *testing.T, value any, name string) []string {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("%s has type %T, want list", name, value)
	}
	out := make([]string, 0, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("%s[%d] has type %T, want string", name, i, item)
		}
		out = append(out, s)
	}
	return out
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
