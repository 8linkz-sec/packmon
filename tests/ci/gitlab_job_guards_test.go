package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

const (
	skippedTestsScript = "scripts/fail-on-skipped-tests.sh"
	skipPatternScript  = "scripts/integration-skip-pattern.sh"
)

// go-test-e2e fails when a test skipped: the browser test skips when it finds no browser, and a skip must not pass
// as coverage. The check lives in scripts/fail-on-skipped-tests.sh so its behaviour can be tested here.
func TestFailOnSkippedTestsScriptRejectsSkippedTests(t *testing.T) {
	requireLinuxShellTools(t)

	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		log     string
		wantErr bool
	}{
		{name: "all passed", log: "=== RUN   TestA\n--- PASS: TestA (0.01s)\nPASS\nok  \tpkg\t0.1s\n", wantErr: false},
		{name: "top-level skip", log: "=== RUN   TestA\n--- SKIP: TestA (0.00s)\n    a_test.go:9: no browser\nPASS\n", wantErr: true},
		{name: "subtest skip", log: "--- PASS: TestA (0.01s)\n    --- SKIP: TestA/case (0.00s)\nPASS\n", wantErr: true},
		{name: "empty log", log: "", wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".log")
			if err := os.WriteFile(path, []byte(tc.log), 0o600); err != nil {
				t.Fatalf("write log fixture: %v", err)
			}
			output, err := runRepoScript(t, skippedTestsScript, path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("%s on %q: err = %v, want error %v\n%s", skippedTestsScript, tc.log, err, tc.wantErr, output)
			}
		})
	}
	for _, args := range [][]string{nil, {filepath.Join(dir, "missing.log")}} {
		if output, err := runRepoScript(t, skippedTestsScript, args...); err == nil {
			t.Fatalf("%s %q succeeded with output %q, want a failure", skippedTestsScript, args, output)
		}
	}
}

// go-test-integration skips exactly the tests of .gitlab/integration-docker-only.txt, as whole names.
func TestIntegrationSkipPatternScriptMatchesDockerOnlyList(t *testing.T) {
	requireLinuxShellTools(t)

	output, err := runRepoScript(t, skipPatternScript)
	if err != nil {
		t.Fatalf("%s: %v\n%s", skipPatternScript, err, output)
	}
	pattern := strings.TrimSpace(output)
	inner, ok := strings.CutPrefix(pattern, "^(")
	if ok {
		inner, ok = strings.CutSuffix(inner, ")$")
	}
	if !ok {
		t.Fatalf("%s = %q, want ^(Name|...)$", skipPatternScript, pattern)
	}
	entries := readDockerOnlyList(t)
	want := make([]string, 0, len(entries))
	for name := range entries {
		want = append(want, name)
	}
	slices.Sort(want)
	got := strings.Split(inner, "|")
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("%s names = %q, want the %s entries %q", skipPatternScript, got, dockerOnlyListPath, want)
	}
	compiled := regexp.MustCompile(pattern)
	for _, name := range want {
		if !compiled.MatchString(name) || compiled.MatchString(name+"Extra") || compiled.MatchString("X"+name) {
			t.Fatalf("%s pattern %q must match exactly the whole name %s", skipPatternScript, pattern, name)
		}
	}
	if compiled.MatchString("TestPostgresQueuePauseSurvivesReEnqueue") {
		t.Fatalf("%s pattern %q skips a service-capable test", skipPatternScript, pattern)
	}
}

// The core rules of the tagged-suite jobs, as script lines: e2e fails on a skipped test, integration runs the
// packages one at a time (they share one PostgreSQL server) and skips the Docker-only tests.
func TestGitLabTaggedJobsPinTheirGuards(t *testing.T) {
	t.Parallel()

	var pipeline map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".gitlab-ci.yml")), &pipeline); err != nil {
		t.Fatalf("parse .gitlab-ci.yml: %v", err)
	}
	e2e := jobScriptLines(t, pipeline, "go-test-e2e")
	for _, want := range []string{
		"status=0",
		"bash " + skippedTestsScript + " /tmp/e2e-test.log || status=1",
		`exit "$status"`,
	} {
		if !slices.Contains(e2e, want) {
			t.Fatalf("go-test-e2e script misses the line %q:\n%s", want, strings.Join(e2e, "\n"))
		}
	}
	if !lineWithFields(e2e, "go", "test", "-tags", "e2e", "/tmp/e2e-test.log") {
		t.Fatalf("go-test-e2e must write the e2e go test output to /tmp/e2e-test.log:\n%s", strings.Join(e2e, "\n"))
	}

	integration := jobScriptLines(t, pipeline, "go-test-integration")
	if !slices.Contains(integration, "skip_pattern=$(bash "+skipPatternScript+")") {
		t.Fatalf("go-test-integration must take its skip pattern from %s:\n%s", skipPatternScript, strings.Join(integration, "\n"))
	}
	var testLine []string
	for _, line := range integration {
		if fields := strings.Fields(line); slices.Contains(fields, "go") && slices.Contains(fields, "test") {
			testLine = fields
		}
	}
	for _, pair := range [][2]string{{"-p", "1"}, {"-skip", `"$skip_pattern"`}, {"-tags", "integration"}} {
		index := slices.Index(testLine, pair[0])
		if index < 0 || index+1 >= len(testLine) || testLine[index+1] != pair[1] {
			t.Fatalf("go-test-integration go test line %q misses %s %s", testLine, pair[0], pair[1])
		}
	}
}

func jobScriptLines(t *testing.T, pipeline map[string]yaml.Node, job string) []string {
	t.Helper()
	node, ok := pipeline[job]
	if !ok {
		t.Fatalf(".gitlab-ci.yml has no job %s", job)
	}
	var definition struct {
		Script []string `yaml:"script"`
	}
	if err := node.Decode(&definition); err != nil {
		t.Fatalf("decode .gitlab-ci.yml job %s: %v", job, err)
	}
	var lines []string
	for _, entry := range definition.Script {
		for _, line := range strings.Split(entry, "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				lines = append(lines, trimmed)
			}
		}
	}
	return lines
}

func lineWithFields(lines []string, fields ...string) bool {
	for _, line := range lines {
		lineFields := strings.Fields(line)
		matched := true
		for _, field := range fields {
			if !slices.ContainsFunc(lineFields, func(f string) bool { return strings.Contains(f, field) }) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func runRepoScript(t *testing.T, script string, args ...string) (string, error) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...) // #nosec G204 -- fixed repository script with test-controlled arguments.
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	return string(output), err
}

var (
	createRolePattern       = regexp.MustCompile(`CREATE ROLE ([a-z0-9_]+)`)
	serviceTestRolesPattern = regexp.MustCompile(`(?m)^var serviceTestRoles = \[\]string\{(.*)\}$`)
)

// In service mode the harnesses drop only the roles of serviceTestRoles before each test. Every role an
// integration test creates must be in each copy of that list, or a second creation on the shared server fails.
func TestServiceTestRolesCoverEveryCreatedRole(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	created := make(map[string]bool)
	for _, pkg := range taggedTestPackages(t, "integration") {
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pkg), "*_test.go"))
		if err != nil {
			t.Fatalf("list %s test files: %v", pkg, err)
		}
		for _, path := range files {
			data, err := os.ReadFile(path) //nolint:gosec // path comes from the tracked integration package inventory.
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, match := range createRolePattern.FindAllStringSubmatch(string(data), -1) {
				created[match[1]] = true
			}
		}
	}
	if len(created) == 0 {
		t.Fatal("no integration test creates a role; the role inventory regexp no longer matches")
	}
	for _, rel := range []string{
		"internal/db/postgres/postgres_service_docker_test.go",
		"internal/db/postgres/migrations/postgres_service_docker_test.go",
		"internal/server/postgres_service_integration_test.go",
		"tests/integration/postgres_service_test.go",
	} {
		match := serviceTestRolesPattern.FindStringSubmatch(readRepoFile(t, rel))
		if match == nil {
			t.Fatalf("%s has no serviceTestRoles list", rel)
		}
		for role := range created {
			if !strings.Contains(match[1], `"`+role+`"`) {
				t.Fatalf("%s serviceTestRoles misses %q, which an integration test creates", rel, role)
			}
		}
	}
}
