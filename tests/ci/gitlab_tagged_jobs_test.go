package ci

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

const (
	taggedPackagesScript = "scripts/tagged-test-packages.sh"
	dockerOnlyListPath   = ".gitlab/integration-docker-only.txt"
)

// The GitLab jobs for the tag-gated suites take their package lists from scripts/tagged-test-packages.sh, so a
// new tagged test package runs in CI without a pipeline edit. The script must print exactly the inventory the
// Makefile targets are checked against.
func TestTaggedTestPackagesScriptMatchesInventory(t *testing.T) {
	requireLinuxShellTools(t)

	for _, tags := range [][]string{{"integration"}, {"e2e"}, {"integration", "e2e"}} {
		t.Run(strings.Join(tags, ","), func(t *testing.T) {
			output, err := runTaggedPackagesScript(t, tags...)
			if err != nil {
				t.Fatalf("%s %s: %v\n%s", taggedPackagesScript, strings.Join(tags, " "), err, output)
			}
			got := strings.Fields(output)
			if want := taggedTestPackages(t, tags...); !slices.Equal(got, want) {
				t.Fatalf("%s %s = %q, want the tagged package inventory %q", taggedPackagesScript, strings.Join(tags, " "), got, want)
			}
		})
	}
}

// An empty package list would make a CI job pass without running anything, so the script fails instead.
func TestTaggedTestPackagesScriptFailsClosed(t *testing.T) {
	requireLinuxShellTools(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "no tag", args: nil},
		{name: "tag without tests", args: []string{"packmon_no_such_tag"}},
		{name: "regular expression", args: []string{"integration|e2e"}},
		{name: "option", args: []string{"-e"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := runTaggedPackagesScript(t, tc.args...)
			if err == nil {
				t.Fatalf("%s %q succeeded with output %q, want a failure", taggedPackagesScript, tc.args, output)
			}
		})
	}
}

// The integration job skips the tests listed in .gitlab/integration-docker-only.txt: they need a Docker daemon,
// which the runners do not have. Every entry must name exactly one top-level integration test and give the
// reason, so the list can neither hide a renamed test nor grow without an explanation.
func TestIntegrationDockerOnlyListNamesTaggedTestsWithReasons(t *testing.T) {
	t.Parallel()

	entries := readDockerOnlyList(t)
	if len(entries) == 0 {
		t.Fatalf("%s lists no tests", dockerOnlyListPath)
	}
	definitions := integrationTestDefinitions(t)
	for name := range entries {
		if count := definitions[name]; count != 1 {
			t.Fatalf("%s entry %s is defined %d times in integration-tagged test files, want exactly once", dockerOnlyListPath, name, count)
		}
	}
}

// The pipeline jobs must keep using the script and the Docker-only list rather than inline copies of them.
func TestGitLabTaggedJobsUseTheTaggedInventory(t *testing.T) {
	t.Parallel()

	var pipeline map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".gitlab-ci.yml")), &pipeline); err != nil {
		t.Fatalf("parse .gitlab-ci.yml: %v", err)
	}
	for job, wants := range map[string][]string{
		"go-vet-tagged":       {taggedPackagesScript + " integration e2e", "go vet -tags integration,e2e"},
		"go-test-e2e":         {taggedPackagesScript + " e2e", "make build", "-tags e2e", "PACKMON_TEST_BIN_DIR", skippedTestsScript},
		"go-test-integration": {taggedPackagesScript + " integration", "make build build-server", "-tags integration", "PACKMON_TEST_BIN_DIR", skipPatternScript},
	} {
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
		script := strings.Join(definition.Script, "\n")
		if script == "" {
			t.Fatalf(".gitlab-ci.yml has no script for job %s", job)
		}
		for _, want := range wants {
			if !strings.Contains(script, want) {
				t.Fatalf(".gitlab-ci.yml job %s script misses %q:\n%s", job, want, script)
			}
		}
	}
}

func TestMakeE2ETargetCoversAllTaggedPackages(t *testing.T) {
	makeBin := requireGNMake(t)
	fixture := newMakeFixture(t, makeBin, "checkout")

	output, err := fixture.run(t, nil, "test-e2e")
	if err != nil {
		t.Fatalf("make test-e2e with successful stubs: %v\n%s", err, output)
	}
	var taggedCalls [][]string
	for _, fields := range readStubCallFields(t, fixture.logPath) {
		if len(fields) >= 5 && fields[0] == "go" && slices.Equal(fields[1:5], []string{"test", "-count=1", "-tags", "e2e"}) {
			taggedCalls = append(taggedCalls, fields)
		}
	}
	if len(taggedCalls) != 1 {
		t.Fatalf("e2e-tagged go test call count = %d, want 1; calls:\n%s", len(taggedCalls), strings.Join(readStubCalls(t, fixture.logPath), "\n"))
	}
	got := slices.Clone(taggedCalls[0][5:])
	slices.Sort(got)
	if want := taggedTestPackages(t, "e2e"); !slices.Equal(got, want) {
		t.Fatalf("e2e package argv = %q, want exact tagged package inventory %q", got, want)
	}
}

func requireLinuxShellTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the tagged package script runs under bash on the Linux runners; covered by the focused Linux test command")
	}
	for _, tool := range []string{"bash", "git", "grep", "sort"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required to run %s: %v", tool, taggedPackagesScript, err)
		}
	}
}

func runTaggedPackagesScript(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	cmd := exec.Command("bash", append([]string{taggedPackagesScript}, args...)...) // #nosec G204 -- fixed repository script with test-controlled arguments.
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	return string(output), err
}

var dockerOnlyEntryPattern = regexp.MustCompile(`^(Test[A-Za-z0-9_]+)[ \t]+#[ \t]*(\S.*)$`)

func readDockerOnlyList(t *testing.T) map[string]string {
	t.Helper()
	entries := make(map[string]string)
	for i, line := range strings.Split(readRepoFile(t, dockerOnlyListPath), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		match := dockerOnlyEntryPattern.FindStringSubmatch(trimmed)
		if match == nil {
			t.Fatalf("%s:%d = %q, want \"TestName  # reason\"", dockerOnlyListPath, i+1, line)
		}
		if _, duplicate := entries[match[1]]; duplicate {
			t.Fatalf("%s:%d lists %s twice", dockerOnlyListPath, i+1, match[1])
		}
		entries[match[1]] = match[2]
	}
	return entries
}

var topLevelTestPattern = regexp.MustCompile(`^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)`)

// integrationTestDefinitions counts the top-level test functions per name across the integration-tagged test
// files of the integration package inventory.
func integrationTestDefinitions(t *testing.T) map[string]int {
	t.Helper()
	root := filepath.Join("..", "..")
	counts := make(map[string]int)
	for _, pkg := range taggedTestPackages(t, "integration") {
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pkg), "*_test.go"))
		if err != nil {
			t.Fatalf("list %s test files: %v", pkg, err)
		}
		for _, path := range files {
			expr, ok, parseErr := testFileBuildConstraint(path)
			if parseErr != nil {
				t.Fatalf("parse %s build constraint: %v", path, parseErr)
			}
			if !ok || !mentionsBuildTag(expr, "integration") {
				continue
			}
			countTopLevelTests(t, path, counts)
		}
	}
	return counts
}

func countTopLevelTests(t *testing.T, path string, counts map[string]int) {
	t.Helper()
	file, err := os.Open(path) //nolint:gosec // path comes from the tracked integration package inventory.
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if match := topLevelTestPattern.FindStringSubmatch(scanner.Text()); match != nil {
			counts[match[1]]++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
}
