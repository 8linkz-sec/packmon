package ci

import (
	"bufio"
	"context"
	"fmt"
	"go/build"
	"go/build/constraint"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const stubScript = `#!/bin/sh
tool=${0##*/}
log_line="$PWD	${PACKMON_TEST_BIN_DIR-}	${STUB_TARGET-}	$tool"
for arg do
	log_line="$log_line	$arg"
done
printf '%s\n' "$log_line" >> "$STUB_LOG"
printf 'start\t%s\n' "$log_line" >> "$STUB_EVENT_LOG"

if [ "$tool" = "gofumpt" ] && [ "${1-}" = "-version" ]; then
	printf '%s\n' 'gofumpt v0.9.2'
fi
if [ "$tool" = "golangci-lint" ] && [ "${1-}" = "version" ]; then
	printf '%s\n' 'golangci-lint has version 2.14.0'
fi

if [ "$tool" = "npm" ] && [ "${1-}" = "ci" ] && [ -n "${NPM_BARRIER_DIR-}" ]; then
	id=
	for candidate in 1 2 3; do
		if (set -C; : > "$NPM_BARRIER_DIR/participant.$candidate") 2>/dev/null; then
			id=$candidate
			break
		fi
	done
	if [ -z "$id" ]; then
		printf '%s\n' 'unable to allocate npm barrier participant' >&2
		exit 91
	fi
	if [ ! -f "$NPM_BARRIER_DIR/release" ]; then
		: > "$NPM_BARRIER_DIR/ready.$id"
		while [ ! -f "$NPM_BARRIER_DIR/release" ]; do :; done
	fi
	: > "$NPM_BARRIER_DIR/attempt.$id"
	if [ -f "$NPM_BARRIER_DIR/owner-release" ]; then
		decision=post-owner
	elif (set -C; : > "$NPM_BARRIER_DIR/lock") 2>/dev/null; then
		decision=owner
	else
		decision=overlap
	fi
	printf '%s\n' "$decision" > "$NPM_BARRIER_DIR/decision.$id.tmp"
	/bin/mv -- "$NPM_BARRIER_DIR/decision.$id.tmp" "$NPM_BARRIER_DIR/decision.$id"
	if [ "$decision" = owner ]; then
		while [ ! -f "$NPM_BARRIER_DIR/owner-release" ]; do :; done
	fi
fi

if [ "$tool" = "npm" ] && [ "${1-}" = "ci" ]; then
	printf 'complete\t%s\n' "$log_line" >> "$STUB_EVENT_LOG"
fi

if [ "$tool" = "split-sentinel" ]; then
	printf '%s\n' "$log_line" >> "$SPLIT_LOG"
	exit 73
fi

if [ "$tool:$*" = "${FAIL_CALL-}" ]; then
	exit 42
fi
exit 0
`

type makeFixture struct {
	dir       string
	makeBin   string
	logPath   string
	eventPath string
	stubs     string
}

func TestMakeVerifyPropagatesGateFailures(t *testing.T) {
	makeBin := requireGNMake(t)

	t.Run("baseline", func(t *testing.T) {
		fixture := newMakeFixture(t, makeBin, "checkout")
		output, err := fixture.run(t, nil, "verify")
		if err != nil {
			t.Fatalf("make verify with successful stubs: %v\n%s", err, output)
		}
	})

	for _, test := range []struct {
		name string
		call string
	}{
		{name: "golangci-lint", call: "golangci-lint:run ./..."},
		{name: "go-vet", call: "go:vet ./fixture/package"},
		{name: "coverage-check", call: "go:run ./tools/checkcoverage -profile=coverage.out -min=79.5"},
		{name: "trivy-image", call: "trivy:image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 packmon-server:local"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newMakeFixture(t, makeBin, "checkout")
			output, err := fixture.run(t, []string{"FAIL_CALL=" + test.call}, "verify")
			if err == nil {
				t.Fatalf("make verify succeeded after injected failure %q\n%s", test.call, output)
			}
			calls := readStubCalls(t, fixture.logPath)
			if countExactCall(calls, test.call) != 1 {
				t.Fatalf("injected call count = %d, want 1 for %q\ncalls:\n%s", countExactCall(calls, test.call), test.call, strings.Join(calls, "\n"))
			}
		})
	}
}

func TestMakeIntegrationTargetCoversAllTaggedPackages(t *testing.T) {
	makeBin := requireGNMake(t)
	fixture := newMakeFixture(t, makeBin, "checkout")

	output, err := fixture.run(t, nil, "test-integration")
	if err != nil {
		t.Fatalf("make test-integration with successful stubs: %v\n%s", err, output)
	}

	var taggedCalls [][]string
	for _, fields := range readStubCallFields(t, fixture.logPath) {
		if len(fields) >= 5 && fields[0] == "go" && slices.Equal(fields[1:5], []string{"test", "-count=1", "-tags", "integration"}) {
			taggedCalls = append(taggedCalls, fields)
		}
	}
	if len(taggedCalls) != 1 {
		t.Fatalf("integration-tagged go test call count = %d, want 1; calls:\n%s", len(taggedCalls), strings.Join(readStubCalls(t, fixture.logPath), "\n"))
	}

	gotPackages := taggedCalls[0][5:]
	seen := make(map[string]bool, len(gotPackages))
	for _, pkg := range gotPackages {
		if seen[pkg] {
			t.Fatalf("integration package %q appears more than once in argv %q", pkg, gotPackages)
		}
		seen[pkg] = true
	}
	wantPackages := taggedTestPackages(t, "integration")
	slices.Sort(gotPackages)
	if !slices.Equal(gotPackages, wantPackages) {
		t.Fatalf("integration package argv = %q, want exact tagged package inventory %q", gotPackages, wantPackages)
	}
}

func TestMakeLintRunsTagAwareGolangCIGate(t *testing.T) {
	makeBin := requireGNMake(t)
	wantTaggedPackages := taggedTestPackages(t, "integration", "e2e")
	wantTaggedArgs := append([]string{"run", "--build-tags", "integration,e2e"}, wantTaggedPackages...)
	wantTaggedCall := "golangci-lint:" + strings.Join(wantTaggedArgs, " ")

	assertCalls := func(t *testing.T, fixture makeFixture) {
		t.Helper()
		calls := readStubCallFields(t, fixture.logPath)
		normalCount := 0
		var runCalls [][]string
		var taggedCalls [][]string
		for _, fields := range calls {
			if len(fields) >= 2 && slices.Equal(fields[:2], []string{"golangci-lint", "run"}) {
				runCalls = append(runCalls, fields)
			}
			if slices.Equal(fields, []string{"golangci-lint", "run", "./..."}) {
				normalCount++
			}
			if len(fields) >= 4 && slices.Equal(fields[:4], []string{"golangci-lint", "run", "--build-tags", "integration,e2e"}) {
				taggedCalls = append(taggedCalls, fields)
			}
		}
		if normalCount != 1 {
			t.Fatalf("normal golangci-lint invocation count = %d, want 1; calls:\n%s", normalCount, strings.Join(readStubCalls(t, fixture.logPath), "\n"))
		}
		if len(runCalls) != 2 {
			t.Fatalf("golangci-lint run invocation count = %d, want exactly the normal and tag-aware gates; calls:\n%s", len(runCalls), strings.Join(readStubCalls(t, fixture.logPath), "\n"))
		}
		if len(taggedCalls) != 1 {
			t.Fatalf("tag-aware golangci-lint invocation count = %d, want 1; calls:\n%s", len(taggedCalls), strings.Join(readStubCalls(t, fixture.logPath), "\n"))
		}
		gotPackages := taggedCalls[0][4:]
		seen := make(map[string]bool, len(gotPackages))
		for _, pkg := range gotPackages {
			if seen[pkg] {
				t.Fatalf("tag-aware lint package %q appears more than once in argv %q", pkg, taggedCalls[0])
			}
			seen[pkg] = true
		}
		if !slices.Equal(taggedCalls[0][1:], wantTaggedArgs) {
			t.Fatalf("tag-aware golangci-lint argv = %q, want exact argv %q", taggedCalls[0], append([]string{"golangci-lint"}, wantTaggedArgs...))
		}
		slices.Sort(gotPackages)
		if !slices.Equal(gotPackages, wantTaggedPackages) {
			t.Fatalf("tag-aware lint package argv = %q, want exact tagged package inventory %q", gotPackages, wantTaggedPackages)
		}
	}

	t.Run("success", func(t *testing.T) {
		fixture := newMakeFixture(t, makeBin, "checkout")
		output, err := fixture.run(t, nil, "lint")
		if err != nil {
			t.Fatalf("make lint with successful stubs: %v\n%s", err, output)
		}
		assertCalls(t, fixture)
	})

	t.Run("tag-aware failure propagates", func(t *testing.T) {
		fixture := newMakeFixture(t, makeBin, "checkout")
		output, err := fixture.run(t, []string{"FAIL_CALL=" + wantTaggedCall}, "lint")
		if err == nil {
			t.Fatalf("make lint succeeded after injected tag-aware golangci-lint exit 42\n%s", output)
		}
		assertCalls(t, fixture)
		if countExactCall(readStubCalls(t, fixture.logPath), wantTaggedCall) != 1 {
			t.Fatalf("injected tag-aware golangci-lint invocation count = %d, want 1", countExactCall(readStubCalls(t, fixture.logPath), wantTaggedCall))
		}
	})
}

func TestTaggedTestPackagesIgnoreUntrackedIgnoredCopies(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	ignoredRoot := filepath.Join(root, ".gotmp")
	if err := os.MkdirAll(ignoredRoot, 0o750); err != nil {
		t.Fatalf("create ignored test root: %v", err)
	}
	fixtureDir, err := os.MkdirTemp(ignoredRoot, "tagged-inventory-")
	if err != nil {
		t.Fatalf("create ignored tagged-test copy: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(fixtureDir); err != nil {
			t.Errorf("remove ignored tagged-test copy: %v", err)
		}
	})

	fixturePath := filepath.Join(fixtureDir, "linux-source", "tests", "integration", "copied_test.go")
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o750); err != nil {
		t.Fatalf("create ignored tagged-test package: %v", err)
	}
	if err := os.WriteFile(fixturePath, []byte("//go:build integration\n\npackage integration\n"), 0o600); err != nil { //nolint:gosec // test-owned ignored fixture.
		t.Fatalf("write ignored tagged-test copy: %v", err)
	}
	rel, err := filepath.Rel(root, fixturePath)
	if err != nil {
		t.Fatalf("resolve ignored tagged-test path: %v", err)
	}
	ignoreCmd := exec.Command("git", "check-ignore", "--quiet", "--", filepath.ToSlash(rel))
	ignoreCmd.Dir = root
	if err := ignoreCmd.Run(); err != nil {
		t.Fatalf("fixture %s is not ignored by Git: %v", filepath.ToSlash(rel), err)
	}

	ignoredPackage := "./" + filepath.ToSlash(filepath.Dir(rel))
	if packages := taggedTestPackages(t, "integration", "e2e"); slices.Contains(packages, ignoredPackage) {
		t.Fatalf("tagged package inventory includes ignored untracked copy %q: %q", ignoredPackage, packages)
	}
}

func TestParallelMakeTargetsSerializeNPMCI(t *testing.T) {
	makeBin := requireGNMake(t)
	fixture := newMakeFixture(t, makeBin, "checkout")
	instrumentParallelNPMTargets(t, fixture.dir)
	barrierDir := filepath.Join(fixture.dir, "npm-barrier")
	if err := os.Mkdir(barrierDir, 0o750); err != nil {
		t.Fatalf("create npm barrier: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := fixture.command(ctx, []string{"NPM_BARRIER_DIR=" + barrierDir}, "-j3", "lint-web", "lint-openapi", "security")
	result := make(chan struct {
		output []byte
		err    error
	}, 1)
	go func() {
		output, err := cmd.CombinedOutput()
		result <- struct {
			output []byte
			err    error
		}{output: output, err: err}
	}()

	ready := waitForBarrierParticipants(t, barrierDir, 3, 3*time.Second)
	if err := os.WriteFile(filepath.Join(barrierDir, "release"), nil, 0o600); err != nil {
		t.Fatalf("release npm barrier: %v", err)
	}
	decided := waitForBarrierFiles(t, barrierDir, "decision", ready, 3*time.Second)
	if decided != ready {
		t.Fatalf("npm participants deciding before owner release = %d, want all %d ready participants", decided, ready)
	}
	if err := os.WriteFile(filepath.Join(barrierDir, "owner-release"), nil, 0o600); err != nil {
		t.Fatalf("release npm lock owner: %v", err)
	}
	completed := <-result
	if completed.err != nil {
		t.Fatalf("parallel make targets: %v\n%s", completed.err, completed.output)
	}
	attempts := countBarrierFiles(barrierDir, "attempt", 3)
	decisions := readBarrierDecisions(t, barrierDir, 3)

	calls := readStubCallRecords(t, fixture.logPath)
	var npmCalls []stubCall
	for _, call := range calls {
		if call.tool() == "npm" && len(call.args()) > 0 && call.args()[0] == "ci" {
			npmCalls = append(npmCalls, call)
		}
	}
	for _, call := range npmCalls {
		if !slices.Equal(call.args(), []string{"ci", "--ignore-scripts"}) {
			t.Fatalf("npm ci argv = %q, want exact argv %q", call.argv, []string{"npm", "ci", "--ignore-scripts"})
		}
		if call.cwd != fixture.dir {
			t.Fatalf("npm ci cwd = %q, want fixture checkout %q", call.cwd, fixture.dir)
		}
	}
	assertParallelTargetCalls(t, fixture, calls)

	owners := countDecision(decisions, "owner")
	overlaps := countDecision(decisions, "overlap")
	postOwner := countDecision(decisions, "post-owner")
	if overlaps > 0 {
		if ready != 3 || attempts != 3 || len(decisions) != 3 || owners != 1 || overlaps != 2 || postOwner != 0 || len(npmCalls) != 3 {
			t.Fatalf("npm overlap did not match the known bug: ready=%d attempts=%d decisions=%v exact calls=%d, want 3/3/(one owner, two overlap, zero post-owner)/3\ncalls:\n%s", ready, attempts, decisions, len(npmCalls), formatStubCalls(calls))
		}
		assertKnownParallelNPMBugTargets(t, npmCalls)
		t.Fatalf("parallel lint-web, lint-openapi, and security recipes overlapped npm ci in the shared checkout\ncalls:\n%s", formatStubCalls(calls))
	}
	if len(npmCalls) != 1 || npmCalls[0].target != "" || ready != 1 || attempts != 1 || len(decisions) != 1 || owners != 1 || postOwner != 0 {
		t.Fatalf("shared npm prerequisite state = calls %d target %q ready %d attempts %d decisions %v, want one target-neutral call and 1/1/(one owner, zero post-owner)\ncalls:\n%s", len(npmCalls), firstCallTarget(npmCalls), ready, attempts, decisions, formatStubCalls(calls))
	}
	assertSharedNPMEventOrder(t, fixture)
}

func TestMakeNPMCIPrerequisiteDoesNotTrustExistingNodeModules(t *testing.T) {
	makeBin := requireGNMake(t)
	fixture := newMakeFixture(t, makeBin, "checkout")
	instrumentParallelNPMTargets(t, fixture.dir)

	nodeModules := filepath.Join(fixture.dir, "node_modules")
	if err := os.Mkdir(nodeModules, 0o750); err != nil {
		t.Fatalf("create stale node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nodeModules, "stale-module"), []byte("stale\n"), 0o600); err != nil {
		t.Fatalf("write stale node_modules marker: %v", err)
	}

	for invocation := 1; invocation <= 2; invocation++ {
		output, err := fixture.run(t, nil, "lint-web")
		if err != nil {
			t.Fatalf("make lint-web invocation %d: %v\n%s", invocation, err, output)
		}
	}

	calls := readStubCallRecords(t, fixture.logPath)
	var npmCalls []stubCall
	var lintWebCalls []stubCall
	for _, call := range calls {
		switch {
		case slices.Equal(call.argv, []string{"npm", "ci", "--ignore-scripts"}):
			npmCalls = append(npmCalls, call)
		case slices.Equal(call.argv, []string{"npm", "run", "lint:web"}):
			lintWebCalls = append(lintWebCalls, call)
		}
	}
	if len(npmCalls) != 2 {
		t.Fatalf("npm ci calls = %d, want one for each make invocation despite existing node_modules\ncalls:\n%s", len(npmCalls), formatStubCalls(calls))
	}
	for _, call := range npmCalls {
		if call.target != "" || call.cwd != fixture.dir {
			t.Fatalf("shared npm prerequisite call = target %q cwd %q, want target-neutral call in %q", call.target, call.cwd, fixture.dir)
		}
	}
	if len(lintWebCalls) != 2 {
		t.Fatalf("lint:web calls = %d, want one for each make invocation\ncalls:\n%s", len(lintWebCalls), formatStubCalls(calls))
	}

	events := readStubEvents(t, fixture.eventPath)
	var npmCompletions []int
	var lintWebStarts []int
	for index, event := range events {
		if event.kind == "complete" && slices.Equal(event.call.argv, []string{"npm", "ci", "--ignore-scripts"}) {
			npmCompletions = append(npmCompletions, index)
		}
		if event.kind == "start" && slices.Equal(event.call.argv, []string{"npm", "run", "lint:web"}) {
			lintWebStarts = append(lintWebStarts, index)
		}
	}
	if len(npmCompletions) != 2 || len(lintWebStarts) != 2 ||
		npmCompletions[0] >= lintWebStarts[0] || lintWebStarts[0] >= npmCompletions[1] || npmCompletions[1] >= lintWebStarts[1] {
		t.Fatalf("npm completion/lint start order = %v/%v, want install-before-lint for both invocations", npmCompletions, lintWebStarts)
	}
}

func TestMakeTaggedTargetsPreserveBinaryDirWithSpaces(t *testing.T) {
	makeBin := requireGNMake(t)

	for _, test := range []struct {
		target   string
		tag      string
		packages []string
	}{
		{
			target: "test-integration",
			tag:    "integration",
			packages: []string{
				"./tests/integration",
				"./internal/db/postgres",
				"./internal/db/postgres/migrations",
				"./internal/server",
			},
		},
		{target: "test-e2e", tag: "e2e", packages: []string{"./tests/e2e"}},
	} {
		t.Run(test.target, func(t *testing.T) {
			fixture := newMakeFixture(t, makeBin, "checkout split-sentinel tail")
			splitLog := filepath.Join(fixture.dir, "split.log")
			output, err := fixture.run(t, []string{"SPLIT_LOG=" + splitLog}, test.target)
			calls := readStubCallRecords(t, fixture.logPath)
			wantTaggedArgv := append([]string{"go", "test", "-count=1", "-tags", test.tag}, test.packages...)
			var taggedCalls []stubCall
			var sentinelCalls []stubCall
			for _, call := range calls {
				if slices.Equal(call.argv, wantTaggedArgv) {
					taggedCalls = append(taggedCalls, call)
				}
				if call.tool() == "split-sentinel" {
					sentinelCalls = append(sentinelCalls, call)
				}
			}
			if err == nil {
				if len(taggedCalls) != 1 {
					t.Fatalf("successful make %s exact tagged invocation count = %d, want 1\ncalls:\n%s", test.target, len(taggedCalls), formatStubCalls(calls))
				}
				if taggedCalls[0].cwd != fixture.dir || taggedCalls[0].binaryDir != fixture.dir {
					t.Fatalf("successful make %s tagged invocation cwd/binary dir = %q/%q, want full fixture path %q", test.target, taggedCalls[0].cwd, taggedCalls[0].binaryDir, fixture.dir)
				}
				if len(sentinelCalls) != 0 || fileExists(splitLog) {
					t.Fatalf("successful make %s invoked split sentinel\ncalls:\n%s", test.target, formatStubCalls(calls))
				}
				return
			}

			if len(taggedCalls) != 0 || len(sentinelCalls) != 1 {
				t.Fatalf("failed make %s did not match the known split-path bug: tagged=%d sentinel=%d\n%s\ncalls:\n%s", test.target, len(taggedCalls), len(sentinelCalls), output, formatStubCalls(calls))
			}
			wantTruncatedDir := filepath.Join(filepath.Dir(fixture.dir), "checkout")
			wantSentinelArgv := append([]string{"split-sentinel", "tail", "go", "test", "-count=1", "-tags", test.tag}, test.packages...)
			if sentinelCalls[0].cwd != fixture.dir || sentinelCalls[0].binaryDir != wantTruncatedDir || !slices.Equal(sentinelCalls[0].argv, wantSentinelArgv) {
				t.Fatalf("split sentinel record = cwd %q, binary dir %q, argv %q; want cwd %q, binary dir %q, argv %q", sentinelCalls[0].cwd, sentinelCalls[0].binaryDir, sentinelCalls[0].argv, fixture.dir, wantTruncatedDir, wantSentinelArgv)
			}
			splitCalls := readStubCallRecords(t, splitLog)
			if len(splitCalls) != 1 || !sameStubCall(splitCalls[0], sentinelCalls[0]) {
				t.Fatalf("split interception log = %s, want exactly the sentinel record", formatStubCalls(splitCalls))
			}
			t.Skipf("OPEN F008-bugs-5: Makefile %s leaves PACKMON_TEST_BIN_DIR unquoted and splits checkout paths containing spaces", test.target)
		})
	}
}

func requireGNMake(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("GNU Make recipe execution is covered by the focused WSL test command")
	}
	makeBin, err := exec.LookPath("make")
	if err != nil {
		t.Skipf("GNU Make is unavailable: %v", err)
	}
	makeBin, err = filepath.Abs(makeBin)
	if err != nil {
		t.Fatalf("resolve GNU Make path: %v", err)
	}
	output, err := exec.Command(makeBin, "--version").Output() //nolint:gosec // absolute operator-installed test prerequisite.
	if err != nil {
		t.Skipf("inspect make implementation: %v", err)
	}
	if !strings.Contains(string(output), "GNU Make") {
		t.Skipf("%s is not GNU Make", makeBin)
	}
	return makeBin
}

func newMakeFixture(t *testing.T, makeBin, checkoutName string) makeFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), checkoutName)
	stubs := filepath.Join(dir, "stubs")
	if err := os.MkdirAll(stubs, 0o750); err != nil {
		t.Fatalf("create Make fixture: %v", err)
	}
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("read repository Makefile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), makefile, 0o600); err != nil { //nolint:gosec // test-owned temporary fixture path.
		t.Fatalf("write fixture Makefile: %v", err)
	}
	for _, name := range []string{
		"bash", "docker", "go", "gofumpt", "golangci-lint", "gosec", "govulncheck",
		"mkdir", "npm", "pwsh", "rm", "split-sentinel", "trivy",
	} {
		stubPath := filepath.Join(stubs, name)
		if err := os.WriteFile(stubPath, []byte(stubScript), 0o600); err != nil {
			t.Fatalf("write %s stub: %v", name, err)
		}
		if err := os.Chmod(stubPath, 0o700); err != nil { //nolint:gosec // test stub must be executable by its owner.
			t.Fatalf("make %s stub executable: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatalf("write dummy Dockerfile: %v", err)
	}
	return makeFixture{
		dir:       dir,
		makeBin:   makeBin,
		logPath:   filepath.Join(dir, "calls.log"),
		eventPath: filepath.Join(dir, "events.log"),
		stubs:     stubs,
	}
}

func instrumentParallelNPMTargets(t *testing.T, fixtureDir string) {
	t.Helper()
	path := filepath.Join(fixtureDir, "Makefile")
	data, err := os.ReadFile(path) //nolint:gosec // test-owned fixture path.
	if err != nil {
		t.Fatalf("read fixture Makefile for target instrumentation: %v", err)
	}
	type targetSpec struct {
		characteristic string
		seen           int
	}
	specs := map[string]*targetSpec{
		"lint-web":     {characteristic: "npm run lint:web"},
		"lint-openapi": {characteristic: "npm run lint:openapi"},
		"security":     {characteristic: "npm audit --audit-level=high"},
	}
	lines := strings.Split(string(data), "\n")
	current := ""
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(line, "\t") {
			candidate, _, hasColon := strings.Cut(trimmed, ":")
			candidate = strings.TrimSpace(candidate)
			if _, ok := specs[candidate]; ok {
				current = candidate
			} else {
				current = ""
			}
			if hasColon {
				continue
			}
		}
		if current == "" || !strings.HasPrefix(line, "\t") {
			continue
		}
		command := strings.TrimPrefix(line, "\t")
		if command == "npm ci --ignore-scripts" || command == specs[current].characteristic {
			lines[index] = "\tSTUB_TARGET=" + current + " " + command
			if command == specs[current].characteristic {
				specs[current].seen++
			}
		}
	}
	for target, spec := range specs {
		if spec.seen != 1 {
			t.Fatalf("fixture Makefile %s characteristic command %q count = %d, want 1", target, spec.characteristic, spec.seen)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil { //nolint:gosec // test-owned fixture path.
		t.Fatalf("write instrumented fixture Makefile: %v", err)
	}
}

func (f makeFixture) run(t *testing.T, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, err := f.command(ctx, extraEnv, args...).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("make %q timed out: %v\n%s", args, ctx.Err(), output)
	}
	return string(output), err
}

func (f makeFixture) command(ctx context.Context, extraEnv []string, args ...string) *exec.Cmd {
	variables := []string{
		"COMMIT=fixture", "DATE=fixture", "GOEXE=", "GO_PACKAGES=./fixture/package",
		"GOSEC_DIRS=./fixture/package", "GOFMT_FILES=fixture.go", "GOTMPDIR=" + filepath.Join(f.dir, ".gotmp"),
		"COVERAGE_MIN=79.5",
	}
	cmd := exec.CommandContext(ctx, f.makeBin, append(variables, args...)...) //nolint:gosec // fixed absolute GNU Make prerequisite.
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), "PATH="+f.stubs, "STUB_LOG="+f.logPath, "STUB_EVENT_LOG="+f.eventPath)
	cmd.Env = append(cmd.Env, extraEnv...)
	return cmd
}

func readStubCalls(t *testing.T, path string) []string {
	t.Helper()
	records := readStubCallRecords(t, path)
	calls := make([]string, 0, len(records))
	for _, record := range records {
		calls = append(calls, strings.Join(record.argv, "\t"))
	}
	return calls
}

func readStubCallFields(t *testing.T, path string) [][]string {
	t.Helper()
	records := readStubCallRecords(t, path)
	fields := make([][]string, 0, len(records))
	for _, record := range records {
		fields = append(fields, slices.Clone(record.argv))
	}
	return fields
}

type stubCall struct {
	cwd       string
	binaryDir string
	target    string
	argv      []string
}

func (c stubCall) tool() string {
	if len(c.argv) == 0 {
		return ""
	}
	return c.argv[0]
}

func (c stubCall) args() []string {
	if len(c.argv) < 2 {
		return nil
	}
	return c.argv[1:]
}

func readStubCallRecords(t *testing.T, path string) []stubCall {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-owned fixture path.
	if err != nil {
		t.Fatalf("read stub log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	records := make([]stubCall, 0, len(lines))
	for index, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 || fields[0] == "" || fields[3] == "" {
			t.Fatalf("stub log line %d is malformed: %q", index+1, line)
		}
		records = append(records, stubCall{
			cwd:       fields[0],
			binaryDir: fields[1],
			target:    fields[2],
			argv:      slices.Clone(fields[3:]),
		})
	}
	return records
}

func formatStubCalls(calls []stubCall) string {
	lines := make([]string, 0, len(calls))
	for _, call := range calls {
		lines = append(lines, fmt.Sprintf("cwd=%q PACKMON_TEST_BIN_DIR=%q target=%q argv=%q", call.cwd, call.binaryDir, call.target, call.argv))
	}
	return strings.Join(lines, "\n")
}

func sameStubCall(left, right stubCall) bool {
	return left.cwd == right.cwd && left.binaryDir == right.binaryDir && left.target == right.target && slices.Equal(left.argv, right.argv)
}

type stubEvent struct {
	kind string
	call stubCall
}

func readStubEvents(t *testing.T, path string) []stubEvent {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-owned fixture path.
	if err != nil {
		t.Fatalf("read stub event log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	events := make([]stubEvent, 0, len(lines))
	for index, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) < 5 || (fields[0] != "start" && fields[0] != "complete") || fields[1] == "" || fields[4] == "" {
			t.Fatalf("stub event line %d is malformed: %q", index+1, line)
		}
		events = append(events, stubEvent{
			kind: fields[0],
			call: stubCall{
				cwd:       fields[1],
				binaryDir: fields[2],
				target:    fields[3],
				argv:      slices.Clone(fields[4:]),
			},
		})
	}
	return events
}

func parallelTargetCharacteristics() map[string][]string {
	return map[string][]string{
		"lint-web":     {"npm", "run", "lint:web"},
		"lint-openapi": {"npm", "run", "lint:openapi"},
		"security":     {"npm", "audit", "--audit-level=high"},
	}
}

func assertParallelTargetCalls(t *testing.T, fixture makeFixture, calls []stubCall) {
	t.Helper()
	for target, wantArgv := range parallelTargetCharacteristics() {
		var matches []stubCall
		for _, call := range calls {
			if slices.Equal(call.argv, wantArgv) {
				matches = append(matches, call)
			}
		}
		if len(matches) != 1 || matches[0].target != target || matches[0].cwd != fixture.dir {
			t.Fatalf("%s characteristic calls = %s, want exactly one target=%q cwd=%q argv=%q", target, formatStubCalls(matches), target, fixture.dir, wantArgv)
		}
	}
}

func assertKnownParallelNPMBugTargets(t *testing.T, npmCalls []stubCall) {
	t.Helper()
	counts := make(map[string]int, 3)
	for _, call := range npmCalls {
		counts[call.target]++
	}
	for target := range parallelTargetCharacteristics() {
		if counts[target] != 1 {
			t.Fatalf("known parallel npm bug target mapping = %v, want exactly one install for each parallel target\ncalls:\n%s", counts, formatStubCalls(npmCalls))
		}
	}
	if len(counts) != 3 {
		t.Fatalf("known parallel npm bug includes unexpected target mapping %v\ncalls:\n%s", counts, formatStubCalls(npmCalls))
	}
}

func firstCallTarget(calls []stubCall) string {
	if len(calls) == 0 {
		return ""
	}
	return calls[0].target
}

func assertSharedNPMEventOrder(t *testing.T, fixture makeFixture) {
	t.Helper()
	events := readStubEvents(t, fixture.eventPath)
	var completions []int
	characteristicStart := make(map[string][]int)
	characteristics := parallelTargetCharacteristics()
	for index, event := range events {
		if event.kind == "complete" && slices.Equal(event.call.argv, []string{"npm", "ci", "--ignore-scripts"}) {
			if event.call.target != "" {
				t.Fatalf("shared npm install completion target = %q, want target-neutral", event.call.target)
			}
			completions = append(completions, index)
		}
		if event.kind != "start" {
			continue
		}
		for target, wantArgv := range characteristics {
			if slices.Equal(event.call.argv, wantArgv) {
				if event.call.target != target || event.call.cwd != fixture.dir {
					t.Fatalf("%s characteristic event has target/cwd %q/%q, want %q/%q", target, event.call.target, event.call.cwd, target, fixture.dir)
				}
				characteristicStart[target] = append(characteristicStart[target], index)
			}
		}
	}
	if len(completions) != 1 {
		t.Fatalf("shared npm install completion events = %v, want exactly one", completions)
	}
	for target := range characteristics {
		starts := characteristicStart[target]
		if len(starts) != 1 || completions[0] >= starts[0] {
			t.Fatalf("shared npm install completion index %d must precede the one %s characteristic start; starts=%v", completions[0], target, starts)
		}
	}
}

func readBarrierDecisions(t *testing.T, dir string, maxID int) map[int]string {
	t.Helper()
	decisions := make(map[int]string, maxID)
	for id := 1; id <= maxID; id++ {
		data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("decision.%d", id))) //nolint:gosec // test-owned fixture path.
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("read npm barrier decision %d: %v", id, err)
		}
		decision := strings.TrimSpace(string(data))
		if decision != "owner" && decision != "overlap" && decision != "post-owner" {
			t.Fatalf("npm barrier decision %d = %q, want owner, overlap, or post-owner", id, decision)
		}
		decisions[id] = decision
	}
	return decisions
}

func countDecision(decisions map[int]string, want string) int {
	count := 0
	for _, decision := range decisions {
		if decision == want {
			count++
		}
	}
	return count
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func countExactCall(calls []string, want string) int {
	parts := strings.SplitN(want, ":", 2)
	if len(parts) == 2 {
		want = parts[0] + "\t" + strings.ReplaceAll(parts[1], " ", "\t")
	}
	count := 0
	for _, call := range calls {
		if call == want {
			count++
		}
	}
	return count
}

func taggedTestPackages(t *testing.T, tags ...string) []string {
	t.Helper()
	if len(tags) == 0 {
		t.Fatal("derive tagged test packages: no build tags provided")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	cmd := exec.Command("git", "ls-files", "-z", "--", "*_test.go")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("list tracked Go test files: %v", err)
	}
	packages := make(map[string]bool)
	for _, rel := range strings.Split(string(output), "\x00") {
		if rel == "" {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		name := filepath.Base(path)
		expr, ok, parseErr := testFileBuildConstraint(path)
		if parseErr != nil {
			t.Fatalf("parse tracked test constraint %s: %v", rel, parseErr)
		}
		if !ok || !mentionsAnyBuildTag(expr, tags) {
			continue
		}
		context := build.Default
		context.BuildTags = slices.Clone(tags)
		matched, matchErr := context.MatchFile(filepath.Dir(path), name)
		if matchErr != nil {
			t.Fatalf("match tracked test file %s: %v", rel, matchErr)
		}
		if matched {
			packageDir, relErr := filepath.Rel(root, filepath.Dir(path))
			if relErr != nil {
				t.Fatalf("resolve tracked test package %s: %v", rel, relErr)
			}
			packages["./"+filepath.ToSlash(packageDir)] = true
		}
	}
	result := make([]string, 0, len(packages))
	for pkg := range packages {
		result = append(result, pkg)
	}
	slices.Sort(result)
	return result
}

func mentionsAnyBuildTag(expr constraint.Expr, tags []string) bool {
	for _, tag := range tags {
		if mentionsBuildTag(expr, tag) {
			return true
		}
	}
	return false
}

func testFileBuildConstraint(path string) (constraint.Expr, bool, error) {
	file, err := os.Open(path) //nolint:gosec // path is constrained to the repository walk.
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "//go:build ") {
			expr, parseErr := constraint.Parse(line)
			return expr, true, parseErr
		}
		if strings.HasPrefix(line, "package ") {
			break
		}
	}
	return nil, false, scanner.Err()
}

func mentionsBuildTag(expr constraint.Expr, tag string) bool {
	switch expr := expr.(type) {
	case *constraint.TagExpr:
		return expr.Tag == tag
	case *constraint.NotExpr:
		return mentionsBuildTag(expr.X, tag)
	case *constraint.AndExpr:
		return mentionsBuildTag(expr.X, tag) || mentionsBuildTag(expr.Y, tag)
	case *constraint.OrExpr:
		return mentionsBuildTag(expr.X, tag) || mentionsBuildTag(expr.Y, tag)
	default:
		return false
	}
}

func waitForBarrierParticipants(t *testing.T, dir string, want int, timeout time.Duration) int {
	t.Helper()
	return waitForBarrierFiles(t, dir, "ready", want, timeout)
}

func waitForBarrierFiles(t *testing.T, dir, prefix string, want int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		found := countBarrierFiles(dir, prefix, want)
		if found == want || time.Now().After(deadline) {
			return found
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func countBarrierFiles(dir, prefix string, maxID int) int {
	found := 0
	for id := 1; id <= maxID; id++ {
		if fileExists(filepath.Join(dir, fmt.Sprintf("%s.%d", prefix, id))) {
			found++
		}
	}
	return found
}
