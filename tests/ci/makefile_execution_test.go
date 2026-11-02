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
{
	printf '%s' "$tool"
	for arg do
		printf '\t%s' "$arg"
	done
	printf '\n'
} >> "$STUB_LOG"

if [ "$tool" = "gofumpt" ] && [ "${1-}" = "-version" ]; then
	printf '%s\n' 'gofumpt v0.9.2'
fi
if [ "$tool" = "golangci-lint" ] && [ "${1-}" = "version" ]; then
	printf '%s\n' 'golangci-lint has version 2.14.0'
fi

if [ "$tool" = "npm" ] && [ "${1-}" = "ci" ] && [ -n "${NPM_BARRIER_DIR-}" ]; then
	if [ ! -f "$NPM_BARRIER_DIR/release" ]; then
		id=
		for candidate in 1 2 3; do
			if (set -C; : > "$NPM_BARRIER_DIR/ready.$candidate") 2>/dev/null; then
				id=$candidate
				break
			fi
		done
		if [ -z "$id" ]; then
			printf '%s\n' 'unable to allocate npm barrier participant' >&2
			exit 91
		fi
		while [ ! -f "$NPM_BARRIER_DIR/release" ]; do :; done
		: > "$NPM_BARRIER_DIR/attempt.$id"
		if (set -C; : > "$NPM_BARRIER_DIR/lock") 2>/dev/null; then
			while [ ! -f "$NPM_BARRIER_DIR/owner-release" ]; do :; done
		else
			: > "$NPM_BARRIER_DIR/overlap"
		fi
	fi
fi

if [ "$tool" = "split-sentinel" ]; then
	{
		printf 'PACKMON_TEST_BIN_DIR=%s' "${PACKMON_TEST_BIN_DIR-}"
		for arg do
			printf '\t%s' "$arg"
		done
		printf '\n'
	} >> "$SPLIT_LOG"
	exit 73
fi

if [ "$tool:$*" = "${FAIL_CALL-}" ]; then
	exit 42
fi
exit 0
`

type makeFixture struct {
	dir     string
	makeBin string
	logPath string
	stubs   string
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
	wantPackages := integrationTaggedPackages(t)
	slices.Sort(gotPackages)
	if !slices.Equal(gotPackages, wantPackages) {
		t.Fatalf("integration package argv = %q, want exact tagged package inventory %q", gotPackages, wantPackages)
	}
}

func TestParallelMakeTargetsSerializeNPMCI(t *testing.T) {
	makeBin := requireGNMake(t)
	fixture := newMakeFixture(t, makeBin, "checkout")
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
	attempts := waitForBarrierFiles(t, barrierDir, "attempt", ready, 3*time.Second)
	if err := os.WriteFile(filepath.Join(barrierDir, "owner-release"), nil, 0o600); err != nil {
		t.Fatalf("release npm lock owner: %v", err)
	}
	completed := <-result
	if completed.err != nil {
		t.Fatalf("parallel make targets: %v\n%s", completed.err, completed.output)
	}
	if ready < 2 {
		if _, err := os.Stat(filepath.Join(barrierDir, "overlap")); err == nil {
			t.Fatal("npm overlap recorded without two concurrent barrier participants")
		}
		return
	}
	if attempts != ready {
		t.Fatalf("npm barrier attempts = %d, want %d ready participants", attempts, ready)
	}
	if _, err := os.Stat(filepath.Join(barrierDir, "overlap")); err != nil {
		t.Fatalf("%d concurrent npm ci calls did not record the expected shared-directory overlap: %v", ready, err)
	}
	t.Skip("OPEN F008-bugs-4: parallel lint-web, lint-openapi, and security recipes overlap npm ci in the shared checkout")
}

func TestMakeTaggedTargetsPreserveBinaryDirWithSpaces(t *testing.T) {
	makeBin := requireGNMake(t)

	for _, target := range []string{"test-integration", "test-e2e"} {
		t.Run(target, func(t *testing.T) {
			fixture := newMakeFixture(t, makeBin, "checkout split-sentinel tail")
			splitLog := filepath.Join(fixture.dir, "split.log")
			output, err := fixture.run(t, []string{"SPLIT_LOG=" + splitLog}, target)
			if err == nil {
				t.Fatalf("make %s unexpectedly preserved the unquoted binary directory\n%s", target, output)
			}
			data, readErr := os.ReadFile(splitLog) //nolint:gosec // test-owned fixture path.
			if readErr != nil {
				t.Fatalf("read split-word interception log: %v\nmake output:\n%s", readErr, output)
			}
			wantPrefix := "PACKMON_TEST_BIN_DIR=" + filepath.Join(filepath.Dir(fixture.dir), "checkout") + "\ttail\tgo\ttest\t-count=1\t-tags\t"
			if !strings.HasPrefix(strings.TrimSpace(string(data)), wantPrefix) {
				t.Fatalf("split-word interception = %q, want prefix %q", strings.TrimSpace(string(data)), wantPrefix)
			}
			t.Skipf("OPEN F008-bugs-5: Makefile %s leaves PACKMON_TEST_BIN_DIR unquoted and splits checkout paths containing spaces", target)
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
		dir:     dir,
		makeBin: makeBin,
		logPath: filepath.Join(dir, "calls.log"),
		stubs:   stubs,
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
	cmd.Env = append(os.Environ(), "PATH="+f.stubs, "STUB_LOG="+f.logPath)
	cmd.Env = append(cmd.Env, extraEnv...)
	return cmd
}

func readStubCalls(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test-owned fixture path.
	if err != nil {
		t.Fatalf("read stub log: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func readStubCallFields(t *testing.T, path string) [][]string {
	t.Helper()
	lines := readStubCalls(t, path)
	fields := make([][]string, 0, len(lines))
	for _, line := range lines {
		fields = append(fields, strings.Split(line, "\t"))
	}
	return fields
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

func integrationTaggedPackages(t *testing.T) []string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	packages := make(map[string]bool)
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		expr, ok, parseErr := testFileBuildConstraint(path)
		if parseErr != nil {
			return parseErr
		}
		if !ok || !mentionsBuildTag(expr, "integration") {
			return nil
		}
		context := build.Default
		context.BuildTags = []string{"integration"}
		matched, matchErr := context.MatchFile(filepath.Dir(path), entry.Name())
		if matchErr != nil {
			return matchErr
		}
		if matched {
			rel, relErr := filepath.Rel(root, filepath.Dir(path))
			if relErr != nil {
				return relErr
			}
			packages["./"+filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("derive integration-tagged packages: %v", err)
	}
	result := make([]string, 0, len(packages))
	for pkg := range packages {
		result = append(result, pkg)
	}
	slices.Sort(result)
	return result
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
		found := 0
		for id := 1; id <= want; id++ {
			if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("%s.%d", prefix, id))); err == nil {
				found++
			}
		}
		if found == want || time.Now().After(deadline) {
			return found
		}
		time.Sleep(10 * time.Millisecond)
	}
}
