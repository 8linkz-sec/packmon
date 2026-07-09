package dockerimage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("PACKMON_FAKE_DOCKER") == "1" {
		runFakeDocker()
		return
	}
	os.Exit(m.Run())
}

func TestExecInspectRunnerTerminatesOptionsBeforeImageRefs(t *testing.T) {
	fakeDockerDir := t.TempDir()
	installFakeDockerExecutable(t, fakeDockerDir)

	argsPath := filepath.Join(t.TempDir(), "args")
	pathValue := fakeDockerDir
	if oldPath := os.Getenv("PATH"); oldPath != "" {
		pathValue += string(os.PathListSeparator) + oldPath
	}
	t.Setenv("PATH", pathValue)
	t.Setenv("PACKMON_FAKE_DOCKER", "1")
	t.Setenv("PACKMON_FAKE_DOCKER_ARGS_FILE", argsPath)
	t.Setenv("PACKMON_FAKE_DOCKER_STDOUT", "fake inspect output")

	out, err := (execInspectRunner{}).Inspect(context.Background(), []string{"--format={{json .}}", "ghcr.io/acme/app:1.2.3"})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if got := string(out); got != "fake inspect output" {
		t.Fatalf("Inspect output = %q, want fake inspect output", got)
	}

	rawArgs, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read fake docker args: %v", err)
	}
	gotArgs := strings.Split(strings.TrimSuffix(string(rawArgs), "\n"), "\n")
	wantArgs := []string{"image", "inspect", "--", "--format={{json .}}", "ghcr.io/acme/app:1.2.3"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("docker argv = %#v, want %#v", gotArgs, wantArgs)
	}
}

func TestLocalInspectorExtractsRepoDigest(t *testing.T) {
	runner := &fakeRunner{out: `[{
		"RepoTags":["postgres:18-alpine"],
		"RepoDigests":["postgres@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],
		"Id":"sha256:local"
	}]`}
	inspector := LocalInspector{Runner: runner}
	ref, _ := ParseRef("postgres:18-alpine")

	got := inspector.Digests(context.Background(), []Ref{ref})
	if got[ref.Name] != "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" {
		t.Fatalf("digests = %#v", got)
	}
	if len(runner.refs) != 1 || runner.refs[0] != "docker.io/library/postgres:18-alpine" {
		t.Fatalf("runner refs = %#v, want docker.io/library/postgres:18-alpine", runner.refs)
	}
}

func TestLocalInspectorDegradesWhenDockerUnavailable(t *testing.T) {
	ref, _ := ParseRef("alpine:3.23")
	inspector := LocalInspector{Runner: &fakeRunner{err: errors.New("docker not found")}}

	got := inspector.Digests(context.Background(), []Ref{ref})
	if len(got) != 0 {
		t.Fatalf("digests = %#v, want empty when docker is unavailable", got)
	}
}

type fakeRunner struct {
	out  string
	err  error
	refs []string
}

func (f *fakeRunner) Inspect(_ context.Context, refs []string) ([]byte, error) {
	f.refs = append([]string(nil), refs...)
	return []byte(f.out), f.err
}

func installFakeDockerExecutable(t *testing.T, dir string) {
	t.Helper()

	name := "docker"
	if runtime.GOOS == "windows" {
		name = "docker.exe"
	}
	exe, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatalf("read test executable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), exe, 0o755); err != nil {
		t.Fatalf("write fake docker executable: %v", err)
	}
}

func runFakeDocker() {
	argsPath := os.Getenv("PACKMON_FAKE_DOCKER_ARGS_FILE")
	if argsPath == "" {
		fmt.Fprintln(os.Stderr, "PACKMON_FAKE_DOCKER_ARGS_FILE is required")
		os.Exit(2)
	}
	if err := os.WriteFile(argsPath, []byte(strings.Join(os.Args[1:], "\n")+"\n"), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write fake docker args: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprint(os.Stdout, os.Getenv("PACKMON_FAKE_DOCKER_STDOUT"))
}
