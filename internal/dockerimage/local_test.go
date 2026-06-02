package dockerimage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

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
	if !strings.Contains(strings.Join(runner.args, " "), "image inspect") {
		t.Fatalf("runner args = %#v, want docker image inspect", runner.args)
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
	args []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.args = append([]string{name}, args...)
	return []byte(f.out), f.err
}
