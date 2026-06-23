package dockerimage

import (
	"context"
	"errors"
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
