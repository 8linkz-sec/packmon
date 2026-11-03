package dockerimage

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestF247ParseDockerfileImagesEdges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantRefs  []string
		wantFlags [][]string
		wantErr   string
	}{
		{
			name:    "FROM flags without image",
			input:   "FROM --platform=linux/amd64 --mount=type=cache\n",
			wantErr: "Dockerfile:1: FROM without image",
		},
		{
			name: "full and inline comments",
			input: `# FROM private.example/ignored:latest
FROM alpine:3.23 # AS commented-stage
# trailing comment
`,
			wantRefs:  []string{"docker.io/library/alpine:3.23"},
			wantFlags: [][]string{nil},
		},
		{
			name: "case-insensitive chained stage aliases",
			input: `FROM alpine:3.23 AS Build
FROM build AS package
FROM PACKAGE AS final
`,
			wantRefs:  []string{"docker.io/library/alpine:3.23"},
			wantFlags: [][]string{{"stage=Build"}},
		},
		{
			name: "unbraced argument substitution",
			input: `ARG BASE=busybox
FROM $BASE:1.36
`,
			wantRefs:  []string{"docker.io/library/busybox:1.36"},
			wantFlags: [][]string{nil},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			images, err := ParseDockerfileImages(strings.NewReader(tc.input), "Dockerfile")
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("ParseDockerfileImages() error = %v, want %q", err, tc.wantErr)
				}
				if images != nil {
					t.Fatalf("ParseDockerfileImages() images = %#v after error, want nil", images)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDockerfileImages() error = %v", err)
			}
			gotRefs := make([]string, 0, len(images))
			gotFlags := make([][]string, 0, len(images))
			for _, image := range images {
				gotRefs = append(gotRefs, image.Ref.Name+":"+image.Ref.Reference)
				gotFlags = append(gotFlags, image.Flags)
			}
			if !reflect.DeepEqual(gotRefs, tc.wantRefs) || !reflect.DeepEqual(gotFlags, tc.wantFlags) {
				t.Fatalf("ParseDockerfileImages() = refs %v, flags %v; want refs %v, flags %v", gotRefs, gotFlags, tc.wantRefs, tc.wantFlags)
			}
		})
	}
}

func TestF247StripDockerfileComment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want string
	}{
		{name: "full comment", line: "# FROM private.example/ignored:latest", want: ""},
		{name: "inline comment", line: "FROM alpine:3.23 # AS commented-stage", want: "FROM alpine:3.23"},
		{name: "no comment", line: "FROM busybox:1.36", want: "FROM busybox:1.36"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripDockerfileComment(tc.line); got != tc.want {
				t.Fatalf("stripDockerfileComment(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

func TestF247ParseDockerfileImagesPropagatesReadErrorWithoutLeakingContent(t *testing.T) {
	t.Parallel()

	errRead := errors.New("injected read failure")
	// The parser must report the reader failure, not echo the Dockerfile line
	// that preceded it. That line can contain registry credentials or paths.
	const sensitiveLine = "# https://user:token@registry.internal/private/image"
	reader := io.MultiReader(strings.NewReader(sensitiveLine+"\n"), f247ErrorReader{err: errRead})

	images, err := ParseDockerfileImages(reader, "Dockerfile")
	if images != nil || err == nil || !errors.Is(err, errRead) {
		t.Fatalf("ParseDockerfileImages() = (%#v, %v), want nil and wrapped read failure", images, err)
	}
	if !strings.Contains(err.Error(), "Dockerfile: read Dockerfile") {
		t.Fatalf("read error = %q, want source and operation context", err)
	}
	for _, secret := range []string{sensitiveLine, "user", "token", "registry.internal", "/private/image"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("read error leaked Dockerfile content %q: %v", secret, err)
		}
	}
}

func TestF247ParseDockerArgEmptyAndNameOnlyForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		wantName  string
		wantValue string
		wantOK    bool
	}{
		{name: "empty", raw: " \t "},
		{name: "name only", raw: " BASE ", wantName: "BASE", wantOK: true},
		{name: "empty value", raw: " BASE = \t", wantName: "BASE", wantOK: true},
		{name: "blank name", raw: " \t = alpine"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, value, ok := parseDockerArg(tc.raw)
			if name != tc.wantName || value != tc.wantValue || ok != tc.wantOK {
				t.Fatalf("parseDockerArg(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.raw, name, value, ok, tc.wantName, tc.wantValue, tc.wantOK)
			}
		})
	}
}

type f247ErrorReader struct {
	err error
}

func (r f247ErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}
