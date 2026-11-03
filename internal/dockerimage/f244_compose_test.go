package dockerimage

import (
	"strings"
	"testing"
)

func TestF244ParseComposeImagesBuildShapesAndAbsentServices(t *testing.T) {
	t.Setenv("PACKMON_F244_IMAGE", "docker.io/library/alpine:3.23")

	input := `
name: f244-fixture
services:
  absent:
  scalar-build:
    build: " ./worker "
  mapping-build:
    build:
      context: " ./api "
      dockerfile: " Dockerfile.api "
      target: " release "
  empty-build:
    build: {}
  host-environment-only:
    image: ${PACKMON_F244_IMAGE}
`
	images, err := ParseComposeImages(strings.NewReader(input), "compose.yml")
	if err != nil {
		t.Fatalf("ParseComposeImages(build shapes) error = %v", err)
	}
	if len(images) != 3 {
		t.Fatalf("ParseComposeImages(build shapes) = %+v, want three local builds", images)
	}

	for i, want := range []struct {
		name      string
		reference string
		flags     []string
	}{
		{
			name:      "scalar-build",
			reference: "scalar-build",
			flags:     []string{"service=scalar-build", "local-build", "context=./worker"},
		},
		{
			name:      "mapping-build",
			reference: "release",
			flags:     []string{"service=mapping-build", "local-build", "context=./api", "dockerfile=Dockerfile.api", "target=release"},
		},
		{
			name:      "empty-build",
			reference: "empty-build",
			flags:     []string{"service=empty-build", "local-build"},
		},
	} {
		got := images[i]
		if got.Ref.Name != "local/"+want.name || got.Ref.Reference != want.reference || !got.LocalBuild ||
			got.SourceFile != "compose.yml" || got.SourceType != SourceCompose || got.Relation != "compose-build" ||
			strings.Join(got.Flags, ",") != strings.Join(want.flags, ",") {
			t.Fatalf("build image %d = %+v, want name=%q reference=%q flags=%v", i, got, want.name, want.reference, want.flags)
		}
	}
}

func TestF244ParseComposeImagesRejectsReachableWrongNodeShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		yaml  string
		shape string
	}{
		{
			name: "service sequence",
			yaml: `services:
  app: []
`,
			shape: "!!seq",
		},
		{
			name: "build sequence",
			yaml: `services:
  app:
    build: []
`,
			shape: "!!seq",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			images, err := ParseComposeImages(strings.NewReader(tc.yaml), "compose.yml")
			if images != nil || err == nil {
				t.Fatalf("ParseComposeImages(%s) = (%+v, %v), want nil decode error", tc.name, images, err)
			}
			if msg := err.Error(); !strings.Contains(msg, "compose.yml: parse compose YAML") || !strings.Contains(msg, tc.shape) {
				t.Fatalf("ParseComposeImages(%s) error = %q, want source and generic node shape", tc.name, msg)
			}
		})
	}
}

func TestF244ParseComposeImagesRedactsMergedInvalidImageWithoutDirectLine(t *testing.T) {
	// The merged image is decoded into the service but has no direct image key
	// in that service node, which reaches the line-number fallback.
	//nolint:gosec // G101: fixture credential, deliberately fake.
	const raw = "https://user:token@example.internal/private/app"
	input := `
x-service: &service-defaults
  image: https://user:token@example.internal/private/app
services:
  app:
    <<: *service-defaults
`
	images, err := ParseComposeImages(strings.NewReader(input), "compose.yml")
	if images != nil || err == nil {
		t.Fatalf("ParseComposeImages(merged invalid image) = (%+v, %v), want nil error", images, err)
	}
	if got, want := err.Error(), "compose.yml: invalid image for compose service"; got != want {
		t.Fatalf("merged invalid image error = %q, want %q", got, want)
	}
	for _, leaked := range []string{"user", "token", "example.internal", "/private/app", raw} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("merged Compose image error leaked %q: %s", leaked, err)
		}
	}
}
