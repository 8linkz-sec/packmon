package dockerimage

import (
	"strings"
	"testing"
)

func TestParseComposeImagesFindsImageAndBuildServices(t *testing.T) {
	input := `
services:
  postgres:
    image: postgres:18-alpine
  packmon-server:
    build:
      context: .
      dockerfile: Dockerfile
      target: server
  worker:
    image: ghcr.io/acme/worker:v1
    build: .
`
	images, err := ParseComposeImages(strings.NewReader(input), "docker-compose.yml")
	if err != nil {
		t.Fatalf("ParseComposeImages: %v", err)
	}
	if len(images) != 3 {
		t.Fatalf("images = %#v, want 3 rows", images)
	}
	if images[0].Ref.Name != "docker.io/library/postgres" || images[0].Ref.Reference != "18-alpine" {
		t.Fatalf("postgres image = %#v", images[0])
	}
	if images[0].Scope != "runtime" || images[0].Relation != "compose" || !images[0].Direct {
		t.Fatalf("postgres provenance = %#v", images[0])
	}
	if !containsString(images[0].Flags, "service=postgres") {
		t.Fatalf("postgres flags = %#v, want service flag", images[0].Flags)
	}
	if !images[1].LocalBuild || images[1].Ref.Name != "local/packmon-server" || images[1].Ref.Reference != "server" {
		t.Fatalf("build-only row = %#v", images[1])
	}
	for _, want := range []string{"service=packmon-server", "local-build", "context=.", "dockerfile=Dockerfile", "target=server"} {
		if !containsString(images[1].Flags, want) {
			t.Fatalf("build-only flags = %#v, want %q", images[1].Flags, want)
		}
	}
	if !images[2].LocalBuild || images[2].Ref.Name != "ghcr.io/acme/worker" {
		t.Fatalf("image+build row = %#v", images[2])
	}
	if !containsString(images[2].Flags, "context=.") {
		t.Fatalf("image+build flags = %#v, want scalar build context", images[2].Flags)
	}
}

func TestResolveComposeImageDefault(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{"literal", "postgres:18-alpine", "postgres:18-alpine", true},
		{"colon-dash default", "${IMG:-cgr.dev/chainguard/postgres:18@sha256:abc}", "cgr.dev/chainguard/postgres:18@sha256:abc", true},
		{"dash default", "${IMG-nginx:1.27}", "nginx:1.27", true},
		{"partial default", "nginx:${TAG:-latest}", "nginx:latest", true},
		{"no default", "${IMG}", "", false},
		{"required", "${IMG:?must be set}", "", false},
		{"plus form unset", "${IMG:+override}", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveComposeImageDefault(tc.raw)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("resolveComposeImageDefault(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestParseComposeImagesResolvesVariableDefaults(t *testing.T) {
	input := `
services:
  postgres:
    image: ${PACKMON_POSTGRES_IMAGE:-cgr.dev/chainguard/postgres:18@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461}
  missing:
    image: ${UNSET_IMAGE}
  fallback:
    image: ${UNSET_IMAGE}
    build: .
`
	images, err := ParseComposeImages(strings.NewReader(input), "docker-compose.yml")
	if err != nil {
		t.Fatalf("ParseComposeImages: %v", err)
	}
	// postgres resolves to its declared default; the "missing" service has no
	// usable default and no build, so it is skipped; "fallback" falls back to
	// its local build image.
	if len(images) != 2 {
		t.Fatalf("images = %#v, want 2 rows (resolved default + local build)", images)
	}
	if !strings.Contains(images[0].Ref.Name, "chainguard/postgres") || images[0].Ref.Registry != "cgr.dev" {
		t.Fatalf("postgres resolved image = %#v", images[0].Ref)
	}
	if !containsString(images[0].Flags, "service=postgres") {
		t.Fatalf("postgres flags = %#v", images[0].Flags)
	}
	if !images[1].LocalBuild || !containsString(images[1].Flags, "service=fallback") {
		t.Fatalf("fallback build row = %#v", images[1])
	}
}

func TestParseComposeImagesRejectsMalformedYAML(t *testing.T) {
	_, err := ParseComposeImages(strings.NewReader("services:\n  bad: ["), "compose.yml")
	if err == nil {
		t.Fatal("ParseComposeImages returned nil error for malformed YAML")
	}
}

func TestParseComposeImagesRedactsInvalidImageValue(t *testing.T) {
	const raw = "https://user:token@example.internal/private/app"
	input := `
services:
  app:
    image: https://user:token@example.internal/private/app
`
	_, err := ParseComposeImages(strings.NewReader(input), "docker-compose.yml")
	if err == nil {
		t.Fatal("ParseComposeImages returned nil error for invalid image")
	}
	msg := err.Error()
	for _, leaked := range []string{"user", "token", "example.internal", "/private/app", raw} {
		if strings.Contains(msg, leaked) {
			t.Fatalf("Compose parse error leaked %q: %s", leaked, msg)
		}
	}
	for _, want := range []string{"docker-compose.yml:4", "invalid image for compose service"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Compose parse error missing %q: %s", want, msg)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
