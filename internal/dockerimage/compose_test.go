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
