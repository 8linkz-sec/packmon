package dockerimage

import (
	"strings"
	"testing"
)

func TestParseDockerfileImagesHandlesArgsAndStages(t *testing.T) {
	input := `
ARG GO_VERSION=1.26
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
RUN go build ./...
FROM alpine:3.23 AS server
FROM server AS final
FROM scratch AS empty
`
	images, err := ParseDockerfileImages(strings.NewReader(input), "Dockerfile")
	if err != nil {
		t.Fatalf("ParseDockerfileImages: %v", err)
	}
	if len(images) != 2 {
		t.Fatalf("images = %#v, want 2 external non-scratch images; stage aliases must not become image rows", images)
	}
	if images[0].Ref.Name != "docker.io/library/golang" || images[0].Ref.Reference != "1.26-alpine" {
		t.Fatalf("first image = %#v", images[0])
	}
	if images[0].Scope != "build" || images[0].Relation != "base" || !images[0].Direct {
		t.Fatalf("first provenance = %#v", images[0])
	}
	if got := strings.Join(images[0].Flags, ","); got != "stage=build" {
		t.Fatalf("first flags = %q, want stage=build", got)
	}
	if images[1].Ref.Name != "docker.io/library/alpine" || images[1].Ref.Reference != "3.23" {
		t.Fatalf("second image = %#v", images[1])
	}
	if images[1].Scope != "runtime" || images[1].Relation != "base" || !images[1].Direct {
		t.Fatalf("second provenance = %#v", images[1])
	}
	if got := strings.Join(images[1].Flags, ","); got != "stage=server" {
		t.Fatalf("second flags = %q, want stage=server", got)
	}
}

func TestParseDockerfileImagesIgnoresScratchBase(t *testing.T) {
	images, err := ParseDockerfileImages(strings.NewReader("FROM scratch AS rootfs\n"), "Dockerfile")
	if err != nil {
		t.Fatalf("ParseDockerfileImages: %v", err)
	}
	if len(images) != 0 {
		t.Fatalf("images = %#v, want no image rows for scratch", images)
	}
}

func TestParseDockerfileImagesReturnsParseErrorForBadFrom(t *testing.T) {
	_, err := ParseDockerfileImages(strings.NewReader("FROM :bad\n"), "Dockerfile")
	if err == nil {
		t.Fatal("ParseDockerfileImages returned nil error for invalid FROM")
	}
}

func TestParseDockerfileImagesRedactsInvalidFromValue(t *testing.T) {
	const raw = "https://user:token@example.internal/private/app"
	_, err := ParseDockerfileImages(strings.NewReader("FROM "+raw+"\n"), "Dockerfile")
	if err == nil {
		t.Fatal("ParseDockerfileImages returned nil error for invalid FROM")
	}
	msg := err.Error()
	for _, leaked := range []string{"user", "token", "example.internal", "/private/app", raw} {
		if strings.Contains(msg, leaked) {
			t.Fatalf("Dockerfile parse error leaked %q: %s", leaked, msg)
		}
	}
	for _, want := range []string{"Dockerfile:1", "invalid FROM image"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Dockerfile parse error missing %q: %s", want, msg)
		}
	}
}
