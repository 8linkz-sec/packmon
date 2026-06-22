package dockerimage

import "testing"

func TestParseRefNormalizesDockerHubReferences(t *testing.T) {
	tests := []struct {
		raw       string
		name      string
		reference string
		registry  string
		repo      string
		digest    bool
	}{
		{"alpine:3.23", "docker.io/library/alpine", "3.23", "registry-1.docker.io", "library/alpine", false},
		{"postgres:18-alpine", "docker.io/library/postgres", "18-alpine", "registry-1.docker.io", "library/postgres", false},
		{"library/postgres:18-alpine", "docker.io/library/postgres", "18-alpine", "registry-1.docker.io", "library/postgres", false},
		{"docker.io/library/alpine:3.23", "docker.io/library/alpine", "3.23", "registry-1.docker.io", "library/alpine", false},
		{"ghcr.io/acme/app:v1.2.3", "ghcr.io/acme/app", "v1.2.3", "ghcr.io", "acme/app", false},
		{"postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "docker.io/library/postgres", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "registry-1.docker.io", "library/postgres", true},
		{"python:3.14.5-slim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "docker.io/library/python", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "registry-1.docker.io", "library/python", true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ref, ok := ParseRef(tt.raw)
			if !ok {
				t.Fatalf("ParseRef(%q) returned ok=false", tt.raw)
			}
			if ref.Name != tt.name || ref.Reference != tt.reference || ref.Registry != tt.registry || ref.Repository != tt.repo || ref.Digest != tt.digest {
				t.Fatalf("ParseRef(%q) = %#v", tt.raw, ref)
			}
		})
	}
}

func TestParseRefRejectsInvalidReferences(t *testing.T) {
	for _, raw := range []string{"", "scratch", "http://example.com/image:tag", "$EMPTY"} {
		if ref, ok := ParseRef(raw); ok {
			t.Fatalf("ParseRef(%q) = %#v, true; want false", raw, ref)
		}
	}
}
