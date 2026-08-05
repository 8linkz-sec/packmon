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

func TestValidateRawRefRejectsUnsupportedForms(t *testing.T) {
	tests := []string{"", " scratch ", "http://example.com/image:tag", "$EMPTY"}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if got, ok := validateRawRef(raw); ok {
				t.Fatalf("validateRawRef(%q) = %q, true; want false", raw, got)
			}
		})
	}
}

func TestSplitNameReferencePrioritizesDigestOverTag(t *testing.T) {
	name, reference, digest, ok := splitNameReference("python:3.14.5-slim@sha256:aaaaaaaa")
	if !ok {
		t.Fatal("splitNameReference returned ok=false")
	}
	if name != "python" || reference != "sha256:aaaaaaaa" || !digest {
		t.Fatalf("splitNameReference returned name=%q reference=%q digest=%v", name, reference, digest)
	}
}

func TestSplitNameReferenceUsesLatestWhenNoTagOrDigest(t *testing.T) {
	name, reference, digest, ok := splitNameReference("registry.example.test/acme/app")
	if !ok {
		t.Fatal("splitNameReference returned ok=false")
	}
	if name != "registry.example.test/acme/app" || reference != "latest" || digest {
		t.Fatalf("splitNameReference returned name=%q reference=%q digest=%v", name, reference, digest)
	}
}

func TestNormalizeRegistryAndRepository(t *testing.T) {
	tests := []struct {
		namePart        string
		registry        string
		displayRegistry string
		repository      string
	}{
		{"alpine", "registry-1.docker.io", "docker.io", "library/alpine"},
		{"library/postgres", "registry-1.docker.io", "docker.io", "library/postgres"},
		{"docker.io/library/alpine", "registry-1.docker.io", "docker.io", "library/alpine"},
		{"ghcr.io/acme/app", "ghcr.io", "ghcr.io", "acme/app"},
		{"localhost:5000/acme/app", "localhost:5000", "localhost:5000", "acme/app"},
	}

	for _, tt := range tests {
		t.Run(tt.namePart, func(t *testing.T) {
			registry, displayRegistry, repository, ok := normalizeRegistryAndRepository(tt.namePart)
			if !ok {
				t.Fatalf("normalizeRegistryAndRepository(%q) returned ok=false", tt.namePart)
			}
			if registry != tt.registry || displayRegistry != tt.displayRegistry || repository != tt.repository {
				t.Fatalf("normalizeRegistryAndRepository(%q) = registry %q, displayRegistry %q, repository %q", tt.namePart, registry, displayRegistry, repository)
			}
		})
	}
}
