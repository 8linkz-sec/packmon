package dockerimage

import "strings"

// Ref is a normalized Docker image reference. Name is the Packmon display
// identity; Registry/Repository/Reference are used for registry API calls.
type Ref struct {
	// Original is the raw reference string after trimming.
	Original string
	// Name is the display identity used in reports.
	Name string
	// Registry is the normalized registry host used for optional digest lookups.
	Registry string
	// Repository is the registry repository path.
	Repository string
	// Reference is the tag or digest value; missing tags normalize to latest.
	Reference string
	// Digest is true when Reference came from an image digest instead of a tag.
	Digest bool
}

// ParseRef normalizes a Docker image reference for report output and optional
// registry lookups. It rejects empty values, scratch, URL-like strings, and
// unresolved variable references, normalizes Docker Hub defaults, and returns
// false when the reference is not safe or complete enough to inventory.
func ParseRef(raw string) (Ref, bool) {
	raw, ok := validateRawRef(raw)
	if !ok {
		return Ref{}, false
	}

	namePart, reference, digest, ok := splitNameReference(raw)
	if !ok {
		return Ref{}, false
	}

	registry, displayRegistry, repository, ok := normalizeRegistryAndRepository(namePart)
	if !ok {
		return Ref{}, false
	}

	return Ref{
		Original:   raw,
		Name:       displayRegistry + "/" + repository,
		Registry:   registry,
		Repository: repository,
		Reference:  reference,
		Digest:     digest,
	}, true
}

func validateRawRef(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "scratch" || strings.Contains(raw, "://") || strings.HasPrefix(raw, "$") {
		return "", false
	}
	return raw, true
}

func splitNameReference(raw string) (string, string, bool, bool) {
	var (
		namePart  string
		reference string
		digest    bool
	)
	if strings.Contains(raw, "@") {
		namePart, reference = splitDigestReference(raw)
		digest = true
	} else {
		namePart, reference = splitTagReference(raw)
	}
	if namePart == "" || reference == "" {
		return "", "", false, false
	}
	return namePart, reference, digest, true
}

func splitDigestReference(raw string) (string, string) {
	at := strings.Index(raw, "@")
	namePart := raw[:at]
	reference := raw[at+1:]
	return stripNameTag(namePart), reference
}

func splitTagReference(raw string) (string, string) {
	namePart := raw
	reference := "latest"
	if colon := strings.LastIndex(namePart, ":"); colon > strings.LastIndex(namePart, "/") {
		reference = namePart[colon+1:]
		namePart = namePart[:colon]
	}
	return namePart, reference
}

func stripNameTag(namePart string) string {
	if colon := strings.LastIndex(namePart, ":"); colon > strings.LastIndex(namePart, "/") {
		return namePart[:colon]
	}
	return namePart
}

func normalizeRegistryAndRepository(namePart string) (string, string, string, bool) {
	registry := "registry-1.docker.io"
	displayRegistry := "docker.io"
	repository := namePart
	first := firstPathComponent(namePart)
	if hasExplicitRegistry(first) {
		registry = first
		displayRegistry = first
		repository = strings.TrimPrefix(namePart[len(first):], "/")
		if first == "docker.io" {
			registry = "registry-1.docker.io"
			displayRegistry = "docker.io"
		}
	}
	if repository == "" {
		return "", "", "", false
	}
	if registry == "registry-1.docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}
	return registry, displayRegistry, repository, true
}

func firstPathComponent(name string) string {
	if slash := strings.Index(name, "/"); slash >= 0 {
		return name[:slash]
	}
	return name
}

func hasExplicitRegistry(first string) bool {
	return strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost"
}
