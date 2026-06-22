package dockerimage

import "strings"

// Ref is a normalized Docker image reference. Name is the Packmon display
// identity; Registry/Repository/Reference are used for registry API calls.
type Ref struct {
	Original   string
	Name       string
	Registry   string
	Repository string
	Reference  string
	Digest     bool
}

func ParseRef(raw string) (Ref, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "scratch" || strings.Contains(raw, "://") || strings.HasPrefix(raw, "$") {
		return Ref{}, false
	}

	namePart := raw
	reference := "latest"
	digest := false
	if at := strings.Index(namePart, "@"); at >= 0 {
		reference = namePart[at+1:]
		namePart = namePart[:at]
		digest = true
		if colon := strings.LastIndex(namePart, ":"); colon > strings.LastIndex(namePart, "/") {
			namePart = namePart[:colon]
		}
	} else if colon := strings.LastIndex(namePart, ":"); colon > strings.LastIndex(namePart, "/") {
		reference = namePart[colon+1:]
		namePart = namePart[:colon]
	}
	if namePart == "" || reference == "" {
		return Ref{}, false
	}

	registry := "registry-1.docker.io"
	displayRegistry := "docker.io"
	repository := namePart
	first := namePart
	if slash := strings.Index(namePart, "/"); slash >= 0 {
		first = namePart[:slash]
	}
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		registry = first
		displayRegistry = first
		repository = strings.TrimPrefix(namePart[len(first):], "/")
		if first == "docker.io" {
			registry = "registry-1.docker.io"
			displayRegistry = "docker.io"
		}
	}
	if repository == "" {
		return Ref{}, false
	}
	if registry == "registry-1.docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
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
