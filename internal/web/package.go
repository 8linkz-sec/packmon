package web

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/8linkz/packmon/internal/domain"
)

// PackageData is the view model for the package detail template.
type PackageData struct {
	ActiveNav       string
	Ecosystem       string
	Name            string
	Vulnerabilities []domain.Finding
	Malicious       []domain.Finding
	Sources         []string
}

// HandlePackage serves GET /package/{ecosystem}/{name...}.
// The {name...} wildcard captures the full remaining path, which is
// necessary for scoped package names like @scope/pkg or go module paths.
func HandlePackage(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ecosystem := r.PathValue("ecosystem")
		name := r.PathValue("name")

		if ecosystem == "" || name == "" {
			http.NotFound(w, r)
			return
		}

		ctx := r.Context()

		vulns, err := store.FindVulnerabilities(ctx, ecosystem, name, "")
		if err != nil {
			logger.Error("package: failed to find vulnerabilities",
				"ecosystem", ecosystem, "name", name, "error", err)
		}

		mal, err := store.FindMalicious(ctx, ecosystem, name, "")
		if err != nil {
			logger.Error("package: failed to find malicious findings",
				"ecosystem", ecosystem, "name", name, "error", err)
		}

		// Collect unique sources.
		sourceSet := make(map[string]struct{})
		for _, f := range vulns {
			sourceSet[f.Source] = struct{}{}
		}
		for _, f := range mal {
			sourceSet[f.Source] = struct{}{}
		}
		sources := make([]string, 0, len(sourceSet))
		for s := range sourceSet {
			sources = append(sources, s)
		}

		// Sort sources alphabetically for stable display.
		sortStrings(sources)

		data := PackageData{
			ActiveNav:       "",
			Ecosystem:       ecosystem,
			Name:            name,
			Vulnerabilities: vulns,
			Malicious:       mal,
			Sources:         sources,
		}

		if err := renderer.Render(w, "package.html", data); err != nil {
			logger.Error("package: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

// sortStrings sorts a string slice in place using insertion sort.
// This avoids importing sort for a small slice.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && strings.Compare(s[j], key) > 0 {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}
