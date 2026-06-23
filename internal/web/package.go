package web

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// PackageData is the view model for the package detail template.
type PackageData struct {
	ActiveNav                string
	Ecosystem                string
	Name                     string
	Version                  string
	Vulnerabilities          []domain.Finding
	VulnerabilitiesLoadError string
	Malicious                []domain.Finding
	MaliciousLoadError       string
	SupplyChain              []domain.Finding
	ReputationLoadError      string
	Lifecycle                []domain.Finding
	LifecycleLoadError       string
	Sources                  []string
}

type reputationFindingStore interface {
	FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error)
}

type reputationFindingBatchStore interface {
	FindReputationFindingsBatch(ctx context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error)
}

type lifecycleFindingStore interface {
	FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error)
}

// HandlePackage serves GET /package/{ecosystem}/{name...}.
// The {name...} wildcard captures the full remaining path, which is
// necessary for scoped package names like @scope/pkg or go module paths.
func HandlePackage(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ecosystem := strings.ToLower(strings.TrimSpace(r.PathValue("ecosystem")))
		name := r.PathValue("name")

		if ecosystem == "" || name == "" || !domain.Ecosystem(ecosystem).Valid() {
			http.NotFound(w, r)
			return
		}

		ctx := r.Context()
		version := strings.TrimSpace(r.URL.Query().Get("version"))

		vulns, err := store.FindVulnerabilities(ctx, ecosystem, name, version)
		vulnerabilitiesLoadError := ""
		if err != nil {
			logger.Error("package: failed to find vulnerabilities",
				"ecosystem", ecosystem, "name", name, "error", err)
			vulnerabilitiesLoadError = "Vulnerability findings could not be loaded. Check the server logs and database connection before relying on this section."
		}

		mal, err := store.FindMalicious(ctx, ecosystem, name, version)
		maliciousLoadError := ""
		if err != nil {
			logger.Error("package: failed to find malicious findings",
				"ecosystem", ecosystem, "name", name, "error", err)
			maliciousLoadError = "Malicious package reports could not be loaded. Check the server logs and database connection before relying on this section."
		}

		supplyChain := []domain.Finding{}
		reputationLoadError := ""
		if reputationStore, ok := store.(reputationFindingBatchStore); ok && version != "" {
			reputation, err := reputationStore.FindReputationFindingsBatch(ctx, []db.PackageQuery{{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
			}}, db.ReputationSourceReversingLabs)
			if err != nil {
				logger.Error("package: failed to find reputation findings",
					"ecosystem", ecosystem, "name", name, "version", version, "error", err)
				reputationLoadError = "Reputation findings could not be loaded. Check the server logs and database connection before relying on malicious or supply-chain reputation sections."
			} else {
				for _, finding := range reputation {
					if finding.Type == domain.FindingTypeSupplyChainRisk {
						supplyChain = append(supplyChain, finding)
					} else {
						mal = append(mal, finding)
					}
				}
			}
		} else if reputationStore, ok := store.(reputationFindingStore); ok && version == "" {
			reputation, err := reputationStore.FindReputationFindings(ctx, ecosystem, name, db.ReputationSourceReversingLabs)
			if err != nil {
				logger.Error("package: failed to find reputation findings",
					"ecosystem", ecosystem, "name", name, "error", err)
				reputationLoadError = "Reputation findings could not be loaded. Check the server logs and database connection before relying on malicious or supply-chain reputation sections."
			} else {
				for _, finding := range reputation {
					if finding.Type == domain.FindingTypeSupplyChainRisk {
						supplyChain = append(supplyChain, finding)
					} else {
						mal = append(mal, finding)
					}
				}
			}
		}

		lifecycle := []domain.Finding{}
		lifecycleLoadError := ""
		if lifecycleStore, ok := store.(lifecycleFindingStore); ok && version != "" {
			lifecycle, err = lifecycleStore.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
			}}, time.Now().UTC())
			if err != nil {
				logger.Error("package: failed to find lifecycle findings",
					"ecosystem", ecosystem, "name", name, "version", version, "error", err)
				lifecycleLoadError = "Lifecycle findings could not be loaded. Check the server logs and database connection before relying on this section."
			}
		}

		// Collect unique sources.
		sourceSet := make(map[string]struct{})
		for _, f := range vulns {
			sourceSet[f.Source] = struct{}{}
		}
		for _, f := range mal {
			sourceSet[f.Source] = struct{}{}
		}
		for _, f := range supplyChain {
			sourceSet[f.Source] = struct{}{}
		}
		for _, f := range lifecycle {
			sourceSet[f.Source] = struct{}{}
		}
		sources := make([]string, 0, len(sourceSet))
		for s := range sourceSet {
			sources = append(sources, s)
		}

		// Sort sources alphabetically for stable display.
		sortStrings(sources)

		data := PackageData{
			ActiveNav:                "",
			Ecosystem:                ecosystem,
			Name:                     name,
			Version:                  version,
			Vulnerabilities:          vulns,
			VulnerabilitiesLoadError: vulnerabilitiesLoadError,
			Malicious:                mal,
			MaliciousLoadError:       maliciousLoadError,
			SupplyChain:              supplyChain,
			ReputationLoadError:      reputationLoadError,
			Lifecycle:                lifecycle,
			LifecycleLoadError:       lifecycleLoadError,
			Sources:                  sources,
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
