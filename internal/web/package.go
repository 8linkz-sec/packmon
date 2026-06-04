package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

// PackageData is the view model for the package detail template.
type PackageData struct {
	ActiveNav       string
	Ecosystem       string
	Name            string
	Version         string
	Vulnerabilities []domain.Finding
	Malicious       []domain.Finding
	SupplyChain     []domain.Finding
	Lifecycle       []domain.Finding
	Sources         []string
}

type reputationFindingStore interface {
	FindReputationFindings(ctx context.Context, ecosystem, name, source string) ([]domain.Finding, error)
}

type refreshQueueStore interface {
	EnqueueRefresh(ctx context.Context, job *db.RefreshJob) (bool, int, error)
}

type lifecycleFindingStore interface {
	FindLifecycleFindingsBatch(ctx context.Context, packages []db.PackageQuery, now time.Time) ([]domain.Finding, error)
}

type refreshStatusData struct {
	Message string
	Error   bool
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
		version := strings.TrimSpace(r.URL.Query().Get("version"))

		vulns, err := store.FindVulnerabilities(ctx, ecosystem, name, version)
		if err != nil {
			logger.Error("package: failed to find vulnerabilities",
				"ecosystem", ecosystem, "name", name, "error", err)
		}

		mal, err := store.FindMalicious(ctx, ecosystem, name, version)
		if err != nil {
			logger.Error("package: failed to find malicious findings",
				"ecosystem", ecosystem, "name", name, "error", err)
		}

		supplyChain := []domain.Finding{}
		if reputationStore, ok := store.(reputationFindingStore); ok {
			reputation, err := reputationStore.FindReputationFindings(ctx, ecosystem, name, db.ReputationSourceReversingLabs)
			if err != nil {
				logger.Error("package: failed to find reputation findings",
					"ecosystem", ecosystem, "name", name, "error", err)
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
		if lifecycleStore, ok := store.(lifecycleFindingStore); ok && version != "" {
			lifecycle, err = lifecycleStore.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{{
				Ecosystem: ecosystem,
				Name:      name,
				Version:   version,
			}}, time.Now().UTC())
			if err != nil {
				logger.Error("package: failed to find lifecycle findings",
					"ecosystem", ecosystem, "name", name, "version", version, "error", err)
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
			ActiveNav:       "",
			Ecosystem:       ecosystem,
			Name:            name,
			Version:         version,
			Vulnerabilities: vulns,
			Malicious:       mal,
			SupplyChain:     supplyChain,
			Lifecycle:       lifecycle,
			Sources:         sources,
		}

		if err := renderer.Render(w, "package.html", data); err != nil {
			logger.Error("package: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

// HandlePackageRefresh serves POST /package/{ecosystem}/refresh/{name...}.
// It is the browser-facing refresh endpoint; API-key protected refresh remains
// under /api/v1 for CLI and integration clients.
func HandlePackageRefresh(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ecosystem := strings.ToLower(strings.TrimSpace(r.PathValue("ecosystem")))
		name := strings.TrimSpace(r.PathValue("name"))
		if ecosystem == "" || name == "" || !domain.Ecosystem(ecosystem).Valid() {
			renderRefreshStatus(w, renderer, logger, http.StatusBadRequest, "Invalid package refresh request.", true)
			return
		}

		queueStore, ok := store.(refreshQueueStore)
		if !ok {
			renderRefreshStatus(w, renderer, logger, http.StatusServiceUnavailable, "Package refresh is not available on this instance.", true)
			return
		}

		created, position, err := queueStore.EnqueueRefresh(r.Context(), &db.RefreshJob{
			Ecosystem: ecosystem,
			Name:      name,
			Source:    "socket",
			Priority:  0,
			Status:    "pending",
		})
		if err != nil {
			logger.Error("package refresh: enqueue failed", "ecosystem", ecosystem, "name", name, "error", err)
			renderRefreshStatus(w, renderer, logger, http.StatusInternalServerError, "Failed to queue package refresh.", true)
			return
		}

		message := fmt.Sprintf("Refresh queued at position %d.", position)
		if !created {
			message = fmt.Sprintf("Refresh already queued at position %d.", position)
		}
		renderRefreshStatus(w, renderer, logger, http.StatusOK, message, false)
	}
}

func renderRefreshStatus(w http.ResponseWriter, renderer *Renderer, logger *slog.Logger, status int, message string, isError bool) {
	w.WriteHeader(status)
	if err := renderer.RenderPartial(w, "package.html", "refresh-response", refreshStatusData{
		Message: message,
		Error:   isError,
	}); err != nil {
		logger.Error("package refresh: render failed", "error", err)
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
