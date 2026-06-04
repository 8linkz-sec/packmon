package web

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/8linkz/packmon/internal/db"
)

// SearchData is the view model for the search template.
type SearchData struct {
	ActiveNav string
	Query     string
	Severity  string
	Finding   string
	Results   []db.PackageSearchResult
	Error     string
}

// HandleSearch serves GET /search. It supports both full-page and HTMX
// partial responses: when the HX-Request header is present, only the
// results fragment is returned (for live search).
func HandleSearch(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := strings.TrimSpace(r.URL.Query().Get("q"))
		severity := normalizeSearchSeverity(r.URL.Query().Get("severity"))
		finding := normalizeSearchFindingType(r.URL.Query().Get("finding"))
		ctx := r.Context()

		var results []db.PackageSearchResult
		var searchError string
		if query != "" || severity != "" || finding != "" {
			var err error
			results, err = store.SearchPackages(ctx, db.PackageSearchParams{
				Query:       query,
				Severity:    severity,
				FindingType: finding,
				Limit:       50,
			})
			if err != nil {
				logger.Error("search: query failed", "error", err, "query", query, "severity", severity, "finding", finding)
				searchError = "Search failed. Try again or narrow the filters."
			}
		}

		data := SearchData{
			ActiveNav: "search",
			Query:     query,
			Severity:  severity,
			Finding:   finding,
			Results:   results,
			Error:     searchError,
		}

		// HTMX partial response: only render the results block.
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := renderer.RenderPartial(w, "search.html", "search-results", data); err != nil {
				logger.Error("search: partial render failed", "error", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
			return
		}

		if err := renderer.Render(w, "search.html", data); err != nil {
			logger.Error("search: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

func normalizeSearchSeverity(raw string) string {
	severity := strings.ToUpper(strings.TrimSpace(raw))
	switch severity {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN":
		return severity
	default:
		return ""
	}
}

func normalizeSearchFindingType(raw string) string {
	finding := strings.ToLower(strings.TrimSpace(raw))
	switch finding {
	case "", "vulnerability", "malicious", "supply_chain_risk", "lifecycle":
		return finding
	default:
		return ""
	}
}
