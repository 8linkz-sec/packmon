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
	Results   []db.PackageSearchResult
}

// HandleSearch serves GET /search. It supports both full-page and HTMX
// partial responses: when the HX-Request header is present, only the
// results fragment is returned (for live search).
func HandleSearch(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := strings.TrimSpace(r.URL.Query().Get("q"))
		ctx := r.Context()

		var results []db.PackageSearchResult
		if query != "" {
			var err error
			results, err = store.SearchPackages(ctx, query, 50)
			if err != nil {
				logger.Error("search: query failed", "error", err, "query", query)
			}
		}

		data := SearchData{
			ActiveNav: "search",
			Query:     query,
			Results:   results,
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
