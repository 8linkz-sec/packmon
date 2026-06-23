package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/db"
)

const (
	maxSearchQueryLength = 128
	minSearchQueryLength = 2
	searchResultLimit    = 50
)

// SearchData is the view model for the search template.
type SearchData struct {
	ActiveNav    string
	Query        string
	AppliedQuery string
	Severity     string
	Finding      string
	Results      []db.PackageSearchResult
	HasMore      bool
	ResultLimit  int
	Error        string
}

// HandleSearch serves GET /search. It supports both full-page and HTMX
// partial responses: when the HX-Request header is present, only the
// results fragment is returned (for live search).
func HandleSearch(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "HX-Request")
		query := strings.TrimSpace(r.URL.Query().Get("q"))
		severity := normalizeSearchSeverity(r.URL.Query().Get("severity"))
		finding := normalizeSearchFindingType(r.URL.Query().Get("finding"))
		ctx := r.Context()

		var results []db.PackageSearchResult
		var searchError string
		var hasMore bool
		searchQuery := query
		queryLength := utf8.RuneCountInString(query)
		queryTooLong := queryLength > maxSearchQueryLength
		if queryTooLong {
			searchError = fmt.Sprintf("Search query must be %d characters or fewer.", maxSearchQueryLength)
			query = ""
			searchQuery = ""
		} else {
			if searchQuery != "" && queryLength < minSearchQueryLength {
				searchQuery = ""
			}
		}
		if !queryTooLong && searchQuery == "" && (severity != "" || finding != "") {
			searchError = fmt.Sprintf("Enter at least %d characters to search with filters.", minSearchQueryLength)
		}
		if !queryTooLong && searchError == "" && searchQuery != "" {
			var err error
			results, err = store.SearchPackages(ctx, db.PackageSearchParams{
				Query:       searchQuery,
				Severity:    severity,
				FindingType: finding,
				Limit:       searchResultLimit + 1,
			})
			if err != nil {
				logger.Error("search: query failed", "error", err, "query_length", queryLength, "severity", severity, "finding", finding)
				searchError = "Search failed. Try again or narrow the filters."
			} else if len(results) > searchResultLimit {
				hasMore = true
				results = results[:searchResultLimit]
			}
			normalizeSearchResultPreviews(results)
		}

		data := SearchData{
			ActiveNav:    "search",
			Query:        query,
			AppliedQuery: searchQuery,
			Severity:     severity,
			Finding:      finding,
			Results:      results,
			HasMore:      hasMore,
			ResultLimit:  searchResultLimit,
			Error:        searchError,
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

func normalizeSearchResultPreviews(results []db.PackageSearchResult) {
	for i := range results {
		results[i].VulnerabilityIDs = db.FormatSearchVulnerabilityIDPreview(results[i].VulnerabilityIDs, results[i].VulnerabilityCount)
	}
}

func normalizeSearchSeverity(raw string) string {
	severity := strings.ToUpper(strings.TrimSpace(raw))
	switch severity {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW":
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
