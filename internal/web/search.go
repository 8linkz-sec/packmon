package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxSearchQueryLength = 128
	minSearchQueryLength = 2
	searchResultLimit    = 50
	searchIDPreviewLimit = 5
)

// SearchData is the view model for the search template.
type SearchData struct {
	ActiveNav    string
	Query        string
	AppliedQuery string
	Severity     string
	Finding      string
	Results      []PackageSearchResultView
	HasMore      bool
	Page         int
	StartResult  int
	EndResult    int
	ResultLimit  int
	PrevURL      string
	NextURL      string
	Error        string
}

type PackageSearchResultView struct {
	PackageSearchResult
	PackageQuery string
	NameSegments []SearchTextSegment
}

type SearchTextSegment struct {
	Text  string
	Match bool
}

// HandleSearch serves GET /search. It supports both full-page and HTMX
// partial responses: when the HX-Request header is present, only the
// results fragment is returned (for live search).
func HandleSearch(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "HX-Request")
		query := strings.TrimSpace(r.URL.Query().Get("q"))
		rawSeverity := r.URL.Query().Get("severity")
		rawFinding := r.URL.Query().Get("finding")
		severity := normalizeSearchSeverity(rawSeverity)
		finding := normalizeSearchFindingType(rawFinding)
		page := parseSearchPage(r.URL.Query().Get("page"))
		offset := searchPageOffset(page)
		ctx := r.Context()

		var results []PackageSearchResult
		var searchError string
		var hasMore bool
		searchQuery := query
		queryLength := utf8.RuneCountInString(query)
		queryTooLong := queryLength > maxSearchQueryLength
		if queryTooLong {
			searchError = webMessage(webMessageKey("search.error.query_too_long"), maxSearchQueryLength)
			query = ""
			searchQuery = ""
		} else {
			if searchQuery != "" && queryLength < minSearchQueryLength {
				searchQuery = ""
			}
		}
		if searchError == "" {
			searchError = invalidSearchFilterError(rawSeverity, rawFinding)
		}
		if searchError == "" && !queryTooLong && query != "" && searchQuery == "" {
			searchError = webMessage(webMessageKey("search.error.query_too_short"), minSearchQueryLength)
		}
		shouldSearch := searchQuery != "" || (query == "" && (severity != "" || finding != ""))
		if !queryTooLong && searchError == "" && shouldSearch {
			var err error
			results, err = store.SearchPackages(ctx, PackageSearchParams{
				Query:       searchQuery,
				Severity:    severity,
				FindingType: finding,
				Limit:       searchResultLimit + 1,
				Offset:      offset,
			})
			if err != nil {
				logger.Error("search: query failed", requestLogAttrs(r, "error", err, "query_length", queryLength, "severity", severity, "finding", finding)...)
				searchError = webMessage(webMessageKey("search.error.failed"))
			} else if len(results) > searchResultLimit {
				hasMore = true
				results = results[:searchResultLimit]
			}
			normalizeSearchResultPreviews(results)
		}
		startResult, endResult := searchResultWindow(offset, len(results))
		prevURL := ""
		if len(results) > 0 && page > 1 {
			prevURL = searchPageURL(searchQuery, severity, finding, page-1)
		}
		nextURL := ""
		if hasMore {
			nextURL = searchPageURL(searchQuery, severity, finding, page+1)
		}
		returnTo := searchPageURL(searchQuery, severity, finding, page)
		resultViews := packageSearchResultViews(results, searchQuery, returnTo)

		data := SearchData{
			ActiveNav:    "search",
			Query:        query,
			AppliedQuery: searchQuery,
			Severity:     severity,
			Finding:      finding,
			Results:      resultViews,
			HasMore:      hasMore,
			Page:         page,
			StartResult:  startResult,
			EndResult:    endResult,
			ResultLimit:  searchResultLimit,
			PrevURL:      prevURL,
			NextURL:      nextURL,
			Error:        searchError,
		}

		// HTMX partial response: only render the results block.
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := renderer.RenderPartial(w, "search.html", "search-results", data); err != nil {
				logger.Error("search: partial render failed", requestLogAttrs(r, "error", err)...)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
			return
		}

		if err := renderer.Render(w, "search.html", data); err != nil {
			logger.Error("search: render failed", requestLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

func packageSearchResultViews(results []PackageSearchResult, appliedQuery, returnTo string) []PackageSearchResultView {
	views := make([]PackageSearchResultView, len(results))
	for i, result := range results {
		views[i] = PackageSearchResultView{
			PackageSearchResult: result,
			PackageQuery:        packageSearchResultQuery(result, returnTo),
			NameSegments:        searchTextSegments(result.Name, appliedQuery),
		}
	}
	return views
}

func packageSearchResultQuery(result PackageSearchResult, returnTo string) string {
	parts := make([]string, 0, 2)
	if result.Version != "" {
		parts = append(parts, "version="+url.QueryEscape(result.Version))
	}
	if validatedReturnTo := validateSearchReturnTo(returnTo); validatedReturnTo != "" {
		parts = append(parts, "return_to="+url.QueryEscape(validatedReturnTo))
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

func searchTextSegments(text, query string) []SearchTextSegment {
	if text == "" {
		return nil
	}
	runes := []rune(text)
	matched := matchedSearchRunes(runes, query)
	if len(matched) == 0 {
		return []SearchTextSegment{{Text: text}}
	}

	segments := make([]SearchTextSegment, 0, len(runes))
	start := 0
	currentMatch := matched[0]
	for i := 1; i < len(runes); i++ {
		if matched[i] == currentMatch {
			continue
		}
		segments = append(segments, SearchTextSegment{
			Text:  string(runes[start:i]),
			Match: currentMatch,
		})
		start = i
		currentMatch = matched[i]
	}
	segments = append(segments, SearchTextSegment{
		Text:  string(runes[start:]),
		Match: currentMatch,
	})
	return segments
}

func matchedSearchRunes(text []rune, query string) []bool {
	terms := strings.Fields(query)
	if len(text) == 0 || len(terms) == 0 {
		return nil
	}

	matched := make([]bool, len(text))
	hasMatch := false
	for _, term := range terms {
		termRunes := []rune(term)
		if len(termRunes) == 0 || len(termRunes) > len(text) {
			continue
		}
		for i := 0; i <= len(text)-len(termRunes); i++ {
			if !strings.EqualFold(string(text[i:i+len(termRunes)]), term) {
				continue
			}
			for j := i; j < i+len(termRunes); j++ {
				matched[j] = true
			}
			hasMatch = true
		}
	}
	if !hasMatch {
		return nil
	}
	return matched
}

func normalizeSearchResultPreviews(results []PackageSearchResult) {
	for i := range results {
		results[i].VulnerabilityIDs = formatSearchVulnerabilityIDPreview(results[i].VulnerabilityIDs, results[i].VulnerabilityCount)
	}
}

func formatSearchVulnerabilityIDPreview(ids string, total int) string {
	parts := splitSearchVulnerabilityIDs(ids)
	if len(parts) == 0 {
		return ""
	}
	if len(parts) > searchIDPreviewLimit {
		parts = parts[:searchIDPreviewLimit]
	}
	if total > len(parts) {
		parts = append(parts, fmt.Sprintf("+%d more", total-len(parts)))
	}
	return strings.Join(parts, ", ")
}

func splitSearchVulnerabilityIDs(ids string) []string {
	raw := strings.Split(ids, ",")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseSearchPage(raw string) int {
	page, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || page < 1 {
		return 1
	}
	maxPage := int(^uint(0)>>1) / searchResultLimit
	if page > maxPage {
		return maxPage
	}
	return page
}

func searchPageOffset(page int) int {
	if page <= 1 {
		return 0
	}
	return (page - 1) * searchResultLimit
}

func searchResultWindow(offset, count int) (int, int) {
	if count <= 0 {
		return 0, 0
	}
	return offset + 1, offset + count
}

func searchPageURL(query, severity, finding string, page int) string {
	values := url.Values{}
	if query != "" {
		values.Set("q", query)
	}
	if severity != "" {
		values.Set("severity", severity)
	}
	if finding != "" {
		values.Set("finding", finding)
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	encoded := values.Encode()
	if encoded == "" {
		return "/search"
	}
	return "/search?" + encoded
}

func validateSearchReturnTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Scheme != "" || parsed.Host != "" || parsed.User != nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return ""
	}
	if parsed.Path != "/search" {
		return ""
	}

	values := parsed.Query()
	query := strings.TrimSpace(values.Get("q"))
	if utf8.RuneCountInString(query) > maxSearchQueryLength {
		return ""
	}
	if query != "" && utf8.RuneCountInString(query) < minSearchQueryLength {
		return ""
	}
	rawSeverity := values.Get("severity")
	rawFinding := values.Get("finding")
	if invalidSearchFilterError(rawSeverity, rawFinding) != "" {
		return ""
	}
	page, ok := parseSearchReturnToPage(values.Get("page"))
	if !ok {
		return ""
	}

	return searchPageURL(query, normalizeSearchSeverity(rawSeverity), normalizeSearchFindingType(rawFinding), page)
}

func parseSearchReturnToPage(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 1, true
	}
	page, err := strconv.Atoi(raw)
	if err != nil || page < 1 {
		return 0, false
	}
	maxPage := int(^uint(0)>>1) / searchResultLimit
	if page > maxPage {
		return 0, false
	}
	return page, true
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

func invalidSearchFilterError(rawSeverity, rawFinding string) string {
	trimmedSeverity := strings.TrimSpace(rawSeverity)
	if trimmedSeverity != "" && normalizeSearchSeverity(trimmedSeverity) == "" {
		return webMessage(webMessageKey("search.error.invalid_filter"), "severity", trimmedSeverity, "CRITICAL, HIGH, MEDIUM, or LOW")
	}

	trimmedFinding := strings.TrimSpace(rawFinding)
	if trimmedFinding != "" && normalizeSearchFindingType(trimmedFinding) == "" {
		return webMessage(webMessageKey("search.error.invalid_filter"), "finding", trimmedFinding, "vulnerability, malicious, supply_chain_risk, or lifecycle")
	}

	return ""
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
