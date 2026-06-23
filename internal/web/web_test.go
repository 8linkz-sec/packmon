package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// ---------------------------------------------------------------------------
// Mock store -- implements Store with minimal dummy data.
// ---------------------------------------------------------------------------

type mockStore struct {
	dashboardErr     error
	dailyErr         error
	scansErr         error
	searchErr        error
	dashboardStats   *db.DashboardStatsResult
	feedsErr         error
	feedStatuses     []db.FeedSyncStatus
	vulnErr          error
	malErr           error
	repErr           error
	lifecycleErr     error
	recentVulnErr    error
	recentVulns      []db.RecentVulnerability
	searchResults    []db.PackageSearchResult
	searchCalls      int
	lastSearch       db.PackageSearchParams
	vulnFindings     []domain.Finding
	malFindings      []domain.Finding
	repFindings      []domain.Finding
	repBatchFindings []domain.Finding
	packageLookups   int
	repBatchQueries  []struct {
		packages []db.PackageQuery
		source   string
	}
	lifecycle   []domain.Finding
	refreshErr  error
	refreshNew  bool
	refreshPos  int
	refreshJobs []db.RefreshJob
}

func (m *mockStore) DashboardStats(_ context.Context) (*db.DashboardStatsResult, error) {
	if m.dashboardErr != nil {
		return nil, m.dashboardErr
	}
	if m.dashboardStats != nil {
		return m.dashboardStats, nil
	}
	return &db.DashboardStatsResult{
		TotalPackages:        100,
		TotalVulnerabilities: 42,
		TotalMalicious:       3,
		TotalSupplyChainRisk: 2,
		TotalLifecycle:       4,
		BySeverity:           map[string]int{"CRITICAL": 5, "HIGH": 10, "MEDIUM": 20, "LOW": 7},
	}, nil
}

func (m *mockStore) CountScansByDay(_ context.Context, _ int) ([]db.DailyScanStats, error) {
	if m.dailyErr != nil {
		return nil, m.dailyErr
	}
	return []db.DailyScanStats{}, nil
}

func (m *mockStore) ListRecentScans(_ context.Context, _ int) ([]db.ScanLogEntry, error) {
	if m.scansErr != nil {
		return nil, m.scansErr
	}
	return []db.ScanLogEntry{}, nil
}

func (m *mockStore) ListRecentVulnerabilities(_ context.Context, _, _ int) ([]db.RecentVulnerability, error) {
	if m.recentVulnErr != nil {
		return nil, m.recentVulnErr
	}
	return m.recentVulns, nil
}

func (m *mockStore) SearchPackages(_ context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	m.searchCalls++
	m.lastSearch = params
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	if m.searchResults != nil {
		return append([]db.PackageSearchResult(nil), m.searchResults...), nil
	}
	if params.Query == "" && params.Severity == "" && params.FindingType == "" {
		return nil, nil
	}
	name := "lodash"
	if params.Severity == "CRITICAL" && params.Query == "" {
		name = "openssl"
	}
	if params.FindingType == "malicious" {
		name = "requests-evil"
		return []db.PackageSearchResult{
			{
				Ecosystem:          "pypi",
				Name:               name,
				FindingsCount:      2,
				VulnerabilityCount: 0,
				VulnerabilityIDs:   "",
				FindingTypes:       "malicious",
				Sources:            "openssf",
			},
		}, nil
	}
	if params.FindingType == "lifecycle" {
		return []db.PackageSearchResult{
			{
				Ecosystem:     "pypi",
				Name:          "django",
				Version:       "3.2.25",
				FindingsCount: 1,
				FindingTypes:  "lifecycle",
				Sources:       "endoflife.date",
			},
		}, nil
	}
	if params.Query == "logtrace" {
		return []db.PackageSearchResult{
			{
				Ecosystem:          "cargo",
				Name:               "logtrace",
				FindingsCount:      1,
				VulnerabilityCount: 1,
				VulnerabilityIDs:   "RUSTSEC-2026-0081",
				FindingTypes:       "vulnerability",
				Sources:            "osv",
			},
		}, nil
	}
	return []db.PackageSearchResult{
		{
			Ecosystem:          "npm",
			Name:               name,
			FindingsCount:      2,
			VulnerabilityCount: 1,
			VulnerabilityIDs:   "GHSA-test-1234",
			FindingTypes:       "vulnerability",
			Sources:            "osv,ghsa",
		},
	}, nil
}

func (m *mockStore) FindVulnerabilities(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	m.packageLookups++
	if m.vulnErr != nil {
		return nil, m.vulnErr
	}
	if m.vulnFindings != nil {
		return m.vulnFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindMalicious(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	m.packageLookups++
	if m.malErr != nil {
		return nil, m.malErr
	}
	if m.malFindings != nil {
		return m.malFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindReputationFindings(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	m.packageLookups++
	if m.repErr != nil {
		return nil, m.repErr
	}
	if m.repFindings != nil {
		return m.repFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindReputationFindingsBatch(_ context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error) {
	m.packageLookups++
	copied := append([]db.PackageQuery(nil), packages...)
	m.repBatchQueries = append(m.repBatchQueries, struct {
		packages []db.PackageQuery
		source   string
	}{packages: copied, source: source})
	if m.repErr != nil {
		return nil, m.repErr
	}
	if m.repBatchFindings != nil {
		return m.repBatchFindings, nil
	}
	if m.repFindings != nil {
		return m.repFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindLifecycleFindingsBatch(_ context.Context, _ []db.PackageQuery, _ time.Time) ([]domain.Finding, error) {
	m.packageLookups++
	if m.lifecycleErr != nil {
		return nil, m.lifecycleErr
	}
	return m.lifecycle, nil
}

func (m *mockStore) ListFeedSyncStatuses(_ context.Context) ([]db.FeedSyncStatus, error) {
	if m.feedsErr != nil {
		return nil, m.feedsErr
	}
	if m.feedStatuses != nil {
		return m.feedStatuses, nil
	}
	return []db.FeedSyncStatus{
		{FeedName: "osv", LastSyncStatus: "success", EntriesSynced: 500, EntriesTotal: 500},
	}, nil
}

func (m *mockStore) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	if m.refreshErr != nil {
		return false, 0, m.refreshErr
	}
	copyValue := *job
	m.refreshJobs = append(m.refreshJobs, copyValue)
	position := m.refreshPos
	if position == 0 {
		position = len(m.refreshJobs)
	}
	return m.refreshNew, position, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testRenderer creates a Renderer from the real embedded template FS.
func testRenderer() *Renderer {
	return NewRenderer(TemplateFS(), false)
}

// discardLogger returns a logger that writes nowhere.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// ---------------------------------------------------------------------------
// Dashboard tests
// ---------------------------------------------------------------------------

func TestHandleDashboard_ReturnsOK(t *testing.T) {
	store := &mockStore{
		recentVulns: []db.RecentVulnerability{
			{
				ID:          "GHSA-test-1234",
				Summary:     "Example advisory",
				Severity:    "HIGH",
				Ecosystem:   "actions",
				Name:        "example/action",
				Affected:    ">= 1.2.0, < 1.2.5",
				PublishedAt: time.Now().UTC().Add(-2 * time.Hour),
			},
		},
	}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleDashboard(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Dashboard status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Fatal("Dashboard response does not contain expected heading")
	}
	if !strings.Contains(body, `<h1 class="text-2xl font-bold">Dashboard</h1>`) {
		t.Fatal("Dashboard response does not contain a primary h1 heading")
	}
	if !strings.Contains(body, "Recently Published Vulnerabilities") {
		t.Fatal("Dashboard response does not contain the published vulnerabilities section")
	}
	if !strings.Contains(body, "/search?severity=CRITICAL") {
		t.Fatal("Dashboard response does not contain severity links to search")
	}
	if !strings.Contains(body, "/search?finding=malicious") {
		t.Fatal("Dashboard response does not contain the malicious packages link")
	}
	if !strings.Contains(body, "/search?finding=supply_chain_risk") {
		t.Fatal("Dashboard response does not contain the supply-chain risks link")
	}
	if !strings.Contains(body, "/search?finding=lifecycle") {
		t.Fatal("Dashboard response does not contain the lifecycle findings link")
	}
	if strings.Contains(body, `href="/scans"`) {
		t.Fatal("Dashboard response exposes the protected scan-log page in public navigation")
	}
	if !strings.Contains(body, "border-red-200") {
		t.Fatal("Dashboard response does not style malicious package count as a risk KPI")
	}
	if !strings.Contains(body, "Published") {
		t.Fatal("Dashboard response does not contain the published column heading")
	}
	if !strings.Contains(body, `href="https://github.com/advisories/GHSA-test-1234"`) {
		t.Fatalf("Dashboard advisory link does not point to the advisory resource:\n%s", body)
	}
	if strings.Contains(body, `href="/package/actions/example/action">GHSA-test-1234</a>`) {
		t.Fatalf("Dashboard advisory ID links to package page instead of advisory resource:\n%s", body)
	}
	for _, want := range []string{
		`<th scope="col" class="pb-2 pr-4">Advisory</th>`,
		`<th scope="col" class="pb-2 pr-4">Package</th>`,
		`<th scope="col" class="pb-2 pr-4">Severity</th>`,
		`<th scope="col" class="pb-2 pr-4">Summary</th>`,
		`<th scope="col" class="pb-2">Published</th>`,
		`class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border `,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dashboard response missing table/accessibility marker %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "Affected: &gt;= 1.2.0, &lt; 1.2.5") {
		t.Fatal("Dashboard response does not contain affected version details")
	}
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal("Dashboard response does not contain full HTML layout")
	}
	skipLink := `<a href="#main-content"`
	if !strings.Contains(body, skipLink) {
		t.Fatal("Dashboard response does not contain a skip link to the main content")
	}
	if !strings.Contains(body, `<main id="main-content"`) {
		t.Fatal("Dashboard response main element does not expose the skip-link target")
	}
	if strings.Index(body, skipLink) > strings.Index(body, "<nav") {
		t.Fatal("Dashboard skip link should be rendered before repeated navigation")
	}
}

func TestHandleDashboardDoesNotExposeUnknownSeverityFacet(t *testing.T) {
	store := &mockStore{
		dashboardStats: &db.DashboardStatsResult{
			TotalPackages:        2,
			TotalVulnerabilities: 2,
			BySeverity:           map[string]int{"HIGH": 1, "UNKNOWN": 1},
		},
	}
	handler := HandleDashboard(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Dashboard status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if strings.Contains(body, "UNKNOWN") || strings.Contains(body, "severity=UNKNOWN") {
		t.Fatalf("Dashboard exposed UNKNOWN as a public severity facet:\n%s", body)
	}
	if !strings.Contains(body, "/search?severity=HIGH") {
		t.Fatalf("Dashboard missing normal severity facet after filtering UNKNOWN:\n%s", body)
	}
}

func TestPublicNavigationLinksRemainAvailableAtSmallViewports(t *testing.T) {
	handler := HandleDashboard(&mockStore{}, testRenderer(), discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Dashboard status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	navStart := strings.Index(body, "<nav")
	navEnd := strings.Index(body, "</nav>")
	if navStart < 0 || navEnd < navStart {
		t.Fatalf("Dashboard response missing nav:\n%s", body)
	}
	nav := body[navStart:navEnd]
	for _, want := range []string{`href="/"`, `href="/search"`, `href="/feeds"`, `href="/admin/"`} {
		if !strings.Contains(nav, want) {
			t.Fatalf("public nav missing %s:\n%s", want, nav)
		}
	}
	if strings.Contains(nav, `href="/scans"`) {
		t.Fatalf("public nav exposed protected scan-log route:\n%s", nav)
	}
	if strings.Contains(nav, "hidden sm:flex") || strings.Contains(nav, "hidden sm:") {
		t.Fatalf("public nav hides primary links below the sm breakpoint:\n%s", nav)
	}
	if count := strings.Count(nav, "min-h-11"); count < 4 {
		t.Fatalf("public nav renders %d touch-height links, want at least 4:\n%s", count, nav)
	}
	if !strings.Contains(nav, "flex-wrap") && !strings.Contains(nav, "overflow-x-auto") {
		t.Fatalf("public nav does not provide a small-screen reflow/scroll strategy:\n%s", nav)
	}
}

func TestHandleDashboard_NonRootPath_Returns404(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleDashboard(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Dashboard non-root status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestPrivacyNoticePageAndFooterLinks(t *testing.T) {
	renderer := NewRendererWithLayoutLinks(TemplateFS(), false, LayoutLinks{
		PrivacyURL: "/privacy",
		LegalURL:   "https://example.test/legal",
	})
	logger := discardLogger()

	dashboardRec := httptest.NewRecorder()
	HandleDashboard(&mockStore{}, renderer, logger)(dashboardRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if dashboardRec.Code != http.StatusOK {
		t.Fatalf("Dashboard status = %d, want 200", dashboardRec.Code)
	}
	dashboardBody := dashboardRec.Body.String()
	for _, want := range []string{
		`href="/privacy"`,
		`Privacy`,
		`href="https://example.test/legal"`,
		`Legal Notice`,
	} {
		if !strings.Contains(dashboardBody, want) {
			t.Fatalf("Dashboard body missing footer link marker %q\nbody=%s", want, dashboardBody)
		}
	}

	privacyRec := httptest.NewRecorder()
	HandlePrivacy(renderer, logger)(privacyRec, httptest.NewRequest(http.MethodGet, "/privacy", nil))
	if privacyRec.Code != http.StatusOK {
		t.Fatalf("Privacy status = %d, want 200", privacyRec.Code)
	}
	privacyBody := privacyRec.Body.String()
	for _, want := range []string{
		"Privacy Notice",
		"packmon_session",
		"CSRF protection",
		"admin audit log",
		"scan metadata",
		`href="https://example.test/legal"`,
	} {
		if !strings.Contains(privacyBody, want) {
			t.Fatalf("Privacy body missing %q\nbody=%s", want, privacyBody)
		}
	}
}

func TestHandleDashboard_StoreErrorsRenderLoadErrors(t *testing.T) {
	store := &mockStore{
		dashboardErr:  errors.New("stats unavailable"),
		dailyErr:      errors.New("daily unavailable"),
		recentVulnErr: errors.New("recent unavailable"),
	}
	handler := HandleDashboard(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Dashboard fallback status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Dashboard metrics could not be loaded",
		"Scan activity could not be loaded",
		"Recent vulnerabilities could not be loaded",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dashboard error response missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Total Scans (7d)</div>\n      <div class=\"mt-1 text-3xl font-semibold\">0</div>") {
		t.Fatalf("Dashboard rendered scan-count zero as authoritative on load failure:\n%s", body)
	}
}

// ---------------------------------------------------------------------------
// Search tests
// ---------------------------------------------------------------------------

func TestHandleSearch_WithQuery_ReturnsOK(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleSearch(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/search?q=lodash", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search (with query) status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Package Search") {
		t.Fatal("Search response does not contain expected heading")
	}
	if !strings.Contains(body, "Severity Filter") {
		t.Fatal("Search response does not contain the severity filter")
	}
	if strings.Contains(body, `value="UNKNOWN"`) {
		t.Fatalf("Search response exposes UNKNOWN as a public severity filter:\n%s", body)
	}
	if !strings.Contains(body, "Finding Type") {
		t.Fatal("Search response does not contain the finding type filter")
	}
	if !strings.Contains(body, "Finding details") {
		t.Fatal("Search response does not contain the neutral finding details column")
	}
	if strings.Contains(body, "vulnerability database") {
		t.Fatalf("Search response still frames the whole package search as vulnerability-only:\n%s", body)
	}
}

func TestHandleSearch_EmptyQuery_ReturnsOK(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleSearch(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search (empty query) status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestHandleSearch_HTMXPartial(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleSearch(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/search?q=lodash", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search (HTMX partial) status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "HX-Request") {
		t.Fatalf("Search partial Vary = %q, want HX-Request", got)
	}

	body := rec.Body.String()
	// The partial response should NOT contain the full layout.
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal("Search HTMX partial should not contain full HTML layout")
	}
	for _, want := range []string{
		`id="search-status"`,
		`role="status"`,
		`aria-live="polite"`,
		`aria-atomic="true"`,
		`1 package search result`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search HTMX partial missing live status marker %q:\n%s", want, body)
		}
	}
}

func TestHandleSearchSummaryWrapsLongQueries(t *testing.T) {
	query := strings.Repeat("long-segment-", 8)
	store := &mockStore{searchResults: []db.PackageSearchResult{{
		Ecosystem:          "npm",
		Name:               "long-query-result",
		FindingsCount:      1,
		VulnerabilityCount: 1,
		VulnerabilityIDs:   "GHSA-long-query",
		Sources:            "osv",
	}}}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q="+query, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`text-sm text-gray-500 break-words`,
		`<bdi dir="auto" class="font-medium text-gray-700 break-all">"` + query + `"</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing long-query wrapping marker %q:\n%s", want, body)
		}
	}
}

func TestHandleSearchLiveControlsReplaceHistoryAndSyncRequests(t *testing.T) {
	store := &mockStore{}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=lodash", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if strings.Contains(body, `hx-push-url="true"`) {
		t.Fatalf("Search live controls still push history on every change:\n%s", body)
	}
	if got := strings.Count(body, `hx-replace-url="true"`); got != 3 {
		t.Fatalf("Search live controls hx-replace-url count = %d, want 3\n%s", got, body)
	}
	if got := strings.Count(body, `hx-sync="#search-form:replace"`); got != 3 {
		t.Fatalf("Search live controls hx-sync count = %d, want 3\n%s", got, body)
	}
}

func TestHandleSearchRejectsSeverityOnlyBeforeStore(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleSearch(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/search?severity=CRITICAL", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search (severity only) status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 0 {
		t.Fatalf("SearchPackages calls = %d, want 0 for severity-only search", store.searchCalls)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Enter at least 2 characters") {
		t.Fatalf("Search response missing admission hint for severity-only search:\n%s", body)
	}
	if strings.Contains(body, "openssl") {
		t.Fatalf("Search response rendered broad severity-only results:\n%s", body)
	}
}

func TestHandleSearchRejectsFindingOnlyBeforeStore(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleSearch(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/search?finding=malicious", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search (malicious only) status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 0 {
		t.Fatalf("SearchPackages calls = %d, want 0 for finding-only search", store.searchCalls)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Enter at least 2 characters") {
		t.Fatalf("Search response missing admission hint for finding-only search:\n%s", body)
	}
	if strings.Contains(body, "requests-evil") || strings.Contains(body, "2 malicious package findings") {
		t.Fatalf("Search response rendered broad finding-only results:\n%s", body)
	}
}

func TestHandleSearchUnfilteredShowsFindingTypes(t *testing.T) {
	store := &mockStore{searchResults: []db.PackageSearchResult{
		{
			Ecosystem:          "npm",
			Name:               "left-pad",
			FindingsCount:      2,
			VulnerabilityCount: 1,
			VulnerabilityIDs:   "GHSA-test-1234",
			FindingTypes:       "malicious, vulnerability",
			Sources:            "ghsa, openssf",
		},
	}}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=left-pad", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{"1 result", "Finding details", "1 advisory", "GHSA-test-1234", "Malicious package", "Vulnerability"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "result(s)") || strings.Contains(body, "1 results") {
		t.Fatalf("Search response still uses placeholder plural result label:\n%s", body)
	}
	if strings.Contains(body, "No known vulnerabilities") {
		t.Fatalf("Search response still renders a vulnerability-only empty state:\n%s", body)
	}
}

func TestHandleSearchLifecycleResultsLinkToVersionedPackageDetail(t *testing.T) {
	store := &mockStore{}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=django&finding=lifecycle", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="/package/pypi/django?version=3.2.25"`) {
		t.Fatalf("Lifecycle search result does not link to versioned package detail:\n%s", body)
	}
	if !strings.Contains(body, "Version: 3.2.25") {
		t.Fatalf("Lifecycle search result does not show version context:\n%s", body)
	}
}

func TestHandleSearch_ShowsVulnerabilityCountAndIDs(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleSearch(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/search?q=logtrace", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search (logtrace) status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "1 advisory") {
		t.Fatal("Search response does not contain the vulnerability advisory count")
	}
	if !strings.Contains(body, "RUSTSEC-2026-0081") {
		t.Fatal("Search response does not contain the advisory IDs")
	}
}

func TestHandleSearchCapsVulnerabilityIDPreview(t *testing.T) {
	store := &mockStore{searchResults: []db.PackageSearchResult{{
		Ecosystem:          "npm",
		Name:               "wide-advisory-package",
		FindingsCount:      7,
		VulnerabilityCount: 7,
		VulnerabilityIDs:   "GHSA-001, GHSA-002, GHSA-003, GHSA-004, GHSA-005, GHSA-006, GHSA-007",
		FindingTypes:       "vulnerability",
		Sources:            "osv",
	}}}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=wide", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "7 advisories") {
		t.Fatalf("Search response missing full advisory count:\n%s", body)
	}
	if !strings.Contains(body, "GHSA-001, GHSA-002, GHSA-003, GHSA-004, GHSA-005, &#43;2 more") {
		t.Fatalf("Search response missing capped advisory preview:\n%s", body)
	}
	if strings.Contains(body, "GHSA-006") || strings.Contains(body, "GHSA-007") {
		t.Fatalf("Search response rendered advisory IDs beyond the preview cap:\n%s", body)
	}
}

func TestHandleSearchRejectsTooLongQueryBeforeStore(t *testing.T) {
	store := &mockStore{}
	handler := HandleSearch(store, testRenderer(), discardLogger())
	query := strings.Repeat("a", 129)

	req := httptest.NewRequest(http.MethodGet, "/search?q="+query, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 0 {
		t.Fatalf("SearchPackages calls = %d, want 0 for overlong query", store.searchCalls)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Search query must be") {
		t.Fatalf("Search response missing query length validation error:\n%s", body)
	}
	if strings.Contains(body, query) {
		t.Fatal("Search response echoed the overlong raw query")
	}
}

func TestHandleSearchSingleCharacterQueryDoesNotHitStore(t *testing.T) {
	store := &mockStore{}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=a", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 0 {
		t.Fatalf("SearchPackages calls = %d, want 0 for one-character query", store.searchCalls)
	}
	if !strings.Contains(rec.Body.String(), `value="a"`) {
		t.Fatalf("Search response did not retain the visible query input:\n%s", rec.Body.String())
	}
}

func TestHandleSearchSingleCharacterQueryWithFilterDoesNotHitStore(t *testing.T) {
	store := &mockStore{}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=a&finding=malicious", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 0 {
		t.Fatalf("SearchPackages calls = %d, want 0 for one-character filtered query", store.searchCalls)
	}
	if !strings.Contains(rec.Body.String(), "Enter at least 2 characters") {
		t.Fatalf("Search response missing admission hint:\n%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "requests-evil") || strings.Contains(rec.Body.String(), `for "a"`) {
		t.Fatalf("Search response rendered or applied one-character filtered query:\n%s", rec.Body.String())
	}
}

func TestHandleSearchShowsTruncatedResultWindow(t *testing.T) {
	results := make([]db.PackageSearchResult, 51)
	for i := range results {
		results[i] = db.PackageSearchResult{
			Ecosystem:          "npm",
			Name:               fmt.Sprintf("pkg-%03d", i),
			FindingsCount:      1,
			VulnerabilityCount: 1,
			VulnerabilityIDs:   fmt.Sprintf("GHSA-test-%03d", i),
			Sources:            "osv",
		}
	}
	store := &mockStore{searchResults: results}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=pkg&severity=HIGH", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.lastSearch.Limit != 51 {
		t.Fatalf("SearchPackages limit = %d, want 51 for truncation detection", store.lastSearch.Limit)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Showing first 50 matches") {
		t.Fatalf("Search response missing truncation notice:\n%s", body)
	}
	if !strings.Contains(body, "pkg-049") {
		t.Fatalf("Search response missing last rendered result:\n%s", body)
	}
	if strings.Contains(body, "pkg-050") {
		t.Fatalf("Search response rendered the sentinel result beyond the visible window:\n%s", body)
	}
}

func TestHandleSearchErrorLogDoesNotIncludeRawQuery(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	store := &mockStore{searchErr: errors.New("search unavailable")}
	handler := HandleSearch(store, testRenderer(), logger)
	const query = "token-secret-search-query"

	req := httptest.NewRequest(http.MethodGet, "/search?q="+query, nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 1 {
		t.Fatalf("SearchPackages calls = %d, want 1", store.searchCalls)
	}
	if strings.Contains(logs.String(), query) {
		t.Fatalf("search error log leaked raw query %q: %s", query, logs.String())
	}
}

func TestHandleSearch_ErrorAndNormalizationBranches(t *testing.T) {
	store := &mockStore{searchErr: errors.New("search unavailable")}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=%20lodash%20&severity=invalid&finding=invalid", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search error partial status = %d, want %d", rec.Code, http.StatusOK)
	}
	if strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
		t.Fatal("Search error partial should not contain full HTML layout")
	}
	if !strings.Contains(rec.Body.String(), "Search failed") {
		t.Fatal("Search error partial should contain an error message")
	}
	for _, want := range []string{
		`id="search-status"`,
		`role="alert"`,
		`aria-live="assertive"`,
		`Search failed.`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("Search error partial missing live error marker %q:\n%s", want, rec.Body.String())
		}
	}

	if got := normalizeSearchSeverity(" unknown "); got != "" {
		t.Fatalf("normalizeSearchSeverity(unknown) = %q, want empty", got)
	}
	if got := normalizeSearchSeverity("invalid"); got != "" {
		t.Fatalf("normalizeSearchSeverity(invalid) = %q, want empty", got)
	}
	if got := normalizeSearchFindingType(" VULNERABILITY "); got != "vulnerability" {
		t.Fatalf("normalizeSearchFindingType(vulnerability) = %q", got)
	}
	if got := normalizeSearchFindingType("supply_chain_risk"); got != "supply_chain_risk" {
		t.Fatalf("normalizeSearchFindingType(supply_chain_risk) = %q", got)
	}
	if got := normalizeSearchFindingType("lifecycle"); got != "lifecycle" {
		t.Fatalf("normalizeSearchFindingType(lifecycle) = %q", got)
	}
	if got := normalizeSearchFindingType("invalid"); got != "" {
		t.Fatalf("normalizeSearchFindingType(invalid) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Feeds tests
// ---------------------------------------------------------------------------

func TestHandleFeeds_ReturnsOK(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleFeeds(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/feeds", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Feeds status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Feed Status") {
		t.Fatal("Feeds response does not contain expected heading")
	}
	for _, want := range []string{
		`src="/static/auto-refresh.js"`,
		`data-auto-refresh-control`,
		`data-auto-refresh-event="feed-status-refresh"`,
		`aria-controls="feed-status-container"`,
		`Pause auto-refresh`,
		`hx-trigger="feed-status-refresh from:body"`,
		`Feed status table`,
		`osv`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Feeds response missing auto-refresh pause control fragment %q", want)
		}
	}
	if strings.Contains(body, `hx-trigger="load, every 30s"`) {
		t.Fatal("Feeds response still uses direct htmx interval polling without a pause control")
	}
	if strings.Contains(body, "Loading feed status") {
		t.Fatalf("Feeds response still renders a permanent loading placeholder without htmx:\n%s", body)
	}
}

func TestHandleFeeds_PartialStatus(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandleFeeds(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/feeds?partial=status", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Feeds (partial) status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	// The partial response should NOT contain the full layout.
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal("Feeds partial should not contain full HTML layout")
	}
	if !strings.Contains(body, "500 / 500") {
		t.Fatalf("Feeds partial missing synced/total entries:\n%s", body)
	}
}

func TestFeedHealthStatusDisabledIsNeutral(t *testing.T) {
	status := db.FeedSyncStatus{
		FeedName:       "vulncheck",
		LastSyncStatus: "disabled",
		EntriesSynced:  0,
		EntriesTotal:   0,
	}

	if got, _ := feedHealth(status); got != "disabled" {
		t.Fatalf("feedHealth() status = %q, want %q", got, "disabled")
	}
}

func TestFeedHealthStatusZeroEntriesIsWarning(t *testing.T) {
	now := time.Now().UTC()
	status := db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncStatus: "success",
		LastSyncAt:     &now,
		EntriesSynced:  0,
		EntriesTotal:   0,
	}

	if got, _ := feedHealth(status); got != "warning" {
		t.Fatalf("feedHealth() status = %q, want %q", got, "warning")
	}
	if _, reason := feedHealth(status); reason != "no entries synced yet" {
		t.Fatalf("feedHealth() reason = %q, want no entries reason", reason)
	}
}

func TestHandleFeeds_StoreErrorRendersLoadError(t *testing.T) {
	handler := HandleFeeds(&mockStore{feedsErr: errors.New("feeds unavailable")}, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/feeds?partial=status", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Feeds error partial status = %d, want %d", rec.Code, http.StatusOK)
	}
	if strings.Contains(rec.Body.String(), "<!DOCTYPE html>") {
		t.Fatal("Feeds error partial should not contain full HTML layout")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Feed status could not be loaded") {
		t.Fatalf("Feeds error partial missing load error:\n%s", body)
	}
	if strings.Contains(body, "No feed sync data available") {
		t.Fatalf("Feeds error partial rendered empty feed state:\n%s", body)
	}
}

func TestHandleFeedsRedactsDiagnosticMessages(t *testing.T) {
	lastError := `GET https://user-secret:pass-secret@downloads.example.test/backups/feed.tar.gz?X-Amz-Signature=query-secret failed with Authorization: Bearer bearer-secret-token from C:\Users\Admin\Packmon\feed.json` //nolint:gosec // fake secret-bearing diagnostic verifies redaction.
	store := &mockStore{
		feedStatuses: []db.FeedSyncStatus{{
			FeedName:       "vulncheck",
			LastSyncStatus: "error",
			LastError:      lastError,
		}},
	}
	handler := HandleFeeds(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/feeds?partial=status", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Feeds partial status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leaked := range []string{"user-secret", "pass-secret", "feed.tar.gz", "query-secret", "bearer-secret-token", `C:\Users\Admin\Packmon\feed.json`} {
		if strings.Contains(body, leaked) {
			t.Fatalf("Feeds partial leaked %q:\n%s", leaked, body)
		}
	}
	for _, want := range []string{"https://downloads.example.test/...", "Bearer [redacted]", "(redacted-path)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Feeds partial missing %q:\n%s", want, body)
		}
	}
	for _, want := range []string{`<details`, `<summary`, `<pre`, `Show full feed error for vulncheck`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Feeds partial missing accessible diagnostic disclosure %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `title="GET https://downloads.example.test/...`) {
		t.Fatalf("Feeds partial exposes full diagnostic through title-only tooltip:\n%s", body)
	}
}

func TestFeedHealthStatusBranches(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-49 * time.Hour)

	tests := []struct {
		name   string
		in     db.FeedSyncStatus
		want   string
		reason string
	}{
		{name: "error", in: db.FeedSyncStatus{LastSyncStatus: "error"}, want: "error", reason: "last sync failed"},
		{name: "permanent error", in: db.FeedSyncStatus{LastSyncStatus: "permanent_error", LastSyncAt: &now, EntriesTotal: 1}, want: "error", reason: "permanent feed error"},
		{name: "external", in: db.FeedSyncStatus{LastSyncStatus: "external"}, want: "configured", reason: "external feed managed outside Packmon"},
		{name: "running", in: db.FeedSyncStatus{LastSyncStatus: "running"}, want: "pending", reason: "sync running"},
		{name: "skipped", in: db.FeedSyncStatus{LastSyncStatus: "skipped"}, want: "warning", reason: "last sync skipped"},
		{name: "unknown status", in: db.FeedSyncStatus{LastSyncStatus: "failed", LastSyncAt: &now, EntriesTotal: 1}, want: "error", reason: "unknown feed status: failed"},
		{name: "never", in: db.FeedSyncStatus{LastSyncStatus: "success"}, want: "error", reason: "never synced"},
		{name: "stale", in: db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &old, EntriesSynced: 1}, want: "warning", reason: "stale: no sync in 48h+"},
		{name: "healthy", in: db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &now, EntriesSynced: 1, EntriesTotal: 1}, want: "healthy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := feedHealth(tt.in); got != tt.want {
				t.Fatalf("feedHealth() status = %q, want %q", got, tt.want)
			}
			if _, reason := feedHealth(tt.in); reason != tt.reason {
				t.Fatalf("feedHealth() reason = %q, want %q", reason, tt.reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Package tests
// ---------------------------------------------------------------------------

func TestHandlePackage_ReturnsOK(t *testing.T) {
	store := &mockStore{
		vulnFindings: []domain.Finding{
			{
				Name:         "lodash",
				Ecosystem:    domain.EcosystemNPM,
				Type:         domain.FindingTypeVulnerability,
				Severity:     domain.SeverityHigh,
				AdvisoryID:   "GHSA-test-1234",
				Title:        "Example advisory title that should remain fully visible in the package table",
				FixedVersion: "1.2.3",
				Resources: []domain.ResourceLink{
					{Label: "GHSA", URL: "https://github.com/advisories/GHSA-test-1234"},
					{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"},
				},
				Source: "osv",
			},
		},
	}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandlePackage(store, renderer, logger)

	// Simulate the Go 1.22+ routing with path values.
	req := httptest.NewRequest(http.MethodGet, "/package/npm/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Resources") {
		t.Fatal("Package response does not contain the resources column")
	}
	if !strings.Contains(body, "&gt;= 1.2.3") {
		t.Fatal("Package response does not contain the formatted fixed-in version")
	}
	if !strings.Contains(body, ">GHSA<span") || !strings.Contains(body, ">NVD<span") {
		t.Fatal("Package response does not contain the expected resource link labels")
	}
	for _, want := range []string{
		`aria-label="GHSA opens in a new tab"`,
		`aria-label="NVD opens in a new tab"`,
		`<span aria-hidden="true"> &#8599;</span>`,
		`<span class="sr-only"> (opens in a new tab)</span>`,
		`class="inline-flex min-h-8 items-center rounded-md`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing external resource link marker %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "Example advisory title that should remain fully visible in the package table") {
		t.Fatal("Package response does not contain the full advisory title")
	}
	if strings.Contains(body, "href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-0001\" target=\"_blank\" rel=\"noopener\" class=\"text-blue-600 hover:underline\">GHSA-test-1234</a>") {
		t.Fatal("Package response should not link the advisory ID directly to NVD")
	}
	if strings.Contains(body, "/api/v1/packages/npm/lodash/refresh") {
		t.Fatalf("Package response still posts refresh to API route:\n%s", body)
	}
	if strings.Contains(body, `hx-post="/package/npm/refresh/lodash"`) || strings.Contains(body, "Check Now") {
		t.Fatalf("Package response exposes public refresh action:\n%s", body)
	}
}

func TestHandlePackageRejectsUnsupportedEcosystemBeforeLookup(t *testing.T) {
	store := &mockStore{}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/notvalid/lodash", nil)
	req.SetPathValue("ecosystem", "notvalid")
	req.SetPathValue("name", "lodash")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if store.packageLookups != 0 {
		t.Fatalf("package lookups = %d, want none for unsupported ecosystem", store.packageLookups)
	}
}

func TestDashboardExternalAdvisoryLinksAndTimesAreAccessible(t *testing.T) {
	publishedAt := time.Date(2026, 6, 1, 12, 30, 0, 0, time.UTC)
	store := &mockStore{recentVulns: []db.RecentVulnerability{{
		ID:          "CVE-2026-0001",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "test advisory",
		PublishedAt: publishedAt,
	}}}
	handler := HandleDashboard(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Dashboard status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`aria-label="CVE-2026-0001 advisory opens in a new tab"`,
		`<span aria-hidden="true"> &#8599;</span>`,
		`<span class="sr-only"> (opens in a new tab)</span>`,
		`<time datetime="2026-06-01T12:30:00Z" aria-label="2026-06-01 12:30 UTC">`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dashboard response missing accessible advisory/time marker %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `title="2026-06-01 12:30 UTC"`) {
		t.Fatalf("Dashboard still relies on a title tooltip for the published timestamp:\n%s", body)
	}
}

func TestStaticAssetsExposeCacheHeaders(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, &mockStore{}, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("static asset status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("Cache-Control = %q, want public max-age", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
}

func TestHandlePackageHeaderWrapsLongIdentifiers(t *testing.T) {
	longName := "github.com/example/" + strings.Repeat("very-long-segment-", 12) + "module"
	store := &mockStore{}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/go/"+longName, nil)
	req.SetPathValue("ecosystem", "go")
	req.SetPathValue("name", longName)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{`<div class="min-w-0">`, `class="break-all"`, `class="text-2xl font-bold break-all"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package header missing wrapping class %q:\n%s", want, body)
		}
	}
}

func TestHandlePackagePrioritizesBlockingFindingsAndRendersNonVulnerabilityEvidence(t *testing.T) {
	longSupplyTitle := "ReversingLabs detected a removed package release with version-specific malware history and follow-up triage context that must remain visible"
	store := &mockStore{
		vulnFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityMedium,
				AdvisoryID: "GHSA-vuln-1234",
				Title:      "Threshold-gated vulnerability",
				Source:     "osv",
			},
		},
		malFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "MAL-2026-0001",
				URL:        "https://example.test/malicious/MAL-2026-0001",
				Title:      "Always blocking malware report",
				RiskType:   "malware",
				Source:     "openssf",
			},
		},
		repFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "reversinglabs:npm/left-pad@1.3.0",
				Title:      longSupplyTitle,
				RiskType:   "removed_package",
				Resources: []domain.ResourceLink{
					{Label: "ReversingLabs", URL: "https://example.test/reputation/left-pad/1.3.0"},
				},
				Source: db.ReputationSourceReversingLabs,
			},
		},
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/left-pad", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "left-pad")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	maliciousIndex := strings.Index(body, "Malicious Package Reports")
	supplyIndex := strings.Index(body, "Supply Chain Risks")
	vulnerabilityIndex := strings.Index(body, "Vulnerabilities")
	if maliciousIndex == -1 || supplyIndex == -1 || vulnerabilityIndex == -1 || maliciousIndex >= supplyIndex || supplyIndex >= vulnerabilityIndex {
		t.Fatalf("Package sections are not ordered by blocking priority: malicious=%d supply=%d vuln=%d\n%s", maliciousIndex, supplyIndex, vulnerabilityIndex, body)
	}
	for _, want := range []string{
		"Advisory",
		"Resources",
		"Version",
		"MAL-2026-0001",
		"reversinglabs:npm/left-pad@1.3.0",
		"https://example.test/malicious/MAL-2026-0001",
		">ReversingLabs<",
		"1.3.0",
		longSupplyTitle,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing non-vulnerability evidence %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, truncate(longSupplyTitle, 80)) && !strings.Contains(body, longSupplyTitle) {
		t.Fatalf("Package response only rendered truncated supply-chain title:\n%s", body)
	}
}

func TestRegisterRoutesRejectsPublicPackageRefreshAndDoesNotEnqueue(t *testing.T) {
	store := &mockStore{refreshNew: true, refreshPos: 2}
	mux := http.NewServeMux()
	RegisterRoutes(mux, store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodPost, "/package/npm/refresh/@scope/pkg", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("public refresh status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
	if len(store.refreshJobs) != 0 {
		t.Fatalf("public refresh enqueued jobs = %+v, want none", store.refreshJobs)
	}
}

func TestRegisterRoutesDoesNotExposePublicScansPage(t *testing.T) {
	store := &mockStore{}
	mux := http.NewServeMux()
	RegisterRoutes(mux, store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("public scans status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlePackageLookupErrorsRenderLoadErrors(t *testing.T) {
	store := &mockStore{
		vulnErr:      errors.New("vuln lookup unavailable"),
		malErr:       errors.New("malicious lookup unavailable"),
		repErr:       errors.New("reputation lookup unavailable"),
		lifecycleErr: errors.New("lifecycle lookup unavailable"),
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/lodash?version=1.0.0", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Vulnerability findings could not be loaded",
		"Malicious package reports could not be loaded",
		"Reputation findings could not be loaded",
		"Lifecycle findings could not be loaded",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing %q:\n%s", want, body)
		}
	}
	for _, notWant := range []string{
		"No vulnerability findings for this package.",
		"No malicious package reports for this package.",
		"No supply-chain risk reports for this package.",
		"No lifecycle findings for this package version.",
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("Package response rendered empty state %q on load failure:\n%s", notWant, body)
		}
	}
}

func TestHandlePackageShowsReputationFindings(t *testing.T) {
	store := &mockStore{
		repFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "reversinglabs:npm/left-pad@1.3.0",
				Title:      "ReversingLabs: package version was removed",
				RiskType:   "removed_package",
				Resources: []domain.ResourceLink{
					{Label: "ReversingLabs", URL: "https://example.test/reputation/left-pad/1.3.0"},
				},
				Source: db.ReputationSourceReversingLabs,
			},
		},
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/left-pad", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "left-pad")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ReversingLabs: package version was removed") {
		t.Fatal("Package response does not contain ReversingLabs reputation finding")
	}
	if !strings.Contains(body, db.ReputationSourceReversingLabs) {
		t.Fatal("Package response does not contain ReversingLabs source")
	}
	if !strings.Contains(body, "Supply Chain Risks (1)") {
		t.Fatal("Package response does not render reputation finding in supply-chain section")
	}
	for _, want := range []string{"reversinglabs:npm/left-pad@1.3.0", "1.3.0", ">ReversingLabs<"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing reputation detail %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, "Malicious Package Reports (0)") {
		t.Fatal("Package response should not count supply-chain reputation as malicious")
	}
}

func TestHandlePackageUsesVersionedReputationLookupWhenVersionPresent(t *testing.T) {
	store := &mockStore{
		repFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "1.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "reversinglabs:npm/left-pad@1.0.0",
				Title:      "stale package-wide reputation",
				Source:     db.ReputationSourceReversingLabs,
			},
		},
		repBatchFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "2.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "reversinglabs:npm/left-pad@2.0.0",
				Title:      "version-specific reputation",
				Source:     db.ReputationSourceReversingLabs,
			},
		},
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/left-pad?version=2.0.0", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "left-pad")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	if len(store.repBatchQueries) != 1 {
		t.Fatalf("reputation batch queries = %d, want 1", len(store.repBatchQueries))
	}
	query := store.repBatchQueries[0]
	if query.source != db.ReputationSourceReversingLabs {
		t.Fatalf("reputation source = %q, want %q", query.source, db.ReputationSourceReversingLabs)
	}
	if len(query.packages) != 1 || query.packages[0] != (db.PackageQuery{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"}) {
		t.Fatalf("reputation packages = %+v, want npm/left-pad@2.0.0", query.packages)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "version-specific reputation") {
		t.Fatalf("Package response missing version-specific reputation:\n%s", body)
	}
	if strings.Contains(body, "stale package-wide reputation") {
		t.Fatalf("Package response rendered package-wide reputation for a version-specific view:\n%s", body)
	}
}

func TestHandlePackageShowsLifecycleFindingsForVersion(t *testing.T) {
	store := &mockStore{
		lifecycle: []domain.Finding{
			{
				Name:       "django",
				Version:    "3.2.25",
				Ecosystem:  domain.EcosystemPyPI,
				Type:       domain.FindingTypeLifecycle,
				Severity:   domain.SeverityLow,
				AdvisoryID: "endoflife:pypi:django:django:3.2",
				URL:        "https://endoflife.date/django",
				Title:      "Django 3.2 is in security support only",
				RiskType:   "security_support_only",
				Source:     "endoflife.date",
			},
		},
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/pypi/django?version=3.2.25", nil)
	req.SetPathValue("ecosystem", "pypi")
	req.SetPathValue("name", "django")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Lifecycle (1)") || !strings.Contains(body, "Django 3.2 is in security support only") {
		t.Fatalf("Package response missing lifecycle finding:\n%s", body)
	}
	for _, want := range []string{"endoflife:pypi:django:django:3.2", "3.2.25", "https://endoflife.date/django"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing lifecycle detail %q:\n%s", want, body)
		}
	}
}

func TestHandlePackageWithoutVersionRendersLifecycleVersionControl(t *testing.T) {
	store := &mockStore{}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/pypi/django", nil)
	req.SetPathValue("ecosystem", "pypi")
	req.SetPathValue("name", "django")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`action="/package/pypi/django"`,
		`name="version"`,
		`Check version`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing lifecycle version control marker %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Open a package version to evaluate lifecycle status.") {
		t.Fatalf("Package response still renders dead-end lifecycle empty-state copy:\n%s", body)
	}
}

func TestHandlePackage_MissingParams_Returns404(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	handler := HandlePackage(store, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/package//", nil)
	req.SetPathValue("ecosystem", "")
	req.SetPathValue("name", "")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Package (missing params) status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// Route registration test
// ---------------------------------------------------------------------------

func TestRegisterRoutes_NoPanic(t *testing.T) {
	store := &mockStore{}
	renderer := testRenderer()
	logger := discardLogger()

	mux := http.NewServeMux()

	// This should not panic.
	RegisterRoutes(mux, store, renderer, logger)
}
