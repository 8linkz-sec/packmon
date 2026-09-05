package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

// ---------------------------------------------------------------------------
// Mock store -- implements Store with minimal dummy data.
// ---------------------------------------------------------------------------

type mockStore struct {
	mu               sync.Mutex // guards packageLookups and repBatchQueries; HandlePackage queries stores concurrently
	dashboardErr     error
	dailyErr         error
	scansErr         error
	searchErr        error
	dashboardStats   *db.DashboardStatsResult
	dailyStats       []db.DailyScanStats
	recentScans      []db.ScanLogEntry
	lastScansLimit   int
	lastScansOffset  int
	feedsErr         error
	feedStatuses     []db.FeedSyncStatus
	vulnErr          error
	malErr           error
	repErr           error
	lifecycleErr     error
	recentVulnErr    error
	recentVulns      []db.RecentVulnerability
	searchResults    []PackageSearchResult
	searchCalls      int
	lastSearch       PackageSearchParams
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
	if m.dailyStats != nil {
		return m.dailyStats, nil
	}
	return []db.DailyScanStats{}, nil
}

func (m *mockStore) ListRecentScans(_ context.Context, limit, offset int) ([]db.ScanLogEntry, error) {
	m.lastScansLimit = limit
	m.lastScansOffset = offset
	if m.scansErr != nil {
		return nil, m.scansErr
	}
	if m.recentScans != nil {
		scans := append([]db.ScanLogEntry(nil), m.recentScans...)
		if offset > 0 {
			if offset >= len(scans) {
				return []db.ScanLogEntry{}, nil
			}
			scans = scans[offset:]
		}
		if limit > 0 && len(scans) > limit {
			scans = scans[:limit]
		}
		return scans, nil
	}
	return []db.ScanLogEntry{}, nil
}

func (m *mockStore) ListRecentVulnerabilities(_ context.Context, _, _ int) ([]db.RecentVulnerability, error) {
	if m.recentVulnErr != nil {
		return nil, m.recentVulnErr
	}
	return m.recentVulns, nil
}

func (m *mockStore) SearchPackages(_ context.Context, params PackageSearchParams) ([]PackageSearchResult, error) {
	m.searchCalls++
	m.lastSearch = params
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	if m.searchResults != nil {
		results := append([]PackageSearchResult(nil), m.searchResults...)
		if params.Offset > 0 {
			if params.Offset >= len(results) {
				return []PackageSearchResult{}, nil
			}
			results = results[params.Offset:]
		}
		if params.Limit > 0 && len(results) > params.Limit {
			results = results[:params.Limit]
		}
		return results, nil
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
		return []PackageSearchResult{
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
	if params.FindingType == "supply_chain_risk" {
		return []PackageSearchResult{
			{
				Ecosystem:     "npm",
				Name:          "risky-package",
				FindingsCount: 1,
				FindingTypes:  "supply_chain_risk",
				Sources:       "socket.dev",
			},
		}, nil
	}
	if params.FindingType == "lifecycle" {
		return []PackageSearchResult{
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
		return []PackageSearchResult{
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
	return []PackageSearchResult{
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
	m.mu.Lock()
	m.packageLookups++
	m.mu.Unlock()
	if m.vulnErr != nil {
		return nil, m.vulnErr
	}
	if m.vulnFindings != nil {
		return m.vulnFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindMalicious(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	m.mu.Lock()
	m.packageLookups++
	m.mu.Unlock()
	if m.malErr != nil {
		return nil, m.malErr
	}
	if m.malFindings != nil {
		return m.malFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindReputationFindings(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	m.mu.Lock()
	m.packageLookups++
	m.mu.Unlock()
	if m.repErr != nil {
		return nil, m.repErr
	}
	if m.repFindings != nil {
		return m.repFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindReputationFindingsBatch(_ context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error) {
	copied := append([]db.PackageQuery(nil), packages...)
	m.mu.Lock()
	m.packageLookups++
	m.repBatchQueries = append(m.repBatchQueries, struct {
		packages []db.PackageQuery
		source   string
	}{packages: copied, source: source})
	m.mu.Unlock()
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
	m.mu.Lock()
	m.packageLookups++
	m.mu.Unlock()
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
	return NewRendererWithLayoutLinks(TemplateFS(), false, LayoutLinks{})
}

// discardLogger returns a logger that writes nowhere.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func versionedStaticAssetURL(t *testing.T, body, asset string) string {
	t.Helper()

	re := regexp.MustCompile(`(?:href|src)="/static/` + regexp.QuoteMeta(asset) + `\?v=([a-f0-9]{16})"`)
	match := re.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("rendered layout missing versioned static asset URL for %s:\n%s", asset, body)
	}
	return "/static/" + asset + "?v=" + match[1]
}

func TestPublicWebStoreErrorLogsCorrelationID(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := HandleFeeds(&mockStore{feedsErr: errors.New("database unavailable")}, testRenderer(), logger)
	req := httptest.NewRequest(http.MethodGet, "/feeds?partial=status", nil)
	req.Header.Set("HX-Request", "true")
	req = req.WithContext(requestctx.ContextWithCorrelationID(req.Context(), "corr-web-feeds"))
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Feeds status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(logs.String(), `"correlation_id":"corr-web-feeds"`) {
		t.Fatalf("feed load error log missing correlation_id:\n%s", logs.String())
	}
}

// ---------------------------------------------------------------------------
// Dashboard tests
// ---------------------------------------------------------------------------

func TestHandleDashboard_ReturnsOK(t *testing.T) {
	longSummary := "A recently published advisory summary with enough context to exceed the compact dashboard preview and keep the full remediation detail visible in place."
	store := &mockStore{
		recentVulns: []db.RecentVulnerability{
			{
				ID:          "GHSA-test-1234",
				Summary:     longSummary,
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
	if !strings.Contains(body, "Recently Published Vulnerabilities") {
		t.Fatal("Dashboard response does not contain the published vulnerabilities section")
	}
	if !strings.Contains(body, "/search?severity=CRITICAL") {
		t.Fatal("Dashboard response does not contain severity links to search")
	}
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		tag := tagContaining(t, body, `<a`, `href="/search?severity=`+severity+`"`)
		for _, want := range []string{
			`inline-flex`,
			`min-h-11`,
			`items-center`,
			`justify-center`,
			`rounded-lg`,
			`hover:brightness-95`,
		} {
			if !strings.Contains(tag, want) {
				t.Fatalf("Dashboard severity link %s missing class token %q:\n%s", severity, want, tag)
			}
		}
	}
	if !strings.Contains(body, "/search?finding=malicious") {
		t.Fatal("Dashboard response does not contain the malicious packages link")
	}
	if !strings.Contains(body, "/search?finding=supply_chain_risk") {
		t.Fatal("Dashboard response does not contain the supply-chain risks link")
	}
	// Lifecycle is an operator metric and lives on the admin dashboard only.
	if strings.Contains(body, "/search?finding=lifecycle") {
		t.Fatal("Dashboard response exposes the operator-only lifecycle findings card")
	}
	if strings.Contains(body, `href="/scans"`) {
		t.Fatal("Dashboard response exposes the protected scan-log page in public navigation")
	}
	if !strings.Contains(body, "border-danger") {
		t.Fatal("Dashboard response does not style malicious package count as a risk KPI")
	}
	if !strings.Contains(body, "Published") {
		t.Fatal("Dashboard response does not contain the published column heading")
	}
	if !strings.Contains(body, `href="https://github.com/advisories/GHSA-test-1234"`) {
		t.Fatalf("Dashboard advisory link does not point to the advisory resource:\n%s", body)
	}
	if !strings.Contains(body, `href="/package/actions/example/action"`) {
		t.Fatalf("Dashboard recent vulnerability package does not link to package details:\n%s", body)
	}
	if !strings.Contains(body, `aria-label="View package details for actions/example/action"`) {
		t.Fatalf("Dashboard recent vulnerability package link missing accessible label:\n%s", body)
	}
	if strings.Contains(body, `href="/package/actions/example/action">GHSA-test-1234</a>`) {
		t.Fatalf("Dashboard advisory ID links to package page instead of advisory resource:\n%s", body)
	}
	// The summary column moved to the package page; the dashboard table shows
	// the six columns fixed by the dashboard contract.
	if strings.Contains(body, `<details class="group" data-print-open>`) {
		t.Fatalf("Dashboard still renders the removed summary disclosure:\n%s", body)
	}
	if strings.Contains(body, longSummary) {
		t.Fatalf("Dashboard still renders advisory summary text:\n%s", body)
	}
	for _, want := range []string{
		`<th scope="col" class="pb-2 pe-4">Package</th>`,
		`<th scope="col" class="pb-2 pe-4">Version</th>`,
		`<th scope="col" class="pb-2 pe-4">Ecosystem</th>`,
		`<th scope="col" class="pb-2 pe-4">Severity</th>`,
		`<th scope="col" class="pb-2 pe-4">Advisory</th>`,
		`<th scope="col" class="pb-2">Published</th>`,
		`class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border `,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dashboard response missing table/accessibility marker %q:\n%s", want, body)
		}
	}
	// Affected ranges now fill the dedicated Version column, without the label.
	if !strings.Contains(body, "&gt;= 1.2.0, &lt; 1.2.5") {
		t.Fatal("Dashboard response does not contain affected version details")
	}
	if strings.Contains(body, "Affected: &gt;= 1.2.0") {
		t.Fatal("Dashboard still renders the inline affected-version label")
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

func TestHandleDashboardShowsRecentVulnerabilityEmptyState(t *testing.T) {
	handler := HandleDashboard(&mockStore{}, testRenderer(), discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Dashboard status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Recently Published Vulnerabilities (7 Days)",
		"No vulnerabilities were published in the last 7 days.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dashboard empty recent vulnerability state missing %q:\n%s", want, body)
		}
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

func TestDashboardSearchLinksLandOnFilteredSearchResults(t *testing.T) {
	dashboardRec := httptest.NewRecorder()
	HandleDashboard(&mockStore{}, testRenderer(), discardLogger())(dashboardRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if dashboardRec.Code != http.StatusOK {
		t.Fatalf("Dashboard status = %d, want %d", dashboardRec.Code, http.StatusOK)
	}
	dashboardBody := dashboardRec.Body.String()

	// notOnPublicDashboard marks drill-downs that only the admin dashboard links to.
	tests := []struct {
		name                 string
		href                 string
		wantSeverity         string
		wantFinding          string
		wantResult           string
		wantSummary          string
		notOnPublicDashboard bool
	}{
		{
			name:        "vulnerability KPI",
			href:        "/search?finding=vulnerability",
			wantFinding: "vulnerability",
			wantResult:  "lodash",
			wantSummary: "for vulnerabilities",
		},
		{
			name:        "malicious package KPI",
			href:        "/search?finding=malicious",
			wantFinding: "malicious",
			wantResult:  "requests-evil",
			wantSummary: "for malicious packages",
		},
		{
			name:        "supply-chain risk KPI",
			href:        "/search?finding=supply_chain_risk",
			wantFinding: "supply_chain_risk",
			wantResult:  "risky-package",
			wantSummary: "for supply-chain risks",
		},
		{
			name:                 "lifecycle finding KPI",
			href:                 "/search?finding=lifecycle",
			wantFinding:          "lifecycle",
			wantResult:           "django",
			wantSummary:          "for lifecycle findings",
			notOnPublicDashboard: true,
		},
		{
			name:         "critical severity facet",
			href:         "/search?severity=CRITICAL",
			wantSeverity: "CRITICAL",
			wantResult:   "openssl",
			wantSummary:  "for severity CRITICAL",
		},
		{
			name:         "high severity facet",
			href:         "/search?severity=HIGH",
			wantSeverity: "HIGH",
			wantResult:   "lodash",
			wantSummary:  "for severity HIGH",
		},
		{
			name:         "medium severity facet",
			href:         "/search?severity=MEDIUM",
			wantSeverity: "MEDIUM",
			wantResult:   "lodash",
			wantSummary:  "for severity MEDIUM",
		},
		{
			name:         "low severity facet",
			href:         "/search?severity=LOW",
			wantSeverity: "LOW",
			wantResult:   "lodash",
			wantSummary:  "for severity LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch {
			case tt.notOnPublicDashboard:
				if strings.Contains(dashboardBody, `href="`+tt.href+`"`) {
					t.Fatalf("public dashboard links operator-only drill-down %q:\n%s", tt.href, dashboardBody)
				}
			case !strings.Contains(dashboardBody, `href="`+tt.href+`"`):
				t.Fatalf("Dashboard missing drill-down link %q:\n%s", tt.href, dashboardBody)
			}

			searchStore := &mockStore{}
			searchRec := httptest.NewRecorder()
			HandleSearch(searchStore, testRenderer(), discardLogger())(searchRec, httptest.NewRequest(http.MethodGet, tt.href, nil))
			if searchRec.Code != http.StatusOK {
				t.Fatalf("Search landing status = %d, want %d", searchRec.Code, http.StatusOK)
			}
			if searchStore.searchCalls != 1 {
				t.Fatalf("SearchPackages calls = %d, want 1", searchStore.searchCalls)
			}
			if searchStore.lastSearch.Query != "" || searchStore.lastSearch.Severity != tt.wantSeverity || searchStore.lastSearch.FindingType != tt.wantFinding {
				t.Fatalf("SearchPackages params = %+v, want empty query, severity %q, finding %q", searchStore.lastSearch, tt.wantSeverity, tt.wantFinding)
			}
			if searchStore.lastSearch.Limit != searchResultLimit+1 {
				t.Fatalf("SearchPackages limit = %d, want %d", searchStore.lastSearch.Limit, searchResultLimit+1)
			}

			body := searchRec.Body.String()
			for _, want := range []string{`id="search-status"`, `aria-live="off"`, `1 package search result`, tt.wantResult, tt.wantSummary} {
				if !strings.Contains(body, want) {
					t.Fatalf("Search landing missing %q:\n%s", want, body)
				}
			}
			if strings.Contains(body, `role="status" aria-live="polite"`) {
				t.Fatalf("Search landing should not announce result counts during live search:\n%s", body)
			}
			if strings.Contains(body, "Enter at least 2 characters") {
				t.Fatalf("Search landing rendered filter-only admission block:\n%s", body)
			}
		})
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
		TermsURL:   "/terms",
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
		`href="/terms"`,
		`Terms`,
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
		"API key ID/name",
		"Socket.dev",
		"Webhook recipients",
		`href="https://example.test/legal"`,
	} {
		if !strings.Contains(privacyBody, want) {
			t.Fatalf("Privacy body missing %q\nbody=%s", want, privacyBody)
		}
	}

	termsRec := httptest.NewRecorder()
	HandleTerms(renderer, logger)(termsRec, httptest.NewRequest(http.MethodGet, "/terms", nil))
	if termsRec.Code != http.StatusOK {
		t.Fatalf("Terms status = %d, want 200", termsRec.Code)
	}
	termsBody := termsRec.Body.String()
	for _, want := range []string{
		"Terms of Use",
		"acceptable use",
		"API key responsibilities",
		"third-party feed providers",
		`href="https://example.test/legal"`,
	} {
		if !strings.Contains(termsBody, want) {
			t.Fatalf("Terms body missing %q\nbody=%s", want, termsBody)
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
		"Recent vulnerabilities could not be loaded",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dashboard error response missing %q:\n%s", want, body)
		}
	}
	// The public dashboard no longer loads scan counts at all.
	if strings.Contains(body, "Scan activity could not be loaded") {
		t.Fatalf("Public dashboard surfaces an operator-only scan-count error:\n%s", body)
	}
	if strings.Contains(body, "Total Scans (7d)</div>\n      <div class=\"mt-1 text-3xl font-semibold\">0</div>") {
		t.Fatalf("Dashboard rendered scan-count zero as authoritative on load failure:\n%s", body)
	}
}

func TestHandleDashboardLoadsIndependentWidgetsConcurrently(t *testing.T) {
	store := &blockingDashboardStore{
		started: make(chan string, 3),
		release: make(chan struct{}),
	}
	handler := HandleDashboard(store, testRenderer(), discardLogger())

	rec := httptest.NewRecorder()
	done := make(chan int, 1)
	go func() {
		handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		done <- rec.Code
	}()

	waitForStartedDashboardReads(t, store.started, []string{"stats", "recent"}, store.release)
	close(store.release)

	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("Dashboard status = %d, want %d; body=%s", code, http.StatusOK, rec.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("dashboard handler did not finish after releasing concurrent store reads")
	}
}

func TestHandleDashboardCachesAggregateReadsAcrossRequests(t *testing.T) {
	store := &webAggregateCacheCountingStore{
		mockStore: mockStore{
			dashboardStats: &db.DashboardStatsResult{
				TotalPackages:        8,
				TotalVulnerabilities: 3,
				BySeverity:           map[string]int{"HIGH": 3},
			},
			dailyStats: []db.DailyScanStats{{ScanCount: 4}},
			recentVulns: []db.RecentVulnerability{{
				ID:          "GHSA-cache-test",
				Summary:     "cache test advisory",
				Severity:    "HIGH",
				Ecosystem:   "npm",
				Name:        "cached-package",
				PublishedAt: time.Now().UTC(),
			}},
		},
	}
	handler := HandleDashboard(store, testRenderer(), discardLogger())

	for _, requestID := range []string{"first-dashboard-request", "second-dashboard-request"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), webAggregateCacheRequestIDKey{}, requestID))
		rec := httptest.NewRecorder()

		handler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Dashboard status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "GHSA-cache-test") {
			t.Fatalf("Dashboard response missing uncached recent vulnerability:\n%s", rec.Body.String())
		}
	}

	calls := store.snapshot()
	if calls.dashboardStats != 1 {
		t.Fatalf("DashboardStats calls = %d, want 1 cached aggregate read across requests", calls.dashboardStats)
	}
	// The public dashboard no longer reads scan counts at all.
	if calls.dailyStats != 0 {
		t.Fatalf("CountScansByDay calls = %d, want 0 on the public dashboard", calls.dailyStats)
	}
	if calls.recentVulnerabilities != 2 {
		t.Fatalf("ListRecentVulnerabilities calls = %d, want 2 uncached list reads", calls.recentVulnerabilities)
	}
	if calls.lastDashboardStatsRequestID != "first-dashboard-request" {
		t.Fatalf("aggregate read used request ID stats=%q, want first request context", calls.lastDashboardStatsRequestID)
	}
}

type blockingDashboardStore struct {
	mockStore
	started chan string
	release chan struct{}
}

func (s *blockingDashboardStore) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	s.waitForDashboardRelease(ctx, "stats")
	return &db.DashboardStatsResult{BySeverity: map[string]int{}}, nil
}

func (s *blockingDashboardStore) CountScansByDay(ctx context.Context, _ int) ([]db.DailyScanStats, error) {
	s.waitForDashboardRelease(ctx, "daily")
	return []db.DailyScanStats{{ScanCount: 1}}, nil
}

func (s *blockingDashboardStore) ListRecentVulnerabilities(ctx context.Context, _, _ int) ([]db.RecentVulnerability, error) {
	s.waitForDashboardRelease(ctx, "recent")
	return nil, nil
}

func (s *blockingDashboardStore) waitForDashboardRelease(ctx context.Context, name string) {
	select {
	case s.started <- name:
	case <-ctx.Done():
		return
	}
	select {
	case <-s.release:
	case <-ctx.Done():
	}
}

func waitForStartedDashboardReads(t *testing.T, started <-chan string, want []string, release chan struct{}) {
	t.Helper()

	seen := make(map[string]bool, len(want))
	timeout := time.After(750 * time.Millisecond)
	for len(seen) < len(want) {
		select {
		case name := <-started:
			seen[name] = true
		case <-timeout:
			close(release)
			t.Fatalf("dashboard store reads did not start concurrently; saw %v, want %v", seen, want)
		}
	}
}

type webAggregateCacheRequestIDKey struct{}

type webAggregateCacheCountingStore struct {
	mockStore

	mu                             sync.Mutex
	dashboardStatsCalls            int
	dailyStatsCalls                int
	recentVulnerabilitiesCalls     int
	recentScansCalls               int
	lastDashboardStatsRequestID    string
	lastDailyStatsRequestID        string
	lastRecentVulnerabilitiesReqID string
	lastRecentScansRequestID       string
}

type webAggregateCacheCallSnapshot struct {
	dashboardStats                     int
	dailyStats                         int
	recentVulnerabilities              int
	recentScans                        int
	lastDashboardStatsRequestID        string
	lastDailyStatsRequestID            string
	lastRecentVulnerabilitiesRequestID string
	lastRecentScansRequestID           string
}

func (s *webAggregateCacheCountingStore) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	requestID, _ := ctx.Value(webAggregateCacheRequestIDKey{}).(string)
	s.mu.Lock()
	s.dashboardStatsCalls++
	s.lastDashboardStatsRequestID = requestID
	s.mu.Unlock()
	return s.mockStore.DashboardStats(ctx)
}

func (s *webAggregateCacheCountingStore) CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error) {
	requestID, _ := ctx.Value(webAggregateCacheRequestIDKey{}).(string)
	s.mu.Lock()
	s.dailyStatsCalls++
	s.lastDailyStatsRequestID = requestID
	s.mu.Unlock()
	return s.mockStore.CountScansByDay(ctx, days)
}

func (s *webAggregateCacheCountingStore) ListRecentVulnerabilities(ctx context.Context, days, limit int) ([]db.RecentVulnerability, error) {
	requestID, _ := ctx.Value(webAggregateCacheRequestIDKey{}).(string)
	s.mu.Lock()
	s.recentVulnerabilitiesCalls++
	s.lastRecentVulnerabilitiesReqID = requestID
	s.mu.Unlock()
	return s.mockStore.ListRecentVulnerabilities(ctx, days, limit)
}

func (s *webAggregateCacheCountingStore) ListRecentScans(ctx context.Context, limit, offset int) ([]db.ScanLogEntry, error) {
	requestID, _ := ctx.Value(webAggregateCacheRequestIDKey{}).(string)
	s.mu.Lock()
	s.recentScansCalls++
	s.lastRecentScansRequestID = requestID
	s.mu.Unlock()
	return s.mockStore.ListRecentScans(ctx, limit, offset)
}

func (s *webAggregateCacheCountingStore) snapshot() webAggregateCacheCallSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return webAggregateCacheCallSnapshot{
		dashboardStats:                     s.dashboardStatsCalls,
		dailyStats:                         s.dailyStatsCalls,
		recentVulnerabilities:              s.recentVulnerabilitiesCalls,
		recentScans:                        s.recentScansCalls,
		lastDashboardStatsRequestID:        s.lastDashboardStatsRequestID,
		lastDailyStatsRequestID:            s.lastDailyStatsRequestID,
		lastRecentVulnerabilitiesRequestID: s.lastRecentVulnerabilitiesReqID,
		lastRecentScansRequestID:           s.lastRecentScansRequestID,
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
		`aria-live="off"`,
		`aria-atomic="true"`,
		`1 package search result`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search HTMX partial missing quiet result status marker %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `role="status" aria-live="polite"`) {
		t.Fatalf("Search HTMX partial should not announce debounced result counts:\n%s", body)
	}
}

func TestHandleSearchSummaryWrapsLongQueries(t *testing.T) {
	query := strings.Repeat("long-segment-", 8)
	store := &mockStore{searchResults: []PackageSearchResult{{
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
		`text-sm text-muted break-words`,
		`<bdi dir="auto" class="font-medium text-fg break-all">"` + query + `"</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing long-query wrapping marker %q:\n%s", want, body)
		}
	}
}

func TestHandleSearchUsesAutoDirectionForBidiQueryAndResults(t *testing.T) {
	query := "pkg-\u05d0\u05d1"
	resultName := "left-\u05d0\u05d1"
	resultVersion := "1.2.3-\u05d2"
	resultSources := "osv,\u05d2hsa"
	store := &mockStore{searchResults: []PackageSearchResult{{
		Ecosystem:          "npm",
		Name:               resultName,
		Version:            resultVersion,
		FindingsCount:      1,
		VulnerabilityCount: 1,
		VulnerabilityIDs:   "GHSA-bidi",
		FindingTypes:       "vulnerability",
		Sources:            resultSources,
	}}}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=pkg-%D7%90%D7%91", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	input := tagContaining(t, body, `<input`, `id="search-input"`)
	for _, want := range []string{
		`dir="auto"`,
		`value="` + query + `"`,
	} {
		if !strings.Contains(input, want) {
			t.Fatalf("Search input missing bidi marker %q:\n%s", want, input)
		}
	}
	for _, want := range []string{
		`<bdi dir="auto">` + resultName + `</bdi>`,
		`Version: <bdi dir="auto">` + resultVersion + `</bdi>`,
		`<bdi dir="auto">` + resultSources + `</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing bidi-isolated result marker %q:\n%s", want, body)
		}
	}
}

func TestHandleSearchHighlightsMatchedPackageNameSubstrings(t *testing.T) {
	store := &mockStore{searchResults: []PackageSearchResult{{
		Ecosystem:          "npm",
		Name:               "LoDash-lodASH",
		FindingsCount:      1,
		VulnerabilityCount: 1,
		VulnerabilityIDs:   "GHSA-highlight",
		FindingTypes:       "vulnerability",
		Sources:            "osv",
	}}}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=DASH", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`Lo<mark>Dash</mark>-lo<mark>dASH</mark>`,
		`<bdi dir="auto">`,
		`for <bdi dir="auto" class="font-medium text-fg break-all">"DASH"</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing package highlight marker %q:\n%s", want, body)
		}
	}
	if got := strings.Count(body, "<mark>"); got != 2 {
		t.Fatalf("Package search result highlight count = %d, want 2:\n%s", got, body)
	}
}

func TestHandleSearchHighlightEscapesMarkupLikePackageNames(t *testing.T) {
	store := &mockStore{searchResults: []PackageSearchResult{{
		Ecosystem:          "npm",
		Name:               "safe-<em>DASH</em>",
		FindingsCount:      1,
		VulnerabilityCount: 1,
		VulnerabilityIDs:   "GHSA-highlight-escape",
		FindingTypes:       "vulnerability",
		Sources:            "osv",
	}}}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=%3Cem", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`safe-<mark>&lt;em</mark>&gt;DASH&lt;/em&gt;`,
		`for <bdi dir="auto" class="font-medium text-fg break-all">"&lt;em"</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing escaped highlight marker %q:\n%s", want, body)
		}
	}
	for _, blocked := range []string{`safe-<em`, `</em>`} {
		if strings.Contains(body, blocked) {
			t.Fatalf("Search response rendered package markup as HTML %q:\n%s", blocked, body)
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
	if !strings.Contains(body, `<form id="search-form" action="/search" method="get" role="search"`) {
		t.Fatalf("Search form is not exposed as a search landmark:\n%s", body)
	}
	if !strings.Contains(body, `hx-trigger="input changed delay:300ms, search"`) {
		t.Fatalf("Search input does not listen to input events for non-keyboard edits:\n%s", body)
	}
	for _, want := range []string{
		`id="search-input"` + "\n" + `          name="q"`,
		`id="severity-filter"` + "\n" + `          name="severity"`,
		`id="finding-filter"` + "\n" + `          name="finding"`,
	} {
		start := strings.Index(body, want)
		if start == -1 {
			t.Fatalf("Search response missing control marker %q:\n%s", want, body)
		}
		control := body[start:min(len(body), start+500)]
		if !strings.Contains(control, "min-h-11") && !strings.Contains(control, "pm-form-control") {
			t.Fatalf("Search control missing touch target min-height near %q:\n%s", want, control)
		}
	}
}

func TestHandleSearchSeverityOnlyCallsStoreAndRendersResults(t *testing.T) {
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
	if store.searchCalls != 1 {
		t.Fatalf("SearchPackages calls = %d, want 1 for severity-only search", store.searchCalls)
	}
	if store.lastSearch.Query != "" || store.lastSearch.Severity != "CRITICAL" || store.lastSearch.FindingType != "" {
		t.Fatalf("SearchPackages params = %+v, want empty query with CRITICAL severity", store.lastSearch)
	}

	body := rec.Body.String()
	for _, want := range []string{`id="search-status"`, `aria-live="off"`, `1 package search result`, "openssl", "for severity CRITICAL"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing severity-only result marker %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `role="status" aria-live="polite"`) {
		t.Fatalf("Search response should not announce severity-only result counts during live search:\n%s", body)
	}
	if strings.Contains(body, "Enter at least 2 characters") {
		t.Fatalf("Search response rendered severity-only admission block:\n%s", body)
	}
}

func TestHandleSearchFindingOnlyCallsStoreAndRendersResults(t *testing.T) {
	tests := []struct {
		finding     string
		wantResult  string
		wantSummary string
		wantDetails string
	}{
		{
			finding:     "vulnerability",
			wantResult:  "lodash",
			wantSummary: "for vulnerabilities",
			wantDetails: "1 vulnerability finding",
		},
		{
			finding:     "malicious",
			wantResult:  "requests-evil",
			wantSummary: "for malicious packages",
			wantDetails: "2 malicious package findings",
		},
		{
			finding:     "supply_chain_risk",
			wantResult:  "risky-package",
			wantSummary: "for supply-chain risks",
			wantDetails: "1 supply-chain risk finding",
		},
		{
			finding:     "lifecycle",
			wantResult:  "django",
			wantSummary: "for lifecycle findings",
			wantDetails: "1 lifecycle finding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.finding, func(t *testing.T) {
			store := &mockStore{}
			handler := HandleSearch(store, testRenderer(), discardLogger())

			req := httptest.NewRequest(http.MethodGet, "/search?finding="+tt.finding, nil)
			rec := httptest.NewRecorder()

			handler(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("Search (%s only) status = %d, want %d", tt.finding, rec.Code, http.StatusOK)
			}
			if store.searchCalls != 1 {
				t.Fatalf("SearchPackages calls = %d, want 1 for finding-only search", store.searchCalls)
			}
			if store.lastSearch.Query != "" || store.lastSearch.Severity != "" || store.lastSearch.FindingType != tt.finding {
				t.Fatalf("SearchPackages params = %+v, want empty query with finding %q", store.lastSearch, tt.finding)
			}

			body := rec.Body.String()
			for _, want := range []string{`id="search-status"`, `aria-live="off"`, `1 package search result`, tt.wantResult, tt.wantSummary, tt.wantDetails} {
				if !strings.Contains(body, want) {
					t.Fatalf("Search response missing finding-only result marker %q:\n%s", want, body)
				}
			}
			if strings.Contains(body, `role="status" aria-live="polite"`) {
				t.Fatalf("Search response should not announce finding-only result counts during live search:\n%s", body)
			}
			if strings.Contains(body, "Enter at least 2 characters") {
				t.Fatalf("Search response rendered finding-only admission block:\n%s", body)
			}
		})
	}
}

func TestHandleSearchInvalidSeverityDoesNotQueryStore(t *testing.T) {
	store := &mockStore{}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=lodash&severity=URGENT", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 0 {
		t.Fatalf("SearchPackages calls = %d, want 0 for invalid severity filter", store.searchCalls)
	}
	body := rec.Body.String()
	for _, want := range []string{"Invalid severity filter", "URGENT", `role="alert"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing invalid severity marker %q:\n%s", want, body)
		}
	}
}

func TestHandleSearchInvalidFindingDoesNotQueryStore(t *testing.T) {
	store := &mockStore{}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=lodash&finding=unknown", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 0 {
		t.Fatalf("SearchPackages calls = %d, want 0 for invalid finding filter", store.searchCalls)
	}
	body := rec.Body.String()
	for _, want := range []string{"Invalid finding filter", "unknown", `role="alert"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Search response missing invalid finding marker %q:\n%s", want, body)
		}
	}
}

func TestHandleSearchUnfilteredShowsFindingTypes(t *testing.T) {
	store := &mockStore{searchResults: []PackageSearchResult{
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
	for _, want := range []string{"1 result", "Finding details", "1 vulnerability finding", "GHSA-test-1234", "Malicious package", "Vulnerability"} {
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
	if !strings.Contains(body, `href="/package/pypi/django?version=3.2.25&amp;return_to=%2Fsearch%3Ffinding%3Dlifecycle%26q%3Ddjango"`) {
		t.Fatalf("Lifecycle search result does not link to versioned package detail:\n%s", body)
	}
	if !strings.Contains(body, `Version: <bdi dir="auto">3.2.25</bdi>`) {
		t.Fatalf("Lifecycle search result does not show version context:\n%s", body)
	}
}

func TestHandleSearchPackageLinksCarryFilteredReturnTo(t *testing.T) {
	store := &mockStore{}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=lodash&severity=HIGH&finding=vulnerability", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	want := `href="/package/npm/lodash?return_to=%2Fsearch%3Ffinding%3Dvulnerability%26q%3Dlodash%26severity%3DHIGH"`
	if !strings.Contains(body, want) {
		t.Fatalf("Search result package link missing filtered return_to %q:\n%s", want, body)
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
	if !strings.Contains(body, "1 vulnerability finding") {
		t.Fatal("Search response does not contain the vulnerability finding count")
	}
	if strings.Contains(body, "1 advisory") {
		t.Fatalf("Search response still uses advisory wording for vulnerability counts:\n%s", body)
	}
	if !strings.Contains(body, "RUSTSEC-2026-0081") {
		t.Fatal("Search response does not contain the advisory IDs")
	}
}

func TestHandleSearchCapsVulnerabilityIDPreview(t *testing.T) {
	store := &mockStore{searchResults: []PackageSearchResult{{
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
	if !strings.Contains(body, "7 vulnerability findings") {
		t.Fatalf("Search response missing full vulnerability finding count:\n%s", body)
	}
	if strings.Contains(body, "7 advisories") {
		t.Fatalf("Search response still uses advisory wording for vulnerability counts:\n%s", body)
	}
	for _, id := range []string{"GHSA-001", "GHSA-002", "GHSA-003", "GHSA-004", "GHSA-005"} {
		if !strings.Contains(body, id) {
			t.Fatalf("Search response missing advisory preview ID %s:\n%s", id, body)
		}
	}
	if !strings.Contains(body, "&#43;2 more") {
		t.Fatalf("Search response missing capped advisory preview remainder:\n%s", body)
	}
	if strings.Contains(body, "GHSA-006") || strings.Contains(body, "GHSA-007") {
		t.Fatalf("Search response rendered advisory IDs beyond the preview cap:\n%s", body)
	}
}

func TestHandleSearchLinksAdvisoryIDsToCanonicalAdvisoryPages(t *testing.T) {
	store := &mockStore{searchResults: []PackageSearchResult{{
		Ecosystem:          "npm",
		Name:               "obsidian-local-rest-api",
		FindingsCount:      3,
		VulnerabilityCount: 3,
		VulnerabilityIDs:   "GHSA-62gx-5q78-wrvx, CVE-2026-0001, UNKNOWN-1",
		FindingTypes:       "vulnerability",
		Sources:            "osv",
	}}}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=obsidian", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="https://github.com/advisories/GHSA-62gx-5q78-wrvx"`) {
		t.Fatalf("Search response missing canonical GHSA advisory link:\n%s", body)
	}
	if !strings.Contains(body, `href="https://nvd.nist.gov/vuln/detail/CVE-2026-0001"`) {
		t.Fatalf("Search response missing canonical NVD advisory link:\n%s", body)
	}
	if !strings.Contains(body, "UNKNOWN-1") || strings.Contains(body, `href="UNKNOWN-1"`) {
		t.Fatalf("Search response must keep unknown advisory IDs as plain text:\n%s", body)
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
	body := rec.Body.String()
	if !strings.Contains(body, `value="a"`) {
		t.Fatalf("Search response did not retain the visible query input:\n%s", body)
	}
	if !strings.Contains(body, "Enter at least 2 characters to search.") {
		t.Fatalf("Search response missing minimum query length hint:\n%s", body)
	}
	if strings.Contains(body, "No packages found for the current search and filter.") {
		t.Fatalf("Search response rendered no-results state for an unqueried one-character search:\n%s", body)
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
	store := &mockStore{searchResults: packageSearchResults(51)}
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
	if !strings.Contains(body, "More results are available") || !strings.Contains(body, "Next page") || !strings.Contains(body, "page=2") {
		t.Fatalf("Search response missing next-page control for truncated results:\n%s", body)
	}
	if !strings.Contains(body, "pkg-049") {
		t.Fatalf("Search response missing last rendered result:\n%s", body)
	}
	if strings.Contains(body, "pkg-050") {
		t.Fatalf("Search response rendered the sentinel result beyond the visible window:\n%s", body)
	}
}

func TestHandleSearchPaginatesSecondResultWindow(t *testing.T) {
	store := &mockStore{searchResults: packageSearchResults(60)}
	handler := HandleSearch(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/search?q=pkg&page=2", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Showing matches 51-60") {
		t.Fatalf("Search response missing second-page result window message:\n%s", body)
	}
	if !strings.Contains(body, "Previous page") || !strings.Contains(body, `href="/search?q=pkg"`) {
		t.Fatalf("Search response missing previous-page control:\n%s", body)
	}
	if !strings.Contains(body, "pkg-050") || !strings.Contains(body, "pkg-059") {
		t.Fatalf("Search response missing second-page results:\n%s", body)
	}
	if strings.Contains(body, "pkg-049") {
		t.Fatalf("Search response rendered first-page result on page 2:\n%s", body)
	}
	if strings.Contains(body, "Next page") {
		t.Fatalf("Search response rendered next-page control past the end:\n%s", body)
	}
}

func packageSearchResults(count int) []PackageSearchResult {
	results := make([]PackageSearchResult, count)
	for i := range results {
		results[i] = PackageSearchResult{
			Ecosystem:          "npm",
			Name:               fmt.Sprintf("pkg-%03d", i),
			FindingsCount:      1,
			VulnerabilityCount: 1,
			VulnerabilityIDs:   fmt.Sprintf("GHSA-test-%03d", i),
			FindingTypes:       "vulnerability",
			Sources:            "osv",
		}
	}
	return results
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

	req := httptest.NewRequest(http.MethodGet, "/search?q=%20lodash%20&severity=%20high%20&finding=%20VULNERABILITY%20", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Search error partial status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.searchCalls != 1 {
		t.Fatalf("SearchPackages calls = %d, want 1 for normalized valid filters", store.searchCalls)
	}
	if store.lastSearch.Query != "lodash" || store.lastSearch.Severity != "HIGH" || store.lastSearch.FindingType != "vulnerability" {
		t.Fatalf("SearchPackages params = %+v, want trimmed query with normalized severity and finding", store.lastSearch)
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

func TestDBStoreAdapterMapsPackageSearchBoundaryTypes(t *testing.T) {
	params := PackageSearchParams{
		Query:       "lodash",
		Severity:    "HIGH",
		FindingType: "vulnerability",
		Limit:       51,
		Offset:      50,
	}
	dbParams := dbSearchParams(params)
	if dbParams.Query != params.Query || dbParams.Severity != params.Severity || dbParams.FindingType != params.FindingType || dbParams.Limit != params.Limit || dbParams.Offset != params.Offset {
		t.Fatalf("dbSearchParams() = %+v, want mapped %+v", dbParams, params)
	}

	results := packageSearchResultsFromDB([]db.PackageSearchResult{{
		Ecosystem:          "npm",
		Name:               "lodash",
		Version:            "4.17.21",
		FindingsCount:      2,
		VulnerabilityCount: 1,
		VulnerabilityIDs:   "GHSA-test",
		FindingTypes:       "vulnerability",
		Sources:            "osv",
	}})
	if len(results) != 1 {
		t.Fatalf("packageSearchResultsFromDB() len = %d, want 1", len(results))
	}
	got := results[0]
	if got.Ecosystem != "npm" || got.Name != "lodash" || got.Version != "4.17.21" || got.FindingsCount != 2 || got.VulnerabilityCount != 1 || got.VulnerabilityIDs != "GHSA-test" || got.FindingTypes != "vulnerability" || got.Sources != "osv" {
		t.Fatalf("packageSearchResultsFromDB()[0] = %+v, want DB fields mapped", got)
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
		`src="/static/auto-refresh.js?v=`,
		`src="/static/form-actions.js?v=`,
		`src="/static/htmx-regions.js?v=`,
		`data-auto-refresh-control`,
		`data-auto-refresh-event="feed-status-refresh"`,
		`aria-controls="feed-status-container"`,
		`aria-describedby="feed-status-refresh-state"`,
		`aria-pressed="true"`,
		`>Auto-refresh</button>`,
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
	req.Header.Set("HX-Request", "true")
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

func TestHandleFeeds_PartialStatusWithoutHTMXRendersFullPage(t *testing.T) {
	handler := HandleFeeds(&mockStore{}, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/feeds?partial=status", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Feeds partial URL status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{"<!DOCTYPE html>", `href="/feeds"`, "Feed Status"} {
		if !strings.Contains(body, want) {
			t.Fatalf("Feeds partial URL full page missing %q:\n%s", want, body)
		}
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
	req.Header.Set("HX-Request", "true")
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
	req.Header.Set("HX-Request", "true")
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
	for _, want := range []string{`<details`, `<summary`, `<pre`, `Show full feed ` + `error for vulncheck`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Feeds partial missing accessible diagnostic disclosure %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `title="GET https://downloads.example.test/...`) {
		t.Fatalf("Feeds partial exposes full diagnostic through title-only tooltip:\n%s", body)
	}
}

func TestHandleFeedsHidesSyntheticPipelineStatuses(t *testing.T) {
	// alias-severity-propagation is a post-sync maintenance step recorded in
	// feed_sync_status for observability, not an upstream feed. It must not show
	// in the user-facing feed list (where it reads as a feed that only ever
	// synced a single entry), while real feeds stay visible.
	store := &mockStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", EntriesSynced: 500, EntriesTotal: 500},
			{FeedName: "alias-severity-propagation", LastSyncStatus: "success", EntriesSynced: 1, EntriesTotal: 1},
		},
	}
	handler := HandleFeeds(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/feeds?partial=status", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Feeds partial status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "alias-severity-propagation") {
		t.Fatalf("feeds list shows synthetic pipeline status alias-severity-propagation; it is not a feed:\n%s", body)
	}
	if !strings.Contains(body, "osv") {
		t.Fatalf("feeds list dropped the real osv feed:\n%s", body)
	}
}

func TestHandleFeedsShowsRejectedImportDetails(t *testing.T) {
	store := &mockStore{
		feedStatuses: []db.FeedSyncStatus{{
			FeedName:       "osv",
			LastSyncStatus: "rejected",
			LastError:      "vulnerability import cvss_score must be between 0 and 10",
			EntriesSynced:  0,
			EntriesTotal:   2,
			Metadata:       json.RawMessage(`{"rejected_count":2,"rejection_reason":"vulnerability import cvss_score must be between 0 and 10"}`),
		}},
	}
	handler := HandleFeeds(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/feeds?partial=status", nil)
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Feeds partial status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"rejected",
		"Rejected records: 2",
		"0 / 2",
		"vulnerability import cvss_score must be between 0 and 10",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Feeds partial missing rejected-import marker %q:\n%s", want, body)
		}
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
	if !strings.Contains(body, "Fixed Version") {
		t.Fatalf("Package response missing canonical fixed-version label:\n%s", body)
	}
	if strings.Contains(body, "Fixed In") {
		t.Fatalf("Package response still uses Fixed In label:\n%s", body)
	}
	for _, label := range []string{`<bdi dir="auto">GHSA</bdi>`, `<bdi dir="auto">NVD</bdi>`} {
		if !strings.Contains(body, label) {
			t.Fatalf("Package response does not contain the expected resource link label %q", label)
		}
	}
	for _, want := range []string{
		`aria-label="GHSA opens in a new tab"`,
		`aria-label="NVD opens in a new tab"`,
		`data-external-link-icon`,
		`aria-hidden="true"`,
		`focusable="false"`,
		`stroke="currentColor"`,
		`<span class="sr-only"> (opens in a new tab)</span>`,
		`class="inline-flex min-h-11 items-center rounded-md`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing external resource link marker %q:\n%s", want, body)
		}
	}
	for _, blocked := range []string{`&#8599;`, `↗`} {
		if strings.Contains(body, blocked) {
			t.Fatalf("Package response still uses raw external link glyph %q:\n%s", blocked, body)
		}
	}
	if !strings.Contains(body, "Example advisory title that should remain fully visible in the package table") {
		t.Fatal("Package response does not contain the full advisory title")
	}
	if strings.Contains(body, "href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-0001\" target=\"_blank\" rel=\"noopener\" class=\"text-accent hover:underline\">GHSA-test-1234</a>") {
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
		`data-external-link-icon`,
		`aria-hidden="true"`,
		`focusable="false"`,
		`stroke="currentColor"`,
		`<span class="sr-only"> (opens in a new tab)</span>`,
		`<time data-local-time="relative" datetime="2026-06-01T12:30:00Z" aria-label="2026-06-01 12:30 UTC">`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dashboard response missing accessible advisory/time marker %q:\n%s", want, body)
		}
	}
	for _, blocked := range []string{`&#8599;`, `↗`} {
		if strings.Contains(body, blocked) {
			t.Fatalf("Dashboard response still uses raw external link glyph %q:\n%s", blocked, body)
		}
	}
	if strings.Contains(body, `title="2026-06-01 12:30 UTC"`) {
		t.Fatalf("Dashboard still relies on a title tooltip for the published timestamp:\n%s", body)
	}
}

func TestStaticAssetsExposeCacheHeaders(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, &mockStore{}, testRenderer(), discardLogger())

	layoutRec := httptest.NewRecorder()
	HandleDashboard(&mockStore{}, testRenderer(), discardLogger())(layoutRec, httptest.NewRequest(http.MethodGet, "/", nil))
	versionedStyleURL := versionedStaticAssetURL(t, layoutRec.Body.String(), "style.css")

	req := httptest.NewRequest(http.MethodGet, versionedStyleURL, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("static asset status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("versioned Cache-Control = %q, want long-lived immutable", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/static/style.css", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unversioned static asset status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("unversioned Cache-Control = %q, want short fallback", got)
	}
}

func TestStaticAssetsServeGzipWhenAccepted(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, &mockStore{}, testRenderer(), discardLogger())

	layoutRec := httptest.NewRecorder()
	HandleDashboard(&mockStore{}, testRenderer(), discardLogger())(layoutRec, httptest.NewRequest(http.MethodGet, "/", nil))
	versionedStyleURL := versionedStaticAssetURL(t, layoutRec.Body.String(), "style.css")

	req := httptest.NewRequest(http.MethodGet, versionedStyleURL, nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("static gzip status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("gzip Cache-Control = %q, want versioned immutable", got)
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("open gzip response body: %v", err)
	}
	decompressed, err := io.ReadAll(gzipReader)
	if closeErr := gzipReader.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("read gzip response body: %v", err)
	}
	if !strings.Contains(string(decompressed), "Tailwind CSS is built locally") {
		t.Fatalf("decompressed gzip body does not look like style.css:\n%s", string(decompressed))
	}
}

func TestStaticAssetsUseIdentityWhenGzipNotAccepted(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, &mockStore{}, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)
	req.Header.Set("Accept-Encoding", "br")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("static identity status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want identity response without header", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("identity Cache-Control = %q, want short fallback", got)
	}
	if !strings.Contains(rec.Body.String(), "Tailwind CSS is built locally") {
		t.Fatalf("identity body does not look like style.css:\n%s", rec.Body.String())
	}
}

func TestSharedLayoutRendersVersionedStaticAssetURLs(t *testing.T) {
	renderer := testRenderer()
	var out strings.Builder
	if err := renderer.Render(&out, "not_found.html", nil); err != nil {
		t.Fatalf("Render(not_found) error = %v", err)
	}
	body := out.String()

	for _, asset := range []string{"tailwind.css", "style.css"} {
		versionedStaticAssetURL(t, body, asset)
	}
	for _, asset := range []string{"htmx.min.js", "auto-refresh.js", "form-actions.js", "htmx-regions.js"} {
		if strings.Contains(body, "/static/"+asset) {
			t.Fatalf("layout rendered %s on a page with no matching behavior:\n%s", asset, body)
		}
	}
	for _, unversioned := range []string{
		`href="/static/tailwind.css"`,
		`href="/static/style.css"`,
		`src="/static/htmx.min.js"`,
		`src="/static/auto-refresh.js"`,
		`src="/static/form-actions.js"`,
		`src="/static/htmx-regions.js"`,
	} {
		if strings.Contains(body, unversioned) {
			t.Fatalf("layout still renders unversioned asset URL %q:\n%s", unversioned, body)
		}
	}
}

func TestSharedLayoutLoadsScriptsOnlyForPagesWithMatchingBehavior(t *testing.T) {
	renderer := testRenderer()

	tests := []struct {
		name              string
		template          string
		data              any
		wantHTMX          bool
		wantHelper        bool
		wantHelperControl string
	}{
		{
			name:     "privacy static page",
			template: "privacy.html",
			data:     nil,
		},
		{
			name:     "search htmx busy target",
			template: "search.html",
			data: map[string]any{
				"Query":    "",
				"Severity": "",
				"Finding":  "",
				"Error":    "",
				"Results":  nil,
			},
			wantHTMX:          true,
			wantHelper:        true,
			wantHelperControl: `aria-busy="false"`,
		},
		{
			name:     "public feeds auto refresh",
			template: "feeds.html",
			data: map[string]any{
				"Feeds": []db.FeedSyncStatus{},
			},
			wantHTMX:          true,
			wantHelper:        true,
			wantHelperControl: `data-auto-refresh-control`,
		},
		{
			name:     "admin login submit lock",
			template: "admin/login.html",
			data: map[string]any{
				"CSRFToken": "csrf-token",
			},
			wantHelper:        true,
			wantHelperControl: `data-submit-lock`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := renderer.Render(&out, tt.template, tt.data); err != nil {
				t.Fatalf("Render(%s) error = %v", tt.template, err)
			}
			body := out.String()

			if gotHTMX := strings.Contains(body, `/static/htmx.min.js?v=`); gotHTMX != tt.wantHTMX {
				t.Fatalf("htmx script present = %v, want %v for %s:\n%s", gotHTMX, tt.wantHTMX, tt.template, body)
			}
			for _, helperAsset := range []string{"auto-refresh.js", "form-actions.js", "htmx-regions.js"} {
				if gotHelper := strings.Contains(body, `/static/`+helperAsset+`?v=`); gotHelper != tt.wantHelper {
					t.Fatalf("%s present = %v, want %v for %s:\n%s", helperAsset, gotHelper, tt.wantHelper, tt.template, body)
				}
			}
			if tt.wantHTMX {
				versionedStaticAssetURL(t, body, "htmx.min.js")
				if !strings.Contains(body, `<meta name="htmx-config"`) {
					t.Fatalf("htmx page missing CSP-safe htmx config:\n%s", body)
				}
			} else if strings.Contains(body, `<meta name="htmx-config"`) {
				t.Fatalf("non-htmx page rendered htmx config:\n%s", body)
			}
			if tt.wantHelper {
				for _, helperAsset := range []string{"auto-refresh.js", "form-actions.js", "htmx-regions.js"} {
					versionedStaticAssetURL(t, body, helperAsset)
				}
				if !strings.Contains(body, tt.wantHelperControl) {
					t.Fatalf("test fixture did not render expected helper hook %q:\n%s", tt.wantHelperControl, body)
				}
			}
		})
	}
}

func TestAdminFlashAlertsRenderDismissControls(t *testing.T) {
	renderer := testRenderer()

	var out strings.Builder
	if err := renderer.RenderPartial(&out, "admin/feeds.html", "admin-feed-flash", map[string]any{
		"Message": "Feed configuration saved.",
		"Error":   "Failed to refresh feed.",
	}); err != nil {
		t.Fatalf("RenderPartial(admin-feed-flash) error = %v", err)
	}
	body := out.String()

	for _, want := range []string{
		`data-alert-dismissible`,
		`data-alert-dismiss`,
		`type="button"`,
		`aria-label="Dismiss alert"`,
		`role="status" aria-live="polite" aria-atomic="true"`,
		`role="alert" aria-live="assertive" aria-atomic="true"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin flash alert output missing %q:\n%s", want, body)
		}
	}
	dismissButtonRE := regexp.MustCompile(`\sdata-alert-dismiss(?:\s|>)`)
	if got := len(dismissButtonRE.FindAllString(body, -1)); got != 2 {
		t.Fatalf("dismiss button count = %d, want 2 in:\n%s", got, body)
	}
}

func TestRegisterRoutesServesSecurityTxt(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, &mockStore{}, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/.well-known/security.txt", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("security.txt status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("security.txt Content-Type = %q, want text/plain", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Contact: https://github.com/8linkz-sec/packmon/security/advisories/new",
		"Policy: https://github.com/8linkz-sec/packmon/security/policy",
		"Preferred-Languages: en",
		"Expires:",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("security.txt missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<html") {
		t.Fatalf("security.txt must be plain text, got:\n%s", body)
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
	supplyIndex := strings.Index(body, "Supply-chain Risks")
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

func TestHandleScansEmptyRecentWindowNamesWindowScope(t *testing.T) {
	store := &mockStore{
		dailyStats: []db.DailyScanStats{},
		recentScans: []db.ScanLogEntry{
			{
				ScanID:        "scan-older",
				ScannedAt:     time.Now().UTC().AddDate(0, 0, -14),
				PackagesCount: 8,
				FindingsCount: 1,
			},
		},
	}
	handler := HandleScans(store, testRenderer(), discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("scans status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No scan activity in the last 7 days.") {
		t.Fatalf("scans page missing scoped empty activity message:\n%s", body)
	}
	if strings.Contains(body, "No scan activity yet.") {
		t.Fatalf("scans page uses unscoped activity empty state despite older scan history:\n%s", body)
	}
	if !strings.Contains(body, "Recent Scans") || !strings.Contains(body, "scan-older") {
		t.Fatalf("scans page did not render older recent scan context:\n%s", body)
	}
}

func TestHandleScansPaginatesRecentScans(t *testing.T) {
	now := time.Now().UTC()
	scans := make([]db.ScanLogEntry, recentScansPageSize+1)
	for i := range scans {
		scans[i] = db.ScanLogEntry{
			ScanID:        fmt.Sprintf("scan-%02d", i),
			ScannedAt:     now.Add(-time.Duration(i) * time.Minute),
			PackagesCount: 1,
		}
	}
	store := &mockStore{
		dailyStats:  []db.DailyScanStats{{Date: now, ScanCount: 1}},
		recentScans: scans,
	}
	handler := HandleScans(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first scans page status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if store.lastScansLimit != recentScansPageSize+1 || store.lastScansOffset != 0 {
		t.Fatalf("first scans page requested limit/offset = %d/%d, want %d/0", store.lastScansLimit, store.lastScansOffset, recentScansPageSize+1)
	}
	for _, want := range []string{
		`aria-label="Recent scans pages"`,
		`href="/scans?offset=50"`,
		"Older scans",
		"scan-49",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("first scans page missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "scan-50") || strings.Contains(body, "Newer scans") {
		t.Fatalf("first scans page rendered outside-page row or unexpected previous link:\n%s", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/scans?offset=50", nil)
	rec = httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("second scans page status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body = rec.Body.String()
	if store.lastScansLimit != recentScansPageSize+1 || store.lastScansOffset != recentScansPageSize {
		t.Fatalf("second scans page requested limit/offset = %d/%d, want %d/%d", store.lastScansLimit, store.lastScansOffset, recentScansPageSize+1, recentScansPageSize)
	}
	for _, want := range []string{
		`href="/scans"`,
		"Newer scans",
		"scan-50",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("second scans page missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Older scans") || strings.Contains(body, "scan-49") {
		t.Fatalf("second scans page rendered unexpected older link or previous-page row:\n%s", body)
	}
}

func TestHandleScansCachesDailyAggregateAcrossRequests(t *testing.T) {
	store := &webAggregateCacheCountingStore{
		mockStore: mockStore{
			dailyStats: []db.DailyScanStats{{ScanCount: 2, FindingsCount: 1}},
			recentScans: []db.ScanLogEntry{{
				ScanID:        "scan-cache-test",
				ScannedAt:     time.Now().UTC(),
				PackagesCount: 7,
				FindingsCount: 1,
			}},
		},
	}
	handler := HandleScans(store, testRenderer(), discardLogger())

	for _, requestID := range []string{"first-scans-request", "second-scans-request"} {
		req := httptest.NewRequest(http.MethodGet, "/scans", nil)
		req = req.WithContext(context.WithValue(req.Context(), webAggregateCacheRequestIDKey{}, requestID))
		rec := httptest.NewRecorder()

		handler(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Scans status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "scan-cache-test") {
			t.Fatalf("Scans response missing uncached recent scan:\n%s", rec.Body.String())
		}
	}

	calls := store.snapshot()
	if calls.dailyStats != 1 {
		t.Fatalf("CountScansByDay calls = %d, want 1 cached aggregate read across requests", calls.dailyStats)
	}
	if calls.recentScans != 2 {
		t.Fatalf("ListRecentScans calls = %d, want 2 uncached list reads", calls.recentScans)
	}
	if calls.lastDailyStatsRequestID != "first-scans-request" {
		t.Fatalf("CountScansByDay request ID = %q, want first request context", calls.lastDailyStatsRequestID)
	}
	if calls.lastRecentScansRequestID != "second-scans-request" {
		t.Fatalf("ListRecentScans request ID = %q, want second request context for uncached reads", calls.lastRecentScansRequestID)
	}
}

func TestRegisterRoutesPublicNotFoundRendersStyledFallback(t *testing.T) {
	store := &mockStore{}
	mux := http.NewServeMux()
	RegisterRoutes(mux, store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/missing-page", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("public not found status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("public not found Content-Type = %q, want text/html", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		"Page not found",
		`href="/"`,
		`href="/search"`,
		`href="/feeds"`,
		`href="/admin/"`,
		"Open admin",
		`id="main-content"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("public not found body missing %q:\n%s", want, body)
		}
	}
}

func TestRegisterRoutesStaticMissDoesNotUseWebNotFoundFallback(t *testing.T) {
	store := &mockStore{}
	mux := http.NewServeMux()
	RegisterRoutes(mux, store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/static/missing.css", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("static miss status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Page not found") {
		t.Fatalf("static miss rendered public web fallback:\n%s", rec.Body.String())
	}
}

func TestRegisterRoutesStaticRootKeepsSubtreeRedirect(t *testing.T) {
	store := &mockStore{}
	mux := http.NewServeMux()
	RegisterRoutes(mux, store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/static", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("static root status = %d, want 301; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/static/" {
		t.Fatalf("static root Location = %q, want /static/", got)
	}
	if strings.Contains(rec.Body.String(), "Page not found") {
		t.Fatalf("static root rendered public web fallback:\n%s", rec.Body.String())
	}
}

func TestRegisterRoutesKeepsMethodSpecificAPIHandling(t *testing.T) {
	store := &mockStore{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/check", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	RegisterRoutes(mux, store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/check", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("API method mismatch status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("API method mismatch Allow = %q, want POST", got)
	}
	if strings.Contains(rec.Body.String(), "Page not found") {
		t.Fatalf("API method mismatch rendered public web fallback:\n%s", rec.Body.String())
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
	if !strings.Contains(body, "Supply-chain Risks (1)") {
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
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("Package (missing params) Content-Type = %q, want text/html", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Page not found",
		`href="/search" aria-current="page"`,
		`href="/admin/"`,
		`id="main-content"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package (missing params) body missing %q:\n%s", want, body)
		}
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
