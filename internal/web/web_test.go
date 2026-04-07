package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

// ---------------------------------------------------------------------------
// Mock store -- implements Store with minimal dummy data.
// ---------------------------------------------------------------------------

type mockStore struct {
	dashboardErr error
	dailyErr     error
	scansErr     error
	searchErr    error
	feedsErr     error
	vulnErr      error
	malErr       error
	recentVulns  []db.RecentVulnerability
	vulnFindings []domain.Finding
	malFindings  []domain.Finding
}

func (m *mockStore) DashboardStats(_ context.Context) (*db.DashboardStatsResult, error) {
	if m.dashboardErr != nil {
		return nil, m.dashboardErr
	}
	return &db.DashboardStatsResult{
		TotalPackages:        100,
		TotalVulnerabilities: 42,
		TotalMalicious:       3,
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
	return m.recentVulns, nil
}

func (m *mockStore) SearchPackages(_ context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	if m.searchErr != nil {
		return nil, m.searchErr
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
				Sources:            "openssf",
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
			Sources:            "osv,ghsa",
		},
	}, nil
}

func (m *mockStore) FindVulnerabilities(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	if m.vulnErr != nil {
		return nil, m.vulnErr
	}
	if m.vulnFindings != nil {
		return m.vulnFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindMalicious(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	if m.malErr != nil {
		return nil, m.malErr
	}
	if m.malFindings != nil {
		return m.malFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) ListFeedSyncStatuses(_ context.Context) ([]db.FeedSyncStatus, error) {
	if m.feedsErr != nil {
		return nil, m.feedsErr
	}
	return []db.FeedSyncStatus{
		{FeedName: "osv", LastSyncStatus: "success", EntriesSynced: 500, EntriesTotal: 500},
	}, nil
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
	if !strings.Contains(body, "Recently Published Vulnerabilities") {
		t.Fatal("Dashboard response does not contain the published vulnerabilities section")
	}
	if !strings.Contains(body, "/search?severity=CRITICAL") {
		t.Fatal("Dashboard response does not contain severity links to search")
	}
	if !strings.Contains(body, "/search?finding=malicious") {
		t.Fatal("Dashboard response does not contain the malicious packages link")
	}
	if !strings.Contains(body, "Published") {
		t.Fatal("Dashboard response does not contain the published column heading")
	}
	if !strings.Contains(body, "Affected: &gt;= 1.2.0, &lt; 1.2.5") {
		t.Fatal("Dashboard response does not contain affected version details")
	}
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal("Dashboard response does not contain full HTML layout")
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
	if !strings.Contains(body, "Finding Type") {
		t.Fatal("Search response does not contain the finding type filter")
	}
	if !strings.Contains(body, "Vulnerabilities") {
		t.Fatal("Search response does not contain the vulnerabilities column")
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

	body := rec.Body.String()
	// The partial response should NOT contain the full layout.
	if strings.Contains(body, "<!DOCTYPE html>") {
		t.Fatal("Search HTMX partial should not contain full HTML layout")
	}
}

func TestHandleSearch_WithSeverityOnly_ReturnsOK(t *testing.T) {
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

	body := rec.Body.String()
	if !strings.Contains(body, "severity CRITICAL") {
		t.Fatal("Search response does not contain the active severity summary")
	}
	if !strings.Contains(body, "openssl") {
		t.Fatal("Search response does not contain results for the severity filter")
	}
}

func TestHandleSearch_WithMaliciousFindingOnly_ReturnsOK(t *testing.T) {
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

	body := rec.Body.String()
	if !strings.Contains(body, "for malicious packages") {
		t.Fatal("Search response does not contain the active malicious finding summary")
	}
	if !strings.Contains(body, "requests-evil") {
		t.Fatal("Search response does not contain malicious package results")
	}
	if !strings.Contains(body, "No known vulnerabilities") {
		t.Fatal("Search response should show that malicious-only results have no vulnerabilities")
	}
}

func TestHandleSearch_ShowsVulnerabilityCountOnly(t *testing.T) {
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
	if strings.Contains(body, "RUSTSEC-2026-0081") {
		t.Fatal("Search response should not contain the advisory IDs directly")
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
}

// ---------------------------------------------------------------------------
// Package tests
// ---------------------------------------------------------------------------

func TestHandlePackage_ReturnsOK(t *testing.T) {
	store := &mockStore{
		vulnFindings: []domain.Finding{
			{
				Name:       "lodash",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-test-1234",
				Title:      "Example advisory title that should remain fully visible in the package table",
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
	if !strings.Contains(body, ">GHSA<") || !strings.Contains(body, ">NVD<") {
		t.Fatal("Package response does not contain the expected resource links")
	}
	if !strings.Contains(body, "Example advisory title that should remain fully visible in the package table") {
		t.Fatal("Package response does not contain the full advisory title")
	}
	if strings.Contains(body, "href=\"https://nvd.nist.gov/vuln/detail/CVE-2026-0001\" target=\"_blank\" rel=\"noopener\" class=\"text-blue-600 hover:underline\">GHSA-test-1234</a>") {
		t.Fatal("Package response should not link the advisory ID directly to NVD")
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
