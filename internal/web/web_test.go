package web

import (
	"context"
	"errors"
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
	repFindings  []domain.Finding
	lifecycle    []domain.Finding
	refreshErr   error
	refreshNew   bool
	refreshPos   int
	refreshJobs  []db.RefreshJob
}

type storeWithoutRefresh struct {
	Store
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

func (m *mockStore) FindReputationFindings(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	if m.repFindings != nil {
		return m.repFindings, nil
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindLifecycleFindingsBatch(_ context.Context, _ []db.PackageQuery, _ time.Time) ([]domain.Finding, error) {
	return m.lifecycle, nil
}

func (m *mockStore) ListFeedSyncStatuses(_ context.Context) ([]db.FeedSyncStatus, error) {
	if m.feedsErr != nil {
		return nil, m.feedsErr
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

func TestHandleDashboard_StoreErrorsRenderFallback(t *testing.T) {
	store := &mockStore{
		dashboardErr: errors.New("stats unavailable"),
		dailyErr:     errors.New("daily unavailable"),
	}
	handler := HandleDashboard(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Dashboard fallback status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); !strings.Contains(body, "Dashboard") {
		t.Fatalf("Dashboard fallback body does not contain heading: %s", body)
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

	if got := normalizeSearchSeverity(" unknown "); got != "UNKNOWN" {
		t.Fatalf("normalizeSearchSeverity(unknown) = %q, want UNKNOWN", got)
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

	if got := feedHealthStatus(status); got != "disabled" {
		t.Fatalf("feedHealthStatus() = %q, want %q", got, "disabled")
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

	if got := feedHealthStatus(status); got != "warning" {
		t.Fatalf("feedHealthStatus() = %q, want %q", got, "warning")
	}
	if _, reason := feedHealth(status); reason != "no entries synced yet" {
		t.Fatalf("feedHealth() reason = %q, want no entries reason", reason)
	}
}

func TestHandleFeeds_StoreErrorRendersEmptyStatus(t *testing.T) {
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
		{name: "running", in: db.FeedSyncStatus{LastSyncStatus: "running"}, want: "pending", reason: "sync running"},
		{name: "skipped", in: db.FeedSyncStatus{LastSyncStatus: "skipped"}, want: "warning", reason: "last sync skipped"},
		{name: "never", in: db.FeedSyncStatus{LastSyncStatus: "success"}, want: "error", reason: "never synced"},
		{name: "stale", in: db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &old, EntriesSynced: 1}, want: "warning", reason: "stale: no sync in 48h+"},
		{name: "healthy", in: db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &now, EntriesSynced: 1, EntriesTotal: 1}, want: "healthy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := feedHealthStatus(tt.in); got != tt.want {
				t.Fatalf("feedHealthStatus() = %q, want %q", got, tt.want)
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
	if !strings.Contains(body, ">GHSA<") || !strings.Contains(body, ">NVD<") {
		t.Fatal("Package response does not contain the expected resource links")
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
	if !strings.Contains(body, `hx-post="/package/npm/refresh/lodash"`) {
		t.Fatalf("Package response missing web refresh route:\n%s", body)
	}
}

func TestHandlePackageRefreshQueuesJob(t *testing.T) {
	store := &mockStore{refreshNew: true, refreshPos: 2}
	handler := HandlePackageRefresh(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodPost, "/package/npm/refresh/@scope/pkg", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "@scope/pkg")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if len(store.refreshJobs) != 1 {
		t.Fatalf("refreshJobs len = %d, want 1", len(store.refreshJobs))
	}
	job := store.refreshJobs[0]
	if job.Ecosystem != "npm" || job.Name != "@scope/pkg" || job.Source != "socket" || job.Priority != 0 || job.Status != "pending" {
		t.Fatalf("refresh job = %+v", job)
	}
	if !strings.Contains(rec.Body.String(), "Refresh queued at position 2") {
		t.Fatalf("refresh response body = %s", rec.Body.String())
	}
}

func TestHandlePackageRefreshErrorBranches(t *testing.T) {
	t.Parallel()

	renderer := testRenderer()
	logger := discardLogger()

	methodHandler := HandlePackageRefresh(&mockStore{}, renderer, logger)
	req := httptest.NewRequest(http.MethodGet, "/package/npm/refresh/lodash", nil)
	rec := httptest.NewRecorder()
	methodHandler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET refresh status = %d, want 405", rec.Code)
	}

	invalidHandler := HandlePackageRefresh(&mockStore{}, renderer, logger)
	req = httptest.NewRequest(http.MethodPost, "/package/notvalid/refresh/lodash", nil)
	req.SetPathValue("ecosystem", "notvalid")
	req.SetPathValue("name", "lodash")
	rec = httptest.NewRecorder()
	invalidHandler(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Invalid package refresh request") {
		t.Fatalf("invalid refresh = %d %q", rec.Code, rec.Body.String())
	}

	unavailableHandler := HandlePackageRefresh(storeWithoutRefresh{}, renderer, logger)
	req = httptest.NewRequest(http.MethodPost, "/package/npm/refresh/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec = httptest.NewRecorder()
	unavailableHandler(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "not available") {
		t.Fatalf("unavailable refresh = %d %q", rec.Code, rec.Body.String())
	}

	errorHandler := HandlePackageRefresh(&mockStore{refreshErr: errors.New("queue down")}, renderer, logger)
	req = httptest.NewRequest(http.MethodPost, "/package/npm/refresh/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec = httptest.NewRecorder()
	errorHandler(rec, req)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Failed to queue") {
		t.Fatalf("enqueue error refresh = %d %q", rec.Code, rec.Body.String())
	}

	duplicateHandler := HandlePackageRefresh(&mockStore{refreshNew: false, refreshPos: 4}, renderer, logger)
	req = httptest.NewRequest(http.MethodPost, "/package/npm/refresh/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec = httptest.NewRecorder()
	duplicateHandler(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "already queued at position 4") {
		t.Fatalf("duplicate refresh = %d %q", rec.Code, rec.Body.String())
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
				Source:     db.ReputationSourceReversingLabs,
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
	if !strings.Contains(body, "Malicious Package Reports (0)") {
		t.Fatal("Package response should not count supply-chain reputation as malicious")
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
