package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func (m *mockStore) SearchPackages(_ context.Context, query string, _ int) ([]db.PackageSearchResult, error) {
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	if query == "" {
		return nil, nil
	}
	return []db.PackageSearchResult{
		{Ecosystem: "npm", Name: "lodash", FindingsCount: 2, Sources: "osv,ghsa"},
	}, nil
}

func (m *mockStore) FindVulnerabilities(_ context.Context, _, _, _ string) ([]domain.Finding, error) {
	if m.vulnErr != nil {
		return nil, m.vulnErr
	}
	return []domain.Finding{}, nil
}

func (m *mockStore) FindMalicious(_ context.Context, _, _ string) ([]domain.Finding, error) {
	if m.malErr != nil {
		return nil, m.malErr
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
	store := &mockStore{}
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
	store := &mockStore{}
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
