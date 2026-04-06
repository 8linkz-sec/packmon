package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
// stubStore implements db.Store for handler tests. It returns canned data
// controlled by the test. Only the methods called by HandleCheck and helpers
// need real implementations; everything else is a no-op.
// ---------------------------------------------------------------------------

type stubStore struct {
	vulnBatchFindings []domain.Finding
	vulnBatchErr      error
	malBatchFindings  []domain.Finding
	malBatchErr       error
	feedStatuses      []db.FeedSyncStatus
	feedStatusesErr   error

	// capture InsertScanLog calls
	scanLogEntries []db.ScanLogEntry
}

func (s *stubStore) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}
func (s *stubStore) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}
func (s *stubStore) FindVulnerabilitiesBatch(_ context.Context, _ []db.PackageQuery) ([]domain.Finding, error) {
	return s.vulnBatchFindings, s.vulnBatchErr
}
func (s *stubStore) FindMaliciousBatch(_ context.Context, _ []db.PackageQuery) ([]domain.Finding, error) {
	return s.malBatchFindings, s.malBatchErr
}
func (s *stubStore) UpsertVulnerability(context.Context, *db.Vulnerability) error { return nil }
func (s *stubStore) UpsertMaliciousFinding(context.Context, *db.MaliciousFinding) error {
	return nil
}
func (s *stubStore) DeleteVulnerability(context.Context, string) error        { return nil }
func (s *stubStore) DeleteMaliciousFinding(context.Context, string) error     { return nil }
func (s *stubStore) ListMaliciousFindings(context.Context, string, int) ([]db.MaliciousFinding, error) {
	return nil, nil
}
func (s *stubStore) SetCISAKEV(context.Context, []string) (int, error)              { return 0, nil }
func (s *stubStore) ClearCISAKEV(context.Context, []string) (int, error)            { return 0, nil }
func (s *stubStore) SetEPSSScores(context.Context, []db.EPSSEntry) (int, error)     { return 0, nil }
func (s *stubStore) EnrichVulnCheck(context.Context, []db.VulnCheckEntry) (int, error) {
	return 0, nil
}
func (s *stubStore) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	return nil, nil
}
func (s *stubStore) UpsertFeedSyncStatus(context.Context, *db.FeedSyncStatus) error { return nil }
func (s *stubStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return s.feedStatuses, s.feedStatusesErr
}
func (s *stubStore) GetFeedConfig(context.Context, string) (*db.FeedConfig, error) { return nil, nil }
func (s *stubStore) UpsertFeedConfig(context.Context, *db.FeedConfig) error        { return nil }
func (s *stubStore) DeleteFeedConfig(context.Context, string) error                { return nil }
func (s *stubStore) ListFeedConfigs(context.Context) ([]db.FeedConfig, error)      { return nil, nil }
func (s *stubStore) EnqueueRefresh(_ context.Context, _ *db.RefreshJob) (bool, int, error) {
	return true, 1, nil
}
func (s *stubStore) DequeueRefresh(context.Context, string) (*db.RefreshJob, error) { return nil, nil }
func (s *stubStore) CompleteRefresh(context.Context, int, error) error              { return nil }
func (s *stubStore) ResetStuckJobs(context.Context, string, time.Duration) (int, error) {
	return 0, nil
}
func (s *stubStore) GetPackageCheckStatus(context.Context, string, string, string) (*db.PackageCheckStatus, error) {
	return nil, nil
}
func (s *stubStore) UpsertPackageCheckStatus(context.Context, *db.PackageCheckStatus) error {
	return nil
}
func (s *stubStore) InsertScanLog(_ context.Context, entry *db.ScanLogEntry) error {
	s.scanLogEntries = append(s.scanLogEntries, *entry)
	return nil
}
func (s *stubStore) ListRecentScans(context.Context, int) ([]db.ScanLogEntry, error) {
	return nil, nil
}
func (s *stubStore) CountScansByDay(context.Context, int) ([]db.DailyScanStats, error) {
	return nil, nil
}
func (s *stubStore) SearchPackages(context.Context, string, int) ([]db.PackageSearchResult, error) {
	return nil, nil
}
func (s *stubStore) FindAPIKeyByHash(context.Context, string) (*db.APIKey, error) { return nil, nil }
func (s *stubStore) TouchAPIKeyLastUsed(context.Context, int) error               { return nil }
func (s *stubStore) ListAPIKeys(context.Context) ([]db.APIKey, error)             { return nil, nil }
func (s *stubStore) CreateAPIKey(context.Context, string, string) (int, error)    { return 0, nil }
func (s *stubStore) RevokeAPIKey(context.Context, int) error                      { return nil }
func (s *stubStore) DeleteAPIKey(context.Context, int) error                      { return nil }
func (s *stubStore) GetAdminAuth(context.Context) (*db.AdminAuth, error)          { return nil, nil }
func (s *stubStore) UpsertAdminAuth(context.Context, string, bool) error          { return nil }
func (s *stubStore) InsertAdminAuditLog(context.Context, *db.AdminAuditEntry) error {
	return nil
}
func (s *stubStore) ListAdminAuditLog(context.Context, int) ([]db.AdminAuditLogEntry, error) {
	return nil, nil
}
func (s *stubStore) QueueStats(context.Context) (*db.QueueStatsResult, error)         { return &db.QueueStatsResult{}, nil }
func (s *stubStore) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return nil, nil
}
func (s *stubStore) PurgeQueue(context.Context) (int, error)                       { return 0, nil }
func (s *stubStore) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	return &db.DashboardStatsResult{BySeverity: map[string]int{}}, nil
}
func (s *stubStore) Close() error { return nil }

// newTestHandler creates a handler backed by the given stubStore.
func newTestHandler(store *stubStore) *Handler {
	logger := slog.Default()
	return NewHandler(store, logger)
}

// ---------------------------------------------------------------------------
// HandleCheck tests
// ---------------------------------------------------------------------------

func TestHandleCheck_ValidRequest(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubStore{
		vulnBatchFindings: []domain.Finding{
			{
				Name:       "lodash",
				Version:    "4.17.15",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "CVE-2021-23337",
				Title:      "Prototype pollution in lodash",
				Source:     "osv",
			},
		},
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-1 * time.Hour))},
		},
	}

	h := newTestHandler(store)

	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify response JSON shape.
	var result domain.ScanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.ScanID == "" {
		t.Fatal("scan_id must not be empty")
	}
	if result.Mode != "remote" {
		t.Fatalf("mode = %q, want %q", result.Mode, "remote")
	}
	if result.PackagesScanned != 1 {
		t.Fatalf("packages_scanned = %d, want 1", result.PackagesScanned)
	}
	if result.FindingsCount != 1 {
		t.Fatalf("findings_count = %d, want 1", result.FindingsCount)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].AdvisoryID != "CVE-2021-23337" {
		t.Fatalf("findings[0].advisory_id = %q, want %q", result.Findings[0].AdvisoryID, "CVE-2021-23337")
	}

	// Verify response headers.
	if rr.Header().Get("X-Correlation-ID") == "" {
		t.Fatal("X-Correlation-ID header must be set")
	}
	if rr.Header().Get("X-Scan-Duration-Ms") == "" {
		t.Fatal("X-Scan-Duration-Ms header must be set")
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleCheck_EmptyPackages(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})

	body := `{"packages":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	// The handler returns 400 for empty packages array per the contract:
	// "packages array is required and must not be empty"
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for empty packages, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp errorJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if !strings.Contains(errResp.Error, "empty") {
		t.Fatalf("error message should mention 'empty', got: %q", errResp.Error)
	}
}

func TestHandleCheck_TooManyPackages(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})

	// Build a request with >5000 packages.
	packages := make([]domain.Package, maxPackagesPerCheck+1)
	for i := range packages {
		packages[i] = domain.Package{
			Name:      fmt.Sprintf("pkg-%d", i),
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
		}
	}
	reqBody := domain.ScanRequest{Packages: packages}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for too many packages, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp errorJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if !strings.Contains(errResp.Error, "too many packages") {
		t.Fatalf("error message should mention 'too many packages', got: %q", errResp.Error)
	}
}

func TestHandleCheck_InvalidJSON(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(`{invalid json`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for invalid JSON, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCheck_RequestTooLarge(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})

	// Create a body larger than maxRequestBody (1 MB).
	// We build a valid-ish JSON prefix but padded to exceed the limit.
	bigPayload := `{"packages":[` + strings.Repeat(`{"name":"x","version":"1.0.0","ecosystem":"npm"},`, 30000) + `{"name":"x","version":"1.0.0","ecosystem":"npm"}]}`
	if len(bigPayload) < int(maxRequestBody) {
		// Pad further if needed.
		padding := strings.Repeat(" ", int(maxRequestBody)-len(bigPayload)+100)
		bigPayload = bigPayload + padding
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(bigPayload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for oversized body, got %d", rr.Code)
	}
}

func TestHandleCheck_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/check", nil)
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405 for GET, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// buildSummary tests
// ---------------------------------------------------------------------------

func TestBuildSummary(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{Severity: domain.SeverityCritical, Type: domain.FindingTypeVulnerability, Source: "osv"},
		{Severity: domain.SeverityHigh, Type: domain.FindingTypeVulnerability, Source: "osv"},
		{Severity: domain.SeverityHigh, Type: domain.FindingTypeVulnerability, Source: "ghsa"},
		{Severity: domain.SeverityCritical, Type: domain.FindingTypeMalicious, Source: "openssf"},
	}

	summary := buildSummary(findings)

	if summary.BySeverity["CRITICAL"] != 2 {
		t.Fatalf("BySeverity[CRITICAL] = %d, want 2", summary.BySeverity["CRITICAL"])
	}
	if summary.BySeverity["HIGH"] != 2 {
		t.Fatalf("BySeverity[HIGH] = %d, want 2", summary.BySeverity["HIGH"])
	}
	if summary.ByType["vulnerability"] != 3 {
		t.Fatalf("ByType[vulnerability] = %d, want 3", summary.ByType["vulnerability"])
	}
	if summary.ByType["malicious"] != 1 {
		t.Fatalf("ByType[malicious] = %d, want 1", summary.ByType["malicious"])
	}
	if summary.BySource["osv"] != 2 {
		t.Fatalf("BySource[osv] = %d, want 2", summary.BySource["osv"])
	}
	if summary.BySource["ghsa"] != 1 {
		t.Fatalf("BySource[ghsa] = %d, want 1", summary.BySource["ghsa"])
	}
	if summary.BySource["openssf"] != 1 {
		t.Fatalf("BySource[openssf] = %d, want 1", summary.BySource["openssf"])
	}
}

func TestBuildSummary_Empty(t *testing.T) {
	t.Parallel()

	summary := buildSummary(nil)

	if len(summary.BySeverity) != 0 {
		t.Fatalf("BySeverity should be empty, got %v", summary.BySeverity)
	}
	if len(summary.ByType) != 0 {
		t.Fatalf("ByType should be empty, got %v", summary.ByType)
	}
	if len(summary.BySource) != 0 {
		t.Fatalf("BySource should be empty, got %v", summary.BySource)
	}
}

// ---------------------------------------------------------------------------
// isBlocking tests
// ---------------------------------------------------------------------------

func TestIsBlocking_MalwareAlwaysBlocks(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{
			Type:     domain.FindingTypeMalicious,
			Severity: domain.SeverityLow,
		},
	}

	// Malware should block even when the threshold is CRITICAL.
	if !isBlocking(findings, domain.SeverityCritical) {
		t.Fatal("malware finding should always block, regardless of threshold")
	}
}

func TestIsBlocking_VulnAboveThreshold(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{
			Type:     domain.FindingTypeVulnerability,
			Severity: domain.SeverityCritical,
		},
	}

	if !isBlocking(findings, domain.SeverityCritical) {
		t.Fatal("CRITICAL vuln should block with CRITICAL threshold")
	}
	if !isBlocking(findings, domain.SeverityHigh) {
		t.Fatal("CRITICAL vuln should block with HIGH threshold")
	}
}

func TestIsBlocking_VulnBelowThreshold(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{
			Type:     domain.FindingTypeVulnerability,
			Severity: domain.SeverityMedium,
		},
	}

	if isBlocking(findings, domain.SeverityCritical) {
		t.Fatal("MEDIUM vuln should NOT block with CRITICAL threshold")
	}
}

func TestIsBlocking_NoFindings(t *testing.T) {
	t.Parallel()

	if isBlocking(nil, domain.SeverityCritical) {
		t.Fatal("no findings should never block")
	}
	if isBlocking([]domain.Finding{}, domain.SeverityLow) {
		t.Fatal("empty findings should never block")
	}
}

func TestIsBlocking_MixedFindings(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow},
		{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityMedium},
	}

	// With CRITICAL threshold, neither LOW nor MEDIUM should block.
	if isBlocking(findings, domain.SeverityCritical) {
		t.Fatal("LOW+MEDIUM findings should not block with CRITICAL threshold")
	}

	// With MEDIUM threshold, the MEDIUM finding should block.
	if !isBlocking(findings, domain.SeverityMedium) {
		t.Fatal("MEDIUM finding should block with MEDIUM threshold")
	}
}

// ---------------------------------------------------------------------------
// HandleCheck: response shape and scan log capture
// ---------------------------------------------------------------------------

func TestHandleCheck_ScanLogCaptured(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-1 * time.Hour))},
		},
	}

	h := newTestHandler(store)

	body := `{"packages":[{"name":"express","version":"4.18.0","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if len(store.scanLogEntries) != 1 {
		t.Fatalf("expected 1 scan log entry, got %d", len(store.scanLogEntries))
	}

	entry := store.scanLogEntries[0]
	if entry.PackagesCount != 1 {
		t.Fatalf("scan log packages_count = %d, want 1", entry.PackagesCount)
	}
}

func TestHandleCheck_StoreError(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnBatchErr: fmt.Errorf("connection refused"),
	}

	h := newTestHandler(store)

	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500 on store error, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCheck_FeedStatusDegraded(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "error", LastSyncAt: ptrFeedTime(time.Now().UTC().Add(-1 * time.Hour))},
		},
	}

	h := newTestHandler(store)

	body := `{"packages":[{"name":"express","version":"4.18.0","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var result domain.ScanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if result.FeedStatus != "degraded" {
		t.Fatalf("feed_status = %q, want %q", result.FeedStatus, "degraded")
	}
}

func TestOverallFeedStatus(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		statuses []db.FeedSyncStatus
		want     string
	}{
		{
			name: "no statuses default degraded",
			want: "degraded",
		},
		{
			name: "all feeds healthy",
			statuses: []db.FeedSyncStatus{
				{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-2 * time.Hour))},
				{FeedName: "ghsa", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-3 * time.Hour))},
			},
			want: "healthy",
		},
		{
			name: "stale feed degrades response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-72 * time.Hour))},
			},
			want: "degraded",
		},
		{
			name: "errored feed degrades response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "socket", LastSyncStatus: "error", LastSyncAt: ptrFeedTime(now.Add(-30 * time.Minute))},
			},
			want: "degraded",
		},
		{
			name: "skipped feed degrades response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "vulncheck", LastSyncStatus: "skipped", LastSyncAt: ptrFeedTime(now.Add(-30 * time.Minute))},
			},
			want: "degraded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := overallFeedStatus(tt.statuses); got != tt.want {
				t.Fatalf("overallFeedStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFeedHealthStatusSkippedIsWarning(t *testing.T) {
	now := time.Now().UTC()
	status := db.FeedSyncStatus{
		FeedName:       "vulncheck",
		LastSyncStatus: "skipped",
		LastSyncAt:     ptrFeedTime(now.Add(-10 * time.Minute)),
	}

	if got := feedHealthStatus(status); got != "warning" {
		t.Fatalf("feedHealthStatus() = %q, want %q", got, "warning")
	}
}

func ptrFeedTime(t time.Time) *time.Time {
	return &t
}
