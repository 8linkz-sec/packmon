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
	"sync"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/server/middleware"
)

// ---------------------------------------------------------------------------
// stubStore implements db.Store for handler tests. It returns canned data
// controlled by the test. Only the methods called by HandleCheck and helpers
// need real implementations; everything else is a no-op.
// ---------------------------------------------------------------------------

type stubStore struct {
	mu sync.Mutex

	vulnBatchFindings     []domain.Finding
	vulnBatchErr          error
	vulnFindings          []domain.Finding
	vulnErr               error
	malBatchFindings      []domain.Finding
	malBatchErr           error
	malFindings           []domain.Finding
	malErr                error
	reputationFindings    []domain.Finding
	reputationPackage     []domain.Finding
	reputationErr         error
	lifecycleFindings     []domain.Finding
	lifecycleErr          error
	markReputationQueued  bool
	markReputationErr     error
	markReputationBlock   <-chan struct{}
	markReputationStarted chan<- struct{}
	feedStatuses          []db.FeedSyncStatus
	feedStatusesErr       error

	// capture InsertScanLog calls
	scanLogEntries    []db.ScanLogEntry
	reputationQueries []struct {
		packages []db.PackageQuery
		source   string
	}
	markedReputations   []db.PackageReputation
	upsertedReputations []db.PackageReputation
	upsertedLifecycle   []db.LifecycleProduct
	enqueuedRefreshJobs []db.RefreshJob
	upsertedVulns       []db.Vulnerability
	deletedVulnIDs      []string
	upsertedMalicious   []db.MaliciousFinding
	deletedMaliciousIDs []string
	upsertedStatuses    []db.FeedSyncStatus
	cisaKEVIDs          []string
	clearedCISAKEVIDs   []string
	epssEntries         []db.EPSSEntry
	vulnCheckEntries    []db.VulnCheckEntry
	reputationPackages  []struct {
		ecosystem string
		name      string
		source    string
	}
	lifecycleQueries []db.PackageQuery
}

type syncExportStore struct {
	stubStore
	export *db.SyncExport
	err    error
	opts   db.SyncExportOptions
}

func (s *syncExportStore) ExportSync(_ context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	s.opts = opts
	return s.export, s.err
}

func (s *stubStore) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	return s.vulnFindings, s.vulnErr
}

func (s *stubStore) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return s.malFindings, s.malErr
}

func (s *stubStore) FindVulnerabilitiesBatch(_ context.Context, _ []db.PackageQuery) ([]domain.Finding, error) {
	return s.vulnBatchFindings, s.vulnBatchErr
}

func (s *stubStore) FindMaliciousBatch(_ context.Context, _ []db.PackageQuery) ([]domain.Finding, error) {
	return s.malBatchFindings, s.malBatchErr
}

func (s *stubStore) FindReputationFindingsBatch(_ context.Context, packages []db.PackageQuery, source string) ([]domain.Finding, error) {
	copied := append([]db.PackageQuery(nil), packages...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reputationQueries = append(s.reputationQueries, struct {
		packages []db.PackageQuery
		source   string
	}{packages: copied, source: source})
	return s.reputationFindings, s.reputationErr
}

func (s *stubStore) FindLifecycleFindingsBatch(_ context.Context, packages []db.PackageQuery, _ time.Time) ([]domain.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lifecycleQueries = append(s.lifecycleQueries, packages...)
	return s.lifecycleFindings, s.lifecycleErr
}

func (s *stubStore) FindReputationFindings(_ context.Context, ecosystem, name, source string) ([]domain.Finding, error) {
	s.reputationPackages = append(s.reputationPackages, struct {
		ecosystem string
		name      string
		source    string
	}{ecosystem: ecosystem, name: name, source: source})
	return s.reputationPackage, s.reputationErr
}

func (s *stubStore) PropagateSeverityViaAliases(context.Context) (int, error) { return 0, nil }
func (s *stubStore) UpsertVulnerability(_ context.Context, vuln *db.Vulnerability) error {
	if vuln != nil {
		s.upsertedVulns = append(s.upsertedVulns, *vuln)
	}
	return nil
}

func (s *stubStore) UpsertMaliciousFinding(_ context.Context, finding *db.MaliciousFinding) error {
	if finding != nil {
		s.upsertedMalicious = append(s.upsertedMalicious, *finding)
	}
	return nil
}

func (s *stubStore) MarkPackageReputationDue(_ context.Context, rep *db.PackageReputation) (bool, error) {
	if s.markReputationStarted != nil {
		select {
		case s.markReputationStarted <- struct{}{}:
		default:
		}
	}
	if s.markReputationBlock != nil {
		<-s.markReputationBlock
	}
	if rep != nil {
		s.mu.Lock()
		s.markedReputations = append(s.markedReputations, *rep)
		s.mu.Unlock()
	}
	return s.markReputationQueued, s.markReputationErr
}

func (s *stubStore) ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error) {
	return nil, nil
}

func (s *stubStore) UpsertPackageReputation(_ context.Context, rep *db.PackageReputation) error {
	if rep != nil {
		s.mu.Lock()
		s.upsertedReputations = append(s.upsertedReputations, *rep)
		s.mu.Unlock()
	}
	return nil
}

func (s *stubStore) UpsertLifecycleProducts(_ context.Context, products []db.LifecycleProduct) error {
	s.upsertedLifecycle = append(s.upsertedLifecycle, products...)
	return nil
}

func (s *stubStore) DeleteVulnerability(_ context.Context, id string) error {
	s.deletedVulnIDs = append(s.deletedVulnIDs, id)
	return nil
}

func (s *stubStore) DeleteMaliciousFinding(_ context.Context, id string) error {
	s.deletedMaliciousIDs = append(s.deletedMaliciousIDs, id)
	return nil
}

func (s *stubStore) ListMaliciousFindings(context.Context, string, int) ([]db.MaliciousFinding, error) {
	return nil, nil
}
func (s *stubStore) UpsertManualAdvisory(context.Context, *db.ManualAdvisory) error { return nil }
func (s *stubStore) DeleteManualAdvisory(context.Context, string) error             { return nil }
func (s *stubStore) ListManualAdvisories(context.Context, int) ([]db.ManualAdvisory, error) {
	return nil, nil
}

func (s *stubStore) SetCISAKEV(_ context.Context, ids []string) (int, error) {
	s.cisaKEVIDs = append(s.cisaKEVIDs, ids...)
	return len(ids), nil
}

func (s *stubStore) ClearCISAKEV(_ context.Context, ids []string) (int, error) {
	s.clearedCISAKEVIDs = append(s.clearedCISAKEVIDs, ids...)
	return len(ids), nil
}

func (s *stubStore) SetEPSSScores(_ context.Context, entries []db.EPSSEntry) (int, error) {
	s.epssEntries = append(s.epssEntries, entries...)
	return len(entries), nil
}

func (s *stubStore) EnrichVulnCheck(_ context.Context, entries []db.VulnCheckEntry) (int, error) {
	s.vulnCheckEntries = append(s.vulnCheckEntries, entries...)
	return len(entries), nil
}

func (s *stubStore) FindUnknownSeverityCVEAliases(context.Context) ([]db.UnknownCVEAlias, error) {
	return nil, nil
}

func (s *stubStore) UpdateSeverityByCVE(context.Context, string, string, float64) error {
	return nil
}

func (s *stubStore) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	return nil, nil
}

func (s *stubStore) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	if status != nil {
		s.upsertedStatuses = append(s.upsertedStatuses, *status)
	}
	return nil
}

func (s *stubStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return s.feedStatuses, s.feedStatusesErr
}
func (s *stubStore) GetFeedConfig(context.Context, string) (*db.FeedConfig, error)  { return nil, nil }
func (s *stubStore) UpsertFeedConfig(context.Context, *db.FeedConfig) error         { return nil }
func (s *stubStore) DeleteFeedConfig(context.Context, string) error                 { return nil }
func (s *stubStore) ListFeedConfigs(context.Context) ([]db.FeedConfig, error)       { return nil, nil }
func (s *stubStore) GetSystemSettings(context.Context) (*db.SystemSettings, error)  { return nil, nil }
func (s *stubStore) UpsertSystemSettings(context.Context, *db.SystemSettings) error { return nil }
func (s *stubStore) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	if job != nil {
		s.mu.Lock()
		s.enqueuedRefreshJobs = append(s.enqueuedRefreshJobs, *job)
		s.mu.Unlock()
	}
	return true, 1, nil
}

func (s *stubStore) enqueuedRefreshJobsSnapshot() []db.RefreshJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]db.RefreshJob(nil), s.enqueuedRefreshJobs...)
}

func (s *stubStore) markedReputationsSnapshot() []db.PackageReputation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]db.PackageReputation(nil), s.markedReputations...)
}

func (s *stubStore) upsertedReputationsSnapshot() []db.PackageReputation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]db.PackageReputation(nil), s.upsertedReputations...)
}

func waitForRefreshJobs(t *testing.T, store *stubStore, want int) []db.RefreshJob {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for {
		jobs := store.enqueuedRefreshJobsSnapshot()
		if len(jobs) >= want {
			return jobs
		}
		if time.Now().After(deadline) {
			t.Fatalf("enqueued refresh jobs = %d, want at least %d", len(jobs), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
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

func (s *stubStore) ListRecentVulnerabilities(context.Context, int, int) ([]db.RecentVulnerability, error) {
	return nil, nil
}

func (s *stubStore) CountScansByDay(context.Context, int) ([]db.DailyScanStats, error) {
	return nil, nil
}

func (s *stubStore) SearchPackages(context.Context, db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	return nil, nil
}
func (s *stubStore) FindAPIKeyByHash(context.Context, string) (*db.APIKey, error) { return nil, nil }
func (s *stubStore) TouchAPIKeyLastUsed(context.Context, int) error               { return nil }
func (s *stubStore) ListAPIKeys(context.Context) ([]db.APIKey, error)             { return nil, nil }
func (s *stubStore) CreateAPIKey(context.Context, string, string, *time.Time) (int, error) {
	return 0, nil
}
func (s *stubStore) RevokeAPIKey(context.Context, int) error             { return nil }
func (s *stubStore) DeleteAPIKey(context.Context, int) error             { return nil }
func (s *stubStore) GetAdminAuth(context.Context) (*db.AdminAuth, error) { return nil, nil }
func (s *stubStore) UpsertAdminAuth(context.Context, string, bool) error { return nil }
func (s *stubStore) InsertAdminAuditLog(context.Context, *db.AdminAuditEntry) error {
	return nil
}

func (s *stubStore) ListAdminAuditLog(context.Context, int) ([]db.AdminAuditLogEntry, error) {
	return nil, nil
}

func (s *stubStore) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	return &db.QueueStatsResult{}, nil
}

func (s *stubStore) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return nil, nil
}
func (s *stubStore) PurgeQueue(context.Context) (int, error)                { return 0, nil }
func (s *stubStore) UpdateQueueJobPriority(context.Context, int, int) error { return nil }
func (s *stubStore) RetryQueueJob(context.Context, int) error               { return nil }
func (s *stubStore) PauseQueueJob(context.Context, int) error               { return nil }
func (s *stubStore) ResumeQueueJob(context.Context, int) error              { return nil }
func (s *stubStore) ClearQueue(context.Context, []string) (int, error)      { return 0, nil }
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

func TestHandleCheckUsesConfiguredBlockThreshold(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnBatchFindings: []domain.Finding{
			{
				Name:       "lodash",
				Version:    "4.17.15",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityMedium,
				AdvisoryID: "CVE-2021-0001",
				Title:      "Medium vulnerability",
				Source:     "osv",
			},
		},
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC())},
		},
	}

	h := NewHandlerWithBlockThreshold(store, slog.Default(), domain.SeverityMedium)

	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var result domain.ScanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !result.FindingsBlocking {
		t.Fatal("FindingsBlocking = false, want true for MEDIUM threshold")
	}
}

func TestHandleCheckIncludesLifecycleFindings(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnBatchFindings: []domain.Finding{
			{
				Name:       "django",
				Version:    "4.2.11",
				Ecosystem:  domain.EcosystemPyPI,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-django",
				Title:      "Django vulnerability",
				Source:     "osv",
			},
		},
		malBatchFindings: []domain.Finding{
			{
				Name:       "django",
				Version:    "4.2.11",
				Ecosystem:  domain.EcosystemPyPI,
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "MAL-django",
				Title:      "Malicious package",
				RiskType:   "malware",
				Source:     "openssf",
			},
		},
		lifecycleFindings: []domain.Finding{
			{
				Name:       "django",
				Version:    "4.2.11",
				Ecosystem:  domain.EcosystemPyPI,
				Type:       domain.FindingTypeLifecycle,
				Severity:   domain.SeverityLow,
				AdvisoryID: "endoflife:django:4.2:security_support_only",
				Title:      "Django 4.2 is in security support only",
				RiskType:   "security_support_only",
				Source:     "endoflife.date",
			},
		},
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "endoflife", LastSyncStatus: "error", LastError: "rate limited"},
		},
	}

	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(
		`{"packages":[{"name":"django","version":"4.2.11","ecosystem":"pypi"}]}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var result domain.ScanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(result.Findings) != 3 || result.FindingsCount != 3 {
		t.Fatalf("findings = %d count=%d, want 3/3: %+v", len(result.Findings), result.FindingsCount, result.Findings)
	}
	if result.Summary.ByType[string(domain.FindingTypeLifecycle)] != 1 {
		t.Fatalf("summary.by_type.lifecycle = %d, want 1", result.Summary.ByType[string(domain.FindingTypeLifecycle)])
	}
	if len(store.lifecycleQueries) != 1 {
		t.Fatalf("lifecycle queries = %d, want 1", len(store.lifecycleQueries))
	}
	if result.FeedStatus != "degraded" {
		t.Fatalf("FeedStatus = %q, want degraded", result.FeedStatus)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/status", nil)
	statusRR := httptest.NewRecorder()
	h.HandleFeedStatus(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("feed status code = %d: %s", statusRR.Code, statusRR.Body.String())
	}
	var statusResp FeedStatusResponse
	if err := json.Unmarshal(statusRR.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode feed status: %v", err)
	}
	if len(statusResp.Feeds) != 1 || statusResp.Feeds[0].Name != "endoflife" || !strings.Contains(statusResp.Feeds[0].Message, "rate limited") {
		t.Fatalf("feed status response = %+v, want endoflife rate limited message", statusResp)
	}
}

func TestCollectFindingsIncludesCachedReversingLabsFindings(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		reputationFindings: []domain.Finding{
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
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled:   true,
		ReversingLabsMode:      config.FeedModeSelf,
		ReversingLabsLookupTTL: 24 * time.Hour,
	})

	findings, err := h.collectFindings(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	})
	if err != nil {
		t.Fatalf("collectFindings() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Type != domain.FindingTypeSupplyChainRisk {
		t.Fatalf("finding type = %q, want supply_chain_risk", findings[0].Type)
	}
	if len(store.reputationQueries) != 1 {
		t.Fatalf("reputation queries = %d, want 1", len(store.reputationQueries))
	}
	if store.reputationQueries[0].source != db.ReputationSourceReversingLabs {
		t.Fatalf("reputation source = %q, want reversinglabs", store.reputationQueries[0].source)
	}
}

func TestCollectFindingsSchedulesReversingLabsOnlyForUncoveredSupportedPackages(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnBatchFindings: []domain.Finding{
			{
				Name:      "lodash",
				Version:   "4.17.15",
				Ecosystem: domain.EcosystemNPM,
				Type:      domain.FindingTypeVulnerability,
				Severity:  domain.SeverityHigh,
				Source:    "osv",
			},
		},
		markReputationQueued: true,
	}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled:   true,
		ReversingLabsMode:      config.FeedModeSelf,
		ReversingLabsLookupTTL: 24 * time.Hour,
	})

	_, err := h.collectFindings(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
		{Name: "lodash", Version: "4.17.15", Ecosystem: domain.EcosystemNPM},
		{Name: "github.com/acme/lib", Version: "1.0.0", Ecosystem: domain.EcosystemGo},
	})
	if err != nil {
		t.Fatalf("collectFindings() error = %v", err)
	}

	jobs := waitForRefreshJobs(t, store, 1)
	marked := store.markedReputationsSnapshot()
	if len(marked) != 1 {
		t.Fatalf("marked reputations = %d, want 1", len(marked))
	}
	if got := marked[0]; got.Ecosystem != "npm" || got.Name != "left-pad" || got.Version != "1.3.0" {
		t.Fatalf("marked reputation = %+v, want npm/left-pad@1.3.0", got)
	}
	if got := jobs[0]; got.Source != db.ReputationSourceReversingLabs || got.Ecosystem != "npm" || got.Name != "left-pad" {
		t.Fatalf("enqueued job = %+v, want ReversingLabs left-pad job", got)
	}
	upserted := store.upsertedReputationsSnapshot()
	if len(upserted) != 1 {
		t.Fatalf("upserted reputations = %d, want unsupported Go row", len(upserted))
	}
	if got := upserted[0]; got.Status != "unsupported" || got.Ecosystem != "go" {
		t.Fatalf("unsupported reputation = %+v, want go unsupported", got)
	}
}

func TestHandleCheckSchedulesReversingLabsOffRequestPath(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	store := &stubStore{
		markReputationQueued:  true,
		markReputationBlock:   release,
		markReputationStarted: started,
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC()), EntriesSynced: 1, EntriesTotal: 1},
		},
	}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(
		`{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.HandleCheck(rr, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("HandleCheck blocked on ReversingLabs scheduling")
	}
	if rr.Code != http.StatusOK {
		close(release)
		t.Fatalf("HandleCheck status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("ReversingLabs scheduling did not start")
	}
	close(release)
	_ = waitForRefreshJobs(t, store, 1)
}

func TestHandleCheck_PropagatesCorrelationIDAndRepoMetadata(t *testing.T) {
	t.Parallel()

	incomingCorrelationID := "11111111-2222-4333-8444-555555555555"
	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC())},
		},
	}
	h := newTestHandler(store)

	body := `{
		"repo":{"name":"packmon","branch":"main","commit":"abcdef123456"},
		"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.HeaderCorrelationID, incomingCorrelationID)
	rr := httptest.NewRecorder()

	// Route through the Correlation middleware as in production: it validates
	// the incoming UUID and stores it in the request context, which the handler
	// then propagates. (The handler deliberately does not echo a raw,
	// unvalidated client header on its own.)
	handler := middleware.Correlation(http.HandlerFunc(h.HandleCheck))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get(middleware.HeaderCorrelationID); got != incomingCorrelationID {
		t.Fatalf("X-Correlation-ID = %q, want %q", got, incomingCorrelationID)
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
	entry := store.scanLogEntries[0]
	if entry.RepoName != "packmon" || entry.Branch != "main" || entry.Commit != "abcdef123456" {
		t.Fatalf("scan log repo metadata = (%q,%q,%q), want (packmon,main,abcdef123456)", entry.RepoName, entry.Branch, entry.Commit)
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

func TestHandleCheck_InvalidPackageFields(t *testing.T) {
	t.Parallel()

	h := NewHandler(&stubStore{}, slog.Default())
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing name",
			body: `{"packages":[{"ecosystem":"npm","name":" ","version":"1.0.0"}]}`,
			want: "packages[1].name is required",
		},
		{
			name: "missing version",
			body: `{"packages":[{"ecosystem":"npm","name":"left-pad","version":" "}]}`,
			want: "packages[1].version is required",
		},
		{
			name: "invalid ecosystem",
			body: `{"packages":[{"ecosystem":"unknown","name":"left-pad","version":"1.0.0"}]}`,
			want: "packages[1].ecosystem is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			h.HandleCheck(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tt.want) {
				t.Fatalf("body = %s, want containing %q", rr.Body.String(), tt.want)
			}
		})
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

func TestIsBlocking_NoneThresholdNeverBlocksVulnerabilities(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{
			Type:     domain.FindingTypeVulnerability,
			Severity: domain.SeverityCritical,
		},
	}

	if isBlocking(findings, domain.SeverityNone) {
		t.Fatal("vulnerabilities should not block with NONE threshold")
	}
}

func TestIsBlocking_SupplyChainRiskAlwaysBlocks(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{
			Type:     domain.FindingTypeSupplyChainRisk,
			Severity: domain.SeverityLow,
			Source:   "reversinglabs",
		},
	}

	if !isBlocking(findings, domain.SeverityNone) {
		t.Fatal("supply-chain risk findings must block even when vulnerability threshold is NONE")
	}
}

func TestIsBlocking_LifecycleFindingsUseSeverityThreshold(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{
			Name:       "django",
			Version:    "3.2.25",
			Ecosystem:  domain.EcosystemPyPI,
			Type:       domain.FindingTypeLifecycle,
			Severity:   domain.SeverityMedium,
			AdvisoryID: "eol:django:3.2",
			Title:      "Django 3.2 reaches EOL soon",
			RiskType:   "eol_soon",
			Source:     "endoflife.date",
		},
	}

	if !isBlocking(findings, domain.SeverityMedium) {
		t.Fatal("MEDIUM lifecycle finding should block at MEDIUM threshold")
	}
	if isBlocking(findings, domain.SeverityHigh) {
		t.Fatal("MEDIUM lifecycle finding should not block at HIGH threshold")
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
				{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-2 * time.Hour)), EntriesSynced: 100, EntriesTotal: 100},
				{FeedName: "ghsa", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-3 * time.Hour)), EntriesSynced: 200, EntriesTotal: 200},
			},
			want: "healthy",
		},
		{
			name: "disabled optional feed does not degrade response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-2 * time.Hour)), EntriesSynced: 100, EntriesTotal: 100},
				{FeedName: "ghsa", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-3 * time.Hour)), EntriesSynced: 200, EntriesTotal: 200},
				{FeedName: "vulncheck", LastSyncStatus: "disabled", LastSyncAt: ptrFeedTime(now.Add(-30 * time.Minute)), EntriesSynced: 0, EntriesTotal: 0},
			},
			want: "healthy",
		},
		{
			name: "only disabled feeds default degraded because no active data is available",
			statuses: []db.FeedSyncStatus{
				{FeedName: "vulncheck", LastSyncStatus: "disabled", EntriesSynced: 0, EntriesTotal: 0},
			},
			want: "degraded",
		},
		{
			name: "running feed with fresh cached data does not degrade response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-2 * time.Hour)), EntriesSynced: 100, EntriesTotal: 100},
				{FeedName: "nvd", LastSyncStatus: "running", LastSyncAt: ptrFeedTime(now.Add(-30 * time.Minute)), EntriesSynced: 70, EntriesTotal: 96},
				{FeedName: "vulncheck", LastSyncStatus: "disabled", EntriesSynced: 0, EntriesTotal: 0},
			},
			want: "healthy",
		},
		{
			name: "running feed without cached data degrades response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "nvd", LastSyncStatus: "running", EntriesSynced: 0, EntriesTotal: 0},
			},
			want: "degraded",
		},
		{
			name: "zero-entry feed degrades response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-1 * time.Hour)), EntriesSynced: 0, EntriesTotal: 0},
			},
			want: "degraded",
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

func TestEffectiveBlockThresholdFollowsRuntime(t *testing.T) {
	t.Parallel()

	runtime := config.NewRuntimeSettings("CRITICAL", 60, 60)
	h := NewHandlerWithRuntime(&stubStore{}, nil, runtime)

	if got := h.effectiveBlockThreshold(); got != domain.SeverityCritical {
		t.Fatalf("initial threshold = %q, want CRITICAL", got)
	}

	// An admin lowering the threshold must take effect immediately (no restart).
	runtime.Update("HIGH", 0, 0)
	if got := h.effectiveBlockThreshold(); got != domain.SeverityHigh {
		t.Fatalf("threshold after runtime update = %q, want HIGH", got)
	}
}

func TestHandlePackageDetailIncludesReversingLabsReputation(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		reputationPackage: []domain.Finding{
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
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/left-pad", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "left-pad")
	rr := httptest.NewRecorder()

	h.HandlePackageDetail(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp PackageDetailResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(resp.Findings))
	}
	if resp.Findings[0].Source != db.ReputationSourceReversingLabs || resp.Findings[0].Type != domain.FindingTypeSupplyChainRisk {
		t.Fatalf("finding = %+v, want ReversingLabs supply-chain risk", resp.Findings[0])
	}
	if len(store.reputationPackages) != 1 {
		t.Fatalf("reputation package queries = %d, want 1", len(store.reputationPackages))
	}
	if got := store.reputationPackages[0]; got.ecosystem != "npm" || got.name != "left-pad" || got.source != db.ReputationSourceReversingLabs {
		t.Fatalf("reputation package query = %+v", got)
	}
}

func TestHandleFeedStatusReturnsPerFeedHealthAndMessages(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-1 * time.Hour)), EntriesTotal: 10},
			{FeedName: "vulncheck", LastSyncStatus: "skipped", LastSyncAt: ptrFeedTime(now.Add(-30 * time.Minute)), LastError: "api key not configured"},
			{FeedName: "ghsa", LastSyncStatus: "error", LastSyncAt: ptrFeedTime(now.Add(-15 * time.Minute)), LastError: "clone failed"},
		},
	}
	h := newTestHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds", nil)
	rr := httptest.NewRecorder()

	h.HandleFeedStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp FeedStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Feeds) != 3 {
		t.Fatalf("feeds = %d, want 3", len(resp.Feeds))
	}
	want := map[string]struct {
		status  string
		message string
	}{
		"osv":       {status: "healthy"},
		"vulncheck": {status: "warning", message: "api key not configured"},
		"ghsa":      {status: "error", message: "clone failed"},
	}
	for _, item := range resp.Feeds {
		expect, ok := want[item.Name]
		if !ok {
			t.Fatalf("unexpected feed item: %+v", item)
		}
		if item.Status != expect.status || item.Message != expect.message {
			t.Fatalf("feed %s = status %q message %q, want %+v", item.Name, item.Status, item.Message, expect)
		}
		if item.Name == "osv" && item.LastSyncAt == nil {
			t.Fatal("osv LastSyncAt is nil, want RFC3339 timestamp")
		}
	}
}

func TestHandleFeedStatusRejectsNonGET(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds", nil)
	rr := httptest.NewRecorder()

	h.HandleFeedStatus(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
}

func TestHandleFeedImportAcceptsMaliciousAlias(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)

	body := `{"malicious":[{"id":"MAL-1","ecosystem":"npm","name":"evil","risk_type":"malware","summary":"bad"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/malicious/import", strings.NewReader(body))
	req.SetPathValue("feed", "malicious")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp importResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Feed != "openssf" {
		t.Fatalf("feed = %q, want openssf", resp.Feed)
	}
	if len(store.upsertedMalicious) != 1 {
		t.Fatalf("upserted malicious = %d, want 1", len(store.upsertedMalicious))
	}
	if got := store.upsertedMalicious[0]; got.Source != "openssf" || got.Severity != "CRITICAL" {
		t.Fatalf("malicious import defaults = %+v", got)
	}
}

func TestHandleFeedImportVulnerabilityNormalizesDefaultsAndRecordsStatus(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	body := `{
		"vulnerabilities":[{
			"id":"GHSA-test",
			"summary":"missing severity should normalize",
			"affected_packages":[{"ecosystem":"npm","name":"left-pad","version_ranges":[],"versions_affected":[]}]
		}],
		"delete_vulnerability_ids":["","GHSA-old"],
		"status":{"last_sync_duration_ms":250,"last_sync_status":"success","last_etag":"abc123","metadata":{"batch":1}}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(body))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedVulns) != 1 {
		t.Fatalf("upserted vulnerabilities = %d, want 1", len(store.upsertedVulns))
	}
	vuln := store.upsertedVulns[0]
	if vuln.Severity != "UNKNOWN" || vuln.Published.IsZero() || vuln.Modified.IsZero() {
		t.Fatalf("normalized vulnerability = %+v", vuln)
	}
	if len(vuln.Sources) != 1 || vuln.Sources[0].Source != "osv" || vuln.Sources[0].SourceID != "GHSA-test" {
		t.Fatalf("sources = %+v, want default osv source", vuln.Sources)
	}
	if len(store.deletedVulnIDs) != 1 || store.deletedVulnIDs[0] != "GHSA-old" {
		t.Fatalf("deleted vulnerability IDs = %#v", store.deletedVulnIDs)
	}
	if len(store.upsertedStatuses) != 1 {
		t.Fatalf("feed statuses = %d, want 1", len(store.upsertedStatuses))
	}
	status := store.upsertedStatuses[0]
	if status.FeedName != "osv" || status.LastSyncStatus != "success" || status.EntriesSynced != 1 || status.EntriesTotal != 2 {
		t.Fatalf("feed status = %+v", status)
	}
	if status.LastSyncDuration == nil || *status.LastSyncDuration != 250*time.Millisecond {
		t.Fatalf("LastSyncDuration = %v, want 250ms", status.LastSyncDuration)
	}
}

func TestHandleFeedImportEnrichmentFeeds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		feed       string
		body       string
		assertions func(*testing.T, *stubStore, importResponse)
	}{
		{
			name: "vulncheck",
			feed: "vulncheck",
			body: `{"entries":[{"cve_id":"CVE-2026-0001","exploit_exists":true,"source_url":"https://vulncheck.test/cve"}]}`,
			assertions: func(t *testing.T, store *stubStore, resp importResponse) {
				t.Helper()
				if resp.Imported != 1 || len(store.vulnCheckEntries) != 1 || !store.vulnCheckEntries[0].ExploitExists {
					t.Fatalf("vulncheck import = resp %+v entries %+v", resp, store.vulnCheckEntries)
				}
			},
		},
		{
			name: "cisakev",
			feed: "cisakev",
			body: `{"cve_ids":["CVE-2026-0002"],"clear_missing":true}`,
			assertions: func(t *testing.T, store *stubStore, resp importResponse) {
				t.Helper()
				if resp.Imported != 1 || len(store.cisaKEVIDs) != 1 || len(store.clearedCISAKEVIDs) != 1 {
					t.Fatalf("cisakev import = resp %+v cisa=%+v cleared=%+v", resp, store.cisaKEVIDs, store.clearedCISAKEVIDs)
				}
			},
		},
		{
			name: "epss",
			feed: "epss",
			body: `{"entries":[{"cve_id":"CVE-2026-0003","score":0.91,"percentile":0.99}]}`,
			assertions: func(t *testing.T, store *stubStore, resp importResponse) {
				t.Helper()
				if resp.Imported != 1 || len(store.epssEntries) != 1 || store.epssEntries[0].Score != 0.91 {
					t.Fatalf("epss import = resp %+v entries %+v", resp, store.epssEntries)
				}
			},
		},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := &stubStore{}
			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleFeedImport(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
			}
			var resp importResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Feed != tt.feed {
				t.Fatalf("feed = %q, want %q", resp.Feed, tt.feed)
			}
			tt.assertions(t, store, resp)
		})
	}
}

func TestHandleFeedImportRejectsUnknownFeedAndInvalidMethod(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/nope/import", strings.NewReader(`{}`))
	req.SetPathValue("feed", "nope")
	rr := httptest.NewRecorder()
	h.HandleFeedImport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown feed status = %d, want 400", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/feeds/osv/import", nil)
	req.SetPathValue("feed", "osv")
	rr = httptest.NewRecorder()
	h.HandleFeedImport(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET import status = %d, want 405", rr.Code)
	}
}

func TestHandleRefreshRejectsVersionBody(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", strings.NewReader(`{"version":"4.17.15"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleRefresh(rr, req, "npm", "lodash")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRefreshEnqueuesPathPackage(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash/refresh")
	rr := httptest.NewRecorder()

	h.HandleRefresh(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.enqueuedRefreshJobs) != 1 {
		t.Fatalf("enqueued jobs = %d, want 1", len(store.enqueuedRefreshJobs))
	}
	job := store.enqueuedRefreshJobs[0]
	if job.Ecosystem != "npm" || job.Name != "lodash" || job.Source != "socket" || job.Priority != 0 {
		t.Fatalf("enqueued job = %+v", job)
	}
	var resp RefreshResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Queued || !resp.New || resp.Position != 1 {
		t.Fatalf("refresh response = %+v", resp)
	}
}

func TestHandlePackageOrRefreshRoutesScopedPackageName(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/@scope/pkg/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "@scope/pkg/refresh")
	rr := httptest.NewRecorder()

	h.HandlePackageOrRefresh(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.enqueuedRefreshJobs) != 1 || store.enqueuedRefreshJobs[0].Name != "@scope/pkg" {
		t.Fatalf("enqueued jobs = %+v, want @scope/pkg refresh", store.enqueuedRefreshJobs)
	}
}

func TestHandleSyncEmitsReputationRows(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &syncExportStore{
		export: &db.SyncExport{
			SyncedAt: now,
			Reputation: []db.SyncReputationFinding{
				{
					ID:        "reversinglabs:npm/left-pad@1.3.0",
					Ecosystem: "npm",
					Name:      "left-pad",
					Version:   "1.3.0",
					Type:      "supply_chain_risk",
					RiskType:  "removed_package",
					Severity:  "CRITICAL",
					Summary:   "ReversingLabs: package version was removed",
				},
			},
		},
	}
	h := newTestHandler(&store.stubStore)
	h.store = store

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil)
	rr := httptest.NewRecorder()

	h.HandleSync(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp syncResponsePayload
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Reputation) != 1 {
		t.Fatalf("reputation rows = %d, want 1", len(resp.Reputation))
	}
	if resp.Reputation[0].Type != "supply_chain_risk" || resp.Reputation[0].RiskType != "removed_package" {
		t.Fatalf("reputation row = %+v", resp.Reputation[0])
	}
}

func TestHandleSyncEmitsPerDatasetNextCursor(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	store := &syncExportStore{
		export: &db.SyncExport{
			SyncedAt: now,
			Vulnerabilities: []db.SyncVulnerability{
				{ID: "GHSA-1", Ecosystem: "npm", Name: "a", VersionRanges: "[]", References: `[{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-1"}]`, Severity: "LOW"},
				{ID: "GHSA-2", Ecosystem: "npm", Name: "b", VersionRanges: "[]", Severity: "LOW"},
			},
			Malicious: []db.SyncMalicious{
				{ID: "MAL-1", Ecosystem: "npm", Name: "evil", ReferenceURLs: `["https://example.test/mal"]`, RiskType: "malware", Severity: "CRITICAL"},
			},
			Truncated: true,
			NextCursor: &db.SyncCursor{
				Vulnerabilities: 1002,
				Malicious:       6,
				Reputation:      7,
				Lifecycle:       8,
			},
		},
	}
	h := newTestHandler(&store.stubStore)
	h.store = store

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync?vulnerabilities_offset=1000&malicious_offset=5&reputation_offset=7&lifecycle_offset=8&limit=2", nil)
	rr := httptest.NewRecorder()
	h.HandleSync(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp syncResponsePayload
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode sync response: %v", err)
	}
	if !resp.Truncated || resp.NextCursor == nil {
		t.Fatalf("sync response missing next cursor: %+v", resp)
	}
	if resp.NextCursor.Vulnerabilities != 1002 || resp.NextCursor.Malicious != 6 || resp.NextCursor.Reputation != 7 || resp.NextCursor.Lifecycle != 8 {
		t.Fatalf("next cursor = %+v", resp.NextCursor)
	}
	if resp.Vulnerabilities[0].References == "" || resp.Malicious[0].ReferenceURLs == "" {
		t.Fatalf("sync response dropped references: %+v %+v", resp.Vulnerabilities[0], resp.Malicious[0])
	}
}

func ptrFeedTime(t time.Time) *time.Time {
	return &t
}
