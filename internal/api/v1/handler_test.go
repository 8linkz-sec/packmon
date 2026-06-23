package v1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/feed/socket"
	"github.com/8linkz-sec/packmon/internal/requestctx"
	"github.com/8linkz-sec/packmon/internal/server/middleware"
)

// ---------------------------------------------------------------------------
// stubStore implements the API v1 Store surface for handler tests. It returns
// canned data controlled by the test.
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
	scanLogEntries       []db.ScanLogEntry
	scanLogErr           error
	scanLogDeadline      time.Time
	scanLogObservedAt    time.Time
	scanLogDeadlineSet   bool
	vulnerabilityQueries []db.PackageQuery
	maliciousQueries     []db.PackageQuery
	reputationQueries    []struct {
		packages []db.PackageQuery
		source   string
	}
	markedReputations      []db.PackageReputation
	upsertedReputations    []db.PackageReputation
	enqueuedRefreshJobs    []db.RefreshJob
	upsertedVulns          []db.Vulnerability
	deletedVulnIDs         []string
	upsertedMalicious      []db.MaliciousFinding
	deletedMaliciousIDs    []string
	deletedMaliciousScoped []struct {
		id     string
		source string
	}
	upsertedStatuses   []db.FeedSyncStatus
	auditEntries       []db.AdminAuditEntry
	cisaKEVIDs         []string
	clearedCISAKEVIDs  []string
	epssEntries        []db.EPSSEntry
	epssReplaceCalls   int
	epssCleared        int
	vulnCheckEntries   []db.VulnCheckEntry
	reputationPackages []struct {
		ecosystem string
		name      string
		source    string
	}
	lifecycleQueries          []db.PackageQuery
	packageCheckStatus        *db.PackageCheckStatus
	packageCheckStatusErr     error
	packageCheckStatusLookups []struct {
		ecosystem string
		name      string
		source    string
	}
}

type syncExportStore struct {
	stubStore
	export *db.SyncExport
	err    error
	opts   db.SyncExportOptions
}

type postInsertConflictStore struct {
	*stubStore
	lookups int
}

func (s *postInsertConflictStore) GetScanLogByIdempotencyKey(_ context.Context, key string) (*db.ScanLogEntry, error) {
	s.lookups++
	if s.lookups == 1 {
		return nil, nil
	}
	return &db.ScanLogEntry{
		ScanID:         "scan-from-other-request",
		IdempotencyKey: key,
		RequestDigest:  "sha256:other-request",
	}, nil
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

func (s *stubStore) FindVulnerabilitiesBatch(_ context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	s.mu.Lock()
	s.vulnerabilityQueries = append(s.vulnerabilityQueries, packages...)
	s.mu.Unlock()
	return s.vulnBatchFindings, s.vulnBatchErr
}

func (s *stubStore) FindMaliciousBatch(_ context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	s.mu.Lock()
	s.maliciousQueries = append(s.maliciousQueries, packages...)
	s.mu.Unlock()
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

func (s *stubStore) GetPackageCheckStatus(_ context.Context, ecosystem, name, source string) (*db.PackageCheckStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packageCheckStatusLookups = append(s.packageCheckStatusLookups, struct {
		ecosystem string
		name      string
		source    string
	}{ecosystem: ecosystem, name: name, source: source})
	if s.packageCheckStatusErr != nil {
		return nil, s.packageCheckStatusErr
	}
	return s.packageCheckStatus, nil
}

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

func (s *stubStore) UpsertPackageReputation(_ context.Context, rep *db.PackageReputation) error {
	if rep != nil {
		s.mu.Lock()
		s.upsertedReputations = append(s.upsertedReputations, *rep)
		s.mu.Unlock()
	}
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

func (s *stubStore) DeleteMaliciousFindingForSource(_ context.Context, id, source string) error {
	s.deletedMaliciousScoped = append(s.deletedMaliciousScoped, struct {
		id     string
		source string
	}{id: id, source: source})
	return nil
}

func (s *stubStore) SetCISAKEV(_ context.Context, ids []string) (int, error) {
	s.cisaKEVIDs = append(s.cisaKEVIDs, ids...)
	return len(ids), nil
}

func (s *stubStore) ClearCISAKEV(_ context.Context, ids []string) (int, error) {
	s.clearedCISAKEVIDs = append(s.clearedCISAKEVIDs, ids...)
	return len(ids), nil
}

func (s *stubStore) ReplaceEPSSScores(_ context.Context, entries []db.EPSSEntry) (int, int, error) {
	s.epssEntries = append(s.epssEntries, entries...)
	s.epssReplaceCalls++
	return len(entries), s.epssCleared, nil
}

func (s *stubStore) EnrichVulnCheck(_ context.Context, entries []db.VulnCheckEntry) (int, error) {
	s.vulnCheckEntries = append(s.vulnCheckEntries, entries...)
	return len(entries), nil
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

func (s *stubStore) vulnerabilityQueriesSnapshot() []db.PackageQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]db.PackageQuery(nil), s.vulnerabilityQueries...)
}

func (s *stubStore) maliciousQueriesSnapshot() []db.PackageQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]db.PackageQuery(nil), s.maliciousQueries...)
}

func (s *stubStore) lifecycleQueriesSnapshot() []db.PackageQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]db.PackageQuery(nil), s.lifecycleQueries...)
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

func waitForUpsertedReputations(t *testing.T, store *stubStore, want int) []db.PackageReputation {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for {
		reputations := store.upsertedReputationsSnapshot()
		if len(reputations) >= want {
			return reputations
		}
		if time.Now().After(deadline) {
			t.Fatalf("upserted reputations = %d, want at least %d", len(reputations), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *stubStore) InsertScanLog(ctx context.Context, entry *db.ScanLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		s.scanLogDeadline = deadline
		s.scanLogObservedAt = time.Now()
		s.scanLogDeadlineSet = true
	}
	if entry != nil && entry.IdempotencyKey != "" {
		for _, existing := range s.scanLogEntries {
			if existing.IdempotencyKey == entry.IdempotencyKey {
				return s.scanLogErr
			}
		}
	}
	s.scanLogEntries = append(s.scanLogEntries, *entry)
	return s.scanLogErr
}

func (s *stubStore) GetScanLogByIdempotencyKey(_ context.Context, key string) (*db.ScanLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.scanLogEntries {
		if s.scanLogEntries[i].IdempotencyKey == key {
			entry := s.scanLogEntries[i]
			return &entry, nil
		}
	}
	return nil, nil
}

func (s *stubStore) InsertAdminAuditLog(_ context.Context, entry *db.AdminAuditEntry) error {
	if entry != nil {
		s.auditEntries = append(s.auditEntries, *entry)
	}
	return nil
}

// newTestHandler creates a handler backed by the given store.
func newTestHandler(store Store) *Handler {
	logger := slog.Default()
	return NewHandlerWithBlockThreshold(store, logger, defaultBlockThreshold)
}

func newLogCaptureHandler(store Store, logs *bytes.Buffer) *Handler {
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return NewHandlerWithBlockThreshold(store, logger, defaultBlockThreshold)
}

func withCorrelationID(req *http.Request, correlationID string) *http.Request {
	ctx := requestctx.ContextWithCorrelationID(req.Context(), correlationID)
	return req.WithContext(ctx)
}

func requireLogField(t *testing.T, logs *bytes.Buffer, key, value string) {
	t.Helper()
	needle := fmt.Sprintf("%q:%q", key, value)
	if !strings.Contains(logs.String(), needle) {
		t.Fatalf("log output missing %s: %s", needle, logs.String())
	}
}

func TestAPIOperationalErrorLogsIncludeCorrelationID(t *testing.T) {
	t.Parallel()

	t.Run("feed status store error", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		h := newLogCaptureHandler(&stubStore{feedStatusesErr: errors.New("db down")}, &logs)
		req := withCorrelationID(httptest.NewRequest(http.MethodGet, "/api/v1/feeds/status", nil), "corr-feed-status")
		rr := httptest.NewRecorder()

		h.HandleFeedStatus(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
		requireLogField(t, &logs, "correlation_id", "corr-feed-status")
	})

	t.Run("feed import decode error", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		h := newLogCaptureHandler(&stubStore{}, &logs)
		req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader("{")), "corr-feed-import")
		req.SetPathValue("feed", "osv")
		rr := httptest.NewRecorder()

		h.HandleFeedImport(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		requireLogField(t, &logs, "correlation_id", "corr-feed-import")
	})

	t.Run("package detail store error", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		h := newLogCaptureHandler(&stubStore{vulnErr: errors.New("db down")}, &logs)
		req := withCorrelationID(httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash", nil), "corr-package-detail")
		req.SetPathValue("ecosystem", "npm")
		req.SetPathValue("rest", "lodash")
		rr := httptest.NewRecorder()

		h.HandlePackageDetail(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
		requireLogField(t, &logs, "correlation_id", "corr-package-detail")
	})

	t.Run("refresh budget error", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		store := &stubStore{packageCheckStatusErr: errors.New("status down")}
		h := newLogCaptureHandler(store, &logs)
		h.ConfigureReversingLabs(config.FeedsConfig{
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
			SocketAPIKey:  "socket-token",
		})
		req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", strings.NewReader(`{}`)), "corr-refresh")
		rr := httptest.NewRecorder()

		h.handleRefresh(rr, req, "npm", "lodash")

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
		requireLogField(t, &logs, "correlation_id", "corr-refresh")
	})

	t.Run("sync export error", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		store := &syncExportStore{err: errors.New("export down")}
		h := newLogCaptureHandler(store, &logs)
		req := withCorrelationID(httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil), "corr-sync")
		rr := httptest.NewRecorder()

		h.HandleSync(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
		requireLogField(t, &logs, "correlation_id", "corr-sync")
	})
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

	middleware.Correlation(http.HandlerFunc(h.HandleCheck)).ServeHTTP(rr, req)

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
	if result.BlockThreshold != domain.SeverityCritical {
		t.Fatalf("block_threshold = %q, want %q", result.BlockThreshold, domain.SeverityCritical)
	}
	if result.Findings[0].AdvisoryID != "CVE-2021-23337" {
		t.Fatalf("findings[0].advisory_id = %q, want %q", result.Findings[0].AdvisoryID, "CVE-2021-23337")
	}

	// Verify response headers.
	if rr.Header().Get(correlation.Header) == "" {
		t.Fatal("X-Correlation-ID header must be set")
	}
	if rr.Header().Get("X-Scan-Duration-Ms") == "" {
		t.Fatal("X-Scan-Duration-Ms header must be set")
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleCheck_IdempotencyKeyReusesScanIDAndScanLog(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	body := `{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`
	key := "ci-job-123"

	firstReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	firstReq.Header.Set("Content-Type", "application/json")
	firstReq.Header.Set(idempotencyKeyHeader, key)
	firstRR := httptest.NewRecorder()
	h.HandleCheck(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200: %s", firstRR.Code, firstRR.Body.String())
	}

	var first domain.ScanResult
	if err := json.Unmarshal(firstRR.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	if first.ScanID == "" {
		t.Fatal("first scan_id is empty")
	}
	if got := firstRR.Header().Get(idempotencyKeyHeader); got != key {
		t.Fatalf("first %s header = %q, want %q", idempotencyKeyHeader, got, key)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set(idempotencyKeyHeader, key)
	secondRR := httptest.NewRecorder()
	h.HandleCheck(secondRR, secondReq)
	if secondRR.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200: %s", secondRR.Code, secondRR.Body.String())
	}

	var second domain.ScanResult
	if err := json.Unmarshal(secondRR.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if second.ScanID != first.ScanID {
		t.Fatalf("second scan_id = %q, want first scan_id %q", second.ScanID, first.ScanID)
	}
	if got := secondRR.Header().Get(idempotencyKeyHeader); got != key {
		t.Fatalf("second %s header = %q, want %q", idempotencyKeyHeader, got, key)
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
	entry := store.scanLogEntries[0]
	if entry.ScanID != first.ScanID {
		t.Fatalf("scan log scan_id = %q, want %q", entry.ScanID, first.ScanID)
	}
	if entry.IdempotencyKey != key {
		t.Fatalf("scan log idempotency key = %q, want %q", entry.IdempotencyKey, key)
	}
	if !strings.HasPrefix(entry.RequestDigest, "sha256:") {
		t.Fatalf("scan log request digest = %q, want sha256 digest", entry.RequestDigest)
	}
}

func TestHandleCheck_IdempotencyKeyRejectsDifferentRequest(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	key := "ci-job-456"

	firstReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(
		`{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`,
	))
	firstReq.Header.Set("Content-Type", "application/json")
	firstReq.Header.Set(idempotencyKeyHeader, key)
	firstRR := httptest.NewRecorder()
	h.HandleCheck(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200: %s", firstRR.Code, firstRR.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(
		`{"packages":[{"name":"is-odd","version":"3.0.1","ecosystem":"npm"}]}`,
	))
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set(idempotencyKeyHeader, key)
	secondRR := httptest.NewRecorder()
	h.HandleCheck(secondRR, secondReq)
	if secondRR.Code != http.StatusConflict {
		t.Fatalf("second status = %d, want 409: %s", secondRR.Code, secondRR.Body.String())
	}
	if !strings.Contains(secondRR.Body.String(), "idempotency key") {
		t.Fatalf("second response body = %q, want idempotency error", secondRR.Body.String())
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
}

func TestHandleCheck_IdempotencyKeyRejectsPostInsertConflict(t *testing.T) {
	t.Parallel()

	store := &postInsertConflictStore{stubStore: &stubStore{}}
	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(
		`{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(idempotencyKeyHeader, "ci-race-1")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "idempotency key") {
		t.Fatalf("response body = %q, want idempotency error", rr.Body.String())
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log insert attempts = %d, want 1", len(store.scanLogEntries))
	}
	if store.lookups != 2 {
		t.Fatalf("idempotency lookups = %d, want 2", store.lookups)
	}
}

func TestHandleCheck_InvalidIdempotencyKey(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(
		`{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`,
	))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(idempotencyKeyHeader, "bad key")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "idempotency key") {
		t.Fatalf("response body = %q, want idempotency error", rr.Body.String())
	}
	if len(store.scanLogEntries) != 0 {
		t.Fatalf("scan log entries = %d, want 0", len(store.scanLogEntries))
	}
}

func TestHandleCheck_DeduplicatesNormalizedPackageCoordinates(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)

	body := `{"packages":[` +
		`{"name":" My.Pkg_Name ","version":" 1.0.0 ","ecosystem":"PyPI"},` +
		`{"name":"my-pkg-name","version":"1.0.0","ecosystem":"pypi"},` +
		`{"name":"left-pad","version":"2.0.0","ecosystem":"npm"}` +
		`]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	middleware.Correlation(http.HandlerFunc(h.HandleCheck)).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var result domain.ScanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.PackagesScanned != 2 {
		t.Fatalf("packages_scanned = %d, want unique package count 2", result.PackagesScanned)
	}

	wantQueries := []db.PackageQuery{
		{Ecosystem: "pypi", Name: "my-pkg-name", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"},
	}
	if got := store.vulnerabilityQueriesSnapshot(); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("vulnerability queries = %#v, want %#v", got, wantQueries)
	}
	if got := store.maliciousQueriesSnapshot(); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("malicious queries = %#v, want %#v", got, wantQueries)
	}
	if got := store.lifecycleQueriesSnapshot(); !reflect.DeepEqual(got, wantQueries) {
		t.Fatalf("lifecycle queries = %#v, want %#v", got, wantQueries)
	}
}

func TestHandleCheck_CountsManualAdvisoryFindings(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnBatchFindings: []domain.Finding{
			{
				Name:      "left-pad",
				Version:   "1.0.0",
				Ecosystem: domain.EcosystemNPM,
				Type:      domain.FindingTypeVulnerability,
				Severity:  domain.SeverityHigh,
				Source:    "manual",
			},
			{
				Name:      "left-pad",
				Version:   "1.0.0",
				Ecosystem: domain.EcosystemNPM,
				Type:      domain.FindingTypeVulnerability,
				Severity:  domain.SeverityHigh,
				Source:    "osv",
			},
		},
		malBatchFindings: []domain.Finding{
			{
				Name:      "evil",
				Version:   "1.0.0",
				Ecosystem: domain.EcosystemNPM,
				Type:      domain.FindingTypeMalicious,
				Severity:  domain.SeverityCritical,
				Source:    "manual",
			},
		},
	}
	h := newTestHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(
		`{"packages":[{"name":"left-pad","version":"1.0.0","ecosystem":"npm"}]}`,
	))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var result domain.ScanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.ManualCount != 2 {
		t.Fatalf("manual_advisories_count = %d, want 2", result.ManualCount)
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
	if result.BlockThreshold != domain.SeverityMedium {
		t.Fatalf("block_threshold = %q, want %q", result.BlockThreshold, domain.SeverityMedium)
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
		ReversingLabsAPIKey:    "rl-token",
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
		ReversingLabsAPIKey:    "rl-token",
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
	upserted := waitForUpsertedReputations(t, store, 1)
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
		ReversingLabsAPIKey:  "rl-token",
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

func TestCollectFindingsDoesNotScheduleReversingLabsAfterBackgroundContextCanceled(t *testing.T) {
	t.Parallel()

	started := make(chan struct{}, 1)
	store := &stubStore{
		markReputationQueued:  true,
		markReputationStarted: started,
	}
	h := newTestHandler(store)
	rootCtx, cancel := context.WithCancel(context.Background())
	cancel()
	h.ConfigureBackgroundContext(rootCtx)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
		ReversingLabsAPIKey:  "rl-token",
	})

	_, err := h.collectFindings(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	})
	if err != nil {
		t.Fatalf("collectFindings() error = %v", err)
	}

	select {
	case <-started:
		t.Fatal("ReversingLabs scheduling started after background context cancellation")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestCollectFindingsQueriesCacheButDoesNotScheduleReversingLabsWithoutWorkerKey(t *testing.T) {
	t.Parallel()

	store := &stubStore{markReputationQueued: true}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
	})

	_, err := h.collectFindings(context.Background(), []domain.Package{
		{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM},
	})
	if err != nil {
		t.Fatalf("collectFindings() error = %v", err)
	}

	if got := len(store.reputationQueries); got != 1 {
		t.Fatalf("reputation queries = %d, want 1 cached lookup without ReversingLabs worker key", got)
	}
	if got := len(store.enqueuedRefreshJobsSnapshot()); got != 0 {
		t.Fatalf("refresh jobs = %d, want 0 without ReversingLabs worker key", got)
	}
	if got := len(store.markedReputationsSnapshot()); got != 0 {
		t.Fatalf("marked reputations = %d, want 0 without ReversingLabs worker key", got)
	}
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
	req = req.WithContext(middleware.ContextWithAPIKeyIdentity(req.Context(), middleware.APIKeyIdentity{
		ID:   42,
		Name: "ci-scanner",
	}))
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
	if entry.RepoName != "packmon" {
		t.Fatalf("scan log repo name = %q, want packmon", entry.RepoName)
	}
	if entry.Branch != "" || entry.Commit != "" || entry.UserAgent != "" {
		t.Fatalf("scan log minimized metadata = branch %q commit %q user agent %q, want empty", entry.Branch, entry.Commit, entry.UserAgent)
	}
	if entry.APIKeyID != 42 || entry.APIKeyName != "ci-scanner" {
		t.Fatalf("scan log API key identity = (%d,%q), want (42,ci-scanner)", entry.APIKeyID, entry.APIKeyName)
	}
}

func TestHandleCheck_BoundsScanLogMetadata(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC())},
		},
	}
	h := newTestHandler(store)

	body := `{
		"repo":{
			"name":"C:\\Users\\Admin\\workspace\\` + strings.Repeat("repo", 120) + `",
			"branch":"feature/` + strings.Repeat("branch", 120) + `",
			"commit":"` + strings.Repeat("abcdef", 40) + `"
		},
		"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "packmon-cli/test Authorization: Bearer super-secret-token "+strings.Repeat("x", 400))
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
	entry := store.scanLogEntries[0]
	for label, value := range map[string]string{
		"user_agent": entry.UserAgent,
		"repo":       entry.RepoName,
		"branch":     entry.Branch,
		"commit":     entry.Commit,
	} {
		if strings.Contains(value, "super-secret-token") || strings.Contains(value, strings.Repeat("x", 300)) {
			t.Fatalf("%s was not sanitized: %q", label, value)
		}
	}
	if entry.UserAgent != "" || entry.Branch != "" || entry.Commit != "" {
		t.Fatalf("scan log minimized metadata = user agent %q branch %q commit %q, want empty", entry.UserAgent, entry.Branch, entry.Commit)
	}
	if len(entry.RepoName) > 256 {
		t.Fatalf("scan log repo metadata length = %d, want bounded", len(entry.RepoName))
	}
	if strings.Contains(entry.RepoName, `\`) || strings.Contains(entry.RepoName, "Users") || strings.Contains(entry.RepoName, "workspace") {
		t.Fatalf("scan log repo name = %q, want basename-only value without local path components", entry.RepoName)
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

func TestHandleCheck_MaxPackagesAtDocumentedCoordinateLengths(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	packages := make([]domain.Package, maxPackagesPerCheck)
	for i := range packages {
		packages[i] = domain.Package{
			Name:      strings.Repeat("a", 512),
			Version:   strings.Repeat("1", 256),
			Ecosystem: domain.EcosystemNPM,
		}
	}
	bodyBytes, err := json.Marshal(domain.ScanRequest{Packages: packages})
	if err != nil {
		t.Fatalf("marshal max-size check request: %v", err)
	}
	if len(bodyBytes) <= 1<<20 {
		t.Fatalf("test request body is %d bytes, want larger than the old 1 MiB cap", len(bodyBytes))
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected max package-count request to reach scan handling, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCheck_InvalidPackageFields(t *testing.T) {
	t.Parallel()

	h := NewHandlerWithBlockThreshold(&stubStore{}, slog.Default(), defaultBlockThreshold)
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
			name: "invalid version with requirement options",
			body: `{"packages":[{"ecosystem":"pypi","name":"requests","version":"2.31.0 --hash=sha256:abc"}]}`,
			want: "packages[1].version is invalid",
		},
		{
			name: "name too long",
			body: `{"packages":[{"ecosystem":"npm","name":"` + strings.Repeat("a", 513) + `","version":"1.0.0"}]}`,
			want: "packages[1].name exceeds 512 characters",
		},
		{
			name: "version too long",
			body: `{"packages":[{"ecosystem":"npm","name":"left-pad","version":"` + strings.Repeat("1", 257) + `"}]}`,
			want: "packages[1].version exceeds 256 characters",
		},
		{
			name: "invalid ecosystem",
			body: `{"packages":[{"ecosystem":"unknown","name":"left-pad","version":"1.0.0"}]}`,
			want: "packages[1].ecosystem is invalid",
		},
		{
			name: "docker ecosystem is not a scan ecosystem",
			body: `{"packages":[{"ecosystem":"docker","name":"alpine","version":"3.20"}]}`,
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

func TestHandleCheck_SanitizesJSONDecodeErrors(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	longField := strings.Repeat("secret-field-name-", 200)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(`{"`+longField+`":"value"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for invalid JSON, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, longField) {
		t.Fatalf("error response leaked raw unknown field name: %q", body)
	}
	if !strings.Contains(body, "unknown field") {
		t.Fatalf("error response = %q, want sanitized unknown-field category", body)
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
// domain.BuildScanSummary tests
// ---------------------------------------------------------------------------

func TestBuildSummary(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{Severity: domain.SeverityCritical, Type: domain.FindingTypeVulnerability, Source: "osv"},
		{Severity: domain.SeverityHigh, Type: domain.FindingTypeVulnerability, Source: "osv"},
		{Severity: domain.SeverityHigh, Type: domain.FindingTypeVulnerability, Source: "ghsa"},
		{Severity: domain.SeverityCritical, Type: domain.FindingTypeMalicious, Source: "openssf"},
	}

	summary := domain.BuildScanSummary(findings)

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

	summary := domain.BuildScanSummary(nil)

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
	if !domain.FindingsBlock(findings, domain.SeverityCritical) {
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

	if !domain.FindingsBlock(findings, domain.SeverityCritical) {
		t.Fatal("CRITICAL vuln should block with CRITICAL threshold")
	}
	if !domain.FindingsBlock(findings, domain.SeverityHigh) {
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

	if domain.FindingsBlock(findings, domain.SeverityCritical) {
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

	if domain.FindingsBlock(findings, domain.SeverityNone) {
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

	if !domain.FindingsBlock(findings, domain.SeverityNone) {
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

	if !domain.FindingsBlock(findings, domain.SeverityMedium) {
		t.Fatal("MEDIUM lifecycle finding should block at MEDIUM threshold")
	}
	if domain.FindingsBlock(findings, domain.SeverityHigh) {
		t.Fatal("MEDIUM lifecycle finding should not block at HIGH threshold")
	}
}

func TestIsBlocking_NoFindings(t *testing.T) {
	t.Parallel()

	if domain.FindingsBlock(nil, domain.SeverityCritical) {
		t.Fatal("no findings should never block")
	}
	if domain.FindingsBlock([]domain.Finding{}, domain.SeverityLow) {
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
	if domain.FindingsBlock(findings, domain.SeverityCritical) {
		t.Fatal("LOW+MEDIUM findings should not block with CRITICAL threshold")
	}

	// With MEDIUM threshold, the MEDIUM finding should block.
	if !domain.FindingsBlock(findings, domain.SeverityMedium) {
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
		vulnBatchFindings: []domain.Finding{
			{
				Name:       "express",
				Version:    "4.18.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "CVE-2026-0001",
				Source:     "manual",
			},
		},
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-1 * time.Hour)), EntriesSynced: 1, EntriesTotal: 1},
		},
	}

	h := newTestHandler(store)

	body := `{"packages":[{"name":"express","version":"4.18.0","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(correlation.Header, "11111111-2222-4333-8444-555555555555")
	rr := httptest.NewRecorder()

	middleware.Correlation(http.HandlerFunc(h.HandleCheck)).ServeHTTP(rr, req)

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
	if !entry.FindingsBlocking {
		t.Fatal("scan log findings_blocking = false, want true")
	}
	if entry.BlockThreshold != string(domain.SeverityCritical) {
		t.Fatalf("scan log block_threshold = %q, want CRITICAL", entry.BlockThreshold)
	}
	if entry.FeedStatus != "healthy" {
		t.Fatalf("scan log feed_status = %q, want healthy", entry.FeedStatus)
	}
	if got := entry.FeedVersions["osv"]; got == "" {
		t.Fatalf("scan log feed_versions[osv] is empty: %#v", entry.FeedVersions)
	}
	if !reflect.DeepEqual(entry.FindingIDs, []string{"CVE-2026-0001"}) {
		t.Fatalf("scan log finding_ids = %#v", entry.FindingIDs)
	}
	if !reflect.DeepEqual(entry.FindingSeverities, []string{"CRITICAL"}) {
		t.Fatalf("scan log finding_severities = %#v", entry.FindingSeverities)
	}
	if entry.ManualAdvisoriesCount != 1 {
		t.Fatalf("scan log manual_advisories_count = %d, want 1", entry.ManualAdvisoriesCount)
	}
	if entry.CorrelationID != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("scan log correlation_id = %q, want request correlation ID", entry.CorrelationID)
	}
	responseDigest := sha256.Sum256(rr.Body.Bytes())
	if want := fmt.Sprintf("sha256:%x", responseDigest[:]); entry.ResultDigest != want {
		t.Fatalf("scan log result_digest = %q, want %q", entry.ResultDigest, want)
	}
}

func TestHandleCheckBoundsScanLogInsertBeforeFailingClosed(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		scanLogErr: errors.New("scan log unavailable"),
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC()), EntriesSynced: 1, EntriesTotal: 1},
		},
	}
	h := newTestHandler(store)

	body := `{"packages":[{"name":"express","version":"4.18.0","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "internal error while recording scan") {
		t.Fatalf("body = %q, want scan-log failure message", rr.Body.String())
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log insert attempts = %d, want 1", len(store.scanLogEntries))
	}
	if !store.scanLogDeadlineSet {
		t.Fatal("scan log insert did not receive a deadline")
	}
	if remaining := store.scanLogDeadline.Sub(store.scanLogObservedAt); remaining <= 0 || remaining > time.Second {
		t.Fatalf("scan log deadline remaining = %s, want short positive deadline", remaining)
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
			name: "running feed with stale cached data degrades despite fresh heartbeat",
			statuses: []db.FeedSyncStatus{
				{FeedName: "nvd", LastSyncStatus: "running", LastSyncAt: ptrFeedTime(now.Add(-72 * time.Hour)), UpdatedAt: now, EntriesSynced: 70, EntriesTotal: 96},
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

func TestHandlePackageDetailUsesVersionedReputationLookupWhenVersionPresent(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		reputationPackage: []domain.Finding{
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
		reputationFindings: []domain.Finding{
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
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/left-pad?version=2.0.0", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "left-pad")
	rr := httptest.NewRecorder()

	h.HandlePackageDetail(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.reputationQueries) != 1 {
		t.Fatalf("reputation batch queries = %d, want 1", len(store.reputationQueries))
	}
	query := store.reputationQueries[0]
	if query.source != db.ReputationSourceReversingLabs {
		t.Fatalf("reputation source = %q, want %q", query.source, db.ReputationSourceReversingLabs)
	}
	if len(query.packages) != 1 || query.packages[0] != (db.PackageQuery{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"}) {
		t.Fatalf("reputation packages = %+v, want npm/left-pad@2.0.0", query.packages)
	}
	var resp PackageDetailResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(resp.Findings))
	}
	if resp.Findings[0].Title != "version-specific reputation" || resp.Findings[0].Version != "2.0.0" {
		t.Fatalf("finding = %+v, want version-specific reputation", resp.Findings[0])
	}
	if len(store.reputationPackages) != 0 {
		t.Fatalf("unversioned reputation queries = %+v, want none", store.reputationPackages)
	}
}

func TestHandlePackageDetailIncludesLifecycleFindingsForVersion(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		lifecycleFindings: []domain.Finding{
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
	h := newTestHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/pypi/django?version=3.2.25", nil)
	req.SetPathValue("ecosystem", "pypi")
	req.SetPathValue("rest", "django")
	rr := httptest.NewRecorder()

	h.HandlePackageDetail(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp PackageDetailResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].Type != domain.FindingTypeLifecycle {
		t.Fatalf("findings = %+v, want one lifecycle finding", resp.Findings)
	}
	if len(store.lifecycleQueries) != 1 {
		t.Fatalf("lifecycle queries = %d, want 1", len(store.lifecycleQueries))
	}
	if got := store.lifecycleQueries[0]; got.Ecosystem != "pypi" || got.Name != "django" || got.Version != "3.2.25" {
		t.Fatalf("lifecycle query = %+v, want pypi/django@3.2.25", got)
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
			{FeedName: "socket", LastSyncStatus: "permanent_error", LastSyncAt: ptrFeedTime(now.Add(-10 * time.Minute)), EntriesTotal: 4, LastError: "Socket.dev API key not configured"},
			{FeedName: "nvd", LastSyncStatus: "failed", LastSyncAt: ptrFeedTime(now.Add(-5 * time.Minute)), EntriesTotal: 7, LastError: "unexpected imported status"},
			{FeedName: "external-ghsa", LastSyncStatus: "external", LastSyncAt: ptrFeedTime(now.Add(-3 * time.Minute))},
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
	if len(resp.Feeds) != 6 {
		t.Fatalf("feeds = %d, want 6", len(resp.Feeds))
	}
	want := map[string]struct {
		status  string
		message string
	}{
		"osv":           {status: "healthy"},
		"vulncheck":     {status: "warning", message: "api key not configured"},
		"ghsa":          {status: "error", message: "clone failed"},
		"socket":        {status: "error", message: "Socket.dev API key not configured"},
		"nvd":           {status: "error", message: "unexpected imported status"},
		"external-ghsa": {status: "configured"},
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

func TestOverallFeedStatusTreatsExternalFeedsAsConfigured(t *testing.T) {
	t.Parallel()

	statuses := []db.FeedSyncStatus{{FeedName: "ghsa", LastSyncStatus: "external"}}
	if got := overallFeedStatus(statuses); got != "healthy" {
		t.Fatalf("overallFeedStatus(external only) = %q, want healthy", got)
	}
	if got := feedHealthStatus(statuses[0]); got != "configured" {
		t.Fatalf("feedHealthStatus(external) = %q, want configured", got)
	}
}

func TestHandleFeedStatusEmptyRowsReportsDegraded(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{feedStatuses: []db.FeedSyncStatus{}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/status", nil)
	rr := httptest.NewRecorder()
	h.HandleFeedStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp FeedStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "degraded" || resp.Message == "" {
		t.Fatalf("feed status response = %+v, want degraded message for empty status rows", resp)
	}
	if len(resp.Feeds) != 0 {
		t.Fatalf("feeds = %+v, want empty feed list", resp.Feeds)
	}
}

func TestHandleFeedStatusRedactsDiagnosticMessages(t *testing.T) {
	t.Parallel()

	lastError := `GET https://user-secret:pass-secret@downloads.example.test/backups/feed.tar.gz?X-Amz-Signature=query-secret failed with Authorization: Bearer bearer-secret-token from C:\Users\Admin\Packmon\feed.json` //nolint:gosec // fake secret-bearing diagnostic verifies redaction.
	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{
				FeedName:       "vulncheck",
				LastSyncStatus: "error",
				LastError:      lastError,
			},
		},
	}
	h := newTestHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feeds/status", nil)
	rr := httptest.NewRecorder()
	h.HandleFeedStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp FeedStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Feeds) != 1 {
		t.Fatalf("feeds = %d, want 1", len(resp.Feeds))
	}
	message := resp.Feeds[0].Message
	for _, leaked := range []string{"user-secret", "pass-secret", "feed.tar.gz", "query-secret", "bearer-secret-token", `C:\Users\Admin\Packmon\feed.json`} {
		if strings.Contains(message, leaked) {
			t.Fatalf("feed status message leaked %q in %q", leaked, message)
		}
	}
	if !strings.Contains(message, "https://downloads.example.test/...") || !strings.Contains(message, "Bearer [redacted]") {
		t.Fatalf("feed status message missing redacted context: %q", message)
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
			"affected_packages":[
				{"ecosystem":"npm","name":"left-pad","version_ranges":[],"versions_affected":[]},
				{"ecosystem":"NuGet","name":" Newtonsoft.Json ","version_ranges":[],"versions_affected":[]}
			]
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
	if len(vuln.AffectedPackages) != 2 || vuln.AffectedPackages[1].Ecosystem != "nuget" || vuln.AffectedPackages[1].Name != "newtonsoft.json" {
		t.Fatalf("affected packages = %+v, want normalized NuGet package", vuln.AffectedPackages)
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

func TestHandleFeedImportRejectsManualNamespaceMutations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		feed string
		body string
	}{
		{
			name: "vulnerability import manual id",
			feed: "osv",
			body: `{"vulnerabilities":[{"id":"manual:owned","summary":"bad"}]}`,
		},
		{
			name: "vulnerability delete manual id",
			feed: "osv",
			body: `{"delete_vulnerability_ids":["manual:owned"]}`,
		},
		{
			name: "malicious import manual id",
			feed: "openssf",
			body: `{"malicious":[{"id":"manual:owned","ecosystem":"npm","name":"evil"}]}`,
		},
		{
			name: "malicious delete manual id",
			feed: "socket",
			body: `{"delete_malicious_ids":["manual:owned"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &stubStore{}
			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleFeedImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.upsertedVulns) != 0 || len(store.upsertedMalicious) != 0 || len(store.deletedVulnIDs) != 0 || len(store.deletedMaliciousIDs) != 0 || len(store.deletedMaliciousScoped) != 0 {
				t.Fatalf("store mutated despite rejected manual namespace: vulns=%+v malicious=%+v delV=%+v delM=%+v delScoped=%+v",
					store.upsertedVulns,
					store.upsertedMalicious,
					store.deletedVulnIDs,
					store.deletedMaliciousIDs,
					store.deletedMaliciousScoped,
				)
			}
		})
	}
}

func TestHandleFeedImportForcesImportedSourcesToRouteFeed(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	body := `{
		"vulnerabilities":[{
			"id":"GHSA-feed-owned",
			"summary":"source must be forced",
			"sources":[{"source":"manual","source_id":"manual:owned"}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(body))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedVulns) != 1 || len(store.upsertedVulns[0].Sources) != 1 {
		t.Fatalf("upserted vulnerabilities = %+v", store.upsertedVulns)
	}
	source := store.upsertedVulns[0].Sources[0]
	if source.Source != "osv" || source.SourceID != "GHSA-feed-owned" {
		t.Fatalf("forced source = %+v, want osv/GHSA-feed-owned", source)
	}

	store = &stubStore{}
	h = newTestHandler(store)
	body = `{"malicious":[{"id":"MAL-feed-owned","ecosystem":"npm","name":"evil","source":"manual"}]}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(body))
	req.SetPathValue("feed", "socket")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()

	h.HandleFeedImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("malicious status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedMalicious) != 1 || store.upsertedMalicious[0].Source != "socket" {
		t.Fatalf("malicious source = %+v, want forced socket", store.upsertedMalicious)
	}
}

func TestHandleFeedImportWritesAuditEntry(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	body := `{
		"malicious":[{"id":"MAL-audit","ecosystem":"npm","name":"evil","severity":"HIGH"}],
		"delete_malicious_ids":["MAL-old"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(body))
	req.SetPathValue("feed", "socket")
	req.RemoteAddr = "203.0.113.10:49152"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.HeaderCorrelationID, "12345678-1234-4234-9234-123456789abc")
	req = req.WithContext(middleware.ContextWithAPIKeyIdentity(req.Context(), middleware.APIKeyIdentity{
		ID:   77,
		Name: "n8n-import",
	}))
	rr := httptest.NewRecorder()
	handler := middleware.Correlation(http.HandlerFunc(h.HandleFeedImport))

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(store.auditEntries))
	}
	entry := store.auditEntries[0]
	if entry.Action != "feed_import" {
		t.Fatalf("audit action = %q, want feed_import", entry.Action)
	}
	if entry.IP != "203.0.113.10" {
		t.Fatalf("audit IP = %q, want remote client IP", entry.IP)
	}
	var details map[string]any
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("decode audit details: %v", err)
	}
	want := map[string]any{
		"feed":           "socket",
		"imported":       float64(1),
		"deleted":        float64(1),
		"entries_total":  float64(2),
		"client_ip":      "203.0.113.10",
		"correlation_id": "12345678-1234-4234-9234-123456789abc",
		"api_key_id":     float64(77),
		"api_key_name":   "n8n-import",
	}
	for key, wantValue := range want {
		if got := details[key]; got != wantValue {
			t.Fatalf("audit detail %s = %#v, want %#v (all details: %#v)", key, got, wantValue, details)
		}
	}
}

type atomicImportTestStore struct {
	stubStore
	vulnerabilityCalls   int
	maliciousCalls       int
	vulnerabilityFeed    string
	maliciousFeed        string
	vulnerabilityIDs     []string
	maliciousIDs         []string
	vulnerabilityDeletes []string
	maliciousDeletes     []string
	vulnerabilityStatus  *db.FeedSyncStatus
	maliciousStatus      *db.FeedSyncStatus
}

func (s *atomicImportTestStore) ImportVulnerabilityFeed(_ context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	s.vulnerabilityCalls++
	s.vulnerabilityFeed = feed
	for _, item := range items {
		s.vulnerabilityIDs = append(s.vulnerabilityIDs, item.ID)
	}
	s.vulnerabilityDeletes = append(s.vulnerabilityDeletes, deleteIDs...)
	if status != nil {
		copyValue := *status
		s.vulnerabilityStatus = &copyValue
	}
	return len(items), len(deleteIDs), nil
}

func (s *atomicImportTestStore) ImportMaliciousFeed(_ context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	s.maliciousCalls++
	s.maliciousFeed = feed
	for _, item := range items {
		s.maliciousIDs = append(s.maliciousIDs, item.ID)
	}
	s.maliciousDeletes = append(s.maliciousDeletes, deleteIDs...)
	if status != nil {
		copyValue := *status
		s.maliciousStatus = &copyValue
	}
	return len(items), len(deleteIDs), nil
}

func TestHandleFeedImportUsesAtomicStoreForVulnerabilityAndMaliciousImports(t *testing.T) {
	t.Parallel()

	store := &atomicImportTestStore{}
	h := newTestHandler(store)

	vulnBody := `{
		"vulnerabilities":[{"id":"GHSA-atomic-0001","summary":"atomic","severity":"HIGH","affected_packages":[{"ecosystem":"npm","name":"pkg"}]}],
		"delete_vulnerability_ids":["GHSA-old-0001"],
		"status":{"last_sync_status":"success"}
	}`
	vulnReq := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(vulnBody))
	vulnReq.SetPathValue("feed", "osv")
	vulnReq.Header.Set("Content-Type", "application/json")
	vulnRR := httptest.NewRecorder()

	h.HandleFeedImport(vulnRR, vulnReq)

	if vulnRR.Code != http.StatusOK {
		t.Fatalf("vulnerability status = %d, want 200: %s", vulnRR.Code, vulnRR.Body.String())
	}
	if store.vulnerabilityCalls != 1 || store.vulnerabilityFeed != "osv" {
		t.Fatalf("vulnerability atomic calls/feed = %d/%q, want 1/osv", store.vulnerabilityCalls, store.vulnerabilityFeed)
	}
	if !reflect.DeepEqual(store.vulnerabilityIDs, []string{"GHSA-atomic-0001"}) || !reflect.DeepEqual(store.vulnerabilityDeletes, []string{"GHSA-old-0001"}) {
		t.Fatalf("vulnerability atomic ids/deletes = %+v/%+v", store.vulnerabilityIDs, store.vulnerabilityDeletes)
	}
	if len(store.upsertedVulns) != 0 || len(store.deletedVulnIDs) != 0 || len(store.upsertedStatuses) != 0 {
		t.Fatalf("vulnerability fallback mutated store: upserts=%+v deletes=%+v statuses=%+v", store.upsertedVulns, store.deletedVulnIDs, store.upsertedStatuses)
	}
	if store.vulnerabilityStatus == nil || store.vulnerabilityStatus.FeedName != "osv" || store.vulnerabilityStatus.EntriesSynced != 1 || store.vulnerabilityStatus.EntriesTotal != 2 {
		t.Fatalf("vulnerability status = %+v, want osv 1/2", store.vulnerabilityStatus)
	}

	malBody := `{
		"malicious":[{"id":"MAL-atomic","ecosystem":"npm","name":"evil","severity":"HIGH"}],
		"delete_malicious_ids":["MAL-old"],
		"status":{"last_sync_status":"success"}
	}`
	malReq := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(malBody))
	malReq.SetPathValue("feed", "socket")
	malReq.Header.Set("Content-Type", "application/json")
	malRR := httptest.NewRecorder()

	h.HandleFeedImport(malRR, malReq)

	if malRR.Code != http.StatusOK {
		t.Fatalf("malicious status = %d, want 200: %s", malRR.Code, malRR.Body.String())
	}
	if store.maliciousCalls != 1 || store.maliciousFeed != "socket" {
		t.Fatalf("malicious atomic calls/feed = %d/%q, want 1/socket", store.maliciousCalls, store.maliciousFeed)
	}
	if !reflect.DeepEqual(store.maliciousIDs, []string{"MAL-atomic"}) || !reflect.DeepEqual(store.maliciousDeletes, []string{"MAL-old"}) {
		t.Fatalf("malicious atomic ids/deletes = %+v/%+v", store.maliciousIDs, store.maliciousDeletes)
	}
	if len(store.upsertedMalicious) != 0 || len(store.deletedMaliciousScoped) != 0 || len(store.upsertedStatuses) != 0 {
		t.Fatalf("malicious fallback mutated store: upserts=%+v deletes=%+v statuses=%+v", store.upsertedMalicious, store.deletedMaliciousScoped, store.upsertedStatuses)
	}
	if store.maliciousStatus == nil || store.maliciousStatus.FeedName != "socket" || store.maliciousStatus.EntriesSynced != 1 || store.maliciousStatus.EntriesTotal != 2 {
		t.Fatalf("malicious status = %+v, want socket 1/2", store.maliciousStatus)
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
				if resp.Imported != 1 || resp.Deleted != 1 || len(store.cisaKEVIDs) != 1 || len(store.clearedCISAKEVIDs) != 1 {
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
				if resp.Imported != 1 || len(store.epssEntries) != 1 || store.epssEntries[0].Score != 0.91 || store.epssReplaceCalls != 1 {
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
			if tt.feed == "epss" {
				store.epssCleared = 2
			}
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
			if tt.feed == "epss" && resp.Deleted != 2 {
				t.Fatalf("epss Deleted = %d, want 2", resp.Deleted)
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
	h.ConfigureReversingLabs(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash/refresh")
	rr := httptest.NewRecorder()

	h.HandlePackageOrRefresh(rr, req)

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

func TestHandleRefreshRespectsSocketNextCheckBudget(t *testing.T) {
	t.Parallel()

	nextCheck := time.Now().UTC().Add(time.Hour)
	store := &stubStore{
		packageCheckStatus: &db.PackageCheckStatus{
			Ecosystem:   "npm",
			Name:        "lodash",
			Source:      socket.FeedName,
			NextCheckAt: &nextCheck,
		},
	}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil)
	rr := httptest.NewRecorder()

	h.handleRefresh(rr, req, "npm", "lodash")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.enqueuedRefreshJobsSnapshot()) != 0 {
		t.Fatalf("enqueued jobs = %+v, want none inside next-check budget", store.enqueuedRefreshJobsSnapshot())
	}
	if len(store.packageCheckStatusLookups) != 1 || store.packageCheckStatusLookups[0].source != socket.FeedName {
		t.Fatalf("package check lookups = %+v, want one Socket lookup", store.packageCheckStatusLookups)
	}
	var resp RefreshResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Queued || resp.New || resp.Position != 0 || !strings.Contains(resp.Message, "next check") {
		t.Fatalf("refresh response = %+v, want skipped by next-check budget", resp)
	}
}

func TestHandleRefreshRejectsLongPackageNameBeforeEnqueue(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	name := strings.Repeat("a", maxCheckPackageNameLength+1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/"+name+"/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", name+"/refresh")
	rr := httptest.NewRecorder()

	h.HandlePackageOrRefresh(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "package name exceeds") {
		t.Fatalf("body = %q, want package length error", rr.Body.String())
	}
	if got := len(store.enqueuedRefreshJobsSnapshot()); got != 0 {
		t.Fatalf("enqueued jobs = %d, want 0", got)
	}
}

func TestHandleRefreshRejectsInactiveOrInvalidQueueTarget(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil)
	rr := httptest.NewRecorder()
	h.handleRefresh(rr, req, "npm", "lodash")
	if rr.Code != http.StatusConflict {
		t.Fatalf("inactive refresh status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if got := len(store.enqueuedRefreshJobs); got != 0 {
		t.Fatalf("enqueued jobs = %d, want 0 without active worker", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/packages/notvalid/lodash/refresh", nil)
	rr = httptest.NewRecorder()
	h.handleRefresh(rr, req, "notvalid", "lodash")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid ecosystem status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if got := len(store.enqueuedRefreshJobs); got != 0 {
		t.Fatalf("enqueued jobs = %d, want 0 after invalid ecosystem", got)
	}
}

func TestHandleRefreshRejectsSocketUnsupportedEcosystemWithoutEnqueue(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})

	tests := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "direct refresh route",
			call: func(w http.ResponseWriter, r *http.Request) {
				h.HandlePackageOrRefresh(w, r)
			},
		},
		{
			name: "package dispatcher route",
			call: func(w http.ResponseWriter, r *http.Request) {
				h.HandlePackageOrRefresh(w, r)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/hex/plug/refresh", nil)
			req.SetPathValue("ecosystem", "hex")
			req.SetPathValue("rest", "plug/refresh")
			rr := httptest.NewRecorder()

			tc.call(rr, req)

			if rr.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "no active refresh worker supports ecosystem: hex") {
				t.Fatalf("body = %q, want unsupported-worker message", rr.Body.String())
			}
			if got := len(store.enqueuedRefreshJobsSnapshot()); got != 0 {
				t.Fatalf("enqueued jobs = %d, want 0", got)
			}
		})
	}
}

func TestHandlePackageOrRefreshRoutesScopedPackageName(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
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

func TestHandleSyncEmitsLifecycleDatesAsDateOnly(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	releaseDate := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	eolFrom := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	store := &syncExportStore{
		export: &db.SyncExport{
			SyncedAt: now,
			Lifecycle: []db.SyncLifecycleRelease{
				{
					ID:           "endoflife:pypi:django:django:5.0",
					Ecosystem:    "pypi",
					Name:         "django",
					ProductSlug:  "django",
					ProductLabel: "Django",
					Cycle:        "5.0",
					Latest:       "5.0.14",
					ReleaseDate:  &releaseDate,
					IsEOL:        true,
					EOLFrom:      &eolFrom,
					IsMaintained: false,
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
		t.Fatalf("sync status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var raw struct {
		Lifecycle []map[string]any `json:"lifecycle"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode sync response: %v", err)
	}
	if len(raw.Lifecycle) != 1 {
		t.Fatalf("lifecycle rows = %d, want 1", len(raw.Lifecycle))
	}
	if got := raw.Lifecycle[0]["release_date"]; got != "2026-06-02" {
		t.Fatalf("release_date = %#v, want date-only string", got)
	}
	if got := raw.Lifecycle[0]["eol_from"]; got != "2026-12-31" {
		t.Fatalf("eol_from = %#v, want date-only string", got)
	}
	if strings.Contains(rr.Body.String(), "T00:00:00") {
		t.Fatalf("sync lifecycle payload contains date-time instant: %s", rr.Body.String())
	}
}

func TestHandleSyncEmitsPerDatasetNextCursor(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	epssScore := 0.42
	epssPercentile := 0.88
	store := &syncExportStore{
		export: &db.SyncExport{
			SyncedAt: now,
			Vulnerabilities: []db.SyncVulnerability{
				{ID: "GHSA-1", Ecosystem: "npm", Name: "a", VersionRanges: "[]", References: `[{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-1"}]`, Severity: "LOW", EPSSScore: &epssScore, EPSSPercentile: &epssPercentile, Source: "manual"},
				{ID: "GHSA-2", Ecosystem: "npm", Name: "b", VersionRanges: "[]", Severity: "LOW"},
			},
			Malicious: []db.SyncMalicious{
				{ID: "MAL-1", Ecosystem: "npm", Name: "evil", ReferenceURLs: `["https://example.test/mal"]`, RiskType: "malware", Severity: "CRITICAL", Source: "manual"},
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
	if resp.Vulnerabilities[0].EPSSPercentile == nil || *resp.Vulnerabilities[0].EPSSPercentile != epssPercentile {
		t.Fatalf("sync response EPSS percentile = %+v, want %v", resp.Vulnerabilities[0].EPSSPercentile, epssPercentile)
	}
	if resp.Vulnerabilities[0].Source != "manual" || resp.Malicious[0].Source != "manual" {
		t.Fatalf("sync response sources = %+v %+v, want manual", resp.Vulnerabilities[0], resp.Malicious[0])
	}
}

func ptrFeedTime(t time.Time) *time.Time {
	return &t
}
