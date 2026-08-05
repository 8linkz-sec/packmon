package v1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/checkcontract"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/feed/reputation"
	"github.com/8linkz-sec/packmon/internal/requestctx"
	"github.com/8linkz-sec/packmon/internal/telemetry"
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
	feedStatusListCalls   int

	// capture InsertScanLog calls
	scanLogEntries           []db.ScanLogEntry
	scanLogInsertCalls       int
	scanLogErr               error
	scanLogDeadline          time.Time
	scanLogObservedAt        time.Time
	scanLogDeadlineSet       bool
	lookupDeadline           time.Time
	lookupObservedAt         time.Time
	lookupDeadlineSet        bool
	lookupContextErr         error
	returnLookupCtxErr       bool
	findVulnerabilitiesCalls int
	findMaliciousCalls       int
	vulnerabilityQueries     []PackageLookup
	maliciousQueries         []PackageLookup
	reputationQueries        []struct {
		packages []PackageLookup
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
	auditErr           error
	cisaKEVIDs         []string
	clearedCISAKEVIDs  []string
	replacedCISAKEVIDs []string
	epssEntries        []db.EPSSEntry
	epssReplaceCalls   int
	epssCleared        int
	vulnCheckEntries   []db.VulnCheckEntry
	reputationPackages []struct {
		ecosystem string
		name      string
		source    string
	}
	lifecycleQueries          []PackageLookup
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
	calls  int
}

type postInsertConflictStore struct {
	*stubStore
	lookups int
}

func (s *postInsertConflictStore) GetScanLogByIdempotencyKey(_ context.Context, key string) (*db.ScanLogEntry, error) {
	s.lookups++
	if s.lookups <= 2 {
		return nil, nil
	}
	return &db.ScanLogEntry{
		ScanID:         "scan-from-other-request",
		IdempotencyKey: key,
		RequestDigest:  "sha256:other-request",
	}, nil
}

func (s *syncExportStore) ExportSync(_ context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	s.mu.Lock()
	s.calls++
	s.opts = opts
	s.mu.Unlock()
	return s.export, s.err
}

func (s *stubStore) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	s.mu.Lock()
	s.findVulnerabilitiesCalls++
	s.mu.Unlock()
	return s.vulnFindings, s.vulnErr
}

func (s *stubStore) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	s.mu.Lock()
	s.findMaliciousCalls++
	s.mu.Unlock()
	return s.malFindings, s.malErr
}

func (s *stubStore) recordLookupContext(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		s.lookupDeadline = deadline
		s.lookupObservedAt = time.Now()
		s.lookupDeadlineSet = true
	}
	s.lookupContextErr = ctx.Err()
	return s.lookupContextErr
}

func (s *stubStore) FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	if err := s.recordLookupContext(ctx); err != nil && s.returnLookupCtxErr {
		return nil, err
	}
	s.mu.Lock()
	s.vulnerabilityQueries = append(s.vulnerabilityQueries, packages...)
	s.mu.Unlock()
	return s.vulnBatchFindings, s.vulnBatchErr
}

func (s *stubStore) FindMaliciousBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	if err := s.recordLookupContext(ctx); err != nil && s.returnLookupCtxErr {
		return nil, err
	}
	s.mu.Lock()
	s.maliciousQueries = append(s.maliciousQueries, packages...)
	s.mu.Unlock()
	return s.malBatchFindings, s.malBatchErr
}

func (s *stubStore) FindReputationFindingsBatch(ctx context.Context, packages []PackageLookup, source string) ([]domain.Finding, error) {
	if err := s.recordLookupContext(ctx); err != nil && s.returnLookupCtxErr {
		return nil, err
	}
	copied := append([]PackageLookup(nil), packages...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reputationQueries = append(s.reputationQueries, struct {
		packages []PackageLookup
		source   string
	}{packages: copied, source: source})
	return s.reputationFindings, s.reputationErr
}

func (s *stubStore) FindLifecycleFindingsBatch(ctx context.Context, packages []PackageLookup, _ time.Time) ([]domain.Finding, error) {
	if err := s.recordLookupContext(ctx); err != nil && s.returnLookupCtxErr {
		return nil, err
	}
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

func (s *stubStore) ReplaceCISAKEV(_ context.Context, ids []string) (int, int, error) {
	s.replacedCISAKEVIDs = append(s.replacedCISAKEVIDs, ids...)
	return len(ids), len(ids), nil
}

func (s *stubStore) ReplaceCISAKEVWithAudit(ctx context.Context, _ string, ids []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	s.replacedCISAKEVIDs = append(s.replacedCISAKEVIDs, ids...)
	if status != nil {
		if err := s.UpsertFeedSyncStatus(ctx, status); err != nil {
			return 0, 0, err
		}
	}
	cleared := len(ids)
	if audit != nil {
		if err := s.InsertAdminAuditLog(ctx, ptr(audit(len(ids), cleared))); err != nil {
			return 0, 0, err
		}
	}
	return len(ids), cleared, nil
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

func (s *stubStore) ImportVulnCheckWithAudit(ctx context.Context, _ string, entries []db.VulnCheckEntry, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, error) {
	s.vulnCheckEntries = append(s.vulnCheckEntries, entries...)
	if status != nil {
		if err := s.UpsertFeedSyncStatus(ctx, status); err != nil {
			return 0, err
		}
	}
	if audit != nil {
		if err := s.InsertAdminAuditLog(ctx, ptr(audit(len(entries), 0))); err != nil {
			return 0, err
		}
	}
	return len(entries), nil
}

func (s *stubStore) ImportCISAKEVWithAudit(ctx context.Context, _ string, ids []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, error) {
	s.cisaKEVIDs = append(s.cisaKEVIDs, ids...)
	if status != nil {
		if err := s.UpsertFeedSyncStatus(ctx, status); err != nil {
			return 0, err
		}
	}
	if audit != nil {
		if err := s.InsertAdminAuditLog(ctx, ptr(audit(len(ids), 0))); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}

func (s *stubStore) ImportEPSSWithAudit(ctx context.Context, _ string, entries []db.EPSSEntry, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	s.epssEntries = append(s.epssEntries, entries...)
	s.epssReplaceCalls++
	if status != nil {
		if err := s.UpsertFeedSyncStatus(ctx, status); err != nil {
			return 0, s.epssCleared, err
		}
	}
	if audit != nil {
		if err := s.InsertAdminAuditLog(ctx, ptr(audit(len(entries), s.epssCleared))); err != nil {
			return 0, s.epssCleared, err
		}
	}
	return len(entries), s.epssCleared, nil
}

func (s *stubStore) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	if status != nil {
		s.upsertedStatuses = append(s.upsertedStatuses, *status)
	}
	return nil
}

func (s *stubStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	s.feedStatusListCalls++
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

func (s *stubStore) EnqueueRefreshWithAudit(ctx context.Context, job *db.RefreshJob, audit db.RefreshEnqueueAuditBuilder) (bool, int, error) {
	if s.auditErr != nil {
		return false, 0, s.auditErr
	}
	created, position, err := s.EnqueueRefresh(ctx, job)
	if err != nil {
		return false, 0, err
	}
	if audit != nil {
		auditEntry := audit(created, position)
		if err := s.InsertAdminAuditLog(ctx, &auditEntry); err != nil {
			return false, 0, err
		}
	}
	return created, position, nil
}

func (s *refreshStore) EnqueueRefreshWithAudit(ctx context.Context, job *db.RefreshJob, audit db.RefreshEnqueueAuditBuilder) (bool, int, error) {
	if s.auditErr != nil {
		return false, 0, s.auditErr
	}
	created, position, err := s.EnqueueRefresh(ctx, job)
	if err != nil {
		return false, 0, err
	}
	if audit != nil {
		auditEntry := audit(created, position)
		if err := s.InsertAdminAuditLog(ctx, &auditEntry); err != nil {
			return false, 0, err
		}
	}
	return created, position, nil
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

func (s *stubStore) vulnerabilityQueriesSnapshot() []PackageLookup {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PackageLookup(nil), s.vulnerabilityQueries...)
}

func (s *stubStore) maliciousQueriesSnapshot() []PackageLookup {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PackageLookup(nil), s.maliciousQueries...)
}

func (s *stubStore) lifecycleQueriesSnapshot() []PackageLookup {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PackageLookup(nil), s.lifecycleQueries...)
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

	s.scanLogInsertCalls++
	if deadline, ok := ctx.Deadline(); ok {
		s.scanLogDeadline = deadline
		s.scanLogObservedAt = time.Now()
		s.scanLogDeadlineSet = true
	}
	if s.scanLogErr != nil {
		return s.scanLogErr
	}
	if entry != nil && entry.IdempotencyKey != "" {
		for _, existing := range s.scanLogEntries {
			if existing.IdempotencyKey == entry.IdempotencyKey {
				return nil
			}
		}
	}
	s.scanLogEntries = append(s.scanLogEntries, *entry)
	return nil
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

func (s *stubStore) ExportSync(context.Context, db.SyncExportOptions) (*db.SyncExport, error) {
	return &db.SyncExport{SyncedAt: time.Now().UTC()}, nil
}

func (s *stubStore) InsertAdminAuditLog(_ context.Context, entry *db.AdminAuditEntry) error {
	if s.auditErr != nil {
		return s.auditErr
	}
	if entry != nil {
		s.auditEntries = append(s.auditEntries, *entry)
	}
	return nil
}

func (s *stubStore) ImportVulnerabilityFeedWithAudit(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	imported := 0
	for i := range items {
		if err := s.UpsertVulnerability(ctx, &items[i]); err != nil {
			return imported, 0, err
		}
		imported++
	}
	deleted := 0
	for _, id := range deleteIDs {
		if err := s.DeleteVulnerability(ctx, id); err != nil {
			return imported, deleted, err
		}
		deleted++
	}
	if status != nil {
		if err := s.UpsertFeedSyncStatus(ctx, status); err != nil {
			return imported, deleted, err
		}
	}
	if audit != nil {
		auditEntry := audit(imported, deleted)
		if err := s.InsertAdminAuditLog(ctx, &auditEntry); err != nil {
			return imported, deleted, err
		}
	}
	_ = feed
	return imported, deleted, nil
}

func (s *stubStore) ImportMaliciousFeedWithAudit(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	imported := 0
	for i := range items {
		if err := s.UpsertMaliciousFinding(ctx, &items[i]); err != nil {
			return imported, 0, err
		}
		imported++
	}
	deleted := 0
	for _, id := range deleteIDs {
		if err := s.DeleteMaliciousFindingForSource(ctx, id, feed); err != nil {
			return imported, deleted, err
		}
		deleted++
	}
	if status != nil {
		if err := s.UpsertFeedSyncStatus(ctx, status); err != nil {
			return imported, deleted, err
		}
	}
	if audit != nil {
		auditEntry := audit(imported, deleted)
		if err := s.InsertAdminAuditLog(ctx, &auditEntry); err != nil {
			return imported, deleted, err
		}
	}
	return imported, deleted, nil
}

type testReputationScheduler struct {
	inner *reputation.Scheduler
}

func newTestReputationScheduler(store Store, logger *slog.Logger) ReputationScheduler {
	schedulerStore, ok := any(store).(reputation.Store)
	if !ok {
		return nil
	}
	return &testReputationScheduler{
		inner: reputation.NewScheduler(schedulerStore, logger, reputation.Config{}),
	}
}

func (s *testReputationScheduler) Configure(cfg ReputationSchedulerConfig) {
	if s == nil || s.inner == nil {
		return
	}
	s.inner.Configure(reputation.Config{
		ReversingLabsActive:              cfg.ReversingLabsActive,
		ReversingLabsMaxSchedulePerCheck: cfg.ReversingLabsMaxSchedulePerCheck,
		ReversingLabsExcludedNamespaces:  cfg.ReversingLabsExcludedNamespaces,
	})
}

func (s *testReputationScheduler) ScheduleReversingLabsAsync(ctx context.Context, packages []domain.Package, findings []domain.Finding) {
	if s == nil || s.inner == nil {
		return
	}
	s.inner.ScheduleReversingLabsAsync(ctx, packages, findings)
}

type testPackageRefreshProvider struct {
	active             bool
	source             string
	excludedNamespaces []string
}

func newTestPackageRefreshProvider() *testPackageRefreshProvider {
	return &testPackageRefreshProvider{source: "socket"}
}

func (p *testPackageRefreshProvider) Configure(cfg PackageRefreshProviderConfig) {
	p.active = cfg.Active
	p.excludedNamespaces = append([]string(nil), cfg.ExcludedNamespaces...)
}

func (p *testPackageRefreshProvider) Active() bool {
	return p != nil && p.active
}

func (p *testPackageRefreshProvider) Source() string {
	if p == nil {
		return ""
	}
	return p.source
}

func (p *testPackageRefreshProvider) SupportsEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "pypi", "go", "maven", "cargo", "nuget", "composer", "gem":
		return true
	default:
		return false
	}
}

func (p *testPackageRefreshProvider) ExcludedByPolicy(ecosystem, name string) bool {
	if p == nil {
		return false
	}
	key := strings.ToLower(strings.TrimSpace(ecosystem)) + "/" + strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range p.excludedNamespaces {
		if strings.HasPrefix(key, strings.ToLower(strings.TrimSpace(prefix))) {
			return true
		}
	}
	return false
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newTestHandler creates a handler backed by the given store.
func newTestHandler(store Store) *Handler {
	logger := newDiscardLogger()
	h := NewHandlerWithBlockThreshold(store, logger, defaultBlockThreshold)
	h.ConfigureReputationScheduler(newTestReputationScheduler(store, logger))
	h.ConfigurePackageRefreshProvider(newTestPackageRefreshProvider())
	return h
}

func newLogCaptureHandler(store Store, logs *bytes.Buffer) *Handler {
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := NewHandlerWithBlockThreshold(store, logger, defaultBlockThreshold)
	h.ConfigureReputationScheduler(newTestReputationScheduler(store, logger))
	h.ConfigurePackageRefreshProvider(newTestPackageRefreshProvider())
	return h
}

func newTestFeedImportHandler(store FeedImportStore) *FeedImportHandler {
	return NewFeedImportHandler(store, newDiscardLogger())
}

func newLogCaptureFeedImportHandler(store FeedImportStore, logs *bytes.Buffer) *FeedImportHandler {
	return NewFeedImportHandler(store, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
}

func withCorrelationID(req *http.Request, correlationID string) *http.Request {
	ctx := requestctx.ContextWithCorrelationID(req.Context(), correlationID)
	return req.WithContext(ctx)
}

func testCorrelation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestctx.HeaderCorrelationID)
		if !correlation.Valid(id) {
			id = "00000000-0000-4000-8000-000000000001"
		}
		w.Header().Set(requestctx.HeaderCorrelationID, id)
		next.ServeHTTP(w, withCorrelationID(r, id))
	})
}

func requireLogField(t *testing.T, logs *bytes.Buffer, key, value string) {
	t.Helper()
	needle := fmt.Sprintf("%q:%q", key, value)
	if !strings.Contains(logs.String(), needle) {
		t.Fatalf("log output missing %s: %s", needle, logs.String())
	}
}

type failingResponseWriter struct {
	header http.Header
}

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingResponseWriter) WriteHeader(int) {}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("response write failed")
}

func TestWriteJSONForRequestLogsWriteFailuresWithRequestContext(t *testing.T) {
	var logs bytes.Buffer
	previousDefault := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(previousDefault)
	})

	req := withCorrelationID(httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/@scope/pkg", nil), "corr-json-write")
	writeJSONForRequest(&failingResponseWriter{}, req, http.StatusOK, map[string]string{"status": "ok"})

	requireLogField(t, &logs, "correlation_id", "corr-json-write")
	requireLogField(t, &logs, "path", "/api/v1/packages/{ecosystem}/{name...}")
	if strings.Contains(logs.String(), "/api/v1/packages/npm/@scope/pkg") {
		t.Fatalf("log output contains raw request path: %s", logs.String())
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

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		var resp FeedStatusResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode feed status response: %v", err)
		}
		if resp.Status != "degraded" {
			t.Fatalf("status response = %+v, want degraded status", resp)
		}
		if resp.Message != "feed status unavailable: feed sync status rows could not be read" {
			t.Fatalf("message = %q, want read failure message", resp.Message)
		}
		if len(resp.Feeds) != 0 {
			t.Fatalf("feeds = %+v, want none when status rows cannot be read", resp.Feeds)
		}
		requireLogField(t, &logs, "correlation_id", "corr-feed-status")
	})

	t.Run("feed import decode error", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		h := newLogCaptureFeedImportHandler(&stubStore{}, &logs)
		req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader("{")), "corr-feed-import")
		req.SetPathValue("feed", "osv")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		h.HandleImport(rr, req)

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
		h.ConfigureSocketRefresh(config.FeedsConfig{
			SocketEnabled: true,
			SocketMode:    config.FeedModeSelf,
			SocketAPIKey:  "socket-token",
		})
		req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", strings.NewReader(`{}`)), "corr-refresh")
		req.Header.Set("Content-Type", "application/json")
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

	t.Run("sync feed state warning", func(t *testing.T) {
		t.Parallel()

		var logs bytes.Buffer
		store := &syncExportStore{
			stubStore: stubStore{feedStatusesErr: errors.New("feed statuses down")},
			export:    &db.SyncExport{SyncedAt: time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)},
		}
		h := newLogCaptureHandler(store, &logs)
		req := withCorrelationID(httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil), "corr-feed-state")
		rr := httptest.NewRecorder()

		h.HandleSync(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
		requireLogField(t, &logs, "correlation_id", "corr-feed-state")
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

	testCorrelation(http.HandlerFunc(h.HandleCheck)).ServeHTTP(rr, req)

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
	if store.scanLogInsertCalls != 1 {
		t.Fatalf("scan log insert calls = %d, want 1", store.scanLogInsertCalls)
	}
	entry := store.scanLogEntries[0]
	if entry.ScanID != first.ScanID {
		t.Fatalf("scan log scan_id = %q, want %q", entry.ScanID, first.ScanID)
	}
	if entry.IdempotencyKey == key {
		t.Fatalf("scan log persisted raw idempotency key %q", entry.IdempotencyKey)
	}
	if want := scanLogIdempotencyKey(key); entry.IdempotencyKey != want {
		t.Fatalf("scan log idempotency key = %q, want %q", entry.IdempotencyKey, want)
	}
	if !strings.HasPrefix(entry.RequestDigest, "sha256:") {
		t.Fatalf("scan log request digest = %q, want sha256 digest", entry.RequestDigest)
	}
}

func TestHandleCheck_IdempotencyKeyReplayUsesCachedSuccessfulResponse(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnBatchFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-left-pad",
				Title:      "Cached replay regression",
				Source:     "osv",
			},
		},
	}
	h := newTestHandler(store)
	body := `{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`
	key := "ci-job-cache-123"

	firstReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	firstReq.Header.Set("Content-Type", "application/json")
	firstReq.Header.Set(idempotencyKeyHeader, key)
	firstRR := httptest.NewRecorder()
	h.HandleCheck(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200: %s", firstRR.Code, firstRR.Body.String())
	}
	firstVulnQueries := len(store.vulnerabilityQueriesSnapshot())
	firstMaliciousQueries := len(store.maliciousQueriesSnapshot())
	firstLifecycleQueries := len(store.lifecycleQueriesSnapshot())
	firstFeedStatusCalls := store.feedStatusListCalls

	secondReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set(idempotencyKeyHeader, key)
	secondRR := httptest.NewRecorder()
	h.HandleCheck(secondRR, secondReq)
	if secondRR.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200: %s", secondRR.Code, secondRR.Body.String())
	}

	if got := len(store.vulnerabilityQueriesSnapshot()); got != firstVulnQueries {
		t.Fatalf("vulnerability lookup queries after replay = %d, want %d", got, firstVulnQueries)
	}
	if got := len(store.maliciousQueriesSnapshot()); got != firstMaliciousQueries {
		t.Fatalf("malicious lookup queries after replay = %d, want %d", got, firstMaliciousQueries)
	}
	if got := len(store.lifecycleQueriesSnapshot()); got != firstLifecycleQueries {
		t.Fatalf("lifecycle lookup queries after replay = %d, want %d", got, firstLifecycleQueries)
	}
	if store.feedStatusListCalls != firstFeedStatusCalls {
		t.Fatalf("feed status calls after replay = %d, want %d", store.feedStatusListCalls, firstFeedStatusCalls)
	}
	if secondRR.Body.String() != firstRR.Body.String() {
		t.Fatalf("replay response body changed:\nfirst:  %s\nsecond: %s", firstRR.Body.String(), secondRR.Body.String())
	}
	if got := secondRR.Header().Get(idempotencyKeyHeader); got != key {
		t.Fatalf("second %s header = %q, want %q", idempotencyKeyHeader, got, key)
	}
}

func TestHandleCheck_IdempotencyKeyDoesNotCacheFailedResponse(t *testing.T) {
	t.Parallel()

	store := &stubStore{vulnBatchErr: errors.New("lookup unavailable")}
	h := newTestHandler(store)
	body := `{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`
	key := "ci-job-cache-failure"

	firstReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	firstReq.Header.Set("Content-Type", "application/json")
	firstReq.Header.Set(idempotencyKeyHeader, key)
	firstRR := httptest.NewRecorder()
	h.HandleCheck(firstRR, firstReq)
	if firstRR.Code != http.StatusInternalServerError {
		t.Fatalf("first status = %d, want 500: %s", firstRR.Code, firstRR.Body.String())
	}
	firstVulnQueries := len(store.vulnerabilityQueriesSnapshot())
	if len(store.scanLogEntries) != 0 || store.scanLogInsertCalls != 0 {
		t.Fatalf("failed check persisted scan log entries/calls = %d/%d, want 0/0", len(store.scanLogEntries), store.scanLogInsertCalls)
	}

	store.vulnBatchErr = nil
	store.vulnBatchFindings = []domain.Finding{
		{
			Name:       "left-pad",
			Version:    "1.3.0",
			Ecosystem:  domain.EcosystemNPM,
			Type:       domain.FindingTypeVulnerability,
			Severity:   domain.SeverityHigh,
			AdvisoryID: "GHSA-left-pad",
			Source:     "osv",
		},
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.Header.Set(idempotencyKeyHeader, key)
	secondRR := httptest.NewRecorder()
	h.HandleCheck(secondRR, secondReq)
	if secondRR.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200: %s", secondRR.Code, secondRR.Body.String())
	}
	if got := len(store.vulnerabilityQueriesSnapshot()); got <= firstVulnQueries {
		t.Fatalf("vulnerability lookups after retry = %d, want more than failed attempt count %d", got, firstVulnQueries)
	}
	var result domain.ScanResult
	if err := json.Unmarshal(secondRR.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if result.FindingsCount != 1 || len(result.Findings) != 1 {
		t.Fatalf("second result findings = count %d len %d, want recovered finding", result.FindingsCount, len(result.Findings))
	}
	if len(store.scanLogEntries) != 1 || store.scanLogInsertCalls != 1 {
		t.Fatalf("successful retry scan log entries/calls = %d/%d, want 1/1", len(store.scanLogEntries), store.scanLogInsertCalls)
	}
}

func TestHandleCheck_IdempotencyKeyReplayDoesNotScheduleReversingLabs(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	store := &stubStore{
		markReputationQueued:  true,
		markReputationBlock:   release,
		markReputationStarted: started,
	}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
		ReversingLabsAPIKey:  "rl-token",
	})

	body := `{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm"}]}`
	key := "ci-job-replay-rl"

	firstReq := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	firstReq.Header.Set("Content-Type", "application/json")
	firstReq.Header.Set(idempotencyKeyHeader, key)
	firstRR := httptest.NewRecorder()
	h.HandleCheck(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		close(release)
		t.Fatalf("first status = %d, want 200: %s", firstRR.Code, firstRR.Body.String())
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("first ReversingLabs scheduling did not start")
	}
	close(release)
	_ = waitForRefreshJobs(t, store, 1)

	var first domain.ScanResult
	if err := json.Unmarshal(firstRR.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first response: %v", err)
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
	select {
	case <-started:
		t.Fatal("idempotent replay scheduled another ReversingLabs refresh")
	case <-time.After(100 * time.Millisecond):
	}
	if got := len(store.enqueuedRefreshJobsSnapshot()); got != 1 {
		t.Fatalf("refresh jobs = %d, want only the initial request", got)
	}
	if got := len(store.markedReputationsSnapshot()); got != 1 {
		t.Fatalf("marked reputations = %d, want only the initial request", got)
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
	if store.scanLogInsertCalls != 1 {
		t.Fatalf("scan log insert calls = %d, want 1", store.scanLogInsertCalls)
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

func TestHandleCheckRejectsPackageGraphMetadata(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	for _, field := range []string{"dev", "direct", "indirect", "optional", "peer", "via", "parents"} {
		t.Run(field, func(t *testing.T) {
			body := fmt.Sprintf(`{"packages":[{"name":"left-pad","version":"1.3.0","ecosystem":"npm",%q:%s}]}`, field, graphMetadataJSONValue(field))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleCheck(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if body := rr.Body.String(); !strings.Contains(body, "unknown field") {
				t.Fatalf("response body = %q, want unknown field error", body)
			}
		})
	}
}

func graphMetadataJSONValue(field string) string {
	switch field {
	case "via":
		return `["root"]`
	case "parents":
		return `[{"name":"root","version":"1.0.0","ecosystem":"npm"}]`
	default:
		return `true`
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
	if len(store.scanLogEntries) != 1 || store.scanLogInsertCalls != 1 {
		t.Fatalf("scan log persisted entries/calls = %d/%d, want 1/1", len(store.scanLogEntries), store.scanLogInsertCalls)
	}
	if store.lookups != 3 {
		t.Fatalf("idempotency lookups = %d, want 3", store.lookups)
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

func TestHandleCheckInvalidRequestIncludesMachineReadableErrorCode(t *testing.T) {
	t.Parallel()

	h := newTestHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(`{"packages":[]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response body is not JSON: %v; body=%q", err, rr.Body.String())
	}
	if body.Error != "packages array is required and must not be empty" {
		t.Fatalf("error = %q, want human message", body.Error)
	}
	if body.Code != "invalid_request" {
		t.Fatalf("code = %q, want invalid_request", body.Code)
	}
}

func TestHandleCheckRejectsNonJSONContentType(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name        string
		contentType string
	}{
		{name: "missing"},
		{name: "wrong media type", contentType: "text/plain"},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := newTestHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(`{"packages":[]}`))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rr := httptest.NewRecorder()

			h.HandleCheck(rr, req)

			if rr.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415: %s", rr.Code, rr.Body.String())
			}
			var body errorJSON
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("error response body is not JSON: %v; body=%q", err, rr.Body.String())
			}
			if body.Code != "unsupported" {
				t.Fatalf("code = %q, want unsupported", body.Code)
			}
			if !strings.Contains(body.Error, "Content-Type") {
				t.Fatalf("error = %q, want Content-Type validation message", body.Error)
			}
			if len(store.scanLogEntries) != 0 || len(store.vulnerabilityQueriesSnapshot()) != 0 {
				t.Fatalf("request reached scan work: scan_logs=%d queries=%+v", len(store.scanLogEntries), store.vulnerabilityQueriesSnapshot())
			}
		})
	}
}

func TestErrorCodeForStatusMapsKnownTaxonomy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status int
		want   string
	}{
		{http.StatusBadRequest, "invalid_request"},
		{http.StatusUnauthorized, "auth_failed"},
		{http.StatusForbidden, "forbidden"},
		{http.StatusConflict, "conflict"},
		{http.StatusTooManyRequests, "rate_limited"},
		{http.StatusNotFound, "not_found"},
		{http.StatusMethodNotAllowed, "unsupported"},
		{http.StatusUnsupportedMediaType, "unsupported"},
		{http.StatusNotImplemented, "unsupported"},
		{http.StatusInternalServerError, "internal_error"},
	}
	for _, tt := range tests {
		if got := errorCodeForStatus(tt.status); got != tt.want {
			t.Fatalf("errorCodeForStatus(%d) = %q, want %q", tt.status, got, tt.want)
		}
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

	testCorrelation(http.HandlerFunc(h.HandleCheck)).ServeHTTP(rr, req)

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

	wantQueries := []PackageLookup{
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

type blockingCheckLookupStore struct {
	stubStore
	release <-chan struct{}
	started chan<- string
	results map[string][]domain.Finding
}

func (s *blockingCheckLookupStore) waitLookup(ctx context.Context, lookup string) error {
	select {
	case s.started <- lookup:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *blockingCheckLookupStore) FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	if err := s.waitLookup(ctx, "vulnerabilities"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.vulnerabilityQueries = append(s.vulnerabilityQueries, packages...)
	s.mu.Unlock()
	return s.results["vulnerabilities"], nil
}

func (s *blockingCheckLookupStore) FindMaliciousBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	if err := s.waitLookup(ctx, "malicious"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.maliciousQueries = append(s.maliciousQueries, packages...)
	s.mu.Unlock()
	return s.results["malicious"], nil
}

func (s *blockingCheckLookupStore) FindReputationFindingsBatch(ctx context.Context, packages []PackageLookup, source string) ([]domain.Finding, error) {
	if err := s.waitLookup(ctx, "reputation"); err != nil {
		return nil, err
	}
	copied := append([]PackageLookup(nil), packages...)
	s.mu.Lock()
	s.reputationQueries = append(s.reputationQueries, struct {
		packages []PackageLookup
		source   string
	}{packages: copied, source: source})
	s.mu.Unlock()
	return s.results["reputation"], nil
}

func (s *blockingCheckLookupStore) FindLifecycleFindingsBatch(ctx context.Context, packages []PackageLookup, now time.Time) ([]domain.Finding, error) {
	if err := s.waitLookup(ctx, "lifecycle"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.lifecycleQueries = append(s.lifecycleQueries, packages...)
	s.mu.Unlock()
	return s.results["lifecycle"], nil
}

func TestCollectFindingsForCheckStartsIndependentLookupsConcurrentlyAndMergesStably(t *testing.T) {
	release := make(chan struct{})
	started := make(chan string, 4)
	store := &blockingCheckLookupStore{
		release: release,
		started: started,
		results: map[string][]domain.Finding{
			"vulnerabilities": {{
				Name:       "pkg",
				Version:    "1.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "VULN-1",
				Source:     "osv",
			}},
			"malicious": {{
				Name:       "pkg",
				Version:    "1.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "MAL-1",
				Source:     "openssf",
			}},
			"reputation": {{
				Name:       "pkg",
				Version:    "1.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "REP-1",
				Source:     db.ReputationSourceReversingLabs,
			}},
			"lifecycle": {{
				Name:       "pkg",
				Version:    "1.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeLifecycle,
				Severity:   domain.SeverityLow,
				AdvisoryID: "LIFE-1",
				Source:     "endoflife.date",
			}},
		},
	}
	h := newTestHandler(store)
	h.ConfigureReversingLabs(config.FeedsConfig{
		ReversingLabsEnabled: true,
		ReversingLabsMode:    config.FeedModeSelf,
	})

	type collectResult struct {
		collection findingCollection
		err        error
	}
	done := make(chan collectResult, 1)
	go func() {
		collection, err := h.collectFindingsForCheck(context.Background(), []domain.Package{
			{Name: "pkg", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		}, false)
		done <- collectResult{collection: collection, err: err}
	}()

	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })

	seen := map[string]bool{}
	timeout := time.After(time.Second)
	for len(seen) < 4 {
		select {
		case lookup := <-started:
			seen[lookup] = true
		case <-timeout:
			releaseOnce.Do(func() { close(release) })
			t.Fatalf("started lookups before release = %#v, want vulnerabilities, malicious, reputation, and lifecycle", seen)
		}
	}
	releaseOnce.Do(func() { close(release) })

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("collectFindingsForCheck() error = %v", result.err)
		}
		gotIDs := make([]string, 0, len(result.collection.findings))
		for _, finding := range result.collection.findings {
			gotIDs = append(gotIDs, finding.AdvisoryID)
		}
		wantIDs := []string{"VULN-1", "MAL-1", "REP-1", "LIFE-1"}
		if !reflect.DeepEqual(gotIDs, wantIDs) {
			t.Fatalf("finding merge order = %#v, want %#v", gotIDs, wantIDs)
		}
	case <-time.After(time.Second):
		t.Fatal("collectFindingsForCheck() did not finish after releasing lookup stubs")
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
	if result.ManualAdvisoriesCount != 2 {
		t.Fatalf("manual_advisories_count = %d, want 2", result.ManualAdvisoriesCount)
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

	h := NewHandlerWithBlockThreshold(store, newDiscardLogger(), domain.SeverityMedium)

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

func TestHandleCheck_DegradedWhenOptionalReputationLookupFails(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnBatchFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-left-pad",
				Title:      "Left-pad vulnerability",
				Source:     "osv",
			},
		},
		reputationErr: errors.New("reputation cache unavailable"),
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

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var result domain.ScanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.FeedStatus != "degraded" {
		t.Fatalf("feed_status = %q, want degraded", result.FeedStatus)
	}
	if len(result.Findings) != 1 || result.Findings[0].AdvisoryID != "GHSA-left-pad" {
		t.Fatalf("findings = %+v, want core vulnerability only", result.Findings)
	}
	if len(store.reputationQueries) != 1 {
		t.Fatalf("reputation queries = %d, want 1", len(store.reputationQueries))
	}
}

func TestHandleCheck_DegradedWhenOptionalLifecycleLookupFails(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		malBatchFindings: []domain.Finding{
			{
				Name:       "evil",
				Version:    "1.0.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "MAL-evil",
				Title:      "Malicious package",
				RiskType:   "malware",
				Source:     "openssf",
			},
		},
		lifecycleErr: errors.New("lifecycle cache unavailable"),
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "openssf", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC()), EntriesSynced: 1, EntriesTotal: 1},
		},
	}
	h := newTestHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(
		`{"packages":[{"name":"evil","version":"1.0.0","ecosystem":"npm"}]}`,
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
	if result.FeedStatus != "degraded" {
		t.Fatalf("feed_status = %q, want degraded", result.FeedStatus)
	}
	if len(result.Findings) != 1 || result.Findings[0].AdvisoryID != "MAL-evil" {
		t.Fatalf("findings = %+v, want core malicious finding only", result.Findings)
	}
	if len(store.lifecycleQueries) != 1 {
		t.Fatalf("lifecycle queries = %d, want 1", len(store.lifecycleQueries))
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
		"repo":{"name":"packmon"},
		"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(requestctx.HeaderCorrelationID, incomingCorrelationID)
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   42,
		Name: "ci-scanner",
	}))
	rr := httptest.NewRecorder()

	// Route through the Correlation middleware as in production: it validates
	// the incoming UUID and stores it in the request context, which the handler
	// then propagates. (The handler deliberately does not echo a raw,
	// unvalidated client header on its own.)
	handler := testCorrelation(http.HandlerFunc(h.HandleCheck))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get(requestctx.HeaderCorrelationID); got != incomingCorrelationID {
		t.Fatalf("X-Correlation-ID = %q, want %q", got, incomingCorrelationID)
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
	entry := store.scanLogEntries[0]
	if entry.RepoName != "packmon" {
		t.Fatalf("scan log repo name = %q, want packmon", entry.RepoName)
	}
	if entry.ClientVersion != "" {
		t.Fatalf("scan log client version = %q, want empty without API User-Agent version", entry.ClientVersion)
	}
	if entry.APIKeyID != 42 || entry.APIKeyName != "ci-scanner" {
		t.Fatalf("scan log API key identity = (%d,%q), want (42,ci-scanner)", entry.APIKeyID, entry.APIKeyName)
	}
}

func TestHandleCheckMinimalScanLogIdentitySuppressesClientAndAPIKeyMetadata(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC())},
		},
	}
	h := newTestHandler(store)
	h.ConfigureScanLogIdentityMode(config.ScanLogIdentityModeMinimal)

	body := `{
		"repo":{"name":"packmon"},
		"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "packmon-cli/1.2.3")
	req = req.WithContext(requestctx.ContextWithClientIP(req.Context(), "203.0.113.20"))
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   42,
		Name: "ci-scanner",
	}))
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
	entry := store.scanLogEntries[0]
	if entry.PackagesCount != 1 || entry.ScanID == "" {
		t.Fatalf("scan log was not fully written: %+v", entry)
	}
	if entry.ClientIP != "" || entry.APIKeyID != 0 || entry.APIKeyName != "" {
		t.Fatalf("scan log identity = (%q,%d,%q), want empty client/API-key identity", entry.ClientIP, entry.APIKeyID, entry.APIKeyName)
	}
	if entry.RepoName != "packmon" {
		t.Fatalf("scan log repo name = %q, want packmon in minimal mode", entry.RepoName)
	}
	if entry.ClientVersion != "1.2.3" {
		t.Fatalf("scan log client version = %q, want normalized version in minimal mode", entry.ClientVersion)
	}
}

func TestHandleCheckNoScanLogIdentitySuppressesRepoAndClientVersion(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC())},
		},
	}
	h := newTestHandler(store)
	h.ConfigureScanLogIdentityMode(config.ScanLogIdentityModeNone)

	body := `{
		"repo":{"name":"packmon"},
		"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "packmon-cli/1.2.3")
	req = req.WithContext(requestctx.ContextWithClientIP(req.Context(), "203.0.113.20"))
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   42,
		Name: "ci-scanner",
	}))
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
	entry := store.scanLogEntries[0]
	if entry.PackagesCount != 1 || entry.ScanID == "" {
		t.Fatalf("scan log was not fully written: %+v", entry)
	}
	if entry.ClientIP != "" || entry.APIKeyID != 0 || entry.APIKeyName != "" || entry.RepoName != "" || entry.ClientVersion != "" {
		t.Fatalf("scan log identity fields not suppressed in none mode: %+v", entry)
	}
}

func TestHandleCheckRejectsRemoteRepoBranchAndCommit(t *testing.T) {
	t.Parallel()

	for _, field := range []string{"branch", "commit"} {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			store := &stubStore{}
			h := newTestHandler(store)
			body := fmt.Sprintf(`{
				"repo":{"name":"packmon",%q:"metadata"},
				"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]
			}`, field)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleCheck(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.scanLogEntries) != 0 {
				t.Fatalf("scan log entries = %d, want none", len(store.scanLogEntries))
			}
		})
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
			"name":"C:\\Users\\Admin\\workspace\\` + strings.Repeat("repo", 120) + `"
		},
		"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "packmon-cli/1.2.3 Authorization: Bearer super-secret-token "+strings.Repeat("x", 400))
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   42,
		Name: "ci-scanner",
	}))
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
		"client_version": entry.ClientVersion,
		"repo":           entry.RepoName,
	} {
		if strings.Contains(value, "super-secret-token") || strings.Contains(value, strings.Repeat("x", 300)) {
			t.Fatalf("%s was not sanitized: %q", label, value)
		}
	}
	if entry.ClientVersion != "1.2.3" {
		t.Fatalf("scan log client version = %q, want normalized version", entry.ClientVersion)
	}
	if len(entry.RepoName) > 256 {
		t.Fatalf("scan log repo metadata length = %d, want bounded", len(entry.RepoName))
	}
	if strings.Contains(entry.RepoName, `\`) || strings.Contains(entry.RepoName, "Users") || strings.Contains(entry.RepoName, "workspace") {
		t.Fatalf("scan log repo name = %q, want basename-only value without local path components", entry.RepoName)
	}
}

func TestHandleCheck_DropsInvalidScanLogClientVersion(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "packmon-cli/not-semver Authorization: Bearer super-secret-token")
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   42,
		Name: "ci-scanner",
	}))
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(store.scanLogEntries) != 1 {
		t.Fatalf("scan log entries = %d, want 1", len(store.scanLogEntries))
	}
	entry := store.scanLogEntries[0]
	if entry.ClientVersion != "" {
		t.Fatalf("scan log client version = %q, want empty for invalid UA", entry.ClientVersion)
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

	packages := make([]domain.Package, checkcontract.MaxPackagesPerCheck+1)
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
	packages := make([]domain.Package, checkcontract.MaxPackagesPerCheck)
	for i := range packages {
		packages[i] = domain.Package{
			Name:      strings.Repeat("a", checkcontract.MaxPackageNameLength),
			Version:   strings.Repeat("1", checkcontract.MaxPackageVersionLength),
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

	h := NewHandlerWithBlockThreshold(&stubStore{}, newDiscardLogger(), defaultBlockThreshold)
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
			body: `{"packages":[{"ecosystem":"npm","name":"` + strings.Repeat("a", checkcontract.MaxPackageNameLength+1) + `","version":"1.0.0"}]}`,
			want: fmt.Sprintf("packages[1].name exceeds %d characters", checkcontract.MaxPackageNameLength),
		},
		{
			name: "version too long",
			body: `{"packages":[{"ecosystem":"npm","name":"left-pad","version":"` + strings.Repeat("1", checkcontract.MaxPackageVersionLength+1) + `"}]}`,
			want: fmt.Sprintf("packages[1].version exceeds %d characters", checkcontract.MaxPackageVersionLength),
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
			req.Header.Set("Content-Type", "application/json")
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
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q, want POST", got)
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

	testCorrelation(http.HandlerFunc(h.HandleCheck)).ServeHTTP(rr, req)

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

func TestHandleCheckScanLogFailureReturnsScanResultAndLogs(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	store := &stubStore{
		scanLogErr: errors.New("scan log unavailable"),
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC()), EntriesSynced: 1, EntriesTotal: 1},
		},
	}
	h := newLogCaptureHandler(store, &logs)

	body := `{"packages":[{"name":"express","version":"4.18.0","ecosystem":"npm"}]}`
	req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body)), "corr-scanlog-degraded")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var result domain.ScanResult
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Mode != domain.ScanModeRemote || result.PackagesScanned != 1 || result.FeedStatus != "healthy" {
		t.Fatalf("scan result = %+v, want normal successful scan response", result)
	}
	if len(store.scanLogEntries) != 0 || store.scanLogInsertCalls != 1 {
		t.Fatalf("scan log persisted entries/calls = %d/%d, want 0/1", len(store.scanLogEntries), store.scanLogInsertCalls)
	}
	if !store.scanLogDeadlineSet {
		t.Fatal("scan log insert did not receive a deadline")
	}
	if remaining := store.scanLogDeadline.Sub(store.scanLogObservedAt); remaining <= 0 || remaining > time.Second {
		t.Fatalf("scan log deadline remaining = %s, want short positive deadline", remaining)
	}
	requireLogField(t, &logs, "correlation_id", "corr-scanlog-degraded")
	if strings.Contains(logs.String(), "express") || strings.Contains(logs.String(), body) {
		t.Fatalf("scan-log failure log leaked package/body data: %s", logs.String())
	}
}

func TestHandleCheck_IdempotencyKeyRequiresDurableScanLogPersistence(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	store := &stubStore{
		scanLogErr: errors.New("scan log unavailable"),
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC()), EntriesSynced: 1, EntriesTotal: 1},
		},
	}
	h := newLogCaptureHandler(store, &logs)

	key := "ci-scanlog-required"
	body := `{"packages":[{"name":"express","version":"4.18.0","ecosystem":"npm"}]}`
	req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body)), "corr-scanlog-idempotent")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(idempotencyKeyHeader, key)
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "idempotency state") {
		t.Fatalf("body = %q, want explicit idempotency persistence failure", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), key) {
		t.Fatalf("response leaked idempotency key: %s", rr.Body.String())
	}
	if len(store.scanLogEntries) != 0 || store.scanLogInsertCalls != 1 {
		t.Fatalf("scan log persisted entries/calls = %d/%d, want 0/1", len(store.scanLogEntries), store.scanLogInsertCalls)
	}
	requireLogField(t, &logs, "correlation_id", "corr-scanlog-idempotent")
	if strings.Contains(logs.String(), key) || strings.Contains(logs.String(), body) {
		t.Fatalf("idempotency scan-log failure log leaked request data: %s", logs.String())
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

func TestHandleCheckUsesLookupDeadline(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		feedStatuses: []db.FeedSyncStatus{
			{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(time.Now().UTC()), EntriesSynced: 1, EntriesTotal: 1},
		},
	}
	h := newTestHandler(store)

	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if !store.lookupDeadlineSet {
		t.Fatal("check lookup context did not receive a deadline")
	}
	if remaining := store.lookupDeadline.Sub(store.lookupObservedAt); remaining <= 0 || remaining > 10*time.Second {
		t.Fatalf("lookup deadline remaining = %s, want short positive deadline", remaining)
	}
}

func TestHandleCheckLookupDeadlineHonorsRequestCancellation(t *testing.T) {
	t.Parallel()

	store := &stubStore{returnLookupCtxErr: true}
	h := newTestHandler(store)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleCheck(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 after canceled lookup context: %s", rr.Code, rr.Body.String())
	}
	if !errors.Is(store.lookupContextErr, context.Canceled) {
		t.Fatalf("lookup context error = %v, want context.Canceled", store.lookupContextErr)
	}
	if store.scanLogInsertCalls != 0 {
		t.Fatalf("scan log insert calls = %d, want none after lookup cancellation", store.scanLogInsertCalls)
	}
}

func TestHandleCheckLookupTimeoutReturnsServiceUnavailableWithoutClientCancel(t *testing.T) {
	started := make(chan string, 4)
	store := &blockingCheckLookupStore{started: started}
	h := newTestHandler(store)
	h.checkLookupTimeout = 25 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	body := `{"packages":[{"name":"lodash","version":"4.17.15","ecosystem":"npm"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		h.HandleCheck(rr, req)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("check lookup store was not called")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("HandleCheck did not return within the check lookup deadline")
	}

	if err := ctx.Err(); err != nil {
		t.Fatalf("request context error = %v, want nil so timeout is handler-owned", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("HandleCheck elapsed = %s, want within lookup deadline", elapsed)
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rr.Code, rr.Body.String())
	}
	var bodyErr errorJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &bodyErr); err != nil {
		t.Fatalf("error response body is not JSON: %v; body=%q", err, rr.Body.String())
	}
	if bodyErr.Code != "service_unavailable" {
		t.Fatalf("error code = %q, want service_unavailable", bodyErr.Code)
	}
	if store.scanLogInsertCalls != 0 {
		t.Fatalf("scan log insert calls = %d, want none after lookup timeout", store.scanLogInsertCalls)
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

func TestHandlePackageDetailNormalizesPathPackageName(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnFindings: []domain.Finding{
			{
				Name:       "newtonsoft.json",
				Ecosystem:  domain.EcosystemNuGet,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "CVE-2026-0001",
				Source:     "osv",
			},
		},
	}
	h := newTestHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/nuget/Newtonsoft.JSON", nil)
	req.SetPathValue("ecosystem", "nuget")
	req.SetPathValue("rest", "Newtonsoft.JSON")
	rr := httptest.NewRecorder()

	h.HandlePackageDetail(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp PackageDetailResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Name != "newtonsoft.json" {
		t.Fatalf("response package name = %q, want canonical lowercase", resp.Name)
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
	if len(query.packages) != 1 || query.packages[0] != (PackageLookup{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"}) {
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

func TestHandlePackageDetailIgnoresOptionalReputationLookupFailure(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-left-pad",
				Title:      "Left-pad vulnerability",
				Source:     "osv",
			},
		},
		reputationErr: errors.New("reputation lookup unavailable"),
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
	if len(resp.Findings) != 1 || resp.Findings[0].AdvisoryID != "GHSA-left-pad" {
		t.Fatalf("findings = %+v, want core vulnerability only", resp.Findings)
	}
	if len(store.reputationPackages) != 1 {
		t.Fatalf("reputation package queries = %d, want 1", len(store.reputationPackages))
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

func TestHandlePackageDetailIgnoresOptionalLifecycleLookupFailure(t *testing.T) {
	t.Parallel()

	store := &stubStore{
		vulnFindings: []domain.Finding{
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
		lifecycleErr: errors.New("lifecycle lookup unavailable"),
	}
	h := newTestHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/pypi/django?version=4.2.11", nil)
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
	if len(resp.Findings) != 1 || resp.Findings[0].AdvisoryID != "GHSA-django" {
		t.Fatalf("findings = %+v, want core vulnerability only", resp.Findings)
	}
	if len(store.lifecycleQueries) != 1 {
		t.Fatalf("lifecycle queries = %d, want 1", len(store.lifecycleQueries))
	}
}

func TestHandlePackageDetailRejectsTooLongVersionBeforeLookup(t *testing.T) {
	t.Parallel()

	store := &stubStore{vulnErr: errors.New("unexpected vulnerability lookup")}
	h := newTestHandler(store)
	version := strings.Repeat("1", checkcontract.MaxPackageVersionLength+1)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash?version="+version, nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash")
	rr := httptest.NewRecorder()

	h.HandlePackageDetail(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "package version exceeds") {
		t.Fatalf("body = %q, want package version length error", rr.Body.String())
	}
	if len(store.lifecycleQueries) != 0 {
		t.Fatalf("lifecycle queries = %+v, want none for too-long package version", store.lifecycleQueries)
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
	if got := rr.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want GET, HEAD", got)
	}
}

func TestHandleFeedImportAcceptsMaliciousAlias(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)

	body := `{"malicious":[{"id":"MAL-1","ecosystem":"npm","name":"evil","risk_type":"malware","summary":"bad"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/malicious/import", strings.NewReader(body))
	req.SetPathValue("feed", "malicious")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

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
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw response: %v", err)
	}
	for _, field := range []string{"imported", "deleted", "entries_total"} {
		if _, ok := raw[field]; !ok {
			t.Fatalf("import response missing count field %q: %s", field, rr.Body.String())
		}
	}
	if raw["deleted"] != float64(0) {
		t.Fatalf("deleted = %#v, want 0", raw["deleted"])
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
	h := newTestFeedImportHandler(store)
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

	h.HandleImport(rr, req)

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

func TestHandleFeedImportRejectsStatusDefaultsThatMakeSyncedExceedTotal(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	body := `{
		"vulnerabilities":[{
			"id":"GHSA-default-total",
			"affected_packages":[{"ecosystem":"npm","name":"left-pad","version_ranges":[],"versions_affected":[]}]
		}],
		"status":{"last_sync_status":"success","entries_synced":2}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(body))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedVulns) != 0 {
		t.Fatalf("upserted vulnerabilities = %+v, want none after impossible status", store.upsertedVulns)
	}
	if len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].LastSyncStatus != db.FeedSyncStatusRejected {
		t.Fatalf("rejected feed status = %+v, want one rejected status", store.upsertedStatuses)
	}
	if store.upsertedStatuses[0].EntriesSynced != 0 || store.upsertedStatuses[0].EntriesTotal != 1 {
		t.Fatalf("rejected status counts = %+v, want 0/1", store.upsertedStatuses[0])
	}
}

func TestHandleFeedImportResponseIncludesZeroCountFields(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{}`))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, field := range []string{"imported", "deleted", "entries_total"} {
		if got, ok := raw[field]; !ok || got != float64(0) {
			t.Fatalf("%s = %#v present=%t, want 0 in %s", field, got, ok, rr.Body.String())
		}
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
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

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
	h := newTestFeedImportHandler(store)
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

	h.HandleImport(rr, req)

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
	h = newTestFeedImportHandler(store)
	body = `{"malicious":[{"id":"MAL-feed-owned","ecosystem":"npm","name":"evil","source":"manual"}]}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(body))
	req.SetPathValue("feed", "socket")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()

	h.HandleImport(rr, req)

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
	h := newTestFeedImportHandler(store)
	body := `{
		"malicious":[{"id":"MAL-audit","ecosystem":"npm","name":"evil","severity":"HIGH"}],
		"delete_malicious_ids":["MAL-old"]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/socket/import", strings.NewReader(body))
	req.SetPathValue("feed", "socket")
	req.RemoteAddr = "203.0.113.10:49152"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(requestctx.HeaderCorrelationID, "12345678-1234-4234-9234-123456789abc")
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   77,
		Name: "n8n-import",
	}))
	rr := httptest.NewRecorder()
	handler := testCorrelation(http.HandlerFunc(h.HandleImport))

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
		"correlation_id": "12345678-1234-4234-9234-123456789abc",
		"api_key_id":     float64(77),
		"api_key_name":   "n8n-import",
	}
	for key, wantValue := range want {
		if got := details[key]; got != wantValue {
			t.Fatalf("audit detail %s = %#v, want %#v (all details: %#v)", key, got, wantValue, details)
		}
	}
	if _, ok := details["client_ip"]; ok {
		t.Fatalf("audit details duplicated client_ip despite typed IP column: %#v", details)
	}
}

func assertAuditDetails(t *testing.T, entry db.AdminAuditEntry, want map[string]any) {
	t.Helper()

	var details map[string]any
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("decode audit details: %v", err)
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

type auditedAtomicImportTestStore struct {
	atomicImportTestStore
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

func (s *atomicImportTestStore) ImportVulnerabilityFeedWithAudit(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	imported, deleted, err := s.ImportVulnerabilityFeed(ctx, feed, items, deleteIDs, status)
	if err != nil {
		return imported, deleted, err
	}
	return imported, deleted, s.InsertAdminAuditLog(ctx, ptr(audit(imported, deleted)))
}

func (s *atomicImportTestStore) ImportMaliciousFeedWithAudit(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	imported, deleted, err := s.ImportMaliciousFeed(ctx, feed, items, deleteIDs, status)
	if err != nil {
		return imported, deleted, err
	}
	return imported, deleted, s.InsertAdminAuditLog(ctx, ptr(audit(imported, deleted)))
}

func (s *auditedAtomicImportTestStore) ImportVulnerabilityFeedWithAudit(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	imported, deleted, err := s.ImportVulnerabilityFeed(ctx, feed, items, deleteIDs, status)
	if err != nil {
		return imported, deleted, err
	}
	return imported, deleted, s.InsertAdminAuditLog(ctx, ptr(audit(imported, deleted)))
}

func (s *auditedAtomicImportTestStore) ImportMaliciousFeedWithAudit(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	imported, deleted, err := s.ImportMaliciousFeed(ctx, feed, items, deleteIDs, status)
	if err != nil {
		return imported, deleted, err
	}
	return imported, deleted, s.InsertAdminAuditLog(ctx, ptr(audit(imported, deleted)))
}

func TestHandleFeedImportUsesAtomicStoreForVulnerabilityAndMaliciousImports(t *testing.T) {
	t.Parallel()

	store := &atomicImportTestStore{}
	h := newTestFeedImportHandler(store)

	vulnBody := `{
		"vulnerabilities":[{"id":"GHSA-atomic-0001","summary":"atomic","severity":"HIGH","affected_packages":[{"ecosystem":"npm","name":"pkg"}]}],
		"delete_vulnerability_ids":["GHSA-old-0001"],
		"status":{"last_sync_status":"success"}
	}`
	vulnReq := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(vulnBody))
	vulnReq.SetPathValue("feed", "osv")
	vulnReq.Header.Set("Content-Type", "application/json")
	vulnRR := httptest.NewRecorder()

	h.HandleImport(vulnRR, vulnReq)

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

	h.HandleImport(malRR, malReq)

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
	if len(store.auditEntries) != 2 {
		t.Fatalf("audit entries = %d, want one per audited atomic import", len(store.auditEntries))
	}
}

func TestHandleFeedImportUsesAuditedAtomicStoreWithoutSecondAudit(t *testing.T) {
	t.Parallel()

	store := &auditedAtomicImportTestStore{}
	h := newTestFeedImportHandler(store)
	body := `{
		"vulnerabilities":[{"id":"GHSA-audit-0001","summary":"atomic audited","severity":"HIGH","affected_packages":[{"ecosystem":"npm","name":"pkg"}]}],
		"delete_vulnerability_ids":["GHSA-old-audit"],
		"status":{"last_sync_status":"success"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(body))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if store.vulnerabilityCalls != 1 {
		t.Fatalf("vulnerabilityCalls = %d, want audited atomic import", store.vulnerabilityCalls)
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("audit entries = %d, want exactly one audited import entry", len(store.auditEntries))
	}
	entry := store.auditEntries[0]
	if entry.Action != "feed_import" {
		t.Fatalf("audit action = %q, want feed_import", entry.Action)
	}
	assertAuditDetails(t, entry, map[string]any{
		"feed":          "osv",
		"imported":      float64(1),
		"deleted":       float64(1),
		"entries_total": float64(2),
	})
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
				if resp.Imported != 1 || resp.Deleted != 1 || len(store.replacedCISAKEVIDs) != 1 || len(store.cisaKEVIDs) != 0 || len(store.clearedCISAKEVIDs) != 0 {
					t.Fatalf("cisakev import = resp %+v replaced=%+v cisa=%+v cleared=%+v", resp, store.replacedCISAKEVIDs, store.cisaKEVIDs, store.clearedCISAKEVIDs)
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
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

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
			if len(store.auditEntries) != 1 {
				t.Fatalf("audit entries = %d, want one audited enrichment import", len(store.auditEntries))
			}
		})
	}
}

type streamingEPSSImportStore struct {
	stubStore
	streamCalls            int
	streamBatchLengths     []int
	statusSeenDuringStream bool
	auditSeenDuringStream  bool
}

func (s *streamingEPSSImportStore) ReplaceEPSSScoresStream(_ context.Context, stream func(func([]db.EPSSEntry) error) error) (int, int, int, error) {
	s.streamCalls++
	total := 0
	err := stream(func(batch []db.EPSSEntry) error {
		if len(s.upsertedStatuses) > 0 {
			s.statusSeenDuringStream = true
		}
		if len(s.auditEntries) > 0 {
			s.auditSeenDuringStream = true
		}
		s.streamBatchLengths = append(s.streamBatchLengths, len(batch))
		if len(batch) > 5000 {
			return fmt.Errorf("EPSS stream batch length = %d, want <= 5000", len(batch))
		}
		total += len(batch)
		return nil
	})
	if err != nil {
		return 0, 0, total, err
	}
	return total, 3, total, nil
}

func TestHandleFeedImportStreamsEPSSImportInBatches(t *testing.T) {
	store := &streamingEPSSImportStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/epss/import", strings.NewReader(epssStreamingImportBody(5002)))
	req.SetPathValue("feed", "epss")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp importResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if resp.Imported != 5002 || resp.Deleted != 3 || resp.EntriesTotal != 5002 {
		t.Fatalf("response = %+v, want imported=5002 deleted=3 entries_total=5002", resp)
	}
	if store.streamCalls != 1 {
		t.Fatalf("ReplaceEPSSScoresStream calls = %d, want 1", store.streamCalls)
	}
	if store.epssReplaceCalls != 0 || len(store.epssEntries) != 0 {
		t.Fatalf("EPSS import used full-array replacement path: calls=%d entries=%d", store.epssReplaceCalls, len(store.epssEntries))
	}
	if want := []int{5000, 2}; !reflect.DeepEqual(store.streamBatchLengths, want) {
		t.Fatalf("EPSS stream batch lengths = %+v, want %+v", store.streamBatchLengths, want)
	}
	if store.statusSeenDuringStream || store.auditSeenDuringStream {
		t.Fatalf("status/audit were written before EPSS stream finished: status=%t audit=%t", store.statusSeenDuringStream, store.auditSeenDuringStream)
	}
	if len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].EntriesSynced != 5002 || store.upsertedStatuses[0].EntriesTotal != 5002 {
		t.Fatalf("EPSS status = %+v, want one success status with 5002/5002", store.upsertedStatuses)
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("EPSS audit entries = %d, want 1", len(store.auditEntries))
	}
}

type streamingVulnCheckImportStore struct {
	stubStore
	importWithAuditCalls   int
	enrichBatchLengths     []int
	statusSeenDuringEnrich bool
	auditSeenDuringEnrich  bool
}

func (s *streamingVulnCheckImportStore) ImportVulnCheckWithAudit(ctx context.Context, feed string, entries []db.VulnCheckEntry, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, error) {
	s.importWithAuditCalls++
	return s.stubStore.ImportVulnCheckWithAudit(ctx, feed, entries, status, audit)
}

func (s *streamingVulnCheckImportStore) EnrichVulnCheck(_ context.Context, entries []db.VulnCheckEntry) (int, error) {
	if len(s.upsertedStatuses) > 0 {
		s.statusSeenDuringEnrich = true
	}
	if len(s.auditEntries) > 0 {
		s.auditSeenDuringEnrich = true
	}
	s.enrichBatchLengths = append(s.enrichBatchLengths, len(entries))
	if len(entries) > 1000 {
		return 0, fmt.Errorf("VulnCheck batch length = %d, want <= 1000", len(entries))
	}
	return len(entries), nil
}

func TestHandleFeedImportStreamsVulnCheckImportInBatches(t *testing.T) {
	store := &streamingVulnCheckImportStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/vulncheck/import", strings.NewReader(vulnCheckStreamingImportBody(2005)))
	req.SetPathValue("feed", "vulncheck")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp importResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if resp.Imported != 2005 || resp.Deleted != 0 || resp.EntriesTotal != 2005 {
		t.Fatalf("response = %+v, want imported=2005 deleted=0 entries_total=2005", resp)
	}
	if store.importWithAuditCalls != 0 {
		t.Fatalf("VulnCheck import used full-array audited path %d time(s)", store.importWithAuditCalls)
	}
	if want := []int{1000, 1000, 5}; !reflect.DeepEqual(store.enrichBatchLengths, want) {
		t.Fatalf("VulnCheck batch lengths = %+v, want %+v", store.enrichBatchLengths, want)
	}
	if store.statusSeenDuringEnrich || store.auditSeenDuringEnrich {
		t.Fatalf("status/audit were written before VulnCheck batches finished: status=%t audit=%t", store.statusSeenDuringEnrich, store.auditSeenDuringEnrich)
	}
	if len(store.upsertedStatuses) != 1 || store.upsertedStatuses[0].EntriesSynced != 2005 || store.upsertedStatuses[0].EntriesTotal != 2005 {
		t.Fatalf("VulnCheck status = %+v, want one success status with 2005/2005", store.upsertedStatuses)
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("VulnCheck audit entries = %d, want 1", len(store.auditEntries))
	}
}

func epssStreamingImportBody(total int) string {
	var b strings.Builder
	b.WriteString(`{"entries":[`)
	for i := 0; i < total; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"cve_id":"CVE-2026-%04d","score":0.5,"percentile":0.9}`, i+1000)
	}
	b.WriteString(`],"status":{"last_sync_status":"success"}}`)
	return b.String()
}

func vulnCheckStreamingImportBody(total int) string {
	var b strings.Builder
	b.WriteString(`{"entries":[`)
	for i := 0; i < total; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"cve_id":"CVE-2026-%04d","cvss_score":5.5,"exploit_exists":true}`, i+1000)
	}
	b.WriteString(`],"status":{"last_sync_status":"success"}}`)
	return b.String()
}

func TestHandleFeedImportRejectsMissingEnrichmentCVEIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		feed string
		body string
	}{
		{
			name: "vulncheck missing cve",
			feed: "vulncheck",
			body: `{"entries":[{"exploit_exists":true,"source_url":"https://vulncheck.test/cve"}]}`,
		},
		{
			name: "epss missing cve",
			feed: "epss",
			body: `{"entries":[{"score":0.1,"percentile":0.2}]}`,
		},
		{
			name: "epss empty snapshot",
			feed: "epss",
			body: `{"entries":[]}`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := &stubStore{}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/"+tt.feed+"/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", tt.feed)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.vulnCheckEntries) != 0 || len(store.epssEntries) != 0 || store.epssReplaceCalls != 0 {
				t.Fatalf("store mutated for rejected import: vulncheck=%+v epss=%+v epssCalls=%d", store.vulnCheckEntries, store.epssEntries, store.epssReplaceCalls)
			}
		})
	}
}

func TestHandleFeedImportRejectsMalformedMaliciousVersionRanges(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	body := `{"malicious":[{"id":"MAL-range","ecosystem":"npm","name":"evil","version_ranges":{"introduced":"0"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/openssf/import", strings.NewReader(body))
	req.SetPathValue("feed", "openssf")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedMalicious) != 0 {
		t.Fatalf("upserted malicious = %+v, want none", store.upsertedMalicious)
	}
	if !strings.Contains(rr.Body.String(), "version_ranges") {
		t.Fatalf("body = %q, want version_ranges diagnostic", rr.Body.String())
	}
}

func TestHandleFeedImportRejectsOutOfRangeVulnerabilityScores(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "cvss too high",
			body: `{"vulnerabilities":[{"id":"GHSA-score","severity":"HIGH","cvss_score":99}]}`,
		},
		{
			name: "epss negative",
			body: `{"vulnerabilities":[{"id":"GHSA-score","severity":"HIGH","epss_score":-0.1}]}`,
		},
		{
			name: "epss percentile too high",
			body: `{"vulnerabilities":[{"id":"GHSA-score","severity":"HIGH","epss_percentile":1.1}]}`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := &stubStore{}
			h := newTestFeedImportHandler(store)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(tt.body))
			req.SetPathValue("feed", "osv")
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			h.HandleImport(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if len(store.upsertedVulns) != 0 {
				t.Fatalf("upserted vulnerabilities = %+v, want none", store.upsertedVulns)
			}
		})
	}
}

func TestHandleFeedImportValidationRecordsRejectedStatus(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	body := `{"vulnerabilities":[{"id":"GHSA-score","severity":"HIGH","cvss_score":99}]}`
	req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(body)), "corr-reject")
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.44:12345"
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{ID: 77, Name: "n8n-import"}))
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedVulns) != 0 {
		t.Fatalf("upserted vulnerabilities = %+v, want none", store.upsertedVulns)
	}
	if len(store.upsertedStatuses) != 1 {
		t.Fatalf("feed statuses = %d, want rejected status", len(store.upsertedStatuses))
	}
	status := store.upsertedStatuses[0]
	if status.FeedName != "osv" || status.LastSyncStatus != "rejected" || status.EntriesSynced != 0 || status.EntriesTotal != 1 {
		t.Fatalf("rejected feed status = %+v", status)
	}
	if status.LastSyncAt != nil {
		t.Fatalf("LastSyncAt = %v, want nil for rejected import", status.LastSyncAt)
	}
	if !strings.Contains(status.LastError, "cvss_score") {
		t.Fatalf("LastError = %q, want validation reason", status.LastError)
	}
	var metadata map[string]any
	if err := json.Unmarshal(status.Metadata, &metadata); err != nil {
		t.Fatalf("decode rejected metadata: %v", err)
	}
	if metadata["rejected_count"] != float64(1) || !strings.Contains(fmt.Sprint(metadata["rejection_reason"]), "cvss_score") {
		t.Fatalf("rejected metadata = %+v", metadata)
	}
	if metadata["api_key_id"] != float64(77) || metadata["api_key_name"] != "n8n-import" || metadata["client_ip"] != "192.0.2.44" || metadata["correlation_id"] != "corr-reject" {
		t.Fatalf("rejected attribution metadata = %+v", metadata)
	}
}

func TestHandleFeedImportCISAKEVClearMissingUsesReplacePath(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/cisakev/import", strings.NewReader(`{
		"cve_ids":["CVE-2026-0001"],
		"clear_missing":true,
		"status":{"entries_synced":1,"entries_total":1}
	}`))
	req.SetPathValue("feed", "cisakev")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp importResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if resp.Imported != 1 || resp.Deleted != 1 {
		t.Fatalf("response = %+v, want imported=1 deleted=1", resp)
	}
	if len(store.cisaKEVIDs) != 0 || len(store.clearedCISAKEVIDs) != 0 {
		t.Fatalf("clear_missing used legacy Set/Clear path: set=%+v clear=%+v", store.cisaKEVIDs, store.clearedCISAKEVIDs)
	}
	if len(store.upsertedStatuses) != 1 || len(store.auditEntries) != 1 {
		t.Fatalf("status/audit counts = %d/%d, want 1/1", len(store.upsertedStatuses), len(store.auditEntries))
	}
}

func TestHandleFeedImportDoesNotStampFailedStatusAsFresh(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	body := `{"status":{"last_sync_status":"error","last_error":"importer rejected upstream payload"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(body))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if len(store.upsertedStatuses) != 1 {
		t.Fatalf("feed statuses = %d, want 1", len(store.upsertedStatuses))
	}
	status := store.upsertedStatuses[0]
	if status.LastSyncStatus != "error" {
		t.Fatalf("LastSyncStatus = %q, want error", status.LastSyncStatus)
	}
	if status.LastSyncAt != nil {
		t.Fatalf("LastSyncAt = %v, want nil for failed status without usable timestamp", status.LastSyncAt)
	}
}

func TestHandleFeedImportRejectsEmptyEPSSSnapshotWithFailedStatus(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	body := `{"status":{"last_sync_status":"error","last_error":"upstream payload was empty"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/epss/import", strings.NewReader(body))
	req.SetPathValue("feed", "epss")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if store.epssReplaceCalls != 0 || len(store.epssEntries) != 0 {
		t.Fatalf("EPSS replacement called for empty snapshot: calls=%d entries=%+v", store.epssReplaceCalls, store.epssEntries)
	}
	if len(store.upsertedStatuses) != 1 {
		t.Fatalf("feed statuses = %d, want rejected status", len(store.upsertedStatuses))
	}
	if got := store.upsertedStatuses[0].LastSyncStatus; got != "rejected" {
		t.Fatalf("LastSyncStatus = %q, want rejected", got)
	}
}

func TestHandleFeedImportValidationDiagnosticsAreBounded(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	oversizedID := strings.Repeat("A", 5000)
	body := `{"vulnerabilities":[{"id":"` + oversizedID + `","severity":"BOGUS"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(body))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), oversizedID) {
		t.Fatalf("response echoed unbounded import field value")
	}
	if len(rr.Body.String()) > 1024 {
		t.Fatalf("response length = %d, want bounded diagnostic: %s", len(rr.Body.String()), rr.Body.String())
	}
}

func TestHandleFeedImportRejectsUnknownFeedAndInvalidMethod(t *testing.T) {
	t.Parallel()

	h := newTestFeedImportHandler(&stubStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/nope/import", strings.NewReader(`{}`))
	req.SetPathValue("feed", "nope")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.HandleImport(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown feed status = %d, want 404", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/feeds/osv/import", nil)
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	h.HandleImport(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET import status = %d, want 405", rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q, want POST", got)
	}
}

func TestHandleFeedImportRejectsNonJSONContentType(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestFeedImportHandler(store)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/osv/import", strings.NewReader(`{"vulnerabilities":[]}`))
	req.SetPathValue("feed", "osv")
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	h.HandleImport(rr, req)

	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415: %s", rr.Code, rr.Body.String())
	}
	var body errorJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response body is not JSON: %v; body=%q", err, rr.Body.String())
	}
	if body.Code != "unsupported" {
		t.Fatalf("code = %q, want unsupported", body.Code)
	}
	if len(store.upsertedVulns) != 0 || len(store.upsertedStatuses) != 0 || len(store.auditEntries) != 0 {
		t.Fatalf("feed import mutated store after media type rejection: vulns=%d statuses=%d audits=%d", len(store.upsertedVulns), len(store.upsertedStatuses), len(store.auditEntries))
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

func TestHandleRefreshRejectsNonJSONContentTypeWhenBodyIsPresent(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	h.handleRefresh(rr, req, "npm", "lodash")

	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415: %s", rr.Code, rr.Body.String())
	}
	var body errorJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response body is not JSON: %v; body=%q", err, rr.Body.String())
	}
	if body.Code != "unsupported" {
		t.Fatalf("code = %q, want unsupported", body.Code)
	}
	if len(store.enqueuedRefreshJobsSnapshot()) != 0 {
		t.Fatalf("refresh enqueued jobs after media type rejection: %+v", store.enqueuedRefreshJobsSnapshot())
	}
}

func TestHandleRefreshEnqueuesPathPackage(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash/refresh")
	rr := httptest.NewRecorder()

	h.HandlePackageOrRefresh(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rr.Code, rr.Body.String())
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

func TestHandleRefreshNormalizesPackageNameBeforeBudgetAndEnqueue(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/pypi/My.Pkg_Name/refresh", nil)
	req.SetPathValue("ecosystem", "pypi")
	req.SetPathValue("rest", "My.Pkg_Name/refresh")
	rr := httptest.NewRecorder()

	h.HandlePackageOrRefresh(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rr.Code, rr.Body.String())
	}
	if len(store.packageCheckStatusLookups) != 1 || store.packageCheckStatusLookups[0].name != "my-pkg-name" {
		t.Fatalf("package check lookups = %+v, want normalized PyPI name", store.packageCheckStatusLookups)
	}
	if len(store.enqueuedRefreshJobs) != 1 || store.enqueuedRefreshJobs[0].Name != "my-pkg-name" {
		t.Fatalf("enqueued jobs = %+v, want normalized PyPI name", store.enqueuedRefreshJobs)
	}
}

func TestHandleRefreshWritesAttributedAuditEntry(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil), "corr-refresh-audit")
	req.RemoteAddr = "203.0.113.25:49152"
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   91,
		Name: "incident-runner",
	}))
	rr := httptest.NewRecorder()

	h.handleRefresh(rr, req, "npm", "lodash")

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rr.Code, rr.Body.String())
	}
	if len(store.enqueuedRefreshJobsSnapshot()) != 1 {
		t.Fatalf("enqueued jobs = %d, want 1", len(store.enqueuedRefreshJobsSnapshot()))
	}
	if len(store.auditEntries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(store.auditEntries))
	}
	entry := store.auditEntries[0]
	if entry.Action != "package_refresh_enqueue" {
		t.Fatalf("audit action = %q, want package_refresh_enqueue", entry.Action)
	}
	if entry.IP != "203.0.113.25" {
		t.Fatalf("audit IP = %q, want remote client IP", entry.IP)
	}
	assertAuditDetails(t, entry, map[string]any{
		"ecosystem":      "npm",
		"name":           "lodash",
		"source":         "socket",
		"new":            true,
		"position":       float64(1),
		"correlation_id": "corr-refresh-audit",
		"api_key_id":     float64(91),
		"api_key_name":   "incident-runner",
	})
	var details map[string]any
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("decode audit details: %v", err)
	}
	if _, ok := details["client_ip"]; ok {
		t.Fatalf("audit details duplicated client_ip despite typed IP column: %#v", details)
	}
}

func TestHandleRefreshDoesNotEnqueueWhenAuditFails(t *testing.T) {
	t.Parallel()

	store := &stubStore{auditErr: errors.New("audit unavailable")}
	h := newTestHandler(store)
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := withCorrelationID(httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil), "corr-refresh-audit-fail")
	req.RemoteAddr = "198.51.100.34:49152"
	req = req.WithContext(requestctx.ContextWithAPIKeyIdentity(req.Context(), requestctx.APIKeyIdentity{
		ID:   92,
		Name: "ci-refresh",
	}))
	rr := httptest.NewRecorder()

	h.handleRefresh(rr, req, "npm", "lodash")

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rr.Code, rr.Body.String())
	}
	if len(store.enqueuedRefreshJobsSnapshot()) != 0 {
		t.Fatalf("enqueued jobs = %+v, want none when audit fails", store.enqueuedRefreshJobsSnapshot())
	}
	if len(store.auditEntries) != 0 {
		t.Fatalf("audit entries = %d, want none after audit persistence failure", len(store.auditEntries))
	}
}

func TestHandleRefreshRespectsSocketNextCheckBudget(t *testing.T) {
	t.Parallel()

	nextCheck := time.Now().UTC().Add(time.Hour)
	store := &stubStore{
		packageCheckStatus: &db.PackageCheckStatus{
			Ecosystem:   "npm",
			Name:        "lodash",
			Source:      "socket",
			NextCheckAt: &nextCheck,
		},
	}
	h := newTestHandler(store)
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil)
	rr := httptest.NewRecorder()

	h.handleRefresh(rr, req, "npm", "lodash")

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rr.Code, rr.Body.String())
	}
	if len(store.enqueuedRefreshJobsSnapshot()) != 0 {
		t.Fatalf("enqueued jobs = %+v, want none inside next-check budget", store.enqueuedRefreshJobsSnapshot())
	}
	if len(store.packageCheckStatusLookups) != 1 || store.packageCheckStatusLookups[0].source != "socket" {
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

func TestHandleRefreshRejectsExcludedNamespaceBeforeEnqueue(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled:            true,
		SocketMode:               config.FeedModeSelf,
		SocketAPIKey:             "socket-token",
		SocketExcludedNamespaces: []string{"npm/@internal/"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/@internal/widget/refresh", nil)
	rr := httptest.NewRecorder()

	h.handleRefresh(rr, req, "npm", "@internal/widget")

	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "private namespace policy") {
		t.Fatalf("body = %q, want private namespace policy error", rr.Body.String())
	}
	if got := len(store.enqueuedRefreshJobsSnapshot()); got != 0 {
		t.Fatalf("enqueued jobs = %d, want 0 for excluded namespace", got)
	}
}

func TestHandleRefreshRejectsLongPackageNameBeforeEnqueue(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	name := strings.Repeat("a", checkcontract.MaxPackageNameLength+1)
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
	h.ConfigureSocketRefresh(config.FeedsConfig{
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
	h.ConfigureSocketRefresh(config.FeedsConfig{
		SocketEnabled: true,
		SocketMode:    config.FeedModeSelf,
		SocketAPIKey:  "socket-token",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/@scope/pkg/refresh", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "@scope/pkg/refresh")
	rr := httptest.NewRecorder()

	h.HandlePackageOrRefresh(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rr.Code, rr.Body.String())
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

func TestHandleSyncIncludesFeedState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 23, 12, 34, 56, 789123456, time.UTC)
	store := &syncExportStore{
		stubStore: stubStore{
			feedStatuses: []db.FeedSyncStatus{
				{
					FeedName:       "osv",
					LastSyncAt:     ptrFeedTime(now.Add(-time.Hour)),
					LastSyncStatus: "success",
					EntriesTotal:   10,
				},
				{
					FeedName:       "nvd",
					LastSyncStatus: "pending",
				},
			},
		},
		export: &db.SyncExport{SyncedAt: now},
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
	if resp.FeedStatus != "degraded" {
		t.Fatalf("feed status = %q, want degraded", resp.FeedStatus)
	}
	if resp.SyncedAt != now.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("synced_at = %q, want RFC3339Nano timestamp", resp.SyncedAt)
	}
	if got := resp.FeedVersions["osv"]; got != now.Add(-time.Hour).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("feed versions[osv] = %q", got)
	}
}

func TestHandleSyncCountsDegradedResponses(t *testing.T) {
	t.Parallel()

	before := telemetry.Default().Snapshot().DegradedResponses
	now := time.Now().UTC()
	store := &syncExportStore{
		stubStore: stubStore{
			feedStatuses: []db.FeedSyncStatus{
				{FeedName: "osv", LastSyncStatus: "error", LastSyncAt: ptrFeedTime(now)},
			},
		},
		export: &db.SyncExport{SyncedAt: now},
	}
	h := newTestHandler(&store.stubStore)
	h.store = store

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil)
	rr := httptest.NewRecorder()

	h.HandleSync(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	after := telemetry.Default().Snapshot().DegradedResponses
	if after < before+1 {
		t.Fatalf("degraded response counter = %d, want at least %d", after, before+1)
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
