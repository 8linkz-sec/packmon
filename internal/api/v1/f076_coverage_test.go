package v1

import (
	"bytes"
	"context"
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

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/logsafe"
)

const f076CheckBody = `{"packages":[{"name":"private-package","version":"1.2.3","ecosystem":"npm"}]}`

type f076LookupFailureStore struct {
	*stubStore

	failAt      int
	lookupErr   error
	lookupCalls int
}

func (s *f076LookupFailureStore) GetScanLogByIdempotencyKey(_ context.Context, key string) (*db.ScanLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookupCalls++
	if s.lookupCalls == s.failAt {
		return nil, s.lookupErr
	}
	for i := range s.scanLogEntries {
		if s.scanLogEntries[i].IdempotencyKey == key {
			entry := s.scanLogEntries[i]
			return &entry, nil
		}
	}
	return nil, nil
}

type f076DurableStore struct {
	*stubStore
	lookupCalls int
}

func (s *f076DurableStore) GetScanLogByIdempotencyKey(_ context.Context, key string) (*db.ScanLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookupCalls++
	for i := range s.scanLogEntries {
		if s.scanLogEntries[i].IdempotencyKey == key {
			entry := s.scanLogEntries[i]
			return &entry, nil
		}
	}
	return nil, nil
}

type f076CountingScheduler struct {
	mu             sync.Mutex
	configureCalls int
	scheduleCalls  int
}

func (s *f076CountingScheduler) Configure(ReputationSchedulerConfig) {
	s.mu.Lock()
	s.configureCalls++
	s.mu.Unlock()
}

func (s *f076CountingScheduler) ScheduleReversingLabsAsync(context.Context, []domain.Package, []domain.Finding) {
	s.mu.Lock()
	s.scheduleCalls++
	s.mu.Unlock()
}

func (s *f076CountingScheduler) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scheduleCalls
}

type f076MaliciousFailureStore struct {
	*stubStore
	vulnerabilityDone chan struct{}
	maliciousErr      error
}

func (s *f076MaliciousFailureStore) FindVulnerabilitiesBatch(ctx context.Context, packages []PackageLookup) ([]domain.Finding, error) {
	findings, err := s.stubStore.FindVulnerabilitiesBatch(ctx, packages)
	close(s.vulnerabilityDone)
	return findings, err
}

func (s *f076MaliciousFailureStore) FindMaliciousBatch(_ context.Context, _ []PackageLookup) ([]domain.Finding, error) {
	<-s.vulnerabilityDone
	return nil, s.maliciousErr
}

type f076ReputationContextKey struct{}

type f076VersionedReputationFailureStore struct {
	*stubStore
	gotContext any
}

func (s *f076VersionedReputationFailureStore) FindReputationFindingsBatch(ctx context.Context, packages []PackageLookup, source string) ([]domain.Finding, error) {
	s.gotContext = ctx.Value(f076ReputationContextKey{})
	return s.stubStore.FindReputationFindingsBatch(ctx, packages, source)
}

type f076RefreshFailureStore struct {
	*stubStore
	err      error
	attempts int
}

func (s *f076RefreshFailureStore) EnqueueRefreshWithAudit(context.Context, *db.RefreshJob, db.RefreshEnqueueAuditBuilder) (bool, int, error) {
	s.attempts++
	return false, 0, s.err
}

type f076FailingWriter struct {
	header     http.Header
	statusCode int
	err        error
}

func (w *f076FailingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *f076FailingWriter) WriteHeader(status int) {
	w.statusCode = status
}

func (w *f076FailingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

type f076FailingReadCloser struct {
	err error
}

func (r *f076FailingReadCloser) Read([]byte) (int, error) { return 0, r.err }
func (r *f076FailingReadCloser) Close() error             { return nil }

type f076CountingRefreshProvider struct {
	activeCalls   int
	sourceCalls   int
	supportsCalls int
}

func (*f076CountingRefreshProvider) Configure(PackageRefreshProviderConfig) {}

func (p *f076CountingRefreshProvider) Active() bool {
	p.activeCalls++
	return true
}

func (p *f076CountingRefreshProvider) Source() string {
	p.sourceCalls++
	return "socket"
}

func (p *f076CountingRefreshProvider) SupportsEcosystem(string) bool {
	p.supportsCalls++
	return true
}

func f076CheckRequest(key, correlationID string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", strings.NewReader(f076CheckBody))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set(idempotencyKeyHeader, key)
	}
	if correlationID != "" {
		req = withCorrelationID(req, correlationID)
	}
	return req
}

func f076DecodeScanResult(t *testing.T, recorder *httptest.ResponseRecorder) domain.ScanResult {
	t.Helper()
	var result domain.ScanResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode scan result: %v; body=%q", err, recorder.Body.String())
	}
	return result
}

func TestHandleCheckIdempotencyLookupFailuresAreSanitizedAndNotCached(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		failAt       int
		lookupErr    error
		wantStatus   int
		wantCode     string
		wantInserts  int
		wantSchedule int
	}{
		{name: "initial generic failure", failAt: 1, lookupErr: errors.New("database lookup diagnostic"), wantStatus: http.StatusInternalServerError, wantCode: "internal_error", wantInserts: 0, wantSchedule: 0},
		{name: "initial deadline", failAt: 1, lookupErr: context.DeadlineExceeded, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable", wantInserts: 0, wantSchedule: 0},
		// Post-insert verification occurs after finding collection has scheduled
		// exactly one external reputation refresh, while an initial lookup failure
		// schedules none. These expectations make the observed ordering explicit.
		{name: "post-insert generic failure", failAt: 3, lookupErr: errors.New("database verification diagnostic"), wantStatus: http.StatusInternalServerError, wantCode: "internal_error", wantInserts: 1, wantSchedule: 1},
		{name: "post-insert deadline", failAt: 3, lookupErr: context.DeadlineExceeded, wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable", wantInserts: 1, wantSchedule: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &f076LookupFailureStore{stubStore: &stubStore{}, failAt: tc.failAt, lookupErr: tc.lookupErr}
			scheduler := &f076CountingScheduler{}
			h := NewHandlerWithBlockThreshold(store, newDiscardLogger(), defaultBlockThreshold)
			h.ConfigureReputationScheduler(scheduler)
			h.ConfigureReversingLabs(config.FeedsConfig{
				ReversingLabsEnabled: true,
				ReversingLabsMode:    config.FeedModeSelf,
				ReversingLabsAPIKey:  "configured",
			})
			key := "private-idempotency-key"
			recorder := httptest.NewRecorder()

			h.HandleCheck(recorder, f076CheckRequest(key, "corr-idempotency-failure"))

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			var response errorJSON
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode error response: %v; body=%q", err, recorder.Body.String())
			}
			if response.Code != tc.wantCode {
				t.Fatalf("error code = %q, want %q", response.Code, tc.wantCode)
			}
			for _, sensitive := range []string{key, "private-package", f076CheckBody, "database lookup diagnostic", "database verification diagnostic"} {
				if strings.Contains(recorder.Body.String(), sensitive) {
					t.Fatalf("error response leaked %q: %s", sensitive, recorder.Body.String())
				}
			}
			if store.scanLogInsertCalls != tc.wantInserts {
				t.Fatalf("scan log inserts = %d, want %d", store.scanLogInsertCalls, tc.wantInserts)
			}
			if got := scheduler.calls(); got != tc.wantSchedule {
				t.Fatalf("scheduler calls = %d, want %d", got, tc.wantSchedule)
			}
			if got := len(h.checkResponseCache.entries); got != 0 {
				t.Fatalf("cached responses = %d, want 0", got)
			}
		})
	}
}

func TestHandleCheckIdempotencyReplayAfterHandlerRestartPreservesDurableIdentity(t *testing.T) {
	t.Parallel()

	store := &f076DurableStore{stubStore: &stubStore{}}
	scheduler := &f076CountingScheduler{}
	newHandler := func() *Handler {
		h := NewHandlerWithBlockThreshold(store, newDiscardLogger(), defaultBlockThreshold)
		h.ConfigureReputationScheduler(scheduler)
		h.ConfigureReversingLabs(config.FeedsConfig{
			ReversingLabsEnabled: true,
			ReversingLabsMode:    config.FeedModeSelf,
			ReversingLabsAPIKey:  "configured",
		})
		return h
	}
	key := "restart-idempotency-key"
	storedKey := scanLogIdempotencyKey(key)
	reqForDigest := domain.ScanRequest{Packages: []domain.Package{{Name: "private-package", Version: "1.2.3", Ecosystem: domain.EcosystemNPM}}}
	digest, err := checkRequestDigest(&reqForDigest)
	if err != nil {
		t.Fatalf("check request digest: %v", err)
	}
	wantScanID := scanIDForIdempotencyKey(storedKey, digest)

	h1 := newHandler()
	first := httptest.NewRecorder()
	h1.HandleCheck(first, f076CheckRequest(key, "corr-restart-first"))
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200: %s", first.Code, first.Body.String())
	}
	if got := f076DecodeScanResult(t, first).ScanID; got != wantScanID {
		t.Fatalf("first scan ID = %q, want deterministic %q", got, wantScanID)
	}
	if store.lookupCalls != 3 || store.scanLogInsertCalls != 1 {
		t.Fatalf("after first request lookups/inserts = %d/%d, want 3/1", store.lookupCalls, store.scanLogInsertCalls)
	}
	if len(store.vulnerabilityQueriesSnapshot()) != 1 || len(store.maliciousQueriesSnapshot()) != 1 || len(store.lifecycleQueriesSnapshot()) != 1 || len(store.reputationQueries) != 1 || store.feedStatusListCalls != 1 || scheduler.calls() != 1 {
		t.Fatalf("after first request family counts = vuln %d malicious %d lifecycle %d reputation %d feed %d scheduler %d, want all 1",
			len(store.vulnerabilityQueriesSnapshot()), len(store.maliciousQueriesSnapshot()), len(store.lifecycleQueriesSnapshot()), len(store.reputationQueries), store.feedStatusListCalls, scheduler.calls())
	}

	h2 := newHandler()
	second := httptest.NewRecorder()
	h2.HandleCheck(second, f076CheckRequest(key, "corr-restart-second"))
	if second.Code != http.StatusOK {
		t.Fatalf("restart status = %d, want 200: %s", second.Code, second.Body.String())
	}
	if got := f076DecodeScanResult(t, second).ScanID; got != wantScanID {
		t.Fatalf("restart scan ID = %q, want %q", got, wantScanID)
	}
	if store.lookupCalls != 4 || store.scanLogInsertCalls != 1 {
		t.Fatalf("after restart lookups/inserts = %d/%d, want 4/1", store.lookupCalls, store.scanLogInsertCalls)
	}
	if len(store.vulnerabilityQueriesSnapshot()) != 2 || len(store.maliciousQueriesSnapshot()) != 2 || len(store.lifecycleQueriesSnapshot()) != 2 || len(store.reputationQueries) != 2 || store.feedStatusListCalls != 2 || scheduler.calls() != 1 {
		t.Fatalf("after restart family counts = vuln %d malicious %d lifecycle %d reputation %d feed %d scheduler %d, want 2/2/2/2/2/1",
			len(store.vulnerabilityQueriesSnapshot()), len(store.maliciousQueriesSnapshot()), len(store.lifecycleQueriesSnapshot()), len(store.reputationQueries), store.feedStatusListCalls, scheduler.calls())
	}

	third := httptest.NewRecorder()
	h2.HandleCheck(third, f076CheckRequest(key, "corr-restart-cache"))
	if third.Code != http.StatusOK {
		t.Fatalf("cached status = %d, want 200: %s", third.Code, third.Body.String())
	}
	if third.Body.String() != second.Body.String() {
		t.Fatalf("cached response changed:\nsecond: %s\nthird: %s", second.Body.String(), third.Body.String())
	}
	if store.lookupCalls != 5 || store.scanLogInsertCalls != 1 || len(store.vulnerabilityQueriesSnapshot()) != 2 || len(store.maliciousQueriesSnapshot()) != 2 || len(store.lifecycleQueriesSnapshot()) != 2 || len(store.reputationQueries) != 2 || store.feedStatusListCalls != 2 || scheduler.calls() != 1 {
		t.Fatalf("cache-hit counts changed: lookups %d inserts %d vuln %d malicious %d lifecycle %d reputation %d feed %d scheduler %d",
			store.lookupCalls, store.scanLogInsertCalls, len(store.vulnerabilityQueriesSnapshot()), len(store.maliciousQueriesSnapshot()), len(store.lifecycleQueriesSnapshot()), len(store.reputationQueries), store.feedStatusListCalls, scheduler.calls())
	}
}

func TestHandleCheckMaliciousBatchFailureAbortsWithoutPersistenceOrScheduling(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("malicious batch unavailable")
	store := &f076MaliciousFailureStore{
		stubStore:         &stubStore{},
		vulnerabilityDone: make(chan struct{}),
		maliciousErr:      sentinel,
	}
	scheduler := &f076CountingScheduler{}
	h := NewHandlerWithBlockThreshold(store, newDiscardLogger(), defaultBlockThreshold)
	h.ConfigureReputationScheduler(scheduler)
	h.ConfigureReversingLabs(config.FeedsConfig{ReversingLabsEnabled: true, ReversingLabsMode: config.FeedModeSelf, ReversingLabsAPIKey: "configured"})
	recorder := httptest.NewRecorder()

	h.HandleCheck(recorder, f076CheckRequest("", "corr-malicious-batch"))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), sentinel.Error()) || strings.Contains(recorder.Body.String(), "private-package") {
		t.Fatalf("response leaked store or package detail: %s", recorder.Body.String())
	}
	if store.scanLogInsertCalls != 0 || len(store.scanLogEntries) != 0 || len(h.checkResponseCache.entries) != 0 || scheduler.calls() != 0 {
		t.Fatalf("failure side effects: inserts %d entries %d cache %d scheduler %d, want zero", store.scanLogInsertCalls, len(store.scanLogEntries), len(h.checkResponseCache.entries), scheduler.calls())
	}
}

func TestHandlePackageDetailKeepsCoreFindingsWhenVersionedReputationLookupFails(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	marker := &struct{}{}
	core := domain.Finding{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM, Type: domain.FindingTypeVulnerability, Severity: domain.SeverityHigh, AdvisoryID: "CVE-core", Title: "Core finding", Source: "osv"}
	store := &f076VersionedReputationFailureStore{
		stubStore: &stubStore{vulnFindings: []domain.Finding{core}, reputationErr: errors.New("safe cache failure")},
	}
	h := newLogCaptureHandler(store, &logs)
	h.ConfigureReversingLabs(config.FeedsConfig{ReversingLabsEnabled: true, ReversingLabsMode: config.FeedModeSelf})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash?version=4.17.21&secret=query-value", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("rest", "lodash")
	req = req.WithContext(context.WithValue(req.Context(), f076ReputationContextKey{}, marker))
	req = withCorrelationID(req, "corr-versioned-reputation")
	recorder := httptest.NewRecorder()

	h.HandlePackageDetail(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response PackageDetailResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !reflect.DeepEqual(response.Findings, []domain.Finding{core}) {
		t.Fatalf("findings = %#v, want core finding only", response.Findings)
	}
	if len(store.reputationQueries) != 1 || !reflect.DeepEqual(store.reputationQueries[0].packages, []PackageLookup{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}) || store.reputationQueries[0].source != "reversinglabs" {
		t.Fatalf("reputation queries = %#v, want exact versioned ReversingLabs query", store.reputationQueries)
	}
	if store.gotContext != marker {
		t.Fatal("versioned reputation lookup did not receive the request context")
	}
	requireLogField(t, &logs, "correlation_id", "corr-versioned-reputation")
	if !strings.Contains(logs.String(), "optional reputation lookup failed") || strings.Contains(logs.String(), "query-value") {
		t.Fatalf("optional failure log is missing its stable message or leaked query data: %s", logs.String())
	}
}

func TestHandleCheckRejectsOverlengthIdempotencyKeyWithoutStoreEffects(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	recorder := httptest.NewRecorder()

	h.HandleCheck(recorder, f076CheckRequest(strings.Repeat("a", maxIdempotencyKeyLength+1), "corr-long-key"))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), fmt.Sprintf("exceeds %d characters", maxIdempotencyKeyLength)) {
		t.Fatalf("body = %q, want bounded key-length error", recorder.Body.String())
	}
	if len(store.vulnerabilityQueriesSnapshot()) != 0 || len(store.maliciousQueriesSnapshot()) != 0 || len(store.lifecycleQueriesSnapshot()) != 0 || len(store.reputationQueries) != 0 || store.feedStatusListCalls != 0 || store.scanLogInsertCalls != 0 {
		t.Fatalf("overlength key reached store: vuln %d malicious %d lifecycle %d reputation %d feed %d inserts %d",
			len(store.vulnerabilityQueriesSnapshot()), len(store.maliciousQueriesSnapshot()), len(store.lifecycleQueriesSnapshot()), len(store.reputationQueries), store.feedStatusListCalls, store.scanLogInsertCalls)
	}
}

func TestHandleRefreshRejectsBlankProviderSourceBeforeStoreEffects(t *testing.T) {
	t.Parallel()

	store := &stubStore{}
	h := newTestHandler(store)
	h.packageRefresh = &testPackageRefreshProvider{active: true, source: " \t "}
	recorder := httptest.NewRecorder()

	h.handleRefresh(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil), "npm", "lodash")

	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "no active refresh worker") {
		t.Fatalf("response = %d %q, want 409 inactive-worker error", recorder.Code, recorder.Body.String())
	}
	if len(store.packageCheckStatusLookups) != 0 || len(store.enqueuedRefreshJobsSnapshot()) != 0 || len(store.auditEntries) != 0 {
		t.Fatalf("blank source reached store: budget %d jobs %d audits %d", len(store.packageCheckStatusLookups), len(store.enqueuedRefreshJobsSnapshot()), len(store.auditEntries))
	}
}

func TestHandleRefreshClassifiesAuditedEnqueueFailures(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		err         error
		wantMessage string
	}{
		{name: "audit failure", err: fmt.Errorf("wrapped: %w", db.ErrAdminAuditLog), wantMessage: "failed to record audit log"},
		{name: "queue failure", err: errors.New("queue unavailable"), wantMessage: "failed to enqueue refresh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &f076RefreshFailureStore{stubStore: &stubStore{}, err: tc.err}
			h := newTestHandler(store)
			h.ConfigureSocketRefresh(config.FeedsConfig{SocketEnabled: true, SocketMode: config.FeedModeSelf, SocketAPIKey: "configured"})
			recorder := httptest.NewRecorder()

			h.handleRefresh(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil), "npm", "lodash")

			if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), tc.wantMessage) {
				t.Fatalf("response = %d %q, want 500 containing %q", recorder.Code, recorder.Body.String(), tc.wantMessage)
			}
			if store.attempts != 1 || len(store.enqueuedRefreshJobsSnapshot()) != 0 || len(store.auditEntries) != 0 {
				t.Fatalf("enqueue attempts/jobs/audits = %d/%d/%d, want 1/0/0", store.attempts, len(store.enqueuedRefreshJobsSnapshot()), len(store.auditEntries))
			}
		})
	}
}

func TestWriteStreamingJSONForRequestLogsWriteFailureSafely(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	requestPath := "/api/v1/packages/npm/private-package?secret=query-value"
	req := httptest.NewRequest(http.MethodGet, requestPath, nil)
	req = withCorrelationID(req, "corr-stream-write")
	req = requestWithLogger(req, logger)
	writer := &f076FailingWriter{err: errors.New("short write")}

	writeStreamingJSONForRequest(writer, req, http.StatusAccepted, map[string]string{"status": "ok"})

	if writer.statusCode != http.StatusAccepted {
		t.Fatalf("committed status = %d, want %d", writer.statusCode, http.StatusAccepted)
	}
	if got := writer.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if writer.Header().Get("Cache-Control") != "no-store" || writer.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %#v", writer.Header())
	}
	if !strings.Contains(logs.String(), "failed to stream JSON response") {
		t.Fatalf("log missing stable failure message: %s", logs.String())
	}
	requireLogField(t, &logs, "correlation_id", "corr-stream-write")
	requireLogField(t, &logs, "path", logsafe.RequestPathLabel(req.URL.Path))
	if strings.Contains(logs.String(), "private-package") || strings.Contains(logs.String(), "query-value") || strings.Contains(logs.String(), requestPath) {
		t.Fatalf("stream failure log leaked dynamic path or query: %s", logs.String())
	}
}

func TestHandleRefreshBodyReadFailureIsSanitizedBeforeStoreEffects(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	secret := "reader-secret-value"
	store := &stubStore{}
	h := newLogCaptureHandler(store, &logs)
	provider := &f076CountingRefreshProvider{}
	h.packageRefresh = provider
	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil)
	req.Body = &f076FailingReadCloser{err: errors.New(secret)}
	req.ContentLength = -1
	req = withCorrelationID(req, "corr-refresh-read")
	recorder := httptest.NewRecorder()

	h.handleRefresh(recorder, req, "npm", "lodash")

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "invalid request body") || strings.Contains(recorder.Body.String(), secret) || strings.Contains(logs.String(), secret) {
		t.Fatalf("read failure was not sanitized; body=%q logs=%s", recorder.Body.String(), logs.String())
	}
	if provider.activeCalls != 0 || provider.supportsCalls != 0 || provider.sourceCalls != 0 || len(store.packageCheckStatusLookups) != 0 || len(store.enqueuedRefreshJobsSnapshot()) != 0 || len(store.auditEntries) != 0 {
		t.Fatalf("read failure side effects: provider active/support/source %d/%d/%d budget %d jobs %d audits %d",
			provider.activeCalls, provider.supportsCalls, provider.sourceCalls, len(store.packageCheckStatusLookups), len(store.enqueuedRefreshJobsSnapshot()), len(store.auditEntries))
	}
}

func TestHandlerNilReceiversAndConfigurationFallbacks(t *testing.T) {
	t.Parallel()

	var nilHandler *Handler
	nilHandler.ConfigureScanLogIdentityMode(config.ScanLogIdentityModeNone)
	nilHandler.ConfigureReputationScheduler(&f076CountingScheduler{})
	nilHandler.ConfigurePackageRefreshProvider(newTestPackageRefreshProvider())
	nilHandler.ConfigureBackgroundContext(context.Background())
	nilHandler.ConfigureSocketRefresh(config.FeedsConfig{})
	if _, ok := nilHandler.cachedCheckResponse("stored", "digest"); ok {
		t.Fatal("nil handler returned a cached response")
	}
	nilHandler.cacheCheckResponse("stored", "digest", http.StatusOK, 1, []byte("body"))
	if got := nilHandler.effectiveCheckLookupTimeout(); got != checkLookupTimeout {
		t.Fatalf("nil handler lookup timeout = %s, want %s", got, checkLookupTimeout)
	}
	if nilHandler.backgroundContext() == nil {
		t.Fatal("nil handler returned a nil background context")
	}

	h := NewHandlerWithBlockThreshold(&stubStore{}, newDiscardLogger(), defaultBlockThreshold)
	h.ConfigureScanLogIdentityMode(config.ScanLogIdentityMode("invalid"))
	if h.scanLogIdentityMode != config.ScanLogIdentityModeFull {
		t.Fatalf("invalid identity mode became %q, want full", h.scanLogIdentityMode)
	}
	h.ConfigureBackgroundContext(nil) //nolint:staticcheck // SA1012: the nil-context fallback is under test.
	if h.backgroundCtx == nil || h.backgroundContext() == nil {
		t.Fatal("nil background configuration did not install context.Background")
	}
	h.checkResponseCache = nil
	if _, ok := h.cachedCheckResponse("stored", "digest"); ok {
		t.Fatal("handler without cache returned a cached response")
	}
	h.cacheCheckResponse("stored", "digest", http.StatusOK, 1, []byte("body"))
	h.checkLookupTimeout = 0
	if got := h.effectiveCheckLookupTimeout(); got != checkLookupTimeout {
		t.Fatalf("nonpositive lookup timeout = %s, want %s", got, checkLookupTimeout)
	}
	h.backgroundCtx = nil
	if h.backgroundContext() == nil {
		t.Fatal("handler with nil background context returned nil")
	}
}

func TestScanLogIdentityModeFromEnvFallsBackOnInvalidValue(t *testing.T) {
	t.Setenv("PACKMON_SCAN_LOG_IDENTITY_MODE", "employee")
	if got := scanLogIdentityModeFromEnv(); got != config.ScanLogIdentityModeFull {
		t.Fatalf("scan log identity mode = %q, want full", got)
	}
}

func TestHandlerValidationHelpersRejectMalformedBoundaries(t *testing.T) {
	t.Parallel()

	for _, version := range []string{
		"",
		strings.Repeat("1", maxScanLogClientVersionLength+1),
		"1.2",
		"1..3",
		"1.02.3",
		"1.x.3",
		"1.2.3-",
		"1.2.3-alpha..one",
		"1.2.3-alpha/one",
		"1.2.3+",
		"1.2.3+build..one",
		"1.2.3+build/one",
	} {
		if validScanLogClientVersion(version) {
			t.Errorf("validScanLogClientVersion(%q) = true, want false", version)
		}
	}
	for _, version := range []string{"0.0.0", "1.2.3-alpha.1", "1.2.3+build-7", "1.2.3-alpha+build.7"} {
		if !validScanLogClientVersion(version) {
			t.Errorf("validScanLogClientVersion(%q) = false, want true", version)
		}
	}
	for _, number := range []string{"", "01", "1x"} {
		if validSemVerNumber(number) {
			t.Errorf("validSemVerNumber(%q) = true, want false", number)
		}
	}
	for _, identifiers := range []string{"", ".alpha", "alpha.", "alpha..one", "alpha_one"} {
		if validSemVerIdentifierList(identifiers) {
			t.Errorf("validSemVerIdentifierList(%q) = true, want false", identifiers)
		}
	}

	if got := scanLogIdempotencyLookupKeys(" ", "raw"); got != nil {
		t.Errorf("blank stored lookup keys = %#v, want nil", got)
	}
	if got := scanLogIdempotencyLookupKeys("stored", " "); !reflect.DeepEqual(got, []string{"stored"}) {
		t.Errorf("stored-only lookup keys = %#v", got)
	}
	if got := scanLogIdempotencyLookupKeys("stored", "stored"); !reflect.DeepEqual(got, []string{"stored"}) {
		t.Errorf("equal lookup keys = %#v", got)
	}
	if got := scanLogIdempotencyLookupKeys(" stored ", " raw "); !reflect.DeepEqual(got, []string{"stored", "raw"}) {
		t.Errorf("dual lookup keys = %#v", got)
	}
	if got := scanLogIdempotencyKey(" \t "); got != "" {
		t.Errorf("blank idempotency hash = %q, want empty", got)
	}
	if got := scanLogIdempotencyKey(" raw-key "); !strings.HasPrefix(got, "sha256:") || len(got) != len("sha256:")+64 || strings.Contains(got, "raw-key") {
		t.Errorf("idempotency hash = %q, want opaque SHA-256", got)
	}
	if got := scanLogPathTail("repository"); got != "repository" {
		t.Errorf("path tail without separators = %q", got)
	}
	if got := scanLogPathTail(`C:\private\repository\`); got != "repository" {
		t.Errorf("Windows path tail = %q, want repository", got)
	}
}

var (
	_ Store         = (*f076LookupFailureStore)(nil)
	_ Store         = (*f076DurableStore)(nil)
	_ Store         = (*f076MaliciousFailureStore)(nil)
	_ Store         = (*f076VersionedReputationFailureStore)(nil)
	_ Store         = (*f076RefreshFailureStore)(nil)
	_ io.ReadCloser = (*f076FailingReadCloser)(nil)
)
