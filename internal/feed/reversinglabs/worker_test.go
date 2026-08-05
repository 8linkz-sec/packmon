package reversinglabs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	feedqueue "github.com/8linkz-sec/packmon/internal/feed"
)

type fakeStore struct {
	due                 []db.PackageReputation
	upserts             []db.PackageReputation
	dequeued            *db.RefreshJob
	dequeueErr          error
	listDueBlock        chan struct{}
	completeErr         error
	completedJob        int
	completedClaim      *time.Time
	completedErr        error
	completeCtxErr      error
	dequeueDeadlineSet  bool
	dequeueDeadline     time.Time
	completeDeadlineSet bool
	completeDeadline    time.Time
	resetDeadlineSet    bool
	resetDeadline       time.Time
	resetCount          int
	resetErr            error
	resetSource         string
	resetCh             chan struct{}
	dequeueCalled       int
	prunedSource        string
	prunedOlder         time.Duration
	prunedCount         int
	pruneErr            error
}

type reversingLabsRoundTripFunc func(*http.Request) (*http.Response, error)

func (f reversingLabsRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type reversingLabsRecordingMetricsRecorder struct {
	queueErrors    map[string]int
	stuckRecovered int
	jobsCompleted  map[string]int
}

func newReversingLabsRecordingMetricsRecorder() *reversingLabsRecordingMetricsRecorder {
	return &reversingLabsRecordingMetricsRecorder{
		queueErrors:   make(map[string]int),
		jobsCompleted: make(map[string]int),
	}
}

func (r *reversingLabsRecordingMetricsRecorder) IncFeedSyncTimeout(string) {}

func (r *reversingLabsRecordingMetricsRecorder) IncQueueError(source string) {
	r.queueErrors[source]++
}

func (r *reversingLabsRecordingMetricsRecorder) AddQueueStuckRecovered(count int) {
	r.stuckRecovered += count
}

func (r *reversingLabsRecordingMetricsRecorder) IncQueueJobCompleted(source, result string) {
	r.jobsCompleted[source+":"+result]++
}

func assertReversingLabsJSONLogIntField(t *testing.T, output, msg, field string, want int) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if entry["msg"] != msg {
			continue
		}
		got, ok := entry[field].(float64)
		if !ok {
			t.Fatalf("log %q missing numeric %q field in:\n%s", msg, field, output)
		}
		if int(got) != want {
			t.Fatalf("log %q %s = %v, want %d; logs:\n%s", msg, field, got, want, output)
		}
		return
	}
	t.Fatalf("log message %q not found in:\n%s", msg, output)
}

func assertReversingLabsRateLimit(t *testing.T, worker *Worker, wantTokens, wantLimit int) {
	t.Helper()
	state := worker.Snapshot()
	if state.Tokens != wantTokens || state.Limit != wantLimit {
		t.Fatalf("rate limit tokens = %d/%d, want %d/%d", state.Tokens, state.Limit, wantTokens, wantLimit)
	}
}

func assertReversingLabsTokens(t *testing.T, worker *Worker, want int) {
	t.Helper()
	state := worker.Snapshot()
	if state.Tokens != want {
		t.Fatalf("tokens = %d, want %d", state.Tokens, want)
	}
}

func (s *fakeStore) DequeueRefresh(ctx context.Context, _ string) (*db.RefreshJob, error) {
	s.dequeueCalled++
	if deadline, ok := ctx.Deadline(); ok {
		s.dequeueDeadlineSet = true
		s.dequeueDeadline = deadline
	}
	return claimReversingLabsTestJob(s.dequeued), s.dequeueErr
}

func claimReversingLabsTestJob(job *db.RefreshJob) *db.RefreshJob {
	if job == nil {
		return nil
	}
	if job.ProcessedAt == nil {
		now := time.Now().UTC()
		job.ProcessedAt = &now
	}
	job.Status = "processing"
	return job
}

func (s *fakeStore) CompleteClaimedRefresh(ctx context.Context, id int, claimedAt *time.Time, err error) error {
	s.completeCtxErr = ctx.Err()
	if deadline, ok := ctx.Deadline(); ok {
		s.completeDeadlineSet = true
		s.completeDeadline = deadline
	}
	s.completedJob = id
	s.completedClaim = claimedAt
	s.completedErr = err
	return s.completeErr
}

func (s *fakeStore) ResetStuckJobs(ctx context.Context, source string, _ time.Duration) (int, error) {
	s.resetSource = source
	if deadline, ok := ctx.Deadline(); ok {
		s.resetDeadlineSet = true
		s.resetDeadline = deadline
	}
	if s.resetCh != nil {
		select {
		case <-s.resetCh:
		default:
			close(s.resetCh)
		}
	}
	return s.resetCount, s.resetErr
}

func (s *fakeStore) ListDuePackageReputations(ctx context.Context, _, _, _ string, _ int) ([]db.PackageReputation, error) {
	if s.listDueBlock != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.listDueBlock:
		}
	}
	return append([]db.PackageReputation(nil), s.due...), nil
}

func (s *fakeStore) UpsertPackageReputation(_ context.Context, rep *db.PackageReputation) error {
	s.upserts = append(s.upserts, *rep)
	return nil
}

func (s *fakeStore) PrunePackageReputation(_ context.Context, source string, olderThan time.Duration) (int, error) {
	s.prunedSource = source
	s.prunedOlder = olderThan
	return s.prunedCount, s.pruneErr
}

func TestProcessNextJobUpdatesCompletedThroughputTelemetry(t *testing.T) {
	recorder := newReversingLabsRecordingMetricsRecorder()
	successStore := &fakeStore{
		dequeued: &db.RefreshJob{ID: 1179, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	successWorker := newWorker(successStore, "token", nil, WithRateLimit(1), WithMetricsRecorder(recorder))

	successWorker.processNextJob(context.Background())

	if got := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultSuccess]; got != 1 {
		t.Fatalf("completed success counter = %d, want 1", got)
	}

	errorStore := &fakeStore{
		dequeued: &db.RefreshJob{ID: 1180, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
		due: []db.PackageReputation{{
			Ecosystem: "npm",
			Name:      "left-pad",
			Version:   "1.0.0",
			Source:    FeedName,
		}},
	}
	errorWorker := newWorker(errorStore, "token", nil,
		WithRateLimit(1),
		WithMetricsRecorder(recorder),
		WithHTTPClient(&http.Client{Transport: reversingLabsRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("lookup down")
		})}),
	)

	errorWorker.processNextJob(context.Background())

	if got := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultError]; got != 1 {
		t.Fatalf("completed error counter = %d, want 1", got)
	}

	rateSuccessBefore := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultSuccess]
	rateErrorBefore := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultError]
	rateStore := &fakeStore{
		dequeued: &db.RefreshJob{ID: 1181, Ecosystem: "npm", Name: "rate-limited", Source: FeedName},
		due: []db.PackageReputation{{
			Ecosystem: "npm",
			Name:      "rate-limited",
			Version:   "1.0.0",
			Source:    FeedName,
		}},
	}
	rateWorker := newWorker(rateStore, "token", nil,
		WithRateLimit(1),
		WithMetricsRecorder(recorder),
		WithHTTPClient(&http.Client{Transport: reversingLabsRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})}),
	)

	rateWorker.processNextJob(context.Background())

	if rateStore.completedJob != 0 {
		t.Fatalf("completedJob = %d, want rate-limited job left processing", rateStore.completedJob)
	}
	if got := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultSuccess]; got != rateSuccessBefore {
		t.Fatalf("completed success counter changed after rate limit: got %d, want %d", got, rateSuccessBefore)
	}
	if got := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultError]; got != rateErrorBefore {
		t.Fatalf("completed error counter changed after rate limit: got %d, want %d", got, rateErrorBefore)
	}
}

func TestLookupBatchRejectsHTTPSDowngradeRedirect(t *testing.T) {
	t.Parallel()

	var targetReached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetReached.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"community":{"packages":[]}}`))
	}))
	defer target.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/find/packages?compact=true", http.StatusFound)
	}))
	defer source.Close()

	worker := newWorker(&fakeStore{}, "token", slog.Default(),
		WithBaseURL(source.URL),
		WithHTTPClient(source.Client()),
	)

	_, err := worker.lookupBatch(context.Background(), []db.PackageReputation{{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.0.0",
		Source:    FeedName,
	}})
	if err == nil || !strings.Contains(err.Error(), "refusing redirect from https to http") {
		t.Fatalf("lookupBatch() error = %v, want HTTPS downgrade redirect refusal", err)
	}
	if got := targetReached.Load(); got != 0 {
		t.Fatalf("downgrade redirect target reached %d time(s), want 0", got)
	}
}

func TestProcessNextJobUsesQueueOperationDeadlines(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		dequeued: &db.RefreshJob{ID: 44, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	worker := newWorker(store, "token", slog.Default(), WithRateLimit(1))

	worker.processNextJob(context.Background())

	assertReversingLabsDeadlineSoon(t, "reset stuck jobs", store.resetDeadlineSet, store.resetDeadline)
	assertReversingLabsDeadlineSoon(t, "dequeue refresh", store.dequeueDeadlineSet, store.dequeueDeadline)
	assertReversingLabsDeadlineSoon(t, "complete refresh", store.completeDeadlineSet, store.completeDeadline)
}

func assertReversingLabsDeadlineSoon(t *testing.T, operation string, ok bool, deadline time.Time) {
	t.Helper()
	if !ok {
		t.Fatalf("%s context has no deadline", operation)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 3*time.Second {
		t.Fatalf("%s deadline remaining = %v, want bounded positive deadline within 3s", operation, remaining)
	}
}

func TestWorkerOptionsAndName(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Timeout: time.Second}
	w := newWorker(&fakeStore{}, "token", nil,
		WithHTTPClient(httpClient),
		WithBaseURL(" https://example.test/base/ "),
		WithPollInterval(time.Second),
		WithLookupTTL(2*time.Hour),
		WithBatchSize(20),
		WithJobTimeout(15*time.Second),
		WithCacheRetention(48*time.Hour),
		WithRateLimit(12),
	)

	if w.Name() != FeedName {
		t.Fatalf("Name() = %q, want %q", w.Name(), FeedName)
	}
	if w.httpClient == httpClient || w.httpClient.Timeout != httpClient.Timeout {
		t.Fatalf("WithHTTPClient did not preserve provided client settings: %+v", w.httpClient)
	}
	if err := w.httpClient.CheckRedirect(
		&http.Request{URL: mustReversingLabsTestURL(t, "http://example.test/next")},
		[]*http.Request{{URL: mustReversingLabsTestURL(t, "https://example.test/start")}},
	); err == nil || !strings.Contains(err.Error(), "https to http") {
		t.Fatalf("worker redirect policy error = %v, want HTTPS downgrade refusal", err)
	}
	if w.baseURL != "https://example.test/base" {
		t.Fatalf("baseURL = %q, want trimmed URL", w.baseURL)
	}
	if w.pollInterval != time.Second || w.lookupTTL != 2*time.Hour {
		t.Fatalf("intervals = %v/%v, want configured values", w.pollInterval, w.lookupTTL)
	}
	if w.batchSize != maxBatchSize {
		t.Fatalf("batchSize = %d, want cap %d", w.batchSize, maxBatchSize)
	}
	if w.jobTimeout != 15*time.Second {
		t.Fatalf("jobTimeout = %v, want 15s", w.jobTimeout)
	}
	if w.cacheRetention != 48*time.Hour {
		t.Fatalf("cacheRetention = %v, want 48h", w.cacheRetention)
	}
	assertReversingLabsRateLimit(t, w, 12, 12)
}

func mustReversingLabsTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return u
}

func TestWorkersShareRateLimitState(t *testing.T) {
	t.Parallel()

	limiter := NewRateLimiter(1)
	first := newWorker(&fakeStore{}, "token", nil, WithRateLimiter(limiter))
	second := newWorker(&fakeStore{}, "token", nil, WithRateLimiter(limiter))

	if !first.Acquire() {
		t.Fatal("first worker could not acquire initial shared token")
	}
	if second.Acquire() {
		t.Fatal("second worker acquired a fresh token from a shared exhausted bucket")
	}
	first.Return()
	if !second.Acquire() {
		t.Fatal("second worker could not acquire token returned by first worker")
	}
}

type dbStoreFake struct {
	db.Store
}

func (*dbStoreFake) DequeueRefresh(context.Context, string) (*db.RefreshJob, error) {
	return nil, nil
}

func (*dbStoreFake) CompleteClaimedRefresh(context.Context, int, *time.Time, error) error {
	return nil
}

func (*dbStoreFake) ResetStuckJobs(context.Context, string, time.Duration) (int, error) {
	return 0, nil
}

func (*dbStoreFake) ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error) {
	return nil, nil
}

func (*dbStoreFake) UpsertPackageReputation(context.Context, *db.PackageReputation) error {
	return nil
}

func TestNewWorkerWrapperAndOptionGuardBranches(t *testing.T) {
	t.Parallel()

	store := &dbStoreFake{}
	w := NewWorker(store, "token", nil,
		WithHTTPClient(nil),
		WithBaseURL(" "),
		WithPollInterval(0),
		WithLookupTTL(0),
		WithBatchSize(0),
		WithJobTimeout(0),
		WithCacheRetention(0),
		WithRateLimit(0),
	)

	if w.store != store {
		t.Fatalf("worker store = %T, want wrapper store", w.store)
	}
	if w.baseURL != DefaultBaseURL {
		t.Fatalf("baseURL = %q, want default", w.baseURL)
	}
	if w.pollInterval != defaultPollInterval || w.lookupTTL != defaultLookupTTL {
		t.Fatalf("defaults = %v/%v, want %v/%v", w.pollInterval, w.lookupTTL, defaultPollInterval, defaultLookupTTL)
	}
	state := w.Snapshot()
	if w.batchSize != defaultBatchSize || state.Tokens != defaultRateLimitPerHour || state.Limit != defaultRateLimitPerHour {
		t.Fatalf("batch/tokens = %d/%d/%d, want defaults", w.batchSize, state.Tokens, state.Limit)
	}

	w = NewWorker(store, "token", nil, WithBatchSize(3), WithRateLimit(7))
	state = w.Snapshot()
	if w.batchSize != 3 || state.Tokens != 7 || state.Limit != 7 {
		t.Fatalf("valid option values = batch %d tokens %d/%d", w.batchSize, state.Tokens, state.Limit)
	}
}

func TestPruneCacheUsesRetentionPolicy(t *testing.T) {
	t.Parallel()

	store := &fakeStore{prunedCount: 3}
	worker := newWorker(store, "token", slog.Default(), WithCacheRetention(48*time.Hour))
	worker.pruneCache(context.Background())

	if store.prunedSource != FeedName {
		t.Fatalf("prunedSource = %q, want %q", store.prunedSource, FeedName)
	}
	if store.prunedOlder != 48*time.Hour {
		t.Fatalf("prunedOlder = %v, want 48h", store.prunedOlder)
	}
}

func TestProcessNextJobUsesPerJobDeadline(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		dequeued:     &db.RefreshJob{ID: 99, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
		listDueBlock: make(chan struct{}),
	}
	worker := newWorker(store, "token", slog.Default(), WithJobTimeout(10*time.Millisecond))
	worker.processNextJob(context.Background())

	if store.completedJob != 99 {
		t.Fatalf("completedJob = %d, want 99", store.completedJob)
	}
	if store.completedClaim == nil {
		t.Fatal("completedClaim = nil, want dequeued processed_at claim")
	}
	if !errors.Is(store.completedErr, context.DeadlineExceeded) {
		t.Fatalf("completedErr = %v, want context deadline exceeded", store.completedErr)
	}
}

func TestProcessNextJobLeavesRateLimitedJobForRetry(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		dequeued: &db.RefreshJob{ID: 100, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
		due: []db.PackageReputation{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	worker := newWorker(store, "token", slog.Default(), WithBaseURL(server.URL))
	worker.processNextJob(context.Background())

	if store.completedJob != 0 {
		t.Fatalf("completedJob = %d, want rate-limited job left processing for retry", store.completedJob)
	}
	if len(store.upserts) != 0 {
		t.Fatalf("upserts = %+v, want none for transient rate limit", store.upserts)
	}
}

func TestProcessNextJobLogsJobIDOnRateLimitAndFailureWarnings(t *testing.T) {
	t.Parallel()

	t.Run("rate limited", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{
			dequeued: &db.RefreshJob{ID: 100, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
			due: []db.PackageReputation{
				{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
			},
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		t.Cleanup(server.Close)

		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		worker := newWorker(store, "token", logger, WithBaseURL(server.URL), WithRateLimit(1))

		worker.processNextJob(context.Background())

		assertReversingLabsJSONLogIntField(t, logs.String(), "ReversingLabs check rate limited; leaving job processing for retry", "job_id", 100)
	})

	t.Run("failed", func(t *testing.T) {
		t.Parallel()

		store := &fakeStore{
			dequeued: &db.RefreshJob{ID: 101, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
			due: []db.PackageReputation{
				{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
			},
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(server.Close)

		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		worker := newWorker(store, "token", logger, WithBaseURL(server.URL), WithRateLimit(1))

		worker.processNextJob(context.Background())

		assertReversingLabsJSONLogIntField(t, logs.String(), "ReversingLabs check failed", "job_id", 101)
	})
}

func TestSearchIncidentJSONBranches(t *testing.T) {
	t.Parallel()

	var pkg searchPackageData
	err := json.Unmarshal([]byte(`{"incidents":{"malware":"malware","removal":{"type":"removal"},"counter":2}}`), &pkg)
	if err != nil {
		t.Fatalf("unmarshal incidents object: %v", err)
	}
	if pkg.Incidents["malware"].Type != "malware" || pkg.Incidents["removal"].Type != "removal" || pkg.Incidents["counter"].Count != 2 {
		t.Fatalf("incidents = %+v", pkg.Incidents)
	}

	var incidents searchIncidents
	if err := json.Unmarshal([]byte(`null`), &incidents); err != nil || incidents != nil {
		t.Fatalf("unmarshal null incidents = %+v, %v", incidents, err)
	}
	if err := json.Unmarshal([]byte(`"bad"`), &incidents); err == nil || !strings.Contains(err.Error(), "invalid ReversingLabs response schema") {
		t.Fatalf("unmarshal string incidents error = %v", err)
	}

	var incident searchIncident
	if err := json.Unmarshal([]byte(`null`), &incident); err != nil {
		t.Fatalf("unmarshal null incident: %v", err)
	}
	if err := json.Unmarshal([]byte(`{bad`), &incident); err == nil {
		t.Fatal("unmarshal malformed incident object error = nil")
	}
}

func TestWorkerRunExitsWithoutAPIKeyAndHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	if err := newWorker(&fakeStore{}, " ", slog.Default()).Run(context.Background()); err != nil {
		t.Fatalf("Run without API key error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newWorker(&fakeStore{}, "token", slog.Default(), WithPollInterval(time.Hour)).Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run canceled error = %v, want context.Canceled", err)
	}
}

func TestRunDoesNotResetStuckJobsBeforeFirstPoll(t *testing.T) {
	t.Parallel()

	resetCh := make(chan struct{})
	store := &fakeStore{resetCh: resetCh}
	poller := newManualPollTicker()
	worker := newWorker(store, "token", slog.Default(), WithPollInterval(time.Hour), WithRateLimit(1))
	worker.newPollTicker = func(time.Duration) pollTicker {
		return poller
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()

	select {
	case <-resetCh:
		cancel()
		t.Fatal("Run reset stuck jobs before the first poll")
	case <-poller.ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Run did not start waiting for the first poll")
	}

	select {
	case <-resetCh:
		cancel()
		t.Fatal("Run reset stuck jobs before the first poll")
	default:
	}

	poller.tick()
	select {
	case <-resetCh:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Run did not reset stuck jobs after the first poll")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not exit after cancellation")
	}
	if store.resetSource != FeedName {
		t.Fatalf("reset source = %q, want %q after first poll", store.resetSource, FeedName)
	}
}

type manualPollTicker struct {
	ticks chan time.Time
	ready chan struct{}
}

func newManualPollTicker() *manualPollTicker {
	return &manualPollTicker{
		ticks: make(chan time.Time, 1),
		ready: make(chan struct{}),
	}
}

func (t *manualPollTicker) C() <-chan time.Time {
	select {
	case <-t.ready:
	default:
		close(t.ready)
	}
	return t.ticks
}

func (t *manualPollTicker) Stop() {}

func (t *manualPollTicker) tick() {
	t.ticks <- time.Now()
}

func TestProcessNextJobTokenAndCompletionBranches(t *testing.T) {
	t.Parallel()

	noTokenStore := &fakeStore{}
	noTokenWorker := newWorker(noTokenStore, "token", slog.Default(), WithRateLimit(1))
	noTokenWorker.Drain()
	noTokenWorker.processNextJob(context.Background())
	if noTokenStore.dequeueCalled != 0 {
		t.Fatalf("dequeueCalled = %d, want 0 without token", noTokenStore.dequeueCalled)
	}

	noJobStore := &fakeStore{}
	noJobWorker := newWorker(noJobStore, "token", slog.Default(), WithRateLimit(1))
	noJobWorker.processNextJob(context.Background())
	if noJobStore.dequeueCalled != 1 {
		t.Fatalf("dequeueCalled = %d, want 1", noJobStore.dequeueCalled)
	}
	assertReversingLabsTokens(t, noJobWorker, 1)

	dequeueErrStore := &fakeStore{dequeueErr: errors.New("queue down")}
	dequeueErrWorker := newWorker(dequeueErrStore, "token", slog.Default(), WithRateLimit(1))
	dequeueErrWorker.processNextJob(context.Background())
	if dequeueErrStore.completedJob != 0 {
		t.Fatalf("completedJob = %d, want no completion on dequeue error", dequeueErrStore.completedJob)
	}
	assertReversingLabsTokens(t, dequeueErrWorker, 1)

	t.Run("dequeue error logs are suppressed", func(t *testing.T) {
		store := &fakeStore{dequeueErr: errors.New("queue down")}
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		worker := newWorker(store, "token", logger, WithRateLimit(2))

		worker.processNextJob(context.Background())
		worker.processNextJob(context.Background())

		output := logs.String()
		if got := strings.Count(output, `"level":"ERROR"`); got != 1 {
			t.Fatalf("ERROR dequeue logs = %d, want 1; logs=%s", got, output)
		}
		if !strings.Contains(output, `"suppressed":true`) {
			t.Fatalf("repeated dequeue log missing suppressed marker: %s", output)
		}
	})

	jobStore := &fakeStore{
		dequeued: &db.RefreshJob{ID: 42, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
		due: []db.PackageReputation{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"community":{"errors":[{"uuid":"npm:left-pad@1.3.0","error":{"code":404,"info":"not found"}}]}}`))
	}))
	defer server.Close()
	jobWorker := newWorker(jobStore, "token", slog.Default(), WithBaseURL(server.URL))
	jobWorker.processNextJob(context.Background())
	if jobStore.completedJob != 42 || jobStore.completedErr != nil {
		t.Fatalf("completed = (%d, %v), want job 42 without error", jobStore.completedJob, jobStore.completedErr)
	}
	if len(jobStore.upserts) != 1 || jobStore.upserts[0].Status != "not_found" {
		t.Fatalf("upserts = %+v, want not_found result", jobStore.upserts)
	}

	canceledStore := &fakeStore{dequeued: &db.RefreshJob{ID: 43, Ecosystem: "npm", Name: "left-pad", Source: FeedName}}
	canceledWorker := newWorker(canceledStore, "token", slog.Default(), WithRateLimit(1))
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledWorker.processNextJob(canceledCtx)
	if canceledStore.completedJob != 43 {
		t.Fatalf("completedJob after canceled worker context = %d, want 43", canceledStore.completedJob)
	}
	if canceledStore.completeCtxErr != nil {
		t.Fatalf("CompleteClaimedRefresh context error = %v, want independent live context", canceledStore.completeCtxErr)
	}
}

func TestProcessNextJobReturnsTokenWhenNoUpstreamRequestWasMade(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		due  []db.PackageReputation
	}{
		{name: "no due reputations"},
		{
			name: "all due reputations unsupported",
			due: []db.PackageReputation{
				{Ecosystem: "go", Name: "github.com/acme/lib", Version: "1.0.0", Source: FeedName, Status: "pending"},
			},
		},
		{
			name: "all due reputations excluded",
			due: []db.PackageReputation{
				{Ecosystem: "npm", Name: "@internal/pkg", Version: "1.0.0", Source: FeedName, Status: "pending"},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &fakeStore{
				dequeued: &db.RefreshJob{ID: 44, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
				due:      tt.due,
			}
			worker := newWorker(store, "token", slog.Default(), WithRateLimit(1), WithExcludedNamespaces([]string{"npm/@internal/"}))

			worker.processNextJob(context.Background())

			assertReversingLabsTokens(t, worker, 1)
			if store.completedJob != 44 || store.completedErr != nil {
				t.Fatalf("completed = (%d, %v), want no-op job completed without error", store.completedJob, store.completedErr)
			}
		})
	}
}

func TestLookupBatchClassifiesMaliciousRemovedAndClean(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/find/packages" || r.URL.Query().Get("compact") != "true" {
			t.Fatalf("unexpected request URL %s", r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("Authorization = %q, want bearer token", got)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{
			"community": {
				"packages": [
					{"uuid":"npm:left-pad@1.3.0","package":{"identity":{"removed":true}}},
					{"uuid":"pypi:evil@2.0.0","package":{"all_malicious":true}},
					{"uuid":"gem:safe@1.0.0","package":{"identity":{"removed":false}}}
				]
			}
		}`))
	}))
	defer server.Close()

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL), WithLookupTTL(24*time.Hour))
	results, err := w.lookupBatch(context.Background(), []db.PackageReputation{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
		{Ecosystem: "pypi", Name: "evil", Version: "2.0.0", Source: FeedName, Status: "pending"},
		{Ecosystem: "gem", Name: "safe", Version: "1.0.0", Source: FeedName, Status: "pending"},
	})
	if err != nil {
		t.Fatalf("lookupBatch() error = %v", err)
	}

	statuses := map[string]string{}
	for _, rep := range results {
		statuses[rep.Name] = rep.Status
		if rep.NextCheckAt == nil {
			t.Fatalf("%s NextCheckAt = nil, want ttl refresh", rep.Name)
		}
	}
	if statuses["left-pad"] != "removed" {
		t.Fatalf("left-pad status = %q, want removed", statuses["left-pad"])
	}
	if statuses["evil"] != "malicious" {
		t.Fatalf("evil status = %q, want malicious", statuses["evil"])
	}
	if statuses["safe"] != "clean" {
		t.Fatalf("safe status = %q, want clean", statuses["safe"])
	}
}

func TestLookupBatchToleratesNumericIncidentValues(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"community": {
				"packages": [
					{"uuid":"npm:cssesc@3.0.0","package":{"identity":{"removed":false},"incidents":{"malware":0,"removal":0}}},
					{"uuid":"npm:bad@1.0.0","package":{"incidents":{"malware":1}}},
					{"uuid":"npm:gone@1.0.0","package":{"incidents":{"removal":1}}}
				]
			}
		}`))
	}))
	defer server.Close()

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL), WithLookupTTL(24*time.Hour))
	results, err := w.lookupBatch(context.Background(), []db.PackageReputation{
		{Ecosystem: "npm", Name: "cssesc", Version: "3.0.0", Source: FeedName, Status: "pending"},
		{Ecosystem: "npm", Name: "bad", Version: "1.0.0", Source: FeedName, Status: "pending"},
		{Ecosystem: "npm", Name: "gone", Version: "1.0.0", Source: FeedName, Status: "pending"},
	})
	if err != nil {
		t.Fatalf("lookupBatch() error = %v", err)
	}

	statuses := map[string]string{}
	for _, rep := range results {
		statuses[rep.Name] = rep.Status
	}
	if statuses["cssesc"] != "clean" {
		t.Fatalf("cssesc status = %q, want clean", statuses["cssesc"])
	}
	if statuses["bad"] != "clean" {
		t.Fatalf("bad status = %q, want clean", statuses["bad"])
	}
	if statuses["gone"] != "clean" {
		t.Fatalf("gone status = %q, want clean", statuses["gone"])
	}
}

func TestRemovalIncidentsAreNotCurrentRemovedStatus(t *testing.T) {
	t.Parallel()

	if got := removedSignals(searchPackageData{
		Incidents: map[string]searchIncident{
			"removal": {Type: "removal"},
		},
	}); len(got) != 0 {
		t.Fatalf("removedSignals(removal incident) = %#v, want no active removal signal", got)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"community": {
				"packages": [
					{"uuid":"npm:braces@3.0.3","package":{"identity":{"removed":false},"incidents":{"removal":1}}}
				]
			}
		}`))
	}))
	defer server.Close()

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL), WithLookupTTL(24*time.Hour))
	results, err := w.lookupBatch(context.Background(), []db.PackageReputation{{
		Ecosystem: "npm",
		Name:      "braces",
		Version:   "3.0.3",
		Source:    FeedName,
		Status:    "pending",
	}})
	if err != nil {
		t.Fatalf("lookupBatch() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Status != "clean" {
		t.Fatalf("status = %q, want clean for removal incident without current removed marker", results[0].Status)
	}
}

func TestLookupBatchToleratesNumericIncidentsField(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"community": {
				"packages": [
					{"uuid":"npm:cssesc@3.0.0","package":{"identity":{"removed":false},"incidents":0}}
				]
			}
		}`))
	}))
	defer server.Close()

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL), WithLookupTTL(24*time.Hour))
	results, err := w.lookupBatch(context.Background(), []db.PackageReputation{
		{Ecosystem: "npm", Name: "cssesc", Version: "3.0.0", Source: FeedName, Status: "pending"},
	})
	if err != nil {
		t.Fatalf("lookupBatch() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Status != "clean" {
		t.Fatalf("status = %q, want clean", results[0].Status)
	}
}

func TestLookupBatchMapsPackageErrorToNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"community": {
				"errors": [
					{"uuid":"npm:missing@1.0.0","error":{"code":404,"info":"not found"}}
				]
			}
		}`))
	}))
	defer server.Close()

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL), WithLookupTTL(24*time.Hour))
	results, err := w.lookupBatch(context.Background(), []db.PackageReputation{
		{Ecosystem: "npm", Name: "missing", Version: "1.0.0", Source: FeedName, Status: "pending"},
	})
	if err != nil {
		t.Fatalf("lookupBatch() error = %v", err)
	}
	if len(results) != 1 || results[0].Status != "not_found" {
		t.Fatalf("results = %+v, want one not_found row", results)
	}
}

func TestLookupBatchDrainsTokensOnRateLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL), WithLookupTTL(24*time.Hour), WithRateLimit(3))

	results, err := w.lookupBatch(context.Background(), []db.PackageReputation{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
	})
	if err == nil {
		t.Fatal("lookupBatch() error = nil, want rate-limit error")
	}
	if results != nil {
		t.Fatalf("results = %+v, want nil on rate limit", results)
	}
	state := w.Snapshot()
	if state.Tokens != 0 || state.FractionalTokens != 0 {
		t.Fatalf("drained tokens/fractional = %d/%.2f, want 0/0", state.Tokens, state.FractionalTokens)
	}
}

func TestProcessJobMarksUnsupportedWithoutCallingAPI(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()

	store := &fakeStore{
		due: []db.PackageReputation{
			{Ecosystem: "go", Name: "github.com/acme/lib", Version: "1.0.0", Source: FeedName, Status: "pending"},
		},
		dequeued: &db.RefreshJob{ID: 1, Ecosystem: "go", Name: "github.com/acme/lib", Source: FeedName},
	}
	w := newWorker(store, "token", slog.Default(), WithBaseURL(server.URL))

	madeUpstreamRequest, err := w.processJob(context.Background(), store.dequeued)
	if err != nil {
		t.Fatalf("processJob() error = %v", err)
	}
	if madeUpstreamRequest {
		t.Fatal("processJob() made upstream request for unsupported package")
	}
	if called {
		t.Fatal("API was called for unsupported package")
	}
	if len(store.upserts) != 1 || store.upserts[0].Status != "unsupported" || store.upserts[0].NextCheckAt != nil {
		t.Fatalf("upserts = %+v, want terminal unsupported row", store.upserts)
	}
}

func TestProcessJobMarksPrivateNamespaceExcludedWithoutCallingAPI(t *testing.T) {
	t.Parallel()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()

	store := &fakeStore{
		due: []db.PackageReputation{
			{Ecosystem: "npm", Name: "@school/internal", Version: "1.0.0", Source: FeedName, Status: "pending"},
		},
		dequeued: &db.RefreshJob{ID: 1, Ecosystem: "npm", Name: "@school/internal", Source: FeedName},
	}
	w := newWorker(store, "token", slog.Default(),
		WithBaseURL(server.URL),
		WithExcludedNamespaces([]string{" npm/@school/ "}),
	)

	madeUpstreamRequest, err := w.processJob(context.Background(), store.dequeued)
	if err != nil {
		t.Fatalf("processJob() error = %v", err)
	}
	if madeUpstreamRequest {
		t.Fatal("processJob() made upstream request for excluded private namespace")
	}
	if called {
		t.Fatal("API was called for excluded private namespace")
	}
	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %+v, want one terminal unsupported row", store.upserts)
	}
	got := store.upserts[0]
	if got.Ecosystem != "npm" || got.Name != "@school/internal" || got.Version != "1.0.0" {
		t.Fatalf("upserted package = %s/%s@%s, want npm/@school/internal@1.0.0", got.Ecosystem, got.Name, got.Version)
	}
	if got.Status != "unsupported" || got.Summary != "ReversingLabs: package excluded by private namespace policy" {
		t.Fatalf("upsert = %+v, want unsupported private namespace exclusion", got)
	}
	if got.LastCheckedAt == nil || got.NextCheckAt != nil || got.LastError != "" {
		t.Fatalf("upsert = %+v, want terminal checked unsupported row without retry/error", got)
	}
}

func TestProcessJobStoresErrorResultsWhenLookupFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	store := &fakeStore{
		due: []db.PackageReputation{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
			{Ecosystem: "pypi", Name: "stable", Version: "2.0.0", Source: FeedName, Status: "clean"},
		},
		dequeued: &db.RefreshJob{ID: 1, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	w := newWorker(store, "token", slog.Default(), WithBaseURL(server.URL))

	madeUpstreamRequest, err := w.processJob(context.Background(), store.dequeued)
	if err == nil {
		t.Fatal("processJob() error = nil, want lookup error")
	}
	if !madeUpstreamRequest {
		t.Fatal("processJob() madeUpstreamRequest = false, want true for lookup failure")
	}
	if len(store.upserts) != 2 {
		t.Fatalf("upserts = %d, want 2", len(store.upserts))
	}
	if store.upserts[0].Status != "error" || store.upserts[0].LastError == "" || store.upserts[0].NextCheckAt == nil {
		t.Fatalf("first upsert = %+v, want transient error result", store.upserts[0])
	}
	if store.upserts[1].Status != "clean" || store.upserts[1].LastError == "" {
		t.Fatalf("definitive status should be retained with error detail: %+v", store.upserts[1])
	}
}

func TestProcessNextJobStoresTransientErrorOnTransportFailure(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		due: []db.PackageReputation{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
		},
		dequeued: &db.RefreshJob{ID: 13, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	client := &http.Client{
		Transport: reversingLabsRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("lookup data.reversinglabs.invalid: no such host")
		}),
	}
	worker := newWorker(store, "token", slog.Default(),
		WithBaseURL("https://data.reversinglabs.invalid"),
		WithHTTPClient(client),
		WithRateLimit(1),
	)

	worker.processNextJob(context.Background())

	if store.completedJob != 13 {
		t.Fatalf("completedJob = %d, want failed transport job completed", store.completedJob)
	}
	if store.completedClaim == nil {
		t.Fatal("completedClaim = nil, want dequeued processed_at claim")
	}
	if store.completedErr == nil || !strings.Contains(store.completedErr.Error(), "no such host") {
		t.Fatalf("completedErr = %v, want DNS-style transport error", store.completedErr)
	}
	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %d, want one transient reputation error row", len(store.upserts))
	}
	got := store.upserts[0]
	if got.Status != "error" || got.Summary != "ReversingLabs: lookup failed" || got.LastError == "" {
		t.Fatalf("upsert = %+v, want transient error result", got)
	}
	if got.LastCheckedAt == nil || got.NextCheckAt == nil {
		t.Fatalf("upsert timestamps = checked %v next %v, want retry scheduling", got.LastCheckedAt, got.NextCheckAt)
	}
	assertReversingLabsTokens(t, worker, 0)
}

func TestProcessNextJobRedactsLookupTransportErrors(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		due: []db.PackageReputation{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
		},
		dequeued: &db.RefreshJob{ID: 12, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	secretBaseURL := "https://user-secret:pass-secret@data.example.test/private/path?client_secret=query-secret#frag-secret" //nolint:gosec // fake secret-bearing URL verifies redaction.
	client := &http.Client{
		Transport: reversingLabsRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, &url.Error{
				Op:  "Post",
				URL: req.URL.String(),
				Err: errors.New(`dial tcp password=transport-secret C:\Users\Admin\packmon\private.key`),
			}
		}),
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	worker := newWorker(store, "token", logger, WithBaseURL(secretBaseURL), WithHTTPClient(client), WithRateLimit(1))

	worker.processNextJob(context.Background())

	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %d, want transient error result", len(store.upserts))
	}
	if store.completedErr == nil {
		t.Fatal("completedErr = nil, want sanitized lookup error")
	}
	userVisible := store.upserts[0].LastError + "\n" + store.completedErr.Error() + "\n" + logs.String()
	for _, leaked := range []string{
		"user-secret",
		"pass-secret",
		"private/path",
		"query-secret",
		"frag-secret",
		"transport-secret",
		`C:\Users\Admin\packmon\private.key`,
	} {
		if strings.Contains(userVisible, leaked) {
			t.Fatalf("ReversingLabs transport diagnostics leaked %q in:\n%s", leaked, userVisible)
		}
	}
	for _, want := range []string{
		"https://data.example.test/...",
		"password=[redacted]",
		"(redacted-path)",
		"ReversingLabs check failed",
	} {
		if !strings.Contains(userVisible, want) {
			t.Fatalf("ReversingLabs transport diagnostics missing %q in:\n%s", want, userVisible)
		}
	}
}

func TestProcessJobSanitizesMalformedIncidentParseErrors(t *testing.T) {
	t.Parallel()

	leaked := "secret-/var/tmp/packmon/upstream.json"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"community": {
				"packages": [
					{"uuid":"npm:left-pad@1.3.0","package":{"incidents":"` + leaked + `"}}
				]
			}
		}`))
	}))
	defer server.Close()

	store := &fakeStore{
		due: []db.PackageReputation{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
		},
		dequeued: &db.RefreshJob{ID: 1, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	w := newWorker(store, "token", slog.Default(), WithBaseURL(server.URL))

	madeUpstreamRequest, err := w.processJob(context.Background(), store.dequeued)
	if err == nil || !strings.Contains(err.Error(), "invalid ReversingLabs response schema") {
		t.Fatalf("processJob() error = %v, want sanitized schema error", err)
	}
	if !madeUpstreamRequest {
		t.Fatal("processJob() madeUpstreamRequest = false, want true for parse failure after HTTP")
	}
	if strings.Contains(err.Error(), leaked) {
		t.Fatalf("processJob() error leaked raw upstream data: %q", err.Error())
	}
	if len(store.upserts) != 1 {
		t.Fatalf("upserts = %d, want 1 transient error row", len(store.upserts))
	}
	if strings.Contains(store.upserts[0].LastError, leaked) {
		t.Fatalf("LastError leaked raw upstream data: %q", store.upserts[0].LastError)
	}
	if store.upserts[0].Status != "error" || !strings.Contains(store.upserts[0].LastError, "invalid ReversingLabs response schema") {
		t.Fatalf("upsert = %+v, want sanitized transient error row", store.upserts[0])
	}
}

func TestLookupBatchStatusAndResponseErrorBranches(t *testing.T) {
	t.Parallel()

	statusTests := []struct {
		name   string
		status int
		want   string
	}{
		{"unauthorized", http.StatusUnauthorized, "authentication failed"},
		{"forbidden", http.StatusForbidden, "authentication failed"},
		{"payment required", http.StatusPaymentRequired, "capacity limit"},
		{"unexpected", http.StatusTeapot, "unexpected ReversingLabs status"},
	}
	for _, tt := range statusTests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()

			w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL))
			_, err := w.lookupBatch(context.Background(), []db.PackageReputation{
				{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName},
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("lookupBatch() error = %v, want containing %q", err, tt.want)
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer server.Close()
	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL))
	if _, err := w.lookupBatch(context.Background(), []db.PackageReputation{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName},
	}); err == nil || !strings.Contains(err.Error(), "parse response") {
		t.Fatalf("lookupBatch(invalid JSON) error = %v, want parse response", err)
	}
}

func TestLookupBatchSplitsLargeBatchesAnd413FallsBackToSingleRequests(t *testing.T) {
	t.Parallel()

	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if bytesCount := len(body); bytesCount == 0 {
			t.Fatalf("empty request body")
		}
		if calls == 1 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = w.Write([]byte(`{"community":{"packages":[{"uuid":"npm:left-pad@1.0.0","package":{}},{"uuid":"npm:left-pad@2.0.0","package":{}}]}}`))
	}))
	defer server.Close()

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL), WithBatchSize(2))
	results, err := w.lookupBatch(context.Background(), []db.PackageReputation{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Source: FeedName},
		{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0", Source: FeedName},
		{Ecosystem: "npm", Name: "left-pad", Version: "3.0.0", Source: FeedName},
	})
	if err != nil {
		t.Fatalf("lookupBatch() error = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	if calls < 3 {
		t.Fatalf("calls = %d, want split and single fallback calls", calls)
	}
}

func TestProcessNextJobLeaves413FallbackForRetryWhenNoExtraTokens(t *testing.T) {
	t.Parallel()

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = w.Write([]byte(`{"community":{"packages":[{"uuid":"npm:left-pad@1.0.0","package":{}}]}}`))
	}))
	defer server.Close()

	store := &fakeStore{
		due: []db.PackageReputation{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Source: FeedName, Status: "pending"},
			{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0", Source: FeedName, Status: "pending"},
		},
		dequeued: &db.RefreshJob{ID: 77, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	w := newWorker(store, "token", slog.Default(), WithBaseURL(server.URL), WithRateLimit(1))

	w.processNextJob(context.Background())

	if calls != 1 {
		t.Fatalf("ReversingLabs calls = %d, want only initial 413 call without extra local tokens", calls)
	}
	if store.completedJob != 0 {
		t.Fatalf("completedJob = %d, want job left processing for retry", store.completedJob)
	}
	if len(store.upserts) != 0 {
		t.Fatalf("upserts = %+v, want none before retry", store.upserts)
	}
}

func TestWorkerHelperBranches(t *testing.T) {
	t.Parallel()

	pkg := searchPackageData{
		AllMalicious: true,
		Classifications: []searchClassification{
			{Status: "Malicious"},
		},
		Dependencies: map[string]searchDependency{
			"dep": {Classification: struct {
				Status string `json:"status"`
				Result string `json:"result"`
			}{Status: "Malicious"}},
		},
		Incidents: map[string]searchIncident{
			"malware": {Type: "malware"},
			"removal": {Type: "removal"},
		},
	}
	pkg.Assessments.Malware.Status = "fail"
	pkg.Identity.Removed = true
	pkg.WasRemoved = true

	if got := maliciousSignals(pkg); len(got) != 4 {
		t.Fatalf("maliciousSignals() = %#v, want active malware signals only", got)
	}
	if got := removedSignals(pkg); len(got) != 2 {
		t.Fatalf("removedSignals() = %#v, want current-state removal signals only", got)
	}

	for _, status := range []string{"malicious", "removed", "risk", "clean", "not_found"} {
		if !isDefinitiveStatus(status) {
			t.Fatalf("isDefinitiveStatus(%q) = false, want true", status)
		}
	}
	if isDefinitiveStatus(" pending ") {
		t.Fatal("isDefinitiveStatus(pending) = true, want false")
	}

	store := &fakeStore{resetCount: 2}
	newWorker(store, "token", slog.Default()).resetStuckJobs(context.Background())
	store.resetErr = errors.New("reset failed")
	newWorker(store, "token", slog.Default()).resetStuckJobs(context.Background())
}

func TestResultFromPackageIgnoresHistoricalIncidents(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	w := newWorker(&fakeStore{}, "token", slog.Default())
	rep := db.PackageReputation{
		Ecosystem: "pypi",
		Name:      "polars-runtime-32",
		Version:   "1.40.1",
		Source:    FeedName,
	}
	pkg := searchPackageData{
		Incidents: map[string]searchIncident{
			"malware": {Type: "malware"},
		},
	}

	got := w.resultFromPackage(rep, pkg, now)
	if got.Status != "clean" {
		t.Fatalf("Status = %q, want clean for historical incidents only", got.Status)
	}
	if got.Summary != "ReversingLabs: no malicious signals" {
		t.Fatalf("Summary = %q, want clean summary", got.Summary)
	}
	if strings.Contains(string(got.Evidence), "incidents.type.malware") {
		t.Fatalf("Evidence = %s, want no historical incident signal", string(got.Evidence))
	}
}
