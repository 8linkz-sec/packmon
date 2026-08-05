package socket

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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	feedqueue "github.com/8linkz-sec/packmon/internal/feed"
)

type socketTestStore struct {
	job                 *db.RefreshJob
	jobs                []*db.RefreshJob
	dequeueErr          error
	completeErr         error
	resetErr            error
	resetCount          int
	upsertErr           error
	statusErr           error
	dequeueSource       string
	findings            []db.MaliciousFinding
	statuses            []db.PackageCheckStatus
	completed           []socketCompletion
	completeCtxErr      error
	dequeueDeadlineSet  bool
	dequeueDeadline     time.Time
	completeDeadlineSet bool
	completeDeadline    time.Time
	resetDeadlineSet    bool
	resetDeadline       time.Time
	resetSource         string
	resetCh             chan struct{}
	statusBlock         chan struct{}
	resetOnce           sync.Once
}

type socketCompletion struct {
	id        int
	claimedAt *time.Time
	err       error
}

type socketRecordingMetricsRecorder struct {
	queueErrors    map[string]int
	stuckRecovered int
	jobsCompleted  map[string]int
}

func newSocketRecordingMetricsRecorder() *socketRecordingMetricsRecorder {
	return &socketRecordingMetricsRecorder{
		queueErrors:   make(map[string]int),
		jobsCompleted: make(map[string]int),
	}
}

func (r *socketRecordingMetricsRecorder) IncFeedSyncTimeout(string) {}

func (r *socketRecordingMetricsRecorder) IncQueueError(source string) {
	r.queueErrors[source]++
}

func (r *socketRecordingMetricsRecorder) AddQueueStuckRecovered(count int) {
	r.stuckRecovered += count
}

func (r *socketRecordingMetricsRecorder) IncQueueJobCompleted(source, result string) {
	r.jobsCompleted[source+":"+result]++
}

type socketRoundTripFunc func(*http.Request) (*http.Response, error)

func (f socketRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func assertSocketJSONLogIntField(t *testing.T, output, msg, field string, want int) {
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

func assertSocketRateLimit(t *testing.T, worker *Worker, wantTokens, wantLimit int) {
	t.Helper()
	state := worker.Snapshot()
	if state.Tokens != wantTokens || state.Limit != wantLimit {
		t.Fatalf("rate limit tokens = %d/%d, want %d/%d", state.Tokens, state.Limit, wantTokens, wantLimit)
	}
}

func assertSocketTokens(t *testing.T, worker *Worker, want int) {
	t.Helper()
	state := worker.Snapshot()
	if state.Tokens != want {
		t.Fatalf("tokens = %d, want %d", state.Tokens, want)
	}
}

func withPollTicks(ticks <-chan time.Time) Option {
	return func(w *Worker) {
		w.pollTicks = ticks
	}
}

func withRunReady(ready chan<- struct{}) Option {
	return func(w *Worker) {
		w.runReady = ready
	}
}

func (s *socketTestStore) UpsertMaliciousFinding(_ context.Context, finding *db.MaliciousFinding) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.findings = append(s.findings, *finding)
	return nil
}

func (s *socketTestStore) UpsertPackageCheckStatus(ctx context.Context, status *db.PackageCheckStatus) error {
	if s.statusBlock != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.statusBlock:
		}
	}
	if s.statusErr != nil {
		return s.statusErr
	}
	s.statuses = append(s.statuses, *status)
	return nil
}

func (s *socketTestStore) DequeueRefresh(ctx context.Context, source string) (*db.RefreshJob, error) {
	s.dequeueSource = source
	if deadline, ok := ctx.Deadline(); ok {
		s.dequeueDeadlineSet = true
		s.dequeueDeadline = deadline
	}
	if s.dequeueErr != nil {
		return nil, s.dequeueErr
	}
	if len(s.jobs) > 0 {
		job := s.jobs[0]
		s.jobs = s.jobs[1:]
		return claimSocketTestJob(job), nil
	}
	return claimSocketTestJob(s.job), nil
}

func claimSocketTestJob(job *db.RefreshJob) *db.RefreshJob {
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

func (s *socketTestStore) CompleteClaimedRefresh(ctx context.Context, id int, claimedAt *time.Time, err error) error {
	s.completeCtxErr = ctx.Err()
	if deadline, ok := ctx.Deadline(); ok {
		s.completeDeadlineSet = true
		s.completeDeadline = deadline
	}
	s.completed = append(s.completed, socketCompletion{id: id, claimedAt: claimedAt, err: err})
	return s.completeErr
}

func (s *socketTestStore) ResetStuckJobs(ctx context.Context, source string, _ time.Duration) (int, error) {
	s.resetSource = source
	if deadline, ok := ctx.Deadline(); ok {
		s.resetDeadlineSet = true
		s.resetDeadline = deadline
	}
	if s.resetCh != nil {
		s.resetOnce.Do(func() {
			close(s.resetCh)
		})
	}
	return s.resetCount, s.resetErr
}

func TestProcessNextJobUpdatesCompletedThroughputTelemetry(t *testing.T) {
	recorder := newSocketRecordingMetricsRecorder()
	successStore := &socketTestStore{
		job: &db.RefreshJob{ID: 1179, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	successWorker := NewWorker(successStore, "socket-secret", nil,
		WithRateLimit(1),
		WithMetricsRecorder(recorder),
		WithHTTPClient(&http.Client{Transport: socketRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})}),
	)

	successWorker.processNextJob(context.Background())

	if got := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultSuccess]; got != 1 {
		t.Fatalf("completed success counter = %d, want 1", got)
	}

	errorStore := &socketTestStore{
		job: &db.RefreshJob{ID: 1180, Ecosystem: "hex", Name: "plug", Source: FeedName},
	}
	errorWorker := NewWorker(errorStore, "socket-secret", nil, WithRateLimit(1), WithMetricsRecorder(recorder))

	errorWorker.processNextJob(context.Background())

	if got := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultError]; got != 1 {
		t.Fatalf("completed error counter = %d, want 1", got)
	}

	rateSuccessBefore := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultSuccess]
	rateErrorBefore := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultError]
	rateStore := &socketTestStore{
		job: &db.RefreshJob{ID: 1181, Ecosystem: "npm", Name: "rate-limited", Source: FeedName},
	}
	rateWorker := NewWorker(rateStore, "socket-secret", nil,
		WithRateLimit(1),
		WithMetricsRecorder(recorder),
		WithHTTPClient(&http.Client{Transport: socketRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		})}),
	)

	rateWorker.processNextJob(context.Background())

	if len(rateStore.completed) != 0 {
		t.Fatalf("completed jobs = %+v, want rate-limited job left processing", rateStore.completed)
	}
	if got := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultSuccess]; got != rateSuccessBefore {
		t.Fatalf("completed success counter changed after rate limit: got %d, want %d", got, rateSuccessBefore)
	}
	if got := recorder.jobsCompleted[FeedName+":"+feedqueue.QueueJobResultError]; got != rateErrorBefore {
		t.Fatalf("completed error counter changed after rate limit: got %d, want %d", got, rateErrorBefore)
	}
}

func TestCheckPackageRejectsHTTPSDowngradeRedirect(t *testing.T) {
	t.Parallel()

	var targetReached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetReached.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/api/v1/npm/left-pad/score", http.StatusFound)
	}))
	defer source.Close()

	worker := NewWorker(&socketTestStore{}, "socket-secret", nil,
		WithBaseURL(source.URL),
		WithHTTPClient(source.Client()),
	)

	err := worker.checkPackage(context.Background(), &db.RefreshJob{Ecosystem: "npm", Name: "left-pad"})
	if err == nil || !strings.Contains(err.Error(), "refusing redirect from https to http") {
		t.Fatalf("checkPackage() error = %v, want HTTPS downgrade redirect refusal", err)
	}
	if got := targetReached.Load(); got != 0 {
		t.Fatalf("downgrade redirect target reached %d time(s), want 0", got)
	}
}

func TestNewWorkerOptionsAndName(t *testing.T) {
	t.Parallel()

	client := &http.Client{Timeout: time.Second}
	worker := NewWorker(&socketTestStore{}, "secret", nil,
		WithHTTPClient(client),
		WithBaseURL("https://socket.example/api/"),
		WithPollInterval(25*time.Millisecond),
		WithJobTimeout(15*time.Second),
		WithRateLimit(7),
	)
	if worker.Name() != FeedName {
		t.Fatalf("Name() = %q, want %q", worker.Name(), FeedName)
	}
	if worker.httpClient == client || worker.httpClient.Timeout != client.Timeout || worker.baseURL != "https://socket.example/api/" || worker.pollInterval != 25*time.Millisecond {
		t.Fatalf("worker options not applied: %+v", worker)
	}
	if err := worker.httpClient.CheckRedirect(
		&http.Request{URL: mustSocketTestURL(t, "http://socket.example/next")},
		[]*http.Request{{URL: mustSocketTestURL(t, "https://socket.example/start")}},
	); err == nil || !strings.Contains(err.Error(), "https to http") {
		t.Fatalf("worker redirect policy error = %v, want HTTPS downgrade refusal", err)
	}
	assertSocketRateLimit(t, worker, 7, 7)
	if worker.jobTimeout != 15*time.Second {
		t.Fatalf("jobTimeout = %v, want 15s", worker.jobTimeout)
	}
}

func mustSocketTestURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return u
}

func TestProcessNextJobUsesQueueOperationDeadlines(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{
		job: &db.RefreshJob{ID: 42, Ecosystem: "hex", Name: "plug", Source: FeedName, Priority: 1},
	}
	worker := NewWorker(store, "socket-secret", nil, WithRateLimit(1))

	worker.processNextJob(context.Background())

	assertSocketDeadlineSoon(t, "reset stuck jobs", store.resetDeadlineSet, store.resetDeadline)
	assertSocketDeadlineSoon(t, "dequeue refresh", store.dequeueDeadlineSet, store.dequeueDeadline)
	assertSocketDeadlineSoon(t, "complete refresh", store.completeDeadlineSet, store.completeDeadline)
}

func assertSocketDeadlineSoon(t *testing.T, operation string, ok bool, deadline time.Time) {
	t.Helper()
	if !ok {
		t.Fatalf("%s context has no deadline", operation)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 3*time.Second {
		t.Fatalf("%s deadline remaining = %v, want bounded positive deadline within 3s", operation, remaining)
	}
}

func TestWorkersShareRateLimitState(t *testing.T) {
	t.Parallel()

	limiter := NewRateLimiter(1)
	first := NewWorker(&socketTestStore{}, "secret", nil, WithRateLimiter(limiter))
	second := NewWorker(&socketTestStore{}, "secret", nil, WithRateLimiter(limiter))

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

func TestCheckPackageStoresSecurityIssuesAndStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/npm/left-pad/score" {
			t.Fatalf("request path = %q, want /npm/left-pad/score", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer socket-secret" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"package":{"name":"left-pad","version":"1.0.1"},
			"score":{"overall":0.42,"supplyChain":0.25},
			"issues":[
				{"type":"malware","severity":"high","title":"Malware detected","description":"raw provider incident detail","version":"1.0.0","affectedVersions":["1.0.1"]},
				{"type":"maintenance","severity":"low","title":"raw maintenance title"}
			]
		}`))
	}))
	t.Cleanup(server.Close)

	store := &socketTestStore{}
	worker := NewWorker(store, "socket-secret", slog.New(slog.NewTextHandler(os.Stdout, nil)), WithBaseURL(server.URL))

	err := worker.checkPackage(context.Background(), &db.RefreshJob{
		ID: 7, Ecosystem: "npm", Name: "left-pad", Source: FeedName,
	})
	if err != nil {
		t.Fatalf("checkPackage() error = %v", err)
	}

	if len(store.findings) != 1 {
		t.Fatalf("malicious findings = %d, want 1", len(store.findings))
	}
	finding := store.findings[0]
	if finding.ID != "socket:npm/left-pad:malware" || finding.RiskType != "malware" || finding.Severity != "HIGH" {
		t.Fatalf("finding = %+v", finding)
	}
	var versions []string
	if err := json.Unmarshal(finding.Versions, &versions); err != nil {
		t.Fatalf("versions JSON: %v", err)
	}
	if len(versions) != 2 || versions[0] != "1.0.0" || versions[1] != "1.0.1" {
		t.Fatalf("versions = %#v, want 1.0.0 and 1.0.1", versions)
	}
	var refs []string
	if err := json.Unmarshal(finding.ReferenceURLs, &refs); err != nil {
		t.Fatalf("reference URLs JSON: %v", err)
	}
	if len(refs) != 1 || refs[0] != "https://socket.dev/npm/package/left-pad" {
		t.Fatalf("reference URLs = %#v", refs)
	}
	if len(store.statuses) != 1 {
		t.Fatalf("check statuses = %d, want 1", len(store.statuses))
	}
	if store.statuses[0].LastCheckedAt == nil || store.statuses[0].NextCheckAt == nil {
		t.Fatalf("check status timestamps missing: %+v", store.statuses[0])
	}
	statusResult := string(store.statuses[0].LastResult)
	for _, want := range []string{`"status":"ok"`, `"package_version":"1.0.1"`, `"issue_count":2`, `"security_issue_count":1`, `"overall":0.42`} {
		if !strings.Contains(statusResult, want) {
			t.Fatalf("LastResult = %s, want normalized field %s", statusResult, want)
		}
	}
	for _, leaked := range []string{"raw provider incident detail", "raw maintenance title", "Malware detected"} {
		if strings.Contains(statusResult, leaked) {
			t.Fatalf("LastResult leaked raw Socket.dev response detail %q in %s", leaked, statusResult)
		}
	}
}

func TestCheckPackageStoresNormalizedNotFoundStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"provider_detail":"raw-404-body"}`))
	}))
	t.Cleanup(server.Close)

	store := &socketTestStore{}
	worker := NewWorker(store, "socket-secret", nil, WithBaseURL(server.URL))

	err := worker.checkPackage(context.Background(), &db.RefreshJob{
		ID: 7, Ecosystem: "npm", Name: "missing", Source: FeedName,
	})
	if err != nil {
		t.Fatalf("checkPackage() error = %v", err)
	}

	if len(store.statuses) != 1 {
		t.Fatalf("check statuses = %d, want 1", len(store.statuses))
	}
	statusResult := string(store.statuses[0].LastResult)
	if !strings.Contains(statusResult, `"status":"not_found"`) {
		t.Fatalf("LastResult = %s, want normalized not_found status", statusResult)
	}
	if strings.Contains(statusResult, "raw-404-body") {
		t.Fatalf("LastResult leaked raw Socket.dev 404 body: %s", statusResult)
	}
}

func TestProcessNextJobSkipsExcludedNamespaceBeforeHTTPRequest(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	store := &socketTestStore{
		job: &db.RefreshJob{ID: 71, Ecosystem: "npm", Name: "@internal/widget", Source: FeedName},
	}
	worker := NewWorker(store, "socket-secret", nil,
		WithBaseURL(server.URL),
		WithExcludedNamespaces([]string{"npm/@internal/"}),
		WithRateLimit(1),
	)
	worker.processNextJob(context.Background())

	if requests != 0 {
		t.Fatalf("Socket.dev HTTP requests = %d, want 0 for excluded private namespace", requests)
	}
	if len(store.completed) != 1 || store.completed[0].id != 71 {
		t.Fatalf("completed jobs = %+v, want excluded job completed", store.completed)
	}
	if store.completed[0].err == nil || !strings.Contains(store.completed[0].err.Error(), "excluded by private namespace policy") {
		t.Fatalf("completion error = %v, want private namespace policy error", store.completed[0].err)
	}
	if len(store.statuses) != 0 || len(store.findings) != 0 {
		t.Fatalf("statuses/findings = %d/%d, want no provider-derived writes", len(store.statuses), len(store.findings))
	}
	assertSocketTokens(t, worker, 1)
}

func TestProcessNextJobCompletesWithErrorWhenFindingWriteFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"package":{"name":"left-pad","version":"1.0.1"},
			"issues":[{"type":"malware","severity":"critical","title":"Malware detected"}]
		}`))
	}))
	t.Cleanup(server.Close)

	store := &socketTestStore{
		job:       &db.RefreshJob{ID: 91, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
		upsertErr: errors.New("store unavailable"),
	}
	worker := NewWorker(store, "socket-secret", nil,
		WithBaseURL(server.URL),
		WithRateLimit(1),
	)

	worker.processNextJob(context.Background())

	if len(store.completed) != 1 || store.completed[0].id != 91 {
		t.Fatalf("completed jobs = %+v, want job 91", store.completed)
	}
	if store.completed[0].claimedAt == nil {
		t.Fatalf("completion claim = nil, want dequeued processed_at claim")
	}
	if store.completed[0].err == nil || !strings.Contains(store.completed[0].err.Error(), "store unavailable") {
		t.Fatalf("completion error = %v, want finding write failure", store.completed[0].err)
	}
	if len(store.statuses) != 0 {
		t.Fatalf("statuses = %+v, want no success status after finding write failure", store.statuses)
	}
}

func TestCheckPackageRateLimitDrainsTokens(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	store := &socketTestStore{}
	worker := NewWorker(store, "socket-secret", nil, WithBaseURL(server.URL), WithRateLimit(5))

	err := worker.checkPackage(context.Background(), &db.RefreshJob{Ecosystem: "npm", Name: "left-pad"})
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("checkPackage() error = %v, want rate limited", err)
	}
	assertSocketTokens(t, worker, 0)
	if len(store.statuses) != 0 {
		t.Fatalf("statuses = %d, want 0 after upstream 429", len(store.statuses))
	}
}

func TestProcessNextJobUsesPerJobDeadline(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"missing":true}`))
	}))
	t.Cleanup(server.Close)

	store := &socketTestStore{
		job:         &db.RefreshJob{ID: 88, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
		statusBlock: make(chan struct{}),
	}
	worker := NewWorker(store, "socket-secret", nil,
		WithBaseURL(server.URL),
		WithJobTimeout(10*time.Millisecond),
		WithRateLimit(1),
	)
	worker.processNextJob(context.Background())

	if len(store.completed) != 1 || store.completed[0].id != 88 {
		t.Fatalf("completed jobs = %+v, want job 88", store.completed)
	}
	if !errors.Is(store.completed[0].err, context.DeadlineExceeded) {
		t.Fatalf("completion error = %v, want context deadline exceeded", store.completed[0].err)
	}
}

func TestProcessNextJobLeavesRateLimitedJobForRetry(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(server.Close)

	store := &socketTestStore{
		job: &db.RefreshJob{ID: 89, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	worker := NewWorker(store, "socket-secret", nil,
		WithBaseURL(server.URL),
		WithRateLimit(1),
	)
	worker.processNextJob(context.Background())

	if len(store.completed) != 0 {
		t.Fatalf("completed jobs = %+v, want rate-limited job left processing for retry", store.completed)
	}
	if len(store.statuses) != 0 {
		t.Fatalf("statuses = %+v, want no status write for transient rate limit", store.statuses)
	}
}

func TestProcessNextJobLogsJobIDOnRateLimitAndFailureWarnings(t *testing.T) {
	t.Parallel()

	t.Run("rate limited", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		t.Cleanup(server.Close)

		store := &socketTestStore{
			job: &db.RefreshJob{ID: 89, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
		}
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		worker := NewWorker(store, "socket-secret", logger,
			WithBaseURL(server.URL),
			WithRateLimit(1),
		)

		worker.processNextJob(context.Background())

		assertSocketJSONLogIntField(t, logs.String(), "socket check rate limited; leaving job processing for retry", "job_id", 89)
	})

	t.Run("failed", func(t *testing.T) {
		t.Parallel()

		store := &socketTestStore{
			job: &db.RefreshJob{ID: 90, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
		}
		client := &http.Client{
			Transport: socketRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("socket transport unavailable")
			}),
		}
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		worker := NewWorker(store, "socket-secret", logger,
			WithBaseURL("https://socket.example.test"),
			WithHTTPClient(client),
			WithRateLimit(1),
		)

		worker.processNextJob(context.Background())

		assertSocketJSONLogIntField(t, logs.String(), "socket check failed", "job_id", 90)
	})
}

func TestProcessNextJobCompletesTransportErrorWithoutStatusWrite(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{
		job: &db.RefreshJob{ID: 90, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	client := &http.Client{
		Transport: socketRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp 127.0.0.1:443: connect: connection refused")
		}),
	}
	worker := NewWorker(store, "socket-secret", nil,
		WithBaseURL("https://socket.example.test"),
		WithHTTPClient(client),
		WithRateLimit(1),
	)

	worker.processNextJob(context.Background())

	if len(store.completed) != 1 || store.completed[0].id != 90 {
		t.Fatalf("completed jobs = %+v, want failed transport job completed", store.completed)
	}
	if store.completed[0].claimedAt == nil {
		t.Fatal("completion claim = nil, want dequeued processed_at claim")
	}
	if store.completed[0].err == nil || !strings.Contains(store.completed[0].err.Error(), "connection refused") {
		t.Fatalf("completion error = %v, want transport connection error", store.completed[0].err)
	}
	if len(store.statuses) != 0 || len(store.findings) != 0 {
		t.Fatalf("statuses/findings = %d/%d, want no provider state after transport error", len(store.statuses), len(store.findings))
	}
	assertSocketTokens(t, worker, 0)
}

func TestProcessNextJobRedactsSocketTransportErrorsInLogs(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{
		job: &db.RefreshJob{ID: 88, Ecosystem: "npm", Name: "left-pad", Source: FeedName},
	}
	client := &http.Client{
		Transport: socketRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, &url.Error{
				Op:  "Get",
				URL: req.URL.String(),
				Err: errors.New(`dial tcp password=transport-secret C:\Users\Admin\packmon\socket.json`),
			}
		}),
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	worker := NewWorker(
		store,
		"socket-secret",
		logger,
		WithBaseURL("https://user-secret:pass-secret@socket.example.test/private/path?token=query-secret#frag-secret"),
		WithHTTPClient(client),
		WithRateLimit(1),
	)

	worker.processNextJob(context.Background())

	output := logs.String()
	for _, leaked := range []string{
		"user-secret",
		"pass-secret",
		"private/path",
		"query-secret",
		"frag-secret",
		"transport-secret",
		`C:\Users\Admin\packmon\socket.json`,
	} {
		if strings.Contains(output, leaked) {
			t.Fatalf("socket transport log leaked %q in:\n%s", leaked, output)
		}
	}
	for _, want := range []string{
		"https://socket.example.test/...",
		"password=[redacted]",
		"(redacted-path)",
		"socket check failed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("socket transport log missing %q in:\n%s", want, output)
		}
	}
	if len(store.completed) != 1 || store.completed[0].err == nil {
		t.Fatalf("completed = %+v, want one failed completion", store.completed)
	}
}

func TestCheckPackageStatusAndHTTPErrorBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantErr    string
		wantStatus bool
	}{
		{name: "not found records status", statusCode: http.StatusNotFound, body: `{"missing":true}`, wantStatus: true},
		{name: "unauthorized", statusCode: http.StatusUnauthorized, body: `{}`, wantErr: "authentication failed"},
		{name: "forbidden", statusCode: http.StatusForbidden, body: `{}`, wantErr: "authentication failed"},
		{name: "server error", statusCode: http.StatusInternalServerError, body: `{}`, wantErr: "unexpected status 500"},
		{name: "bad json", statusCode: http.StatusOK, body: `{bad`, wantErr: "parse response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(server.Close)

			store := &socketTestStore{}
			worker := NewWorker(store, "socket-secret", nil, WithBaseURL(server.URL))
			err := worker.checkPackage(context.Background(), &db.RefreshJob{Ecosystem: "npm", Name: "left-pad"})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkPackage() error = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("checkPackage() error = %v, want %q", err, tt.wantErr)
			}
			if (len(store.statuses) > 0) != tt.wantStatus {
				t.Fatalf("statuses = %+v, wantStatus=%v", store.statuses, tt.wantStatus)
			}
		})
	}
}

func TestProcessNextJobHandlesStoreErrors(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{dequeueErr: errors.New("dequeue failed")}
	worker := NewWorker(store, "socket-secret", nil, WithRateLimit(1))
	worker.processNextJob(context.Background())
	if len(store.completed) != 0 {
		t.Fatalf("completed jobs = %+v, want none after dequeue error", store.completed)
	}

	store = &socketTestStore{
		job:         &db.RefreshJob{ID: 3, Ecosystem: "hex", Name: "plug"},
		completeErr: errors.New("complete failed"),
	}
	worker = NewWorker(store, "socket-secret", nil, WithRateLimit(1))
	worker.processNextJob(context.Background())
	if len(store.completed) != 1 || store.completed[0].id != 3 {
		t.Fatalf("completed jobs = %+v, want job 3 despite completion error", store.completed)
	}

	store = &socketTestStore{
		job: &db.RefreshJob{ID: 4, Ecosystem: "hex", Name: "plug"},
	}
	worker = NewWorker(store, "socket-secret", nil, WithRateLimit(1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	worker.processNextJob(ctx)
	if len(store.completed) != 1 || store.completed[0].id != 4 {
		t.Fatalf("completed jobs after canceled worker context = %+v, want job 4", store.completed)
	}
	if store.completeCtxErr != nil {
		t.Fatalf("CompleteClaimedRefresh context error = %v, want independent live context", store.completeCtxErr)
	}

	store = &socketTestStore{resetErr: errors.New("reset failed")}
	worker = NewWorker(store, "socket-secret", nil)
	worker.resetStuckJobs(context.Background())
	if store.resetSource != FeedName {
		t.Fatalf("reset source = %q, want %q", store.resetSource, FeedName)
	}
}

func TestProcessNextJobCompletesUnsupportedEcosystemAsError(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{
		job: &db.RefreshJob{ID: 42, Ecosystem: "hex", Name: "plug", Source: FeedName, Priority: 1},
	}
	worker := NewWorker(store, "socket-secret", nil, WithRateLimit(1))

	worker.processNextJob(context.Background())

	if store.dequeueSource != FeedName {
		t.Fatalf("dequeue source = %q, want %q", store.dequeueSource, FeedName)
	}
	if store.resetSource != FeedName {
		t.Fatalf("reset source = %q, want %q", store.resetSource, FeedName)
	}
	if len(store.completed) != 1 {
		t.Fatalf("completed jobs = %d, want 1", len(store.completed))
	}
	if store.completed[0].id != 42 || store.completed[0].err == nil {
		t.Fatalf("completion = %+v, want job 42 with error", store.completed[0])
	}
	if !strings.Contains(store.completed[0].err.Error(), "unsupported ecosystem") {
		t.Fatalf("completion error = %v", store.completed[0].err)
	}
	assertSocketTokens(t, worker, 1)
}

func TestProcessNextJobReturnsTokenWhenQueueEmpty(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{}
	worker := NewWorker(store, "socket-secret", nil, WithRateLimit(1))

	worker.processNextJob(context.Background())

	assertSocketTokens(t, worker, 1)
	if len(store.completed) != 0 {
		t.Fatalf("completed jobs = %d, want 0", len(store.completed))
	}
}

func TestProcessNextJobReturnsTokenWhenDequeueFails(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{dequeueErr: errors.New("queue down")}
	worker := NewWorker(store, "socket-secret", nil, WithRateLimit(1))

	worker.processNextJob(context.Background())

	if store.dequeueSource != FeedName {
		t.Fatalf("dequeue source = %q, want %q", store.dequeueSource, FeedName)
	}
	assertSocketTokens(t, worker, 1)
	if len(store.completed) != 0 {
		t.Fatalf("completed jobs = %d, want 0", len(store.completed))
	}
}

func TestProcessAvailableJobsDrainsAvailableTokens(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"missing":true}`))
	}))
	t.Cleanup(server.Close)

	store := &socketTestStore{
		jobs: []*db.RefreshJob{
			{ID: 1, Ecosystem: "npm", Name: "pkg-a", Source: FeedName},
			{ID: 2, Ecosystem: "npm", Name: "pkg-b", Source: FeedName},
			{ID: 3, Ecosystem: "npm", Name: "pkg-c", Source: FeedName},
		},
	}
	worker := NewWorker(store, "socket-secret", nil, WithBaseURL(server.URL), WithRateLimit(3))

	worker.processAvailableJobs(context.Background())

	if len(store.completed) != 3 {
		t.Fatalf("completed jobs = %+v, want all 3 available-token jobs", store.completed)
	}
	assertSocketTokens(t, worker, 0)
}

func TestProcessNextJobSuppressesRepeatedDequeueErrorLogs(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{dequeueErr: errors.New("queue down")}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	worker := NewWorker(store, "socket-secret", logger, WithRateLimit(2))

	worker.processNextJob(context.Background())
	worker.processNextJob(context.Background())

	output := logs.String()
	if got := strings.Count(output, `"level":"ERROR"`); got != 1 {
		t.Fatalf("ERROR dequeue logs = %d, want 1; logs=%s", got, output)
	}
	if !strings.Contains(output, `"suppressed":true`) {
		t.Fatalf("repeated dequeue log missing suppressed marker: %s", output)
	}
}

func TestProcessNextJobSkipsWhenNoToken(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{job: &db.RefreshJob{ID: 1, Ecosystem: "npm", Name: "left-pad"}}
	worker := NewWorker(store, "socket-secret", nil, WithRateLimit(1))
	worker.Drain()

	worker.processNextJob(context.Background())

	if store.dequeueSource != "" {
		t.Fatalf("dequeue source = %q, want no dequeue without token", store.dequeueSource)
	}
}

func TestRunDoesNotResetStuckJobsBeforeFirstPoll(t *testing.T) {
	t.Parallel()

	resetCh := make(chan struct{})
	runReady := make(chan struct{})
	pollTick := make(chan time.Time)
	store := &socketTestStore{resetCh: resetCh}
	worker := NewWorker(store, "socket-secret", nil,
		withPollTicks(pollTick),
		withRunReady(runReady),
		WithRateLimit(1),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()

	select {
	case <-runReady:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Run() did not enter the poll loop")
	}

	select {
	case <-resetCh:
		cancel()
		t.Fatal("Run reset stuck jobs before the first poll")
	default:
	}

	select {
	case pollTick <- time.Now():
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Run() did not accept the first poll tick")
	}

	select {
	case <-resetCh:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("Run() did not reset stuck jobs after the first poll")
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
}

func TestRunProcessesUntilContextCancellation(t *testing.T) {
	t.Parallel()

	resetCh := make(chan struct{})
	store := &socketTestStore{resetCount: 1, resetCh: resetCh}
	worker := NewWorker(store, "socket-secret", nil, WithPollInterval(time.Millisecond), WithRateLimit(1))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()

	select {
	case <-resetCh:
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not reset stuck jobs")
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
		t.Fatalf("reset source = %q, want %q", store.resetSource, FeedName)
	}
}

func TestUpdateCheckStatusLogsStoreError(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{statusErr: errors.New("status failed")}
	worker := NewWorker(store, "socket-secret", nil)

	if err := worker.updateCheckStatus(context.Background(), &db.RefreshJob{Ecosystem: "npm", Name: "left-pad"}, []byte(`{}`)); err == nil {
		t.Fatal("updateCheckStatus() error = nil, want store error")
	}

	if len(store.statuses) != 0 {
		t.Fatalf("statuses = %d, want none after status error", len(store.statuses))
	}
}

func TestMapSocketSeverity(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"critical": "CRITICAL",
		"HIGH":     "HIGH",
		"moderate": "MEDIUM",
		"medium":   "MEDIUM",
		"low":      "LOW",
		"":         "CRITICAL",
		"unknown":  "CRITICAL",
	}
	for input, want := range tests {
		if got := mapSocketSeverity(input); got != want {
			t.Fatalf("mapSocketSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRunReturnsImmediatelyWithoutAPIKey(t *testing.T) {
	t.Parallel()

	worker := NewWorker(&socketTestStore{}, "", nil)
	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestProcessIssuesReturnsStoreError(t *testing.T) {
	t.Parallel()

	store := &socketErrorStore{}
	worker := NewWorker(store, "socket-secret", nil)
	err := worker.processIssues(context.Background(), &db.RefreshJob{Ecosystem: "npm", Name: "left-pad"}, &scoreResponse{
		Issues: []issueEntry{{Type: "malware", Severity: "critical"}},
	})
	if err == nil || !strings.Contains(err.Error(), "insert failed") {
		t.Fatalf("processIssues() error = %v, want store failure", err)
	}
	if store.calls != 1 {
		t.Fatalf("upsert calls = %d, want 1", store.calls)
	}
}

type socketErrorStore struct {
	socketTestStore
	calls int
}

func (s *socketErrorStore) UpsertMaliciousFinding(context.Context, *db.MaliciousFinding) error {
	s.calls++
	return errors.New("insert failed")
}
