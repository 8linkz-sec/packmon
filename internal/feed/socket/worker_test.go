package socket

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type socketTestStore struct {
	db.Store

	job           *db.RefreshJob
	dequeueErr    error
	completeErr   error
	resetErr      error
	resetCount    int
	upsertErr     error
	statusErr     error
	dequeueSource string
	findings      []db.MaliciousFinding
	statuses      []db.PackageCheckStatus
	completed     []socketCompletion
	resetSource   string
	resetCh       chan struct{}
	resetOnce     sync.Once
}

type socketCompletion struct {
	id  int
	err error
}

func (s *socketTestStore) UpsertMaliciousFinding(_ context.Context, finding *db.MaliciousFinding) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.findings = append(s.findings, *finding)
	return nil
}

func (s *socketTestStore) UpsertPackageCheckStatus(_ context.Context, status *db.PackageCheckStatus) error {
	if s.statusErr != nil {
		return s.statusErr
	}
	s.statuses = append(s.statuses, *status)
	return nil
}

func (s *socketTestStore) DequeueRefresh(_ context.Context, source string) (*db.RefreshJob, error) {
	s.dequeueSource = source
	if s.dequeueErr != nil {
		return nil, s.dequeueErr
	}
	return s.job, nil
}

func (s *socketTestStore) CompleteRefresh(_ context.Context, id int, err error) error {
	s.completed = append(s.completed, socketCompletion{id: id, err: err})
	return s.completeErr
}

func (s *socketTestStore) ResetStuckJobs(_ context.Context, source string, _ time.Duration) (int, error) {
	s.resetSource = source
	if s.resetCh != nil {
		s.resetOnce.Do(func() {
			close(s.resetCh)
		})
	}
	return s.resetCount, s.resetErr
}

func TestNewWorkerOptionsAndName(t *testing.T) {
	t.Parallel()

	client := &http.Client{Timeout: time.Second}
	worker := NewWorker(&socketTestStore{}, "secret", nil,
		WithHTTPClient(client),
		WithBaseURL("https://socket.example/api/"),
		WithPollInterval(25*time.Millisecond),
		WithRateLimit(7),
	)
	if worker.Name() != FeedName {
		t.Fatalf("Name() = %q, want %q", worker.Name(), FeedName)
	}
	if worker.httpClient != client || worker.baseURL != "https://socket.example/api/" || worker.pollInterval != 25*time.Millisecond {
		t.Fatalf("worker options not applied: %+v", worker)
	}
	if worker.tokens != 7 || worker.maxTokens != 7 {
		t.Fatalf("rate limit tokens = %d/%d, want 7/7", worker.tokens, worker.maxTokens)
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
			"issues":[
				{"type":"malware","severity":"high","title":"Malware detected","description":"exfiltrates tokens","version":"1.0.0","affectedVersions":["1.0.1"]},
				{"type":"maintenance","severity":"low","title":"not security relevant"}
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
	if len(store.statuses[0].LastResult) == 0 {
		t.Fatal("LastResult is empty, want raw Socket.dev response")
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
	worker.tokens = 5

	err := worker.checkPackage(context.Background(), &db.RefreshJob{Ecosystem: "npm", Name: "left-pad"})
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("checkPackage() error = %v, want rate limited", err)
	}
	if worker.tokens != 0 {
		t.Fatalf("tokens = %d, want 0 after upstream 429", worker.tokens)
	}
	if len(store.statuses) != 0 {
		t.Fatalf("statuses = %d, want 0 after upstream 429", len(store.statuses))
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
}

func TestProcessNextJobReturnsTokenWhenQueueEmpty(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{}
	worker := NewWorker(store, "socket-secret", nil, WithRateLimit(1))
	worker.tokens = 1

	worker.processNextJob(context.Background())

	if worker.tokens != 1 {
		t.Fatalf("tokens = %d, want returned token when no job was dequeued", worker.tokens)
	}
	if len(store.completed) != 0 {
		t.Fatalf("completed jobs = %d, want 0", len(store.completed))
	}
}

func TestProcessNextJobSkipsWhenNoToken(t *testing.T) {
	t.Parallel()

	store := &socketTestStore{job: &db.RefreshJob{ID: 1, Ecosystem: "npm", Name: "left-pad"}}
	worker := NewWorker(store, "socket-secret", nil, WithRateLimit(1))
	worker.tokens = 0
	worker.lastRefill = time.Now()

	worker.processNextJob(context.Background())

	if store.dequeueSource != "" {
		t.Fatalf("dequeue source = %q, want no dequeue without token", store.dequeueSource)
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

	worker.updateCheckStatus(context.Background(), &db.RefreshJob{Ecosystem: "npm", Name: "left-pad"}, []byte(`{}`))

	if len(store.statuses) != 0 {
		t.Fatalf("statuses = %d, want none after status error", len(store.statuses))
	}
}

func TestRefillTokensAccumulatesFractionalTokens(t *testing.T) {
	t.Parallel()

	worker := NewWorker(&socketTestStore{}, "socket-secret", nil, WithRateLimit(60))
	worker.tokens = 0
	worker.fractionalTokens = 0.75
	worker.lastRefill = time.Now().Add(-15 * time.Second)

	if !worker.acquireToken() {
		t.Fatal("acquireToken() = false, want true after fractional refill reaches one whole token")
	}
	if worker.tokens != 0 {
		t.Fatalf("tokens after acquire = %d, want 0", worker.tokens)
	}
}

func TestDrainTokensClearsFractionalTokens(t *testing.T) {
	t.Parallel()

	worker := NewWorker(&socketTestStore{}, "socket-secret", nil, WithRateLimit(60))
	worker.tokens = 3
	worker.fractionalTokens = 0.75

	worker.drainTokens()

	if worker.tokens != 0 || worker.fractionalTokens != 0 {
		t.Fatalf("drained tokens = %d fractional %.2f, want 0/0", worker.tokens, worker.fractionalTokens)
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

func TestProcessIssuesContinuesAfterStoreError(t *testing.T) {
	t.Parallel()

	store := &socketErrorStore{}
	worker := NewWorker(store, "socket-secret", nil)
	err := worker.processIssues(context.Background(), &db.RefreshJob{Ecosystem: "npm", Name: "left-pad"}, &scoreResponse{
		Issues: []issueEntry{{Type: "malware", Severity: "critical"}},
	})
	if err != nil {
		t.Fatalf("processIssues() error = %v", err)
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
