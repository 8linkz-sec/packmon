package reversinglabs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type fakeStore struct {
	due           []db.PackageReputation
	upserts       []db.PackageReputation
	dequeued      *db.RefreshJob
	dequeueErr    error
	completeErr   error
	completedJob  int
	completedErr  error
	resetCount    int
	resetErr      error
	dequeueCalled int
}

func (s *fakeStore) DequeueRefresh(context.Context, string) (*db.RefreshJob, error) {
	s.dequeueCalled++
	return s.dequeued, s.dequeueErr
}

func (s *fakeStore) CompleteRefresh(_ context.Context, id int, err error) error {
	s.completedJob = id
	s.completedErr = err
	return s.completeErr
}

func (s *fakeStore) ResetStuckJobs(context.Context, string, time.Duration) (int, error) {
	return s.resetCount, s.resetErr
}

func (s *fakeStore) ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error) {
	return append([]db.PackageReputation(nil), s.due...), nil
}

func (s *fakeStore) UpsertPackageReputation(_ context.Context, rep *db.PackageReputation) error {
	s.upserts = append(s.upserts, *rep)
	return nil
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
		WithRateLimit(12),
	)

	if w.Name() != FeedName {
		t.Fatalf("Name() = %q, want %q", w.Name(), FeedName)
	}
	if w.httpClient != httpClient {
		t.Fatal("WithHTTPClient did not install provided client")
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
	if w.tokens != 12 || w.maxTokens != 12 {
		t.Fatalf("tokens = %d/%d, want 12/12", w.tokens, w.maxTokens)
	}
}

type dbStoreFake struct {
	db.Store
}

func (*dbStoreFake) DequeueRefresh(context.Context, string) (*db.RefreshJob, error) {
	return nil, nil
}

func (*dbStoreFake) CompleteRefresh(context.Context, int, error) error {
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
	if w.batchSize != defaultBatchSize || w.tokens != defaultRateLimitPerHour || w.maxTokens != defaultRateLimitPerHour {
		t.Fatalf("batch/tokens = %d/%d/%d, want defaults", w.batchSize, w.tokens, w.maxTokens)
	}

	w = NewWorker(store, "token", nil, WithBatchSize(3), WithRateLimit(7))
	if w.batchSize != 3 || w.tokens != 7 || w.maxTokens != 7 {
		t.Fatalf("valid option values = batch %d tokens %d/%d", w.batchSize, w.tokens, w.maxTokens)
	}
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
	if err := json.Unmarshal([]byte(`"bad"`), &incidents); err == nil || !strings.Contains(err.Error(), "unexpected incidents") {
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

func TestProcessNextJobTokenAndCompletionBranches(t *testing.T) {
	t.Parallel()

	noTokenStore := &fakeStore{}
	noTokenWorker := newWorker(noTokenStore, "token", slog.Default())
	noTokenWorker.tokens = 0
	noTokenWorker.maxTokens = 1
	noTokenWorker.lastRefill = time.Now()
	noTokenWorker.processNextJob(context.Background())
	if noTokenStore.dequeueCalled != 0 {
		t.Fatalf("dequeueCalled = %d, want 0 without token", noTokenStore.dequeueCalled)
	}

	noJobStore := &fakeStore{}
	noJobWorker := newWorker(noJobStore, "token", slog.Default())
	noJobWorker.tokens = 1
	noJobWorker.processNextJob(context.Background())
	if noJobStore.dequeueCalled != 1 {
		t.Fatalf("dequeueCalled = %d, want 1", noJobStore.dequeueCalled)
	}
	if noJobWorker.tokens != 1 {
		t.Fatalf("token after empty dequeue = %d, want returned token", noJobWorker.tokens)
	}

	dequeueErrStore := &fakeStore{dequeueErr: errors.New("queue down")}
	dequeueErrWorker := newWorker(dequeueErrStore, "token", slog.Default())
	dequeueErrWorker.processNextJob(context.Background())
	if dequeueErrStore.completedJob != 0 {
		t.Fatalf("completedJob = %d, want no completion on dequeue error", dequeueErrStore.completedJob)
	}

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
	if statuses["bad"] != "malicious" {
		t.Fatalf("bad status = %q, want malicious", statuses["bad"])
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

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL(server.URL), WithLookupTTL(24*time.Hour))
	w.tokens = 3

	results, err := w.lookupBatch(context.Background(), []db.PackageReputation{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Source: FeedName, Status: "pending"},
	})
	if err == nil {
		t.Fatal("lookupBatch() error = nil, want rate-limit error")
	}
	if results != nil {
		t.Fatalf("results = %+v, want nil on rate limit", results)
	}
	if w.tokens != 0 {
		t.Fatalf("tokens = %d, want drained tokens after 429", w.tokens)
	}
	if w.fractionalTokens != 0 {
		t.Fatalf("fractionalTokens = %.2f, want drained fractional tokens after 429", w.fractionalTokens)
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

	if err := w.processJob(context.Background(), store.dequeued); err != nil {
		t.Fatalf("processJob() error = %v", err)
	}
	if called {
		t.Fatal("API was called for unsupported package")
	}
	if len(store.upserts) != 1 || store.upserts[0].Status != "unsupported" || store.upserts[0].NextCheckAt != nil {
		t.Fatalf("upserts = %+v, want terminal unsupported row", store.upserts)
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

	err := w.processJob(context.Background(), store.dequeued)
	if err == nil {
		t.Fatal("processJob() error = nil, want lookup error")
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

	if got := maliciousSignals(pkg); len(got) != 5 {
		t.Fatalf("maliciousSignals() = %#v, want all five signals", got)
	}
	if got := removedSignals(pkg); len(got) != 2 {
		t.Fatalf("removedSignals() = %#v, want current-state removal signals only", got)
	}

	for _, status := range []string{"malicious", "removed", "clean", "not_found"} {
		if !isDefinitiveStatus(status) {
			t.Fatalf("isDefinitiveStatus(%q) = false, want true", status)
		}
	}
	if isDefinitiveStatus(" pending ") {
		t.Fatal("isDefinitiveStatus(pending) = true, want false")
	}

	w := newWorker(&fakeStore{}, "token", slog.Default(), WithRateLimit(2))
	w.tokens = 0
	w.lastRefill = time.Now().Add(-2 * time.Hour)
	if !w.acquireToken() {
		t.Fatal("acquireToken() = false, want refilled token")
	}
	w.returnToken()
	w.returnToken()
	if w.tokens != w.maxTokens {
		t.Fatalf("tokens after capped return = %d, want %d", w.tokens, w.maxTokens)
	}
	w.fractionalTokens = 0.75
	w.drainTokens()
	if w.tokens != 0 || w.fractionalTokens != 0 {
		t.Fatalf("drained tokens = %d fractional %.2f, want 0/0", w.tokens, w.fractionalTokens)
	}

	store := &fakeStore{resetCount: 2}
	newWorker(store, "token", slog.Default()).resetStuckJobs(context.Background())
	store.resetErr = errors.New("reset failed")
	newWorker(store, "token", slog.Default()).resetStuckJobs(context.Background())
}
