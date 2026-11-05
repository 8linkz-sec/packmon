package reversinglabs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type reversingLabsFailingBody struct{}

func (reversingLabsFailingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (reversingLabsFailingBody) Close() error             { return nil }

type reversingLabsNoPruneStore struct{ reputationStore }

func TestWorkerPruneCompletionAndEmptyLookupBranches(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	worker := newWorker(store, "token", slog.Default())
	worker.cacheRetention = 0
	worker.pruneCache(context.Background())
	worker.cacheRetention = time.Hour
	worker.lastPrune = time.Now()
	store.prunedSource = ""
	worker.pruneCache(context.Background())
	if store.prunedSource != "" {
		t.Fatalf("prunedSource = %q, want no prune", store.prunedSource)
	}
	noPrune := newWorker(reversingLabsNoPruneStore{reputationStore: &fakeStore{}}, "token", slog.Default())
	noPrune.pruneCache(context.Background())

	if err := completeQueueJob(context.Background(), store, nil, nil, nil); err != nil {
		t.Fatalf("completeQueueJob(nil) error = %v", err)
	}
	if got, err := worker.lookupBatch(context.Background(), nil); err != nil || got != nil {
		t.Fatalf("lookupBatch(nil) = %+v, %v", got, err)
	}
	requests, byUUID := buildLookupRequests([]db.PackageReputation{{Ecosystem: "unsupported", Name: "pkg", Version: "1"}})
	if len(requests) != 0 || len(byUUID) != 0 {
		t.Fatalf("buildLookupRequests(unsupported) = %+v, %+v", requests, byUUID)
	}
}

func TestIncidentUnmarshalErrorBranches(t *testing.T) {
	t.Parallel()

	var incidents searchIncidents
	if err := json.Unmarshal([]byte(`{"bad":`), &incidents); err == nil {
		t.Fatal("searchIncidents malformed object error = nil")
	}
	if err := json.Unmarshal([]byte(`1e9999`), &incidents); err == nil {
		t.Fatal("searchIncidents invalid number error = nil")
	}
	var incident searchIncident
	if err := json.Unmarshal([]byte(`"unterminated`), &incident); err == nil {
		t.Fatal("searchIncident malformed string error = nil")
	}
	if err := json.Unmarshal([]byte(`1.5`), &incident); err == nil {
		t.Fatal("searchIncident non-integer count error = nil")
	}
}

func TestPostLookupRequestConstructionAndReadErrors(t *testing.T) {
	t.Parallel()

	rep := db.PackageReputation{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"}
	worker := newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL("://bad"))
	requests, _ := buildLookupRequests([]db.PackageReputation{rep})
	if _, _, err := worker.postLookupRequest(context.Background(), requests); err == nil {
		t.Fatal("postLookupRequest(bad URL) error = nil")
	}

	worker = newWorker(&fakeStore{}, "token", slog.Default(), WithBaseURL("https://example.test"), WithHTTPClient(&http.Client{
		Transport: reversingLabsRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: reversingLabsFailingBody{}}, nil
		}),
	}))
	if _, _, err := worker.postLookupRequest(context.Background(), requests); err == nil {
		t.Fatal("postLookupRequest(read error) error = nil")
	}

	now := time.Now().UTC()
	got := worker.statusResult(rep, "risk", "history", nil, now)
	if got.Severity != "HIGH" {
		t.Fatalf("statusResult(risk) severity = %q", got.Severity)
	}
}
