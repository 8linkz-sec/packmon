package cisakev

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

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

// -- Store stub ---------------------------------------------------------------

type kevStoreStub struct {
	db.Store
	status           *db.FeedSyncStatus
	setCISAKEVIDs    []string
	clearCISAKEVKeep []string
	replaceCVEIDs    []string
	getStatusCalled  bool
	setCalled        bool
	clearCalled      bool
	replaceCalled    bool
	setUpdated       int
	clearCleared     int
	replaceUpdated   int
	replaceCleared   int
	setErr           error
	clearErr         error
	replaceErr       error
}

func (s *kevStoreStub) GetFeedSyncStatus(_ context.Context, name string) (*db.FeedSyncStatus, error) {
	s.getStatusCalled = true
	if name != feedName {
		return nil, nil
	}
	if s.status == nil {
		return nil, nil
	}
	status := *s.status
	if s.status.Metadata != nil {
		status.Metadata = append([]byte(nil), s.status.Metadata...)
	}
	return &status, nil
}

func (s *kevStoreStub) ReplaceCISAKEV(_ context.Context, cveIDs []string) (int, int, error) {
	s.replaceCalled = true
	s.replaceCVEIDs = cveIDs
	if s.replaceErr != nil {
		return 0, 0, s.replaceErr
	}
	if s.replaceUpdated == 0 {
		s.replaceUpdated = len(cveIDs)
	}
	return s.replaceUpdated, s.replaceCleared, nil
}

func (s *kevStoreStub) SetCISAKEV(_ context.Context, cveIDs []string) (int, error) {
	s.setCalled = true
	s.setCISAKEVIDs = cveIDs
	if s.setErr != nil {
		return 0, s.setErr
	}
	s.setUpdated = len(cveIDs)
	return s.setUpdated, nil
}

func (s *kevStoreStub) ClearCISAKEV(_ context.Context, keepIDs []string) (int, error) {
	s.clearCalled = true
	s.clearCISAKEVKeep = keepIDs
	if s.clearErr != nil {
		return 0, s.clearErr
	}
	return s.clearCleared, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type errorReadCloser struct{}

func (errorReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func (errorReadCloser) Close() error {
	return nil
}

// -- Tests --------------------------------------------------------------------

func TestSync_ParsesKEVCatalog(t *testing.T) {
	t.Parallel()

	catalogPayload := catalog{
		Title:          "CISA KEV",
		CatalogVersion: "2026.04.03",
		Count:          2,
		Vulnerabilities: []catalogVulnEntry{
			{CVEID: "CVE-2021-44228", VendorProject: "Apache", Product: "Log4j"},
			{CVEID: "CVE-2023-0001", VendorProject: "TestVendor", Product: "TestProduct"},
		},
	}
	catalogJSON, err := json.Marshal(catalogPayload)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(catalogJSON)
	}))
	defer srv.Close()

	store := &kevStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	syncer := NewSyncer(logger,
		WithCatalogURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if result == nil {
		t.Fatal("Sync() result = nil, want non-nil")
	}
	if result.EntriesTotal != 2 {
		t.Errorf("EntriesTotal = %d, want 2", result.EntriesTotal)
	}
	if result.EntriesSynced != 2 {
		t.Errorf("EntriesSynced = %d, want 2", result.EntriesSynced)
	}

	// Verify the store received the complete snapshot.
	if !store.replaceCalled || len(store.replaceCVEIDs) != 2 {
		t.Fatalf("ReplaceCISAKEV called = %v with %d IDs, want 2", store.replaceCalled, len(store.replaceCVEIDs))
	}
	if store.setCalled || store.clearCalled {
		t.Fatalf("separate KEV mutations called despite replacement contract: set=%v clear=%v", store.setCalled, store.clearCalled)
	}

	expected := map[string]bool{
		"CVE-2021-44228": true,
		"CVE-2023-0001":  true,
	}
	for _, id := range store.replaceCVEIDs {
		if !expected[id] {
			t.Errorf("unexpected CVE ID %q in ReplaceCISAKEV call", id)
		}
	}
}

func TestSync_UsesAtomicReplacementWhenAvailable(t *testing.T) {
	t.Parallel()

	catalogJSON, err := json.Marshal(catalog{
		CatalogVersion: "2026.04.03",
		Count:          1,
		Vulnerabilities: []catalogVulnEntry{
			{CVEID: "CVE-2026-0001"},
		},
	})
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(catalogJSON)
	}))
	defer srv.Close()

	store := &kevStoreStub{replaceCleared: 2}
	syncer := NewSyncer(discardLogger(),
		WithCatalogURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 1 || result.EntriesTotal != 1 {
		t.Fatalf("Sync() result = %+v, want one updated of one total", result)
	}
	if !store.replaceCalled || len(store.replaceCVEIDs) != 1 || store.replaceCVEIDs[0] != "CVE-2026-0001" {
		t.Fatalf("ReplaceCISAKEV calls = called %v ids %+v", store.replaceCalled, store.replaceCVEIDs)
	}
	if store.setCalled || store.clearCalled {
		t.Fatalf("separate KEV mutations called despite replacement path: set=%v clear=%v", store.setCalled, store.clearCalled)
	}
}

func TestSync_SendsStoredHTTPValidatorsAndPersistsUpdatedMetadata(t *testing.T) {
	t.Parallel()

	catalogJSON, err := json.Marshal(catalog{
		CatalogVersion: "2026.04.04",
		Count:          1,
		Vulnerabilities: []catalogVulnEntry{
			{CVEID: "CVE-2026-0001"},
		},
	})
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}

	store := &kevStoreStub{
		status: &db.FeedSyncStatus{
			FeedName:       feedName,
			LastSyncStatus: db.FeedSyncStatusSuccess,
			LastETag:       `"stored-etag"`,
			Metadata:       []byte(`{"last_modified":"Mon, 01 Jun 2026 12:00:00 GMT"}`),
			EntriesSynced:  4,
			EntriesTotal:   4,
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got != `"stored-etag"` {
			t.Fatalf("If-None-Match = %q, want stored ETag", got)
		}
		if got := r.Header.Get("If-Modified-Since"); got != "Mon, 01 Jun 2026 12:00:00 GMT" {
			t.Fatalf("If-Modified-Since = %q, want stored Last-Modified", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"new-etag"`)
		w.Header().Set("Last-Modified", "Tue, 02 Jun 2026 12:00:00 GMT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(catalogJSON)
	}))
	defer srv.Close()

	syncer := NewSyncer(discardLogger(),
		WithCatalogURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if !store.getStatusCalled {
		t.Fatal("GetFeedSyncStatus was not called")
	}
	if !store.replaceCalled {
		t.Fatal("ReplaceCISAKEV was not called for modified catalog")
	}
	assertCISAKEVMetadata(t, result.Metadata, map[string]string{
		"etag":            `"new-etag"`,
		"last_modified":   "Tue, 02 Jun 2026 12:00:00 GMT",
		"catalog_version": "2026.04.04",
	})
}

func TestSync_TreatsNotModifiedAsSuccessfulUnchangedSync(t *testing.T) {
	t.Parallel()

	store := &kevStoreStub{
		status: &db.FeedSyncStatus{
			FeedName:       feedName,
			LastSyncStatus: db.FeedSyncStatusSuccess,
			LastETag:       `"stored-etag"`,
			Metadata:       []byte(`{"last_modified":"Mon, 01 Jun 2026 12:00:00 GMT"}`),
			EntriesSynced:  7,
			EntriesTotal:   9,
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("If-None-Match"); got != `"stored-etag"` {
			t.Fatalf("If-None-Match = %q, want stored ETag", got)
		}
		if got := r.Header.Get("If-Modified-Since"); got != "Mon, 01 Jun 2026 12:00:00 GMT" {
			t.Fatalf("If-Modified-Since = %q, want stored Last-Modified", got)
		}
		w.Header().Set("ETag", `"stored-etag"`)
		w.Header().Set("Last-Modified", "Mon, 01 Jun 2026 12:00:00 GMT")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	syncer := NewSyncer(discardLogger(),
		WithCatalogURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result == nil {
		t.Fatal("Sync() result = nil, want unchanged success result")
	}
	if result.EntriesSynced != 7 || result.EntriesTotal != 9 {
		t.Fatalf("Sync() result = %+v, want preserved counts 7/9", result)
	}
	if store.replaceCalled || store.setCalled || store.clearCalled {
		t.Fatalf("store mutated on 304: replace=%v set=%v clear=%v", store.replaceCalled, store.setCalled, store.clearCalled)
	}
	assertCISAKEVMetadata(t, result.Metadata, map[string]string{
		"etag":          `"stored-etag"`,
		"last_modified": "Mon, 01 Jun 2026 12:00:00 GMT",
	})
}

func TestSync_RejectsInvalidOrEmptyCatalogWithoutMutating(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "malformed json",
			body: `{`,
		},
		{
			name: "missing vulnerabilities",
			body: `{"error":"rate limited"}`,
		},
		{
			name: "empty vulnerabilities",
			body: `{"title":"CISA KEV","catalogVersion":"2026.04.03","dateReleased":"2026-04-03","count":0,"vulnerabilities":[]}`,
		},
		{
			name: "count mismatch",
			body: `{"title":"CISA KEV","catalogVersion":"2026.04.03","dateReleased":"2026-04-03","count":2,"vulnerabilities":[{"cveID":"CVE-2026-0001"}]}`,
		},
		{
			name: "invalid CVE ID",
			body: `{"title":"CISA KEV","catalogVersion":"2026.04.03","dateReleased":"2026-04-03","count":1,"vulnerabilities":[{"cveID":"not-a-cve"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			store := &kevStoreStub{}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))

			syncer := NewSyncer(logger,
				WithCatalogURL(srv.URL),
				WithHTTPClient(srv.Client()),
			)

			result, err := syncer.Sync(context.Background(), store)
			if err == nil {
				t.Fatal("Sync() error = nil, want invalid catalog error")
			}
			if !feed.IsNonRetryableError(err) {
				t.Fatalf("Sync() error = %v, want non-retryable invalid catalog error", err)
			}
			if result != nil {
				t.Fatalf("Sync() result = %+v, want nil", result)
			}
			if store.setCalled || store.clearCalled || store.replaceCalled {
				t.Fatalf("store mutated for invalid catalog: set=%v clear=%v replace=%v setIDs=%+v clearKeep=%+v replaceIDs=%+v",
					store.setCalled,
					store.clearCalled,
					store.replaceCalled,
					store.setCISAKEVIDs,
					store.clearCISAKEVKeep,
					store.replaceCVEIDs,
				)
			}
		})
	}
}

func TestSync_RejectsOversizedCatalogWithValidJSONPrefixWithoutMutating(t *testing.T) {
	t.Parallel()

	type paddedCatalog struct {
		Title           string             `json:"title"`
		CatalogVersion  string             `json:"catalogVersion"`
		DateReleased    string             `json:"dateReleased"`
		Count           int                `json:"count"`
		Vulnerabilities []catalogVulnEntry `json:"vulnerabilities"`
		Padding         string             `json:"padding"`
	}

	payload := paddedCatalog{
		Title:          "CISA KEV",
		CatalogVersion: "2026.04.03",
		DateReleased:   "2026-04-03",
		Count:          1,
		Vulnerabilities: []catalogVulnEntry{
			{CVEID: "CVE-2026-0001"},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	paddingLen := maxBodySize - len(body)
	if paddingLen <= 0 {
		t.Fatalf("test catalog length = %d, want less than max body size %d", len(body), maxBodySize)
	}
	payload.Padding = strings.Repeat("a", paddingLen)
	body, err = json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal padded catalog: %v", err)
	}
	if len(body) != maxBodySize {
		t.Fatalf("padded catalog length = %d, want %d", len(body), maxBodySize)
	}
	body = append(body, 'x')

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	store := &kevStoreStub{}
	syncer := NewSyncer(discardLogger(),
		WithCatalogURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want oversized body error")
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil", result)
	}
	if store.setCalled || store.clearCalled || store.replaceCalled {
		t.Fatalf("store mutated for oversized catalog: set=%v clear=%v replace=%v", store.setCalled, store.clearCalled, store.replaceCalled)
	}
}

func TestSync_HandlesHTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	store := &kevStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	syncer := NewSyncer(logger,
		WithCatalogURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want error for HTTP 500")
	}
	if result != nil {
		t.Errorf("Sync() result = %v, want nil", result)
	}
}

func TestSync_ReturnsTransportErrorWithoutMutatingCISAKEV(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("dial tcp: lookup cisa.example.test: no such host")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})}
	store := &kevStoreStub{}
	syncer := NewSyncer(discardLogger(),
		WithCatalogURL("https://cisa.example.test/known_exploited_vulnerabilities.json"),
		WithHTTPClient(client),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want transport error")
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("Sync() error = %v, want wrapped transport error", err)
	}
	if !strings.Contains(err.Error(), "cisakev: download catalog") || !strings.Contains(err.Error(), "http get") {
		t.Fatalf("Sync() error = %v, want download and HTTP context", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil", result)
	}
	if store.setCalled || store.clearCalled || store.replaceCalled {
		t.Fatalf("store mutated: set=%v clear=%v replace=%v", store.setCalled, store.clearCalled, store.replaceCalled)
	}
}

func TestSync_PropagatesStoreErrors(t *testing.T) {
	t.Parallel()

	catalogJSON, err := json.Marshal(catalog{
		CatalogVersion: "2026.04.03",
		Count:          1,
		Vulnerabilities: []catalogVulnEntry{
			{CVEID: "CVE-2026-0001"},
		},
	})
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(catalogJSON)
	}))
	defer srv.Close()

	tests := []struct {
		name  string
		store *kevStoreStub
		want  string
	}{
		{name: "replace", store: &kevStoreStub{replaceErr: errors.New("replace failed")}, want: "replace flags"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncer := NewSyncer(discardLogger(),
				WithCatalogURL(srv.URL),
				WithHTTPClient(srv.Client()),
			)
			result, err := syncer.Sync(context.Background(), tt.store)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Sync() error = %v, want containing %q", err, tt.want)
			}
			if result != nil {
				t.Fatalf("Sync() result = %+v, want nil", result)
			}
		})
	}
}

func TestDownloadCatalog_ErrorBranches(t *testing.T) {
	t.Parallel()

	if _, _, err := NewSyncer(discardLogger(), WithCatalogURL("://bad")).downloadCatalog(context.Background()); err == nil {
		t.Fatal("downloadCatalog(bad URL) error = nil, want error")
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{`))
	}))
	defer invalidJSON.Close()

	if _, _, err := NewSyncer(discardLogger(),
		WithCatalogURL(invalidJSON.URL),
		WithHTTPClient(invalidJSON.Client()),
	).downloadCatalog(context.Background()); err == nil || !strings.Contains(err.Error(), "parse json") {
		t.Fatalf("downloadCatalog(invalid JSON) error = %v, want parse json error", err)
	}

	readErrClient := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errorReadCloser{},
			}, nil
		}),
	}
	if _, _, err := NewSyncer(discardLogger(),
		WithCatalogURL("https://example.test/catalog.json"),
		WithHTTPClient(readErrClient),
	).downloadCatalog(context.Background()); err == nil || !strings.Contains(err.Error(), "read body") {
		t.Fatalf("downloadCatalog(read error) error = %v, want read body error", err)
	}
}

func TestSync_RejectsEmptyCVEIDsWithoutMutating(t *testing.T) {
	t.Parallel()

	catalogPayload := catalog{
		Title:          "CISA KEV",
		CatalogVersion: "2026.04.03",
		Count:          3,
		Vulnerabilities: []catalogVulnEntry{
			{CVEID: "CVE-2021-44228"},
			{CVEID: ""},
			{CVEID: "CVE-2023-0001"},
		},
	}
	catalogJSON, _ := json.Marshal(catalogPayload)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(catalogJSON)
	}))
	defer srv.Close()

	store := &kevStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	syncer := NewSyncer(logger,
		WithCatalogURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want invalid catalog error")
	}
	if !feed.IsNonRetryableError(err) {
		t.Fatalf("Sync() error = %v, want non-retryable invalid catalog error", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil", result)
	}
	if store.setCalled || store.clearCalled || store.replaceCalled {
		t.Fatalf("store mutated for invalid catalog: set=%v clear=%v replace=%v", store.setCalled, store.clearCalled, store.replaceCalled)
	}
}

func TestSyncerName(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil)
	if syncer.Name() != "cisakev" {
		t.Errorf("Name() = %q, want %q", syncer.Name(), "cisakev")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func assertCISAKEVMetadata(t *testing.T, raw json.RawMessage, want map[string]string) {
	t.Helper()

	if len(raw) == 0 {
		t.Fatal("metadata is empty")
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("metadata[%q] = %q, want %q in %s", key, got[key], wantValue, raw)
		}
	}
}

// Verify compile-time interface compliance.
var _ feed.FeedSyncer = (*Syncer)(nil)
