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
	setCISAKEVIDs    []string
	clearCISAKEVKeep []string
	setCalled        bool
	clearCalled      bool
	setUpdated       int
	clearCleared     int
	setErr           error
	clearErr         error
}

type kevReplaceStoreStub struct {
	kevStoreStub
	replaceCalled  bool
	replaceCVEIDs  []string
	replaceUpdated int
	replaceCleared int
	replaceErr     error
}

func (s *kevReplaceStoreStub) ReplaceCISAKEV(_ context.Context, cveIDs []string) (int, int, error) {
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

	// Verify the store received the correct CVE IDs.
	if len(store.setCISAKEVIDs) != 2 {
		t.Fatalf("SetCISAKEV called with %d IDs, want 2", len(store.setCISAKEVIDs))
	}

	expected := map[string]bool{
		"CVE-2021-44228": true,
		"CVE-2023-0001":  true,
	}
	for _, id := range store.setCISAKEVIDs {
		if !expected[id] {
			t.Errorf("unexpected CVE ID %q in SetCISAKEV call", id)
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

	store := &kevReplaceStoreStub{replaceCleared: 2}
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

func TestSync_RejectsInvalidOrEmptyCatalogWithoutMutating(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
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
			if result != nil {
				t.Fatalf("Sync() result = %+v, want nil", result)
			}
			if store.setCalled || store.clearCalled {
				t.Fatalf("store mutated for invalid catalog: set=%v clear=%v setIDs=%+v clearKeep=%+v",
					store.setCalled,
					store.clearCalled,
					store.setCISAKEVIDs,
					store.clearCISAKEVKeep,
				)
			}
		})
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
		{name: "set", store: &kevStoreStub{setErr: errors.New("set failed")}, want: "set flags"},
		{name: "clear", store: &kevStoreStub{clearErr: errors.New("clear failed")}, want: "clear stale flags"},
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
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil", result)
	}
	if store.setCalled || store.clearCalled {
		t.Fatalf("store mutated for invalid catalog: set=%v clear=%v", store.setCalled, store.clearCalled)
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

// Verify compile-time interface compliance.
var _ feed.FeedSyncer = (*Syncer)(nil)
