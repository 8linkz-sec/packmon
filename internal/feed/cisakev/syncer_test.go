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

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

// -- Store stub ---------------------------------------------------------------

type kevStoreStub struct {
	db.Store
	setCISAKEVIDs    []string
	clearCISAKEVKeep []string
	setUpdated       int
	clearCleared     int
	setErr           error
	clearErr         error
}

func (s *kevStoreStub) SetCISAKEV(_ context.Context, cveIDs []string) (int, error) {
	s.setCISAKEVIDs = cveIDs
	if s.setErr != nil {
		return 0, s.setErr
	}
	s.setUpdated = len(cveIDs)
	return s.setUpdated, nil
}

func (s *kevStoreStub) ClearCISAKEV(_ context.Context, keepIDs []string) (int, error) {
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

func TestSync_HandlesEmptyCatalog(t *testing.T) {
	t.Parallel()

	catalogPayload := catalog{
		Title:           "CISA KEV",
		CatalogVersion:  "2026.04.03",
		Count:           0,
		Vulnerabilities: []catalogVulnEntry{},
	}
	catalogJSON, err := json.Marshal(catalogPayload)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		t.Fatalf("Sync() error = %v, want nil", err)
	}
	if result == nil {
		t.Fatal("Sync() result = nil, want non-nil")
	}
	if result.EntriesTotal != 0 {
		t.Errorf("EntriesTotal = %d, want 0", result.EntriesTotal)
	}
	if result.EntriesSynced != 0 {
		t.Errorf("EntriesSynced = %d, want 0", result.EntriesSynced)
	}
	if len(store.setCISAKEVIDs) != 0 {
		t.Errorf("SetCISAKEV called with %d IDs, want 0", len(store.setCISAKEVIDs))
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

func TestSync_SkipsEmptyCVEIDs(t *testing.T) {
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
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	// Only 2 non-empty CVE IDs should be passed to the store.
	if result.EntriesTotal != 2 {
		t.Errorf("EntriesTotal = %d, want 2", result.EntriesTotal)
	}
	if len(store.setCISAKEVIDs) != 2 {
		t.Errorf("SetCISAKEV called with %d IDs, want 2", len(store.setCISAKEVIDs))
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
