package cisakev

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

// -- Store stub ---------------------------------------------------------------

type kevStoreStub struct {
	db.Store
	setCISAKEVIDs     []string
	clearCISAKEVKeep  []string
	setUpdated        int
	clearCleared      int
}

func (s *kevStoreStub) SetCISAKEV(_ context.Context, cveIDs []string) (int, error) {
	s.setCISAKEVIDs = cveIDs
	s.setUpdated = len(cveIDs)
	return s.setUpdated, nil
}

func (s *kevStoreStub) ClearCISAKEV(_ context.Context, keepIDs []string) (int, error) {
	s.clearCISAKEVKeep = keepIDs
	return s.clearCleared, nil
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

// Verify compile-time interface compliance.
var _ feed.FeedSyncer = (*Syncer)(nil)
