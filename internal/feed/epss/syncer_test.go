package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/feed"
)

// -- Store stub ---------------------------------------------------------------

type epssStoreStub struct {
	db.Store
	entries      []db.EPSSEntry
	totalUpdated int
	callCount    int
}

func (s *epssStoreStub) SetEPSSScores(_ context.Context, scores []db.EPSSEntry) (int, error) {
	s.entries = append(s.entries, scores...)
	s.callCount++
	s.totalUpdated += len(scores)
	return len(scores), nil
}

// -- Helper: gzip compress a string -------------------------------------------

func gzipCompress(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(data)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// -- Tests --------------------------------------------------------------------

func TestSync_ParsesEPSSCSV(t *testing.T) {
	t.Parallel()

	csvData := `#model_version:v2024.01.01,score_date:2026-04-03
cve,epss,percentile
CVE-2021-44228,0.97560,0.99990
CVE-2023-0001,0.01234,0.87654
CVE-2024-9999,0.00010,0.12300
`
	compressed := gzipCompress(t, csvData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(compressed)
	}))
	defer srv.Close()

	store := &epssStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	syncer := NewSyncer(logger,
		WithScoresURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result == nil {
		t.Fatal("Sync() result = nil, want non-nil")
	}
	if result.EntriesTotal != 3 {
		t.Errorf("EntriesTotal = %d, want 3", result.EntriesTotal)
	}
	if result.EntriesSynced != 3 {
		t.Errorf("EntriesSynced = %d, want 3", result.EntriesSynced)
	}

	// Verify the store received the correct entries.
	if len(store.entries) != 3 {
		t.Fatalf("store received %d entries, want 3", len(store.entries))
	}

	// Check first entry values.
	found := false
	for _, e := range store.entries {
		if e.CVEID == "CVE-2021-44228" {
			found = true
			if e.Score != 0.97560 {
				t.Errorf("CVE-2021-44228 score = %f, want 0.97560", e.Score)
			}
			if e.Percentile != 0.99990 {
				t.Errorf("CVE-2021-44228 percentile = %f, want 0.99990", e.Percentile)
			}
		}
	}
	if !found {
		t.Error("CVE-2021-44228 not found in store entries")
	}
}

func TestSync_HandlesEmptyCSV(t *testing.T) {
	t.Parallel()

	// Only comment and header, no data rows.
	csvData := `#model_version:v2024.01.01,score_date:2026-04-03
cve,epss,percentile
`
	compressed := gzipCompress(t, csvData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(compressed)
	}))
	defer srv.Close()

	store := &epssStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	syncer := NewSyncer(logger,
		WithScoresURL(srv.URL),
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
}

func TestSync_SkipsInvalidCVERows(t *testing.T) {
	t.Parallel()

	csvData := `#model_version:v2024.01.01
cve,epss,percentile
CVE-2021-44228,0.97560,0.99990
not-a-cve,0.50000,0.50000
CVE-2023-0001,invalid-score,0.87654
CVE-2024-1111,0.01000,invalid-percentile
CVE-2024-2222,0.02000,0.30000
`
	compressed := gzipCompress(t, csvData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(compressed)
	}))
	defer srv.Close()

	store := &epssStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	syncer := NewSyncer(logger,
		WithScoresURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	// Only CVE-2021-44228 and CVE-2024-2222 should parse successfully.
	if result.EntriesTotal != 2 {
		t.Errorf("EntriesTotal = %d, want 2", result.EntriesTotal)
	}
}

func TestSync_HandlesHTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	store := &epssStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	syncer := NewSyncer(logger,
		WithScoresURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	_, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want error for HTTP 503")
	}
}

func TestParseCSV_NoHeader(t *testing.T) {
	t.Parallel()

	// No header row -- the first non-comment line that does not look like
	// a header should be treated as data (defensive).
	csv := "CVE-2021-44228,0.97560,0.99990\n"
	entries, err := parseCSV(bytes.NewReader([]byte(csv)))
	if err != nil {
		t.Fatalf("parseCSV() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("parseCSV() returned %d entries, want 1", len(entries))
	}
	if entries[0].CVEID != "CVE-2021-44228" {
		t.Errorf("CVEID = %q, want CVE-2021-44228", entries[0].CVEID)
	}
}

func TestSyncerName(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil)
	if syncer.Name() != "epss" {
		t.Errorf("Name() = %q, want %q", syncer.Name(), "epss")
	}
}

// Verify compile-time interface compliance.
var _ feed.FeedSyncer = (*Syncer)(nil)
