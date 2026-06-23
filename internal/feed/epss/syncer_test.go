package epss

import (
	"bytes"
	"compress/gzip"
	"context"
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

type epssStoreStub struct {
	db.Store
	entries          []db.EPSSEntry
	totalUpdated     int
	callCount        int
	replaceCallCount int
	cleared          int
}

func (s *epssStoreStub) SetEPSSScores(_ context.Context, scores []db.EPSSEntry) (int, error) {
	s.entries = append(s.entries, scores...)
	s.callCount++
	s.totalUpdated += len(scores)
	return len(scores), nil
}

func (s *epssStoreStub) ReplaceEPSSScores(_ context.Context, scores []db.EPSSEntry) (int, int, error) {
	s.entries = append(s.entries, scores...)
	s.replaceCallCount++
	s.totalUpdated += len(scores)
	return len(scores), s.cleared, nil
}

type epssStreamingStoreStub struct {
	epssStoreStub
	streamReplaceCallCount int
	streamBatchSizes       []int
}

func (s *epssStreamingStoreStub) ReplaceEPSSScoresStream(_ context.Context, stream func(func([]db.EPSSEntry) error) error) (int, int, int, error) {
	s.streamReplaceCallCount++
	total := 0
	err := stream(func(batch []db.EPSSEntry) error {
		s.streamBatchSizes = append(s.streamBatchSizes, len(batch))
		s.entries = append(s.entries, batch...)
		total += len(batch)
		return nil
	})
	if err != nil {
		return 0, 0, total, err
	}
	s.totalUpdated += total
	return total, s.cleared, total, nil
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
	if !strings.Contains(string(result.Metadata), `"model_version":"v2024.01.01"`) ||
		!strings.Contains(string(result.Metadata), `"score_date":"2026-04-03"`) {
		t.Fatalf("Sync() metadata = %s, want model version and score date", result.Metadata)
	}
	if store.replaceCallCount != 1 {
		t.Fatalf("ReplaceEPSSScores called %d times, want 1", store.replaceCallCount)
	}
	if store.callCount != 0 {
		t.Fatalf("SetEPSSScores called %d times, want 0", store.callCount)
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

func TestSync_StreamsEPSSCSVWhenStoreSupportsStreaming(t *testing.T) {
	t.Parallel()

	csvData := `#model_version:v2024.01.01,score_date:2026-04-03
cve,epss,percentile
CVE-2021-44228,0.97560,0.99990
CVE-2023-0001,0.01234,0.87654
CVE-2024-9999,0.00010,0.12300
`
	compressed := gzipCompress(t, csvData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(compressed)
	}))
	defer srv.Close()

	store := &epssStreamingStoreStub{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithScoresURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if store.streamReplaceCallCount != 1 {
		t.Fatalf("ReplaceEPSSScoresStream called %d times, want 1", store.streamReplaceCallCount)
	}
	if store.replaceCallCount != 0 {
		t.Fatalf("ReplaceEPSSScores fallback called %d times, want 0", store.replaceCallCount)
	}
	if result.EntriesTotal != 3 || result.EntriesSynced != 3 {
		t.Fatalf("Sync() result = %+v, want 3/3", result)
	}
	if len(store.entries) != 3 {
		t.Fatalf("streamed entries = %d, want 3", len(store.entries))
	}
}

func TestStreamCSVFlushesBoundedBatchesAndMetadata(t *testing.T) {
	t.Parallel()

	csvData := `#model_version:v2024.01.01,score_date:2026-04-03
cve,epss,percentile
CVE-2021-44228,0.97560,0.99990
CVE-2023-0001,0.01234,0.87654
CVE-2024-9999,0.00010,0.12300
`
	var batches []int
	var ids []string
	total, metadata, err := streamCSV(strings.NewReader(csvData), 2, func(batch []db.EPSSEntry) error {
		batches = append(batches, len(batch))
		for _, entry := range batch {
			ids = append(ids, entry.CVEID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("streamCSV() error = %v", err)
	}
	if total != 3 {
		t.Fatalf("streamCSV() total = %d, want 3", total)
	}
	if metadata.ModelVersion != "v2024.01.01" || metadata.ScoreDate != "2026-04-03" {
		t.Fatalf("metadata = %+v, want model version and score date", metadata)
	}
	if len(batches) != 2 || batches[0] != 2 || batches[1] != 1 {
		t.Fatalf("batches = %+v, want [2 1]", batches)
	}
	if strings.Join(ids, ",") != "CVE-2021-44228,CVE-2023-0001,CVE-2024-9999" {
		t.Fatalf("ids = %+v", ids)
	}
}

func TestSync_RejectsEmptyCSV(t *testing.T) {
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
	if err == nil {
		t.Fatal("Sync() error = nil, want empty feed error")
	}
	if !strings.Contains(err.Error(), "no EPSS score rows") {
		t.Fatalf("Sync() error = %v, want no rows", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil", result)
	}
	if store.callCount != 0 {
		t.Fatalf("SetEPSSScores called %d times, want 0", store.callCount)
	}
}

func TestSync_RejectsInvalidCVERows(t *testing.T) {
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
	if err == nil {
		t.Fatal("Sync() error = nil, want malformed row error")
	}
	if !strings.Contains(err.Error(), "row 4") || !strings.Contains(err.Error(), "invalid CVE") {
		t.Fatalf("Sync() error = %v, want row-numbered invalid CVE", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil", result)
	}
	if store.callCount != 0 {
		t.Fatalf("SetEPSSScores called %d times, want 0", store.callCount)
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

	csv := "CVE-2021-44228,0.97560,0.99990\n"
	entries, err := parseCSV(bytes.NewReader([]byte(csv)))
	if err == nil {
		t.Fatal("parseCSV() error = nil, want missing header error")
	}
	if !strings.Contains(err.Error(), "expected header") {
		t.Fatalf("parseCSV() error = %v, want expected header", err)
	}
	if len(entries) != 0 {
		t.Fatalf("parseCSV() returned %d entries, want 0", len(entries))
	}
}

func TestParseCSV_RejectsWrongHeader(t *testing.T) {
	t.Parallel()

	entries, err := parseCSV(strings.NewReader("html,error,page\nnot,csv,data\n"))
	if err == nil {
		t.Fatal("parseCSV() error = nil, want wrong header error")
	}
	if !strings.Contains(err.Error(), "expected header") {
		t.Fatalf("parseCSV() error = %v, want expected header", err)
	}
	if len(entries) != 0 {
		t.Fatalf("parseCSV() returned %d entries, want 0", len(entries))
	}
}

func TestParseLimitedCSVRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	csv := "cve,epss,percentile\nCVE-2026-0001,0.1,0.2\n"
	entries, _, err := parseLimitedCSV(strings.NewReader(csv), int64(len(csv)-1))
	if err == nil {
		t.Fatal("parseLimitedCSV() error = nil, want oversized payload error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("parseLimitedCSV() error = %v, want exceeds", err)
	}
	if len(entries) != 0 {
		t.Fatalf("parseLimitedCSV() returned %d entries, want 0", len(entries))
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
