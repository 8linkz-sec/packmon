package epss

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	status           *db.FeedSyncStatus
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

func (s *epssStoreStub) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	if s.status == nil {
		return nil, nil
	}
	status := *s.status
	if s.status.Metadata != nil {
		status.Metadata = append([]byte(nil), s.status.Metadata...)
	}
	return &status, nil
}

type epssStreamingStoreStub struct {
	epssStoreStub
	streamReplaceCallCount int
	streamBatchSizes       []int
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type readTrackingBody struct {
	reader             *bytes.Reader
	replaceActive      *atomic.Bool
	readsDuringReplace atomic.Int32
	reachedEOF         atomic.Bool
}

func (b *readTrackingBody) Read(p []byte) (int, error) {
	if b.replaceActive.Load() {
		b.readsDuringReplace.Add(1)
	}
	n, err := b.reader.Read(p)
	if err == io.EOF || b.reader.Len() == 0 {
		b.reachedEOF.Store(true)
	}
	return n, err
}

func (b *readTrackingBody) Close() error {
	return nil
}

type epssStreamingStoreObserver struct {
	epssStreamingStoreStub
	replaceActive *atomic.Bool
}

func (s *epssStreamingStoreObserver) ReplaceEPSSScoresStream(ctx context.Context, stream func(func([]db.EPSSEntry) error) error) (int, int, int, error) {
	s.replaceActive.Store(true)
	defer s.replaceActive.Store(false)
	return s.epssStreamingStoreStub.ReplaceEPSSScoresStream(ctx, stream)
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

func TestSync_DrainsUpstreamBodyBeforeStreamingReplace(t *testing.T) {
	t.Parallel()

	csvData := `#model_version:v2024.01.01,score_date:2026-04-03
cve,epss,percentile
CVE-2021-44228,0.97560,0.99990
CVE-2023-0001,0.01234,0.87654
`
	compressed := gzipCompress(t, csvData)
	var replaceActive atomic.Bool
	body := &readTrackingBody{
		reader:        bytes.NewReader(compressed),
		replaceActive: &replaceActive,
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Encoding": []string{"gzip"}},
			Body:       body,
			Request:    req,
		}, nil
	})}
	store := &epssStreamingStoreObserver{replaceActive: &replaceActive}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithScoresURL("https://epss.example.test/epss_scores-current.csv.gz"),
		WithHTTPClient(client),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesTotal != 2 || result.EntriesSynced != 2 {
		t.Fatalf("Sync() result = %+v, want 2/2", result)
	}
	if store.streamReplaceCallCount != 1 {
		t.Fatalf("ReplaceEPSSScoresStream called %d times, want 1", store.streamReplaceCallCount)
	}
	if !body.reachedEOF.Load() {
		t.Fatal("upstream body was not fully read before streaming replace")
	}
	if reads := body.readsDuringReplace.Load(); reads != 0 {
		t.Fatalf("upstream body read %d times during streaming replace, want 0", reads)
	}
}

func TestSync_SendsStoredHTTPValidatorsAndSkipsUnchangedSnapshot(t *testing.T) {
	t.Parallel()

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("If-None-Match"); got != `"epss-etag"` {
			t.Fatalf("If-None-Match = %q, want stored ETag", got)
		}
		if got := r.Header.Get("If-Modified-Since"); got != "Mon, 29 Jun 2026 12:00:00 GMT" {
			t.Fatalf("If-Modified-Since = %q, want stored Last-Modified", got)
		}
		w.Header().Set("ETag", `"epss-etag"`)
		w.Header().Set("Last-Modified", "Mon, 29 Jun 2026 12:00:00 GMT")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	store := &epssStoreStub{status: &db.FeedSyncStatus{
		FeedName:       feedName,
		EntriesSynced:  12,
		EntriesTotal:   34,
		LastETag:       `"epss-etag"`,
		Metadata:       []byte(`{"last_modified":"Mon, 29 Jun 2026 12:00:00 GMT","model_version":"v2026.06.29"}`),
		LastSyncStatus: db.FeedSyncStatusSuccess,
	}}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithScoresURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	if store.replaceCallCount != 0 || len(store.entries) != 0 {
		t.Fatalf("store mutated: replace=%d entries=%+v, want none", store.replaceCallCount, store.entries)
	}
	if result.EntriesSynced != 12 || result.EntriesTotal != 34 {
		t.Fatalf("Sync() result = %+v, want preserved counts 12/34", result)
	}
	if !strings.Contains(string(result.Metadata), `"etag":"\"epss-etag\""`) ||
		!strings.Contains(string(result.Metadata), `"last_modified":"Mon, 29 Jun 2026 12:00:00 GMT"`) ||
		!strings.Contains(string(result.Metadata), `"model_version":"v2026.06.29"`) {
		t.Fatalf("Sync() metadata = %s, want stored validators and metadata", result.Metadata)
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

func TestParseEPSSCSVRecordClassifiesCommentHeaderAndData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		record           []string
		wantKind         epssCSVRecordKind
		wantModelVersion string
		wantScoreDate    string
	}{
		{
			name:             "comment metadata",
			record:           []string{"#model_version:v2024.01.01", "score_date:2026-04-03"},
			wantKind:         epssCSVRecordComment,
			wantModelVersion: "v2024.01.01",
			wantScoreDate:    "2026-04-03",
		},
		{
			name:     "header",
			record:   []string{" cve ", " EPSS ", " percentile "},
			wantKind: epssCSVRecordHeader,
		},
		{
			name:     "data",
			record:   []string{"CVE-2026-0001", "0.12345", "0.98765"},
			wantKind: epssCSVRecordData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEPSSCSVRecord(7, tt.record)
			if got.kind != tt.wantKind {
				t.Fatalf("parseEPSSCSVRecord() kind = %v, want %v", got.kind, tt.wantKind)
			}
			if got.metadata.ModelVersion != tt.wantModelVersion || got.metadata.ScoreDate != tt.wantScoreDate {
				t.Fatalf("parseEPSSCSVRecord() metadata = %+v, want model=%q date=%q", got.metadata, tt.wantModelVersion, tt.wantScoreDate)
			}
		})
	}
}

func TestParseEPSSEntryRejectsInvalidScalarValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		record  []string
		wantErr string
	}{
		{
			name:    "nan score",
			record:  []string{"CVE-2026-0001", "NaN", "0.50000"},
			wantErr: "EPSS score NaN outside range 0..1",
		},
		{
			name:    "infinite score",
			record:  []string{"CVE-2026-0001", "+Inf", "0.50000"},
			wantErr: "EPSS score +Inf outside range 0..1",
		},
		{
			name:    "nan percentile",
			record:  []string{"CVE-2026-0001", "0.50000", "NaN"},
			wantErr: "EPSS percentile NaN outside range 0..1",
		},
		{
			name:    "infinite percentile",
			record:  []string{"CVE-2026-0001", "0.50000", "-Inf"},
			wantErr: "EPSS percentile -Inf outside range 0..1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseEPSSEntry(4, tt.record)
			if err == nil {
				t.Fatalf("parseEPSSEntry() error = nil, entry = %+v", entry)
			}
			if !feed.IsNonRetryableError(err) {
				t.Fatalf("parseEPSSEntry() error = %v, want non-retryable marker", err)
			}
			if !strings.Contains(err.Error(), "row 4") || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseEPSSEntry() error = %v, want row-numbered %q", err, tt.wantErr)
			}
		})
	}
}

func TestSync_RejectsEmptyCSV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		csvData string
		wantErr string
	}{
		{
			name:    "blank payload",
			csvData: "",
			wantErr: "expected header",
		},
		{
			name: "only comment and header",
			csvData: `#model_version:v2024.01.01,score_date:2026-04-03
cve,epss,percentile
`,
			wantErr: "no EPSS score rows",
		},
		{
			name:    "missing header",
			csvData: "CVE-2021-44228,0.97560,0.99990\n",
			wantErr: "expected header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed := gzipCompress(t, tt.csvData)

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
			if !feed.IsNonRetryableError(err) {
				t.Fatalf("Sync() error = %v, want non-retryable marker", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Sync() error = %v, want %q", err, tt.wantErr)
			}
			if result != nil {
				t.Fatalf("Sync() result = %+v, want nil", result)
			}
			if store.callCount != 0 || store.replaceCallCount != 0 || len(store.entries) != 0 {
				t.Fatalf("store mutated: set=%d replace=%d entries=%+v, want none", store.callCount, store.replaceCallCount, store.entries)
			}
		})
	}
}

func TestSync_RejectsInvalidCVERows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		row     string
		wantErr string
	}{
		{
			name:    "invalid cve shape",
			row:     "CVE-not-year,0.50000,0.50000",
			wantErr: "invalid CVE",
		},
		{
			name:    "invalid score",
			row:     "CVE-2023-0001,invalid-score,0.87654",
			wantErr: "invalid EPSS score",
		},
		{
			name:    "score out of range",
			row:     "CVE-2023-0001,1.50000,0.87654",
			wantErr: "outside range",
		},
		{
			name:    "invalid percentile",
			row:     "CVE-2024-1111,0.01000,invalid-percentile",
			wantErr: "invalid EPSS percentile",
		},
		{
			name:    "percentile out of range",
			row:     "CVE-2024-1111,0.01000,-0.10000",
			wantErr: "outside range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csvData := `#model_version:v2024.01.01
cve,epss,percentile
` + tt.row + "\n"
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
			if !feed.IsNonRetryableError(err) {
				t.Fatalf("Sync() error = %v, want non-retryable marker", err)
			}
			if !strings.Contains(err.Error(), "row 3") || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Sync() error = %v, want row-numbered %q", err, tt.wantErr)
			}
			if result != nil {
				t.Fatalf("Sync() result = %+v, want nil", result)
			}
			if store.callCount != 0 || store.replaceCallCount != 0 || len(store.entries) != 0 {
				t.Fatalf("store mutated: set=%d replace=%d entries=%+v, want none", store.callCount, store.replaceCallCount, store.entries)
			}
		})
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
	if feed.IsNonRetryableError(err) {
		t.Fatalf("Sync() error = %v, want retryable HTTP error", err)
	}
}

func TestSync_ReturnsTransportErrorWithoutReplacingEPSS(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("dial tcp: connect: connection refused")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})}
	store := &epssStoreStub{}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithScoresURL("https://epss.example.test/epss_scores-current.csv.gz"),
		WithHTTPClient(client),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want transport error")
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("Sync() error = %v, want wrapped transport error", err)
	}
	if feed.IsNonRetryableError(err) {
		t.Fatalf("Sync() error = %v, want retryable transport error", err)
	}
	if !strings.Contains(err.Error(), "epss: download scores") || !strings.Contains(err.Error(), "http get") {
		t.Fatalf("Sync() error = %v, want download and HTTP context", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil", result)
	}
	if store.callCount != 0 || store.replaceCallCount != 0 || len(store.entries) != 0 {
		t.Fatalf("store mutated: set=%d replace=%d entries=%+v, want none", store.callCount, store.replaceCallCount, store.entries)
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
	if !feed.IsNonRetryableError(err) {
		t.Fatalf("parseCSV() error = %v, want non-retryable marker", err)
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
	if !feed.IsNonRetryableError(err) {
		t.Fatalf("parseCSV() error = %v, want non-retryable marker", err)
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
	if !feed.IsNonRetryableError(err) {
		t.Fatalf("parseLimitedCSV() error = %v, want non-retryable marker", err)
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
