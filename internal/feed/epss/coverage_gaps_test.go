package epss

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

type epssFailingBody struct{}

func (epssFailingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (epssFailingBody) Close() error             { return nil }

type epssStatusErrorStore struct{ db.Store }

func (epssStatusErrorStore) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	return nil, errors.New("status unavailable")
}

type epssGapReplacer struct {
	updated, cleared, total int
	err                     error
}

func (r epssGapReplacer) ReplaceEPSSScoresStream(_ context.Context, stream func(func([]db.EPSSEntry) error) error) (int, int, int, error) {
	if err := stream(func([]db.EPSSEntry) error { return nil }); err != nil {
		return 0, 0, 0, err
	}
	return r.updated, r.cleared, r.total, r.err
}

func TestEPSSSnapshotAndMetadataEmptyBranches(t *testing.T) {
	t.Parallel()

	var snapshot epssScoreSnapshot
	if err := snapshot.addBatch(nil); err != nil || snapshot.total != 0 {
		t.Fatalf("addBatch(nil) total=%d err=%v", snapshot.total, err)
	}
	snapshot.batches = [][]db.EPSSEntry{{{CVEID: "CVE-2026-0001"}}}
	wantErr := errors.New("yield failed")
	if err := snapshot.stream(func([]db.EPSSEntry) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("stream() error = %v", err)
	}
	if got := metadataJSON(epssMetadata{}); got != nil {
		t.Fatalf("metadataJSON(empty) = %s", got)
	}
	if got := (epssMetadata{ETag: "stored"}).mergeResponseValidators(nil); got.ETag != "stored" {
		t.Fatalf("mergeResponseValidators(nil) = %+v", got)
	}
	if synced, total := statusCounts(nil); synced != 0 || total != 0 {
		t.Fatalf("statusCounts(nil) = %d, %d", synced, total)
	}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if status := syncer.loadFeedStatus(epssStatusErrorStore{}); status != nil {
		t.Fatalf("loadFeedStatus(error) = %+v", status)
	}
}

func TestOpenScoresRequestPeekAndGzipErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		url        string
		response   *http.Response
		wantSubstr string
	}{
		{name: "bad request URL", url: "://bad", wantSubstr: "create request"},
		{name: "gzip header", url: "https://example.test/scores.csv", response: &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": []string{"gzip"}}, Body: io.NopCloser(strings.NewReader("not gzip"))}, wantSubstr: "gzip reader"},
		{name: "peek read", url: "https://example.test/scores.csv", response: &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: epssFailingBody{}}, wantSubstr: "peek response"},
		{name: "gzip magic", url: "https://example.test/scores.csv", response: &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("\x1f\x8bbad"))}, wantSubstr: "detected from magic bytes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return tc.response, nil })}
			syncer := NewSyncer(nil, WithScoresURL(tc.url), WithHTTPClient(client))
			_, _, _, _, err := syncer.openScores(context.Background(), epssMetadata{})
			if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("openScores() error = %v, want %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestStreamCSVSecondaryHeaderYieldAndHelperBranches(t *testing.T) {
	t.Parallel()

	if _, _, err := streamCSV(strings.NewReader("cve,epss,percentile\nCVE-2026-0001,0.1,0.2\n"), 0, func([]db.EPSSEntry) error {
		return errors.New("yield failed")
	}); err == nil || !strings.Contains(err.Error(), "yield failed") {
		t.Fatalf("streamCSV(yield error) = %v", err)
	}
	if _, _, err := streamCSV(strings.NewReader("cve,epss,percentile\ncve,epss,percentile\n"), 1, func([]db.EPSSEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), "invalid CVE") {
		t.Fatalf("streamCSV(second header) = %v", err)
	}

	metadata := parseCommentMetadata([]string{"#ignored,model_version=v2,score_date=2026-11-05"})
	if metadata.ModelVersion != "v2" || metadata.ScoreDate != "2026-11-05" {
		t.Fatalf("parseCommentMetadata() = %+v", metadata)
	}
	if isBlankCSVRecord([]string{"", "x"}) {
		t.Fatal("isBlankCSVRecord(nonblank) = true")
	}
	if isEPSSHeader([]string{"cve", "epss"}) {
		t.Fatal("isEPSSHeader(short) = true")
	}
}

func TestReplaceScoresStreamErrorNotModifiedAndFallbackBranches(t *testing.T) {
	t.Parallel()

	responseClient := func(status int, body string) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
	}

	syncer := NewSyncer(nil, WithScoresURL("https://example.test/scores.csv"), WithHTTPClient(responseClient(http.StatusNotModified, "")))
	if _, _, _, _, notModified, err := syncer.replaceScoresStream(context.Background(), epssGapReplacer{}, epssMetadata{}); err != nil || !notModified {
		t.Fatalf("replaceScoresStream(304) notModified=%v err=%v", notModified, err)
	}

	syncer = NewSyncer(nil, WithScoresURL("https://example.test/scores.csv"), WithHTTPClient(responseClient(http.StatusOK, "bad")))
	if _, _, _, _, _, err := syncer.replaceScoresStream(context.Background(), epssGapReplacer{}, epssMetadata{}); err == nil {
		t.Fatal("replaceScoresStream(parse error) error = nil")
	}

	valid := "cve,epss,percentile\nCVE-2026-0001,0.1,0.2\n"
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	syncer = NewSyncer(nil, WithScoresURL("https://example.test/scores.csv"), WithHTTPClient(responseClient(http.StatusOK, valid)))
	if _, _, _, _, _, err := syncer.replaceScoresStream(canceled, epssGapReplacer{}, epssMetadata{}); err == nil || !strings.Contains(err.Error(), "context cancelled") {
		t.Fatalf("replaceScoresStream(cancelled) error = %v", err)
	}

	replaceErr := errors.New("replace failed")
	syncer = NewSyncer(nil, WithScoresURL("https://example.test/scores.csv"), WithHTTPClient(responseClient(http.StatusOK, valid)))
	if _, _, _, _, _, err := syncer.replaceScoresStream(context.Background(), epssGapReplacer{err: replaceErr}, epssMetadata{}); !errors.Is(err, replaceErr) {
		t.Fatalf("replaceScoresStream(replace error) = %v", err)
	}

	syncer = NewSyncer(nil, WithScoresURL("https://example.test/scores.csv"), WithHTTPClient(responseClient(http.StatusOK, valid)))
	updated, cleared, total, _, _, err := syncer.replaceScoresStream(context.Background(), epssGapReplacer{updated: 1, cleared: 2}, epssMetadata{})
	if err != nil || updated != 1 || cleared != 2 || total != 1 {
		t.Fatalf("replaceScoresStream(total fallback) = %d/%d/%d, %v", updated, cleared, total, err)
	}
}

func TestParseCSVWithMetadataRejectsHeaderOnlySnapshot(t *testing.T) {
	t.Parallel()

	if _, _, err := parseCSVWithMetadata(strings.NewReader("cve,epss,percentile\n")); err == nil || !strings.Contains(err.Error(), "no EPSS score rows") {
		t.Fatalf("parseCSVWithMetadata(header only) error = %v", err)
	}
}

func TestStreamLimitedCSVRejectsLimitReachedAfterCompleteCSV(t *testing.T) {
	t.Parallel()

	valid := "cve,epss,percentile\nCVE-2026-0001,0.1,0.2\n"
	if _, _, err := streamLimitedCSV(strings.NewReader(valid+"x"), int64(len(valid)-1), 1, func([]db.EPSSEntry) error { return nil }); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("streamLimitedCSV(limit reached) error = %v", err)
	}
}
