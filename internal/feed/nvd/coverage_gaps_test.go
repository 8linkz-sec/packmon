package nvd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

type nvdDiscoveryErrorStore struct{ db.Store }

func (nvdDiscoveryErrorStore) FindUnknownSeverityCVEIDs(context.Context, string, int) ([]string, error) {
	return nil, errors.New("discovery failed")
}

func TestSyncReturnsDiscoveryFailure(t *testing.T) {
	t.Parallel()

	if _, err := NewSyncer(nil, WithDiscoveryPageSize(0)).Sync(context.Background(), nvdDiscoveryErrorStore{}); err == nil || !strings.Contains(err.Error(), "find unknown") {
		t.Fatalf("Sync(discovery failure) error = %v", err)
	}
}

type nvdFailingBody struct{}

func (nvdFailingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (nvdFailingBody) Close() error             { return nil }

type nvdBareStore struct{ db.Store }

func TestNVDLimiterBatchAndNegativeLookupBranches(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, limiter := range []*nvdRequestRateLimiter{{batchSize: 0}, {batchSize: 2}} {
		if err := limiter.waitBeforeRequest(context.Background(), logger, nvdSyncProgress{}); err != nil {
			t.Fatalf("waitBeforeRequest() error = %v", err)
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	limiter := &nvdRequestRateLimiter{batchSize: 1, sent: 1}
	if err := limiter.waitBeforeRequest(cancelled, logger, nvdSyncProgress{}); err == nil || !strings.Contains(err.Error(), "rate limit wait") {
		t.Fatalf("waitBeforeRequest(cancelled) error = %v", err)
	}

	if err := forEachNVDBatch(nil, 0, func(int, []string) error { t.Fatal("callback called"); return nil }); err != nil {
		t.Fatalf("forEachNVDBatch(empty) error = %v", err)
	}
	wantErr := errors.New("stop")
	if err := forEachNVDBatch([]string{"a", "b", "c"}, 2, func(start int, batch []string) error {
		if start == 2 {
			return wantErr
		}
		return nil
	}); !errors.Is(err, wantErr) {
		t.Fatalf("forEachNVDBatch() error = %v", err)
	}
	if err := recordNVDNegativeLookup(context.Background(), nvdBareStore{}, "CVE-2026-0001"); err != nil {
		t.Fatalf("recordNVDNegativeLookup(unsupported) error = %v", err)
	}
}

func TestFetchCVSSPropagatesResponseReadError(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAPIURL("https://example.test/rest/json/cves/2.0"),
		WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: nvdFailingBody{}}, nil
		})}),
	)
	if _, _, err := syncer.fetchCVSS(context.Background(), "CVE-2026-0001"); err == nil || !strings.Contains(err.Error(), "read body") {
		t.Fatalf("fetchCVSS() error = %v, want read body error", err)
	}
}

func TestNVDZeroBatchUsesWholeSliceAndRateLimitRetryWithoutLimiter(t *testing.T) {
	t.Parallel()

	calls := 0
	if err := forEachNVDBatch([]string{"a", "b"}, 0, func(start int, batch []string) error {
		calls++
		if start != 0 || len(batch) != 2 {
			t.Fatalf("callback = start %d, batch %+v", start, batch)
		}
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("forEachNVDBatch(zero size) calls=%d err=%v", calls, err)
	}

	var requests atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			return &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"1"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	syncer := NewSyncer(nil, WithAPIURL("https://example.test/cves"), WithHTTPClient(client))
	if _, severity, err := syncer.fetchCVSSWithRateLimitRetry(context.Background(), "CVE-2026-0001", nil); err != nil || severity != "UNKNOWN" || requests.Load() != 2 {
		t.Fatalf("fetchCVSSWithRateLimitRetry() severity=%q requests=%d err=%v", severity, requests.Load(), err)
	}
}
