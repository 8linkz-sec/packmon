package nvd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/feed"
)

// -- Store stub ---------------------------------------------------------------

type nvdStoreStub struct {
	db.Store
	aliases   []db.UnknownCVEAlias
	updated   map[string]updateRecord
	findErr   error
	updateErr error
}

type updateRecord struct {
	severity  string
	cvssScore float64
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type countingReadCloser struct {
	remaining int64
	read      int64
}

func (r *countingReadCloser) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = 'x'
	}
	n := len(p)
	r.remaining -= int64(n)
	r.read += int64(n)
	return n, nil
}

func (r *countingReadCloser) Close() error {
	return nil
}

func (s *nvdStoreStub) FindUnknownSeverityCVEAliases(_ context.Context) ([]db.UnknownCVEAlias, error) {
	if s.findErr != nil {
		return nil, s.findErr
	}
	return s.aliases, nil
}

func (s *nvdStoreStub) UpdateSeverityByCVE(_ context.Context, cveID, severity string, cvssScore float64) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	if s.updated == nil {
		s.updated = make(map[string]updateRecord)
	}
	s.updated[cveID] = updateRecord{severity: severity, cvssScore: cvssScore}
	return nil
}

// -- Tests --------------------------------------------------------------------

func TestSync_NoUnknownAliases(t *testing.T) {
	t.Parallel()

	store := &nvdStoreStub{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncer := NewSyncer(logger)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 0 {
		t.Errorf("EntriesSynced = %d, want 0", result.EntriesSynced)
	}
	if result.EntriesTotal != 0 {
		t.Errorf("EntriesTotal = %d, want 0", result.EntriesTotal)
	}
}

func TestSync_FetchesCVSSAndUpdates(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		cveID := r.URL.Query().Get("cveId")

		resp := nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{
				{
					CVE: nvdCVE{
						ID: cveID,
						Metrics: nvdMetrics{
							CvssMetricV31: []nvdCvssMetric{
								{
									CvssData: nvdCvssData{
										BaseScore:    9.8,
										BaseSeverity: "CRITICAL",
										VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									},
								},
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		aliases: []db.UnknownCVEAlias{
			{VulnerabilityID: "GO-2026-4337", CVEID: "CVE-2025-68121"},
			{VulnerabilityID: "RUSTSEC-2025-0001", CVEID: "CVE-2025-99999"},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncer := NewSyncer(logger,
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if result.EntriesSynced != 2 {
		t.Errorf("EntriesSynced = %d, want 2", result.EntriesSynced)
	}
	if result.EntriesTotal != 2 {
		t.Errorf("EntriesTotal = %d, want 2", result.EntriesTotal)
	}

	// Verify updates were recorded.
	for _, cve := range []string{"CVE-2025-68121", "CVE-2025-99999"} {
		rec, ok := store.updated[cve]
		if !ok {
			t.Errorf("CVE %s was not updated", cve)
			continue
		}
		if rec.severity != "CRITICAL" {
			t.Errorf("CVE %s severity = %q, want CRITICAL", cve, rec.severity)
		}
		if rec.cvssScore != 9.8 {
			t.Errorf("CVE %s cvssScore = %f, want 9.8", cve, rec.cvssScore)
		}
	}

	if int(requestCount.Load()) != 2 {
		t.Errorf("request count = %d, want 2", requestCount.Load())
	}
}

func TestSync_DeduplicatesCVEs(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		resp := nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{
				{CVE: nvdCVE{
					ID: r.URL.Query().Get("cveId"),
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CvssData: nvdCvssData{BaseScore: 7.5, BaseSeverity: "HIGH"}},
						},
					},
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	// Two different vulnerabilities share the same CVE alias.
	store := &nvdStoreStub{
		aliases: []db.UnknownCVEAlias{
			{VulnerabilityID: "GO-2026-0001", CVEID: "CVE-2025-11111"},
			{VulnerabilityID: "PYSEC-2025-0001", CVEID: "CVE-2025-11111"},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncer := NewSyncer(logger,
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// Only 1 unique CVE should be fetched, not 2.
	if int(requestCount.Load()) != 1 {
		t.Errorf("request count = %d, want 1 (deduplication)", requestCount.Load())
	}
	if result.EntriesTotal != 1 {
		t.Errorf("EntriesTotal = %d, want 1", result.EntriesTotal)
	}
}

func TestSync_SkipsNotFoundCVEs(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		aliases: []db.UnknownCVEAlias{
			{VulnerabilityID: "GO-2026-0001", CVEID: "CVE-2025-00000"},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncer := NewSyncer(logger,
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// Not found CVEs should be skipped, not cause errors.
	if result.EntriesSynced != 0 {
		t.Errorf("EntriesSynced = %d, want 0", result.EntriesSynced)
	}
}

func TestSync_FallsBackToV30(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{
				{CVE: nvdCVE{
					ID: "CVE-2020-12345",
					Metrics: nvdMetrics{
						// No v3.1, only v3.0.
						CvssMetricV30: []nvdCvssMetric{
							{CvssData: nvdCvssData{BaseScore: 5.5, BaseSeverity: "MEDIUM"}},
						},
					},
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		aliases: []db.UnknownCVEAlias{
			{VulnerabilityID: "PYSEC-2020-0001", CVEID: "CVE-2020-12345"},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncer := NewSyncer(logger,
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 1 {
		t.Errorf("EntriesSynced = %d, want 1", result.EntriesSynced)
	}
	rec := store.updated["CVE-2020-12345"]
	if rec.severity != "MEDIUM" {
		t.Errorf("severity = %q, want MEDIUM", rec.severity)
	}
}

func TestSyncer_ImplementsFeedSyncer(t *testing.T) {
	t.Parallel()

	syncer := NewSyncer(nil)
	var _ feed.FeedSyncer = syncer

	if syncer.Name() != "nvd" {
		t.Errorf("Name() = %q, want %q", syncer.Name(), "nvd")
	}
}

func TestSync_SendsAPIKeyHeader(t *testing.T) {
	t.Parallel()

	var gotAPIKey string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("apiKey")
		resp := nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{
				{CVE: nvdCVE{
					ID: "CVE-2025-00001",
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CvssData: nvdCvssData{BaseScore: 8.0, BaseSeverity: "HIGH"}},
						},
					},
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		aliases: []db.UnknownCVEAlias{
			{VulnerabilityID: "GO-2026-0002", CVEID: "CVE-2025-00001"},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	syncer := NewSyncer(logger,
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithAPIKey("test-key-12345"),
	)

	_, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if gotAPIKey != "test-key-12345" {
		t.Errorf("apiKey header = %q, want %q", gotAPIKey, "test-key-12345")
	}
}

func TestFetchCVSS_EncodesCVEQuery(t *testing.T) {
	t.Parallel()

	var (
		gotQuery string
		gotCVEID string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		gotCVEID = r.URL.Query().Get("cveId")
		resp := nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{
				{CVE: nvdCVE{
					ID: gotCVEID,
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CvssData: nvdCvssData{BaseScore: 5.0, BaseSeverity: "MEDIUM"}},
						},
					},
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	score, severity, err := syncer.fetchCVSS(context.Background(), "CVE-&apiKey=stolen&x=")
	if err != nil {
		t.Fatalf("fetchCVSS() error = %v", err)
	}
	if score != 5.0 || severity != "MEDIUM" {
		t.Fatalf("fetchCVSS() = (%v, %q), want (5.0, MEDIUM)", score, severity)
	}
	if gotCVEID != "CVE-&apiKey=stolen&x=" {
		t.Fatalf("cveId query value = %q, want original CVE string", gotCVEID)
	}
	if gotQuery != "cveId=CVE-%26apiKey%3Dstolen%26x%3D" {
		t.Fatalf("raw query = %q, want encoded cveId parameter", gotQuery)
	}
}

func TestSync_RetriesRateLimitedCVE(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		resp := nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{
				{CVE: nvdCVE{
					ID: r.URL.Query().Get("cveId"),
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCvssMetric{
							{CvssData: nvdCvssData{BaseScore: 8.8, BaseSeverity: "HIGH"}},
						},
					},
				}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		aliases: []db.UnknownCVEAlias{
			{VulnerabilityID: "GO-2026-0003", CVEID: "CVE-2025-42424"},
		},
	}

	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 1 || result.EntriesTotal != 1 {
		t.Fatalf("Sync() result = %+v, want 1 synced / 1 total", result)
	}
	if int(requestCount.Load()) != 2 {
		t.Fatalf("request count = %d, want 2 (initial + retry)", requestCount.Load())
	}
	if rec := store.updated["CVE-2025-42424"]; rec.severity != "HIGH" || rec.cvssScore != 8.8 {
		t.Fatalf("updated record = %+v, want HIGH / 8.8", rec)
	}
}

func TestSyncFailsOnOperationalFetchAndUpdateFailures(t *testing.T) {
	t.Parallel()

	if _, err := NewSyncer(nil).Sync(context.Background(), &nvdStoreStub{findErr: errors.New("db down")}); err == nil || !strings.Contains(err.Error(), "find unknown") {
		t.Fatalf("Sync(find error) error = %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("cveId") {
		case "CVE-NO-METRICS":
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-NO-METRICS","metrics":{}}}]}`))
		case "CVE-BAD-JSON":
			_, _ = w.Write([]byte(`{bad json`))
		default:
			resp := nvdResponse{Vulnerabilities: []nvdVulnWrapper{{CVE: nvdCVE{Metrics: nvdMetrics{
				CvssMetricV31: []nvdCvssMetric{{CvssData: nvdCvssData{BaseScore: 9.1}}},
			}}}}}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		aliases: []db.UnknownCVEAlias{
			{CVEID: "CVE-NO-METRICS"},
			{CVEID: "CVE-BAD-JSON"},
			{CVEID: "CVE-UPDATE-FAILS"},
		},
		updateErr: errors.New("update failed"),
	}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)), WithAPIURL(srv.URL), WithHTTPClient(srv.Client()))
	result, err := syncer.Sync(context.Background(), store)
	if err == nil || !strings.Contains(err.Error(), "2 CVE enrichment error") {
		t.Fatalf("Sync() error = %v, want aggregated enrichment failure", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on operational failures", result)
	}
}

func TestFetchCVSSErrorBranchesAndRetryHelpers(t *testing.T) {
	t.Parallel()

	if _, _, err := NewSyncer(nil, WithAPIURL("://bad")).fetchCVSS(context.Background(), "CVE-1"); err == nil || !strings.Contains(err.Error(), "parse API URL") {
		t.Fatalf("fetchCVSS(bad URL) error = %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/forbidden":
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusForbidden)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
		}
	}))
	defer srv.Close()

	syncer := NewSyncer(nil, WithHTTPClient(srv.Client()), WithAPIURL(srv.URL+"/forbidden"))
	_, _, err := syncer.fetchCVSS(context.Background(), "CVE-1")
	var rl *rateLimitError
	if !errors.As(err, &rl) || rl.retryAfter != time.Second {
		t.Fatalf("fetchCVSS(rate limit) error = %v, want one-second rate limit", err)
	}

	syncer = NewSyncer(nil, WithHTTPClient(srv.Client()), WithAPIURL(srv.URL+"/error"))
	if _, _, err := syncer.fetchCVSS(context.Background(), "CVE-1"); err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("fetchCVSS(500) error = %v", err)
	}

	future := time.Now().UTC().Add(10 * time.Millisecond).Format(http.TimeFormat)
	if got := parseRetryAfter(""); got != rateLimitWindow {
		t.Fatalf("parseRetryAfter(empty) = %v, want default", got)
	}
	if got := parseRetryAfter("-1"); got != rateLimitWindow {
		t.Fatalf("parseRetryAfter(negative) = %v, want default", got)
	}
	if got := parseRetryAfter(future); got < 0 || got > time.Second {
		t.Fatalf("parseRetryAfter(date) = %v, want small positive duration", got)
	}
	if err := waitForRetry(context.Background(), 0); err != nil {
		t.Fatalf("waitForRetry(0) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForRetry(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForRetry(canceled) error = %v", err)
	}
}

func TestFetchCVSSBoundsErrorBodyDrain(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			body := &countingReadCloser{remaining: 1 << 20}
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       body,
					Request:    req,
				}, nil
			})}
			syncer := NewSyncer(nil,
				WithHTTPClient(client),
				WithAPIURL("https://nvd.example.test/rest/json/cves/2.0"),
			)

			_, _, err := syncer.fetchCVSS(context.Background(), "CVE-2026-0001")
			if status == http.StatusTooManyRequests {
				var rl *rateLimitError
				if !errors.As(err, &rl) {
					t.Fatalf("fetchCVSS() error = %v, want rate-limit error", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "unexpected status") {
				t.Fatalf("fetchCVSS() error = %v, want unexpected-status error", err)
			}
			if body.read > 64<<10 {
				t.Fatalf("drained %d bytes, want at most 64 KiB", body.read)
			}
		})
	}
}

func TestRateLimitErrorString(t *testing.T) {
	t.Parallel()

	err := (&rateLimitError{status: http.StatusTooManyRequests, retryAfter: time.Second}).Error()
	if !strings.Contains(err, "HTTP 429") || !strings.Contains(err, "1s") {
		t.Fatalf("rateLimitError.Error() = %q", err)
	}
}
