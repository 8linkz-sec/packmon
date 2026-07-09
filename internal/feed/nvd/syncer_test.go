package nvd

import (
	"bytes"
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
	cveIDs      []string
	listCalls   []unknownCVEIDPageCall
	updated     map[string]updateRecord
	nvdNegative map[string]struct{}
	findErr     error
	updateErr   error
	negativeErr error
}

type unknownCVEIDPageCall struct {
	after string
	limit int
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

func (s *nvdStoreStub) FindUnknownSeverityCVEIDs(_ context.Context, after string, limit int) ([]string, error) {
	if s.findErr != nil {
		return nil, s.findErr
	}
	s.listCalls = append(s.listCalls, unknownCVEIDPageCall{after: after, limit: limit})

	cveIDs := make([]string, 0, len(s.cveIDs))
	for _, cveID := range s.cveIDs {
		if _, cached := s.nvdNegative[cveID]; cached {
			continue
		}
		cveIDs = append(cveIDs, cveID)
	}
	start := len(cveIDs)
	for i, cveID := range cveIDs {
		if after == "" || cveID > after {
			start = i
			break
		}
	}
	if start >= len(cveIDs) {
		return nil, nil
	}
	end := len(cveIDs)
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	return append([]string(nil), cveIDs[start:end]...), nil
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

func (s *nvdStoreStub) RecordNVDCVSSNegativeLookup(_ context.Context, cveID string) error {
	if s.negativeErr != nil {
		return s.negativeErr
	}
	if s.nvdNegative == nil {
		s.nvdNegative = make(map[string]struct{})
	}
	s.nvdNegative[cveID] = struct{}{}
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
							CVSSMetricV31: []nvdCVSSMetric{
								{
									CVSSData: nvdCVSSData{
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
		cveIDs: []string{"CVE-2025-68121", "CVE-2025-99999"},
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

func TestFetchCVSSRejectsHTTPSDowngradeRedirect(t *testing.T) {
	t.Parallel()

	var targetReached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetReached.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
	}))
	defer target.Close()

	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/nvd", http.StatusFound)
	}))
	defer source.Close()

	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAPIURL(source.URL),
		WithAPIKey("test-key"),
		WithHTTPClient(source.Client()),
	)

	_, _, err := syncer.fetchCVSS(context.Background(), "CVE-2026-0001")
	if err == nil || !strings.Contains(err.Error(), "refusing redirect from https to http") {
		t.Fatalf("fetchCVSS() error = %v, want HTTPS downgrade redirect refusal", err)
	}
	if got := targetReached.Load(); got != 0 {
		t.Fatalf("downgrade redirect target reached %d time(s), want 0", got)
	}
}

func TestSyncPagesUnknownCVEIDsWithKeysetCursor(t *testing.T) {
	t.Parallel()

	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cveID := r.URL.Query().Get("cveId")
		requested = append(requested, cveID)
		resp := nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{
				{CVE: nvdCVE{
					ID: cveID,
					Metrics: nvdMetrics{
						CVSSMetricV31: []nvdCVSSMetric{
							{CVSSData: nvdCVSSData{BaseScore: 7.2, BaseSeverity: "HIGH"}},
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
		cveIDs: []string{
			"CVE-2026-00001",
			"CVE-2026-00002",
			"CVE-2026-00003",
		},
	}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithAPIKey("test-key"),
		WithDiscoveryPageSize(2),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.EntriesSynced != 3 || result.EntriesTotal != 3 {
		t.Fatalf("Sync() result = %+v, want 3 synced / 3 total", result)
	}
	wantCalls := []unknownCVEIDPageCall{
		{after: "", limit: 2},
		{after: "CVE-2026-00002", limit: 2},
	}
	if len(store.listCalls) != len(wantCalls) {
		t.Fatalf("FindUnknownSeverityCVEIDs calls = %+v, want %+v", store.listCalls, wantCalls)
	}
	for i := range wantCalls {
		if store.listCalls[i] != wantCalls[i] {
			t.Fatalf("FindUnknownSeverityCVEIDs calls = %+v, want %+v", store.listCalls, wantCalls)
		}
	}
	wantRequested := []string{"CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003"}
	if len(requested) != len(wantRequested) {
		t.Fatalf("requested CVEs = %v, want %v", requested, wantRequested)
	}
	for i := range wantRequested {
		if requested[i] != wantRequested[i] {
			t.Fatalf("requested CVEs = %v, want %v", requested, wantRequested)
		}
	}
}

func TestSyncCapsOperationalErrorSamples(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		cveIDs: []string{
			"CVE-2026-10001",
			"CVE-2026-10002",
			"CVE-2026-10003",
			"CVE-2026-10004",
			"CVE-2026-10005",
			"CVE-2026-10006",
		},
	}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAPIURL(srv.URL),
		WithHTTPClient(srv.Client()),
		WithAPIKey("test-key"),
		WithDiscoveryPageSize(3),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want aggregated fetch errors")
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil on operational failures", result)
	}
	if !strings.Contains(err.Error(), "6 CVE enrichment error(s)") {
		t.Fatalf("Sync() error = %v, want total error count", err)
	}
	if !strings.Contains(err.Error(), "CVE-2026-10001") {
		t.Fatalf("Sync() error = %v, want early error sample", err)
	}
	if strings.Contains(err.Error(), "CVE-2026-10006") {
		t.Fatalf("Sync() error = %v, want capped error samples", err)
	}
}

func TestSyncLogsSafeUpdateDiagnostics(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(nvdResponse{
			Vulnerabilities: []nvdVulnWrapper{
				{
					CVE: nvdCVE{
						ID: r.URL.Query().Get("cveId"),
						Metrics: nvdMetrics{
							CVSSMetricV31: []nvdCVSSMetric{
								{
									CVSSData: nvdCVSSData{
										BaseScore:    7.5,
										BaseSeverity: "HIGH",
									},
								},
							},
						},
					},
				},
			},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store := &nvdStoreStub{
		cveIDs:    []string{"CVE-2026-0001"},
		updateErr: errors.New(`write failed password=db-secret C:\Users\Admin\nvd.json`), //nolint:gosec // fake secret verifies diagnostic redaction.
	}
	syncer := NewSyncer(logger, WithAPIURL(srv.URL))

	if _, err := syncer.Sync(context.Background(), store); err == nil {
		t.Fatal("Sync() error = nil, want update failure")
	}
	output := logs.String()
	for _, leaked := range []string{"db-secret", `C:\Users\Admin\nvd.json`} {
		if strings.Contains(output, leaked) {
			t.Fatalf("NVD log leaked %q in:\n%s", leaked, output)
		}
	}
	for _, want := range []string{"password=[redacted]", "(redacted-path)"} {
		if !strings.Contains(output, want) {
			t.Fatalf("NVD log missing %q in:\n%s", want, output)
		}
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
						CVSSMetricV31: []nvdCVSSMetric{
							{CVSSData: nvdCVSSData{BaseScore: 7.5, BaseSeverity: "HIGH"}},
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
		cveIDs: []string{"CVE-2025-11111"},
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

func TestSync_ReturnsTransportErrorWithoutUpdatingNVD(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("dial tcp: lookup nvd.example.test: no such host")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})}
	store := &nvdStoreStub{
		cveIDs: []string{"CVE-2026-1258"},
	}
	syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithAPIURL("https://nvd.example.test/rest/json/cves/2.0"),
		WithHTTPClient(client),
	)

	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync() error = nil, want transport error")
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("Sync() error = %v, want wrapped transport error", err)
	}
	if !strings.Contains(err.Error(), "fetch CVE-2026-1258") || !strings.Contains(err.Error(), "http get") {
		t.Fatalf("Sync() error = %v, want CVE fetch and HTTP context", err)
	}
	if result != nil {
		t.Fatalf("Sync() result = %+v, want nil", result)
	}
	if len(store.updated) != 0 {
		t.Fatalf("store updates = %+v, want none", store.updated)
	}
}

func TestForEachNVDBatchSplitsAndStopsOnError(t *testing.T) {
	t.Parallel()

	var batches []string
	errStop := errors.New("stop")
	err := forEachNVDBatch([]string{"CVE-1", "CVE-2", "CVE-3"}, 2, func(start int, batch []string) error {
		batches = append(batches, strings.Join(batch, ","))
		if start == 2 {
			return errStop
		}
		return nil
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("forEachNVDBatch() error = %v, want stop", err)
	}
	want := []string{"CVE-1,CVE-2", "CVE-3"}
	if len(batches) != len(want) {
		t.Fatalf("batches = %v, want %v", batches, want)
	}
	for i := range want {
		if batches[i] != want[i] {
			t.Fatalf("batches = %v, want %v", batches, want)
		}
	}
}

func TestApplyNVDSeverityUpdateSkipsUnknownOrInvalidScore(t *testing.T) {
	t.Parallel()

	store := &nvdStoreStub{}
	ctx := context.Background()

	for _, tc := range []struct {
		name     string
		score    float64
		severity string
	}{
		{name: "zero score", score: 0, severity: "HIGH"},
		{name: "unknown severity", score: 7.5, severity: "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updated, err := applyNVDSeverityUpdate(ctx, store, "CVE-2025-00004", tc.score, tc.severity)
			if err != nil {
				t.Fatalf("applyNVDSeverityUpdate() error = %v", err)
			}
			if updated {
				t.Fatalf("applyNVDSeverityUpdate() updated = true, want false")
			}
		})
	}

	if len(store.updated) != 0 {
		t.Fatalf("store updates = %v, want none", store.updated)
	}
}

func TestApplyNVDSeverityUpdateStoresValidSeverity(t *testing.T) {
	t.Parallel()

	store := &nvdStoreStub{}
	updated, err := applyNVDSeverityUpdate(context.Background(), store, "CVE-2025-00005", 7.5, "HIGH")
	if err != nil {
		t.Fatalf("applyNVDSeverityUpdate() error = %v", err)
	}
	if !updated {
		t.Fatalf("applyNVDSeverityUpdate() updated = false, want true")
	}
	rec := store.updated["CVE-2025-00005"]
	if rec.severity != "HIGH" || rec.cvssScore != 7.5 {
		t.Fatalf("updated record = %+v, want HIGH / 7.5", rec)
	}

	store = &nvdStoreStub{updateErr: errors.New("update failed")}
	if _, err := applyNVDSeverityUpdate(context.Background(), store, "CVE-2025-00005", 7.5, "HIGH"); err == nil {
		t.Fatalf("applyNVDSeverityUpdate() error = nil, want update failure")
	}
}

func TestSync_SkipsNotFoundCVEs(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		cveIDs: []string{"CVE-2025-00000"},
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

func TestSync_CachesNegativeCVSSLookups(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "not found",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		},
		{
			name: "empty vulnerabilities",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(nvdResponse{})
			},
		},
		{
			name: "no cvss metrics",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(nvdResponse{
					Vulnerabilities: []nvdVulnWrapper{
						{CVE: nvdCVE{
							ID:      r.URL.Query().Get("cveId"),
							Metrics: nvdMetrics{},
						}},
					},
				})
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var requestCount atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount.Add(1)
				tc.handler(w, r)
			}))
			defer srv.Close()

			store := &nvdStoreStub{
				cveIDs: []string{"CVE-2026-3930"},
			}
			syncer := NewSyncer(slog.New(slog.NewTextHandler(io.Discard, nil)),
				WithAPIURL(srv.URL),
				WithHTTPClient(srv.Client()),
			)

			first, err := syncer.Sync(context.Background(), store)
			if err != nil {
				t.Fatalf("first Sync() error = %v", err)
			}
			if first.EntriesSynced != 0 || first.EntriesTotal != 1 {
				t.Fatalf("first Sync() result = %+v, want 0 synced / 1 total", first)
			}

			second, err := syncer.Sync(context.Background(), store)
			if err != nil {
				t.Fatalf("second Sync() error = %v", err)
			}
			if second.EntriesSynced != 0 || second.EntriesTotal != 0 {
				t.Fatalf("second Sync() result = %+v, want no candidates", second)
			}
			if got := requestCount.Load(); got != 1 {
				t.Fatalf("request count after two syncs = %d, want 1", got)
			}
			if _, ok := store.nvdNegative["CVE-2026-3930"]; !ok {
				t.Fatal("negative CVSS lookup was not recorded")
			}
		})
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
						CVSSMetricV30: []nvdCVSSMetric{
							{CVSSData: nvdCVSSData{BaseScore: 5.5, BaseSeverity: "MEDIUM"}},
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
		cveIDs: []string{"CVE-2020-12345"},
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
						CVSSMetricV31: []nvdCVSSMetric{
							{CVSSData: nvdCVSSData{BaseScore: 8.0, BaseSeverity: "HIGH"}},
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
		cveIDs: []string{"CVE-2025-00001"},
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
						CVSSMetricV31: []nvdCVSSMetric{
							{CVSSData: nvdCVSSData{BaseScore: 5.0, BaseSeverity: "MEDIUM"}},
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
						CVSSMetricV31: []nvdCVSSMetric{
							{CVSSData: nvdCVSSData{BaseScore: 8.8, BaseSeverity: "HIGH"}},
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
		cveIDs: []string{"CVE-2025-42424"},
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

func TestFetchCVSSWithRateLimitRetryRetriesTypedRateLimit(t *testing.T) {
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
						CVSSMetricV31: []nvdCVSSMetric{
							{CVSSData: nvdCVSSData{BaseScore: 6.5, BaseSeverity: "MEDIUM"}},
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

	score, severity, err := syncer.fetchCVSSWithRateLimitRetry(context.Background(), "CVE-2025-51515")
	if err != nil {
		t.Fatalf("fetchCVSSWithRateLimitRetry() error = %v", err)
	}
	if score != 6.5 || severity != "MEDIUM" {
		t.Fatalf("fetchCVSSWithRateLimitRetry() = (%v, %q), want (6.5, MEDIUM)", score, severity)
	}
	if int(requestCount.Load()) != 2 {
		t.Fatalf("request count = %d, want 2", requestCount.Load())
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
				CVSSMetricV31: []nvdCVSSMetric{{CVSSData: nvdCVSSData{BaseScore: 9.1}}},
			}}}}}
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	store := &nvdStoreStub{
		cveIDs:    []string{"CVE-NO-METRICS", "CVE-BAD-JSON", "CVE-UPDATE-FAILS"},
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

	var forbiddenRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/forbidden":
			forbiddenRequests.Add(1)
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusForbidden)
		case "/rate-limit":
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		case "/error":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
		}
	}))
	defer srv.Close()

	syncer := NewSyncer(nil, WithHTTPClient(srv.Client()), WithAPIURL(srv.URL+"/rate-limit"))
	_, _, err := syncer.fetchCVSS(context.Background(), "CVE-1")
	var rl *rateLimitError
	if !errors.As(err, &rl) || rl.retryAfter != time.Second {
		t.Fatalf("fetchCVSS(rate limit) error = %v, want one-second rate limit", err)
	}

	syncer = NewSyncer(nil, WithHTTPClient(srv.Client()), WithAPIURL(srv.URL+"/forbidden"))
	_, _, err = syncer.fetchCVSSWithRateLimitRetry(context.Background(), "CVE-1")
	if !feed.IsPermanentError(err) {
		t.Fatalf("fetchCVSSWithRateLimitRetry(403) error = %v, want permanent error", err)
	}
	if errors.As(err, &rl) {
		t.Fatalf("fetchCVSSWithRateLimitRetry(403) error = %v, want non-rate-limit error", err)
	}
	var retryWait *rateLimitRetryWaitError
	if errors.As(err, &retryWait) {
		t.Fatalf("fetchCVSSWithRateLimitRetry(403) error = %v, want no retry-wait error", err)
	}
	if got := forbiddenRequests.Load(); got != 1 {
		t.Fatalf("forbidden request count = %d, want 1", got)
	}

	syncer = NewSyncer(nil, WithHTTPClient(srv.Client()), WithAPIURL(srv.URL+"/error"))
	if _, _, err := syncer.fetchCVSS(context.Background(), "CVE-1"); err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("fetchCVSS(500) error = %v", err)
	}

	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	future := now.Add(3 * time.Second).Format(http.TimeFormat)
	past := now.Add(-time.Second).Format(http.TimeFormat)
	if got := parseRetryAfter(""); got != rateLimitWindow {
		t.Fatalf("parseRetryAfter(empty) = %v, want default", got)
	}
	if got := parseRetryAfter("-1"); got != rateLimitWindow {
		t.Fatalf("parseRetryAfter(negative) = %v, want default", got)
	}
	if got := parseRetryAfterAt(future, now); got != 3*time.Second {
		t.Fatalf("parseRetryAfterAt(future date) = %v, want 3s", got)
	}
	if got := parseRetryAfterAt(past, now); got != 0 {
		t.Fatalf("parseRetryAfterAt(past date) = %v, want 0", got)
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

func TestParseRetryAfterBoundsLongDelays(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	farFuture := now.Add(24 * time.Hour).Format(http.TimeFormat)

	for _, tc := range []struct {
		name  string
		value string
	}{
		{name: "seconds", value: "86400"},
		{name: "date", value: farFuture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRetryAfterAt(tc.value, now); got != 5*time.Minute {
				t.Fatalf("parseRetryAfterAt(%q) = %v, want 5m0s", tc.value, got)
			}
		})
	}
}

func TestFetchCVSSBoundsErrorBodyDrain(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusNotFound} {
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
			} else if status == http.StatusNotFound {
				if err != nil {
					t.Fatalf("fetchCVSS() error = %v, want nil for 404", err)
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
