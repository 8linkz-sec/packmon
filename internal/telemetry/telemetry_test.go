package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestWriteMetricsIncludesCorePhaseFiveSeries(t *testing.T) {
	now := time.Now().UTC()
	registry := NewRegistry()
	registry.IncAuthLoginFailures()
	registry.IncDegradedResponses()
	registry.AddQueueStuckRecovered(2)
	registry.IncFeedSyncTimeout("osv")
	registry.IncQueueError("socket")

	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeMetrics(writer, registry.Snapshot(), []db.FeedSyncStatus{
		{
			FeedName:       "osv",
			LastSyncAt:     ptrTime(now.Add(-2 * time.Hour)),
			LastSyncStatus: "success",
		},
	}, []db.RefreshJob{
		{
			Source:      "socket",
			Status:      "pending",
			RequestedAt: now.Add(-30 * time.Minute),
		},
	}, &db.QueueStatsResult{
		Pending:    3,
		Processing: 1,
		Done:       5,
		Error:      2,
		Paused:     4,
	}, &db.DashboardStatsResult{
		TotalPackages:        11,
		TotalVulnerabilities: 7,
		TotalMalicious:       2,
		TotalSupplyChainRisk: 5,
		TotalLifecycle:       3,
		BySeverity:           map[string]int{"HIGH": 3},
	}, &db.ScanTotals{
		PackagesScanned: 21,
		Findings:        9,
	}, &db.DBPoolStats{
		MaxConns:          20,
		AcquiredConns:     2,
		IdleConns:         6,
		ConstructingConns: 1,
	}, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	for _, metric := range []string{
		"packmon_auth_login_failures_total 1",
		"packmon_degraded_responses_total 1",
		"packmon_queue_stuck_jobs_recovered_total 2",
		`packmon_feed_last_sync_timestamp{feed="osv"}`,
		`packmon_feed_entries_age_seconds{feed="osv"}`,
		`packmon_feed_sync_timeout_total{feed="osv"} 1`,
		`packmon_queue_oldest_job_seconds{source="socket"}`,
		`packmon_queue_error_total{source="socket"} 1`,
		`packmon_queue_size{status="pending"} 3`,
		`packmon_queue_size{status="processing"} 1`,
		`packmon_queue_size{status="done"} 5`,
		`packmon_queue_size{status="error"} 2`,
		`packmon_queue_size{status="paused"} 4`,
		`packmon_packages_total 11`,
		`packmon_findings_total{type="vulnerability"} 7`,
		`packmon_findings_total{type="malicious"} 2`,
		`packmon_findings_total{type="supply_chain_risk"} 5`,
		`packmon_findings_total{type="lifecycle"} 3`,
		`packmon_findings_by_severity{severity="HIGH"} 3`,
		`packmon_packages_scanned_total 21`,
		`packmon_scan_findings_total 9`,
		`packmon_db_pool_connections{state="max"} 20`,
		`packmon_db_pool_connections{state="acquired"} 2`,
		`packmon_db_pool_connections{state="idle"} 6`,
		`packmon_db_pool_connections{state="constructing"} 1`,
		"packmon_db_migration_version 1",
	} {
		if !strings.Contains(output, metric) {
			t.Fatalf("metrics output missing %q\n%s", metric, output)
		}
	}
}

func TestWriteMetricsClampsFindingSeverityLabels(t *testing.T) {
	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeMetrics(writer, CounterSnapshot{}, nil, nil, nil, &db.DashboardStatsResult{
		BySeverity: map[string]int{
			"HIGH":         3,
			" high ":       2,
			"UNKNOWN":      1,
			`HI"GH`:        4,
			"critical-ish": 5,
			"NONE":         6,
		},
	}, nil, nil, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	for _, want := range []string{
		`packmon_findings_by_severity{severity="HIGH"} 5`,
		`packmon_findings_by_severity{severity="UNKNOWN"} 16`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("metrics output missing %q\n%s", want, output)
		}
	}
	for _, notWant := range []string{`HI\"GH`, "critical-ish", `severity="NONE"`} {
		if strings.Contains(output, notWant) {
			t.Fatalf("metrics output leaked non-canonical severity label %q\n%s", notWant, output)
		}
	}
}

func TestHTTPMiddlewareRecordsRequestCountAndDuration(t *testing.T) {
	registry := NewRegistry()
	// Register on a ServeMux so r.Pattern is populated with the matched route
	// pattern, exactly as in production.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/check", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	handler := HTTPMiddleware(registry)(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeMetrics(writer, registry.Snapshot(), nil, nil, nil, nil, nil, nil, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	for _, metric := range []string{
		`packmon_http_requests_total{method="POST",route="POST /api/v1/check",status="201"} 1`,
		`packmon_http_request_duration_seconds_count{method="POST",route="POST /api/v1/check",status="201"} 1`,
		`packmon_http_request_duration_seconds_sum{method="POST",route="POST /api/v1/check",status="201"}`,
	} {
		if !strings.Contains(output, metric) {
			t.Fatalf("metrics output missing %q\n%s", metric, output)
		}
	}
}

func TestWriteMetricsSeparatesFeedAttemptTimestampFromDataAge(t *testing.T) {
	lastSuccessfulSync := time.Unix(1_000, 0).UTC()
	lastAttempt := time.Unix(2_000, 0).UTC()

	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeMetrics(writer, CounterSnapshot{}, []db.FeedSyncStatus{
		{
			FeedName:       "osv",
			LastSyncAt:     &lastSuccessfulSync,
			LastSyncStatus: "running",
			EntriesSynced:  10,
			EntriesTotal:   10,
			UpdatedAt:      lastAttempt,
		},
	}, nil, nil, nil, nil, nil, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	if want := `packmon_feed_last_sync_timestamp{feed="osv"} 2000`; !strings.Contains(output, want) {
		t.Fatalf("metrics output missing attempt timestamp %q\n%s", want, output)
	}
	if staleFreshnessTimestamp := `packmon_feed_last_sync_timestamp{feed="osv"} 1000`; strings.Contains(output, staleFreshnessTimestamp) {
		t.Fatalf("last sync timestamp used stale data freshness timestamp\n%s", output)
	}
	if want := `packmon_feed_entries_age_seconds{feed="osv"}`; !strings.Contains(output, want) {
		t.Fatalf("metrics output missing data age metric %q\n%s", want, output)
	}
}

func TestHTTPMiddlewareBucketsUnmatchedRoutes(t *testing.T) {
	registry := NewRegistry()
	// No ServeMux: r.Pattern stays empty, as for a 404. The raw request path
	// must NOT become a metric label (unbounded cardinality); it is bucketed
	// under a single constant.
	handler := HTTPMiddleware(registry)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	for _, path := range []string{"/.env", "/wp-admin/index.php", "/random-scan-path"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}

	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeMetrics(writer, registry.Snapshot(), nil, nil, nil, nil, nil, nil, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	if !strings.Contains(output, `packmon_http_requests_total{method="GET",route="__unmatched__",status="404"} 3`) {
		t.Fatalf("expected unmatched routes bucketed into one series with count 3\n%s", output)
	}
	for _, raw := range []string{"/.env", "/wp-admin", "/random-scan-path"} {
		if strings.Contains(output, raw) {
			t.Fatalf("raw request path %q leaked into a metric label\n%s", raw, output)
		}
	}
}

func TestHTTPMiddlewareBucketsUnknownMethods(t *testing.T) {
	registry := NewRegistry()
	handler := HTTPMiddleware(registry)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	for _, method := range []string{"BREW", "PROPFIND", "PACKMON-ATTACK-METHOD"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, "/coffee", nil))
	}

	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeMetrics(writer, registry.Snapshot(), nil, nil, nil, nil, nil, nil, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	if !strings.Contains(output, `packmon_http_requests_total{method="OTHER",route="__unmatched__",status="418"} 3`) {
		t.Fatalf("expected unknown methods bucketed into OTHER series\n%s", output)
	}
	for _, raw := range []string{"BREW", "PROPFIND", "PACKMON-ATTACK-METHOD"} {
		if strings.Contains(output, raw) {
			t.Fatalf("raw HTTP method %q leaked into a metric label\n%s", raw, output)
		}
	}
}

type metricsStoreStub struct {
	db.Store
	statuses     []db.FeedSyncStatus
	jobs         []db.RefreshJob
	queue        *db.QueueStatsResult
	oldestQueue  map[string]time.Time
	dash         *db.DashboardStatsResult
	scans        *db.ScanTotals
	pool         db.DBPoolStats
	deadlineSeen bool
	listJobs     int
	oldestCalls  int
	dashCalls    int
	scanCalls    int
}

func (s *metricsStoreStub) recordContext(ctx context.Context) {
	if _, ok := ctx.Deadline(); ok {
		s.deadlineSeen = true
	}
}

func (s *metricsStoreStub) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	s.recordContext(ctx)
	return s.statuses, nil
}

func (s *metricsStoreStub) ListQueueJobs(ctx context.Context, _ string, _ int) ([]db.RefreshJob, error) {
	s.recordContext(ctx)
	s.listJobs++
	return s.jobs, nil
}

func (s *metricsStoreStub) OldestQueueJobs(ctx context.Context) (map[string]time.Time, error) {
	s.recordContext(ctx)
	s.oldestCalls++
	if s.oldestQueue != nil {
		out := make(map[string]time.Time, len(s.oldestQueue))
		for source, requestedAt := range s.oldestQueue {
			out[source] = requestedAt
		}
		return out, nil
	}
	oldest, _ := oldestQueueJobs(s.jobs)
	return oldest, nil
}

func (s *metricsStoreStub) QueueStats(ctx context.Context) (*db.QueueStatsResult, error) {
	s.recordContext(ctx)
	return s.queue, nil
}

func (s *metricsStoreStub) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	s.recordContext(ctx)
	s.dashCalls++
	return s.dash, nil
}

func (s *metricsStoreStub) ScanTotals(ctx context.Context) (*db.ScanTotals, error) {
	s.recordContext(ctx)
	s.scanCalls++
	return s.scans, nil
}

func (s *metricsStoreStub) DBPoolStats() db.DBPoolStats {
	return s.pool
}

type failingMetricsStore struct {
	db.Store
}

func (failingMetricsStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return nil, errors.New("feeds failed")
}

func (failingMetricsStore) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return nil, errors.New("jobs failed")
}

func (failingMetricsStore) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	return nil, errors.New("queue failed")
}

func (failingMetricsStore) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	return nil, errors.New("dashboard failed")
}

func (failingMetricsStore) ScanTotals(context.Context) (*db.ScanTotals, error) {
	return nil, errors.New("scans failed")
}

func TestMetricsHandlerUsesStoreDerivedSeries(t *testing.T) {
	now := time.Now().UTC()
	store := &metricsStoreStub{
		statuses: []db.FeedSyncStatus{{FeedName: `feed"quoted`, LastSyncAt: ptrTime(now), LastSyncStatus: "success"}},
		jobs: []db.RefreshJob{
			{Source: `socket\dev`, Status: "pending", RequestedAt: now.Add(-time.Minute)},
			{Source: "ignored", Status: "done", RequestedAt: now.Add(-2 * time.Minute)},
		},
		queue: &db.QueueStatsResult{Pending: 1},
		dash:  &db.DashboardStatsResult{TotalPackages: 3, BySeverity: map[string]int{`HI"GH`: 2}},
		scans: &db.ScanTotals{PackagesScanned: 4, Findings: 5},
		pool:  db.DBPoolStats{MaxConns: 9},
	}

	rec := httptest.NewRecorder()
	MetricsHandler(store, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
	if !store.deadlineSeen {
		t.Fatal("metrics store calls did not receive a bounded context")
	}
	output := rec.Body.String()
	for _, want := range []string{
		"packmon_db_migration_version 7",
		`packmon_feed_last_sync_timestamp{feed="feed\"quoted"}`,
		`packmon_queue_oldest_job_seconds{source="socket\\dev"}`,
		`packmon_findings_by_severity{severity="UNKNOWN"} 2`,
		"packmon_packages_scanned_total 4",
		`packmon_db_pool_connections{state="max"} 9`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("metrics output missing %q\n%s", want, output)
		}
	}
	if strings.Contains(output, `source="ignored"`) {
		t.Fatalf("done queue job should not create oldest-job metric\n%s", output)
	}
}

func TestMetricsHandlerRendersInjectedRegistry(t *testing.T) {
	registry := NewRegistry()
	registry.RecordHTTPRequest(http.MethodGet, "GET /custom", http.StatusNoContent, time.Second)

	rec := httptest.NewRecorder()
	MetricsHandlerWithRegistry(registry, &metricsStoreStub{}, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `packmon_http_requests_total{method="GET",route="GET /custom",status="204"} 1`) {
		t.Fatalf("metrics output did not render injected registry counters:\n%s", body)
	}
}

func TestMetricsHandlerUsesOldestQueueJobsProvider(t *testing.T) {
	now := time.Now().UTC()
	store := &metricsStoreStub{
		jobs: []db.RefreshJob{
			{Source: "socket", Status: "pending", RequestedAt: now.Add(-time.Minute)},
		},
		oldestQueue: map[string]time.Time{
			"socket": now.Add(-3 * time.Hour),
		},
	}

	rec := httptest.NewRecorder()
	MetricsHandler(store, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if store.oldestCalls != 1 {
		t.Fatalf("OldestQueueJobs calls = %d, want 1", store.oldestCalls)
	}
	if store.listJobs != 0 {
		t.Fatalf("ListQueueJobs calls = %d, want 0 for metrics oldest-job provider", store.listJobs)
	}
	if !strings.Contains(rec.Body.String(), `packmon_queue_oldest_job_seconds{source="socket"}`) {
		t.Fatalf("metrics output missing socket oldest-job metric\n%s", rec.Body.String())
	}
}

func TestMetricsHandlerCachesDashboardAndScanTotals(t *testing.T) {
	store := &metricsStoreStub{
		dash:  &db.DashboardStatsResult{TotalPackages: 3},
		scans: &db.ScanTotals{PackagesScanned: 4, Findings: 5},
	}
	handler := MetricsHandlerWithRegistry(NewRegistry(), store, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("scrape %d status = %d, want 200", i+1, rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{
			"packmon_packages_total 3",
			"packmon_packages_scanned_total 4",
			"packmon_scan_findings_total 5",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("scrape %d missing %q:\n%s", i+1, want, body)
			}
		}
	}

	if store.dashCalls != 1 {
		t.Fatalf("DashboardStats calls = %d, want 1 within metrics cache window", store.dashCalls)
	}
	if store.scanCalls != 1 {
		t.Fatalf("ScanTotals calls = %d, want 1 within metrics cache window", store.scanCalls)
	}
}

func TestMetricsHandlerToleratesStoreErrorsAndNilLogger(t *testing.T) {
	rec := httptest.NewRecorder()
	MetricsHandler(failingMetricsStore{}, 3, nil)(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "packmon_db_migration_version 3") {
		t.Fatalf("metrics output missing schema version after store errors\n%s", body)
	}
}

func TestMetricsHandlerCollapsesAndThrottlesStoreErrorWarnings(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := MetricsHandlerWithRegistry(NewRegistry(), failingMetricsStore{}, 3, logger)

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("scrape %d status = %d, want 200", i+1, rec.Code)
		}
	}

	logText := logs.String()
	if got := strings.Count(logText, `"level":"WARN"`); got != 1 {
		t.Fatalf("warning count = %d, want one throttled warning; logs:\n%s", got, logText)
	}
	if !strings.Contains(logText, `"msg":"metrics: store-derived metrics read failed"`) {
		t.Fatalf("logs missing collapsed metrics store failure message:\n%s", logText)
	}
	for _, operation := range []string{"feed_sync_statuses", "queue_jobs", "queue_stats", "dashboard_stats", "scan_totals"} {
		if !strings.Contains(logText, operation) {
			t.Fatalf("logs missing failed operation %q:\n%s", operation, logText)
		}
	}
}

func TestStatusRecorderWriteDefaultsStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	status := &statusRecorder{ResponseWriter: rec}

	if _, err := status.Write([]byte("ok")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if status.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status.status, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want ok", rec.Body.String())
	}
}

func TestRegistrySnapshotAndHelpersHandleEmptyInputs(t *testing.T) {
	registry := NewRegistry()
	registry.AddQueueStuckRecovered(-1)
	registry.IncFeedSyncTimeout("")
	registry.IncQueueError("")
	registry.RecordHTTPRequest("", "", 0, -time.Second)

	snapshot := registry.Snapshot()
	if snapshot.QueueStuckRecovered != 0 {
		t.Fatalf("QueueStuckRecovered = %d, want 0 for negative increment", snapshot.QueueStuckRecovered)
	}
	if len(snapshot.FeedSyncTimeouts) != 0 || len(snapshot.QueueErrors) != 0 {
		t.Fatalf("empty labels should be ignored: %+v", snapshot)
	}
	key := httpMetricKey{Method: "OTHER", Route: "unknown", Status: "200"}
	if metric, ok := snapshot.HTTPRequests[key]; !ok || metric.Count != 1 || metric.DurationNanos != 0 {
		t.Fatalf("default HTTP metric = %+v ok=%v", metric, ok)
	}

	if got := feedNames([]db.FeedSyncStatus{{FeedName: ""}, {FeedName: "osv"}}); len(got) != 1 || got[0] != "osv" {
		t.Fatalf("feedNames() = %#v", got)
	}
	if got := unionKeys(map[string]uint64{"": 1, "a": 2}, []string{"b", ""}); len(got) != 2 {
		t.Fatalf("unionKeys() = %#v, want two non-empty keys", got)
	}
	if got := escapeLabelValue("a\\b\nc\"d"); got != `a\\b\nc\"d` {
		t.Fatalf("escapeLabelValue() = %q", got)
	}
}

func TestSortedHTTPMetricKeysOrdersByRouteMethodStatus(t *testing.T) {
	keys := sortedHTTPMetricKeys(map[httpMetricKey]httpMetricSnapshot{
		{Method: "POST", Route: "/b", Status: "200"}: {},
		{Method: "GET", Route: "/a", Status: "500"}:  {},
		{Method: "GET", Route: "/a", Status: "200"}:  {},
	})
	got := []string{
		keys[0].Route + " " + keys[0].Method + " " + keys[0].Status,
		keys[1].Route + " " + keys[1].Method + " " + keys[1].Status,
		keys[2].Route + " " + keys[2].Method + " " + keys[2].Status,
	}
	want := []string{"/a GET 200", "/a GET 500", "/b POST 200"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted key %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
