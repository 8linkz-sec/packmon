package telemetry

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
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

type metricsStoreStub struct {
	db.Store
	statuses []db.FeedSyncStatus
	jobs     []db.RefreshJob
	queue    *db.QueueStatsResult
	dash     *db.DashboardStatsResult
	scans    *db.ScanTotals
	pool     db.DBPoolStats
}

func (s *metricsStoreStub) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return s.statuses, nil
}

func (s *metricsStoreStub) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return s.jobs, nil
}

func (s *metricsStoreStub) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	return s.queue, nil
}

func (s *metricsStoreStub) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	return s.dash, nil
}

func (s *metricsStoreStub) ScanTotals(context.Context) (*db.ScanTotals, error) {
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
	output := rec.Body.String()
	for _, want := range []string{
		"packmon_db_migration_version 7",
		`packmon_feed_last_sync_timestamp{feed="feed\\\"quoted"}`,
		`packmon_queue_oldest_job_seconds{source="socket\\\\dev"}`,
		`packmon_findings_by_severity{severity="HI\\\"GH"} 2`,
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
	key := httpMetricKey{Method: "UNKNOWN", Route: "unknown", Status: "200"}
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
