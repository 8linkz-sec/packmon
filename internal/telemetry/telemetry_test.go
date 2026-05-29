package telemetry

import (
	"bufio"
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

func ptrTime(t time.Time) *time.Time {
	return &t
}
