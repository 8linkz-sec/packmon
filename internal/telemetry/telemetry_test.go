package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestMetricsStoreContractRequiresStoreDerivedSeries(t *testing.T) {
	source, err := os.ReadFile("telemetry.go")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "telemetry.go", source, 0)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	var metricsStore *ast.InterfaceType
	var handler *ast.FuncDecl
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				switch typeSpec.Name.Name {
				case "scanTotalsProvider", "dbPoolStatsProvider":
					t.Fatalf("telemetry.go still declares optional provider %s", typeSpec.Name.Name)
				case "MetricsStore":
					var ok bool
					metricsStore, ok = typeSpec.Type.(*ast.InterfaceType)
					if !ok {
						t.Fatalf("MetricsStore is %T, want interface", typeSpec.Type)
					}
				}
			}
		case *ast.FuncDecl:
			if decl.Name.Name == "MetricsHandlerWithRegistry" {
				handler = decl
			}
		}
	}
	if metricsStore == nil {
		t.Fatal("telemetry.go missing explicit MetricsStore interface")
	}

	methods := interfaceMethodNames(metricsStore)
	for _, want := range []string{
		"ListFeedSyncStatuses",
		"ListQueueJobs",
		"QueueStats",
		"DashboardStats",
		"ScanTotals",
		"DBPoolStats",
	} {
		if !methods[want] {
			t.Fatalf("MetricsStore missing required method %s", want)
		}
	}

	if handler == nil {
		t.Fatal("telemetry.go missing MetricsHandlerWithRegistry")
	}
	if got := handlerParamTypeName(handler, 1); got != "MetricsStore" {
		t.Fatalf("MetricsHandlerWithRegistry store parameter type = %q, want MetricsStore", got)
	}
}

func interfaceMethodNames(iface *ast.InterfaceType) map[string]bool {
	methods := make(map[string]bool)
	for _, method := range iface.Methods.List {
		for _, name := range method.Names {
			methods[name.Name] = true
		}
	}
	return methods
}

func handlerParamTypeName(fn *ast.FuncDecl, index int) string {
	if fn == nil || fn.Type == nil || fn.Type.Params == nil || index >= len(fn.Type.Params.List) {
		return ""
	}
	return exprTypeName(fn.Type.Params.List[index].Type)
}

func exprTypeName(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		return exprTypeName(expr.X) + "." + expr.Sel.Name
	case *ast.StarExpr:
		return "*" + exprTypeName(expr.X)
	default:
		return fmt.Sprintf("%T", expr)
	}
}

func TestWriteMetricsDelegatesToMetricGroupWriters(t *testing.T) {
	source, err := os.ReadFile("telemetry.go")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "telemetry.go", source, 0)
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		funcs[fn.Name.Name] = fn
	}

	want := []string{
		"writeProcessMetrics",
		"writeBuildInfoMetrics",
		"writeGoRuntimeMetrics",
		"writeHTTPMetrics",
		"writeQueueSizeMetrics",
		"writeFindingMetrics",
		"writeScanTotalsMetrics",
		"writeDBPoolMetrics",
		"writeFeedMetrics",
		"writeRefreshQueueMetrics",
	}
	for _, name := range want {
		if funcs[name] == nil {
			t.Fatalf("telemetry.go missing metric group writer %s", name)
		}
	}

	writeMetrics := funcs["writeMetrics"]
	if writeMetrics == nil {
		t.Fatal("telemetry.go missing writeMetrics")
	}
	if got := len(writeMetrics.Type.Params.List); got != 2 {
		t.Fatalf("writeMetrics parameter groups = %d, want writer plus metricsRenderSnapshot", got)
	}
	if got := handlerParamTypeName(writeMetrics, 1); got != "metricsRenderSnapshot" {
		t.Fatalf("writeMetrics snapshot parameter type = %q, want metricsRenderSnapshot", got)
	}
	if got, wantLen := len(writeMetrics.Body.List), len(want)+1; got != wantLen {
		t.Fatalf("writeMetrics statement count = %d, want %d dispatcher statements", got, wantLen)
	}

	var got []string
	for i, stmt := range writeMetrics.Body.List {
		if i == 8 {
			if !isUTCNowAssignment(stmt) {
				t.Fatalf("writeMetrics statement %d should capture now := time.Now().UTC()", i+1)
			}
			continue
		}
		name, ok := directMetricGroupWriterCall(stmt)
		if !ok {
			t.Fatalf("writeMetrics contains a non-dispatch statement: %#v", stmt)
		}
		got = append(got, name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("writeMetrics helper order = %#v, want %#v", got, want)
	}
}

func writeTestMetrics(
	w *bufio.Writer,
	counters CounterSnapshot,
	statuses []db.FeedSyncStatus,
	jobs []db.RefreshJob,
	queueStats *db.QueueStatsResult,
	dashboardStats *db.DashboardStatsResult,
	scanTotals *db.ScanTotals,
	dbPoolStats *db.DBPoolStats,
	schemaVersion uint,
) {
	writeMetrics(w, metricsRenderSnapshot{
		Counters:       counters,
		Statuses:       statuses,
		Jobs:           jobs,
		QueueStats:     queueStats,
		DashboardStats: dashboardStats,
		ScanTotals:     scanTotals,
		DBPoolStats:    dbPoolStats,
		SchemaVersion:  schemaVersion,
	})
}

func TestRegistryQueueJobsCompletedCounterUsesSourceAndResult(t *testing.T) {
	registry := NewRegistry()

	registry.IncQueueJobCompleted("socket", QueueJobResultSuccess)
	registry.IncQueueJobCompleted("socket", QueueJobResultSuccess)
	registry.IncQueueJobCompleted("socket", QueueJobResultError)
	registry.IncQueueJobCompleted("socket", "unexpected raw result")
	registry.IncQueueJobCompleted("", QueueJobResultSuccess)

	snapshot := registry.Snapshot()
	successKey := QueueJobCompletedKey{Source: "socket", Result: QueueJobResultSuccess}
	errorKey := QueueJobCompletedKey{Source: "socket", Result: QueueJobResultError}
	if got := snapshot.QueueJobsCompleted[successKey]; got != 2 {
		t.Fatalf("QueueJobsCompleted success = %d, want 2", got)
	}
	if got := snapshot.QueueJobsCompleted[errorKey]; got != 1 {
		t.Fatalf("QueueJobsCompleted error = %d, want 1", got)
	}
	if got := len(snapshot.QueueJobsCompleted); got != 2 {
		t.Fatalf("QueueJobsCompleted series = %d, want only success/error labels", got)
	}
}

func TestWriteHTTPMetricsIncludesDurationHistogramBuckets(t *testing.T) {
	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeTestMetrics(writer, CounterSnapshot{
		HTTPRequests: map[httpMetricKey]httpMetricSnapshot{
			{Method: http.MethodPost, Route: "POST /api/v1/check", Status: "200"}: {
				Count:         2,
				DurationNanos: 300_000_000,
				DurationBuckets: []uint64{
					1, 2, 2, 2, 2, 2, 2,
				},
			},
		},
	}, nil, nil, nil, nil, nil, nil, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	for _, want := range []string{
		"# TYPE packmon_http_request_duration_seconds histogram",
		`packmon_http_request_duration_seconds_bucket{method="POST",route="POST /api/v1/check",status="200",le="0.1"} 1`,
		`packmon_http_request_duration_seconds_bucket{method="POST",route="POST /api/v1/check",status="200",le="0.25"} 2`,
		`packmon_http_request_duration_seconds_bucket{method="POST",route="POST /api/v1/check",status="200",le="+Inf"} 2`,
		`packmon_http_request_duration_seconds_count{method="POST",route="POST /api/v1/check",status="200"} 2`,
		`packmon_http_request_duration_seconds_sum{method="POST",route="POST /api/v1/check",status="200"} 0.300000000`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("metrics output missing %q\n%s", want, output)
		}
	}
}

func TestRegistryRecordsHTTPRequestDurationBuckets(t *testing.T) {
	registry := NewRegistry()

	registry.RecordHTTPRequest(http.MethodGet, "GET /healthz", http.StatusOK, 50*time.Millisecond)
	registry.RecordHTTPRequest(http.MethodGet, "GET /healthz", http.StatusOK, 250*time.Millisecond)

	snapshot := registry.Snapshot()
	key := httpMetricKey{Method: http.MethodGet, Route: "GET /healthz", Status: "200"}
	metric, ok := snapshot.HTTPRequests[key]
	if !ok {
		t.Fatalf("missing HTTP metric for %v", key)
	}
	if got := metric.DurationBuckets; len(got) != len(httpDurationBucketBounds) {
		t.Fatalf("duration bucket count = %d, want %d", len(got), len(httpDurationBucketBounds))
	}
	if got := metric.DurationBuckets[0]; got != 1 {
		t.Fatalf("<=0.1s bucket = %d, want 1", got)
	}
	if got := metric.DurationBuckets[1]; got != 2 {
		t.Fatalf("<=0.25s bucket = %d, want 2", got)
	}
}

func TestMetricsHandlerExportsStoreReadFailureCounter(t *testing.T) {
	registry := NewRegistry()
	handler := MetricsHandlerWithRegistry(registry, failingMetricsStore{}, 3, slog.New(slog.NewTextHandler(io.Discard, nil)))

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("scrape %d status = %d, want 200", i+1, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	output := rec.Body.String()
	for _, want := range []string{
		"# HELP packmon_metrics_store_read_failures_total Store-derived metrics read failures since process start.",
		"# TYPE packmon_metrics_store_read_failures_total counter",
		`packmon_metrics_store_read_failures_total{operation="feed_sync_statuses"} 3`,
		`packmon_metrics_store_read_failures_total{operation="queue_jobs"} 3`,
		`packmon_metrics_store_read_failures_total{operation="queue_stats"} 3`,
		`packmon_metrics_store_read_failures_total{operation="dashboard_stats"} 1`,
		`packmon_metrics_store_read_failures_total{operation="scan_totals"} 1`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("metrics output missing %q\n%s", want, output)
		}
	}
}

func TestWriteMetricsOutputRegression(t *testing.T) {
	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeTestMetrics(writer, CounterSnapshot{
		AuthLoginFailures:   2,
		DegradedResponses:   3,
		QueueStuckRecovered: 4,
		FeedSyncTimeouts:    map[string]uint64{`feed\quoted`: 5},
		QueueErrors:         map[string]uint64{`socket"dev`: 6},
		QueueJobsCompleted: map[QueueJobCompletedKey]uint64{
			{Source: `reversing\labs`, Result: QueueJobResultError}: 8,
			{Source: `socket"dev`, Result: QueueJobResultSuccess}:   7,
		},
		HTTPRequests: map[httpMetricKey]httpMetricSnapshot{
			{Method: http.MethodGet, Route: `GET /api/"quote"`, Status: "200"}: {
				Count:         7,
				DurationNanos: 2_500_000_000,
			},
		},
	}, []db.FeedSyncStatus{
		{FeedName: `feed\quoted`, LastSyncStatus: db.FeedSyncStatusRunning},
	}, nil, &db.QueueStatsResult{
		Pending:    1,
		Processing: 2,
		Done:       3,
		Error:      4,
		Paused:     5,
	}, &db.DashboardStatsResult{
		TotalPackages:        10,
		TotalVulnerabilities: 11,
		TotalMalicious:       12,
		TotalSupplyChainRisk: 13,
		TotalLifecycle:       14,
		BySeverity:           map[string]int{"LOW": 15},
	}, &db.ScanTotals{
		PackagesScanned: 16,
		Findings:        17,
	}, &db.DBPoolStats{
		MaxConns:          18,
		AcquiredConns:     19,
		IdleConns:         20,
		ConstructingConns: 21,
		AcquireCount:      22,
		AcquireDuration:   1500 * time.Millisecond,
		CanceledAcquires:  23,
		EmptyAcquires:     24,
		EmptyAcquireWait:  250 * time.Millisecond,
	}, 25)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	want := strings.Join([]string{
		"# HELP packmon_auth_login_failures_total Failed admin login attempts since process start.",
		"# TYPE packmon_auth_login_failures_total counter",
		"packmon_auth_login_failures_total 2",
		"# HELP packmon_degraded_responses_total API responses sent with feed_status=degraded.",
		"# TYPE packmon_degraded_responses_total counter",
		"packmon_degraded_responses_total 3",
		"# HELP packmon_queue_stuck_jobs_recovered_total Queue jobs recovered from a stuck processing state.",
		"# TYPE packmon_queue_stuck_jobs_recovered_total counter",
		"packmon_queue_stuck_jobs_recovered_total 4",
		"# HELP packmon_db_migration_version Current database schema version expected by the running server.",
		"# TYPE packmon_db_migration_version gauge",
		"packmon_db_migration_version 25",
		"# HELP packmon_metrics_store_read_failures_total Store-derived metrics read failures since process start.",
		"# TYPE packmon_metrics_store_read_failures_total counter",
		"# HELP packmon_go_goroutines Current number of goroutines.",
		"# TYPE packmon_go_goroutines gauge",
		"packmon_go_goroutines 0",
		"# HELP packmon_go_heap_alloc_bytes Bytes of allocated heap objects.",
		"# TYPE packmon_go_heap_alloc_bytes gauge",
		"packmon_go_heap_alloc_bytes 0",
		"# HELP packmon_go_heap_inuse_bytes Bytes in in-use heap spans.",
		"# TYPE packmon_go_heap_inuse_bytes gauge",
		"packmon_go_heap_inuse_bytes 0",
		"# HELP packmon_go_gc_cycles_total Completed Go garbage collection cycles.",
		"# TYPE packmon_go_gc_cycles_total counter",
		"packmon_go_gc_cycles_total 0",
		"# HELP packmon_go_gc_last_pause_seconds Pause duration of the most recent Go garbage collection cycle.",
		"# TYPE packmon_go_gc_last_pause_seconds gauge",
		"packmon_go_gc_last_pause_seconds 0.000000000",
		"# HELP packmon_http_requests_total HTTP requests handled by the main server.",
		"# TYPE packmon_http_requests_total counter",
		`packmon_http_requests_total{method="GET",route="GET /api/\"quote\"",status="200"} 7`,
		"# HELP packmon_http_request_duration_seconds Cumulative request duration on the main server.",
		"# TYPE packmon_http_request_duration_seconds histogram",
		`packmon_http_request_duration_seconds_bucket{method="GET",route="GET /api/\"quote\"",status="200",le="0.1"} 0`,
		`packmon_http_request_duration_seconds_bucket{method="GET",route="GET /api/\"quote\"",status="200",le="0.25"} 0`,
		`packmon_http_request_duration_seconds_bucket{method="GET",route="GET /api/\"quote\"",status="200",le="0.5"} 0`,
		`packmon_http_request_duration_seconds_bucket{method="GET",route="GET /api/\"quote\"",status="200",le="1"} 0`,
		`packmon_http_request_duration_seconds_bucket{method="GET",route="GET /api/\"quote\"",status="200",le="2.5"} 0`,
		`packmon_http_request_duration_seconds_bucket{method="GET",route="GET /api/\"quote\"",status="200",le="5"} 0`,
		`packmon_http_request_duration_seconds_bucket{method="GET",route="GET /api/\"quote\"",status="200",le="10"} 0`,
		`packmon_http_request_duration_seconds_bucket{method="GET",route="GET /api/\"quote\"",status="200",le="+Inf"} 7`,
		`packmon_http_request_duration_seconds_count{method="GET",route="GET /api/\"quote\"",status="200"} 7`,
		`packmon_http_request_duration_seconds_sum{method="GET",route="GET /api/\"quote\"",status="200"} 2.500000000`,
		"# HELP packmon_queue_size Current refresh queue size by status.",
		"# TYPE packmon_queue_size gauge",
		`packmon_queue_size{status="pending"} 1`,
		`packmon_queue_size{status="processing"} 2`,
		`packmon_queue_size{status="done"} 3`,
		`packmon_queue_size{status="error"} 4`,
		`packmon_queue_size{status="paused"} 5`,
		"# HELP packmon_packages_total Current unique package count in indexed findings.",
		"# TYPE packmon_packages_total gauge",
		"packmon_packages_total 10",
		"# HELP packmon_findings_total Current finding count by type.",
		"# TYPE packmon_findings_total gauge",
		`packmon_findings_total{type="vulnerability"} 11`,
		`packmon_findings_total{type="malicious"} 12`,
		`packmon_findings_total{type="supply_chain_risk"} 13`,
		`packmon_findings_total{type="lifecycle"} 14`,
		"# HELP packmon_findings_by_severity Current finding count by severity.",
		"# TYPE packmon_findings_by_severity gauge",
		`packmon_findings_by_severity{severity="LOW"} 15`,
		"# HELP packmon_packages_scanned_total Cumulative packages scanned from scan logs.",
		"# TYPE packmon_packages_scanned_total counter",
		"packmon_packages_scanned_total 16",
		"# HELP packmon_scan_findings_total Cumulative findings returned in scan logs.",
		"# TYPE packmon_scan_findings_total counter",
		"packmon_scan_findings_total 17",
		"# HELP packmon_db_pool_connections PostgreSQL connection pool gauge by state.",
		"# TYPE packmon_db_pool_connections gauge",
		`packmon_db_pool_connections{state="max"} 18`,
		`packmon_db_pool_connections{state="acquired"} 19`,
		`packmon_db_pool_connections{state="idle"} 20`,
		`packmon_db_pool_connections{state="constructing"} 21`,
		"# HELP packmon_db_pool_acquire_total Cumulative successful PostgreSQL pool acquires.",
		"# TYPE packmon_db_pool_acquire_total counter",
		"packmon_db_pool_acquire_total 22",
		"# HELP packmon_db_pool_acquire_duration_seconds_total Cumulative duration spent acquiring PostgreSQL pool connections.",
		"# TYPE packmon_db_pool_acquire_duration_seconds_total counter",
		"packmon_db_pool_acquire_duration_seconds_total 1.500000000",
		"# HELP packmon_db_pool_canceled_acquire_total Cumulative PostgreSQL pool acquires canceled before a connection was acquired.",
		"# TYPE packmon_db_pool_canceled_acquire_total counter",
		"packmon_db_pool_canceled_acquire_total 23",
		"# HELP packmon_db_pool_empty_acquire_total Cumulative successful PostgreSQL pool acquires that waited because the pool was empty.",
		"# TYPE packmon_db_pool_empty_acquire_total counter",
		"packmon_db_pool_empty_acquire_total 24",
		"# HELP packmon_db_pool_empty_acquire_wait_seconds_total Cumulative wait time for successful PostgreSQL pool acquires when the pool was empty.",
		"# TYPE packmon_db_pool_empty_acquire_wait_seconds_total counter",
		"packmon_db_pool_empty_acquire_wait_seconds_total 0.250000000",
		"# HELP packmon_feed_last_sync_timestamp Unix timestamp of the latest feed sync attempt or status heartbeat.",
		"# TYPE packmon_feed_last_sync_timestamp gauge",
		"# HELP packmon_feed_entries_age_seconds Freshness proxy for feed data, derived from time since the last usable sync.",
		"# TYPE packmon_feed_entries_age_seconds gauge",
		"# HELP packmon_feed_sync_status Current feed sync status as one-hot gauges per canonical status.",
		"# TYPE packmon_feed_sync_status gauge",
		`packmon_feed_sync_status{feed="feed\\quoted",status="pending"} 0`,
		`packmon_feed_sync_status{feed="feed\\quoted",status="running"} 1`,
		`packmon_feed_sync_status{feed="feed\\quoted",status="success"} 0`,
		`packmon_feed_sync_status{feed="feed\\quoted",status="error"} 0`,
		`packmon_feed_sync_status{feed="feed\\quoted",status="skipped"} 0`,
		`packmon_feed_sync_status{feed="feed\\quoted",status="disabled"} 0`,
		`packmon_feed_sync_status{feed="feed\\quoted",status="external"} 0`,
		`packmon_feed_sync_status{feed="feed\\quoted",status="rejected"} 0`,
		`packmon_feed_sync_status{feed="feed\\quoted",status="permanent_error"} 0`,
		"# HELP packmon_feed_sync_timeout_total Feed sync attempts that failed due to timeouts since process start.",
		"# TYPE packmon_feed_sync_timeout_total counter",
		`packmon_feed_sync_timeout_total{feed="feed\\quoted"} 5`,
		"# HELP packmon_feed_sync_duration_seconds Duration in seconds of the latest recorded feed sync attempt.",
		"# TYPE packmon_feed_sync_duration_seconds gauge",
		"# HELP packmon_queue_oldest_job_seconds Age in seconds of the oldest pending or processing queue job per source.",
		"# TYPE packmon_queue_oldest_job_seconds gauge",
		"# HELP packmon_queue_error_total Queue jobs that failed while being processed since process start.",
		"# TYPE packmon_queue_error_total counter",
		`packmon_queue_error_total{source="socket\"dev"} 6`,
		"# HELP packmon_queue_jobs_completed_total Queue jobs completed by workers since process start.",
		"# TYPE packmon_queue_jobs_completed_total counter",
		`packmon_queue_jobs_completed_total{source="reversing\\labs",result="error"} 8`,
		`packmon_queue_jobs_completed_total{source="socket\"dev",result="success"} 7`,
	}, "\n") + "\n"

	if got := builder.String(); got != want {
		t.Fatalf("writeMetrics output changed\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestWriteMetricsIncludesFeedSyncDurationByFeedAndStatus(t *testing.T) {
	duration := 1250 * time.Millisecond
	invalidDuration := 2 * time.Second

	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeTestMetrics(writer, CounterSnapshot{}, []db.FeedSyncStatus{
		{
			FeedName:         `osv"primary`,
			LastSyncStatus:   db.FeedSyncStatusSuccess,
			LastSyncDuration: &duration,
		},
		{
			FeedName:         "ignored",
			LastSyncStatus:   `bad"status`,
			LastSyncDuration: &invalidDuration,
		},
	}, nil, nil, nil, nil, nil, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	if want := `packmon_feed_sync_duration_seconds{feed="osv\"primary",status="success"} 1.250000000`; !strings.Contains(output, want) {
		t.Fatalf("metrics output missing feed sync duration %q\n%s", want, output)
	}
	if strings.Contains(output, `packmon_feed_sync_duration_seconds{feed="ignored"`) ||
		strings.Contains(output, `packmon_feed_sync_duration_seconds{feed="ignored",status="bad\"status"`) {
		t.Fatalf("metrics output leaked invalid feed sync status label\n%s", output)
	}
}

func TestMetricsHandlerIncludesGoRuntimeMetrics(t *testing.T) {
	rec := httptest.NewRecorder()
	MetricsHandlerWithRegistry(NewRegistry(), &metricsStoreStub{}, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	output := rec.Body.String()
	for _, want := range []string{
		"# TYPE packmon_go_goroutines gauge",
		"packmon_go_goroutines ",
		"# TYPE packmon_go_heap_alloc_bytes gauge",
		"packmon_go_heap_alloc_bytes ",
		"# TYPE packmon_go_heap_inuse_bytes gauge",
		"packmon_go_heap_inuse_bytes ",
		"# TYPE packmon_go_gc_cycles_total counter",
		"packmon_go_gc_cycles_total ",
		"# TYPE packmon_go_gc_last_pause_seconds gauge",
		"packmon_go_gc_last_pause_seconds ",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("metrics output missing %q\n%s", want, output)
		}
	}
}

func TestMetricsHandlerRendersBuildInfoFromRegistry(t *testing.T) {
	registry := NewRegistry()
	registry.SetBuildInfo(BuildInfo{
		Service: "packmon-server",
		Version: `1.2."3`,
		Commit:  "abc123",
		Date:    "2026-06-28T00:00:00Z",
	})

	rec := httptest.NewRecorder()
	MetricsHandlerWithRegistry(registry, &metricsStoreStub{}, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if want := `packmon_build_info{service="packmon-server",version="1.2.\"3",commit="abc123",date="2026-06-28T00:00:00Z"} 1`; !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("metrics output missing build info %q\n%s", want, rec.Body.String())
	}
}

func isUTCNowAssignment(stmt ast.Stmt) bool {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return false
	}
	lhs, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || lhs.Name != "now" {
		return false
	}
	utcCall, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	utcSelector, ok := utcCall.Fun.(*ast.SelectorExpr)
	if !ok || utcSelector.Sel.Name != "UTC" {
		return false
	}
	nowCall, ok := utcSelector.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	nowSelector, ok := nowCall.Fun.(*ast.SelectorExpr)
	if !ok || nowSelector.Sel.Name != "Now" {
		return false
	}
	packageIdent, ok := nowSelector.X.(*ast.Ident)
	return ok && packageIdent.Name == "time"
}

func directMetricGroupWriterCall(stmt ast.Stmt) (string, bool) {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return "", false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || !strings.HasPrefix(ident.Name, "write") || !strings.HasSuffix(ident.Name, "Metrics") {
		return "", false
	}
	return ident.Name, ident.Name != "writeMetrics"
}

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
	writeTestMetrics(writer, registry.Snapshot(), []db.FeedSyncStatus{
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
		AcquireCount:      31,
		AcquireDuration:   2 * time.Second,
		CanceledAcquires:  4,
		EmptyAcquires:     5,
		EmptyAcquireWait:  750 * time.Millisecond,
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
		`packmon_feed_sync_status{feed="osv",status="success"} 1`,
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
		`packmon_db_pool_acquire_total 31`,
		`packmon_db_pool_acquire_duration_seconds_total 2.000000000`,
		`packmon_db_pool_canceled_acquire_total 4`,
		`packmon_db_pool_empty_acquire_total 5`,
		`packmon_db_pool_empty_acquire_wait_seconds_total 0.750000000`,
		"packmon_db_migration_version 1",
	} {
		if !strings.Contains(output, metric) {
			t.Fatalf("metrics output missing %q\n%s", metric, output)
		}
	}
}

func TestWriteMetricsIncludesFeedSyncStatusGauges(t *testing.T) {
	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeTestMetrics(writer, CounterSnapshot{}, []db.FeedSyncStatus{
		{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusSuccess},
		{FeedName: "nvd", LastSyncStatus: db.FeedSyncStatusError},
		{FeedName: "ignored", LastSyncStatus: "failed"},
	}, nil, nil, nil, nil, nil, 1)
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	output := builder.String()
	for _, want := range []string{
		`packmon_feed_sync_status{feed="osv",status="success"} 1`,
		`packmon_feed_sync_status{feed="osv",status="error"} 0`,
		`packmon_feed_sync_status{feed="nvd",status="error"} 1`,
		`packmon_feed_sync_status{feed="nvd",status="success"} 0`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("metrics output missing %q\n%s", want, output)
		}
	}
	if strings.Contains(output, `packmon_feed_sync_status{feed="ignored"`) {
		t.Fatalf("metrics output included invalid feed status label:\n%s", output)
	}
}

func TestWriteMetricsClampsFindingSeverityLabels(t *testing.T) {
	var builder strings.Builder
	writer := bufio.NewWriter(&builder)
	writeTestMetrics(writer, CounterSnapshot{}, nil, nil, nil, &db.DashboardStatsResult{
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
	writeTestMetrics(writer, registry.Snapshot(), nil, nil, nil, nil, nil, nil, 1)
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
	writeTestMetrics(writer, CounterSnapshot{}, []db.FeedSyncStatus{
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
	writeTestMetrics(writer, registry.Snapshot(), nil, nil, nil, nil, nil, nil, 1)
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
	writeTestMetrics(writer, registry.Snapshot(), nil, nil, nil, nil, nil, nil, 1)
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
	mu           sync.Mutex
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
		s.mu.Lock()
		s.deadlineSeen = true
		s.mu.Unlock()
	}
}

func (s *metricsStoreStub) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	s.recordContext(ctx)
	return s.statuses, nil
}

func (s *metricsStoreStub) ListQueueJobs(ctx context.Context, _ string, _ int) ([]db.RefreshJob, error) {
	s.recordContext(ctx)
	s.mu.Lock()
	s.listJobs++
	s.mu.Unlock()
	return s.jobs, nil
}

func (s *metricsStoreStub) OldestQueueJobs(ctx context.Context) (map[string]time.Time, error) {
	s.recordContext(ctx)
	s.mu.Lock()
	s.oldestCalls++
	s.mu.Unlock()
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
	s.mu.Lock()
	s.dashCalls++
	s.mu.Unlock()
	return s.dash, nil
}

func (s *metricsStoreStub) ScanTotals(ctx context.Context) (*db.ScanTotals, error) {
	s.recordContext(ctx)
	s.mu.Lock()
	s.scanCalls++
	s.mu.Unlock()
	return s.scans, nil
}

func (s *metricsStoreStub) DBPoolStats() db.DBPoolStats {
	return s.pool
}

var _ MetricsStore = (*metricsStoreStub)(nil)

type failingMetricsStore struct {
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

func (failingMetricsStore) DBPoolStats() db.DBPoolStats {
	return db.DBPoolStats{}
}

var _ MetricsStore = failingMetricsStore{}

type parallelProbeMetricsStore struct {
	expected int32
	started  atomic.Int32
	active   atomic.Int32
	maxSeen  atomic.Int32
	release  chan struct{}
	once     sync.Once
}

func newParallelProbeMetricsStore(expected int32) *parallelProbeMetricsStore {
	return &parallelProbeMetricsStore{
		expected: expected,
		release:  make(chan struct{}),
	}
}

func (s *parallelProbeMetricsStore) enter() {
	active := s.active.Add(1)
	for {
		maxSeen := s.maxSeen.Load()
		if active <= maxSeen || s.maxSeen.CompareAndSwap(maxSeen, active) {
			break
		}
	}
	if s.started.Add(1) == s.expected {
		s.once.Do(func() {
			close(s.release)
		})
	}
}

func (s *parallelProbeMetricsStore) observe(ctx context.Context) error {
	s.enter()
	defer s.active.Add(-1)
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *parallelProbeMetricsStore) observeWithoutContext() {
	s.enter()
	defer s.active.Add(-1)
	select {
	case <-s.release:
	case <-time.After(time.Second):
	}
}

func (s *parallelProbeMetricsStore) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	return []db.FeedSyncStatus{{FeedName: "osv", LastSyncStatus: db.FeedSyncStatusSuccess}}, nil
}

func (s *parallelProbeMetricsStore) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return nil, errors.New("unexpected queue job fallback read")
}

func (s *parallelProbeMetricsStore) OldestQueueJobs(ctx context.Context) (map[string]time.Time, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	return map[string]time.Time{"socket": time.Now().Add(-time.Minute)}, nil
}

func (s *parallelProbeMetricsStore) QueueStats(ctx context.Context) (*db.QueueStatsResult, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	return &db.QueueStatsResult{Pending: 1}, nil
}

func (s *parallelProbeMetricsStore) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	return &db.DashboardStatsResult{TotalPackages: 1}, nil
}

func (s *parallelProbeMetricsStore) ScanTotals(ctx context.Context) (*db.ScanTotals, error) {
	if err := s.observe(ctx); err != nil {
		return nil, err
	}
	return &db.ScanTotals{PackagesScanned: 1, Findings: 1}, nil
}

func (s *parallelProbeMetricsStore) DBPoolStats() db.DBPoolStats {
	s.observeWithoutContext()
	return db.DBPoolStats{MaxConns: 1}
}

var _ MetricsStore = (*parallelProbeMetricsStore)(nil)
var _ queueOldestProvider = (*parallelProbeMetricsStore)(nil)

type derivedStampedeMetricsStore struct {
	dashboardCalls   atomic.Int32
	scanCalls        atomic.Int32
	dashboardStarted chan struct{}
	scanStarted      chan struct{}
	release          chan struct{}
	dashboardOnce    sync.Once
	scanOnce         sync.Once
	releaseOnce      sync.Once
}

func newDerivedStampedeMetricsStore() *derivedStampedeMetricsStore {
	return &derivedStampedeMetricsStore{
		dashboardStarted: make(chan struct{}),
		scanStarted:      make(chan struct{}),
		release:          make(chan struct{}),
	}
}

func (s *derivedStampedeMetricsStore) unblock() {
	s.releaseOnce.Do(func() {
		close(s.release)
	})
}

func (s *derivedStampedeMetricsStore) waitForFirstRefresh(t *testing.T) {
	t.Helper()
	for name, started := range map[string]chan struct{}{
		"DashboardStats": s.dashboardStarted,
		"ScanTotals":     s.scanStarted,
	} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("%s did not start", name)
		}
	}
}

func (s *derivedStampedeMetricsStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return nil, nil
}

func (s *derivedStampedeMetricsStore) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return nil, nil
}

func (s *derivedStampedeMetricsStore) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	return nil, nil
}

func (s *derivedStampedeMetricsStore) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	s.dashboardCalls.Add(1)
	s.dashboardOnce.Do(func() {
		close(s.dashboardStarted)
	})
	select {
	case <-s.release:
		return &db.DashboardStatsResult{TotalPackages: 42}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *derivedStampedeMetricsStore) ScanTotals(ctx context.Context) (*db.ScanTotals, error) {
	s.scanCalls.Add(1)
	s.scanOnce.Do(func() {
		close(s.scanStarted)
	})
	select {
	case <-s.release:
		return &db.ScanTotals{PackagesScanned: 43, Findings: 44}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *derivedStampedeMetricsStore) DBPoolStats() db.DBPoolStats {
	return db.DBPoolStats{}
}

var _ MetricsStore = (*derivedStampedeMetricsStore)(nil)

func TestMetricsHandlerParallelizesIndependentStoreReads(t *testing.T) {
	const expectedReads int32 = 6
	store := newParallelProbeMetricsStore(expectedReads)
	handler := MetricsHandlerWithRegistry(NewRegistry(), store, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil).WithContext(ctx))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := store.started.Load(); got != expectedReads {
		t.Fatalf("store reads started = %d, want %d", got, expectedReads)
	}
	if got := store.maxSeen.Load(); got < expectedReads {
		t.Fatalf("max concurrent store reads = %d, want at least %d", got, expectedReads)
	}
}

func TestMetricsDerivedCacheCoalescesConcurrentColdRefreshStampede(t *testing.T) {
	const callers = 16

	store := newDerivedStampedeMetricsStore()
	defer store.unblock()
	cache := &metricsDerivedCache{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := make(chan struct{})
	errs := make(chan string, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			dashboardStats, scanTotals, failures := cache.load(ctx, store)
			if len(failures) != 0 {
				errs <- fmt.Sprintf("load failures = %v", failures)
				return
			}
			if dashboardStats == nil || dashboardStats.TotalPackages != 42 {
				errs <- fmt.Sprintf("DashboardStats = %+v, want TotalPackages 42", dashboardStats)
			}
			if scanTotals == nil || scanTotals.PackagesScanned != 43 || scanTotals.Findings != 44 {
				errs <- fmt.Sprintf("ScanTotals = %+v, want PackagesScanned 43 and Findings 44", scanTotals)
			}
		}()
	}

	close(start)
	store.waitForFirstRefresh(t)
	time.Sleep(50 * time.Millisecond)
	store.unblock()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent cache loads did not finish")
	}
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if got := store.dashboardCalls.Load(); got != 1 {
		t.Fatalf("DashboardStats calls = %d, want 1 coalesced refresh", got)
	}
	if got := store.scanCalls.Load(); got != 1 {
		t.Fatalf("ScanTotals calls = %d, want 1 coalesced refresh", got)
	}
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
	MetricsHandlerWithRegistry(NewRegistry(), store, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
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
	MetricsHandlerWithRegistry(NewRegistry(), store, 7, slog.New(slog.NewTextHandler(io.Discard, nil)))(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

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
	MetricsHandlerWithRegistry(NewRegistry(), failingMetricsStore{}, 3, nil)(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

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
