package telemetry

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

// Registry stores lightweight in-process counters for operational metrics.
// Dynamic gauges are derived from the backing store on every scrape.
type Registry struct {
	authLoginFailures   atomic.Uint64
	degradedResponses   atomic.Uint64
	queueStuckRecovered atomic.Uint64

	mu                 sync.RWMutex
	buildInfo          BuildInfo
	feedSyncTimeouts   map[string]*atomic.Uint64
	queueErrors        map[string]*atomic.Uint64
	queueJobsCompleted map[QueueJobCompletedKey]*atomic.Uint64
	httpRequests       map[httpMetricKey]*httpMetricCounters
	metricsStoreErrors map[string]*atomic.Uint64
}

// CounterSnapshot is a copy-on-read view of all in-memory counters.
type CounterSnapshot struct {
	AuthLoginFailures   uint64
	DegradedResponses   uint64
	QueueStuckRecovered uint64
	FeedSyncTimeouts    map[string]uint64
	QueueErrors         map[string]uint64
	QueueJobsCompleted  map[QueueJobCompletedKey]uint64
	HTTPRequests        map[httpMetricKey]httpMetricSnapshot
	MetricsStoreErrors  map[string]uint64
}

// BuildInfo describes the running service identity exposed through metrics.
type BuildInfo struct {
	Service string
	Version string
	Commit  string
	Date    string
}

// Queue completion result labels are intentionally fixed to keep cardinality
// bounded and avoid exposing raw worker errors as metric labels.
const (
	QueueJobResultSuccess = "success"
	QueueJobResultError   = "error"
)

// QueueJobCompletedKey identifies one queue-completion counter series.
type QueueJobCompletedKey struct {
	Source string
	Result string
}

const (
	metricsStoreTimeout          = 2 * time.Second
	metricsDerivedCacheTTL       = 30 * time.Second
	metricsStoreErrorLogInterval = 30 * time.Second
)

var defaultRegistry = NewRegistry()

var httpDurationBucketBounds = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type httpMetricKey struct {
	Method string
	Route  string
	Status string
}

type httpMetricCounters struct {
	count         atomic.Uint64
	durationNanos atomic.Uint64
	buckets       []atomic.Uint64
}

type httpMetricSnapshot struct {
	Count           uint64
	DurationNanos   uint64
	DurationBuckets []uint64
}

type goRuntimeMetrics struct {
	Goroutines       int
	HeapAllocBytes   uint64
	HeapInuseBytes   uint64
	GCCycles         uint32
	LastGCPauseNanos uint64
}

// Default returns the process-wide telemetry registry.
func Default() *Registry {
	return defaultRegistry
}

// NewRegistry creates an empty telemetry registry.
func NewRegistry() *Registry {
	return &Registry{
		feedSyncTimeouts:   make(map[string]*atomic.Uint64),
		queueErrors:        make(map[string]*atomic.Uint64),
		queueJobsCompleted: make(map[QueueJobCompletedKey]*atomic.Uint64),
		httpRequests:       make(map[httpMetricKey]*httpMetricCounters),
		metricsStoreErrors: make(map[string]*atomic.Uint64),
	}
}

// SetBuildInfo sets the low-cardinality service identity exported by metrics.
func (r *Registry) SetBuildInfo(info BuildInfo) {
	if r == nil {
		return
	}
	info = normalizeBuildInfo(info)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buildInfo = info
}

// BuildInfo returns the configured service identity for metrics output.
func (r *Registry) BuildInfo() BuildInfo {
	if r == nil {
		return BuildInfo{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.buildInfo
}

// IncAuthLoginFailures increments the failed admin-login counter.
func (r *Registry) IncAuthLoginFailures() {
	r.authLoginFailures.Add(1)
}

// IncDegradedResponses increments the degraded API response counter.
func (r *Registry) IncDegradedResponses() {
	r.degradedResponses.Add(1)
}

// AddQueueStuckRecovered increments the recovered stuck-jobs counter.
func (r *Registry) AddQueueStuckRecovered(n int) {
	if n > 0 {
		r.queueStuckRecovered.Add(uint64(n))
	}
}

// IncFeedSyncTimeout increments the timeout counter for a feed.
func (r *Registry) IncFeedSyncTimeout(feed string) {
	if feed == "" {
		return
	}
	r.counterFor(r.feedSyncTimeouts, feed).Add(1)
}

// IncQueueError increments the cumulative queue-error counter for a source.
func (r *Registry) IncQueueError(source string) {
	if source == "" {
		return
	}
	r.counterFor(r.queueErrors, source).Add(1)
}

// IncQueueJobCompleted increments the completed queue-job throughput counter.
func (r *Registry) IncQueueJobCompleted(source, result string) {
	source = strings.TrimSpace(source)
	result = normalizeQueueJobResult(result)
	if source == "" || result == "" {
		return
	}
	r.queueJobCompletedCounterFor(QueueJobCompletedKey{Source: source, Result: result}).Add(1)
}

// RecordHTTPRequest records one completed HTTP request.
func (r *Registry) RecordHTTPRequest(method, route string, status int, duration time.Duration) {
	method = normalizeHTTPMethod(method)
	if route == "" {
		route = "unknown"
	}
	if status <= 0 {
		status = http.StatusOK
	}
	if duration < 0 {
		duration = 0
	}

	counter := r.httpCounterFor(httpMetricKey{
		Method: method,
		Route:  route,
		Status: fmt.Sprintf("%d", status),
	})
	counter.count.Add(1)
	nanos := duration.Nanoseconds()
	if nanos > 0 {
		counter.durationNanos.Add(uint64(nanos)) // #nosec G115 -- duration is clamped to a non-negative value above.
	}
	durationSeconds := duration.Seconds()
	for i, bound := range httpDurationBucketBounds {
		if durationSeconds <= bound {
			counter.buckets[i].Add(1)
		}
	}
}

func (r *Registry) recordMetricsStoreFailures(failures []metricsStoreFailure) {
	for _, failure := range failures {
		operation := normalizeMetricsStoreFailureOperation(failure.operation)
		if operation == "" {
			continue
		}
		r.counterFor(r.metricsStoreErrors, operation).Add(1)
	}
}

func normalizeHTTPMethod(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet:
		return http.MethodGet
	case http.MethodHead:
		return http.MethodHead
	case http.MethodPost:
		return http.MethodPost
	case http.MethodPut:
		return http.MethodPut
	case http.MethodPatch:
		return http.MethodPatch
	case http.MethodDelete:
		return http.MethodDelete
	case http.MethodConnect:
		return http.MethodConnect
	case http.MethodOptions:
		return http.MethodOptions
	case http.MethodTrace:
		return http.MethodTrace
	default:
		return "OTHER"
	}
}

func (r *Registry) counterFor(buckets map[string]*atomic.Uint64, key string) *atomic.Uint64 {
	r.mu.RLock()
	counter := buckets[key]
	r.mu.RUnlock()
	if counter != nil {
		return counter
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if counter = buckets[key]; counter != nil {
		return counter
	}

	counter = &atomic.Uint64{}
	buckets[key] = counter
	return counter
}

func (r *Registry) queueJobCompletedCounterFor(key QueueJobCompletedKey) *atomic.Uint64 {
	r.mu.RLock()
	counter := r.queueJobsCompleted[key]
	r.mu.RUnlock()
	if counter != nil {
		return counter
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if counter = r.queueJobsCompleted[key]; counter != nil {
		return counter
	}

	counter = &atomic.Uint64{}
	r.queueJobsCompleted[key] = counter
	return counter
}

func (r *Registry) httpCounterFor(key httpMetricKey) *httpMetricCounters {
	r.mu.RLock()
	counter := r.httpRequests[key]
	r.mu.RUnlock()
	if counter != nil {
		return counter
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if counter = r.httpRequests[key]; counter != nil {
		return counter
	}

	counter = &httpMetricCounters{
		buckets: make([]atomic.Uint64, len(httpDurationBucketBounds)),
	}
	r.httpRequests[key] = counter
	return counter
}

// Snapshot returns a stable copy of all in-memory counters.
func (r *Registry) Snapshot() CounterSnapshot {
	snapshot := CounterSnapshot{
		AuthLoginFailures:   r.authLoginFailures.Load(),
		DegradedResponses:   r.degradedResponses.Load(),
		QueueStuckRecovered: r.queueStuckRecovered.Load(),
		FeedSyncTimeouts:    make(map[string]uint64),
		QueueErrors:         make(map[string]uint64),
		QueueJobsCompleted:  make(map[QueueJobCompletedKey]uint64),
		HTTPRequests:        make(map[httpMetricKey]httpMetricSnapshot),
		MetricsStoreErrors:  make(map[string]uint64),
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for feed, counter := range r.feedSyncTimeouts {
		snapshot.FeedSyncTimeouts[feed] = counter.Load()
	}
	for source, counter := range r.queueErrors {
		snapshot.QueueErrors[source] = counter.Load()
	}
	for key, counter := range r.queueJobsCompleted {
		snapshot.QueueJobsCompleted[key] = counter.Load()
	}
	for key, counter := range r.httpRequests {
		buckets := make([]uint64, len(counter.buckets))
		for i := range counter.buckets {
			buckets[i] = counter.buckets[i].Load()
		}
		snapshot.HTTPRequests[key] = httpMetricSnapshot{
			Count:           counter.count.Load(),
			DurationNanos:   counter.durationNanos.Load(),
			DurationBuckets: buckets,
		}
	}
	for operation, counter := range r.metricsStoreErrors {
		snapshot.MetricsStoreErrors[operation] = counter.Load()
	}

	return snapshot
}

// MetricsStore is the persistence boundary required by the metrics endpoint.
// Store-derived metric series are part of the telemetry contract, so required
// methods live here instead of being discovered through optional type assertions.
type MetricsStore interface {
	ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error)
	ListQueueJobs(ctx context.Context, status string, limit int) ([]db.RefreshJob, error)
	QueueStats(ctx context.Context) (*db.QueueStatsResult, error)
	DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error)
	ScanTotals(ctx context.Context) (*db.ScanTotals, error)
	DBPoolStats() db.DBPoolStats
}

type queueOldestProvider interface {
	OldestQueueJobs(ctx context.Context) (map[string]time.Time, error)
}

type metricsStoreFailure struct {
	operation string
	err       error
}

type metricsStoreReadSnapshot struct {
	statuses       []db.FeedSyncStatus
	jobs           []db.RefreshJob
	queueStats     *db.QueueStatsResult
	dashboardStats *db.DashboardStatsResult
	scanTotals     *db.ScanTotals
	dbPoolStats    *db.DBPoolStats
	failures       []metricsStoreFailure
}

type metricsDerivedCache struct {
	mu             sync.Mutex
	expiresAt      time.Time
	dashboardStats *db.DashboardStatsResult
	scanTotals     *db.ScanTotals
	refreshDone    chan struct{}
}

type metricsStoreErrorLogger struct {
	logger  *slog.Logger
	mu      sync.Mutex
	nextLog time.Time
}

// unmatchedRouteLabel is the route label used for requests that did not match
// any registered route. Bucketing all such requests under one constant keeps
// the metric label cardinality bounded.
const unmatchedRouteLabel = "__unmatched__"

// HTTPMiddleware records request count and duration metrics for the wrapped handler.
func HTTPMiddleware(registry *Registry) func(http.Handler) http.Handler {
	if registry == nil {
		registry = Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			// Use the matched route pattern as the label. For requests that
			// did not match any registered route (404s) r.Pattern is empty;
			// bucket those under a single constant label instead of the raw
			// request path to avoid unbounded, attacker-controlled metric
			// label cardinality.
			route := r.Pattern
			if strings.TrimSpace(route) == "" {
				route = unmatchedRouteLabel
			}
			registry.RecordHTTPRequest(r.Method, route, rec.status, time.Since(start))
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(data)
}

// MetricsHandlerWithRegistry renders a Prometheus-compatible plaintext metrics
// response using the supplied in-process telemetry registry. A failing store
// read does not fail the response; failures are collapsed into a bounded WARN so
// repeated scrapes during an outage do not produce one warning per failed query.
func MetricsHandlerWithRegistry(registry *Registry, store MetricsStore, schemaVersion uint, logger *slog.Logger) http.HandlerFunc {
	if registry == nil {
		registry = Default()
	}
	if logger == nil {
		logger = slog.Default()
	}
	derivedCache := &metricsDerivedCache{}
	errorLogger := &metricsStoreErrorLogger{logger: logger}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		storeCtx, cancel := context.WithTimeout(r.Context(), metricsStoreTimeout)
		defer cancel()

		storeSnapshot := collectMetricsStoreReadSnapshot(storeCtx, store, derivedCache)

		registry.recordMetricsStoreFailures(storeSnapshot.failures)
		errorLogger.log(storeSnapshot.failures)

		writer := bufio.NewWriter(w)
		writeMetrics(writer, metricsRenderSnapshot{
			Counters:       registry.Snapshot(),
			BuildInfo:      registry.BuildInfo(),
			Runtime:        collectGoRuntimeMetrics(),
			Statuses:       storeSnapshot.statuses,
			Jobs:           storeSnapshot.jobs,
			QueueStats:     storeSnapshot.queueStats,
			DashboardStats: storeSnapshot.dashboardStats,
			ScanTotals:     storeSnapshot.scanTotals,
			DBPoolStats:    storeSnapshot.dbPoolStats,
			SchemaVersion:  schemaVersion,
		})
		_ = writer.Flush()
	}
}

func collectMetricsStoreReadSnapshot(ctx context.Context, store MetricsStore, derivedCache *metricsDerivedCache) metricsStoreReadSnapshot {
	var snapshot metricsStoreReadSnapshot
	if store == nil {
		return snapshot
	}

	var feedFailures []metricsStoreFailure
	var queueJobFailures []metricsStoreFailure
	var queueStatsFailures []metricsStoreFailure
	var derivedFailures []metricsStoreFailure

	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		statuses, err := store.ListFeedSyncStatuses(ctx)
		if err != nil {
			feedFailures = appendMetricStoreFailure(feedFailures, "feed_sync_statuses", err)
			return
		}
		snapshot.statuses = statuses
	}()

	go func() {
		defer wg.Done()
		if provider, ok := store.(queueOldestProvider); ok {
			oldest, err := provider.OldestQueueJobs(ctx)
			if err != nil {
				queueJobFailures = appendMetricStoreFailure(queueJobFailures, "oldest_queue_jobs", err)
				return
			}
			snapshot.jobs = queueJobsFromOldest(oldest)
			return
		}

		jobs, err := store.ListQueueJobs(ctx, "", 1000)
		if err != nil {
			queueJobFailures = appendMetricStoreFailure(queueJobFailures, "queue_jobs", err)
			return
		}
		snapshot.jobs = jobs
	}()

	go func() {
		defer wg.Done()
		queueStats, err := store.QueueStats(ctx)
		if err != nil {
			queueStatsFailures = appendMetricStoreFailure(queueStatsFailures, "queue_stats", err)
			return
		}
		snapshot.queueStats = queueStats
	}()

	go func() {
		defer wg.Done()
		var failures []metricsStoreFailure
		snapshot.dashboardStats, snapshot.scanTotals, failures = derivedCache.load(ctx, store)
		derivedFailures = append(derivedFailures, failures...)
	}()

	go func() {
		defer wg.Done()
		stats := store.DBPoolStats()
		snapshot.dbPoolStats = &stats
	}()

	wg.Wait()

	snapshot.failures = append(snapshot.failures, feedFailures...)
	snapshot.failures = append(snapshot.failures, queueJobFailures...)
	snapshot.failures = append(snapshot.failures, queueStatsFailures...)
	snapshot.failures = append(snapshot.failures, derivedFailures...)
	return snapshot
}

func (c *metricsDerivedCache) load(ctx context.Context, store MetricsStore) (*db.DashboardStatsResult, *db.ScanTotals, []metricsStoreFailure) {
	for {
		now := time.Now()

		c.mu.Lock()
		if c.expiresAt.After(now) {
			dashboardStats := cloneDashboardStats(c.dashboardStats)
			scanTotals := cloneScanTotals(c.scanTotals)
			c.mu.Unlock()
			return dashboardStats, scanTotals, nil
		}
		if done := c.refreshDone; done != nil {
			c.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				c.mu.Lock()
				dashboardStats := cloneDashboardStats(c.dashboardStats)
				scanTotals := cloneScanTotals(c.scanTotals)
				c.mu.Unlock()
				return dashboardStats, scanTotals, nil
			}
		}
		c.refreshDone = make(chan struct{})
		c.mu.Unlock()
		break
	}

	var failures []metricsStoreFailure
	var dashboardStats *db.DashboardStatsResult
	var scanTotals *db.ScanTotals
	var dashboardFailures []metricsStoreFailure
	var scanFailures []metricsStoreFailure

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		dashboardStats, err = store.DashboardStats(ctx)
		if err != nil {
			dashboardFailures = appendMetricStoreFailure(dashboardFailures, "dashboard_stats", err)
		}
	}()
	go func() {
		defer wg.Done()
		var err error
		scanTotals, err = store.ScanTotals(ctx)
		if err != nil {
			scanFailures = appendMetricStoreFailure(scanFailures, "scan_totals", err)
		}
	}()
	wg.Wait()
	failures = append(failures, dashboardFailures...)
	failures = append(failures, scanFailures...)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(dashboardFailures) == 0 {
		c.dashboardStats = cloneDashboardStats(dashboardStats)
	}
	if scanTotals != nil {
		c.scanTotals = cloneScanTotals(scanTotals)
	}
	c.expiresAt = time.Now().Add(metricsDerivedCacheTTL)
	close(c.refreshDone)
	c.refreshDone = nil

	return cloneDashboardStats(c.dashboardStats), cloneScanTotals(c.scanTotals), failures
}

func cloneDashboardStats(stats *db.DashboardStatsResult) *db.DashboardStatsResult {
	if stats == nil {
		return nil
	}
	out := *stats
	if stats.BySeverity != nil {
		out.BySeverity = make(map[string]int, len(stats.BySeverity))
		for severity, count := range stats.BySeverity {
			out.BySeverity[severity] = count
		}
	}
	return &out
}

func cloneScanTotals(totals *db.ScanTotals) *db.ScanTotals {
	if totals == nil {
		return nil
	}
	out := *totals
	return &out
}

func appendMetricStoreFailure(failures []metricsStoreFailure, operation string, err error) []metricsStoreFailure {
	if err == nil {
		return failures
	}
	return append(failures, metricsStoreFailure{operation: operation, err: err})
}

func normalizeMetricsStoreFailureOperation(operation string) string {
	switch operation {
	case "feed_sync_statuses", "queue_jobs", "oldest_queue_jobs", "queue_stats", "dashboard_stats", "scan_totals":
		return operation
	default:
		return ""
	}
}

func (l *metricsStoreErrorLogger) log(failures []metricsStoreFailure) {
	if len(failures) == 0 {
		return
	}
	if l.logger == nil {
		l.logger = slog.Default()
	}

	now := time.Now()
	l.mu.Lock()
	if l.nextLog.After(now) {
		l.mu.Unlock()
		return
	}
	l.nextLog = now.Add(metricsStoreErrorLogInterval)
	l.mu.Unlock()

	operations := make([]string, 0, len(failures))
	for _, failure := range failures {
		if failure.operation != "" {
			operations = append(operations, failure.operation)
		}
	}
	sort.Strings(operations)

	firstErr := ""
	if failures[0].err != nil {
		firstErr = failures[0].err.Error()
	}

	l.logger.Warn("metrics: store-derived metrics read failed",
		slog.Int("failures", len(failures)),
		slog.String("operations", strings.Join(operations, ",")),
		slog.String("error", firstErr),
	)
}

type metricsRenderSnapshot struct {
	Counters       CounterSnapshot
	BuildInfo      BuildInfo
	Runtime        goRuntimeMetrics
	Statuses       []db.FeedSyncStatus
	Jobs           []db.RefreshJob
	QueueStats     *db.QueueStatsResult
	DashboardStats *db.DashboardStatsResult
	ScanTotals     *db.ScanTotals
	DBPoolStats    *db.DBPoolStats
	SchemaVersion  uint
}

func writeMetrics(w *bufio.Writer, snapshot metricsRenderSnapshot) {
	writeProcessMetrics(w, snapshot.Counters, snapshot.SchemaVersion)
	writeBuildInfoMetrics(w, snapshot.BuildInfo)
	writeGoRuntimeMetrics(w, snapshot.Runtime)
	writeHTTPMetrics(w, snapshot.Counters.HTTPRequests)
	writeQueueSizeMetrics(w, snapshot.QueueStats)
	writeFindingMetrics(w, snapshot.DashboardStats)
	writeScanTotalsMetrics(w, snapshot.ScanTotals)
	writeDBPoolMetrics(w, snapshot.DBPoolStats)
	now := time.Now().UTC()
	writeFeedMetrics(w, snapshot.Counters.FeedSyncTimeouts, snapshot.Statuses, now)
	writeRefreshQueueMetrics(w, snapshot.Counters.QueueErrors, snapshot.Counters.QueueJobsCompleted, snapshot.Jobs, now)
}

func writeProcessMetrics(w *bufio.Writer, counters CounterSnapshot, schemaVersion uint) {
	_, _ = fmt.Fprintln(w, "# HELP packmon_auth_login_failures_total Failed admin login attempts since process start.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_auth_login_failures_total counter")
	_, _ = fmt.Fprintf(w, "packmon_auth_login_failures_total %d\n", counters.AuthLoginFailures)

	_, _ = fmt.Fprintln(w, "# HELP packmon_degraded_responses_total API responses sent with feed_status=degraded.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_degraded_responses_total counter")
	_, _ = fmt.Fprintf(w, "packmon_degraded_responses_total %d\n", counters.DegradedResponses)

	_, _ = fmt.Fprintln(w, "# HELP packmon_queue_stuck_jobs_recovered_total Queue jobs recovered from a stuck processing state.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_queue_stuck_jobs_recovered_total counter")
	_, _ = fmt.Fprintf(w, "packmon_queue_stuck_jobs_recovered_total %d\n", counters.QueueStuckRecovered)

	_, _ = fmt.Fprintln(w, "# HELP packmon_db_migration_version Current database schema version expected by the running server.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_db_migration_version gauge")
	_, _ = fmt.Fprintf(w, "packmon_db_migration_version %d\n", schemaVersion)

	writeMetricsStoreFailureMetrics(w, counters.MetricsStoreErrors)
}

func writeMetricsStoreFailureMetrics(w *bufio.Writer, failures map[string]uint64) {
	_, _ = fmt.Fprintln(w, "# HELP packmon_metrics_store_read_failures_total Store-derived metrics read failures since process start.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_metrics_store_read_failures_total counter")
	operations := make([]string, 0, len(failures))
	for operation := range failures {
		if normalizeMetricsStoreFailureOperation(operation) == "" {
			continue
		}
		operations = append(operations, operation)
	}
	sort.Strings(operations)
	for _, operation := range operations {
		_, _ = fmt.Fprintf(w, "packmon_metrics_store_read_failures_total{operation=%s} %d\n",
			prometheusLabelValue(operation),
			failures[operation],
		)
	}
}

func writeBuildInfoMetrics(w *bufio.Writer, build BuildInfo) {
	if strings.TrimSpace(build.Service) == "" {
		return
	}
	build = normalizeBuildInfo(build)
	_, _ = fmt.Fprintln(w, "# HELP packmon_build_info Running Packmon service build identity.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_build_info gauge")
	_, _ = fmt.Fprintf(w, "packmon_build_info{service=%s,version=%s,commit=%s,date=%s} 1\n",
		prometheusLabelValue(build.Service),
		prometheusLabelValue(build.Version),
		prometheusLabelValue(build.Commit),
		prometheusLabelValue(build.Date),
	)
}

func writeGoRuntimeMetrics(w *bufio.Writer, metrics goRuntimeMetrics) {
	_, _ = fmt.Fprintln(w, "# HELP packmon_go_goroutines Current number of goroutines.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_go_goroutines gauge")
	_, _ = fmt.Fprintf(w, "packmon_go_goroutines %d\n", metrics.Goroutines)

	_, _ = fmt.Fprintln(w, "# HELP packmon_go_heap_alloc_bytes Bytes of allocated heap objects.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_go_heap_alloc_bytes gauge")
	_, _ = fmt.Fprintf(w, "packmon_go_heap_alloc_bytes %d\n", metrics.HeapAllocBytes)

	_, _ = fmt.Fprintln(w, "# HELP packmon_go_heap_inuse_bytes Bytes in in-use heap spans.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_go_heap_inuse_bytes gauge")
	_, _ = fmt.Fprintf(w, "packmon_go_heap_inuse_bytes %d\n", metrics.HeapInuseBytes)

	_, _ = fmt.Fprintln(w, "# HELP packmon_go_gc_cycles_total Completed Go garbage collection cycles.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_go_gc_cycles_total counter")
	_, _ = fmt.Fprintf(w, "packmon_go_gc_cycles_total %d\n", metrics.GCCycles)

	_, _ = fmt.Fprintln(w, "# HELP packmon_go_gc_last_pause_seconds Pause duration of the most recent Go garbage collection cycle.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_go_gc_last_pause_seconds gauge")
	_, _ = fmt.Fprintf(w, "packmon_go_gc_last_pause_seconds %.9f\n", float64(metrics.LastGCPauseNanos)/float64(time.Second))
}

func writeHTTPMetrics(w *bufio.Writer, metrics map[httpMetricKey]httpMetricSnapshot) {
	httpKeys := sortedHTTPMetricKeys(metrics)
	_, _ = fmt.Fprintln(w, "# HELP packmon_http_requests_total HTTP requests handled by the main server.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_http_requests_total counter")
	for _, key := range httpKeys {
		metric := metrics[key]
		_, _ = fmt.Fprintf(w, "packmon_http_requests_total{method=%s,route=%s,status=%s} %d\n",
			prometheusLabelValue(key.Method),
			prometheusLabelValue(key.Route),
			prometheusLabelValue(key.Status),
			metric.Count,
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_http_request_duration_seconds Cumulative request duration on the main server.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_http_request_duration_seconds histogram")
	for _, key := range httpKeys {
		metric := metrics[key]
		for i, bound := range httpDurationBucketBounds {
			value := uint64(0)
			if i < len(metric.DurationBuckets) {
				value = metric.DurationBuckets[i]
			}
			_, _ = fmt.Fprintf(w, "packmon_http_request_duration_seconds_bucket{method=%s,route=%s,status=%s,le=%s} %d\n",
				prometheusLabelValue(key.Method),
				prometheusLabelValue(key.Route),
				prometheusLabelValue(key.Status),
				prometheusLabelValue(formatDurationBucketBound(bound)),
				value,
			)
		}
		_, _ = fmt.Fprintf(w, "packmon_http_request_duration_seconds_bucket{method=%s,route=%s,status=%s,le=%s} %d\n",
			prometheusLabelValue(key.Method),
			prometheusLabelValue(key.Route),
			prometheusLabelValue(key.Status),
			prometheusLabelValue("+Inf"),
			metric.Count,
		)
		_, _ = fmt.Fprintf(w, "packmon_http_request_duration_seconds_count{method=%s,route=%s,status=%s} %d\n",
			prometheusLabelValue(key.Method),
			prometheusLabelValue(key.Route),
			prometheusLabelValue(key.Status),
			metric.Count,
		)
		_, _ = fmt.Fprintf(w, "packmon_http_request_duration_seconds_sum{method=%s,route=%s,status=%s} %.9f\n",
			prometheusLabelValue(key.Method),
			prometheusLabelValue(key.Route),
			prometheusLabelValue(key.Status),
			float64(metric.DurationNanos)/float64(time.Second),
		)
	}
}

func formatDurationBucketBound(bound float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", bound), "0"), ".")
}

func writeQueueSizeMetrics(w *bufio.Writer, queueStats *db.QueueStatsResult) {
	if queueStats == nil {
		return
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_queue_size Current refresh queue size by status.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_queue_size gauge")
	_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "pending", queueStats.Pending)
	_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "processing", queueStats.Processing)
	_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "done", queueStats.Done)
	_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "error", queueStats.Error)
	_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "paused", queueStats.Paused)
}

func writeFindingMetrics(w *bufio.Writer, dashboardStats *db.DashboardStatsResult) {
	if dashboardStats == nil {
		return
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_packages_total Current unique package count in indexed findings.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_packages_total gauge")
	_, _ = fmt.Fprintf(w, "packmon_packages_total %d\n", dashboardStats.TotalPackages)

	_, _ = fmt.Fprintln(w, "# HELP packmon_findings_total Current finding count by type.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_findings_total gauge")
	_, _ = fmt.Fprintf(w, "packmon_findings_total{type=%q} %d\n", "vulnerability", dashboardStats.TotalVulnerabilities)
	_, _ = fmt.Fprintf(w, "packmon_findings_total{type=%q} %d\n", "malicious", dashboardStats.TotalMalicious)
	_, _ = fmt.Fprintf(w, "packmon_findings_total{type=%q} %d\n", "supply_chain_risk", dashboardStats.TotalSupplyChainRisk)
	_, _ = fmt.Fprintf(w, "packmon_findings_total{type=%q} %d\n", "lifecycle", dashboardStats.TotalLifecycle)

	_, _ = fmt.Fprintln(w, "# HELP packmon_findings_by_severity Current finding count by severity.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_findings_by_severity gauge")
	bySeverity := canonicalSeverityCounts(dashboardStats.BySeverity)
	severities := make([]string, 0, len(bySeverity))
	for severity := range bySeverity {
		severities = append(severities, severity)
	}
	sort.Strings(severities)
	for _, severity := range severities {
		_, _ = fmt.Fprintf(w, "packmon_findings_by_severity{severity=%s} %d\n",
			prometheusLabelValue(severity),
			bySeverity[severity],
		)
	}
}

func writeScanTotalsMetrics(w *bufio.Writer, scanTotals *db.ScanTotals) {
	if scanTotals == nil {
		return
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_packages_scanned_total Cumulative packages scanned from scan logs.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_packages_scanned_total counter")
	_, _ = fmt.Fprintf(w, "packmon_packages_scanned_total %d\n", scanTotals.PackagesScanned)

	_, _ = fmt.Fprintln(w, "# HELP packmon_scan_findings_total Cumulative findings returned in scan logs.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_scan_findings_total counter")
	_, _ = fmt.Fprintf(w, "packmon_scan_findings_total %d\n", scanTotals.Findings)
}

func writeDBPoolMetrics(w *bufio.Writer, dbPoolStats *db.DBPoolStats) {
	if dbPoolStats == nil {
		return
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_db_pool_connections PostgreSQL connection pool gauge by state.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_db_pool_connections gauge")
	_, _ = fmt.Fprintf(w, "packmon_db_pool_connections{state=%q} %d\n", "max", dbPoolStats.MaxConns)
	_, _ = fmt.Fprintf(w, "packmon_db_pool_connections{state=%q} %d\n", "acquired", dbPoolStats.AcquiredConns)
	_, _ = fmt.Fprintf(w, "packmon_db_pool_connections{state=%q} %d\n", "idle", dbPoolStats.IdleConns)
	_, _ = fmt.Fprintf(w, "packmon_db_pool_connections{state=%q} %d\n", "constructing", dbPoolStats.ConstructingConns)

	_, _ = fmt.Fprintln(w, "# HELP packmon_db_pool_acquire_total Cumulative successful PostgreSQL pool acquires.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_db_pool_acquire_total counter")
	_, _ = fmt.Fprintf(w, "packmon_db_pool_acquire_total %d\n", dbPoolStats.AcquireCount)

	_, _ = fmt.Fprintln(w, "# HELP packmon_db_pool_acquire_duration_seconds_total Cumulative duration spent acquiring PostgreSQL pool connections.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_db_pool_acquire_duration_seconds_total counter")
	_, _ = fmt.Fprintf(w, "packmon_db_pool_acquire_duration_seconds_total %.9f\n", dbPoolStats.AcquireDuration.Seconds())

	_, _ = fmt.Fprintln(w, "# HELP packmon_db_pool_canceled_acquire_total Cumulative PostgreSQL pool acquires canceled before a connection was acquired.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_db_pool_canceled_acquire_total counter")
	_, _ = fmt.Fprintf(w, "packmon_db_pool_canceled_acquire_total %d\n", dbPoolStats.CanceledAcquires)

	_, _ = fmt.Fprintln(w, "# HELP packmon_db_pool_empty_acquire_total Cumulative successful PostgreSQL pool acquires that waited because the pool was empty.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_db_pool_empty_acquire_total counter")
	_, _ = fmt.Fprintf(w, "packmon_db_pool_empty_acquire_total %d\n", dbPoolStats.EmptyAcquires)

	_, _ = fmt.Fprintln(w, "# HELP packmon_db_pool_empty_acquire_wait_seconds_total Cumulative wait time for successful PostgreSQL pool acquires when the pool was empty.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_db_pool_empty_acquire_wait_seconds_total counter")
	_, _ = fmt.Fprintf(w, "packmon_db_pool_empty_acquire_wait_seconds_total %.9f\n", dbPoolStats.EmptyAcquireWait.Seconds())
}

func writeFeedMetrics(w *bufio.Writer, feedSyncTimeouts map[string]uint64, statuses []db.FeedSyncStatus, now time.Time) {
	timeoutFeeds := unionKeys(feedSyncTimeouts, feedNames(statuses))
	sort.Strings(timeoutFeeds)

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_last_sync_timestamp Unix timestamp of the latest feed sync attempt or status heartbeat.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_last_sync_timestamp gauge")
	for _, status := range statuses {
		attemptAt := feedAttemptTimestamp(status)
		if attemptAt.IsZero() {
			continue
		}
		_, _ = fmt.Fprintf(w, "packmon_feed_last_sync_timestamp{feed=%s} %d\n",
			prometheusLabelValue(status.FeedName),
			attemptAt.UTC().Unix(),
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_entries_age_seconds Freshness proxy for feed data, derived from time since the last usable sync.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_entries_age_seconds gauge")
	for _, status := range statuses {
		if status.LastSyncAt == nil {
			continue
		}
		ageSeconds := now.Sub(status.LastSyncAt.UTC()).Seconds()
		if ageSeconds < 0 {
			ageSeconds = 0
		}
		_, _ = fmt.Fprintf(w, "packmon_feed_entries_age_seconds{feed=%s} %.0f\n",
			prometheusLabelValue(status.FeedName),
			ageSeconds,
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_sync_status Current feed sync status as one-hot gauges per canonical status.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_sync_status gauge")
	for _, status := range statuses {
		if strings.TrimSpace(status.FeedName) == "" {
			continue
		}
		current := db.NormalizeFeedSyncStatus(status.LastSyncStatus)
		if !db.IsValidFeedSyncStatus(current) {
			continue
		}
		for _, value := range db.FeedSyncStatusValues() {
			gauge := 0
			if current == value {
				gauge = 1
			}
			_, _ = fmt.Fprintf(w, "packmon_feed_sync_status{feed=%s,status=%s} %d\n",
				prometheusLabelValue(status.FeedName),
				prometheusLabelValue(value),
				gauge,
			)
		}
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_sync_timeout_total Feed sync attempts that failed due to timeouts since process start.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_sync_timeout_total counter")
	for _, feed := range timeoutFeeds {
		_, _ = fmt.Fprintf(w, "packmon_feed_sync_timeout_total{feed=%s} %d\n",
			prometheusLabelValue(feed),
			feedSyncTimeouts[feed],
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_sync_duration_seconds Duration in seconds of the latest recorded feed sync attempt.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_sync_duration_seconds gauge")
	for _, status := range statuses {
		if strings.TrimSpace(status.FeedName) == "" || status.LastSyncDuration == nil {
			continue
		}
		current := db.NormalizeFeedSyncStatus(status.LastSyncStatus)
		if !db.IsValidFeedSyncStatus(current) {
			continue
		}
		durationSeconds := status.LastSyncDuration.Seconds()
		if durationSeconds < 0 {
			durationSeconds = 0
		}
		_, _ = fmt.Fprintf(w, "packmon_feed_sync_duration_seconds{feed=%s,status=%s} %.9f\n",
			prometheusLabelValue(status.FeedName),
			prometheusLabelValue(current),
			durationSeconds,
		)
	}
}

func writeRefreshQueueMetrics(w *bufio.Writer, queueErrors map[string]uint64, queueJobsCompleted map[QueueJobCompletedKey]uint64, jobs []db.RefreshJob, now time.Time) {
	oldestBySource, activeSources := oldestQueueJobs(jobs)
	errorSources := unionKeys(queueErrors, activeSources)
	sort.Strings(errorSources)
	completedKeys := sortedQueueJobCompletedKeys(queueJobsCompleted)

	_, _ = fmt.Fprintln(w, "# HELP packmon_queue_oldest_job_seconds Age in seconds of the oldest pending or processing queue job per source.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_queue_oldest_job_seconds gauge")
	for _, source := range activeSources {
		requestedAt, ok := oldestBySource[source]
		if !ok {
			continue
		}
		ageSeconds := now.Sub(requestedAt.UTC()).Seconds()
		if ageSeconds < 0 {
			ageSeconds = 0
		}
		_, _ = fmt.Fprintf(w, "packmon_queue_oldest_job_seconds{source=%s} %.0f\n",
			prometheusLabelValue(source),
			ageSeconds,
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_queue_error_total Queue jobs that failed while being processed since process start.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_queue_error_total counter")
	for _, source := range errorSources {
		_, _ = fmt.Fprintf(w, "packmon_queue_error_total{source=%s} %d\n",
			prometheusLabelValue(source),
			queueErrors[source],
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_queue_jobs_completed_total Queue jobs completed by workers since process start.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_queue_jobs_completed_total counter")
	for _, key := range completedKeys {
		_, _ = fmt.Fprintf(w, "packmon_queue_jobs_completed_total{source=%s,result=%s} %d\n",
			prometheusLabelValue(key.Source),
			prometheusLabelValue(key.Result),
			queueJobsCompleted[key],
		)
	}
}

func normalizeQueueJobResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case QueueJobResultSuccess:
		return QueueJobResultSuccess
	case QueueJobResultError:
		return QueueJobResultError
	default:
		return ""
	}
}

func sortedQueueJobCompletedKeys(metrics map[QueueJobCompletedKey]uint64) []QueueJobCompletedKey {
	keys := make([]QueueJobCompletedKey, 0, len(metrics))
	for key := range metrics {
		if key.Source == "" || key.Result == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Source != keys[j].Source {
			return keys[i].Source < keys[j].Source
		}
		return keys[i].Result < keys[j].Result
	})
	return keys
}

func feedNames(statuses []db.FeedSyncStatus) []string {
	names := make([]string, 0, len(statuses))
	for _, status := range statuses {
		if status.FeedName == "" {
			continue
		}
		names = append(names, status.FeedName)
	}
	return names
}

func feedAttemptTimestamp(status db.FeedSyncStatus) time.Time {
	if !status.UpdatedAt.IsZero() {
		return status.UpdatedAt
	}
	if status.LastSyncAt != nil {
		return *status.LastSyncAt
	}
	return time.Time{}
}

func oldestQueueJobs(jobs []db.RefreshJob) (map[string]time.Time, []string) {
	oldest := make(map[string]time.Time)
	for _, job := range jobs {
		if job.Source == "" {
			continue
		}
		if job.Status != "pending" && job.Status != "processing" {
			continue
		}
		current, ok := oldest[job.Source]
		if !ok || job.RequestedAt.Before(current) {
			oldest[job.Source] = job.RequestedAt
		}
	}

	sources := make([]string, 0, len(oldest))
	for source := range oldest {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return oldest, sources
}

func queueJobsFromOldest(oldest map[string]time.Time) []db.RefreshJob {
	jobs := make([]db.RefreshJob, 0, len(oldest))
	for source, requestedAt := range oldest {
		if source == "" || requestedAt.IsZero() {
			continue
		}
		jobs = append(jobs, db.RefreshJob{
			Source:      source,
			Status:      "pending",
			RequestedAt: requestedAt,
		})
	}
	return jobs
}

func unionKeys(counterMap map[string]uint64, extra []string) []string {
	set := make(map[string]struct{}, len(counterMap)+len(extra))
	for key := range counterMap {
		if key != "" {
			set[key] = struct{}{}
		}
	}
	for _, key := range extra {
		if key != "" {
			set[key] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	return out
}

func canonicalSeverityCounts(raw map[string]int) map[string]int {
	out := make(map[string]int, len(raw))
	for severity, count := range raw {
		out[canonicalSeverityLabel(severity)] += count
	}
	return out
}

func canonicalSeverityLabel(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "UNKNOWN":
		return "UNKNOWN"
	default:
		return "UNKNOWN"
	}
}

func normalizeBuildInfo(info BuildInfo) BuildInfo {
	info.Service = strings.TrimSpace(info.Service)
	info.Version = strings.TrimSpace(info.Version)
	info.Commit = strings.TrimSpace(info.Commit)
	info.Date = strings.TrimSpace(info.Date)
	if info.Service == "" {
		info.Service = "packmon"
	}
	if info.Version == "" {
		info.Version = "unknown"
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.Date == "" {
		info.Date = "unknown"
	}
	return info
}

func collectGoRuntimeMetrics() goRuntimeMetrics {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var lastPause uint64
	if mem.NumGC > 0 {
		lastPause = mem.PauseNs[(mem.NumGC+255)%uint32(len(mem.PauseNs))]
	}

	return goRuntimeMetrics{
		Goroutines:       runtime.NumGoroutine(),
		HeapAllocBytes:   mem.HeapAlloc,
		HeapInuseBytes:   mem.HeapInuse,
		GCCycles:         mem.NumGC,
		LastGCPauseNanos: lastPause,
	}
}

func sortedHTTPMetricKeys(metrics map[httpMetricKey]httpMetricSnapshot) []httpMetricKey {
	keys := make([]httpMetricKey, 0, len(metrics))
	for key := range metrics {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Route != keys[j].Route {
			return keys[i].Route < keys[j].Route
		}
		if keys[i].Method != keys[j].Method {
			return keys[i].Method < keys[j].Method
		}
		return keys[i].Status < keys[j].Status
	})
	return keys
}

func escapeLabelValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	return replacer.Replace(value)
}

func prometheusLabelValue(value string) string {
	return `"` + escapeLabelValue(value) + `"`
}
