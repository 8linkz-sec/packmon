package telemetry

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
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

	mu               sync.RWMutex
	feedSyncTimeouts map[string]*atomic.Uint64
	queueErrors      map[string]*atomic.Uint64
	httpRequests     map[httpMetricKey]*httpMetricCounters
}

// CounterSnapshot is a copy-on-read view of all in-memory counters.
type CounterSnapshot struct {
	AuthLoginFailures   uint64
	DegradedResponses   uint64
	QueueStuckRecovered uint64
	FeedSyncTimeouts    map[string]uint64
	QueueErrors         map[string]uint64
	HTTPRequests        map[httpMetricKey]httpMetricSnapshot
}

const (
	metricsStoreTimeout          = 2 * time.Second
	metricsDerivedCacheTTL       = 30 * time.Second
	metricsStoreErrorLogInterval = 30 * time.Second
)

var defaultRegistry = NewRegistry()

type httpMetricKey struct {
	Method string
	Route  string
	Status string
}

type httpMetricCounters struct {
	count         atomic.Uint64
	durationNanos atomic.Uint64
}

type httpMetricSnapshot struct {
	Count         uint64
	DurationNanos uint64
}

// Default returns the process-wide telemetry registry.
func Default() *Registry {
	return defaultRegistry
}

// NewRegistry creates an empty telemetry registry.
func NewRegistry() *Registry {
	return &Registry{
		feedSyncTimeouts: make(map[string]*atomic.Uint64),
		queueErrors:      make(map[string]*atomic.Uint64),
		httpRequests:     make(map[httpMetricKey]*httpMetricCounters),
	}
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

	counter = &httpMetricCounters{}
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
		HTTPRequests:        make(map[httpMetricKey]httpMetricSnapshot),
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for feed, counter := range r.feedSyncTimeouts {
		snapshot.FeedSyncTimeouts[feed] = counter.Load()
	}
	for source, counter := range r.queueErrors {
		snapshot.QueueErrors[source] = counter.Load()
	}
	for key, counter := range r.httpRequests {
		snapshot.HTTPRequests[key] = httpMetricSnapshot{
			Count:         counter.count.Load(),
			DurationNanos: counter.durationNanos.Load(),
		}
	}

	return snapshot
}

type scanTotalsProvider interface {
	ScanTotals(ctx context.Context) (*db.ScanTotals, error)
}

type queueOldestProvider interface {
	OldestQueueJobs(ctx context.Context) (map[string]time.Time, error)
}

type dbPoolStatsProvider interface {
	DBPoolStats() db.DBPoolStats
}

type metricsStoreFailure struct {
	operation string
	err       error
}

type metricsDerivedCache struct {
	mu             sync.Mutex
	expiresAt      time.Time
	dashboardStats *db.DashboardStatsResult
	scanTotals     *db.ScanTotals
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

// MetricsHandler renders a Prometheus-compatible plaintext metrics response
// using the process-wide telemetry registry.
func MetricsHandler(store db.Store, schemaVersion uint, logger *slog.Logger) http.HandlerFunc {
	return MetricsHandlerWithRegistry(Default(), store, schemaVersion, logger)
}

// MetricsHandlerWithRegistry renders a Prometheus-compatible plaintext metrics
// response using the supplied in-process telemetry registry. A failing store
// read does not fail the response; failures are collapsed into a bounded WARN so
// repeated scrapes during an outage do not produce one warning per failed query.
func MetricsHandlerWithRegistry(registry *Registry, store db.Store, schemaVersion uint, logger *slog.Logger) http.HandlerFunc {
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

		var failures []metricsStoreFailure

		var statuses []db.FeedSyncStatus
		var jobs []db.RefreshJob
		var queueStats *db.QueueStatsResult
		var dashboardStats *db.DashboardStatsResult
		var scanTotals *db.ScanTotals
		var dbPoolStats *db.DBPoolStats

		if store != nil {
			var err error
			statuses, err = store.ListFeedSyncStatuses(storeCtx)
			if err != nil {
				failures = appendMetricStoreFailure(failures, "feed_sync_statuses", err)
			}
			if provider, ok := store.(queueOldestProvider); ok {
				oldest, oerr := provider.OldestQueueJobs(storeCtx)
				if oerr != nil {
					failures = appendMetricStoreFailure(failures, "oldest_queue_jobs", oerr)
				} else {
					jobs = queueJobsFromOldest(oldest)
				}
			} else {
				var jerr error
				jobs, jerr = store.ListQueueJobs(storeCtx, "", 1000)
				if jerr != nil {
					failures = appendMetricStoreFailure(failures, "queue_jobs", jerr)
				}
			}
			queueStats, err = store.QueueStats(storeCtx)
			if err != nil {
				failures = appendMetricStoreFailure(failures, "queue_stats", err)
			}

			var derivedFailures []metricsStoreFailure
			dashboardStats, scanTotals, derivedFailures = derivedCache.load(storeCtx, store)
			failures = append(failures, derivedFailures...)

			if provider, ok := store.(dbPoolStatsProvider); ok {
				stats := provider.DBPoolStats()
				dbPoolStats = &stats
			}
		}

		errorLogger.log(failures)

		writer := bufio.NewWriter(w)
		writeMetrics(writer, registry.Snapshot(), statuses, jobs, queueStats, dashboardStats, scanTotals, dbPoolStats, schemaVersion)
		_ = writer.Flush()
	}
}

func (c *metricsDerivedCache) load(ctx context.Context, store db.Store) (*db.DashboardStatsResult, *db.ScanTotals, []metricsStoreFailure) {
	now := time.Now()

	c.mu.Lock()
	if c.expiresAt.After(now) {
		dashboardStats := cloneDashboardStats(c.dashboardStats)
		scanTotals := cloneScanTotals(c.scanTotals)
		c.mu.Unlock()
		return dashboardStats, scanTotals, nil
	}
	c.mu.Unlock()

	var failures []metricsStoreFailure
	dashboardStats, err := store.DashboardStats(ctx)
	if err != nil {
		failures = appendMetricStoreFailure(failures, "dashboard_stats", err)
	}

	var scanTotals *db.ScanTotals
	if provider, ok := store.(scanTotalsProvider); ok {
		totals, terr := provider.ScanTotals(ctx)
		if terr != nil {
			failures = appendMetricStoreFailure(failures, "scan_totals", terr)
		} else {
			scanTotals = totals
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.dashboardStats = cloneDashboardStats(dashboardStats)
	}
	if scanTotals != nil {
		c.scanTotals = cloneScanTotals(scanTotals)
	}
	c.expiresAt = now.Add(metricsDerivedCacheTTL)

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

func writeMetrics(w *bufio.Writer, counters CounterSnapshot, statuses []db.FeedSyncStatus, jobs []db.RefreshJob, queueStats *db.QueueStatsResult, dashboardStats *db.DashboardStatsResult, scanTotals *db.ScanTotals, dbPoolStats *db.DBPoolStats, schemaVersion uint) {
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

	httpKeys := sortedHTTPMetricKeys(counters.HTTPRequests)
	_, _ = fmt.Fprintln(w, "# HELP packmon_http_requests_total HTTP requests handled by the main server.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_http_requests_total counter")
	for _, key := range httpKeys {
		metric := counters.HTTPRequests[key]
		_, _ = fmt.Fprintf(w, "packmon_http_requests_total{method=%s,route=%s,status=%s} %d\n",
			prometheusLabelValue(key.Method),
			prometheusLabelValue(key.Route),
			prometheusLabelValue(key.Status),
			metric.Count,
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_http_request_duration_seconds Cumulative request duration on the main server.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_http_request_duration_seconds summary")
	for _, key := range httpKeys {
		metric := counters.HTTPRequests[key]
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

	if queueStats != nil {
		_, _ = fmt.Fprintln(w, "# HELP packmon_queue_size Current refresh queue size by status.")
		_, _ = fmt.Fprintln(w, "# TYPE packmon_queue_size gauge")
		_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "pending", queueStats.Pending)
		_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "processing", queueStats.Processing)
		_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "done", queueStats.Done)
		_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "error", queueStats.Error)
		_, _ = fmt.Fprintf(w, "packmon_queue_size{status=%q} %d\n", "paused", queueStats.Paused)
	}

	if dashboardStats != nil {
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

	if scanTotals != nil {
		_, _ = fmt.Fprintln(w, "# HELP packmon_packages_scanned_total Cumulative packages scanned from scan logs.")
		_, _ = fmt.Fprintln(w, "# TYPE packmon_packages_scanned_total counter")
		_, _ = fmt.Fprintf(w, "packmon_packages_scanned_total %d\n", scanTotals.PackagesScanned)

		_, _ = fmt.Fprintln(w, "# HELP packmon_scan_findings_total Cumulative findings returned in scan logs.")
		_, _ = fmt.Fprintln(w, "# TYPE packmon_scan_findings_total counter")
		_, _ = fmt.Fprintf(w, "packmon_scan_findings_total %d\n", scanTotals.Findings)
	}

	if dbPoolStats != nil {
		_, _ = fmt.Fprintln(w, "# HELP packmon_db_pool_connections PostgreSQL connection pool gauge by state.")
		_, _ = fmt.Fprintln(w, "# TYPE packmon_db_pool_connections gauge")
		_, _ = fmt.Fprintf(w, "packmon_db_pool_connections{state=%q} %d\n", "max", dbPoolStats.MaxConns)
		_, _ = fmt.Fprintf(w, "packmon_db_pool_connections{state=%q} %d\n", "acquired", dbPoolStats.AcquiredConns)
		_, _ = fmt.Fprintf(w, "packmon_db_pool_connections{state=%q} %d\n", "idle", dbPoolStats.IdleConns)
		_, _ = fmt.Fprintf(w, "packmon_db_pool_connections{state=%q} %d\n", "constructing", dbPoolStats.ConstructingConns)
	}

	now := time.Now().UTC()
	timeoutFeeds := unionKeys(counters.FeedSyncTimeouts, feedNames(statuses))
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

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_sync_timeout_total Feed sync attempts that failed due to timeouts since process start.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_sync_timeout_total counter")
	for _, feed := range timeoutFeeds {
		_, _ = fmt.Fprintf(w, "packmon_feed_sync_timeout_total{feed=%s} %d\n",
			prometheusLabelValue(feed),
			counters.FeedSyncTimeouts[feed],
		)
	}

	oldestBySource, activeSources := oldestQueueJobs(jobs)
	errorSources := unionKeys(counters.QueueErrors, activeSources)
	sort.Strings(errorSources)

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
			counters.QueueErrors[source],
		)
	}
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
