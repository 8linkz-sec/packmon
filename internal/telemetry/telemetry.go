package telemetry

import (
	"bufio"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/8linkz/packmon/internal/db"
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
}

// CounterSnapshot is a copy-on-read view of all in-memory counters.
type CounterSnapshot struct {
	AuthLoginFailures   uint64
	DegradedResponses   uint64
	QueueStuckRecovered uint64
	FeedSyncTimeouts    map[string]uint64
	QueueErrors         map[string]uint64
}

var defaultRegistry = NewRegistry()

// Default returns the process-wide telemetry registry.
func Default() *Registry {
	return defaultRegistry
}

// NewRegistry creates an empty telemetry registry.
func NewRegistry() *Registry {
	return &Registry{
		feedSyncTimeouts: make(map[string]*atomic.Uint64),
		queueErrors:      make(map[string]*atomic.Uint64),
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

// Snapshot returns a stable copy of all in-memory counters.
func (r *Registry) Snapshot() CounterSnapshot {
	snapshot := CounterSnapshot{
		AuthLoginFailures:   r.authLoginFailures.Load(),
		DegradedResponses:   r.degradedResponses.Load(),
		QueueStuckRecovered: r.queueStuckRecovered.Load(),
		FeedSyncTimeouts:    make(map[string]uint64),
		QueueErrors:         make(map[string]uint64),
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for feed, counter := range r.feedSyncTimeouts {
		snapshot.FeedSyncTimeouts[feed] = counter.Load()
	}
	for source, counter := range r.queueErrors {
		snapshot.QueueErrors[source] = counter.Load()
	}

	return snapshot
}

// MetricsHandler renders a Prometheus-compatible plaintext metrics response.
func MetricsHandler(store db.Store, schemaVersion uint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		statuses, _ := store.ListFeedSyncStatuses(r.Context())
		jobs, _ := store.ListQueueJobs(r.Context(), "", 1000)

		writer := bufio.NewWriter(w)
		writeMetrics(writer, Default().Snapshot(), statuses, jobs, schemaVersion)
		_ = writer.Flush()
	}
}

func writeMetrics(w *bufio.Writer, counters CounterSnapshot, statuses []db.FeedSyncStatus, jobs []db.RefreshJob, schemaVersion uint) {
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

	now := time.Now().UTC()
	timeoutFeeds := unionKeys(counters.FeedSyncTimeouts, feedNames(statuses))
	sort.Strings(timeoutFeeds)

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_last_sync_timestamp Unix timestamp of the last successful or attempted feed sync.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_last_sync_timestamp gauge")
	for _, status := range statuses {
		if status.LastSyncAt == nil {
			continue
		}
		_, _ = fmt.Fprintf(w, "packmon_feed_last_sync_timestamp{feed=%q} %d\n",
			escapeLabelValue(status.FeedName),
			status.LastSyncAt.UTC().Unix(),
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_entries_age_seconds Freshness proxy for feed data, derived from time since the last sync.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_entries_age_seconds gauge")
	for _, status := range statuses {
		if status.LastSyncAt == nil {
			continue
		}
		ageSeconds := now.Sub(status.LastSyncAt.UTC()).Seconds()
		if ageSeconds < 0 {
			ageSeconds = 0
		}
		_, _ = fmt.Fprintf(w, "packmon_feed_entries_age_seconds{feed=%q} %.0f\n",
			escapeLabelValue(status.FeedName),
			ageSeconds,
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_feed_sync_timeout_total Feed sync attempts that failed due to timeouts since process start.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_feed_sync_timeout_total counter")
	for _, feed := range timeoutFeeds {
		_, _ = fmt.Fprintf(w, "packmon_feed_sync_timeout_total{feed=%q} %d\n",
			escapeLabelValue(feed),
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
		_, _ = fmt.Fprintf(w, "packmon_queue_oldest_job_seconds{source=%q} %.0f\n",
			escapeLabelValue(source),
			ageSeconds,
		)
	}

	_, _ = fmt.Fprintln(w, "# HELP packmon_queue_error_total Queue jobs that failed while being processed since process start.")
	_, _ = fmt.Fprintln(w, "# TYPE packmon_queue_error_total counter")
	for _, source := range errorSources {
		_, _ = fmt.Fprintf(w, "packmon_queue_error_total{source=%q} %d\n",
			escapeLabelValue(source),
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

func escapeLabelValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	return replacer.Replace(value)
}
