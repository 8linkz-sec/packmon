package telemetry

import (
	"bufio"
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
		"packmon_db_migration_version 1",
	} {
		if !strings.Contains(output, metric) {
			t.Fatalf("metrics output missing %q\n%s", metric, output)
		}
	}
}

func ptrTime(t time.Time) *time.Time {
	return &t
}
