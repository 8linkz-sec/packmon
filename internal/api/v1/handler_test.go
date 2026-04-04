package v1

import (
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

func TestOverallFeedStatus(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name     string
		statuses []db.FeedSyncStatus
		want     string
	}{
		{
			name: "no statuses default degraded",
			want: "degraded",
		},
		{
			name: "all feeds healthy",
			statuses: []db.FeedSyncStatus{
				{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-2 * time.Hour))},
				{FeedName: "ghsa", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-3 * time.Hour))},
			},
			want: "healthy",
		},
		{
			name: "stale feed degrades response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "osv", LastSyncStatus: "success", LastSyncAt: ptrFeedTime(now.Add(-72 * time.Hour))},
			},
			want: "degraded",
		},
		{
			name: "errored feed degrades response",
			statuses: []db.FeedSyncStatus{
				{FeedName: "socket", LastSyncStatus: "error", LastSyncAt: ptrFeedTime(now.Add(-30 * time.Minute))},
			},
			want: "degraded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := overallFeedStatus(tt.statuses); got != tt.want {
				t.Fatalf("overallFeedStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func ptrFeedTime(t time.Time) *time.Time {
	return &t
}
