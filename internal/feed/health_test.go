package feed

import (
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestFeedStatusHealthBranches(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Hour)
	old := now.Add(-49 * time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name   string
		in     db.FeedSyncStatus
		want   string
		reason string
	}{
		{name: "error", in: db.FeedSyncStatus{LastSyncStatus: "error"}, want: "error", reason: "last sync failed"},
		{name: "permanent error", in: db.FeedSyncStatus{LastSyncStatus: "permanent_error"}, want: "error", reason: "permanent feed error"},
		{name: "disabled", in: db.FeedSyncStatus{LastSyncStatus: "disabled"}, want: "disabled", reason: "feed disabled"},
		{name: "external", in: db.FeedSyncStatus{LastSyncStatus: "external"}, want: "configured", reason: "external feed managed outside Packmon"},
		{name: "running", in: db.FeedSyncStatus{LastSyncStatus: "running"}, want: "pending", reason: "sync running"},
		{name: "pending", in: db.FeedSyncStatus{LastSyncStatus: "pending"}, want: "pending", reason: "sync pending"},
		{name: "skipped", in: db.FeedSyncStatus{LastSyncStatus: "skipped"}, want: "warning", reason: "last sync skipped"},
		{name: "unknown", in: db.FeedSyncStatus{LastSyncStatus: "failed"}, want: "error", reason: "unknown feed status: failed"},
		{name: "never", in: db.FeedSyncStatus{LastSyncStatus: "success"}, want: "error", reason: "never synced"},
		{name: "future", in: db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &future, EntriesTotal: 1}, want: "warning", reason: "last sync timestamp is in the future"},
		{name: "stale", in: db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &old, EntriesTotal: 1}, want: "warning", reason: "stale: no sync in 48h+"},
		{name: "zero entries", in: db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &recent}, want: "warning", reason: "no entries synced yet"},
		{name: "healthy", in: db.FeedSyncStatus{LastSyncStatus: "success", LastSyncAt: &recent, EntriesTotal: 1}, want: "healthy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FeedStatusHealth(tt.in, HealthOptions{Now: now})
			if got.Status != tt.want || got.Reason != tt.reason {
				t.Fatalf("FeedStatusHealth() = %+v, want status %q reason %q", got, tt.want, tt.reason)
			}
		})
	}
}

func TestOverallFeedStatusAndFreshEntriesUseLastUsableSync(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Hour)
	old := now.Add(-72 * time.Hour)
	future := now.Add(time.Hour)

	if got := OverallFeedStatus(nil, HealthOptions{Now: now}); got != "degraded" {
		t.Fatalf("OverallFeedStatus(nil) = %q, want degraded", got)
	}
	if got := OverallFeedStatus([]db.FeedSyncStatus{{FeedName: "ghsa", LastSyncStatus: "external"}}, HealthOptions{Now: now}); got != "healthy" {
		t.Fatalf("OverallFeedStatus(external only) = %q, want healthy", got)
	}
	if got := OverallFeedStatus([]db.FeedSyncStatus{{FeedName: "vulncheck", LastSyncStatus: "disabled"}}, HealthOptions{Now: now}); got != "degraded" {
		t.Fatalf("OverallFeedStatus(disabled only) = %q, want degraded", got)
	}
	if got := OverallFeedStatus([]db.FeedSyncStatus{{FeedName: "nvd", LastSyncStatus: "running", LastSyncAt: &recent, EntriesTotal: 1}}, HealthOptions{Now: now}); got != "healthy" {
		t.Fatalf("OverallFeedStatus(running fresh data) = %q, want healthy", got)
	}
	if got := OverallFeedStatus([]db.FeedSyncStatus{{FeedName: "nvd", LastSyncStatus: "running", LastSyncAt: &old, EntriesTotal: 1}}, HealthOptions{Now: now}); got != "degraded" {
		t.Fatalf("OverallFeedStatus(running stale data) = %q, want degraded", got)
	}
	if HasFreshFeedEntries(db.FeedSyncStatus{LastSyncAt: &future, EntriesTotal: 1}, HealthOptions{Now: now}) {
		t.Fatal("HasFreshFeedEntries(future timestamp) = true, want false")
	}
}

func TestRuntimeFeedHealthWithoutStatusRows(t *testing.T) {
	tests := []struct {
		name string
		cfg  RuntimeHealthConfig
		want string
	}{
		{name: "disabled", cfg: RuntimeHealthConfig{Enabled: false, SupportsSyncInterval: true}, want: "disabled"},
		{name: "external", cfg: RuntimeHealthConfig{Enabled: true, Mode: FeedModeExternal, SupportsSyncInterval: true}, want: "configured"},
		{name: "missing api key", cfg: RuntimeHealthConfig{Enabled: true, RequiresAPIKey: true, SupportsSyncInterval: true}, want: "warning"},
		{name: "no interval support", cfg: RuntimeHealthConfig{Enabled: true}, want: "configured"},
		{name: "enabled scheduled", cfg: RuntimeHealthConfig{Enabled: true, SupportsSyncInterval: true}, want: "pending"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RuntimeFeedHealth(tt.cfg, nil, HealthOptions{}).Status; got != tt.want {
				t.Fatalf("RuntimeFeedHealth() = %q, want %q", got, tt.want)
			}
		})
	}
}
