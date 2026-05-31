package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
)

func TestAdminFeedRowsMergeRuntimeConfigAndStoreStatus(t *testing.T) {
	t.Parallel()

	lastSync := time.Now().Add(-time.Hour)
	duration := 1500 * time.Millisecond
	cfg := &config.Config{
		FeedSync: config.FeedSyncConfig{Interval: 6 * time.Hour},
		Feeds: config.FeedsConfig{
			OSVEnabled:        true,
			OSVMode:           config.FeedModeSelf,
			OSVInterval:       2 * time.Hour,
			VulnCheckEnabled:  true,
			VulnCheckMode:     config.FeedModeSelf,
			OpenSSFMode:       config.FeedModeSelf,
			GHSAMode:          config.FeedModeSelf,
			CISAKEVMode:       config.FeedModeSelf,
			EPSSMode:          config.FeedModeSelf,
			NVDMode:           config.FeedModeSelf,
			SocketMode:        config.FeedModeSelf,
			ReversingLabsMode: config.FeedModeSelf,
		},
	}
	handler := &AdminHandler{cfg: cfg}

	rows := handler.adminFeedRows([]db.FeedSyncStatus{
		{
			FeedName:         "OSV",
			LastSyncAt:       &lastSync,
			LastSyncDuration: &duration,
			LastSyncStatus:   "success",
			EntriesSynced:    3,
			EntriesTotal:     4,
		},
		{
			FeedName:       "custom-feed",
			LastSyncStatus: "skipped",
		},
	})

	osv := findAdminFeedRow(t, rows, "osv")
	if osv.Status != "healthy" || osv.ConfigMode != "self" || osv.SyncIntervalStr != "2h (override)" {
		t.Fatalf("osv row = %+v", osv)
	}
	if osv.DurationStr != "1.5s" || osv.EntriesSynced != 3 || osv.EntriesTotal != 4 {
		t.Fatalf("osv status fields = %+v", osv)
	}

	vulncheck := findAdminFeedRow(t, rows, "vulncheck")
	if vulncheck.APIKeyState != "missing" || vulncheck.Status != "warning" {
		t.Fatalf("vulncheck row = %+v", vulncheck)
	}

	custom := findAdminFeedRow(t, rows, "custom-feed")
	if custom.FeedName != "CUSTOM-FEED" || custom.Status != "pending" {
		t.Fatalf("custom status row = %+v", custom)
	}
}

func TestAdminFeedFormRowsReflectOverridesAndRestartState(t *testing.T) {
	t.Parallel()

	overrideUpdatedAt := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	overrideInterval := 30 * time.Minute
	cfg := &config.Config{
		FeedSync: config.FeedSyncConfig{Interval: 6 * time.Hour},
		Feeds: config.FeedsConfig{
			VulnCheckEnabled: true,
			VulnCheckMode:    config.FeedModeSelf,
			VulnCheckAPIKey:  "runtime-key",
			OSVEnabled:       true,
			OSVMode:          config.FeedModeSelf,
		},
	}
	handler := &AdminHandler{cfg: cfg}

	rows := handler.adminFeedFormRows([]db.FeedConfig{
		{
			FeedName:     "vulncheck",
			Enabled:      false,
			Mode:         "external",
			SyncInterval: &overrideInterval,
			APIKey:       "override-key",
			UpdatedAt:    overrideUpdatedAt,
		},
	})

	vulncheck := findAdminFeedFormRow(t, rows, "vulncheck")
	if !vulncheck.OverrideActive || !vulncheck.PendingRestart || !vulncheck.HasUpdatedAt {
		t.Fatalf("override state not reflected: %+v", vulncheck)
	}
	if vulncheck.Enabled || vulncheck.Mode != "external" || vulncheck.SyncInterval != "30m" {
		t.Fatalf("override values not reflected: %+v", vulncheck)
	}
	if !vulncheck.APIKeyConfigured || !vulncheck.RuntimeAPIKeyConfigured {
		t.Fatalf("api key state not reflected: %+v", vulncheck)
	}
	if !strings.Contains(vulncheck.SyncIntervalHelp, "Ignored while mode is external") {
		t.Fatalf("sync interval help = %q", vulncheck.SyncIntervalHelp)
	}

	osv := findAdminFeedFormRow(t, rows, "osv")
	if osv.OverrideActive || osv.PendingRestart {
		t.Fatalf("osv should have no override: %+v", osv)
	}
}

func TestRuntimeConfigFormattingHelpers(t *testing.T) {
	t.Parallel()

	if got := runtimeAPIKeyState(config.FeedSettings{RequiresAPIKey: true, Enabled: true}); got != "missing" {
		t.Fatalf("runtimeAPIKeyState(missing enabled) = %q", got)
	}
	if got := runtimeAPIKeyState(config.FeedSettings{RequiresAPIKey: true}); got != "not configured" {
		t.Fatalf("runtimeAPIKeyState(missing disabled) = %q", got)
	}
	if got := runtimeAPIKeyState(config.FeedSettings{APIKey: "key"}); got != "configured" {
		t.Fatalf("runtimeAPIKeyState(configured) = %q", got)
	}
	if got := runtimeAPIKeyState(config.FeedSettings{}); got != "not required" {
		t.Fatalf("runtimeAPIKeyState(not required) = %q", got)
	}

	for _, tt := range []struct {
		duration time.Duration
		want     string
	}{
		{0, "0s"},
		{2 * time.Hour, "2h"},
		{15 * time.Minute, "15m"},
		{90 * time.Second, "1m30s"},
	} {
		if got := formatRuntimeDuration(tt.duration); got != tt.want {
			t.Fatalf("formatRuntimeDuration(%v) = %q, want %q", tt.duration, got, tt.want)
		}
	}
	if got := formatOptionalDuration(0); got != "" {
		t.Fatalf("formatOptionalDuration(0) = %q", got)
	}
	if supportsManualFeedSync("socket") {
		t.Fatal("supportsManualFeedSync(socket) = true")
	}
	if !supportsManualFeedSync("osv") {
		t.Fatal("supportsManualFeedSync(osv) = false")
	}
	if got := statusOrNil(false, db.FeedSyncStatus{}); got != nil {
		t.Fatalf("statusOrNil(false) = %+v", got)
	}
}

func findAdminFeedRow(t *testing.T, rows []adminFeedRow, key string) adminFeedRow {
	t.Helper()
	for _, row := range rows {
		if row.FeedKey == key {
			return row
		}
	}
	t.Fatalf("feed row %q not found in %+v", key, rows)
	return adminFeedRow{}
}

func findAdminFeedFormRow(t *testing.T, rows []adminFeedFormRow, key string) adminFeedFormRow {
	t.Helper()
	for _, row := range rows {
		if row.FeedKey == key {
			return row
		}
	}
	t.Fatalf("feed form row %q not found in %+v", key, rows)
	return adminFeedFormRow{}
}
