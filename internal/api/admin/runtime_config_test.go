package admin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

func TestAdminFeedRowsMergeRuntimeConfigAndStoreStatus(t *testing.T) {
	t.Parallel()

	lastSync := time.Now().Add(-time.Hour)
	duration := 1500 * time.Millisecond
	lastError := `GET https://user-secret:pass-secret@downloads.example.test/backups/feed.tar.gz?X-Amz-Signature=query-secret failed with Authorization: Bearer bearer-secret-token from C:\Users\Admin\Packmon\feed.json` //nolint:gosec // fake secret-bearing diagnostic verifies redaction.
	cfg := &config.Config{
		FeedSync: config.FeedSyncConfig{Interval: 6 * time.Hour},
		Feeds: config.FeedsConfig{
			OSVEnabled:        true,
			OSVMode:           config.FeedModeSelf,
			OSVInterval:       2 * time.Hour,
			VulnCheckEnabled:  true,
			VulnCheckMode:     config.FeedModeSelf,
			OpenSSFMode:       config.FeedModeSelf,
			GHSAEnabled:       true,
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
			LastError:      lastError,
		},
		{
			FeedName:       "ghsa",
			LastSyncStatus: "rejected",
			LastError:      "vulnerability import cvss_score must be between 0 and 10",
			EntriesSynced:  0,
			EntriesTotal:   2,
			Metadata:       json.RawMessage(`{"rejected_count":2,"client_ip":"192.0.2.10","api_key_id":77,"api_key_name":"n8n-import","correlation_id":"corr-reject"}`),
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
	if vulncheck.APIKeyState != "missing" || vulncheck.Status != "warning" || vulncheck.StatusReason() != "required API key not configured" {
		t.Fatalf("vulncheck row = %+v", vulncheck)
	}

	custom := findAdminFeedRow(t, rows, "custom-feed")
	if custom.FeedName != "CUSTOM-FEED" || custom.Status != "warning" {
		t.Fatalf("custom status row = %+v", custom)
	}
	for _, leaked := range []string{"user-secret", "pass-secret", "feed.tar.gz", "query-secret", "bearer-secret-token", `C:\Users\Admin\Packmon\feed.json`} {
		if strings.Contains(custom.LastError, leaked) {
			t.Fatalf("custom LastError leaked %q in %q", leaked, custom.LastError)
		}
	}
	if !strings.Contains(custom.LastError, "https://downloads.example.test/...") || !strings.Contains(custom.LastError, "Bearer [redacted]") {
		t.Fatalf("custom LastError missing redacted context: %q", custom.LastError)
	}

	ghsa := findAdminFeedRow(t, rows, "ghsa")
	if ghsa.Status != "error" || ghsa.RejectedCount != 2 || ghsa.LastSyncStatus != "rejected" {
		t.Fatalf("ghsa rejected row = %+v", ghsa)
	}
	if ghsa.RejectedClientIP != "192.0.2.10" || ghsa.RejectedAPIKeyID != 77 || ghsa.RejectedAPIKeyName != "n8n-import" || ghsa.RejectedCorrelationID != "corr-reject" {
		t.Fatalf("ghsa rejected attribution = %+v", ghsa)
	}
}

func TestAdminFeedFormRowsReflectOverridesAndRestartState(t *testing.T) {
	t.Parallel()

	overrideUpdatedAt := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	overrideInterval := 30 * time.Minute
	cfg := &config.Config{
		FeedSync: config.FeedSyncConfig{Interval: 6 * time.Hour},
		Feeds: config.FeedsConfig{
			VulnCheckEnabled:  true,
			VulnCheckMode:     config.FeedModeSelf,
			VulnCheckAPIKey:   "runtime-key",
			OSVEnabled:        true,
			OSVMode:           config.FeedModeSelf,
			NVDMode:           config.FeedModeSelf,
			EndOfLifeMode:     config.FeedModeSelf,
			ReversingLabsMode: config.FeedModeSelf,
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
	if vulncheck.CanSyncNow {
		t.Fatalf("vulncheck CanSyncNow = true, want false for disabled external override")
	}
	if !strings.Contains(vulncheck.SyncIntervalHelp, "Ignored while mode is external") {
		t.Fatalf("sync interval help = %q", vulncheck.SyncIntervalHelp)
	}
	requireFeedModeOptions(t, vulncheck.ModeOptions, config.FeedModeSelf, config.FeedModeExternal)

	osv := findAdminFeedFormRow(t, rows, "osv")
	if osv.OverrideActive || osv.PendingRestart {
		t.Fatalf("osv should have no override: %+v", osv)
	}
	if !osv.CanSyncNow {
		t.Fatalf("osv CanSyncNow = false, want true for enabled self-mode feed")
	}

	for _, key := range []string{"nvd", "endoflife", "reversinglabs"} {
		row := findAdminFeedFormRow(t, rows, key)
		if row.SupportsExternalMode {
			t.Fatalf("%s SupportsExternalMode = true, want false", key)
		}
	}
	nvd := findAdminFeedFormRow(t, rows, "nvd")
	if !nvd.SupportsAPIKey || nvd.RequiresAPIKey || nvd.APIKeyConfigured {
		t.Fatalf("nvd API-key state = supports:%v requires:%v configured:%v, want optional unconfigured key", nvd.SupportsAPIKey, nvd.RequiresAPIKey, nvd.APIKeyConfigured)
	}
	requireFeedModeOptions(t, nvd.ModeOptions, config.FeedModeSelf)
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

func requireFeedModeOptions(t *testing.T, got []config.FeedModeOption, want ...config.FeedMode) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ModeOptions = %+v, want %v", got, want)
	}
	for i, mode := range want {
		if got[i].Value != mode || got[i].Label != string(mode) {
			t.Fatalf("ModeOptions[%d] = %+v, want value/label %q", i, got[i], mode)
		}
	}
}
