package admin

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

func TestAdminFeedRunningStatusTimingBoundaries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		lastSync := now.Add(-9 * time.Hour)
		feed := config.FeedSettings{Name: "osv", DisplayName: "OSV", Enabled: true, Mode: config.FeedModeSelf}

		tests := []struct {
			name   string
			status db.FeedSyncStatus
			want   string
		}{
			{
				name: "updated at takes precedence",
				status: db.FeedSyncStatus{
					LastSyncStatus: db.FeedSyncStatusRunning,
					LastSyncAt:     &lastSync,
					UpdatedAt:      now.Add(-2 * time.Minute),
				},
				want: "running for 2m0s",
			},
			{
				name: "last sync is the fallback",
				status: db.FeedSyncStatus{
					LastSyncStatus: db.FeedSyncStatusRunning,
					LastSyncAt:     func() *time.Time { value := now.Add(-3 * time.Minute); return &value }(),
				},
				want: "running for 3m0s",
			},
			{
				name:   "no timestamps leaves duration empty",
				status: db.FeedSyncStatus{LastSyncStatus: db.FeedSyncStatusRunning},
				want:   "",
			},
			{
				name: "future start is clamped",
				status: db.FeedSyncStatus{
					LastSyncStatus: db.FeedSyncStatusRunning,
					UpdatedAt:      now.Add(time.Hour),
				},
				want: "running for 0s",
			},
		}

		for _, tt := range tests {
			row := buildAdminFeedRow(nil, feed, true, tt.status)
			if row.DurationStr != tt.want {
				t.Errorf("%s: DurationStr = %q, want %q", tt.name, row.DurationStr, tt.want)
			}
		}
	})
}

func TestAdminFeedPresentationFallbacksAndClasses(t *testing.T) {
	t.Parallel()

	if got := (adminFeedFormRow{OverrideActive: true}).OverrideClass(); got != "pm-badge-status-configured" {
		t.Fatalf("active OverrideClass = %q", got)
	}
	if got := (adminFeedFormRow{}).OverrideClass(); got != "pm-badge-status-default" {
		t.Fatalf("default OverrideClass = %q", got)
	}
	if got := (adminFeedFormRow{PendingRestart: true}).RuntimeMatchClass(); got != "pm-badge-status-warning" {
		t.Fatalf("pending RuntimeMatchClass = %q", got)
	}
	if got := (adminFeedFormRow{}).RuntimeMatchClass(); got != "pm-badge-status-healthy" {
		t.Fatalf("matching RuntimeMatchClass = %q", got)
	}
	if got := adminFeedAPIKeyStateClass(adminFeedAPIKeyStateMissingCode); got != "pm-badge-status-warning" {
		t.Fatalf("missing APIKeyStateClass = %q", got)
	}

	row := buildAdminFeedRow(nil, config.FeedSettings{Name: "custom-feed", Enabled: true}, false, db.FeedSyncStatus{})
	if row.FeedName != "CUSTOM-FEED" {
		t.Fatalf("FeedName = %q, want uppercase fallback", row.FeedName)
	}
	if row.ConfigMode != "unknown" {
		t.Fatalf("ConfigMode = %q, want runtime-unknown fallback", row.ConfigMode)
	}
	if got := configuredEditableFeeds(nil); got != nil {
		t.Fatalf("configuredEditableFeeds(nil) = %+v, want nil", got)
	}
}

func TestAdminFeedStatusMetadataRedactsSecrets(t *testing.T) {
	t.Parallel()

	row := buildAdminFeedRow(nil, config.FeedSettings{Name: "ghsa", DisplayName: "GHSA"}, true, db.FeedSyncStatus{
		Metadata: json.RawMessage(`{
			"client_ip":"client=192.0.2.10 password=client-ip-secret",
			"api_key_name":"importer token=api-name-secret",
			"correlation_id":"corr-safe Authorization: Bearer correlation-secret-token"
		}`),
	})

	checks := []struct {
		name    string
		got     string
		secret  string
		context string
		marker  string
	}{
		{"client IP", row.RejectedClientIP, "client-ip-secret", "client=192.0.2.10", "[redacted]"},
		{"API key name", row.RejectedAPIKeyName, "api-name-secret", "importer", "[redacted]"},
		{"correlation ID", row.RejectedCorrelationID, "correlation-secret-token", "corr-safe", "Bearer [redacted]"},
	}
	for _, check := range checks {
		if strings.Contains(check.got, check.secret) {
			t.Errorf("%s was not redacted", check.name)
		}
		if !strings.Contains(check.got, check.context) {
			t.Errorf("%s did not preserve its safe context", check.name)
		}
		if !strings.Contains(check.got, check.marker) {
			t.Errorf("%s did not include a redaction marker", check.name)
		}
	}
}

func TestAdminFeedFormRestartMismatchDimensions(t *testing.T) {
	t.Parallel()

	runtimeFeed := config.FeedSettings{
		Name:                 "osv",
		DisplayName:          "OSV",
		Enabled:              true,
		Mode:                 config.FeedModeSelf,
		SyncInterval:         time.Hour,
		APIKey:               "runtime-key",
		SupportsAPIKey:       true,
		SupportsSyncInterval: true,
	}
	tests := []struct {
		name         string
		mutate       func(*db.FeedConfig)
		wantPending  bool
		wantInterval string
	}{
		{"enabled", func(override *db.FeedConfig) { override.Enabled = false }, true, "1h"},
		{"mode", func(override *db.FeedConfig) { override.Mode = string(config.FeedModeExternal) }, true, "1h"},
		{"interval", func(override *db.FeedConfig) { value := 2 * time.Hour; override.SyncInterval = &value }, true, "2h"},
		{"API key", func(override *db.FeedConfig) { override.APIKey = "override-key" }, true, "1h"},
		{"whitespace-equivalent API key", func(override *db.FeedConfig) { override.APIKey = "  runtime-key\t" }, false, "1h"},
		{"nil override interval", func(override *db.FeedConfig) { override.SyncInterval = nil }, true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interval := runtimeFeed.SyncInterval
			override := db.FeedConfig{
				FeedName:     runtimeFeed.Name,
				Enabled:      runtimeFeed.Enabled,
				Mode:         string(runtimeFeed.Mode),
				SyncInterval: &interval,
				APIKey:       runtimeFeed.APIKey,
			}
			tt.mutate(&override)

			row := buildAdminFeedFormRow(nil, runtimeFeed, override, true)
			if row.PendingRestart != tt.wantPending {
				t.Fatalf("PendingRestart = %v, want %v: %+v", row.PendingRestart, tt.wantPending, row)
			}
			if row.SyncInterval != tt.wantInterval {
				t.Fatalf("SyncInterval = %q, want %q", row.SyncInterval, tt.wantInterval)
			}
			if row.OverrideClass() != "pm-badge-status-configured" {
				t.Fatalf("OverrideClass = %q", row.OverrideClass())
			}
			wantClass := "pm-badge-status-healthy"
			if tt.wantPending {
				wantClass = "pm-badge-status-warning"
			}
			if row.RuntimeMatchClass() != wantClass {
				t.Fatalf("RuntimeMatchClass = %q, want %q", row.RuntimeMatchClass(), wantClass)
			}
		})
	}
}

func TestRuntimeConfigCadenceAndAPIKeyFallbacks(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		feed config.FeedSettings
		want string
	}{
		{"display name", config.FeedSettings{Name: "private", DisplayName: "Private Feed", RequiresAPIKey: true}, "Private Feed"},
		{"feed name fallback", config.FeedSettings{Name: "custom-feed", RequiresAPIKey: true}, "custom-feed"},
	} {
		t.Run("required key help uses "+tt.name, func(t *testing.T) {
			help := adminFeedAPIKeyHelp(tt.feed)
			if !strings.Contains(help, "Required") || !strings.Contains(help, tt.want) {
				t.Fatalf("adminFeedAPIKeyHelp = %q, want required help containing %q", help, tt.want)
			}
		})
	}

	queueDriven := config.FeedSettings{Name: "socket"}
	if got := runtimeIntervalLabel(nil, queueDriven); got != "queue-driven" {
		t.Fatalf("queue-driven runtime label = %q", got)
	}
	if got := formRuntimeIntervalLabel(nil, queueDriven); got != "queue-driven" {
		t.Fatalf("queue-driven form label = %q", got)
	}

	periodic := config.FeedSettings{Name: "osv", SupportsSyncInterval: true}
	if got := runtimeIntervalLabel(nil, periodic); got != "unknown" {
		t.Fatalf("nil-config runtime label = %q", got)
	}
	if got := formRuntimeIntervalLabel(nil, periodic); got != "default" {
		t.Fatalf("nil-config form label = %q", got)
	}

	cfg := &config.Config{FeedSync: config.FeedSyncConfig{Interval: 6 * time.Hour}}
	if got := runtimeIntervalLabel(cfg, periodic); got != "6h (default)" {
		t.Fatalf("default runtime label = %q", got)
	}
	if got := formRuntimeIntervalLabel(cfg, periodic); got != "default (6h)" {
		t.Fatalf("default form label = %q", got)
	}

	periodic.SyncInterval = 45 * time.Minute
	cfg.Feeds.OSVInterval = periodic.SyncInterval
	if got := runtimeIntervalLabel(cfg, periodic); got != "45m (override)" {
		t.Fatalf("override runtime label = %q", got)
	}
	if got := formRuntimeIntervalLabel(cfg, periodic); got != "45m" {
		t.Fatalf("explicit form label = %q", got)
	}
}

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

func TestAdminFeedRowsExcludeSyntheticPipelineStatuses(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Feeds: config.FeedsConfig{OSVEnabled: true, OSVMode: config.FeedModeSelf}}
	handler := &AdminHandler{cfg: cfg}

	rows := handler.adminFeedRows([]db.FeedSyncStatus{
		{FeedName: "OSV", LastSyncStatus: "success"},
		{FeedName: "alias-severity-propagation", LastSyncStatus: "success", EntriesSynced: 1, EntriesTotal: 1},
	})

	for _, row := range rows {
		if strings.EqualFold(row.FeedName, "alias-severity-propagation") || row.FeedKey == "alias-severity-propagation" {
			t.Fatalf("admin feed rows include synthetic pipeline status alias-severity-propagation: %+v", rows)
		}
	}
	// The real feed is still present.
	findAdminFeedRow(t, rows, "osv")
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
