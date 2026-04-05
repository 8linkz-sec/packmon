package admin

import (
	"fmt"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
)

type adminFeedFormRow struct {
	FeedName                string
	FeedKey                 string
	Enabled                 bool
	Mode                    string
	SyncInterval            string
	SyncIntervalLabel       string
	SyncIntervalHelp        string
	SupportsSyncInterval    bool
	RequiresAPIKey          bool
	APIKeyConfigured        bool
	CanSyncNow              bool
	OverrideActive          bool
	PendingRestart          bool
	HasUpdatedAt            bool
	UpdatedAt               time.Time
	RuntimeMode             string
	RuntimeEnabled          bool
	RuntimeSyncInterval     string
	RuntimeAPIKeyConfigured bool
	RuntimeSupportsInterval bool
}

func (h *AdminHandler) adminFeedRows(statuses []db.FeedSyncStatus) []adminFeedRow {
	statusByName := make(map[string]db.FeedSyncStatus, len(statuses))
	for _, status := range statuses {
		statusByName[config.NormalizeFeedName(status.FeedName)] = status
	}

	runtimeFeeds := configuredEditableFeeds(h.cfg)
	rows := make([]adminFeedRow, 0, len(runtimeFeeds)+len(statuses))
	seen := make(map[string]struct{}, len(runtimeFeeds))

	for _, feedCfg := range runtimeFeeds {
		feedKey := config.NormalizeFeedName(feedCfg.Name)
		seen[feedKey] = struct{}{}
		status, ok := statusByName[feedKey]
		rows = append(rows, buildAdminFeedRow(h.cfg, feedCfg, ok, status))
	}

	for _, status := range statuses {
		feedKey := config.NormalizeFeedName(status.FeedName)
		if _, ok := seen[feedKey]; ok {
			continue
		}
		rows = append(rows, buildAdminFeedRow(h.cfg, config.FeedSettings{
			Name:        status.FeedName,
			DisplayName: strings.ToUpper(status.FeedName),
			Enabled:     true,
			Mode:        config.FeedModeSelf,
		}, true, status))
	}

	return rows
}

func (h *AdminHandler) adminFeedFormRows(overrides []db.FeedConfig) []adminFeedFormRow {
	overrideByName := make(map[string]db.FeedConfig, len(overrides))
	for _, override := range overrides {
		overrideByName[config.NormalizeFeedName(override.FeedName)] = override
	}

	runtimeFeeds := configuredEditableFeeds(h.cfg)
	rows := make([]adminFeedFormRow, 0, len(runtimeFeeds))
	for _, runtimeFeed := range runtimeFeeds {
		override, hasOverride := overrideByName[config.NormalizeFeedName(runtimeFeed.Name)]
		rows = append(rows, buildAdminFeedFormRow(h.cfg, runtimeFeed, override, hasOverride))
	}
	return rows
}

func buildAdminFeedRow(cfg *config.Config, feedCfg config.FeedSettings, hasStatus bool, status db.FeedSyncStatus) adminFeedRow {
	row := adminFeedRow{
		FeedName:        feedCfg.DisplayName,
		FeedKey:         feedCfg.Name,
		ConfigMode:      string(feedCfg.Mode),
		ConfigEnabled:   feedCfg.Enabled,
		APIKeyState:     runtimeAPIKeyState(feedCfg),
		SyncIntervalStr: runtimeIntervalLabel(cfg, feedCfg),
	}

	if hasStatus {
		row.LastSyncStatus = status.LastSyncStatus
		row.EntriesSynced = status.EntriesSynced
		row.EntriesTotal = status.EntriesTotal
		row.LastError = status.LastError
		if status.LastSyncAt != nil {
			row.LastSyncAt = status.LastSyncAt
			row.LastSyncAtTime = *status.LastSyncAt
		}
		if status.LastSyncDuration != nil {
			row.DurationStr = status.LastSyncDuration.Round(time.Millisecond).String()
		}
	}

	row.Status = adminFeedHealth(feedCfg.Enabled, feedCfg.Mode, statusOrNil(hasStatus, status))
	if row.ConfigMode == "" {
		row.ConfigMode = "unknown"
	}
	if row.FeedName == "" {
		row.FeedName = strings.ToUpper(feedCfg.Name)
	}
	return row
}

func buildAdminFeedFormRow(cfg *config.Config, runtimeFeed config.FeedSettings, override db.FeedConfig, hasOverride bool) adminFeedFormRow {
	desired := runtimeFeed
	row := adminFeedFormRow{
		FeedName:                runtimeFeed.DisplayName,
		FeedKey:                 runtimeFeed.Name,
		SupportsSyncInterval:    runtimeFeed.SupportsSyncInterval,
		RequiresAPIKey:          runtimeFeed.RequiresAPIKey,
		CanSyncNow:              supportsManualFeedSync(runtimeFeed.Name),
		RuntimeMode:             string(runtimeFeed.Mode),
		RuntimeEnabled:          runtimeFeed.Enabled,
		RuntimeSyncInterval:     formRuntimeIntervalLabel(cfg, runtimeFeed),
		RuntimeAPIKeyConfigured: strings.TrimSpace(runtimeFeed.APIKey) != "",
		RuntimeSupportsInterval: runtimeFeed.SupportsSyncInterval,
	}

	if hasOverride {
		desired.Enabled = override.Enabled
		if mode, err := config.ParseFeedMode(override.Mode); err == nil {
			desired.Mode = mode
		}
		if override.SyncInterval != nil {
			desired.SyncInterval = *override.SyncInterval
		} else {
			desired.SyncInterval = 0
		}
		if desired.RequiresAPIKey || strings.TrimSpace(override.APIKey) != "" {
			desired.APIKey = override.APIKey
		}

		row.OverrideActive = true
		row.HasUpdatedAt = !override.UpdatedAt.IsZero()
		row.UpdatedAt = override.UpdatedAt
	}

	row.Enabled = desired.Enabled
	row.Mode = string(desired.Mode)
	row.APIKeyConfigured = strings.TrimSpace(desired.APIKey) != ""
	if desired.SupportsSyncInterval {
		row.SyncInterval = formatOptionalDuration(desired.SyncInterval)
		row.SyncIntervalLabel = "Self-sync interval"
		row.SyncIntervalHelp = "How often Packmon syncs this feed while mode is self. Blank uses the global default."
		if desired.Mode == config.FeedModeExternal {
			row.SyncIntervalHelp = "Ignored while mode is external. External feeds wait for imports or webhooks instead."
		}
	} else {
		row.SyncIntervalLabel = "Sync cadence"
		row.SyncIntervalHelp = "This feed does not run on a periodic timer. It is queue-driven."
	}

	row.PendingRestart = runtimeFeed.Enabled != desired.Enabled ||
		runtimeFeed.Mode != desired.Mode ||
		runtimeFeed.SyncInterval != desired.SyncInterval ||
		strings.TrimSpace(runtimeFeed.APIKey) != strings.TrimSpace(desired.APIKey)

	return row
}

func configuredEditableFeeds(cfg *config.Config) []config.FeedSettings {
	if cfg == nil {
		return nil
	}
	return cfg.FeedSettingsList()
}

func runtimeAPIKeyState(feed config.FeedSettings) string {
	if strings.TrimSpace(feed.APIKey) != "" {
		return "configured"
	}
	if feed.RequiresAPIKey {
		if feed.Enabled {
			return "missing"
		}
		return "not configured"
	}
	return "not required"
}

func runtimeIntervalLabel(cfg *config.Config, feed config.FeedSettings) string {
	if !feed.SupportsSyncInterval {
		return "queue-driven"
	}
	if cfg == nil {
		return "unknown"
	}
	interval := cfg.EffectiveFeedInterval(feed.Name)
	label := formatRuntimeDuration(interval)
	if feed.SyncInterval <= 0 {
		return label + " (default)"
	}
	return label + " (override)"
}

func formRuntimeIntervalLabel(cfg *config.Config, feed config.FeedSettings) string {
	if !feed.SupportsSyncInterval {
		return "queue-driven"
	}
	if feed.SyncInterval > 0 {
		return formatRuntimeDuration(feed.SyncInterval)
	}
	if cfg == nil {
		return "default"
	}
	return "default (" + formatRuntimeDuration(cfg.EffectiveFeedInterval(feed.Name)) + ")"
}

func statusOrNil(ok bool, status db.FeedSyncStatus) *db.FeedSyncStatus {
	if !ok {
		return nil
	}
	copyValue := status
	return &copyValue
}

func formatRuntimeDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

func formatOptionalDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return formatRuntimeDuration(d)
}

func supportsManualFeedSync(feedName string) bool {
	switch config.NormalizeFeedName(feedName) {
	case "osv", "ghsa", "openssf", "vulncheck", "cisakev", "epss":
		return true
	default:
		return false
	}
}
