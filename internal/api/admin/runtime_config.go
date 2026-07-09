package admin

import (
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	feedhealth "github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/web"
)

const (
	adminFeedAPIKeyStateConfiguredCode    = "api-key-configured"
	adminFeedAPIKeyStateMissingCode       = "api-key-missing"
	adminFeedAPIKeyStateNotConfiguredCode = "api-key-not-configured"
	adminFeedAPIKeyStateNotRequiredCode   = "api-key-not-required"

	adminFeedSyncIntervalDefaultCode     = "sync-interval-default"
	adminFeedSyncIntervalQueueDrivenCode = "sync-interval-queue-driven"
)

type adminFeedFormRow struct {
	FeedName                string
	FeedKey                 string
	Enabled                 bool
	Mode                    string
	ModeOptions             []config.FeedModeOption
	SyncInterval            string
	SyncIntervalLabel       string
	SyncIntervalHelp        string
	SupportsSyncInterval    bool
	SupportsExternalMode    bool
	RequiresAPIKey          bool
	SupportsAPIKey          bool
	APIKeyHelp              string
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

func (row adminFeedRow) ConfigModeClass() string {
	return "pm-badge-status-default"
}

func (row adminFeedRow) ConfigEnabledClass() string {
	if row.ConfigEnabled {
		return "pm-badge-status-healthy"
	}
	return "pm-badge-status-disabled"
}

func (row adminFeedRow) SyncIntervalClass() string {
	if row.SyncIntervalCode == adminFeedSyncIntervalQueueDrivenCode {
		return "pm-badge-status-disabled"
	}
	return "pm-badge-status-default"
}

func (row adminFeedRow) LastSyncStatusClass() string {
	return adminFeedLastSyncStatusClass(row.LastSyncStatus)
}

func (row adminFeedRow) APIKeyStateClass() string {
	return adminFeedAPIKeyStateClass(row.APIKeyStateCode)
}

func (row adminFeedFormRow) OverrideClass() string {
	if row.OverrideActive {
		return "pm-badge-status-configured"
	}
	return "pm-badge-status-default"
}

func (row adminFeedFormRow) RuntimeMatchClass() string {
	if row.PendingRestart {
		return "pm-badge-status-warning"
	}
	return "pm-badge-status-healthy"
}

func (row adminFeedFormRow) UpdatedAtClass() string {
	return "pm-badge-status-default"
}

func adminFeedLastSyncStatusClass(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case db.FeedSyncStatusSuccess:
		return "pm-badge-status-healthy"
	case db.FeedSyncStatusRunning:
		return "pm-badge-status-running"
	case db.FeedSyncStatusPending:
		return "pm-badge-status-pending"
	case db.FeedSyncStatusError, db.FeedSyncStatusPermanentError, db.FeedSyncStatusRejected:
		return "pm-badge-status-error"
	case db.FeedSyncStatusExternal:
		return "pm-badge-status-configured"
	case db.FeedSyncStatusDisabled, db.FeedSyncStatusSkipped:
		return "pm-badge-status-disabled"
	case "":
		return "pm-badge-status-default"
	default:
		return "pm-badge-status-warning"
	}
}

func adminFeedAPIKeyStateClass(state string) string {
	switch strings.TrimSpace(state) {
	case adminFeedAPIKeyStateConfiguredCode:
		return "pm-badge-status-healthy"
	case adminFeedAPIKeyStateMissingCode:
		return "pm-badge-status-warning"
	case adminFeedAPIKeyStateNotConfiguredCode:
		return "pm-badge-status-disabled"
	default:
		return "pm-badge-status-default"
	}
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
			Name:                 status.FeedName,
			DisplayName:          strings.ToUpper(status.FeedName),
			Enabled:              true,
			Mode:                 config.FeedModeSelf,
			SupportsSyncInterval: true,
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
		FeedName:         feedCfg.DisplayName,
		FeedKey:          feedCfg.Name,
		ConfigMode:       string(feedCfg.Mode),
		ConfigEnabled:    feedCfg.Enabled,
		APIKeyState:      runtimeAPIKeyState(feedCfg),
		APIKeyStateCode:  runtimeAPIKeyStateCode(feedCfg),
		SyncIntervalStr:  runtimeIntervalLabel(cfg, feedCfg),
		SyncIntervalCode: runtimeIntervalCode(feedCfg),
	}

	if hasStatus {
		row.LastSyncStatus = status.LastSyncStatus
		row.EntriesSynced = status.EntriesSynced
		row.EntriesTotal = status.EntriesTotal
		row.RejectedCount = feedhealth.RejectedRecordCount(status)
		metadata := feedhealth.ParseStatusMetadata(status.Metadata)
		row.RejectedClientIP = logsafe.RedactDiagnosticMessage(metadata.ClientIP)
		row.RejectedAPIKeyID = metadata.APIKeyID
		row.RejectedAPIKeyName = logsafe.RedactDiagnosticMessage(metadata.APIKeyName)
		row.RejectedCorrelationID = logsafe.RedactDiagnosticMessage(metadata.CorrelationID)
		row.LastError = logsafe.RedactDiagnosticMessage(status.LastError)
		if status.LastSyncAt != nil {
			row.LastSyncAt = status.LastSyncAt
			row.LastSyncAtTime = *status.LastSyncAt
		}
		if status.LastSyncDuration != nil {
			row.DurationStr = status.LastSyncDuration.Round(time.Millisecond).String()
		}
		if strings.EqualFold(status.LastSyncStatus, "running") {
			startedAt := status.UpdatedAt
			if startedAt.IsZero() && status.LastSyncAt != nil {
				startedAt = *status.LastSyncAt
			}
			if !startedAt.IsZero() {
				elapsed := time.Since(startedAt)
				if elapsed < 0 {
					elapsed = 0
				}
				row.DurationStr = "running for " + elapsed.Round(time.Second).String()
			}
		}
	}

	row.Status = adminFeedHealth(feedCfg, statusOrNil(hasStatus, status))
	if row.ConfigMode == "" {
		row.ConfigMode = web.Message("admin.feeds.status.runtime_unknown")
	}
	if row.FeedName == "" {
		row.FeedName = strings.ToUpper(feedCfg.Name)
	}
	return row
}

func buildAdminFeedFormRow(cfg *config.Config, runtimeFeed config.FeedSettings, override db.FeedConfig, hasOverride bool) adminFeedFormRow {
	desired := runtimeFeed
	supportsExternal := config.FeedSupportsExternalMode(runtimeFeed.Name)
	row := adminFeedFormRow{
		FeedName:                runtimeFeed.DisplayName,
		FeedKey:                 runtimeFeed.Name,
		SupportsSyncInterval:    runtimeFeed.SupportsSyncInterval,
		SupportsExternalMode:    supportsExternal,
		ModeOptions:             config.FeedModeOptions(supportsExternal),
		RequiresAPIKey:          runtimeFeed.RequiresAPIKey,
		SupportsAPIKey:          runtimeFeed.SupportsAPIKey,
		APIKeyHelp:              adminFeedAPIKeyHelp(runtimeFeed),
		CanSyncNow:              runtimeFeed.SupportsManualSync,
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
		if desired.SupportsAPIKey || strings.TrimSpace(override.APIKey) != "" {
			desired.APIKey = override.APIKey
		}

		row.OverrideActive = true
		row.HasUpdatedAt = !override.UpdatedAt.IsZero()
		row.UpdatedAt = override.UpdatedAt
	}

	row.Enabled = desired.Enabled
	row.Mode = string(desired.Mode)
	row.CanSyncNow = desired.SupportsManualSync && desired.Enabled && desired.Mode == config.FeedModeSelf
	row.APIKeyConfigured = strings.TrimSpace(desired.APIKey) != ""
	if desired.SupportsSyncInterval {
		row.SyncInterval = formatOptionalDuration(desired.SyncInterval)
		row.SyncIntervalLabel = web.Message("admin.feeds.form.sync_interval.self_label")
		row.SyncIntervalHelp = adminFeedSyncIntervalHelp(false)
		if desired.Mode == config.FeedModeExternal {
			row.SyncIntervalHelp = adminFeedSyncIntervalHelp(true)
		}
	} else {
		row.SyncIntervalLabel = web.Message("admin.feeds.form.sync_interval.cadence_label")
		row.SyncIntervalHelp = web.Message("admin.feeds.form.sync_interval.queue_driven_help")
	}

	row.PendingRestart = runtimeFeed.Enabled != desired.Enabled ||
		runtimeFeed.Mode != desired.Mode ||
		runtimeFeed.SyncInterval != desired.SyncInterval ||
		strings.TrimSpace(runtimeFeed.APIKey) != strings.TrimSpace(desired.APIKey)

	return row
}

func adminFeedSyncIntervalHelp(external bool) string {
	syntax := web.Message("admin.feeds.form.sync_interval.syntax_help", formatRuntimeDuration(config.FeedSyncMinInterval))
	if external {
		return web.Message("admin.feeds.form.sync_interval.external_help", syntax)
	}
	return web.Message("admin.feeds.form.sync_interval.self_help", syntax)
}

func adminFeedAPIKeyHelp(feed config.FeedSettings) string {
	common := web.Message("admin.feeds.form.api_key.common_help")
	switch config.NormalizeFeedName(feed.Name) {
	case "vulncheck":
		return web.Message("admin.feeds.form.api_key.vulncheck_help", common)
	case "nvd":
		return web.Message("admin.feeds.form.api_key.nvd_help", common)
	case "socket":
		return web.Message("admin.feeds.form.api_key.socket_help", common)
	case "reversinglabs":
		return web.Message("admin.feeds.form.api_key.reversinglabs_help", common)
	default:
		displayName := strings.TrimSpace(feed.DisplayName)
		if displayName == "" {
			displayName = feed.Name
		}
		if feed.RequiresAPIKey {
			return web.Message("admin.feeds.form.api_key.required_help", displayName, common)
		}
		return web.Message("admin.feeds.form.api_key.optional_help", common)
	}
}

func configuredEditableFeeds(cfg *config.Config) []config.FeedSettings {
	if cfg == nil {
		return nil
	}
	return cfg.FeedSettingsList()
}

func runtimeAPIKeyState(feed config.FeedSettings) string {
	switch runtimeAPIKeyStateCode(feed) {
	case adminFeedAPIKeyStateConfiguredCode:
		return web.Message("admin.feeds.status.key.configured")
	case adminFeedAPIKeyStateMissingCode:
		return web.Message("admin.feeds.status.key.missing")
	case adminFeedAPIKeyStateNotConfiguredCode:
		return web.Message("admin.feeds.status.key.not_configured")
	default:
		return web.Message("admin.feeds.status.key.not_required")
	}
}

func runtimeAPIKeyStateCode(feed config.FeedSettings) string {
	if strings.TrimSpace(feed.APIKey) != "" {
		return adminFeedAPIKeyStateConfiguredCode
	}
	if feed.RequiresAPIKey {
		if feed.Enabled {
			return adminFeedAPIKeyStateMissingCode
		}
		return adminFeedAPIKeyStateNotConfiguredCode
	}
	return adminFeedAPIKeyStateNotRequiredCode
}

func runtimeIntervalLabel(cfg *config.Config, feed config.FeedSettings) string {
	if !feed.SupportsSyncInterval {
		return web.Message("admin.feeds.status.queue_driven")
	}
	if cfg == nil {
		return web.Message("admin.feeds.status.runtime_unknown")
	}
	interval := cfg.EffectiveFeedInterval(feed.Name)
	label := formatRuntimeDuration(interval)
	if feed.SyncInterval <= 0 {
		return web.Message("admin.feeds.status.runtime_default", label)
	}
	return web.Message("admin.feeds.status.runtime_override", label)
}

func runtimeIntervalCode(feed config.FeedSettings) string {
	if !feed.SupportsSyncInterval {
		return adminFeedSyncIntervalQueueDrivenCode
	}
	return adminFeedSyncIntervalDefaultCode
}

func formRuntimeIntervalLabel(cfg *config.Config, feed config.FeedSettings) string {
	if !feed.SupportsSyncInterval {
		return web.Message("admin.feeds.status.queue_driven")
	}
	if feed.SyncInterval > 0 {
		return formatRuntimeDuration(feed.SyncInterval)
	}
	if cfg == nil {
		return web.Message("admin.feeds.status.runtime_default_label")
	}
	return web.Message("admin.feeds.status.runtime_default_value", formatRuntimeDuration(cfg.EffectiveFeedInterval(feed.Name)))
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
