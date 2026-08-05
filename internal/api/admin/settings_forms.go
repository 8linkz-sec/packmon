package admin

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/web"
)

const (
	// MaxAdminRateLimit is the highest runtime rate-limit value accepted by the
	// admin settings form and rendered in the matching HTML constraints.
	MaxAdminRateLimit = 100000

	// MaxAdminRetentionDays is the highest metadata-retention value accepted by
	// the admin settings form and rendered in the matching HTML constraints.
	MaxAdminRetentionDays = 3650

	adminRetentionDay             = 24 * time.Hour
	adminMetadataRetentionDefault = 30 * adminRetentionDay
)

// HandleSystemSettingsSave handles POST /admin/settings/system.
func (h *AdminHandler) HandleSystemSettingsSave(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "system_settings_save",
		bootstrapRedirectPath: "/admin/settings",
	}); !ok {
		return
	}

	blockThreshold, ok := normalizeSystemBlockThreshold(r.PostForm.Get("block_threshold"))
	if !ok {
		redirectSettings(w, r, web.Message("admin.settings.error.invalid_block_threshold"), true)
		return
	}
	if blockThreshold == "NONE" && !acknowledgedSetting(r.PostForm.Get("ack_block_threshold_none")) {
		redirectSettings(w, r, web.Message("admin.settings.error.block_threshold_none_ack"), true)
		return
	}

	rateLimitPerMinute, ok := parsePositiveSettingInt(r.PostForm.Get("rate_limit_per_minute"))
	if !ok {
		redirectSettings(w, r, web.Message("admin.settings.error.invalid_rate_limit_per_minute"), true)
		return
	}

	rateLimitBurst, ok := parsePositiveSettingInt(r.PostForm.Get("rate_limit_burst"))
	if !ok {
		redirectSettings(w, r, web.Message("admin.settings.error.invalid_rate_limit_burst"), true)
		return
	}

	previous, err := h.store.GetSystemSettings(r.Context())
	if err != nil {
		h.logger.Error("admin settings: failed to load previous system settings", h.adminLogAttrs(r, "error", err)...)
		redirectSettings(w, r, web.Message("admin.settings.error.load_system_settings"), true)
		return
	}

	scanLogRetentionFallback, adminAuditRetentionFallback := h.effectiveSystemMetadataRetention(previous)
	scanLogRetention, ok := parseRetentionDaysSetting(r.PostForm, "scan_log_retention_days", scanLogRetentionFallback)
	if !ok {
		redirectSettings(w, r, web.Message("admin.settings.error.invalid_scan_log_retention"), true)
		return
	}
	adminAuditRetention, ok := parseRetentionDaysSetting(r.PostForm, "admin_audit_retention_days", adminAuditRetentionFallback)
	if !ok {
		redirectSettings(w, r, web.Message("admin.settings.error.invalid_admin_audit_retention"), true)
		return
	}

	settings := &db.SystemSettings{
		BlockThreshold:      blockThreshold,
		RateLimitPerMinute:  rateLimitPerMinute,
		RateLimitBurst:      rateLimitBurst,
		ScanLogRetention:    scanLogRetention,
		AdminAuditRetention: adminAuditRetention,
	}
	if _, submitted := r.PostForm["updated_at"]; submitted {
		expectedUpdatedAt, ok := parseSystemSettingsRevision(r.PostForm.Get("updated_at"))
		if !ok {
			redirectSettings(w, r, web.Message("admin.settings.error.invalid_revision"), true)
			return
		}
		settings.ExpectedUpdatedAt = &expectedUpdatedAt
	}
	audit := h.adminAuditEntry(r, "system_settings_save", systemSettingsAuditDetails(previous, settings))

	auditCtx, cancel := h.adminAuditContext()
	defer cancel()

	if err := h.store.UpsertSystemSettingsWithAudit(auditCtx, settings, audit); err != nil {
		h.logger.Error("admin settings: failed to save system settings", h.adminLogAttrs(r, "error", err)...)
		if errors.Is(err, db.ErrConflict) {
			redirectSettings(w, r, web.Message("admin.settings.error.conflict"), true)
			return
		}
		if errors.Is(err, db.ErrAdminAuditLog) {
			redirectSettings(w, r, web.Message("admin.settings.error.audit_log"), true)
			return
		}
		redirectSettings(w, r, web.Message("admin.settings.error.save"), true)
		return
	}

	// Apply to the live runtime so the new block threshold and rate limit take
	// effect immediately, without a server restart.
	if h.runtime != nil {
		h.runtime.Update(blockThreshold, rateLimitPerMinute, rateLimitBurst)
		h.runtime.UpdateRetention(scanLogRetention, adminAuditRetention)
	}

	redirectSettings(w, r, web.Message("admin.settings.flash.saved"), false)
}

func systemSettingsAuditDetails(previous, next *db.SystemSettings) map[string]string {
	details := map[string]string{}
	addSystemSettingsAuditDetails(details, "previous_", previous)
	addSystemSettingsAuditDetails(details, "new_", next)
	return details
}

func addSystemSettingsAuditDetails(details map[string]string, prefix string, settings *db.SystemSettings) {
	if settings == nil {
		details[prefix+"block_threshold"] = "unset"
		details[prefix+"rate_limit_per_minute"] = "unset"
		details[prefix+"rate_limit_burst"] = "unset"
		details[prefix+"scan_log_retention"] = "unset"
		details[prefix+"admin_audit_retention"] = "unset"
		return
	}
	details[prefix+"block_threshold"] = settings.BlockThreshold
	details[prefix+"rate_limit_per_minute"] = strconv.Itoa(settings.RateLimitPerMinute)
	details[prefix+"rate_limit_burst"] = strconv.Itoa(settings.RateLimitBurst)
	details[prefix+"scan_log_retention"] = settings.ScanLogRetention.String()
	details[prefix+"admin_audit_retention"] = settings.AdminAuditRetention.String()
}

func normalizeSystemBlockThreshold(raw string) (string, bool) {
	threshold, ok := domain.ParseBlockThreshold(raw)
	if !ok {
		return "", false
	}
	return string(threshold), true
}

func acknowledgedSetting(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parsePositiveSettingInt(raw string) (int, bool) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 || value > MaxAdminRateLimit {
		return 0, false
	}
	return value, true
}

func parseRetentionDaysSetting(values url.Values, key string, fallback time.Duration) (time.Duration, bool) {
	rawValues, submitted := values[key]
	if !submitted {
		return fallback, true
	}
	if len(rawValues) == 0 {
		return 0, false
	}
	raw := strings.TrimSpace(rawValues[0])
	if raw == "" {
		return 0, false
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 0 || days > MaxAdminRetentionDays {
		return 0, false
	}
	return time.Duration(days) * adminRetentionDay, true
}

func (h *AdminHandler) effectiveSystemMetadataRetention(previous *db.SystemSettings) (time.Duration, time.Duration) {
	scanLogRetention := adminMetadataRetentionDefault
	adminAuditRetention := adminMetadataRetentionDefault
	if h != nil && h.cfg != nil {
		if h.cfg.Retention.ScanLog >= 0 {
			scanLogRetention = h.cfg.Retention.ScanLog
		}
		if h.cfg.Retention.AdminAuditLog >= 0 {
			adminAuditRetention = h.cfg.Retention.AdminAuditLog
		}
	}
	if h != nil && h.runtime != nil {
		runtimeRetention := h.runtime.Retention()
		if runtimeRetention.ScanLog >= 0 {
			scanLogRetention = runtimeRetention.ScanLog
		}
		if runtimeRetention.AdminAuditLog >= 0 {
			adminAuditRetention = runtimeRetention.AdminAuditLog
		}
	}
	if previous != nil {
		if previous.ScanLogRetention >= 0 {
			scanLogRetention = previous.ScanLogRetention
		}
		if previous.AdminAuditRetention >= 0 {
			adminAuditRetention = previous.AdminAuditRetention
		}
	}
	return scanLogRetention, adminAuditRetention
}

func parseSystemSettingsRevision(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, true
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return updatedAt.UTC(), true
}

func redirectSettings(w http.ResponseWriter, r *http.Request, message string, isError bool) {
	key := "msg"
	if isError {
		key = "err"
	}
	http.Redirect(w, r, "/admin/settings?"+key+"="+url.QueryEscape(message), http.StatusSeeOther)
}
