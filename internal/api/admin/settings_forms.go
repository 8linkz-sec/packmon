package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
)

const maxAdminRateLimit = 100000

// HandleSystemSettingsSave handles POST /admin/settings/system.
func (h *AdminHandler) HandleSystemSettingsSave(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}
	if !parseAdminForm(w, r) {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/settings") {
		return
	}

	blockThreshold, ok := normalizeSystemBlockThreshold(r.PostForm.Get("block_threshold"))
	if !ok {
		redirectSettings(w, r, "Invalid block threshold", true)
		return
	}
	if blockThreshold == "NONE" && !acknowledgedSetting(r.PostForm.Get("ack_block_threshold_none")) {
		redirectSettings(w, r, "Block threshold NONE requires explicit acknowledgement", true)
		return
	}

	rateLimitPerMinute, ok := parsePositiveSettingInt(r.PostForm.Get("rate_limit_per_minute"))
	if !ok {
		redirectSettings(w, r, "Invalid rate limit per minute", true)
		return
	}

	rateLimitBurst, ok := parsePositiveSettingInt(r.PostForm.Get("rate_limit_burst"))
	if !ok {
		redirectSettings(w, r, "Invalid rate limit burst", true)
		return
	}

	previous, err := h.store.GetSystemSettings(r.Context())
	if err != nil {
		h.logger.Error("admin settings: failed to load previous system settings", "error", err)
		redirectSettings(w, r, "Failed to load system settings", true)
		return
	}

	settings := &db.SystemSettings{
		BlockThreshold:     blockThreshold,
		RateLimitPerMinute: rateLimitPerMinute,
		RateLimitBurst:     rateLimitBurst,
	}

	if err := h.auditLog(r, "system_settings_save", systemSettingsAuditDetails(previous, settings)); err != nil {
		redirectSettings(w, r, "Failed to record audit log", true)
		return
	}

	if err := h.store.UpsertSystemSettings(r.Context(), settings); err != nil {
		h.logger.Error("admin settings: failed to save system settings", "error", err)
		redirectSettings(w, r, "Failed to save system settings", true)
		return
	}

	// Apply to the live runtime so the new block threshold and rate limit take
	// effect immediately, without a server restart.
	if h.runtime != nil {
		h.runtime.Update(blockThreshold, rateLimitPerMinute, rateLimitBurst)
	}

	redirectSettings(w, r, "System settings saved and applied.", false)
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
		return
	}
	details[prefix+"block_threshold"] = settings.BlockThreshold
	details[prefix+"rate_limit_per_minute"] = strconv.Itoa(settings.RateLimitPerMinute)
	details[prefix+"rate_limit_burst"] = strconv.Itoa(settings.RateLimitBurst)
}

func normalizeSystemBlockThreshold(raw string) (string, bool) {
	switch normalized := strings.ToUpper(strings.TrimSpace(raw)); normalized {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return normalized, true
	default:
		return "", false
	}
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
	if err != nil || value <= 0 || value > maxAdminRateLimit {
		return 0, false
	}
	return value, true
}

func redirectSettings(w http.ResponseWriter, r *http.Request, message string, isError bool) {
	key := "msg"
	if isError {
		key = "err"
	}
	http.Redirect(w, r, "/admin/settings?"+key+"="+url.QueryEscape(message), http.StatusSeeOther)
}
