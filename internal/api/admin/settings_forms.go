package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/db"
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

	blockThreshold, ok := normalizeSystemBlockThreshold(r.PostForm.Get("block_threshold"))
	if !ok {
		redirectSettings(w, r, "Invalid block threshold", true)
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

	settings := &db.SystemSettings{
		BlockThreshold:     blockThreshold,
		RateLimitPerMinute: rateLimitPerMinute,
		RateLimitBurst:     rateLimitBurst,
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

	h.auditLog(r, "system_settings_save", map[string]string{
		"block_threshold":       blockThreshold,
		"rate_limit_per_minute": strconv.Itoa(rateLimitPerMinute),
		"rate_limit_burst":      strconv.Itoa(rateLimitBurst),
	})

	redirectSettings(w, r, "System settings saved and applied.", false)
}

func normalizeSystemBlockThreshold(raw string) (string, bool) {
	switch normalized := strings.ToUpper(strings.TrimSpace(raw)); normalized {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return normalized, true
	default:
		return "", false
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
