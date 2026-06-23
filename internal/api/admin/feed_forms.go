package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
)

type adminFeedFlashData struct {
	Message string
	Error   string
}

const maxAdminFormBytes = 1 << 20

func parseAdminForm(w http.ResponseWriter, r *http.Request) bool {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBytes)
	}
	if err := r.ParseForm(); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "request body too large") {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "invalid form payload", status)
		return false
	}
	return true
}

// HandleFeedConfigSave handles POST /admin/feeds/save.
func (h *AdminHandler) HandleFeedConfigSave(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/feeds") {
		return
	}

	feedName := r.PostForm.Get("feed_name")
	feed, err := h.desiredFeedSettings(r.Context(), feedName)
	if err != nil {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	previous, err := h.store.GetFeedConfig(r.Context(), feed.Name)
	if err != nil {
		h.logger.Error("admin feeds: failed to load previous config", "feed", feed.Name, "error", err)
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Failed to load feed configuration"), http.StatusSeeOther)
		return
	}

	mode, err := config.ParseFeedMode(r.PostForm.Get("mode"))
	if err != nil {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Invalid feed mode"), http.StatusSeeOther)
		return
	}
	feed.Mode = mode
	feed.Enabled = r.PostForm.Get("enabled") == "on"

	if feed.SupportsSyncInterval {
		rawInterval := strings.TrimSpace(r.PostForm.Get("sync_interval"))
		if rawInterval == "" {
			feed.SyncInterval = 0
		} else {
			interval, err := time.ParseDuration(rawInterval)
			if err != nil || interval <= 0 {
				http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Invalid sync interval"), http.StatusSeeOther)
				return
			}
			feed.SyncInterval = interval
		}
	}

	if feed.SupportsAPIKey {
		rawAPIKey := strings.TrimSpace(r.PostForm.Get("api_key"))
		clearAPIKey := r.PostForm.Get("clear_api_key") == "on"
		switch {
		case clearAPIKey && rawAPIKey != "":
			http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Choose either a new API key or clear the stored key"), http.StatusSeeOther)
			return
		case clearAPIKey && r.PostForm.Get("confirm_clear_api_key") != "on":
			http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Confirm API key removal"), http.StatusSeeOther)
			return
		case clearAPIKey:
			feed.APIKey = ""
		case rawAPIKey != "":
			feed.APIKey = rawAPIKey
		}
	}
	if err := config.ValidateFeedSettings(feed); err != nil {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	record := &db.FeedConfig{
		FeedName: feed.Name,
		Enabled:  feed.Enabled,
		Mode:     string(feed.Mode),
		APIKey:   feed.APIKey,
	}
	if feed.SupportsSyncInterval && feed.SyncInterval > 0 {
		interval := feed.SyncInterval
		record.SyncInterval = &interval
	}

	if err := h.auditLog(r, "feed_config_save", feedConfigAuditDetails(feed.Name, previous, record)); err != nil {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Failed to record audit log"), http.StatusSeeOther)
		return
	}

	if err := h.store.UpsertFeedConfig(r.Context(), record); err != nil {
		h.logger.Error("admin feeds: failed to save config", "feed", feed.Name, "error", err)
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Failed to save feed configuration"), http.StatusSeeOther)
		return
	}

	if h.applyFeedConfig != nil {
		if err := h.applyFeedConfig(r.Context(), feed); err != nil {
			h.logger.Error("admin feeds: failed to apply config", "feed", feed.Name, "error", err)
			h.restoreFeedConfigAfterFailedApply(r.Context(), feed.Name, previous)
			http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Feed configuration saved, but applying it failed"), http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape("Feed configuration saved and applied."), http.StatusSeeOther)
}

// HandleFeedConfigReset handles POST /admin/feeds/reset.
func (h *AdminHandler) HandleFeedConfigReset(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/feeds") {
		return
	}

	feedName := config.NormalizeFeedName(r.PostForm.Get("feed_name"))
	if _, ok := h.cfg.FeedSettings(feedName); !ok {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Unknown feed"), http.StatusSeeOther)
		return
	}
	if r.PostForm.Get("confirm_reset") != "on" {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Confirm feed configuration reset"), http.StatusSeeOther)
		return
	}

	previous, err := h.store.GetFeedConfig(r.Context(), feedName)
	if err != nil {
		h.logger.Error("admin feeds: failed to load previous config", "feed", feedName, "error", err)
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Failed to load feed configuration"), http.StatusSeeOther)
		return
	}

	if err := h.auditLog(r, "feed_config_reset", feedConfigAuditDetails(feedName, previous, nil)); err != nil {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Failed to record audit log"), http.StatusSeeOther)
		return
	}
	if err := h.store.DeleteFeedConfig(r.Context(), feedName); err != nil {
		h.logger.Error("admin feeds: failed to reset config", "feed", feedName, "error", err)
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Failed to reset feed configuration"), http.StatusSeeOther)
		return
	}
	if h.resetFeedConfig != nil {
		if err := h.resetFeedConfig(r.Context(), feedName); err != nil {
			h.logger.Error("admin feeds: failed to apply reset config", "feed", feedName, "error", err)
			h.restoreFeedConfigAfterFailedApply(r.Context(), feedName, previous)
			http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Feed configuration reset, but applying it failed"), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape("Feed configuration reset and applied."), http.StatusSeeOther)
}

// HandleFeedSyncNow handles POST /admin/feeds/sync.
func (h *AdminHandler) HandleFeedSyncNow(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/feeds") {
		return
	}

	feedName := config.NormalizeFeedName(r.PostForm.Get("feed_name"))
	feed, ok := h.cfg.FeedSettings(feedName)
	if !ok {
		h.respondFeedSyncResult(w, r, "", "Unknown feed", http.StatusBadRequest, false)
		return
	}
	if !feed.SupportsManualSync {
		h.respondFeedSyncResult(w, r, "", "Manual sync is not available for this feed", http.StatusBadRequest, false)
		return
	}
	if !feed.Enabled || feed.Mode != config.FeedModeSelf {
		h.respondFeedSyncResult(w, r, "", "Manual sync is available only for enabled self-managed feeds.", http.StatusBadRequest, false)
		return
	}
	if h.syncFeed == nil {
		h.respondFeedSyncResult(w, r, "", "Manual sync is not available in this server mode", http.StatusBadRequest, false)
		return
	}
	if !h.beginManualFeedSync(feed.Name) {
		h.respondFeedSyncResult(w, r, "", feed.DisplayName+" sync is already running.", http.StatusConflict, false)
		return
	}

	h.markFeedSyncRunning(r.Context(), feed.Name)

	go func(feed config.FeedSettings) { // #nosec G118 -- manual sync intentionally outlives the request and is bounded by root context plus timeout.
		defer h.endManualFeedSync(feed.Name)

		rootCtx := h.rootCtx
		if rootCtx == nil {
			rootCtx = context.Background()
		}
		ctx, cancel := context.WithTimeout(rootCtx, 30*time.Minute)
		defer cancel()

		if err := h.syncFeed(ctx, feed.Name); err != nil {
			h.logger.Error("admin feeds: manual sync failed", "feed", feed.Name, "error", err)
			return
		}
		h.logger.Info("admin feeds: manual sync finished", "feed", feed.Name)
	}(feed)

	if err := h.auditLog(r, "feed_sync_trigger", map[string]string{
		"feed": feed.Name,
		"mode": string(feed.Mode),
	}); err != nil {
		h.respondFeedSyncResult(w, r, "", "Failed to record audit log", http.StatusInternalServerError, false)
		return
	}

	h.respondFeedSyncResult(w, r, feed.DisplayName+" sync started with current runtime settings.", "", http.StatusOK, true)
}

func (h *AdminHandler) beginManualFeedSync(feedName string) bool {
	if h == nil {
		return false
	}
	name := config.NormalizeFeedName(feedName)
	h.manualSyncMu.Lock()
	defer h.manualSyncMu.Unlock()
	if h.manualSyncs == nil {
		h.manualSyncs = make(map[string]struct{})
	}
	if _, exists := h.manualSyncs[name]; exists {
		return false
	}
	h.manualSyncs[name] = struct{}{}
	return true
}

func (h *AdminHandler) endManualFeedSync(feedName string) {
	if h == nil {
		return
	}
	name := config.NormalizeFeedName(feedName)
	h.manualSyncMu.Lock()
	defer h.manualSyncMu.Unlock()
	delete(h.manualSyncs, name)
}

func (h *AdminHandler) markFeedSyncRunning(ctx context.Context, feedName string) {
	now := time.Now().UTC()
	status := &db.FeedSyncStatus{
		FeedName:       feedName,
		LastSyncAt:     &now,
		LastSyncStatus: "running",
	}

	current, err := h.store.GetFeedSyncStatus(ctx, feedName)
	if err != nil {
		h.logger.Warn("admin feeds: failed to load current sync status", "feed", feedName, "error", err)
	} else if current != nil {
		status.EntriesSynced = current.EntriesSynced
		status.EntriesTotal = current.EntriesTotal
		status.LastCommitHash = current.LastCommitHash
		status.LastEtag = current.LastEtag
		if current.Metadata != nil {
			status.Metadata = append([]byte(nil), current.Metadata...)
		}
	}

	if err := h.store.UpsertFeedSyncStatus(ctx, status); err != nil {
		h.logger.Warn("admin feeds: failed to mark sync as running", "feed", feedName, "error", err)
	}
}

func (h *AdminHandler) respondFeedSyncResult(w http.ResponseWriter, r *http.Request, message, errMsg string, statusCode int, triggerRefresh bool) {
	if isHTMXRequest(r) {
		if triggerRefresh {
			payload, err := json.Marshal(map[string]string{"feed-runtime-refresh": "true"})
			if err == nil {
				w.Header().Set("HX-Trigger", string(payload))
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(statusCode)
		if renderErr := h.renderer.RenderPartial(w, "admin/feeds.html", "admin-feed-flash", adminFeedFlashData{
			Message: message,
			Error:   errMsg,
		}); renderErr != nil {
			h.logger.Error("admin feeds: flash render failed", "error", renderErr)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	if errMsg != "" {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape(errMsg), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape(message), http.StatusSeeOther)
}

func isHTMXRequest(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("HX-Request")), "true")
}

func (h *AdminHandler) desiredFeedSettings(ctx context.Context, feedName string) (config.FeedSettings, error) {
	name := config.NormalizeFeedName(feedName)
	current, ok := h.cfg.FeedSettings(name)
	if !ok {
		return config.FeedSettings{}, fmt.Errorf("unknown feed")
	}

	stored, err := h.store.GetFeedConfig(ctx, name)
	if err != nil {
		return config.FeedSettings{}, fmt.Errorf("load persisted feed config: %w", err)
	}
	if stored == nil {
		return current, nil
	}

	mode, err := config.ParseFeedMode(stored.Mode)
	if err != nil {
		return config.FeedSettings{}, fmt.Errorf("invalid persisted mode for %s", name)
	}

	current.Enabled = stored.Enabled
	current.Mode = mode
	if stored.SyncInterval != nil {
		current.SyncInterval = *stored.SyncInterval
	} else {
		current.SyncInterval = 0
	}
	if current.SupportsAPIKey || strings.TrimSpace(stored.APIKey) != "" {
		current.APIKey = strings.TrimSpace(stored.APIKey)
	}
	return current, nil
}

func (h *AdminHandler) restoreFeedConfigAfterFailedApply(ctx context.Context, feedName string, previous *db.FeedConfig) {
	var err error
	if previous == nil {
		err = h.store.DeleteFeedConfig(ctx, feedName)
	} else {
		err = h.store.UpsertFeedConfig(ctx, previous)
	}
	if err != nil {
		h.logger.Error("admin feeds: failed to roll back persisted config after apply failure", "feed", feedName, "error", err)
	}
}

func feedConfigAuditDetails(feedName string, previous, next *db.FeedConfig) map[string]string {
	details := map[string]string{"feed": feedName}
	addFeedConfigAuditDetails(details, "previous_", previous)
	addFeedConfigAuditDetails(details, "new_", next)
	return details
}

func addFeedConfigAuditDetails(details map[string]string, prefix string, cfg *db.FeedConfig) {
	if cfg == nil {
		details[prefix+"enabled"] = "unset"
		details[prefix+"mode"] = "unset"
		details[prefix+"sync_interval"] = "unset"
		details[prefix+"api_key_configured"] = "unset"
		return
	}
	details[prefix+"enabled"] = strconv.FormatBool(cfg.Enabled)
	details[prefix+"mode"] = cfg.Mode
	details[prefix+"api_key_configured"] = strconv.FormatBool(strings.TrimSpace(cfg.APIKey) != "")
	if cfg.SyncInterval == nil {
		details[prefix+"sync_interval"] = ""
		return
	}
	details[prefix+"sync_interval"] = cfg.SyncInterval.String()
}
