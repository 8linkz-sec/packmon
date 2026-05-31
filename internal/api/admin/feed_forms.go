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

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
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

	feedName := r.PostForm.Get("feed_name")
	feed, err := h.desiredFeedSettings(r.Context(), feedName)
	if err != nil {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
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

	if feed.RequiresAPIKey {
		switch {
		case r.PostForm.Get("clear_api_key") == "on":
			feed.APIKey = ""
		case strings.TrimSpace(r.PostForm.Get("api_key")) != "":
			feed.APIKey = strings.TrimSpace(r.PostForm.Get("api_key"))
		}
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

	if err := h.store.UpsertFeedConfig(r.Context(), record); err != nil {
		h.logger.Error("admin feeds: failed to save config", "feed", feed.Name, "error", err)
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Failed to save feed configuration"), http.StatusSeeOther)
		return
	}

	if h.applyFeedConfig != nil {
		if err := h.applyFeedConfig(r.Context(), feed); err != nil {
			h.logger.Error("admin feeds: failed to apply config", "feed", feed.Name, "error", err)
			http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Feed configuration saved, but applying it failed"), http.StatusSeeOther)
			return
		}
	}

	h.auditLog(r, "feed_config_save", map[string]string{
		"feed":               feed.Name,
		"enabled":            strconv.FormatBool(feed.Enabled),
		"mode":               string(feed.Mode),
		"sync_interval":      formatOptionalDuration(feed.SyncInterval),
		"api_key_configured": strconv.FormatBool(strings.TrimSpace(feed.APIKey) != ""),
	})

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

	feedName := config.NormalizeFeedName(r.PostForm.Get("feed_name"))
	if _, ok := h.cfg.FeedSettings(feedName); !ok {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Unknown feed"), http.StatusSeeOther)
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
			http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Feed configuration reset, but applying it failed"), http.StatusSeeOther)
			return
		}
	}

	h.auditLog(r, "feed_config_reset", map[string]string{"feed": feedName})
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

	feedName := config.NormalizeFeedName(r.PostForm.Get("feed_name"))
	feed, ok := h.cfg.FeedSettings(feedName)
	if !ok {
		h.respondFeedSyncResult(w, r, "", "Unknown feed", http.StatusBadRequest, false)
		return
	}
	if !supportsManualFeedSync(feedName) {
		h.respondFeedSyncResult(w, r, "", "Manual sync is not available for this feed", http.StatusBadRequest, false)
		return
	}
	if h.syncFeed == nil {
		h.respondFeedSyncResult(w, r, "", "Manual sync is not available in this server mode", http.StatusBadRequest, false)
		return
	}

	h.markFeedSyncRunning(r.Context(), feed.Name)

	go func(feed config.FeedSettings) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Minute)
		defer cancel()

		if err := h.syncFeed(ctx, feed.Name); err != nil {
			h.logger.Error("admin feeds: manual sync failed", "feed", feed.Name, "error", err)
			return
		}
		h.logger.Info("admin feeds: manual sync finished", "feed", feed.Name)
	}(feed)

	h.auditLog(r, "feed_sync_trigger", map[string]string{
		"feed": feed.Name,
		"mode": string(feed.Mode),
	})

	h.respondFeedSyncResult(w, r, feed.DisplayName+" sync started with current runtime settings.", "", http.StatusOK, true)
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
		if errMsg == "" {
			w.WriteHeader(statusCode)
			return
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
	if current.RequiresAPIKey || strings.TrimSpace(stored.APIKey) != "" {
		current.APIKey = strings.TrimSpace(stored.APIKey)
	}
	return current, nil
}
