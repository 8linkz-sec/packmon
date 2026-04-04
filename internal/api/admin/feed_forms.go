package admin

import (
	"context"
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

// HandleFeedConfigSave handles POST /admin/feeds/save.
func (h *AdminHandler) HandleFeedConfigSave(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	feed, err := h.desiredFeedSettings(r.Context(), r.FormValue("feed_name"))
	if err != nil {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	mode, err := config.ParseFeedMode(r.FormValue("mode"))
	if err != nil {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Invalid feed mode"), http.StatusSeeOther)
		return
	}
	feed.Mode = mode
	feed.Enabled = r.FormValue("enabled") == "on"

	if feed.SupportsSyncInterval {
		rawInterval := strings.TrimSpace(r.FormValue("sync_interval"))
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
		case r.FormValue("clear_api_key") == "on":
			feed.APIKey = ""
		case strings.TrimSpace(r.FormValue("api_key")) != "":
			feed.APIKey = strings.TrimSpace(r.FormValue("api_key"))
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

	h.auditLog(r, "feed_config_save", map[string]string{
		"feed":               feed.Name,
		"enabled":            strconv.FormatBool(feed.Enabled),
		"mode":               string(feed.Mode),
		"sync_interval":      formatOptionalDuration(feed.SyncInterval),
		"api_key_configured": strconv.FormatBool(strings.TrimSpace(feed.APIKey) != ""),
	})

	http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape("Feed configuration saved. Restart the server to apply changes."), http.StatusSeeOther)
}

// HandleFeedConfigReset handles POST /admin/feeds/reset.
func (h *AdminHandler) HandleFeedConfigReset(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	feedName := config.NormalizeFeedName(r.FormValue("feed_name"))
	if _, ok := h.cfg.FeedSettings(feedName); !ok {
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Unknown feed"), http.StatusSeeOther)
		return
	}

	if err := h.store.DeleteFeedConfig(r.Context(), feedName); err != nil {
		h.logger.Error("admin feeds: failed to reset config", "feed", feedName, "error", err)
		http.Redirect(w, r, "/admin/feeds?err="+url.QueryEscape("Failed to reset feed configuration"), http.StatusSeeOther)
		return
	}

	h.auditLog(r, "feed_config_reset", map[string]string{"feed": feedName})
	http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape("Feed configuration reset to runtime defaults."), http.StatusSeeOther)
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
