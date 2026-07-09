package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	feedstatus "github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/web"
)

type adminFeedFlashData struct {
	Message string
	Error   string
}

const maxAdminFormBytes = 1 << 20

type adminPostGate struct {
	csrfAction            string
	bootstrapRedirectPath string
}

var (
	failedFeedConfigLoadMessage    = web.Message("admin.feeds.error.load_config")
	adminInvalidRequestMessage     = web.Message("admin.form.error.invalid_request")
	adminInvalidFormMessage        = web.Message("admin.form.error.invalid_payload")
	errInvalidFeedMode             = errors.New(web.Message("admin.feeds.error.invalid_mode"))
	errInvalidFeedSyncInterval     = errors.New(web.Message("admin.feeds.error.invalid_sync_interval"))
	errAmbiguousFeedAPIKeyAction   = errors.New(web.Message("admin.feeds.error.ambiguous_api_key_action"))
	errUnconfirmedFeedAPIKeyClear  = errors.New(web.Message("admin.feeds.error.unconfirmed_api_key_clear"))
	errFeedConfigSaveApplyFailed   = errors.New(web.Message("admin.feeds.error.save_apply_failed"))
	errFeedConfigApplyUnavailable  = errors.New(web.Message("admin.feeds.error.apply_unavailable"))
	errFeedConfigSaveConflict      = errors.New(web.Message("admin.feeds.error.save_conflict"))
	errFeedConfigSaveAuditFailed   = errors.New(web.Message("admin.feeds.error.audit_log"))
	errFeedConfigSavePersistFailed = errors.New(web.Message("admin.feeds.error.save_persist"))
	errFeedConfigResetUnavailable  = errors.New(web.Message("admin.feeds.error.reset_unavailable"))
)

func parseAdminForm(w http.ResponseWriter, r *http.Request) bool {
	return parseAdminFormWithError(w, r, func(status int) {
		http.Error(w, "invalid form payload", status)
	})
}

func parseAdminPostForm(w http.ResponseWriter, r *http.Request, redirectPath string) bool {
	return parseAdminFormWithError(w, r, func(int) {
		redirectAdminFormError(w, r, redirectPath, adminInvalidFormMessage)
	})
}

func parseAdminFormWithError(w http.ResponseWriter, r *http.Request, respond func(status int)) bool {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBytes)
	}
	if err := r.ParseForm(); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "request body too large") {
			status = http.StatusRequestEntityTooLarge
		}
		respond(status)
		return false
	}
	return true
}

func (h *AdminHandler) requireAdminPost(w http.ResponseWriter, r *http.Request, gate adminPostGate) (*auth.Session, bool) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return nil, false
	}
	redirectPath := adminPostRedirectPath(r, gate)
	if !parseAdminPostForm(w, r, redirectPath) {
		return nil, false
	}
	if !auth.ValidateCSRF(r, sess) {
		h.rejectInvalidAdminCSRF(w, r, gate.csrfAction, redirectPath)
		return nil, false
	}
	if gate.bootstrapRedirectPath != "" && !h.requireBootstrapPasswordRotated(w, r, gate.bootstrapRedirectPath) {
		return nil, false
	}
	return sess, true
}

func adminPostRedirectPath(r *http.Request, gate adminPostGate) string {
	if gate.bootstrapRedirectPath != "" {
		return gate.bootstrapRedirectPath
	}
	if r == nil || r.URL == nil {
		return "/admin/"
	}
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/admin/feeds/"):
		return "/admin/feeds"
	case strings.HasPrefix(path, "/admin/queue/"):
		return "/admin/queue"
	case strings.HasPrefix(path, "/admin/keys/"):
		return "/admin/keys"
	case strings.HasPrefix(path, "/admin/advisories/"):
		return "/admin/advisories"
	case strings.HasPrefix(path, "/admin/settings/"):
		return "/admin/settings"
	default:
		return "/admin/"
	}
}

func redirectAdminFormError(w http.ResponseWriter, r *http.Request, path, message string) {
	if path == "" || !strings.HasPrefix(path, "/admin/") || strings.HasPrefix(path, "//") {
		path = "/admin/"
	}
	redirectAdminError(w, r, path, message)
}

// HandleFeedConfigSave handles POST /admin/feeds/save.
func (h *AdminHandler) HandleFeedConfigSave(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "feed_config_save",
		bootstrapRedirectPath: "/admin/feeds",
	}); !ok {
		return
	}

	feedName := r.PostForm.Get("feed_name")
	feed, err := h.desiredFeedSettings(r.Context(), feedName)
	if err != nil {
		errMsg := desiredFeedSettingsRedirectError(err)
		if errMsg == failedFeedConfigLoadMessage && h.logger != nil {
			h.logger.Error("admin feeds: failed to load desired feed configuration", h.adminLogAttrs(r, "feed", config.NormalizeFeedName(feedName), "error", err)...)
		}
		redirectAdminFeedsError(w, r, errMsg, feedName)
		return
	}
	previous, err := h.store.GetFeedConfig(r.Context(), feed.Name)
	if err != nil {
		h.logger.Error("admin feeds: failed to load previous config", h.adminLogAttrs(r, "feed", feed.Name, "error", err)...)
		redirectAdminFeedsError(w, r, failedFeedConfigLoadMessage, feed.Name)
		return
	}

	feed, err = parseFeedSettingsForm(feed, r.PostForm)
	if err != nil {
		redirectAdminFeedsError(w, r, err.Error(), feed.Name)
		return
	}

	record := feedConfigRecordFromRuntimeSetting(feed, previous)
	appliedRuntime, err := h.persistAndApplyFeedConfig(r, feed, previous, record)
	if err != nil {
		redirectAdminFeedsError(w, r, err.Error(), feed.Name)
		return
	}

	if appliedRuntime {
		http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape(web.Message("admin.feeds.flash.saved_applied")), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape(web.Message("admin.feeds.flash.saved")), http.StatusSeeOther)
}

func desiredFeedSettingsRedirectError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "load persisted feed config:") {
		return failedFeedConfigLoadMessage
	}
	return msg
}

func parseFeedSettingsForm(feed config.FeedSettings, form url.Values) (config.FeedSettings, error) {
	mode, err := config.ParseFeedMode(form.Get("mode"))
	if err != nil {
		return feed, errInvalidFeedMode
	}
	feed.Mode = mode
	feed.Enabled = form.Get("enabled") == "on"

	if feed.SupportsSyncInterval {
		rawInterval := strings.TrimSpace(form.Get("sync_interval"))
		if rawInterval == "" {
			feed.SyncInterval = 0
		} else {
			interval, err := time.ParseDuration(rawInterval)
			if err != nil || interval <= 0 {
				return feed, errInvalidFeedSyncInterval
			}
			feed.SyncInterval = interval
		}
	}

	feed, err = applyFeedAPIKeyFormAction(feed, form)
	if err != nil {
		return feed, err
	}
	if err := config.ValidateFeedSettings(feed); err != nil {
		return feed, err
	}
	return feed, nil
}

func applyFeedAPIKeyFormAction(feed config.FeedSettings, form url.Values) (config.FeedSettings, error) {
	if !feed.SupportsAPIKey {
		return feed, nil
	}
	rawAPIKey := strings.TrimSpace(form.Get("api_key"))
	clearAPIKey := form.Get("clear_api_key") == "on"
	switch {
	case clearAPIKey && rawAPIKey != "":
		return feed, errAmbiguousFeedAPIKeyAction
	case clearAPIKey && form.Get("confirm_clear_api_key") != "on":
		return feed, errUnconfirmedFeedAPIKeyClear
	case clearAPIKey:
		feed.APIKey = ""
	case rawAPIKey != "":
		feed.APIKey = rawAPIKey
	}
	return feed, nil
}

func feedConfigRecordFromRuntimeSetting(feed config.FeedSettings, previous *db.FeedConfig) *db.FeedConfig {
	record := &db.FeedConfig{
		FeedName:          feed.Name,
		Enabled:           feed.Enabled,
		Mode:              string(feed.Mode),
		APIKey:            feed.APIKey,
		ExpectedUpdatedAt: feedConfigRevisionExpectation(previous),
	}
	if feed.SupportsSyncInterval && feed.SyncInterval > 0 {
		interval := feed.SyncInterval
		record.SyncInterval = &interval
	}
	return record
}

func (h *AdminHandler) persistAndApplyFeedConfig(r *http.Request, feed config.FeedSettings, previous *db.FeedConfig, record *db.FeedConfig) (bool, error) {
	previousRuntime, previousRuntimeOK := h.cfg.FeedSettings(feed.Name)
	correlationID := adminRequestCorrelationID(r)

	if h.applyFeedConfig == nil {
		h.logger.Error("admin feeds: runtime apply callback is not configured", adminLogAttrsForCorrelationID(correlationID, "feed", feed.Name)...)
		return false, errFeedConfigApplyUnavailable
	}

	appliedRuntime := false
	if err := h.applyFeedConfig(r.Context(), feed); err != nil {
		h.logger.Error("admin feeds: failed to apply config", adminLogAttrsForCorrelationID(correlationID, "feed", feed.Name, "error", err)...)
		h.restoreRuntimeFeedConfig(r.Context(), correlationID, previousRuntime, previousRuntimeOK, feed, true, "save apply failure")
		return false, errFeedConfigSaveApplyFailed
	}
	appliedRuntime = true

	audit := h.adminAuditEntry(r, "feed_config_save", feedConfigAuditDetails(feed.Name, previous, record))
	auditCtx, cancel := h.adminAuditContext()
	defer cancel()
	if err := h.store.UpsertFeedConfigWithAudit(auditCtx, record, audit); err != nil {
		h.logger.Error("admin feeds: failed to save config", adminLogAttrsForCorrelationID(correlationID, "feed", feed.Name, "error", err)...)
		if appliedRuntime {
			h.restoreRuntimeFeedConfig(r.Context(), correlationID, previousRuntime, previousRuntimeOK, feed, true, "save persistence failure")
		}
		if errors.Is(err, db.ErrConflict) {
			return appliedRuntime, errFeedConfigSaveConflict
		}
		if errors.Is(err, db.ErrAdminAuditLog) {
			return appliedRuntime, errFeedConfigSaveAuditFailed
		}
		return appliedRuntime, errFeedConfigSavePersistFailed
	}

	return appliedRuntime, nil
}

func feedConfigRevisionExpectation(previous *db.FeedConfig) *time.Time {
	if previous == nil {
		zero := time.Time{}
		return &zero
	}
	if previous.UpdatedAt.IsZero() {
		return nil
	}
	updatedAt := previous.UpdatedAt.UTC()
	return &updatedAt
}

func (h *AdminHandler) restoreRuntimeFeedConfig(ctx context.Context, correlationID string, previous config.FeedSettings, previousOK bool, applied config.FeedSettings, appliedOK bool, reason string) {
	if !previousOK || !appliedOK || h.applyFeedConfig == nil || h.cfg == nil {
		return
	}
	current, currentOK := h.cfg.FeedSettings(applied.Name)
	if !currentOK || !sameRuntimeFeedSettings(current, applied) {
		h.logger.Warn("admin feeds: skipped stale runtime rollback", adminLogAttrsForCorrelationID(correlationID, "feed", applied.Name, "reason", reason)...)
		return
	}
	if err := h.applyFeedConfig(ctx, previous); err != nil {
		h.logger.Error("admin feeds: failed to roll back runtime config", adminLogAttrsForCorrelationID(correlationID, "feed", previous.Name, "reason", reason, "error", err)...)
	}
}

func sameRuntimeFeedSettings(a, b config.FeedSettings) bool {
	return config.NormalizeFeedName(a.Name) == config.NormalizeFeedName(b.Name) &&
		a.Enabled == b.Enabled &&
		a.Mode == b.Mode &&
		a.SyncInterval == b.SyncInterval &&
		strings.TrimSpace(a.APIKey) == strings.TrimSpace(b.APIKey)
}

// HandleFeedConfigReset handles POST /admin/feeds/reset.
func (h *AdminHandler) HandleFeedConfigReset(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "feed_config_reset",
		bootstrapRedirectPath: "/admin/feeds",
	}); !ok {
		return
	}

	feedName := config.NormalizeFeedName(r.PostForm.Get("feed_name"))
	previousRuntime, previousRuntimeOK := h.cfg.FeedSettings(feedName)
	if !previousRuntimeOK {
		redirectAdminFeedsError(w, r, web.Message("admin.feeds.error.unknown_feed"), feedName)
		return
	}
	if r.PostForm.Get("confirm_reset") != "on" {
		redirectAdminFeedsError(w, r, web.Message("admin.feeds.error.confirm_reset"), feedName)
		return
	}

	previous, err := h.store.GetFeedConfig(r.Context(), feedName)
	if err != nil {
		h.logger.Error("admin feeds: failed to load previous config", h.adminLogAttrs(r, "feed", feedName, "error", err)...)
		redirectAdminFeedsError(w, r, web.Message("admin.feeds.error.load_config"), feedName)
		return
	}

	appliedRuntime := false
	var resetRuntime config.FeedSettings
	resetRuntimeOK := false
	correlationID := adminRequestCorrelationID(r)
	if h.resetFeedConfig == nil {
		h.logger.Error("admin feeds: runtime reset callback is not configured", adminLogAttrsForCorrelationID(correlationID, "feed", feedName)...)
		redirectAdminFeedsError(w, r, errFeedConfigResetUnavailable.Error(), feedName)
		return
	}
	var resetErr error
	resetRuntime, resetRuntimeOK, resetErr = h.resetFeedConfig(r.Context(), feedName)
	if resetErr != nil {
		h.logger.Error("admin feeds: failed to apply reset config", adminLogAttrsForCorrelationID(correlationID, "feed", feedName, "error", resetErr)...)
		h.restoreRuntimeFeedConfig(r.Context(), correlationID, previousRuntime, previousRuntimeOK, resetRuntime, resetRuntimeOK, "reset apply failure")
		redirectAdminFeedsError(w, r, web.Message("admin.feeds.error.reset_apply_failed"), feedName)
		return
	}
	if !resetRuntimeOK {
		h.logger.Error("admin feeds: runtime reset callback did not apply config", adminLogAttrsForCorrelationID(correlationID, "feed", feedName)...)
		redirectAdminFeedsError(w, r, errFeedConfigResetUnavailable.Error(), feedName)
		return
	}
	appliedRuntime = true

	audit := h.adminAuditEntry(r, "feed_config_reset", feedConfigAuditDetails(feedName, previous, nil))
	auditCtx, cancel := h.adminAuditContext()
	defer cancel()
	if err := h.store.DeleteFeedConfigWithAudit(auditCtx, feedName, feedConfigRevisionExpectation(previous), audit); err != nil {
		h.logger.Error("admin feeds: failed to reset config", adminLogAttrsForCorrelationID(correlationID, "feed", feedName, "error", err)...)
		if appliedRuntime {
			h.restoreRuntimeFeedConfig(r.Context(), correlationID, previousRuntime, previousRuntimeOK, resetRuntime, resetRuntimeOK, "reset persistence failure")
		}
		if errors.Is(err, db.ErrConflict) {
			redirectAdminFeedsError(w, r, web.Message("admin.feeds.error.save_conflict"), feedName)
			return
		}
		if errors.Is(err, db.ErrAdminAuditLog) {
			redirectAdminFeedsError(w, r, web.Message("admin.feeds.error.audit_log"), feedName)
			return
		}
		redirectAdminFeedsError(w, r, web.Message("admin.feeds.error.reset_persist"), feedName)
		return
	}

	if appliedRuntime {
		http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape(web.Message("admin.feeds.flash.reset_applied")), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/feeds?msg="+url.QueryEscape(web.Message("admin.feeds.flash.reset")), http.StatusSeeOther)
}

func redirectAdminFeedsError(w http.ResponseWriter, r *http.Request, message, feedName string) {
	http.Redirect(w, r, adminFeedsRedirectURL("err", message, feedName), http.StatusSeeOther)
}

func adminFeedsRedirectURL(key, message, feedName string) string {
	values := url.Values{key: {message}}
	feedKey := config.NormalizeFeedName(feedName)
	if feedKey != "" {
		values.Set("feed", feedKey)
	}
	target := "/admin/feeds?" + values.Encode()
	if feedKey != "" {
		target += "#feed-" + feedKey
	}
	return target
}

// HandleFeedSyncNow handles POST /admin/feeds/sync.
func (h *AdminHandler) HandleFeedSyncNow(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "feed_sync_trigger",
		bootstrapRedirectPath: "/admin/feeds",
	}); !ok {
		return
	}

	feedName := config.NormalizeFeedName(r.PostForm.Get("feed_name"))
	feed, ok := h.cfg.FeedSettings(feedName)
	if !ok {
		h.respondFeedSyncResult(w, r, "", web.Message("admin.feeds.error.unknown_feed"), http.StatusBadRequest, false)
		return
	}
	if !feed.SupportsManualSync {
		h.respondFeedSyncResult(w, r, "", web.Message("admin.feeds.sync.error.unavailable_for_feed"), http.StatusBadRequest, false)
		return
	}
	if !feed.Enabled || feed.Mode != config.FeedModeSelf {
		h.respondFeedSyncResult(w, r, "", web.Message("admin.feeds.sync.error.enabled_self_only"), http.StatusBadRequest, false)
		return
	}
	if h.syncFeed == nil {
		h.respondFeedSyncResult(w, r, "", web.Message("admin.feeds.sync.error.unavailable_mode"), http.StatusBadRequest, false)
		return
	}
	started, err := h.beginManualFeedSyncAfterAudit(feed.Name, func() error {
		return h.auditLog(r, "feed_sync_trigger", map[string]string{
			"feed": feed.Name,
			"mode": string(feed.Mode),
		})
	})
	if err != nil {
		h.respondFeedSyncResult(w, r, "", web.Message("admin.feeds.error.audit_log"), http.StatusInternalServerError, false)
		return
	}
	if !started {
		h.respondFeedSyncResult(w, r, "", web.Message("admin.feeds.sync.error.already_running", feed.DisplayName), http.StatusConflict, false)
		return
	}

	correlationID := adminRequestCorrelationID(r)
	if err := h.markFeedSyncRunning(r.Context(), correlationID, feed.Name); err != nil {
		h.endManualFeedSync(feed.Name)
		h.respondFeedSyncResult(w, r, "", web.Message("admin.feeds.sync.error.status"), http.StatusInternalServerError, false)
		return
	}

	go func(feed config.FeedSettings) { // #nosec G118 -- manual sync intentionally outlives the request and is bounded by root context plus timeout.
		defer h.endManualFeedSync(feed.Name)

		rootCtx := h.rootCtx
		if rootCtx == nil {
			rootCtx = context.Background()
		}
		ctx, cancel := context.WithTimeout(rootCtx, 30*time.Minute)
		defer cancel()

		if err := h.syncFeed(ctx, feed.Name); err != nil {
			h.logger.Error("admin feeds: manual sync failed", adminLogAttrsForCorrelationID(correlationID, "feed", feed.Name, "error", err)...)
			return
		}
		h.logger.Info("admin feeds: manual sync finished", adminLogAttrsForCorrelationID(correlationID, "feed", feed.Name)...)
	}(feed)

	h.respondFeedSyncResult(w, r, web.Message("admin.feeds.sync.flash.started", feed.DisplayName), "", http.StatusOK, true)
}

func (h *AdminHandler) beginManualFeedSyncAfterAudit(feedName string, audit func() error) (bool, error) {
	if h == nil {
		return false, nil
	}
	name := config.NormalizeFeedName(feedName)
	h.manualSyncMu.Lock()
	if h.manualSyncs == nil {
		h.manualSyncs = make(map[string]struct{})
	}
	if _, exists := h.manualSyncs[name]; exists {
		h.manualSyncMu.Unlock()
		return false, nil
	}
	h.manualSyncMu.Unlock()

	if audit != nil {
		if err := audit(); err != nil {
			return false, err
		}
	}

	h.manualSyncMu.Lock()
	defer h.manualSyncMu.Unlock()
	if _, exists := h.manualSyncs[name]; exists {
		return false, nil
	}
	h.manualSyncs[name] = struct{}{}
	return true, nil
}

func (h *AdminHandler) beginManualFeedSync(feedName string) bool {
	started, err := h.beginManualFeedSyncAfterAudit(feedName, nil)
	return err == nil && started
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

func (h *AdminHandler) markFeedSyncRunning(ctx context.Context, correlationID, feedName string) error {
	now := time.Now().UTC()
	status := &db.FeedSyncStatus{
		FeedName:       feedName,
		LastSyncStatus: "running",
		UpdatedAt:      now,
	}

	if err := feedstatus.UpsertFeedSyncStatusPreservingData(ctx, h.store, status); err != nil {
		h.logger.Warn("admin feeds: failed to mark sync as running", adminLogAttrsForCorrelationID(correlationID, "feed", feedName, "error", err)...)
		return err
	}
	return nil
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
			h.logger.Error("admin feeds: flash render failed", h.adminLogAttrs(r, "error", renderErr)...)
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
		return config.FeedSettings{}, errors.New(web.Message("admin.feeds.error.unknown_feed"))
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
		return config.FeedSettings{}, fmt.Errorf("%s: invalid persisted mode: %w", web.Message("admin.feeds.error.load_config"), err)
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
