package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/db"
)

type manualAdvisoryView struct {
	ID          string
	Ecosystem   string
	Name        string
	Severity    string
	RiskType    string
	Summary     string
	Description string
}

// requireAdmin checks for a valid admin session and returns the session.
// If not authenticated, it redirects to the login page and returns nil.
func (h *AdminHandler) requireAdmin(w http.ResponseWriter, r *http.Request) *auth.Session {
	sess := h.sm.Get(r)
	if sess == nil || !sess.Admin {
		h.redirectToLogin(w, r)
		return nil
	}
	return sess
}

func (h *AdminHandler) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	h.sm.Delete(w, r)
	w.Header().Set("Cache-Control", "no-store")
	if isHTMXRequest(r) {
		w.Header().Set("HX-Redirect", "/admin/login")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// HandleAdminFeeds serves GET /admin/feeds with detailed feed configuration.
func (h *AdminHandler) HandleAdminFeeds(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	csrfToken, _ := auth.CSRFToken(sess)

	feeds, err := h.store.ListFeedSyncStatuses(ctx)
	if err != nil {
		h.logger.Error("admin feeds: failed to load statuses", "error", err)
	}
	overrides, err := h.store.ListFeedConfigs(ctx)
	if err != nil {
		h.logger.Error("admin feeds: failed to load config overrides", "error", err)
	}
	defaultSyncInterval := "unknown"
	if h.cfg != nil {
		defaultSyncInterval = formatRuntimeDuration(h.cfg.FeedSync.Interval)
	}

	data := map[string]any{
		"ActiveNav":           "admin",
		"CSRFToken":           csrfToken,
		"Feeds":               h.adminFeedRows(feeds),
		"EditableFeeds":       h.adminFeedFormRows(overrides),
		"DefaultSyncInterval": defaultSyncInterval,
		"Message":             r.URL.Query().Get("msg"),
		"Error":               r.URL.Query().Get("err"),
	}

	switch r.URL.Query().Get("partial") {
	case "runtime":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.renderer.RenderPartial(w, "admin/feeds.html", "admin-feed-runtime", data); err != nil {
			h.logger.Error("admin feeds: partial runtime render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	case "flash":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.renderer.RenderPartial(w, "admin/feeds.html", "admin-feed-flash", data); err != nil {
			h.logger.Error("admin feeds: partial flash render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}
	h.renderAdmin(w, "admin/feeds.html", data)
}

// HandleAdminQueue serves GET /admin/queue with queue stats and job list.
func (h *AdminHandler) HandleAdminQueue(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	csrfToken, _ := auth.CSRFToken(sess)

	queueStats, err := h.store.QueueStats(ctx)
	if err != nil {
		h.logger.Error("admin queue: failed to load stats", "error", err)
		queueStats = &db.QueueStatsResult{}
	}

	jobs, err := h.store.ListQueueJobs(ctx, "", 50)
	if err != nil {
		h.logger.Error("admin queue: failed to load jobs", "error", err)
	}

	data := map[string]any{
		"ActiveNav":  "admin",
		"CSRFToken":  csrfToken,
		"QueueStats": queueStats,
		"Jobs":       jobs,
		"Message":    r.URL.Query().Get("msg"),
	}
	h.renderAdmin(w, "admin/queue.html", data)
}

// HandleQueuePurge handles POST /admin/queue/purge to remove completed/errored jobs.
func (h *AdminHandler) HandleQueuePurge(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	purged, err := h.store.PurgeQueue(r.Context())
	if err != nil {
		h.logger.Error("admin queue purge failed", "error", err)
		http.Redirect(w, r, "/admin/queue?msg=Purge+failed", http.StatusSeeOther)
		return
	}

	h.auditLog(r, "queue_purge", map[string]string{"purged": strconv.Itoa(purged)})

	msg := fmt.Sprintf("Purged %d completed/errored jobs.", purged)
	http.Redirect(w, r, "/admin/queue?msg="+msg, http.StatusSeeOther)
}

// HandleAdminKeys serves GET /admin/keys with API key list.
func (h *AdminHandler) HandleAdminKeys(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	csrfToken, _ := auth.CSRFToken(sess)

	keys, err := h.store.ListAPIKeys(ctx)
	if err != nil {
		h.logger.Error("admin keys: failed to load keys", "error", err)
	}

	// Wrap keys in view model to safely dereference optional timestamps.
	keyViews := make([]apiKeyView, len(keys))
	for i, k := range keys {
		keyViews[i] = apiKeyView{APIKey: k}
	}

	data := map[string]any{
		"ActiveNav": "admin",
		"CSRFToken": csrfToken,
		"Keys":      keyViews,
		"Message":   r.URL.Query().Get("msg"),
		"Error":     r.URL.Query().Get("err"),
		"NewKey":    r.URL.Query().Get("newkey"),
	}
	h.renderAdmin(w, "admin/keys.html", data)
}

// apiKeyView wraps db.APIKey with template-friendly accessor methods.
type apiKeyView struct {
	db.APIKey
}

// DerefLastUsedAt returns the dereferenced LastUsedAt time, or zero time
// if nil. Used by templates.
func (k apiKeyView) DerefLastUsedAt() time.Time {
	if k.LastUsedAt != nil {
		return *k.LastUsedAt
	}
	return time.Time{}
}

// HandleKeyCreate handles POST /admin/keys/create.
func (h *AdminHandler) HandleKeyCreate(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		http.Redirect(w, r, "/admin/keys?err=Key+name+is+required", http.StatusSeeOther)
		return
	}

	// Generate a random API key.
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		h.logger.Error("admin keys: failed to generate key", "error", err)
		http.Redirect(w, r, "/admin/keys?err=Failed+to+generate+key", http.StatusSeeOther)
		return
	}
	plaintext := hex.EncodeToString(rawKey)

	keyHash := sha256Hash(plaintext)

	_, err := h.store.CreateAPIKey(r.Context(), name, keyHash)
	if err != nil {
		h.logger.Error("admin keys: failed to create key", "error", err)
		http.Redirect(w, r, "/admin/keys?err=Failed+to+create+key", http.StatusSeeOther)
		return
	}

	h.auditLog(r, "api_key_create", map[string]string{"name": name})

	http.Redirect(w, r, "/admin/keys?newkey="+plaintext, http.StatusSeeOther)
}

// HandleKeyRevoke handles POST /admin/keys/revoke.
func (h *AdminHandler) HandleKeyRevoke(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	keyIDStr := r.FormValue("key_id")
	keyID, err := strconv.Atoi(keyIDStr)
	if err != nil {
		http.Redirect(w, r, "/admin/keys?err=Invalid+key+ID", http.StatusSeeOther)
		return
	}

	if err := h.store.RevokeAPIKey(r.Context(), keyID); err != nil {
		h.logger.Error("admin keys: failed to revoke key", "error", err, "key_id", keyID)
		http.Redirect(w, r, "/admin/keys?err=Failed+to+revoke+key", http.StatusSeeOther)
		return
	}

	h.auditLog(r, "api_key_revoke", map[string]string{"key_id": keyIDStr})

	http.Redirect(w, r, "/admin/keys?msg=Key+revoked", http.StatusSeeOther)
}

// HandleKeyDelete handles POST /admin/keys/delete.
func (h *AdminHandler) HandleKeyDelete(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	keyIDStr := r.FormValue("key_id")
	keyID, err := strconv.Atoi(keyIDStr)
	if err != nil {
		http.Redirect(w, r, "/admin/keys?err=Invalid+key+ID", http.StatusSeeOther)
		return
	}

	if err := h.store.DeleteAPIKey(r.Context(), keyID); err != nil {
		h.logger.Error("admin keys: failed to delete key", "error", err, "key_id", keyID)
		http.Redirect(w, r, "/admin/keys?err=Failed+to+delete+key", http.StatusSeeOther)
		return
	}

	h.auditLog(r, "api_key_delete", map[string]string{"key_id": keyIDStr})

	http.Redirect(w, r, "/admin/keys?msg=Key+deleted", http.StatusSeeOther)
}

// HandleAdminAdvisories serves GET /admin/advisories with the manual advisory form.
func (h *AdminHandler) HandleAdminAdvisories(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	csrfToken, _ := auth.CSRFToken(sess)
	advisories, err := h.store.ListMaliciousFindings(r.Context(), "manual", 100)
	if err != nil {
		h.logger.Error("admin advisories: failed to list advisories", "error", err)
	}

	views := make([]manualAdvisoryView, 0, len(advisories))
	var editAdvisory *manualAdvisoryView
	editID := r.URL.Query().Get("edit")
	for _, advisory := range advisories {
		view := manualAdvisoryView{
			ID:          advisory.ID,
			Ecosystem:   advisory.Ecosystem,
			Name:        advisory.Name,
			Severity:    advisory.Severity,
			RiskType:    advisory.RiskType,
			Summary:     advisory.Summary,
			Description: advisory.Description,
		}
		views = append(views, view)
		if editID != "" && advisory.ID == editID {
			copyValue := view
			editAdvisory = &copyValue
		}
	}

	data := map[string]any{
		"ActiveNav":    "admin",
		"CSRFToken":    csrfToken,
		"Message":      r.URL.Query().Get("msg"),
		"Error":        r.URL.Query().Get("err"),
		"Advisories":   views,
		"EditAdvisory": editAdvisory,
		"IsEditing":    editAdvisory != nil,
	}
	h.renderAdmin(w, "admin/advisories.html", data)
}

// HandleAdvisoryCreate handles POST /admin/advisories/create.
func (h *AdminHandler) HandleAdvisoryCreate(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	ecosystem := r.FormValue("ecosystem")
	name := r.FormValue("name")
	advisoryID := r.FormValue("id")
	severity := r.FormValue("severity")
	riskType := r.FormValue("risk_type")
	summary := r.FormValue("summary")
	description := r.FormValue("description")

	if ecosystem == "" || name == "" || severity == "" || summary == "" {
		http.Redirect(w, r, "/admin/advisories?err=All+required+fields+must+be+filled", http.StatusSeeOther)
		return
	}

	mf := &db.MaliciousFinding{
		ID:          advisoryID,
		Ecosystem:   ecosystem,
		Name:        name,
		Source:      "manual",
		RiskType:    riskType,
		Severity:    severity,
		Summary:     summary,
		Description: description,
		CreatedBy:   "admin",
	}

	if err := h.store.UpsertMaliciousFinding(r.Context(), mf); err != nil {
		h.logger.Error("admin advisories: failed to create advisory", "error", err)
		http.Redirect(w, r, "/admin/advisories?err=Failed+to+create+advisory", http.StatusSeeOther)
		return
	}

	h.auditLog(r, "advisory_create", map[string]string{
		"id":        advisoryID,
		"ecosystem": ecosystem,
		"name":      name,
		"severity":  severity,
	})

	msg := "Advisory+created"
	if advisoryID != "" {
		msg = "Advisory+updated"
	}
	http.Redirect(w, r, "/admin/advisories?msg="+msg, http.StatusSeeOther)
}

// HandleAdvisoryDelete handles POST /admin/advisories/delete.
func (h *AdminHandler) HandleAdvisoryDelete(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	advisoryID := r.FormValue("id")
	if advisoryID == "" {
		http.Redirect(w, r, "/admin/advisories?err=Missing+advisory+ID", http.StatusSeeOther)
		return
	}

	if err := h.store.DeleteMaliciousFinding(r.Context(), advisoryID); err != nil {
		h.logger.Error("admin advisories: failed to delete advisory", "error", err, "id", advisoryID)
		http.Redirect(w, r, "/admin/advisories?err=Failed+to+delete+advisory", http.StatusSeeOther)
		return
	}

	h.auditLog(r, "advisory_delete", map[string]string{"id": advisoryID})
	http.Redirect(w, r, "/admin/advisories?msg=Advisory+deleted", http.StatusSeeOther)
}

// HandleAdminAudit serves GET /admin/audit with the audit log table.
func (h *AdminHandler) HandleAdminAudit(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	csrfToken, _ := auth.CSRFToken(sess)

	entries, err := h.store.ListAdminAuditLog(ctx, 100)
	if err != nil {
		h.logger.Error("admin audit: failed to load entries", "error", err)
	}

	// Wrap entries with a string representation of the JSON details.
	views := make([]auditLogView, len(entries))
	for i, e := range entries {
		detailsStr := string(e.Details)
		if detailsStr == "" || detailsStr == "null" {
			detailsStr = "-"
		}
		views[i] = auditLogView{
			AdminAuditLogEntry: e,
			DetailsStr:         detailsStr,
		}
	}

	data := map[string]any{
		"ActiveNav": "admin",
		"CSRFToken": csrfToken,
		"Entries":   views,
	}
	h.renderAdmin(w, "admin/audit.html", data)
}

// auditLogView wraps db.AdminAuditLogEntry with a string representation
// of the Details JSON for template display.
type auditLogView struct {
	db.AdminAuditLogEntry
	DetailsStr string
}

// HandleAdminSettings serves GET /admin/settings.
func (h *AdminHandler) HandleAdminSettings(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	csrfToken, _ := auth.CSRFToken(sess)

	adminAuth, err := h.store.GetAdminAuth(ctx)
	if err != nil {
		h.logger.Error("admin settings: failed to get auth info", "error", err)
	}

	var (
		lastLoginAt          time.Time
		passwordChangedAt    time.Time
		hasLastLoginAt       bool
		hasPasswordChangedAt bool
	)
	if adminAuth != nil {
		if adminAuth.LastLoginAt != nil {
			lastLoginAt = *adminAuth.LastLoginAt
			hasLastLoginAt = true
		}
		if adminAuth.PasswordChangedAt != nil {
			passwordChangedAt = *adminAuth.PasswordChangedAt
			hasPasswordChangedAt = true
		}
	}

	serverMode := "unknown"
	syncInterval := "unknown"
	syncOnStartup := "unknown"
	adminSessionTimeout := "unknown"
	metricsAddr := "unknown"
	databaseHost := "unknown"
	databaseName := "unknown"
	databaseSSLMode := "unknown"
	if h.cfg != nil {
		serverMode = string(h.cfg.Server.Mode)
		syncInterval = formatRuntimeDuration(h.cfg.FeedSync.Interval)
		syncOnStartup = strconv.FormatBool(h.cfg.FeedSync.OnStartup)
		adminSessionTimeout = formatRuntimeDuration(h.cfg.Admin.SessionTimeout)
		metricsAddr = h.cfg.Metrics.Addr()
		databaseHost = h.cfg.DB.Host
		databaseName = h.cfg.DB.Name
		databaseSSLMode = h.cfg.DB.SSLMode
	}

	data := map[string]any{
		"ActiveNav":            "admin",
		"CSRFToken":            csrfToken,
		"ServerMode":           serverMode,
		"SyncInterval":         syncInterval,
		"FeedSyncOnStartup":    syncOnStartup,
		"AdminSessionTimeout":  adminSessionTimeout,
		"MetricsAddr":          metricsAddr,
		"DatabaseHost":         databaseHost,
		"DatabaseName":         databaseName,
		"DatabaseSSLMode":      databaseSSLMode,
		"LastLoginAt":          lastLoginAt,
		"HasLastLoginAt":       hasLastLoginAt,
		"PasswordChangedAt":    passwordChangedAt,
		"HasPasswordChangedAt": hasPasswordChangedAt,
		"Message":              r.URL.Query().Get("msg"),
		"Error":                r.URL.Query().Get("err"),
	}
	h.renderAdmin(w, "admin/settings.html", data)
}

// HandlePasswordChange handles POST /admin/settings/password.
func (h *AdminHandler) HandlePasswordChange(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	if newPassword != confirmPassword {
		http.Redirect(w, r, "/admin/settings?err=New+passwords+do+not+match", http.StatusSeeOther)
		return
	}

	if len(newPassword) < 8 {
		http.Redirect(w, r, "/admin/settings?err=Password+must+be+at+least+8+characters", http.StatusSeeOther)
		return
	}

	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil || adminAuth == nil {
		http.Redirect(w, r, "/admin/settings?err=Failed+to+verify+current+password", http.StatusSeeOther)
		return
	}

	if !auth.CheckPassword(adminAuth.PasswordHash, currentPassword) {
		h.auditLog(r, "password_change_failed", map[string]string{
			"reason": "invalid current password",
		})
		http.Redirect(w, r, "/admin/settings?err=Current+password+is+incorrect", http.StatusSeeOther)
		return
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		h.logger.Error("admin settings: failed to hash new password", "error", err)
		http.Redirect(w, r, "/admin/settings?err=Failed+to+update+password", http.StatusSeeOther)
		return
	}

	if err := h.store.UpsertAdminAuth(r.Context(), newHash); err != nil {
		h.logger.Error("admin settings: failed to update password", "error", err)
		http.Redirect(w, r, "/admin/settings?err=Failed+to+update+password", http.StatusSeeOther)
		return
	}

	h.auditLog(r, "password_change", map[string]string{})

	http.Redirect(w, r, "/admin/settings?msg=Password+changed+successfully", http.StatusSeeOther)
}

// renderAdmin is a helper that renders an admin template with error handling.
func (h *AdminHandler) renderAdmin(w http.ResponseWriter, tmpl string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := h.renderer.Render(w, tmpl, data); err != nil {
		h.logger.Error("admin render failed", "template", tmpl, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// sha256Hash returns the hex-encoded SHA-256 hash of a string.
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
