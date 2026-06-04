package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

const (
	adminPasswordMinLength           = 12
	bootstrapRotationRequiredMessage = "Change the bootstrap password before making admin changes."
)

type manualAdvisoryView struct {
	ID          string
	FindingType string
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

func (h *AdminHandler) requireBootstrapPasswordRotated(w http.ResponseWriter, r *http.Request, redirectPath string) bool {
	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil {
		h.logger.Error("admin write blocked: failed to check bootstrap password state", "error", err)
		redirectAdminError(w, r, redirectPath, "Failed to verify admin password state")
		return false
	}
	if adminAuth == nil || !adminAuth.PasswordIsBootstrap {
		return true
	}

	h.auditLog(r, "bootstrap_rotation_required", map[string]string{"path": r.URL.Path})
	if isHTMXRequest(r) && strings.HasPrefix(redirectPath, "/admin/feeds") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		if renderErr := h.renderer.RenderPartial(w, "admin/feeds.html", "admin-feed-flash", adminFeedFlashData{
			Error: bootstrapRotationRequiredMessage,
		}); renderErr != nil {
			h.logger.Error("admin feeds: bootstrap flash render failed", "error", renderErr)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return false
	}

	redirectAdminError(w, r, redirectPath, bootstrapRotationRequiredMessage)
	return false
}

func redirectAdminError(w http.ResponseWriter, r *http.Request, path, message string) {
	http.Redirect(w, r, path+"?err="+url.QueryEscape(message), http.StatusSeeOther)
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

	// Count UNKNOWN-severity vulnerabilities for the NVD info hint.
	unknownCount := 0
	if stats, statsErr := h.store.DashboardStats(ctx); statsErr == nil && stats != nil {
		unknownCount = stats.BySeverity["UNKNOWN"]
	}

	data := map[string]any{
		"ActiveNav":            "admin",
		"CSRFToken":            csrfToken,
		"Feeds":                h.adminFeedRows(feeds),
		"EditableFeeds":        h.adminFeedFormRows(overrides),
		"DefaultSyncInterval":  defaultSyncInterval,
		"UnknownSeverityCount": unknownCount,
		"Message":              r.URL.Query().Get("msg"),
		"Error":                r.URL.Query().Get("err"),
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
		"Error":      r.URL.Query().Get("err"),
	}
	h.renderAdmin(w, "admin/queue.html", data)
}

// HandleQueuePurge handles POST /admin/queue/purge to remove completed/errored jobs.
func (h *AdminHandler) HandleQueuePurge(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/queue") {
		return
	}

	purged, err := h.store.PurgeQueue(r.Context())
	if err != nil {
		h.logger.Error("admin queue purge failed", "error", err)
		http.Redirect(w, r, "/admin/queue?err="+url.QueryEscape("Purge failed"), http.StatusSeeOther)
		return
	}

	h.auditLog(r, "queue_purge", map[string]string{"purged": strconv.Itoa(purged)})

	msg := fmt.Sprintf("Purged %d completed/errored jobs.", purged)
	http.Redirect(w, r, "/admin/queue?msg="+msg, http.StatusSeeOther)
}

// HandleQueuePriorityUpdate handles POST /admin/queue/priority.
func (h *AdminHandler) HandleQueuePriorityUpdate(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/queue") {
		return
	}

	jobID, ok := queueJobIDFromForm(w, r)
	if !ok {
		return
	}
	priority, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("priority")))
	if err != nil || priority < 0 || priority > 9 {
		redirectQueue(w, r, "Invalid priority", true)
		return
	}

	if err := h.store.UpdateQueueJobPriority(r.Context(), jobID, priority); err != nil {
		h.logger.Error("admin queue priority update failed", "job_id", jobID, "error", err)
		redirectQueue(w, r, "Priority update failed", true)
		return
	}
	h.auditLog(r, "queue_priority_update", map[string]string{
		"job_id":   strconv.Itoa(jobID),
		"priority": strconv.Itoa(priority),
	})
	redirectQueue(w, r, "Priority updated", false)
}

// HandleQueuePause handles POST /admin/queue/pause.
func (h *AdminHandler) HandleQueuePause(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_pause", "Job paused", h.store.PauseQueueJob)
}

// HandleQueueResume handles POST /admin/queue/resume.
func (h *AdminHandler) HandleQueueResume(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_resume", "Job resumed", h.store.ResumeQueueJob)
}

// HandleQueueRetry handles POST /admin/queue/retry.
func (h *AdminHandler) HandleQueueRetry(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_retry", "Job queued for retry", h.store.RetryQueueJob)
}

// HandleQueueClear handles POST /admin/queue/clear.
func (h *AdminHandler) HandleQueueClear(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/queue") {
		return
	}

	status := strings.ToLower(strings.TrimSpace(r.PostForm.Get("status")))
	statuses := []string{status}
	if status == "all" {
		statuses = []string{"pending", "paused", "done", "error"}
	}

	cleared, err := h.store.ClearQueue(r.Context(), statuses)
	if err != nil {
		h.logger.Error("admin queue clear failed", "status", status, "error", err)
		redirectQueue(w, r, "Queue clear failed", true)
		return
	}
	h.auditLog(r, "queue_clear", map[string]string{
		"status":  status,
		"cleared": strconv.Itoa(cleared),
	})
	redirectQueue(w, r, fmt.Sprintf("Cleared %d queue jobs.", cleared), false)
}

func (h *AdminHandler) handleQueueJobAction(w http.ResponseWriter, r *http.Request, auditAction, message string, action func(context.Context, int) error) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/queue") {
		return
	}

	jobID, ok := queueJobIDFromForm(w, r)
	if !ok {
		return
	}
	if err := action(r.Context(), jobID); err != nil {
		h.logger.Error("admin queue action failed", "action", auditAction, "job_id", jobID, "error", err)
		redirectQueue(w, r, message+" failed", true)
		return
	}
	h.auditLog(r, auditAction, map[string]string{"job_id": strconv.Itoa(jobID)})
	redirectQueue(w, r, message, false)
}

func queueJobIDFromForm(w http.ResponseWriter, r *http.Request) (int, bool) {
	jobID, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("job_id")))
	if err != nil || jobID <= 0 {
		redirectQueue(w, r, "Invalid queue job ID", true)
		return 0, false
	}
	return jobID, true
}

func redirectQueue(w http.ResponseWriter, r *http.Request, message string, isError bool) {
	key := "msg"
	if isError {
		key = "err"
	}
	http.Redirect(w, r, "/admin/queue?"+key+"="+url.QueryEscape(message), http.StatusSeeOther)
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

	// Read the newly created key from session flash (one-time read)
	// instead of URL query parameter to avoid exposing it in logs and
	// browser history (SEC-H5).
	newKey := h.sm.GetFlash(sess.ID, "newkey")

	data := map[string]any{
		"ActiveNav": "admin",
		"CSRFToken": csrfToken,
		"Keys":      keyViews,
		"Message":   r.URL.Query().Get("msg"),
		"Error":     r.URL.Query().Get("err"),
		"NewKey":    newKey,
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

// DerefExpiresAt returns the dereferenced ExpiresAt time, or zero time if nil.
func (k apiKeyView) DerefExpiresAt() time.Time {
	if k.ExpiresAt != nil {
		return *k.ExpiresAt
	}
	return time.Time{}
}

// IsExpired reports whether the key is past its optional expiry timestamp.
func (k apiKeyView) IsExpired() bool {
	return k.APIKey.IsExpired(time.Now().UTC())
}

// HandleKeyCreate handles POST /admin/keys/create.
func (h *AdminHandler) HandleKeyCreate(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/keys") {
		return
	}

	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		http.Redirect(w, r, "/admin/keys?err=Key+name+is+required", http.StatusSeeOther)
		return
	}
	expiresAt, err := parseAPIKeyExpiresAt(r.PostForm.Get("expires_at"), time.Now().UTC())
	if err != nil {
		http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
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

	_, err = h.store.CreateAPIKey(r.Context(), name, keyHash, expiresAt)
	if err != nil {
		h.logger.Error("admin keys: failed to create key", "error", err)
		http.Redirect(w, r, "/admin/keys?err=Failed+to+create+key", http.StatusSeeOther)
		return
	}

	auditDetails := map[string]string{"name": name}
	if expiresAt != nil {
		auditDetails["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	h.auditLog(r, "api_key_create", auditDetails)

	// Store the plaintext key in a flash message so it is never exposed
	// in the URL query string (SEC-H5).
	h.sm.SetFlash(sess.ID, "newkey", plaintext)
	http.Redirect(w, r, "/admin/keys?msg=Key+created", http.StatusSeeOther)
}

func parseAPIKeyExpiresAt(raw string, now time.Time) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	layouts := []string{"2006-01-02T15:04", "2006-01-02", time.RFC3339}
	var (
		expiresAt time.Time
		parseErr  error
	)
	for _, layout := range layouts {
		expiresAt, parseErr = time.Parse(layout, raw)
		if parseErr == nil {
			expiresAt = expiresAt.UTC()
			if !expiresAt.After(now.UTC()) {
				return nil, fmt.Errorf("expiration must be in the future")
			}
			return &expiresAt, nil
		}
	}
	return nil, fmt.Errorf("invalid expiration timestamp")
}

// HandleKeyRevoke handles POST /admin/keys/revoke.
func (h *AdminHandler) HandleKeyRevoke(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/keys") {
		return
	}

	keyIDStr := r.PostForm.Get("key_id")
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
	if !parseAdminForm(w, r) {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/keys") {
		return
	}

	keyIDStr := r.PostForm.Get("key_id")
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
	advisories, err := h.store.ListManualAdvisories(r.Context(), 100)
	if err != nil {
		h.logger.Error("admin advisories: failed to list advisories", "error", err)
	}

	views := make([]manualAdvisoryView, 0, len(advisories))
	var editAdvisory *manualAdvisoryView
	editID := r.URL.Query().Get("edit")
	for _, advisory := range advisories {
		view := manualAdvisoryView{
			ID:          advisory.ID,
			FindingType: advisory.FindingType,
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
	if !parseAdminForm(w, r) {
		return
	}

	if !auth.ValidateCSRF(r, sess) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/advisories") {
		return
	}

	ecosystem := strings.ToLower(strings.TrimSpace(r.PostForm.Get("ecosystem")))
	name := strings.TrimSpace(r.PostForm.Get("name"))
	advisoryID := strings.TrimSpace(r.PostForm.Get("id"))
	findingType, ok := normalizeAdvisoryFindingType(r.PostForm.Get("finding_type"))
	if !ok {
		http.Redirect(w, r, "/admin/advisories?err=Invalid+finding+type", http.StatusSeeOther)
		return
	}
	severity := strings.ToUpper(strings.TrimSpace(r.PostForm.Get("severity")))
	riskType := strings.TrimSpace(r.PostForm.Get("risk_type"))
	summary := strings.TrimSpace(r.PostForm.Get("summary"))
	description := r.PostForm.Get("description")
	isEditing := advisoryID != ""

	if ecosystem == "" || name == "" || severity == "" || summary == "" {
		http.Redirect(w, r, "/admin/advisories?err=All+required+fields+must+be+filled", http.StatusSeeOther)
		return
	}

	// The HTML <select> only constrains the browser; a direct request can
	// submit arbitrary values. Validate against the supported sets so a
	// mistyped severity cannot silently rank 0 (and never block) and a bogus
	// ecosystem cannot create findings that never match a real scan.
	switch severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
	default:
		http.Redirect(w, r, "/admin/advisories?err=Invalid+severity", http.StatusSeeOther)
		return
	}
	if !domain.Ecosystem(ecosystem).Valid() {
		http.Redirect(w, r, "/admin/advisories?err=Unknown+ecosystem", http.StatusSeeOther)
		return
	}
	if len(name) > 256 || len(summary) > 1000 || len(description) > 8000 {
		http.Redirect(w, r, "/admin/advisories?err=Field+exceeds+maximum+length", http.StatusSeeOther)
		return
	}

	if advisoryID == "" {
		var err error
		advisoryID, err = generateManualAdvisoryID()
		if err != nil {
			h.logger.Error("admin advisories: failed to generate advisory ID", "error", err)
			http.Redirect(w, r, "/admin/advisories?err=Failed+to+generate+advisory+ID", http.StatusSeeOther)
			return
		}
	} else if !strings.HasPrefix(advisoryID, "manual:") {
		// Operator-supplied IDs must stay within the manual: namespace so they
		// cannot collide with and overwrite a feed-sourced advisory (e.g. a
		// CVE/GHSA ID) via ON CONFLICT (id) DO UPDATE.
		http.Redirect(w, r, "/admin/advisories?err=Advisory+ID+must+start+with+manual%3A", http.StatusSeeOther)
		return
	}
	if findingType == "malicious" && strings.TrimSpace(riskType) == "" {
		riskType = "other"
	}

	advisory := &db.ManualAdvisory{
		ID:          advisoryID,
		FindingType: findingType,
		Ecosystem:   ecosystem,
		Name:        name,
		RiskType:    riskType,
		Severity:    severity,
		Summary:     summary,
		Description: description,
	}

	if err := h.store.UpsertManualAdvisory(r.Context(), advisory); err != nil {
		h.logger.Error("admin advisories: failed to create advisory", "error", err)
		http.Redirect(w, r, "/admin/advisories?err=Failed+to+create+advisory", http.StatusSeeOther)
		return
	}

	h.auditLog(r, "advisory_create", map[string]string{
		"id":           advisoryID,
		"finding_type": findingType,
		"ecosystem":    ecosystem,
		"name":         name,
		"severity":     severity,
	})

	msg := "Advisory+created"
	if isEditing {
		msg = "Advisory+updated"
	}
	http.Redirect(w, r, "/admin/advisories?msg="+msg, http.StatusSeeOther)
}

func normalizeAdvisoryFindingType(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "malicious":
		return "malicious", true
	case "vulnerability":
		return "vulnerability", true
	default:
		return "", false
	}
}

func generateManualAdvisoryID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("manual:%s-%s-%s-%s-%s",
		encoded[0:8],
		encoded[8:12],
		encoded[12:16],
		encoded[16:20],
		encoded[20:32],
	), nil
}

// HandleAdvisoryDelete handles POST /admin/advisories/delete.
func (h *AdminHandler) HandleAdvisoryDelete(w http.ResponseWriter, r *http.Request) {
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
	if !h.requireBootstrapPasswordRotated(w, r, "/admin/advisories") {
		return
	}

	advisoryID := r.PostForm.Get("id")
	if advisoryID == "" {
		http.Redirect(w, r, "/admin/advisories?err=Missing+advisory+ID", http.StatusSeeOther)
		return
	}

	if err := h.store.DeleteManualAdvisory(r.Context(), advisoryID); err != nil {
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

	systemSettings, err := h.store.GetSystemSettings(ctx)
	if err != nil {
		h.logger.Error("admin settings: failed to get system settings", "error", err)
	}

	serverMode := "unknown"
	syncInterval := "unknown"
	syncOnStartup := "unknown"
	adminSessionTimeout := "unknown"
	metricsAddr := "unknown"
	databaseHost := "unknown"
	databaseName := "unknown"
	databaseSSLMode := "unknown"
	runtimeBlockThreshold := "CRITICAL"
	runtimeRateLimitPerMinute := 60
	runtimeRateLimitBurst := 60
	if h.cfg != nil {
		serverMode = string(h.cfg.Server.Mode)
		syncInterval = formatRuntimeDuration(h.cfg.FeedSync.Interval)
		syncOnStartup = strconv.FormatBool(h.cfg.FeedSync.OnStartup)
		adminSessionTimeout = formatRuntimeDuration(h.cfg.Admin.SessionTimeout)
		metricsAddr = h.cfg.Metrics.Addr()
		databaseHost = h.cfg.DB.Host
		databaseName = h.cfg.DB.Name
		databaseSSLMode = h.cfg.DB.SSLMode
		if h.cfg.Server.BlockThreshold != "" {
			runtimeBlockThreshold = h.cfg.Server.BlockThreshold
		}
		if h.cfg.Server.RateLimitPerMinute > 0 {
			runtimeRateLimitPerMinute = h.cfg.Server.RateLimitPerMinute
		}
		if h.cfg.Server.RateLimitBurst > 0 {
			runtimeRateLimitBurst = h.cfg.Server.RateLimitBurst
		}
	}
	formBlockThreshold := runtimeBlockThreshold
	formRateLimitPerMinute := runtimeRateLimitPerMinute
	formRateLimitBurst := runtimeRateLimitBurst
	var systemSettingsUpdatedAt time.Time
	hasSystemSettings := false
	hasSystemSettingsUpdatedAt := false
	if systemSettings != nil {
		hasSystemSettings = true
		if systemSettings.BlockThreshold != "" {
			formBlockThreshold = systemSettings.BlockThreshold
		}
		if systemSettings.RateLimitPerMinute > 0 {
			formRateLimitPerMinute = systemSettings.RateLimitPerMinute
		}
		if systemSettings.RateLimitBurst > 0 {
			formRateLimitBurst = systemSettings.RateLimitBurst
		}
		if !systemSettings.UpdatedAt.IsZero() {
			systemSettingsUpdatedAt = systemSettings.UpdatedAt
			hasSystemSettingsUpdatedAt = true
		}
	}

	data := map[string]any{
		"ActiveNav":                  "admin",
		"CSRFToken":                  csrfToken,
		"ServerMode":                 serverMode,
		"SyncInterval":               syncInterval,
		"FeedSyncOnStartup":          syncOnStartup,
		"AdminSessionTimeout":        adminSessionTimeout,
		"MetricsAddr":                metricsAddr,
		"DatabaseHost":               databaseHost,
		"DatabaseName":               databaseName,
		"DatabaseSSLMode":            databaseSSLMode,
		"RuntimeBlockThreshold":      runtimeBlockThreshold,
		"RuntimeRateLimitPerMinute":  runtimeRateLimitPerMinute,
		"RuntimeRateLimitBurst":      runtimeRateLimitBurst,
		"SystemBlockThreshold":       formBlockThreshold,
		"SystemRateLimitPerMinute":   formRateLimitPerMinute,
		"SystemRateLimitBurst":       formRateLimitBurst,
		"HasSystemSettings":          hasSystemSettings,
		"SystemSettingsUpdatedAt":    systemSettingsUpdatedAt,
		"HasSystemSettingsUpdatedAt": hasSystemSettingsUpdatedAt,
		"LastLoginAt":                lastLoginAt,
		"HasLastLoginAt":             hasLastLoginAt,
		"PasswordChangedAt":          passwordChangedAt,
		"HasPasswordChangedAt":       hasPasswordChangedAt,
		"MinPasswordLength":          adminPasswordMinLength,
		"Message":                    r.URL.Query().Get("msg"),
		"Error":                      r.URL.Query().Get("err"),
	}
	h.renderAdmin(w, "admin/settings.html", data)
}

// HandlePasswordChange handles POST /admin/settings/password.
func (h *AdminHandler) HandlePasswordChange(w http.ResponseWriter, r *http.Request) {
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

	currentPassword := r.PostForm.Get("current_password")
	newPassword := r.PostForm.Get("new_password")
	confirmPassword := r.PostForm.Get("confirm_password")

	if newPassword != confirmPassword {
		http.Redirect(w, r, "/admin/settings?err=New+passwords+do+not+match", http.StatusSeeOther)
		return
	}

	if len(newPassword) < adminPasswordMinLength {
		http.Redirect(w, r, fmt.Sprintf("/admin/settings?err=Password+must+be+at+least+%d+characters", adminPasswordMinLength), http.StatusSeeOther)
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

	if err := h.store.UpsertAdminAuth(r.Context(), newHash, false); err != nil {
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
