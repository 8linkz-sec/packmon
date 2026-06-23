package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/telemetry"
)

const (
	adminPasswordMinLength           = auth.MinAdminPasswordLength
	bootstrapRotationRequiredMessage = "Change the bootstrap password before making admin changes."
	maxAPIKeyLifetime                = 90 * 24 * time.Hour
	maxAPIKeyNameLength              = 128
	adminAuditPageSize               = 100
	adminManualAdvisoryPageSize      = 100
	adminQueuePageSize               = 50
)

type adminAuditLogPageLister interface {
	ListAdminAuditLogPage(ctx context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error)
}

type manualAdvisoryGetter interface {
	GetManualAdvisory(ctx context.Context, id string) (*db.ManualAdvisory, error)
}

type manualAdvisoryPageLister interface {
	ListManualAdvisoriesPage(ctx context.Context, limit, offset int) ([]db.ManualAdvisory, error)
}

type auditedManualAdvisoryStore interface {
	UpsertManualAdvisoryWithAudit(ctx context.Context, advisory *db.ManualAdvisory, audit *db.AdminAuditEntry) error
	DeleteManualAdvisoryWithAudit(ctx context.Context, id string, audit *db.AdminAuditEntry) error
}

type auditedAPIKeyStore interface {
	CreateAPIKeyWithAudit(ctx context.Context, name, keyHash string, expiresAt *time.Time, audit *db.AdminAuditEntry) (int, error)
	RevokeAPIKeyWithAudit(ctx context.Context, keyID int, audit *db.AdminAuditEntry) error
	DeleteAPIKeyWithAudit(ctx context.Context, keyID int, audit *db.AdminAuditEntry) error
}

type auditedAdminAuthStore interface {
	UpsertAdminAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *db.AdminAuditEntry) error
}

type auditedQueueStore interface {
	PurgeQueueWithAudit(ctx context.Context, audit *db.AdminAuditEntry) (int, error)
	UpdateQueueJobPriorityWithAudit(ctx context.Context, jobID, priority int, audit *db.AdminAuditEntry) error
	PauseQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error
	ResumeQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error
	RetryQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error
	ClearQueueWithAudit(ctx context.Context, statuses []string, audit *db.AdminAuditEntry) (int, error)
}

type adminQueueJobPageLister interface {
	ListQueueJobsPage(ctx context.Context, status string, limit, offset int) ([]db.RefreshJob, error)
}

type adminBootstrapPageState struct {
	Warning   bool
	LoadError string
}

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
	target := auth.AdminLoginRedirectTarget(r)
	if isHTMXRequest(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusOK)
		return
	}
	auth.RedirectSameOrigin(w, r, target, http.StatusSeeOther)
}

func (h *AdminHandler) requireBootstrapPasswordRotated(w http.ResponseWriter, r *http.Request, redirectPath string) bool {
	sess := h.sm.Get(r)
	authenticatedWithBootstrap := sess != nil && sess.AuthenticatedWithBootstrap

	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil {
		h.logger.Error("admin write blocked: failed to check bootstrap password state", "error", err)
		redirectAdminError(w, r, redirectPath, "Failed to verify admin password state")
		return false
	}
	if !authenticatedWithBootstrap && (adminAuth == nil || !adminAuth.PasswordIsBootstrap) {
		return true
	}

	h.auditLogBestEffort(r, "bootstrap_rotation_required", map[string]string{"path": logsafe.RequestPathLabel(r.URL.Path)})
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

func (h *AdminHandler) adminBootstrapPageState(ctx context.Context, sess *auth.Session, logScope string) adminBootstrapPageState {
	state := adminBootstrapPageState{}
	if sess != nil && sess.AuthenticatedWithBootstrap {
		state.Warning = true
	}
	adminAuth, err := h.store.GetAdminAuth(ctx)
	if err != nil {
		h.logger.Error(logScope+": failed to check bootstrap password state", "error", err)
		state.LoadError = "Bootstrap password status could not be verified. Check the server logs and database connection before relying on this account state."
		return state
	}
	if adminAuth != nil && adminAuth.PasswordIsBootstrap {
		state.Warning = true
	}
	return state
}

func addAdminBootstrapPageState(data map[string]any, state adminBootstrapPageState) {
	data["BootstrapWarning"] = state.Warning
	if state.LoadError != "" {
		data["AdminAuthLoadError"] = state.LoadError
	}
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
	partial := r.URL.Query().Get("partial")

	if partial == "flash" {
		data := map[string]any{
			"Message": r.URL.Query().Get("msg"),
			"Error":   r.URL.Query().Get("err"),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.renderer.RenderPartial(w, "admin/feeds.html", "admin-feed-flash", data); err != nil {
			h.logger.Error("admin feeds: partial flash render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	feeds, err := h.store.ListFeedSyncStatuses(ctx)
	feedStatusLoadError := ""
	if err != nil {
		h.logger.Error("admin feeds: failed to load statuses", "error", err)
		feedStatusLoadError = "Feed runtime status could not be loaded. Check the server logs and database connection before relying on feed health."
	}
	if partial == "runtime" {
		data := map[string]any{
			"Feeds":               h.adminFeedRows(feeds),
			"FeedStatusLoadError": feedStatusLoadError,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.renderer.RenderPartial(w, "admin/feeds.html", "admin-feed-runtime", data); err != nil {
			h.logger.Error("admin feeds: partial runtime render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	overrides, err := h.store.ListFeedConfigs(ctx)
	feedConfigLoadError := ""
	if err != nil {
		h.logger.Error("admin feeds: failed to load config overrides", "error", err)
		feedConfigLoadError = "Saved feed configuration could not be loaded. Reload after the database is healthy before saving feed changes."
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
		"FeedStatusLoadError":  feedStatusLoadError,
		"EditableFeeds":        h.adminFeedFormRows(overrides),
		"FeedConfigLoadError":  feedConfigLoadError,
		"DefaultSyncInterval":  defaultSyncInterval,
		"UnknownSeverityCount": unknownCount,
		"Message":              r.URL.Query().Get("msg"),
		"Error":                r.URL.Query().Get("err"),
	}
	addAdminBootstrapPageState(data, h.adminBootstrapPageState(ctx, sess, "admin feeds"))

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
	queueStatsLoadError := ""
	if err != nil {
		h.logger.Error("admin queue: failed to load stats", "error", err)
		queueStats = &db.QueueStatsResult{}
		queueStatsLoadError = "Queue stats could not be loaded. Check the server logs and database connection before relying on these counters."
	}

	queueStatus := normalizeAdminQueueStatus(r.URL.Query().Get("status"))
	queueOffset := parseNonNegativeOffset(r.URL.Query().Get("offset"))
	jobs, queueHasNext, err := h.listQueueJobsPage(ctx, queueStatus, queueOffset)
	queueJobsLoadError := ""
	if err != nil {
		h.logger.Error("admin queue: failed to load jobs", "error", err)
		queueJobsLoadError = "Queue jobs could not be loaded. Check the server logs and database connection before changing queue state."
	}

	data := map[string]any{
		"ActiveNav":           "admin",
		"CSRFToken":           csrfToken,
		"QueueStats":          queueStats,
		"QueueStatsLoadError": queueStatsLoadError,
		"Jobs":                jobs,
		"QueueJobsLoadError":  queueJobsLoadError,
		"QueueStatus":         queueStatus,
		"QueueFilters":        buildAdminQueueFilters(queueStatus),
		"QueueHasPrevious":    queueOffset > 0,
		"QueueHasNext":        queueHasNext,
		"QueuePreviousURL":    adminQueuePageURL(queueStatus, max(queueOffset-adminQueuePageSize, 0)),
		"QueueNextURL":        adminQueuePageURL(queueStatus, queueOffset+adminQueuePageSize),
		"QueuePageStart":      auditPageStart(queueOffset, len(jobs)),
		"QueuePageEnd":        queueOffset + len(jobs),
		"Message":             r.URL.Query().Get("msg"),
		"Error":               r.URL.Query().Get("err"),
	}
	addAdminBootstrapPageState(data, h.adminBootstrapPageState(ctx, sess, "admin queue"))
	h.renderAdmin(w, "admin/queue.html", data)
}

func (h *AdminHandler) listQueueJobsPage(ctx context.Context, status string, offset int) ([]db.RefreshJob, bool, error) {
	limit := adminQueuePageSize + 1
	var (
		jobs []db.RefreshJob
		err  error
	)
	if pager, ok := h.store.(adminQueueJobPageLister); ok {
		jobs, err = pager.ListQueueJobsPage(ctx, status, limit, offset)
	} else {
		if offset > 0 {
			return nil, false, fmt.Errorf("admin queue pagination is not available for this store")
		}
		jobs, err = h.store.ListQueueJobs(ctx, status, limit)
	}
	if err != nil {
		return nil, false, err
	}
	if len(jobs) > adminQueuePageSize {
		return jobs[:adminQueuePageSize], true, nil
	}
	return jobs, false, nil
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

	audit := h.adminAuditEntry(r, "queue_purge", map[string]string{})
	var (
		purged int
		err    error
	)
	if store, ok := h.store.(auditedQueueStore); ok {
		purged, err = store.PurgeQueueWithAudit(r.Context(), audit)
	} else {
		if err := h.writeAdminAuditLog(audit); err != nil {
			redirectQueue(w, r, "Failed to record audit log", true)
			return
		}
		purged, err = h.store.PurgeQueue(r.Context())
	}
	if err != nil {
		h.logger.Error("admin queue purge failed", "error", err)
		redirectQueue(w, r, adminMutationErrorMessage(err, "Purge failed"), true)
		return
	}

	redirectQueue(w, r, fmt.Sprintf("Purged %d completed/errored jobs.", purged), false)
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
	if err != nil || priority < 0 || priority > 3 {
		redirectQueue(w, r, "Invalid priority", true)
		return
	}

	audit := h.adminAuditEntry(r, "queue_priority_update", map[string]string{
		"job_id":   strconv.Itoa(jobID),
		"priority": strconv.Itoa(priority),
	})
	var actionErr error
	if store, ok := h.store.(auditedQueueStore); ok {
		actionErr = store.UpdateQueueJobPriorityWithAudit(r.Context(), jobID, priority, audit)
	} else {
		if err := h.writeAdminAuditLog(audit); err != nil {
			redirectQueue(w, r, "Failed to record audit log", true)
			return
		}
		actionErr = h.store.UpdateQueueJobPriority(r.Context(), jobID, priority)
	}
	if actionErr != nil {
		h.logger.Error("admin queue priority update failed", "job_id", jobID, "error", actionErr)
		redirectQueue(w, r, adminMutationErrorMessage(actionErr, "Priority update failed"), true)
		return
	}
	redirectQueue(w, r, "Priority updated", false)
}

// HandleQueuePause handles POST /admin/queue/pause.
func (h *AdminHandler) HandleQueuePause(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_pause", "Job paused", h.store.PauseQueueJob, func(store auditedQueueStore, ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
		return store.PauseQueueJobWithAudit(ctx, jobID, audit)
	})
}

// HandleQueueResume handles POST /admin/queue/resume.
func (h *AdminHandler) HandleQueueResume(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_resume", "Job resumed", h.store.ResumeQueueJob, func(store auditedQueueStore, ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
		return store.ResumeQueueJobWithAudit(ctx, jobID, audit)
	})
}

// HandleQueueRetry handles POST /admin/queue/retry.
func (h *AdminHandler) HandleQueueRetry(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_retry", "Job queued for retry", h.store.RetryQueueJob, func(store auditedQueueStore, ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
		return store.RetryQueueJobWithAudit(ctx, jobID, audit)
	})
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
	var statuses []string
	switch status {
	case "all":
		statuses = []string{"pending", "paused", "done", "error"}
	case "pending", "paused", "done", "error":
		statuses = []string{status}
	default:
		redirectQueue(w, r, "Invalid queue status", true)
		return
	}

	audit := h.adminAuditEntry(r, "queue_clear", map[string]string{
		"status": status,
	})
	var (
		cleared int
		err     error
	)
	if store, ok := h.store.(auditedQueueStore); ok {
		cleared, err = store.ClearQueueWithAudit(r.Context(), statuses, audit)
	} else {
		if err := h.writeAdminAuditLog(audit); err != nil {
			redirectQueue(w, r, "Failed to record audit log", true)
			return
		}
		cleared, err = h.store.ClearQueue(r.Context(), statuses)
	}
	if err != nil {
		h.logger.Error("admin queue clear failed", "status", status, "error", err)
		redirectQueue(w, r, adminMutationErrorMessage(err, "Queue clear failed"), true)
		return
	}
	redirectQueue(w, r, fmt.Sprintf("Cleared %d queue jobs.", cleared), false)
}

func (h *AdminHandler) handleQueueJobAction(w http.ResponseWriter, r *http.Request, auditAction, message string, action func(context.Context, int) error, auditedAction func(auditedQueueStore, context.Context, int, *db.AdminAuditEntry) error) {
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
	audit := h.adminAuditEntry(r, auditAction, map[string]string{"job_id": strconv.Itoa(jobID)})
	var err error
	if store, ok := h.store.(auditedQueueStore); ok {
		err = auditedAction(store, r.Context(), jobID, audit)
	} else {
		if err := h.writeAdminAuditLog(audit); err != nil {
			redirectQueue(w, r, "Failed to record audit log", true)
			return
		}
		err = action(r.Context(), jobID)
	}
	if err != nil {
		h.logger.Error("admin queue action failed", "action", auditAction, "job_id", jobID, "error", err)
		redirectQueue(w, r, adminMutationErrorMessage(err, message+" failed"), true)
		return
	}
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

func adminMutationErrorMessage(err error, fallback string) string {
	if errors.Is(err, db.ErrAdminAuditLog) {
		return "Failed to record audit log"
	}
	return fallback
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
	keysLoadError := ""
	if err != nil {
		h.logger.Error("admin keys: failed to load keys", "error", err)
		keysLoadError = "API keys could not be loaded. Check the server logs and database connection before changing key access."
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
		"ActiveNav":           "admin",
		"CSRFToken":           csrfToken,
		"Keys":                keyViews,
		"KeysLoadError":       keysLoadError,
		"Message":             r.URL.Query().Get("msg"),
		"Error":               r.URL.Query().Get("err"),
		"NewKey":              newKey,
		"MaxAPIKeyNameLength": maxAPIKeyNameLength,
	}
	addAdminBootstrapPageState(data, h.adminBootstrapPageState(ctx, sess, "admin keys"))
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

// IsDeleted reports whether the key has been soft-deleted after revocation.
func (k apiKeyView) IsDeleted() bool {
	return k.DeletedAt != nil
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

	name, err := normalizeAPIKeyName(r.PostForm.Get("name"))
	if err != nil {
		http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape(apiKeyNameValidationMessage(err)), http.StatusSeeOther)
		return
	}
	expiresAt, err := parseAPIKeyExpiresAt(r.PostForm.Get("expires_at"), time.Now().UTC())
	if err != nil {
		http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if !h.requireAPIKeyCreateStepUp(w, r) {
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

	auditDetails := map[string]string{
		"name": name,
	}
	if expiresAt != nil {
		auditDetails["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	audit := h.adminAuditEntry(r, "api_key_create", auditDetails)

	var (
		keyID     int
		createErr error
	)
	if store, ok := h.store.(auditedAPIKeyStore); ok {
		keyID, createErr = store.CreateAPIKeyWithAudit(r.Context(), name, keyHash, expiresAt, audit)
	} else {
		if err := h.writeAdminAuditLog(audit); err != nil {
			http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape("Failed to record audit log"), http.StatusSeeOther)
			return
		}
		keyID, createErr = h.store.CreateAPIKey(r.Context(), name, keyHash, expiresAt)
	}
	if createErr != nil {
		h.logger.Error("admin keys: failed to create key", "error", createErr, "key_id", keyID)
		http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape(adminMutationErrorMessage(createErr, "Failed to create key")), http.StatusSeeOther)
		return
	}

	// Store the plaintext key in a flash message so it is never exposed
	// in the URL query string (SEC-H5).
	h.sm.SetFlash(sess.ID, "newkey", plaintext)
	http.Redirect(w, r, "/admin/keys?msg=Key+created", http.StatusSeeOther)
}

func normalizeAPIKeyName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("key name is required")
	}
	if utf8.RuneCountInString(name) > maxAPIKeyNameLength {
		return "", fmt.Errorf("key name must be 128 characters or fewer")
	}
	return name, nil
}

func apiKeyNameValidationMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "key name ") {
		return "K" + msg[1:]
	}
	return msg
}

func parseAPIKeyExpiresAt(raw string, now time.Time) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("expiration is required")
	}

	expiresAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid expiration timestamp; use RFC3339 UTC ending in Z")
	}
	if _, offset := expiresAt.Zone(); offset != 0 || !strings.HasSuffix(raw, "Z") {
		return nil, fmt.Errorf("expiration must be an RFC3339 UTC timestamp ending in Z")
	}
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now.UTC()) {
		return nil, fmt.Errorf("expiration must be in the future")
	}
	if expiresAt.After(now.UTC().Add(maxAPIKeyLifetime)) {
		return nil, fmt.Errorf("expiration must be within 90 days")
	}
	return &expiresAt, nil
}

func (h *AdminHandler) requireAPIKeyCreateStepUp(w http.ResponseWriter, r *http.Request) bool {
	ip := clientIP(r)
	if h.isLockedOut(ip) {
		telemetry.Default().IncAuthLoginFailures()
		if h.markLockoutAudited(ip) {
			h.logger.Warn("api key create attempt from locked out principal", "ip", ip)
			h.auditLogBestEffort(r, "login_lockout", map[string]string{
				"reason": "too many failed attempts",
			})
		}
		http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape("Too many failed password attempts. Please try again later."), http.StatusSeeOther)
		return false
	}

	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil || adminAuth == nil {
		http.Redirect(w, r, "/admin/keys?err=Failed+to+verify+current+password", http.StatusSeeOther)
		return false
	}
	if !auth.CheckPassword(adminAuth.PasswordHash, r.PostForm.Get("current_password")) {
		h.recordFailedAttempt(ip)
		h.auditLogBestEffort(r, "api_key_create_failed", map[string]string{
			"reason": "invalid current password",
		})
		http.Redirect(w, r, "/admin/keys?err=Current+password+is+incorrect", http.StatusSeeOther)
		return false
	}

	h.resetAttempts(ip)
	return true
}

// HandleKeyRevoke handles POST /admin/keys/revoke.
func (h *AdminHandler) HandleKeyRevoke(w http.ResponseWriter, r *http.Request) {
	h.handleAPIKeyMutation(w, r, apiKeyMutation{
		auditAction:    "api_key_revoke",
		logVerb:        "revoke",
		successMessage: "Key revoked",
		failureMessage: "Failed to revoke key",
		action:         h.store.RevokeAPIKey,
		auditedAction: func(store auditedAPIKeyStore, ctx context.Context, keyID int, audit *db.AdminAuditEntry) error {
			return store.RevokeAPIKeyWithAudit(ctx, keyID, audit)
		},
	})
}

// HandleKeyDelete handles POST /admin/keys/delete.
func (h *AdminHandler) HandleKeyDelete(w http.ResponseWriter, r *http.Request) {
	h.handleAPIKeyMutation(w, r, apiKeyMutation{
		auditAction:    "api_key_delete",
		logVerb:        "delete",
		successMessage: "Key deleted",
		failureMessage: "Failed to delete key",
		action:         h.store.DeleteAPIKey,
		auditedAction: func(store auditedAPIKeyStore, ctx context.Context, keyID int, audit *db.AdminAuditEntry) error {
			return store.DeleteAPIKeyWithAudit(ctx, keyID, audit)
		},
	})
}

type apiKeyMutation struct {
	auditAction    string
	logVerb        string
	successMessage string
	failureMessage string
	action         func(context.Context, int) error
	auditedAction  func(auditedAPIKeyStore, context.Context, int, *db.AdminAuditEntry) error
}

func (h *AdminHandler) handleAPIKeyMutation(w http.ResponseWriter, r *http.Request, mutation apiKeyMutation) {
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

	auditDetails, err := h.apiKeyAuditDetails(r.Context(), keyID)
	if err != nil {
		h.logger.Error("admin keys: failed to load key metadata", "action", mutation.logVerb, "error", err, "key_id", keyID)
		http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape(mutation.failureMessage), http.StatusSeeOther)
		return
	}

	audit := h.adminAuditEntry(r, mutation.auditAction, auditDetails)
	var auditErr error
	if store, ok := h.store.(auditedAPIKeyStore); ok {
		auditErr = mutation.auditedAction(store, r.Context(), keyID, audit)
	} else {
		if err := h.writeAdminAuditLog(audit); err != nil {
			http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape("Failed to record audit log"), http.StatusSeeOther)
			return
		}
		auditErr = mutation.action(r.Context(), keyID)
	}
	if auditErr != nil {
		h.logger.Error("admin keys: failed to mutate key", "action", mutation.logVerb, "error", auditErr, "key_id", keyID)
		http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape(adminMutationErrorMessage(auditErr, mutation.failureMessage)), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin/keys?msg="+url.QueryEscape(mutation.successMessage), http.StatusSeeOther)
}

func (h *AdminHandler) apiKeyAuditDetails(ctx context.Context, keyID int) (map[string]string, error) {
	keys, err := h.store.ListAPIKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.ID != keyID {
			continue
		}
		details := map[string]string{
			"key_id":     strconv.Itoa(key.ID),
			"name":       key.Name,
			"created_at": key.CreatedAt.UTC().Format(time.RFC3339),
		}
		if key.LastUsedAt != nil {
			details["last_used_at"] = key.LastUsedAt.UTC().Format(time.RFC3339)
		}
		if key.ExpiresAt != nil {
			details["expires_at"] = key.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if key.RevokedAt != nil {
			details["revoked_at"] = key.RevokedAt.UTC().Format(time.RFC3339)
		}
		if key.DeletedAt != nil {
			details["deleted_at"] = key.DeletedAt.UTC().Format(time.RFC3339)
		}
		return details, nil
	}
	return nil, fmt.Errorf("api key %d not found", keyID)
}

// HandleAdminAdvisories serves GET /admin/advisories with the manual advisory form.
func (h *AdminHandler) HandleAdminAdvisories(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	csrfToken, _ := auth.CSRFToken(sess)
	offset := parseNonNegativeOffset(r.URL.Query().Get("offset"))
	advisories, hasNext, err := h.listManualAdvisoryPage(r.Context(), offset)
	advisoriesLoadError := ""
	if err != nil {
		h.logger.Error("admin advisories: failed to list advisories", "error", err)
		advisoriesLoadError = "Manual advisories could not be loaded. Check the server logs and database connection before changing advisory coverage."
	}

	views := make([]manualAdvisoryView, 0, len(advisories))
	var editAdvisory *manualAdvisoryView
	editID := r.URL.Query().Get("edit")
	for _, advisory := range advisories {
		view := manualAdvisoryToView(advisory)
		views = append(views, view)
		if editID != "" && advisory.ID == editID {
			copyValue := view
			editAdvisory = &copyValue
		}
	}
	if editID != "" && editAdvisory == nil && advisoriesLoadError == "" {
		advisory, found, err := h.findManualAdvisoryByID(r.Context(), editID)
		if err != nil {
			h.logger.Error("admin advisories: failed to load edit advisory", "error", err, "id", editID)
			advisoriesLoadError = "Manual advisories could not be loaded. Check the server logs and database connection before changing advisory coverage."
		} else if found {
			view := manualAdvisoryToView(advisory)
			editAdvisory = &view
		}
	}

	data := map[string]any{
		"ActiveNav":              "admin",
		"CSRFToken":              csrfToken,
		"Message":                r.URL.Query().Get("msg"),
		"Error":                  r.URL.Query().Get("err"),
		"Advisories":             views,
		"AdvisoriesLoadError":    advisoriesLoadError,
		"EditAdvisory":           editAdvisory,
		"IsEditing":              editAdvisory != nil,
		"ShowRiskTypeControl":    editAdvisory != nil && editAdvisory.FindingType == "malicious",
		"AdvisoryHasPrevious":    offset > 0,
		"AdvisoryHasNext":        hasNext,
		"AdvisoryPreviousOffset": max(offset-adminManualAdvisoryPageSize, 0),
		"AdvisoryNextOffset":     offset + adminManualAdvisoryPageSize,
		"AdvisoryPageStart":      auditPageStart(offset, len(views)),
		"AdvisoryPageEnd":        offset + len(views),
	}
	addAdminBootstrapPageState(data, h.adminBootstrapPageState(r.Context(), sess, "admin advisories"))
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
	var previous db.ManualAdvisory
	isEditing := false
	if advisoryID != "" {
		var err error
		previous, isEditing, err = h.findManualAdvisoryByID(r.Context(), advisoryID)
		if err != nil {
			h.logger.Error("admin advisories: failed to load advisory before save", "error", err, "id", advisoryID)
			http.Redirect(w, r, "/admin/advisories?err=Failed+to+load+existing+advisory", http.StatusSeeOther)
			return
		}
	}

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
	switch findingType {
	case "malicious":
		if strings.TrimSpace(riskType) == "" {
			riskType = "other"
		}
	case "vulnerability":
		riskType = ""
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

	action := "advisory_create"
	auditDetails := manualAdvisoryAuditDetails(*advisory)
	if isEditing {
		action = "advisory_update"
		auditDetails = manualAdvisoryUpdateAuditDetails(previous, *advisory)
	}
	audit := h.adminAuditEntry(r, action, auditDetails)

	if err := h.upsertManualAdvisoryWithAudit(r, advisory, audit); err != nil {
		h.logger.Error("admin advisories: failed to save advisory", "error", err, "id", advisoryID)
		if errors.Is(err, db.ErrAdminAuditLog) {
			http.Redirect(w, r, "/admin/advisories?err="+url.QueryEscape("Failed to record audit log"), http.StatusSeeOther)
			return
		}
		if isEditing {
			http.Redirect(w, r, "/admin/advisories?err=Failed+to+update+advisory", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/advisories?err=Failed+to+create+advisory", http.StatusSeeOther)
		return
	}

	msg := "Advisory+created"
	if isEditing {
		msg = "Advisory+updated"
	}
	http.Redirect(w, r, "/admin/advisories?msg="+msg, http.StatusSeeOther)
}

func normalizeAdvisoryFindingType(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "vulnerability":
		return "vulnerability", true
	case "malicious":
		return "malicious", true
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

func manualAdvisoryToView(advisory db.ManualAdvisory) manualAdvisoryView {
	return manualAdvisoryView{
		ID:          advisory.ID,
		FindingType: advisory.FindingType,
		Ecosystem:   advisory.Ecosystem,
		Name:        advisory.Name,
		Severity:    advisory.Severity,
		RiskType:    advisory.RiskType,
		Summary:     advisory.Summary,
		Description: advisory.Description,
	}
}

func (h *AdminHandler) listManualAdvisoryPage(ctx context.Context, offset int) ([]db.ManualAdvisory, bool, error) {
	limit := adminManualAdvisoryPageSize + 1
	var (
		advisories []db.ManualAdvisory
		err        error
	)
	if pager, ok := h.store.(manualAdvisoryPageLister); ok {
		advisories, err = pager.ListManualAdvisoriesPage(ctx, limit, offset)
	} else {
		advisories, err = h.store.ListManualAdvisories(ctx, offset+limit)
		if err == nil && offset > 0 {
			if offset >= len(advisories) {
				advisories = nil
			} else {
				advisories = advisories[offset:]
			}
		}
	}
	if err != nil {
		return nil, false, err
	}
	if len(advisories) > adminManualAdvisoryPageSize {
		return advisories[:adminManualAdvisoryPageSize], true, nil
	}
	return advisories, false, nil
}

func (h *AdminHandler) findManualAdvisoryByID(ctx context.Context, id string) (db.ManualAdvisory, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return db.ManualAdvisory{}, false, nil
	}
	if getter, ok := h.store.(manualAdvisoryGetter); ok {
		advisory, err := getter.GetManualAdvisory(ctx, id)
		if err != nil {
			return db.ManualAdvisory{}, false, err
		}
		if advisory == nil {
			return db.ManualAdvisory{}, false, nil
		}
		return *advisory, true, nil
	}
	advisories, err := h.store.ListManualAdvisories(ctx, 500)
	if err != nil {
		return db.ManualAdvisory{}, false, err
	}
	for _, advisory := range advisories {
		if advisory.ID == id {
			return advisory, true, nil
		}
	}
	return db.ManualAdvisory{}, false, nil
}

func manualAdvisoryAuditDetails(advisory db.ManualAdvisory) map[string]string {
	return map[string]string{
		"id":           advisory.ID,
		"finding_type": advisory.FindingType,
		"ecosystem":    advisory.Ecosystem,
		"name":         advisory.Name,
		"severity":     advisory.Severity,
		"risk_type":    advisory.RiskType,
		"summary":      advisory.Summary,
		"description":  advisory.Description,
	}
}

func manualAdvisoryUpdateAuditDetails(previous, next db.ManualAdvisory) map[string]string {
	details := map[string]string{"id": next.ID}
	addManualAdvisoryAuditDetails(details, "previous_", previous)
	addManualAdvisoryAuditDetails(details, "new_", next)
	return details
}

func addManualAdvisoryAuditDetails(details map[string]string, prefix string, advisory db.ManualAdvisory) {
	details[prefix+"finding_type"] = advisory.FindingType
	details[prefix+"ecosystem"] = advisory.Ecosystem
	details[prefix+"name"] = advisory.Name
	details[prefix+"severity"] = advisory.Severity
	details[prefix+"risk_type"] = advisory.RiskType
	details[prefix+"summary"] = advisory.Summary
	details[prefix+"description"] = advisory.Description
}

func (h *AdminHandler) upsertManualAdvisoryWithAudit(r *http.Request, advisory *db.ManualAdvisory, audit *db.AdminAuditEntry) error {
	if auditedStore, ok := h.store.(auditedManualAdvisoryStore); ok {
		ctx, cancel := h.adminAuditContext()
		defer cancel()
		return auditedStore.UpsertManualAdvisoryWithAudit(ctx, advisory, audit)
	}
	if err := h.writeAdminAuditLog(audit); err != nil {
		return err
	}
	if err := h.store.UpsertManualAdvisory(r.Context(), advisory); err != nil {
		return fmt.Errorf("upsert manual advisory: %w", err)
	}
	return nil
}

func (h *AdminHandler) deleteManualAdvisoryWithAudit(r *http.Request, id string, audit *db.AdminAuditEntry) error {
	if auditedStore, ok := h.store.(auditedManualAdvisoryStore); ok {
		ctx, cancel := h.adminAuditContext()
		defer cancel()
		return auditedStore.DeleteManualAdvisoryWithAudit(ctx, id, audit)
	}
	if err := h.writeAdminAuditLog(audit); err != nil {
		return err
	}
	if err := h.store.DeleteManualAdvisory(r.Context(), id); err != nil {
		return fmt.Errorf("delete manual advisory: %w", err)
	}
	return nil
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

	advisoryID := strings.TrimSpace(r.PostForm.Get("id"))
	if advisoryID == "" {
		http.Redirect(w, r, "/admin/advisories?err=Missing+advisory+ID", http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(r.PostForm.Get("confirm_id")) != advisoryID {
		http.Redirect(w, r, "/admin/advisories?err=Confirm+advisory+ID+before+deleting", http.StatusSeeOther)
		return
	}

	advisory, found, err := h.findManualAdvisoryByID(r.Context(), advisoryID)
	if err != nil {
		h.logger.Error("admin advisories: failed to load advisory before delete", "error", err, "id", advisoryID)
		http.Redirect(w, r, "/admin/advisories?err=Failed+to+load+advisory", http.StatusSeeOther)
		return
	}
	if !found {
		http.Redirect(w, r, "/admin/advisories?err=Advisory+not+found", http.StatusSeeOther)
		return
	}
	audit := h.adminAuditEntry(r, "advisory_delete", manualAdvisoryAuditDetails(advisory))

	if err := h.deleteManualAdvisoryWithAudit(r, advisoryID, audit); err != nil {
		h.logger.Error("admin advisories: failed to delete advisory", "error", err, "id", advisoryID)
		if errors.Is(err, db.ErrAdminAuditLog) {
			http.Redirect(w, r, "/admin/advisories?err="+url.QueryEscape("Failed to record audit log"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/advisories?err=Failed+to+delete+advisory", http.StatusSeeOther)
		return
	}
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

	offset := parseAdminAuditOffset(r.URL.Query().Get("offset"))
	entries, hasNext, err := h.listAdminAuditPage(ctx, offset)
	auditLoadError := ""
	if err != nil {
		h.logger.Error("admin audit: failed to load entries", "error", err)
		auditLoadError = "Audit log entries could not be loaded. Check the server logs and database connection before relying on this page."
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
			DetailsExpanded:    len(detailsStr) > 80,
			IntegrityLabel:     adminAuditIntegrityLabel(e.IntegrityStatus),
			IntegrityClass:     adminAuditIntegrityClass(e.IntegrityStatus),
		}
	}

	data := map[string]any{
		"ActiveNav":           "admin",
		"CSRFToken":           csrfToken,
		"Entries":             views,
		"AuditLoadError":      auditLoadError,
		"AuditHasPrevious":    offset > 0,
		"AuditHasNext":        hasNext,
		"AuditPreviousOffset": max(offset-adminAuditPageSize, 0),
		"AuditNextOffset":     offset + adminAuditPageSize,
		"AuditPageStart":      auditPageStart(offset, len(views)),
		"AuditPageEnd":        offset + len(views),
	}
	h.renderAdmin(w, "admin/audit.html", data)
}

func (h *AdminHandler) listAdminAuditPage(ctx context.Context, offset int) ([]db.AdminAuditLogEntry, bool, error) {
	limit := adminAuditPageSize + 1
	var (
		entries []db.AdminAuditLogEntry
		err     error
	)
	if pager, ok := h.store.(adminAuditLogPageLister); ok {
		entries, err = pager.ListAdminAuditLogPage(ctx, limit, offset)
	} else {
		if offset > 0 {
			return nil, false, fmt.Errorf("admin audit pagination is not available for this store")
		}
		entries, err = h.store.ListAdminAuditLog(ctx, limit)
	}
	if err != nil {
		return nil, false, err
	}
	if len(entries) > adminAuditPageSize {
		return entries[:adminAuditPageSize], true, nil
	}
	return entries, false, nil
}

func parseAdminAuditOffset(raw string) int {
	return parseNonNegativeOffset(raw)
}

func parseNonNegativeOffset(raw string) int {
	offset, err := strconv.Atoi(raw)
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}

type adminQueueFilterView struct {
	Label  string
	URL    string
	Active bool
}

func buildAdminQueueFilters(active string) []adminQueueFilterView {
	filters := []struct {
		status string
		label  string
	}{
		{"", "All"},
		{"pending", "Pending"},
		{"processing", "Processing"},
		{"paused", "Paused"},
		{"error", "Error"},
		{"done", "Done"},
	}
	out := make([]adminQueueFilterView, 0, len(filters))
	for _, filter := range filters {
		out = append(out, adminQueueFilterView{
			Label:  filter.label,
			URL:    adminQueueURL(filter.status, 0),
			Active: active == filter.status,
		})
	}
	return out
}

func normalizeAdminQueueStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pending", "processing", "paused", "error", "done":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func adminQueueURL(status string, offset int) string {
	return adminQueueURLWithOffset(status, offset, false)
}

func adminQueuePageURL(status string, offset int) string {
	return adminQueueURLWithOffset(status, offset, true)
}

func adminQueueURLWithOffset(status string, offset int, includeZeroOffset bool) string {
	parts := make([]string, 0, 2)
	if status != "" {
		parts = append(parts, "status="+url.QueryEscape(status))
	}
	if offset > 0 || includeZeroOffset {
		parts = append(parts, "offset="+strconv.Itoa(max(offset, 0)))
	}
	if len(parts) == 0 {
		return "/admin/queue"
	}
	return "/admin/queue?" + strings.Join(parts, "&")
}

func auditPageStart(offset, entries int) int {
	if entries == 0 {
		return 0
	}
	return offset + 1
}

// auditLogView wraps db.AdminAuditLogEntry with a string representation
// of the Details JSON for template display.
type auditLogView struct {
	db.AdminAuditLogEntry
	DetailsStr      string
	DetailsExpanded bool
	IntegrityLabel  string
	IntegrityClass  string
}

func adminAuditIntegrityLabel(status string) string {
	switch status {
	case db.AdminAuditIntegrityVerified:
		return "Verified"
	case db.AdminAuditIntegrityBroken:
		return "Broken"
	default:
		return "Legacy"
	}
}

func adminAuditIntegrityClass(status string) string {
	switch status {
	case db.AdminAuditIntegrityVerified:
		return "bg-green-100 text-green-800"
	case db.AdminAuditIntegrityBroken:
		return "bg-red-100 text-red-800"
	default:
		return "bg-gray-100 text-gray-800"
	}
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
	adminAuthLoadError := ""
	if err != nil {
		h.logger.Error("admin settings: failed to get auth info", "error", err)
		adminAuthLoadError = "Admin account metadata could not be loaded. Check the server logs and database connection before relying on login timestamps."
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
	bootstrapWarning := sess.AuthenticatedWithBootstrap || (adminAuth != nil && adminAuth.PasswordIsBootstrap)

	systemSettings, err := h.store.GetSystemSettings(ctx)
	systemSettingsLoadError := ""
	if err != nil {
		h.logger.Error("admin settings: failed to get system settings", "error", err)
		systemSettingsLoadError = "System settings could not be loaded. Reload after the database is healthy before saving policy changes."
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
	if h.runtime != nil {
		if threshold := h.runtime.BlockThreshold(); threshold != "" {
			runtimeBlockThreshold = threshold
		}
		perMinute, burst := h.runtime.RateLimit()
		if perMinute > 0 {
			runtimeRateLimitPerMinute = perMinute
		}
		if burst > 0 {
			runtimeRateLimitBurst = burst
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
		"SystemSettingsLoadError":    systemSettingsLoadError,
		"LastLoginAt":                lastLoginAt,
		"HasLastLoginAt":             hasLastLoginAt,
		"PasswordChangedAt":          passwordChangedAt,
		"HasPasswordChangedAt":       hasPasswordChangedAt,
		"AdminAuthLoadError":         adminAuthLoadError,
		"BootstrapWarning":           bootstrapWarning,
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

	ip := clientIP(r)
	if h.isLockedOut(ip) {
		telemetry.Default().IncAuthLoginFailures()
		if h.markLockoutAudited(ip) {
			h.logger.Warn("password change attempt from locked out principal", "ip", ip)
			h.auditLogBestEffort(r, "login_lockout", map[string]string{
				"reason": "too many failed attempts",
			})
		}
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape("Too many failed password attempts. Please try again later."), http.StatusSeeOther)
		return
	}

	currentPassword := r.PostForm.Get("current_password")
	newPassword := r.PostForm.Get("new_password")
	confirmPassword := r.PostForm.Get("confirm_password")

	if newPassword != confirmPassword {
		http.Redirect(w, r, "/admin/settings?err=New+passwords+do+not+match", http.StatusSeeOther)
		return
	}

	if err := auth.ValidateAdminPassword(newPassword); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/settings?err=Password+must+be+at+least+%d+characters", adminPasswordMinLength), http.StatusSeeOther)
		return
	}

	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil || adminAuth == nil {
		http.Redirect(w, r, "/admin/settings?err=Failed+to+verify+current+password", http.StatusSeeOther)
		return
	}

	if !auth.CheckPassword(adminAuth.PasswordHash, currentPassword) {
		h.recordFailedAttempt(ip)
		h.auditLogBestEffort(r, "password_change_failed", map[string]string{
			"reason": "invalid current password",
		})
		http.Redirect(w, r, "/admin/settings?err=Current+password+is+incorrect", http.StatusSeeOther)
		return
	}

	if auth.CheckPassword(adminAuth.PasswordHash, newPassword) {
		h.auditLogBestEffort(r, "password_change_failed", map[string]string{
			"reason": "new password reused current password",
		})
		http.Redirect(w, r, "/admin/settings?err=New+password+must+differ+from+current+password", http.StatusSeeOther)
		return
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		h.logger.Error("admin settings: failed to hash new password", "error", err)
		http.Redirect(w, r, "/admin/settings?err=Failed+to+update+password", http.StatusSeeOther)
		return
	}

	audit := h.adminAuditEntry(r, "password_change", map[string]string{})
	var updateErr error
	if store, ok := h.store.(auditedAdminAuthStore); ok {
		updateErr = store.UpsertAdminAuthWithAudit(r.Context(), newHash, false, audit)
	} else {
		if err := h.writeAdminAuditLog(audit); err != nil {
			http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape("Failed to record audit log"), http.StatusSeeOther)
			return
		}
		updateErr = h.store.UpsertAdminAuth(r.Context(), newHash, false)
	}
	if updateErr != nil {
		h.logger.Error("admin settings: failed to update password", "error", updateErr)
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(adminMutationErrorMessage(updateErr, "Failed to update password")), http.StatusSeeOther)
		return
	}

	h.resetAttempts(ip)

	if _, err := h.sm.CreateExclusiveAdmin(w); err != nil {
		h.logger.Error("admin settings: failed to rotate admin session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

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
