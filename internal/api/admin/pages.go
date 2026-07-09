package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/telemetry"
	"github.com/8linkz-sec/packmon/internal/web"
)

const (
	adminPasswordMinLength    = auth.MinAdminPasswordLength
	maxAPIKeyLifetime         = 90 * 24 * time.Hour
	maxAPIKeyNameLength       = 128
	apiKeyCreateNonceField    = "create_nonce"
	apiKeyCreateNonceFlashKey = "api_key_create_nonce"
	adminAuditPageSize        = 100
	adminAPIKeyPageSize       = 100
)

var bootstrapRotationRequiredMessage = web.Message("admin.bootstrap.error.rotation_required")

type adminAuditLogPageLister interface {
	ListAdminAuditLogPage(ctx context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error)
}

type apiKeyPageLister interface {
	ListAPIKeysPage(ctx context.Context, limit, offset int) ([]db.APIKey, error)
}

type adminBootstrapPageState struct {
	Warning   bool
	LoadError string
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
		h.logger.Error("admin write blocked: failed to check bootstrap password state", h.adminLogAttrs(r, "error", err)...)
		redirectAdminError(w, r, redirectPath, web.Message("admin.bootstrap.error.verify_password_state"))
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
			h.logger.Error("admin feeds: bootstrap flash render failed", h.adminLogAttrs(r, "error", renderErr)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return false
	}

	redirectAdminError(w, r, redirectPath, bootstrapRotationRequiredMessage)
	return false
}

func (h *AdminHandler) adminBootstrapPageState(ctx context.Context, r *http.Request, sess *auth.Session, logScope string) adminBootstrapPageState {
	state := adminBootstrapPageState{}
	if sess != nil && sess.AuthenticatedWithBootstrap {
		state.Warning = true
	}
	adminAuth, err := h.store.GetAdminAuth(ctx)
	if err != nil {
		h.logger.Error(logScope+": failed to check bootstrap password state", h.adminLogAttrs(r, "error", err)...)
		state.LoadError = web.Message("admin.settings.error.auth_state")
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
	partial := r.URL.Query().Get("partial")
	if partial == "flash" || partial == "runtime" {
		w.Header().Add("Vary", "HX-Request")
	}

	if partial == "flash" && isHTMXRequest(r) {
		data := map[string]any{
			"Message": r.URL.Query().Get("msg"),
			"Error":   r.URL.Query().Get("err"),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.renderer.RenderPartial(w, "admin/feeds.html", "admin-feed-flash", data); err != nil {
			h.logger.Error("admin feeds: partial flash render failed", h.adminLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	feeds, err := h.store.ListFeedSyncStatuses(ctx)
	feedStatusLoadError := ""
	if err != nil {
		h.logger.Error("admin feeds: failed to load statuses", h.adminLogAttrs(r, "error", err)...)
		feedStatusLoadError = "Feed runtime status could not be loaded. Check the server logs and database connection before relying on feed health."
	}
	if partial == "runtime" && isHTMXRequest(r) {
		data := map[string]any{
			"Feeds":               h.adminFeedRows(feeds),
			"FeedStatusLoadError": feedStatusLoadError,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.renderer.RenderPartial(w, "admin/feeds.html", "admin-feed-runtime", data); err != nil {
			h.logger.Error("admin feeds: partial runtime render failed", h.adminLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	csrfToken, ok := h.adminCSRFToken(w, r, sess, "admin feeds")
	if !ok {
		return
	}

	overrides, err := h.store.ListFeedConfigs(ctx)
	feedConfigLoadError := ""
	if err != nil {
		h.logger.Error("admin feeds: failed to load config overrides", h.adminLogAttrs(r, "error", err)...)
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
		"ActiveFeedKey":        config.NormalizeFeedName(r.URL.Query().Get("feed")),
	}
	addAdminBootstrapPageState(data, h.adminBootstrapPageState(ctx, r, sess, "admin feeds"))

	h.renderAdmin(w, "admin/feeds.html", data)
}

func (row adminFeedRow) StatusReason() string {
	status := strings.ToLower(strings.TrimSpace(row.Status))
	lastSyncStatus := strings.ToLower(strings.TrimSpace(row.LastSyncStatus))

	if !row.ConfigEnabled || lastSyncStatus == db.FeedSyncStatusDisabled {
		return "feed disabled"
	}
	if row.APIKeyStateCode == adminFeedAPIKeyStateMissingCode {
		return "required API key not configured"
	}
	if status == "running" || lastSyncStatus == db.FeedSyncStatusRunning {
		return "sync running"
	}

	switch lastSyncStatus {
	case db.FeedSyncStatusError:
		return "last sync failed"
	case db.FeedSyncStatusPermanentError:
		return "permanent feed error"
	case db.FeedSyncStatusExternal:
		return "external feed managed outside Packmon"
	case db.FeedSyncStatusPending:
		return "sync pending"
	case db.FeedSyncStatusSkipped:
		return "last sync skipped"
	case db.FeedSyncStatusRejected:
		return "feed import rejected"
	case "", db.FeedSyncStatusSuccess:
	default:
		return "unknown feed status: " + lastSyncStatus
	}

	if row.LastSyncAt == nil {
		return "never synced"
	}
	if row.LastSyncAtTime.After(time.Now().UTC()) {
		return "last sync timestamp is in the future"
	}
	if time.Since(row.LastSyncAtTime) > 48*time.Hour {
		return "stale: no sync in 48h+"
	}
	if status == "warning" && row.EntriesTotal == 0 && row.EntriesSynced == 0 {
		return "no entries synced yet"
	}
	return ""
}

// HandleAdminScans serves GET /admin/scans with persisted scan history.
func (h *AdminHandler) HandleAdminScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}
	csrfToken, ok := h.adminCSRFToken(w, r, sess, "admin scans")
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	web.HandleScansWithOptions(h.store, h.renderer, h.logger, web.ScansOptions{
		ActiveNav:    "admin",
		AdminPage:    true,
		AdminSection: "scans",
		CSRFToken:    csrfToken,
	})(w, r)
}

func adminMutationErrorMessage(err error, fallback string) string {
	if errors.Is(err, db.ErrAdminAuditLog) {
		return web.Message("admin.settings.error.audit_log")
	}
	return fallback
}

func apiKeyMutationErrorMessage(err error, fallback string) string {
	if errors.Is(err, db.ErrAdminAuditLog) {
		return web.Message("admin.keys.error.audit_log")
	}
	return fallback
}

func settingsMutationErrorMessage(err error, fallback string) string {
	if errors.Is(err, db.ErrAdminAuditLog) {
		return web.Message("admin.settings.error.audit_log")
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
	csrfToken, ok := h.adminCSRFToken(w, r, sess, "admin keys")
	if !ok {
		return
	}

	offset := parseNonNegativeOffset(r.URL.Query().Get("offset"))
	keys, hasNext, err := h.listAPIKeyPage(ctx, offset)
	keysLoadError := ""
	if err != nil {
		h.logger.Error("admin keys: failed to load keys", h.adminLogAttrs(r, "error", err)...)
		keysLoadError = web.Message("admin.keys.error.load")
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
	createNonce, err := newAdminFormNonce()
	if err != nil {
		h.logger.Error("admin keys: failed to generate create nonce", h.adminLogAttrs(r, "error", err)...)
		http.Error(w, web.Message("admin.keys.error.render_form"), http.StatusInternalServerError)
		return
	}
	h.sm.SetFlash(sess.ID, apiKeyCreateNonceFlashKey, createNonce)

	data := map[string]any{
		"ActiveNav":             "admin",
		"CSRFToken":             csrfToken,
		"Keys":                  keyViews,
		"KeysLoadError":         keysLoadError,
		"KeyHasPrevious":        offset > 0,
		"KeyHasNext":            hasNext,
		"KeyCurrentOffset":      offset,
		"KeyPreviousOffset":     max(offset-adminAPIKeyPageSize, 0),
		"KeyNextOffset":         offset + adminAPIKeyPageSize,
		"KeyPageStart":          auditPageStart(offset, len(keyViews)),
		"KeyPageEnd":            offset + len(keyViews),
		"Message":               r.URL.Query().Get("msg"),
		"Error":                 r.URL.Query().Get("err"),
		"NewKey":                newKey,
		"MaxAPIKeyNameLength":   maxAPIKeyNameLength,
		"APIKeyCreateNonce":     createNonce,
		"APIKeyExpiryExample":   apiKeyExpiryExample(time.Now().UTC()),
		"APIKeyCreateName":      r.URL.Query().Get("name"),
		"APIKeyCreateExpiresAt": r.URL.Query().Get("expires_at"),
	}
	addAdminBootstrapPageState(data, h.adminBootstrapPageState(ctx, r, sess, "admin keys"))
	h.renderAdmin(w, "admin/keys.html", data)
}

func (h *AdminHandler) listAPIKeyPage(ctx context.Context, offset int) ([]db.APIKey, bool, error) {
	limit := adminAPIKeyPageSize + 1
	var (
		keys []db.APIKey
		err  error
	)
	if pager, ok := h.store.(apiKeyPageLister); ok {
		keys, err = pager.ListAPIKeysPage(ctx, limit, offset)
	} else {
		keys, err = h.store.ListAPIKeys(ctx)
		if err == nil {
			if offset >= len(keys) {
				keys = nil
			} else {
				end := min(offset+limit, len(keys))
				keys = keys[offset:end]
			}
		}
	}
	if err != nil {
		return nil, false, err
	}
	if len(keys) > adminAPIKeyPageSize {
		return keys[:adminAPIKeyPageSize], true, nil
	}
	return keys, false, nil
}

func apiKeyExpiryExample(now time.Time) string {
	return now.UTC().Add(30 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
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

// StatusLabel returns the display label for the API key lifecycle state.
func (k apiKeyView) StatusLabel() string {
	switch {
	case k.DeletedAt != nil:
		return "deleted"
	case k.RevokedAt != nil:
		return "revoked"
	case k.IsExpired():
		return "expired"
	default:
		return "active"
	}
}

// StatusClass returns the badge color classes for the API key lifecycle state.
func (k apiKeyView) StatusClass() string {
	switch {
	case k.DeletedAt != nil:
		return "pm-badge-status-disabled"
	case k.RevokedAt != nil:
		return "pm-badge-status-error"
	case k.IsExpired():
		return "pm-badge-status-warning"
	default:
		return "pm-badge-status-healthy"
	}
}

// HandleKeyCreate handles POST /admin/keys/create.
func (h *AdminHandler) HandleKeyCreate(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "api_key_create",
		bootstrapRedirectPath: "/admin/keys",
	})
	if !ok {
		return
	}
	if !h.consumeAPIKeyCreateNonce(w, r, sess) {
		return
	}

	name, err := normalizeAPIKeyName(r.PostForm.Get("name"))
	if err != nil {
		redirectAPIKeyCreateError(w, r, apiKeyNameValidationMessage(err), r.PostForm.Get("name"), r.PostForm.Get("expires_at"))
		return
	}
	expiresAt, err := parseAPIKeyExpiresAt(r.PostForm.Get("expires_at"), time.Now().UTC())
	if err != nil {
		redirectAPIKeyCreateError(w, r, err.Error(), name, r.PostForm.Get("expires_at"))
		return
	}
	if !h.requireAPIKeyCreateStepUp(w, r, name, r.PostForm.Get("expires_at")) {
		return
	}

	// Generate a random API key.
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		h.logger.Error("admin keys: failed to generate key", h.adminLogAttrs(r, "error", err)...)
		redirectAPIKeyCreateError(w, r, web.Message("admin.keys.error.generate"), name, r.PostForm.Get("expires_at"))
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
	keyID, createErr = h.store.CreateAPIKeyWithAudit(r.Context(), name, keyHash, expiresAt, audit)
	if createErr != nil {
		h.logger.Error("admin keys: failed to create key", h.adminLogAttrs(r, "error", createErr, "key_id", keyID)...)
		redirectAPIKeyCreateError(w, r, apiKeyMutationErrorMessage(createErr, web.Message("admin.keys.error.create")), name, r.PostForm.Get("expires_at"))
		return
	}

	// Store the plaintext key in a flash message so it is never exposed
	// in the URL query string (SEC-H5).
	h.sm.SetFlash(sess.ID, "newkey", plaintext)
	http.Redirect(w, r, "/admin/keys?msg="+url.QueryEscape(web.Message("admin.keys.flash.created")), http.StatusSeeOther)
}

func redirectAPIKeyCreateError(w http.ResponseWriter, r *http.Request, message, name, expiresAt string) {
	values := url.Values{"err": {message}}
	if safeName := safeAPIKeyCreateNameValue(name); safeName != "" {
		values.Set("name", safeName)
	}
	if safeExpiresAt := safeAPIKeyCreateExpiresAtValue(expiresAt); safeExpiresAt != "" {
		values.Set("expires_at", safeExpiresAt)
	}
	http.Redirect(w, r, "/admin/keys?"+values.Encode(), http.StatusSeeOther)
}

func safeAPIKeyCreateNameValue(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" || utf8.RuneCountInString(name) > maxAPIKeyNameLength {
		return ""
	}
	return name
}

func safeAPIKeyCreateExpiresAtValue(raw string) string {
	expiresAt := strings.TrimSpace(raw)
	if len(expiresAt) > len(time.RFC3339) {
		return ""
	}
	return expiresAt
}

func newAdminFormNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (h *AdminHandler) consumeAPIKeyCreateNonce(w http.ResponseWriter, r *http.Request, sess *auth.Session) bool {
	nonce := strings.TrimSpace(r.PostForm.Get(apiKeyCreateNonceField))
	if nonce == "" {
		return true
	}

	expected := h.sm.GetFlash(sess.ID, apiKeyCreateNonceFlashKey)
	if expected != "" && subtle.ConstantTimeCompare([]byte(nonce), []byte(expected)) == 1 {
		return true
	}

	if h.sm.PeekFlash(sess.ID, "newkey") != "" {
		http.Redirect(w, r, "/admin/keys?msg="+url.QueryEscape(web.Message("admin.keys.flash.created")), http.StatusSeeOther)
		return false
	}

	http.Redirect(w, r, "/admin/keys?err="+url.QueryEscape(web.Message("admin.keys.error.create_expired")), http.StatusSeeOther)
	return false
}

func normalizeAPIKeyName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New(web.Message("admin.keys.error.name_required"))
	}
	if utf8.RuneCountInString(name) > maxAPIKeyNameLength {
		return "", errors.New(web.Message("admin.keys.error.name_too_long"))
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
		return nil, errors.New(web.Message("admin.keys.error.expiration_required"))
	}

	expiresAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, errors.New(web.Message("admin.keys.error.expiration_invalid"))
	}
	if _, offset := expiresAt.Zone(); offset != 0 || !strings.HasSuffix(raw, "Z") {
		return nil, errors.New(web.Message("admin.keys.error.expiration_utc"))
	}
	expiresAt = expiresAt.UTC()
	if !expiresAt.After(now.UTC()) {
		return nil, errors.New(web.Message("admin.keys.error.expiration_future"))
	}
	if expiresAt.After(now.UTC().Add(maxAPIKeyLifetime)) {
		return nil, errors.New(web.Message("admin.keys.error.expiration_max_lifetime"))
	}
	return &expiresAt, nil
}

func (h *AdminHandler) requireAPIKeyCreateStepUp(w http.ResponseWriter, r *http.Request, name, expiresAt string) bool {
	ip := clientIP(r)
	if h.isLockedOut(ip) {
		telemetry.Default().IncAuthLoginFailures()
		if h.markLockoutAudited(ip) {
			h.logger.Warn("api key create attempt from locked out principal", h.adminLogAttrs(r, "client_ip", ip)...)
			if err := h.auditLog(r, "login_lockout", map[string]string{
				"reason": "too many failed attempts",
			}); err != nil {
				redirectAPIKeyCreateError(w, r, web.Message("admin.keys.error.audit_log"), name, expiresAt)
				return false
			}
			h.markLockoutAuditWritten(ip)
		}
		redirectAPIKeyCreateError(w, r, web.Message("admin.keys.error.too_many_attempts"), name, expiresAt)
		return false
	}

	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil || adminAuth == nil {
		redirectAPIKeyCreateError(w, r, web.Message("admin.keys.error.verify_current_password"), name, expiresAt)
		return false
	}
	if !auth.CheckPassword(adminAuth.PasswordHash, r.PostForm.Get("current_password")) {
		if err := h.auditLog(r, "api_key_create_failed", map[string]string{
			"reason": "invalid current password",
		}); err != nil {
			redirectAPIKeyCreateError(w, r, web.Message("admin.keys.error.audit_log"), name, expiresAt)
			return false
		}
		h.recordFailedAttempt(ip)
		redirectAPIKeyCreateError(w, r, web.Message("admin.keys.error.current_password_incorrect"), name, expiresAt)
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
		successMessage: web.Message("admin.keys.flash.revoked"),
		failureMessage: web.Message("admin.keys.error.revoke"),
		auditedAction: func(ctx context.Context, keyID int, audit *adminAuditEntry) error {
			return h.store.RevokeAPIKeyWithAudit(ctx, keyID, audit)
		},
	})
}

// HandleKeyDelete handles POST /admin/keys/delete.
func (h *AdminHandler) HandleKeyDelete(w http.ResponseWriter, r *http.Request) {
	h.handleAPIKeyMutation(w, r, apiKeyMutation{
		auditAction:    "api_key_delete",
		logVerb:        "delete",
		successMessage: web.Message("admin.keys.flash.deleted"),
		failureMessage: web.Message("admin.keys.error.delete"),
		auditedAction: func(ctx context.Context, keyID int, audit *adminAuditEntry) error {
			return h.store.DeleteAPIKeyWithAudit(ctx, keyID, audit)
		},
	})
}

type apiKeyMutation struct {
	auditAction    string
	logVerb        string
	successMessage string
	failureMessage string
	auditedAction  func(context.Context, int, *adminAuditEntry) error
}

func (h *AdminHandler) handleAPIKeyMutation(w http.ResponseWriter, r *http.Request, mutation apiKeyMutation) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            mutation.auditAction,
		bootstrapRedirectPath: "/admin/keys",
	}); !ok {
		return
	}

	returnOffset := parseNonNegativeOffset(r.PostForm.Get("return_offset"))
	keyIDStr := r.PostForm.Get("key_id")
	keyID, err := strconv.Atoi(keyIDStr)
	if err != nil {
		http.Redirect(w, r, adminKeysURL(returnOffset, "err", web.Message("admin.keys.error.invalid_id")), http.StatusSeeOther)
		return
	}

	auditDetails, err := h.apiKeyAuditDetails(r.Context(), keyID)
	if err != nil {
		h.logger.Error("admin keys: failed to load key metadata", h.adminLogAttrs(r, "action", mutation.logVerb, "error", err, "key_id", keyID)...)
		http.Redirect(w, r, adminKeysURL(returnOffset, "err", mutation.failureMessage), http.StatusSeeOther)
		return
	}

	audit := h.adminAuditEntry(r, mutation.auditAction, auditDetails)
	auditErr := mutation.auditedAction(r.Context(), keyID, audit)
	if auditErr != nil {
		h.logger.Error("admin keys: failed to mutate key", h.adminLogAttrs(r, "action", mutation.logVerb, "error", auditErr, "key_id", keyID)...)
		http.Redirect(w, r, adminKeysURL(returnOffset, "err", apiKeyMutationErrorMessage(auditErr, mutation.failureMessage)), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, adminKeysURL(returnOffset, "msg", mutation.successMessage), http.StatusSeeOther)
}

func adminKeysURL(offset int, param, value string) string {
	values := url.Values{}
	if strings.TrimSpace(param) != "" && value != "" {
		values.Set(param, value)
	}
	if offset > 0 {
		values.Set("offset", strconv.Itoa(offset))
	}
	if len(values) == 0 {
		return "/admin/keys"
	}
	return "/admin/keys?" + values.Encode()
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

// HandleAdminAudit serves GET /admin/audit with the audit log table.
func (h *AdminHandler) HandleAdminAudit(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	csrfToken, ok := h.adminCSRFToken(w, r, sess, "admin audit")
	if !ok {
		return
	}

	offset := parseAdminAuditOffset(r.URL.Query().Get("offset"))
	entries, hasNext, err := h.listAdminAuditPage(ctx, offset)
	auditLoadError := ""
	if err != nil {
		h.logger.Error("admin audit: failed to load entries", h.adminLogAttrs(r, "error", err)...)
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
		"AuditPageOutOfRange": auditLoadError == "" && offset > 0 && len(views) == 0,
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

// ActionClass returns the badge color classes for the audit action.
func (v auditLogView) ActionClass() string {
	switch v.Action {
	case "login_success":
		return "pm-badge-status-configured"
	case "login_failed":
		return "pm-badge-status-error"
	case "login_lockout":
		return "pm-badge-status-warning"
	default:
		return "pm-badge-status-default"
	}
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
		return "pm-badge-status-healthy"
	case db.AdminAuditIntegrityBroken:
		return "pm-badge-status-error"
	default:
		return "pm-badge-status-default"
	}
}

// HandleAdminSettings serves GET /admin/settings.
func (h *AdminHandler) HandleAdminSettings(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	csrfToken, ok := h.adminCSRFToken(w, r, sess, "admin settings")
	if !ok {
		return
	}

	data := h.buildAdminSettingsPageData(ctx, r, sess, csrfToken, r.URL.Query())
	h.renderAdmin(w, "admin/settings.html", data)
}

func (h *AdminHandler) buildAdminSettingsPageData(ctx context.Context, r *http.Request, sess *auth.Session, csrfToken string, query url.Values) map[string]any {
	state := h.loadAdminSettingsViewState(ctx, r, sess)
	return adminSettingsTemplateData(state, csrfToken, query)
}

type adminSettingsViewState struct {
	ServerMode                     string
	SyncInterval                   string
	FeedSyncOnStartup              string
	AdminSessionTimeout            string
	MetricsAddr                    string
	DatabaseHost                   string
	DatabaseName                   string
	DatabaseSSLMode                string
	RuntimeBlockThreshold          string
	RuntimeRateLimitPerMinute      int
	RuntimeRateLimitBurst          int
	RuntimeScanLogRetentionDays    int
	RuntimeAdminAuditRetentionDays int
	SystemBlockThreshold           string
	SystemRateLimitPerMinute       int
	SystemRateLimitBurst           int
	SystemScanLogRetentionDays     int
	SystemAdminAuditRetentionDays  int
	HasSystemSettings              bool
	SystemSettingsUpdatedAt        time.Time
	SystemSettingsRevision         string
	HasSystemSettingsUpdatedAt     bool
	SystemSettingsLoadError        string
	LastLoginAt                    time.Time
	HasLastLoginAt                 bool
	PasswordChangedAt              time.Time
	HasPasswordChangedAt           bool
	AdminAuthLoadError             string
	BootstrapWarning               bool
}

func defaultAdminSettingsViewState() adminSettingsViewState {
	return adminSettingsViewState{
		ServerMode:                     "unknown",
		SyncInterval:                   "unknown",
		FeedSyncOnStartup:              "unknown",
		AdminSessionTimeout:            "unknown",
		MetricsAddr:                    "unknown",
		DatabaseHost:                   "unknown",
		DatabaseName:                   "unknown",
		DatabaseSSLMode:                "unknown",
		RuntimeBlockThreshold:          "CRITICAL",
		RuntimeRateLimitPerMinute:      60,
		RuntimeRateLimitBurst:          60,
		RuntimeScanLogRetentionDays:    retentionDurationDays(adminMetadataRetentionDefault),
		RuntimeAdminAuditRetentionDays: retentionDurationDays(adminMetadataRetentionDefault),
	}
}

func (h *AdminHandler) loadAdminSettingsViewState(ctx context.Context, r *http.Request, sess *auth.Session) adminSettingsViewState {
	state := defaultAdminSettingsViewState()
	h.loadAdminSettingsAuthState(ctx, r, sess, &state)
	h.applyAdminSettingsRuntimeState(&state)
	state.SystemBlockThreshold = state.RuntimeBlockThreshold
	state.SystemRateLimitPerMinute = state.RuntimeRateLimitPerMinute
	state.SystemRateLimitBurst = state.RuntimeRateLimitBurst
	state.SystemScanLogRetentionDays = state.RuntimeScanLogRetentionDays
	state.SystemAdminAuditRetentionDays = state.RuntimeAdminAuditRetentionDays
	h.loadPersistedAdminSettingsState(ctx, r, &state)
	return state
}

func (h *AdminHandler) loadAdminSettingsAuthState(ctx context.Context, r *http.Request, sess *auth.Session, state *adminSettingsViewState) {
	adminAuth, err := h.store.GetAdminAuth(ctx)
	if err != nil {
		h.logger.Error("admin settings: failed to get auth info", h.adminLogAttrs(r, "error", err)...)
		state.AdminAuthLoadError = web.Message("admin.settings.error.auth_state")
	}

	if adminAuth != nil {
		if adminAuth.LastLoginAt != nil {
			state.LastLoginAt = *adminAuth.LastLoginAt
			state.HasLastLoginAt = true
		}
		if adminAuth.PasswordChangedAt != nil {
			state.PasswordChangedAt = *adminAuth.PasswordChangedAt
			state.HasPasswordChangedAt = true
		}
	}
	state.BootstrapWarning = sess.AuthenticatedWithBootstrap || (adminAuth != nil && adminAuth.PasswordIsBootstrap)
}

func (h *AdminHandler) applyAdminSettingsRuntimeState(state *adminSettingsViewState) {
	if h.cfg != nil {
		state.ServerMode = string(h.cfg.Server.Mode)
		state.SyncInterval = formatRuntimeDuration(h.cfg.FeedSync.Interval)
		state.FeedSyncOnStartup = strconv.FormatBool(h.cfg.FeedSync.OnStartup)
		state.AdminSessionTimeout = formatRuntimeDuration(h.cfg.Admin.SessionTimeout)
		state.MetricsAddr = h.cfg.Metrics.Addr()
		state.DatabaseHost = h.cfg.DB.Host
		state.DatabaseName = h.cfg.DB.Name
		state.DatabaseSSLMode = h.cfg.DB.SSLMode
		if h.cfg.Server.BlockThreshold != "" {
			state.RuntimeBlockThreshold = h.cfg.Server.BlockThreshold
		}
		if h.cfg.Server.RateLimitPerMinute > 0 {
			state.RuntimeRateLimitPerMinute = h.cfg.Server.RateLimitPerMinute
		}
		if h.cfg.Server.RateLimitBurst > 0 {
			state.RuntimeRateLimitBurst = h.cfg.Server.RateLimitBurst
		}
		if h.cfg.Retention.ScanLog >= 0 {
			state.RuntimeScanLogRetentionDays = retentionDurationDays(h.cfg.Retention.ScanLog)
		}
		if h.cfg.Retention.AdminAuditLog >= 0 {
			state.RuntimeAdminAuditRetentionDays = retentionDurationDays(h.cfg.Retention.AdminAuditLog)
		}
	}
	if h.runtime != nil {
		if threshold := h.runtime.BlockThreshold(); threshold != "" {
			state.RuntimeBlockThreshold = threshold
		}
		perMinute, burst := h.runtime.RateLimit()
		if perMinute > 0 {
			state.RuntimeRateLimitPerMinute = perMinute
		}
		if burst > 0 {
			state.RuntimeRateLimitBurst = burst
		}
		retention := h.runtime.Retention()
		if retention.ScanLog >= 0 {
			state.RuntimeScanLogRetentionDays = retentionDurationDays(retention.ScanLog)
		}
		if retention.AdminAuditLog >= 0 {
			state.RuntimeAdminAuditRetentionDays = retentionDurationDays(retention.AdminAuditLog)
		}
	}
}

func (h *AdminHandler) loadPersistedAdminSettingsState(ctx context.Context, r *http.Request, state *adminSettingsViewState) {
	systemSettings, err := h.store.GetSystemSettings(ctx)
	if err != nil {
		h.logger.Error("admin settings: failed to get system settings", h.adminLogAttrs(r, "error", err)...)
		state.SystemSettingsLoadError = web.Message("admin.settings.error.system_settings_load")
	}
	if systemSettings != nil {
		state.HasSystemSettings = true
		if systemSettings.BlockThreshold != "" {
			state.SystemBlockThreshold = systemSettings.BlockThreshold
		}
		if systemSettings.RateLimitPerMinute > 0 {
			state.SystemRateLimitPerMinute = systemSettings.RateLimitPerMinute
		}
		if systemSettings.RateLimitBurst > 0 {
			state.SystemRateLimitBurst = systemSettings.RateLimitBurst
		}
		if systemSettings.ScanLogRetention >= 0 {
			state.SystemScanLogRetentionDays = retentionDurationDays(systemSettings.ScanLogRetention)
		}
		if systemSettings.AdminAuditRetention >= 0 {
			state.SystemAdminAuditRetentionDays = retentionDurationDays(systemSettings.AdminAuditRetention)
		}
		if !systemSettings.UpdatedAt.IsZero() {
			state.SystemSettingsUpdatedAt = systemSettings.UpdatedAt
			state.SystemSettingsRevision = systemSettings.UpdatedAt.UTC().Format(time.RFC3339Nano)
			state.HasSystemSettingsUpdatedAt = true
		}
	}
}

func retentionDurationDays(retention time.Duration) int {
	if retention <= 0 {
		return 0
	}
	days := retention / adminRetentionDay
	if retention%adminRetentionDay != 0 {
		days++
	}
	if days > time.Duration(MaxAdminRetentionDays) {
		return MaxAdminRetentionDays
	}
	return int(days)
}

func adminSettingsTemplateData(state adminSettingsViewState, csrfToken string, query url.Values) map[string]any {
	data := map[string]any{
		"ActiveNav":                      "admin",
		"CSRFToken":                      csrfToken,
		"ServerMode":                     state.ServerMode,
		"SyncInterval":                   state.SyncInterval,
		"FeedSyncOnStartup":              state.FeedSyncOnStartup,
		"AdminSessionTimeout":            state.AdminSessionTimeout,
		"MetricsAddr":                    state.MetricsAddr,
		"DatabaseHost":                   state.DatabaseHost,
		"DatabaseName":                   state.DatabaseName,
		"DatabaseSSLMode":                state.DatabaseSSLMode,
		"RuntimeBlockThreshold":          state.RuntimeBlockThreshold,
		"RuntimeRateLimitPerMinute":      state.RuntimeRateLimitPerMinute,
		"RuntimeRateLimitBurst":          state.RuntimeRateLimitBurst,
		"RuntimeScanLogRetentionDays":    state.RuntimeScanLogRetentionDays,
		"RuntimeAdminAuditRetentionDays": state.RuntimeAdminAuditRetentionDays,
		"SystemBlockThreshold":           state.SystemBlockThreshold,
		"SystemRateLimitPerMinute":       state.SystemRateLimitPerMinute,
		"SystemRateLimitBurst":           state.SystemRateLimitBurst,
		"SystemScanLogRetentionDays":     state.SystemScanLogRetentionDays,
		"SystemAdminAuditRetentionDays":  state.SystemAdminAuditRetentionDays,
		"MaxAdminRateLimit":              MaxAdminRateLimit,
		"MaxAdminRetentionDays":          MaxAdminRetentionDays,
		"HasSystemSettings":              state.HasSystemSettings,
		"SystemSettingsUpdatedAt":        state.SystemSettingsUpdatedAt,
		"SystemSettingsRevision":         state.SystemSettingsRevision,
		"HasSystemSettingsUpdatedAt":     state.HasSystemSettingsUpdatedAt,
		"SystemSettingsLoadError":        state.SystemSettingsLoadError,
		"LastLoginAt":                    state.LastLoginAt,
		"HasLastLoginAt":                 state.HasLastLoginAt,
		"PasswordChangedAt":              state.PasswordChangedAt,
		"HasPasswordChangedAt":           state.HasPasswordChangedAt,
		"AdminAuthLoadError":             state.AdminAuthLoadError,
		"BootstrapWarning":               state.BootstrapWarning,
		"MinPasswordLength":              adminPasswordMinLength,
		"Message":                        query.Get("msg"),
		"Error":                          query.Get("err"),
	}
	return data
}

// HandlePasswordChange handles POST /admin/settings/password.
func (h *AdminHandler) HandlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{csrfAction: "password_change"}); !ok {
		return
	}

	ip := clientIP(r)
	if h.isLockedOut(ip) {
		telemetry.Default().IncAuthLoginFailures()
		if h.markLockoutAudited(ip) {
			h.logger.Warn("password change attempt from locked out principal", h.adminLogAttrs(r, "client_ip", ip)...)
			if err := h.auditLog(r, "login_lockout", map[string]string{
				"reason": "too many failed attempts",
			}); err != nil {
				http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.audit_log")), http.StatusSeeOther)
				return
			}
			h.markLockoutAuditWritten(ip)
		}
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.password.too_many_attempts")), http.StatusSeeOther)
		return
	}

	currentPassword := r.PostForm.Get("current_password")
	newPassword := r.PostForm.Get("new_password")
	confirmPassword := r.PostForm.Get("confirm_password")

	if newPassword != confirmPassword {
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.password.mismatch")), http.StatusSeeOther)
		return
	}

	if err := auth.ValidateAdminPassword(newPassword); err != nil {
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.password.too_short", adminPasswordMinLength)), http.StatusSeeOther)
		return
	}

	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil || adminAuth == nil {
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.password.verify_current")), http.StatusSeeOther)
		return
	}

	if !auth.CheckPassword(adminAuth.PasswordHash, currentPassword) {
		if err := h.auditLog(r, "password_change_failed", map[string]string{
			"reason": "invalid current password",
		}); err != nil {
			http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.audit_log")), http.StatusSeeOther)
			return
		}
		h.recordFailedAttempt(ip)
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.password.current_incorrect")), http.StatusSeeOther)
		return
	}

	if auth.CheckPassword(adminAuth.PasswordHash, newPassword) {
		if err := h.auditLog(r, "password_change_failed", map[string]string{
			"reason": "new password reused current password",
		}); err != nil {
			http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.audit_log")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.password.reused")), http.StatusSeeOther)
		return
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		h.logger.Error("admin settings: failed to hash new password", h.adminLogAttrs(r, "error", err)...)
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.password.update")), http.StatusSeeOther)
		return
	}

	audit := h.adminAuditEntry(r, "password_change", map[string]string{})
	updateErr := h.store.ChangeAdminPasswordWithAudit(r.Context(), newHash, adminAuth.PasswordHash, audit)
	if updateErr != nil {
		h.logger.Error("admin settings: failed to update password", h.adminLogAttrs(r, "error", updateErr)...)
		if errors.Is(updateErr, db.ErrAdminAuthConflict) {
			http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(web.Message("admin.settings.error.password.current_incorrect")), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/admin/settings?err="+url.QueryEscape(settingsMutationErrorMessage(updateErr, web.Message("admin.settings.error.password.update"))), http.StatusSeeOther)
		return
	}

	h.resetAttempts(ip)

	if _, err := h.sm.CreateExclusiveAdmin(w); err != nil {
		h.logger.Error("admin settings: failed to rotate admin session", h.adminLogAttrs(r, "error", err)...)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/settings?msg="+url.QueryEscape(web.Message("admin.settings.flash.password_changed")), http.StatusSeeOther)
}

// renderAdmin is a helper that renders an admin template with error handling.
func (h *AdminHandler) renderAdmin(w http.ResponseWriter, tmpl string, data any) {
	h.renderAdminWithStatus(w, tmpl, data, http.StatusOK)
}

func (h *AdminHandler) renderAdminWithStatus(w http.ResponseWriter, tmpl string, data any, status int) {
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
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
