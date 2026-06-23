// Package admin implements the admin-only HTTP handlers for the Packmon
// server. All routes except the login page itself require an active
// admin session.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	feedhealth "github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/requestctx"
	"github.com/8linkz-sec/packmon/internal/telemetry"
	"github.com/8linkz-sec/packmon/internal/web"
)

const (
	// loginMaxAttempts is the number of allowed login attempts per IP
	// before a lockout is triggered.
	loginMaxAttempts = 5

	// loginLockoutDuration is how long an IP is locked out after
	// exceeding the maximum number of login attempts.
	loginLockoutDuration = 15 * time.Minute

	adminAuditWriteTimeout = 5 * time.Second

	adminLoginAccountKey = "account:admin"

	adminUnconfiguredLoginError = "Admin account has not been configured."
)

// loginAttempt tracks failed login attempts for an IP address or the shared
// admin account.
type loginAttempt struct {
	count            int
	lockedAt         time.Time
	lastFailedAt     time.Time
	lockoutAuditedAt time.Time
}

// FeedSyncFunc triggers an immediate feed synchronisation.
type FeedSyncFunc func(ctx context.Context, feedName string) error

// FeedConfigApplyFunc applies a saved feed configuration to the running
// process so changes take effect without a server restart.
type FeedConfigApplyFunc func(ctx context.Context, feed config.FeedSettings) error

// FeedConfigResetFunc applies the runtime default for a feed after its saved
// database override has been removed.
type FeedConfigResetFunc func(ctx context.Context, feedName string) error

// Store is the admin handler persistence surface. Optional atomic/audited
// variants are modeled as separate interfaces in pages.go.
type Store interface {
	GetAdminAuth(ctx context.Context) (*db.AdminAuth, error)
	UpsertAdminAuth(ctx context.Context, passwordHash string, isBootstrap bool) error
	InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error
	ListAdminAuditLog(ctx context.Context, limit int) ([]db.AdminAuditLogEntry, error)

	ListAPIKeys(ctx context.Context) ([]db.APIKey, error)
	CreateAPIKey(ctx context.Context, name, keyHash string, expiresAt *time.Time) (int, error)
	RevokeAPIKey(ctx context.Context, keyID int) error
	DeleteAPIKey(ctx context.Context, keyID int) error

	GetFeedSyncStatus(ctx context.Context, feedName string) (*db.FeedSyncStatus, error)
	UpsertFeedSyncStatus(ctx context.Context, status *db.FeedSyncStatus) error
	ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error)
	GetFeedConfig(ctx context.Context, feedName string) (*db.FeedConfig, error)
	UpsertFeedConfig(ctx context.Context, cfg *db.FeedConfig) error
	DeleteFeedConfig(ctx context.Context, feedName string) error
	ListFeedConfigs(ctx context.Context) ([]db.FeedConfig, error)

	GetSystemSettings(ctx context.Context) (*db.SystemSettings, error)
	UpsertSystemSettings(ctx context.Context, settings *db.SystemSettings) error

	DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error)

	ListManualAdvisories(ctx context.Context, limit int) ([]db.ManualAdvisory, error)
	UpsertManualAdvisory(ctx context.Context, advisory *db.ManualAdvisory) error
	DeleteManualAdvisory(ctx context.Context, id string) error

	QueueStats(ctx context.Context) (*db.QueueStatsResult, error)
	ListQueueJobs(ctx context.Context, status string, limit int) ([]db.RefreshJob, error)
	PurgeQueue(ctx context.Context) (int, error)
	UpdateQueueJobPriority(ctx context.Context, jobID, priority int) error
	PauseQueueJob(ctx context.Context, jobID int) error
	ResumeQueueJob(ctx context.Context, jobID int) error
	RetryQueueJob(ctx context.Context, jobID int) error
	ClearQueue(ctx context.Context, statuses []string) (int, error)
}

// AdminHandler holds the dependencies for admin HTTP handlers.
type AdminHandler struct {
	store           Store
	sm              *auth.SessionManager
	renderer        *web.Renderer
	logger          *slog.Logger
	cfg             *config.Config
	runtime         *config.RuntimeSettings
	rootCtx         context.Context
	syncFeed        FeedSyncFunc
	applyFeedConfig FeedConfigApplyFunc
	resetFeedConfig FeedConfigResetFunc

	// loginMu protects the loginAttempts map.
	loginMu       sync.Mutex
	loginAttempts map[string]*loginAttempt

	manualSyncMu sync.Mutex
	manualSyncs  map[string]struct{}
}

// NewAdminHandler creates an AdminHandler with the given dependencies.
// The provided context controls the lifetime of the background cleanup
// goroutine; when the context is cancelled the goroutine exits.
func NewAdminHandler(ctx context.Context, store Store, sm *auth.SessionManager, renderer *web.Renderer, logger *slog.Logger, cfg *config.Config, runtime *config.RuntimeSettings, syncFeed FeedSyncFunc) *AdminHandler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &AdminHandler{
		store:         store,
		sm:            sm,
		renderer:      renderer,
		logger:        logger,
		cfg:           cfg,
		runtime:       runtime,
		rootCtx:       ctx,
		syncFeed:      syncFeed,
		loginAttempts: make(map[string]*loginAttempt),
		manualSyncs:   make(map[string]struct{}),
	}
	// Background goroutine to evict stale lockout entries.
	go h.cleanupAttempts(ctx)
	return h
}

// SetFeedConfigApplyFunc installs the callback used after admin feed saves.
// It is kept as a setter so tests and server wiring can opt in without making
// older handler construction sites carry nil placeholders.
func (h *AdminHandler) SetFeedConfigApplyFunc(fn FeedConfigApplyFunc) {
	if h == nil {
		return
	}
	h.applyFeedConfig = fn
}

// SetFeedConfigResetFunc installs the callback used after admin feed resets.
func (h *AdminHandler) SetFeedConfigResetFunc(fn FeedConfigResetFunc) {
	if h == nil {
		return
	}
	h.resetFeedConfig = fn
}

// HandleLogin processes both GET (show login form) and POST (validate
// credentials) requests to /admin/login.
//
// GET returns a minimal HTML login form with CSRF token. Templates
// will be created by another agent; this handler provides the data.
//
// POST validates the username/password against the stored bcrypt hash,
// applies rate limiting per IP (5 attempts, then 15 min lockout), and
// creates a session on success.
func (h *AdminHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.showLoginForm(w, r, "")
	case http.MethodPost:
		h.processLogin(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// showLoginForm renders the login page. The errorMsg parameter is shown
// when a previous login attempt failed.
func (h *AdminHandler) showLoginForm(w http.ResponseWriter, r *http.Request, errorMsg string) {
	// If user already has a valid admin session, redirect to admin dashboard.
	// Pre-auth sessions only carry login CSRF tokens and must still render the
	// login form, including lockout and validation errors.
	if sess := h.sm.Get(r); sess != nil && sess.Admin {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}

	// Create a short-lived, non-admin session just to carry the CSRF token on
	// the login form. It is created non-admin atomically (no post-hoc mutation)
	// and expires quickly, so anonymous form loads cannot accumulate long-lived
	// sessions. On successful login a new authenticated session replaces it.
	sess, err := h.sm.CreatePreAuth(w)
	if err != nil {
		h.logger.Error("failed to create login session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	csrfToken, err := auth.CSRFToken(sess)
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	data := map[string]any{
		"ActiveNav":         "admin",
		"CSRFToken":         csrfToken,
		"Error":             errorMsg,
		"AdminUnconfigured": errorMsg == adminUnconfiguredLoginError,
		"NextPath":          auth.SafeAdminReturnTarget(r.URL.Query().Get("next")),
	}
	if err := h.renderer.Render(w, "admin/login.html", data); err != nil {
		h.logger.Error("failed to render login template", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// processLogin validates the credentials from the POST form.
func (h *AdminHandler) processLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !parseAdminForm(w, r) {
		return
	}

	// Check rate limit before doing any work.
	if h.isLockedOut(ip) {
		telemetry.Default().IncAuthLoginFailures()
		if h.markLockoutAudited(ip) {
			h.logger.Warn("login attempt from locked out principal", "ip", ip)
			h.auditLogBestEffort(r, "login_lockout", map[string]string{
				"reason": "too many failed attempts",
			})
		}
		h.showLoginForm(w, r, "Too many failed login attempts. Please try again later.")
		return
	}

	// Validate CSRF token against the session created when the form was rendered.
	sess := h.sm.Get(r)
	if sess == nil || !auth.ValidateCSRF(r, sess) {
		h.recordFailedAttemptFor(ip, false)
		h.logger.Warn("CSRF validation failed on login", "ip", ip)
		h.showLoginForm(w, r, "Invalid request. Please try again.")
		return
	}

	// Destroy the pre-login CSRF session -- we will create a fresh one
	// on success or show a new form on failure.
	h.sm.Delete(w, r)

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	nextPath := auth.SafeAdminReturnTarget(r.PostForm.Get("next"))

	if username != "admin" {
		h.recordFailedAttempt(ip)
		h.auditLogBestEffort(r, "login_failed", map[string]string{
			"reason": "invalid username",
		})
		h.showLoginForm(w, r, "Invalid username or password.")
		return
	}

	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil {
		h.logger.Error("failed to get admin auth", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if adminAuth == nil {
		h.logger.Warn("login attempt but no admin account exists", "ip", ip)
		h.showLoginForm(w, r, adminUnconfiguredLoginError)
		return
	}

	if !auth.CheckPassword(adminAuth.PasswordHash, password) {
		h.recordFailedAttempt(ip)
		h.auditLogBestEffort(r, "login_failed", map[string]string{
			"reason": "invalid password",
		})
		h.showLoginForm(w, r, "Invalid username or password.")
		return
	}

	// Successful login -- reset attempts and create session.
	h.resetAttempts(ip)

	_, err = h.sm.CreateAdmin(w, adminAuth.PasswordIsBootstrap)
	if err != nil {
		h.logger.Error("failed to create admin session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.auditLogBestEffort(r, "login_success", map[string]string{})

	h.logger.Info("admin login successful", "ip", ip)
	auth.RedirectSameOrigin(w, r, adminLoginSuccessRedirect(nextPath), http.StatusSeeOther)
}

func adminLoginSuccessRedirect(nextPath string) string {
	if nextPath == "" {
		return "/admin/"
	}
	return nextPath
}

// HandleLogout destroys the admin session and redirects to the login page.
// Requires a valid CSRF token to prevent cross-site logout attacks (SEC-H6).
func (h *AdminHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !parseAdminForm(w, r) {
		return
	}

	sess := h.sm.Get(r)
	if sess == nil || !auth.ValidateCSRF(r, sess) {
		h.logger.Warn("CSRF validation failed on logout", "ip", clientIP(r))
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	ip := clientIP(r)
	h.sm.Delete(w, r)

	h.auditLogBestEffort(r, "logout", map[string]string{})

	h.logger.Info("admin logout", "ip", ip)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// HandleDashboard serves the admin dashboard page with DB stats, feed
// status, and queue summary.
func (h *AdminHandler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()

	csrfToken, _ := auth.CSRFToken(sess)

	// Check if this session is still constrained by the bootstrap password.
	bootstrapWarning := sess.AuthenticatedWithBootstrap
	adminAuthLoadError := ""
	adminAuth, err := h.store.GetAdminAuth(ctx)
	if err != nil {
		h.logger.Error("admin dashboard: failed to check bootstrap flag", "error", err)
		adminAuthLoadError = "Bootstrap password status could not be verified. Check the server logs and database connection before relying on this account state."
	} else if adminAuth != nil && adminAuth.PasswordIsBootstrap {
		bootstrapWarning = true
	}

	stats, err := h.store.DashboardStats(ctx)
	dashboardStatsLoadError := ""
	if err != nil {
		h.logger.Error("admin dashboard: failed to load stats", "error", err)
		stats = &db.DashboardStatsResult{BySeverity: map[string]int{}}
		dashboardStatsLoadError = "Dashboard stats could not be loaded. Check the server logs and database connection before relying on these totals."
	}

	feeds, err := h.store.ListFeedSyncStatuses(ctx)
	feedStatusLoadError := ""
	if err != nil {
		h.logger.Error("admin dashboard: failed to load feed statuses", "error", err)
		feedStatusLoadError = "Feed status could not be loaded. Check the server logs and database connection before relying on feed health."
	}

	feedRows := h.adminFeedRows(feeds)

	queueStats, err := h.store.QueueStats(ctx)
	queueStatsLoadError := ""
	if err != nil {
		h.logger.Error("admin dashboard: failed to load queue stats", "error", err)
		queueStats = &db.QueueStatsResult{}
		queueStatsLoadError = "Queue summary could not be loaded. Check the server logs and database connection before relying on queue counts."
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	data := map[string]any{
		"ActiveNav":               "admin",
		"CSRFToken":               csrfToken,
		"Stats":                   stats,
		"DashboardStatsLoadError": dashboardStatsLoadError,
		"Feeds":                   feedRows,
		"FeedStatusLoadError":     feedStatusLoadError,
		"QueueStats":              queueStats,
		"QueueStatsLoadError":     queueStatsLoadError,
		"AdminAuthLoadError":      adminAuthLoadError,
		"BootstrapWarning":        bootstrapWarning,
	}
	if err := h.renderer.Render(w, "admin/dashboard.html", data); err != nil {
		h.logger.Error("admin dashboard: render failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// adminFeedRow is a view model for feed status rows in admin templates.
type adminFeedRow struct {
	FeedName        string
	Status          string
	LastSyncAt      *time.Time
	LastSyncAtTime  time.Time
	LastSyncStatus  string
	EntriesSynced   int
	EntriesTotal    int
	LastError       string
	DurationStr     string
	ConfigMode      string
	ConfigEnabled   bool
	APIKeyState     string
	FeedKey         string
	SyncIntervalStr string
}

// adminFeedHealth derives a health string from runtime config and sync status
// for admin views.
func adminFeedHealth(feed config.FeedSettings, s *db.FeedSyncStatus) string {
	health := feedhealth.RuntimeFeedHealth(feedhealth.RuntimeHealthConfig{
		Enabled:              feed.Enabled,
		Mode:                 feedhealth.FeedMode(feed.Mode),
		RequiresAPIKey:       feed.RequiresAPIKey,
		APIKey:               feed.APIKey,
		SupportsSyncInterval: feed.SupportsSyncInterval,
	}, s, feedhealth.HealthOptions{})
	if health.Status == "pending" && s != nil && strings.EqualFold(s.LastSyncStatus, "running") {
		return "running"
	}
	return health.Status
}

// -- Rate limiting helpers ---------------------------------------------------

// isLockedOut returns true if the given IP has exceeded the maximum
// login attempts, or the shared admin account has exceeded the maximum
// attempts, and the relevant lockout has not expired.
func (h *AdminHandler) isLockedOut(ip string) bool {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	now := time.Now()
	return h.isAttemptLocked(ip, now) || h.isAttemptLocked(adminLoginAccountKey, now)
}

// recordFailedAttempt increments the failure count for the given IP.
// When the count reaches the threshold, the lockout timer starts.
func (h *AdminHandler) recordFailedAttempt(ip string) {
	h.recordFailedAttemptFor(ip, true)
}

func (h *AdminHandler) recordFailedAttemptFor(ip string, includeAccount bool) {
	telemetry.Default().IncAuthLoginFailures()

	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	now := time.Now()
	h.recordFailedAttemptLocked(ip, now)
	if includeAccount {
		h.recordFailedAttemptLocked(adminLoginAccountKey, now)
	}
}

func (h *AdminHandler) recordFailedAttemptLocked(key string, now time.Time) {
	a, ok := h.loginAttempts[key]
	if !ok {
		a = &loginAttempt{}
		h.loginAttempts[key] = a
	} else if a.lockedAt.IsZero() && !a.lastFailedAt.IsZero() && now.Sub(a.lastFailedAt) >= loginLockoutDuration {
		*a = loginAttempt{}
	}

	a.count++
	a.lastFailedAt = now
	if a.count >= loginMaxAttempts {
		if a.lockedAt.IsZero() {
			a.lockedAt = now
		}
	}
}

func (h *AdminHandler) isAttemptLocked(key string, now time.Time) bool {
	a, ok := h.loginAttempts[key]
	if !ok || a.count < loginMaxAttempts || a.lockedAt.IsZero() {
		return false
	}
	if now.Sub(a.lockedAt) < loginLockoutDuration {
		return true
	}
	delete(h.loginAttempts, key)
	return false
}

func (h *AdminHandler) markLockoutAudited(ip string) bool {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	now := time.Now()
	shouldAudit := false
	for _, key := range []string{ip, adminLoginAccountKey} {
		a, ok := h.loginAttempts[key]
		if !ok || !h.isAttemptLocked(key, now) {
			continue
		}
		if a.lockoutAuditedAt.IsZero() || a.lockoutAuditedAt.Before(a.lockedAt) {
			a.lockoutAuditedAt = now
			shouldAudit = true
		}
	}
	return shouldAudit
}

// resetAttempts clears the failure count for the given IP and the shared admin
// account after a successful login.
func (h *AdminHandler) resetAttempts(ip string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	delete(h.loginAttempts, ip)
	delete(h.loginAttempts, adminLoginAccountKey)
}

// cleanupAttempts periodically removes stale lockout entries. It runs
// in its own goroutine, started by NewAdminHandler. It exits when ctx
// is cancelled.
func (h *AdminHandler) cleanupAttempts(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.cleanupExpiredLoginAttempts(time.Now())
		}
	}
}

func (h *AdminHandler) cleanupExpiredLoginAttempts(now time.Time) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	cutoff := now.Add(-loginLockoutDuration)
	for key, a := range h.loginAttempts {
		if a == nil {
			delete(h.loginAttempts, key)
			continue
		}
		if a.count >= loginMaxAttempts {
			if !a.lockedAt.IsZero() && a.lockedAt.Before(cutoff) {
				delete(h.loginAttempts, key)
			}
			continue
		}
		if a.lastFailedAt.IsZero() || a.lastFailedAt.Before(cutoff) {
			delete(h.loginAttempts, key)
		}
	}
}

// -- Helpers -----------------------------------------------------------------

// auditLog writes an entry to the admin audit log.
func (h *AdminHandler) auditLog(r *http.Request, action string, details map[string]string) error {
	return h.writeAdminAuditLog(h.adminAuditEntry(r, action, details))
}

func (h *AdminHandler) adminAuditEntry(r *http.Request, action string, details map[string]string) *db.AdminAuditEntry {
	raw, _ := json.Marshal(details)
	return &db.AdminAuditEntry{
		Action:  action,
		Details: raw,
		IP:      clientIP(r),
	}
}

func (h *AdminHandler) adminAuditContext() (context.Context, context.CancelFunc) {
	ctx := h.rootCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, adminAuditWriteTimeout)
}

func (h *AdminHandler) writeAdminAuditLog(entry *db.AdminAuditEntry) error {
	auditCtx, cancel := h.adminAuditContext()
	defer cancel()

	if err := h.store.InsertAdminAuditLog(auditCtx, entry); err != nil {
		h.logger.Warn("failed to write admin audit log",
			"action", entry.Action,
			"error", err,
		)
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	return nil
}

func (h *AdminHandler) auditLogBestEffort(r *http.Request, action string, details map[string]string) {
	if err := h.auditLog(r, action, details); err != nil {
		return
	}
}

// clientIP delegates to the shared request-context helper.
func clientIP(r *http.Request) string {
	return requestctx.ClientIP(r)
}
