// Package admin implements the admin-only HTTP handlers for the Packmon
// server. All routes except the login page itself require an active
// admin session.
package admin

import (
	"bytes"
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
// database override has been removed and returns the settings it applied.
type FeedConfigResetFunc func(ctx context.Context, feedName string) (config.FeedSettings, bool, error)

// AdminMutationStore is the required persistence surface for security-sensitive
// admin mutations that must be committed atomically with their audit row.
type AdminMutationStore interface {
	UpsertManualAdvisoryWithAudit(ctx context.Context, advisory *db.ManualAdvisory, audit *adminAuditEntry) error
	DeleteManualAdvisoryWithAudit(ctx context.Context, id string, audit *adminAuditEntry) error

	CreateAPIKeyWithAudit(ctx context.Context, name, keyHash string, expiresAt *time.Time, audit *adminAuditEntry) (int, error)
	RevokeAPIKeyWithAudit(ctx context.Context, keyID int, audit *adminAuditEntry) error
	DeleteAPIKeyWithAudit(ctx context.Context, keyID int, audit *adminAuditEntry) error

	UpsertAdminAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *adminAuditEntry) error
	ChangeAdminPasswordWithAudit(ctx context.Context, newHash, expectedOldHash string, audit *adminAuditEntry) error

	UpsertSystemSettingsWithAudit(ctx context.Context, settings *db.SystemSettings, audit *adminAuditEntry) error

	UpsertFeedConfigWithAudit(ctx context.Context, cfg *db.FeedConfig, audit *adminAuditEntry) error
	DeleteFeedConfigWithAudit(ctx context.Context, feedName string, expectedUpdatedAt *time.Time, audit *adminAuditEntry) error

	PurgeQueueWithAudit(ctx context.Context, audit *adminAuditEntry) (int, error)
	UpdateQueueJobPriorityWithAudit(ctx context.Context, jobID, priority int, audit *adminAuditEntry) error
	PauseQueueJobWithAudit(ctx context.Context, jobID int, audit *adminAuditEntry) error
	ResumeQueueJobWithAudit(ctx context.Context, jobID int, audit *adminAuditEntry) error
	RetryQueueJobWithAudit(ctx context.Context, jobID int, audit *adminAuditEntry) error
	ClearQueueWithAudit(ctx context.Context, statuses []string, audit *adminAuditEntry) (int, error)
}

// Store is the admin handler persistence surface.
type Store interface {
	AdminMutationStore

	GetAdminAuth(ctx context.Context) (*db.AdminAuth, error)
	UpsertAdminAuth(ctx context.Context, passwordHash string, isBootstrap bool) error
	InsertAdminAuditLog(ctx context.Context, entry *adminAuditEntry) error
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
	CountUnknownSeverityFindings(ctx context.Context) (int, error)
	CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error)
	ListRecentScans(ctx context.Context, limit, offset int) ([]db.ScanLogEntry, error)

	ListManualAdvisories(ctx context.Context, limit int) ([]db.ManualAdvisory, error)
	UpsertManualAdvisory(ctx context.Context, advisory *db.ManualAdvisory) error
	DeleteManualAdvisory(ctx context.Context, id string) error

	QueueStats(ctx context.Context) (*adminQueueStats, error)
	ListQueueJobs(ctx context.Context, status string, limit int) ([]adminQueueJob, error)
}

// AdminHandler holds the dependencies for admin HTTP handlers.
// adminDashboardStatsCacheTTL bounds how stale the admin dashboard aggregate
// may be; feed syncs are hours apart, so 15s is invisible to operators while
// collapsing repeated tab switches into one aggregate query.
const adminDashboardStatsCacheTTL = 15 * time.Second

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
	csrfToken       func(*auth.Session) (string, error)

	// dashboardStatsCache memoizes the expensive dashboard aggregate (UNION
	// dedupe over all finding sources) between page loads; the numbers only
	// change when feeds sync or advisories are edited.
	dashboardStatsCache *web.AggregateCache[*db.DashboardStatsResult]

	// loginMu protects the loginAttempts map.
	loginMu       sync.Mutex
	loginAttempts map[string]*loginAttempt

	manualSyncMu sync.Mutex
	manualSyncs  map[string]struct{}
}

// NewAdminHandler creates an AdminHandler with the given dependencies.
// The provided context controls the lifetime of the background cleanup
// goroutine; when the context is cancelled the goroutine exits.
func NewAdminHandler(ctx context.Context, store any, sm *auth.SessionManager, renderer *web.Renderer, logger *slog.Logger, cfg *config.Config, runtime *config.RuntimeSettings, syncFeed FeedSyncFunc) *AdminHandler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &AdminHandler{
		store:               adaptAdminStore(store),
		dashboardStatsCache: web.NewAggregateCache[*db.DashboardStatsResult](adminDashboardStatsCacheTTL),
		sm:                  sm,
		renderer:            renderer,
		logger:              logger,
		cfg:                 cfg,
		runtime:             runtime,
		rootCtx:             ctx,
		syncFeed:            syncFeed,
		csrfToken:           auth.CSRFToken,
		loginAttempts:       make(map[string]*loginAttempt),
		manualSyncs:         make(map[string]struct{}),
	}
	// Background goroutine to evict stale lockout entries.
	go h.cleanupAttempts(ctx)
	return h
}

func (h *AdminHandler) adminCSRFToken(w http.ResponseWriter, r *http.Request, sess *auth.Session, scope string) (string, bool) {
	csrfToken := auth.CSRFToken
	if h.csrfToken != nil {
		csrfToken = h.csrfToken
	}
	token, err := csrfToken(sess)
	if err != nil {
		h.logger.Error("admin csrf token generation failed", h.adminLogAttrs(r, "scope", scope, "error", err)...)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return "", false
	}
	return token, true
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

	// Reuse a valid short-lived, non-admin session when the browser already has
	// one; otherwise create one just to carry the CSRF token on the login form.
	// On successful login a new authenticated session replaces it.
	sess, err := h.sm.CreateOrReusePreAuth(w, r)
	if err != nil {
		h.logger.Error("failed to create login session", h.adminLogAttrs(r, "error", err)...)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	csrfToken, ok := h.adminCSRFToken(w, r, sess, "login")
	if !ok {
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
		h.logger.Error("failed to render login template", h.adminLogAttrs(r, "error", err)...)
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
			h.logger.Warn("login attempt from locked out principal", h.adminLogAttrs(r, "client_ip", ip)...)
			if !h.requireAudit(w, r, "login_lockout", map[string]string{
				"reason": "too many failed attempts",
			}) {
				return
			}
			h.markLockoutAuditWritten(ip)
		}
		h.showLoginForm(w, r, "Too many failed login attempts. Please try again later.")
		return
	}

	// Validate CSRF token against the session created when the form was rendered.
	sess := h.sm.Get(r)
	if sess == nil || !auth.ValidateCSRF(r, sess) {
		h.recordFailedAttemptFor(ip, false)
		h.logger.Warn("CSRF validation failed on login", h.adminLogAttrs(r, "client_ip", ip)...)
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
		if !h.requireAudit(w, r, "login_failed", map[string]string{
			"reason": "invalid username",
		}) {
			return
		}
		h.recordFailedAttempt(ip)
		h.showLoginForm(w, r, "Invalid username or password.")
		return
	}

	adminAuth, err := h.store.GetAdminAuth(r.Context())
	if err != nil {
		h.logger.Error("failed to get admin auth", h.adminLogAttrs(r, "error", err)...)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if adminAuth == nil {
		h.logger.Warn("login attempt but no admin account exists", h.adminLogAttrs(r, "client_ip", ip)...)
		h.showLoginForm(w, r, adminUnconfiguredLoginError)
		return
	}

	if !auth.CheckPassword(adminAuth.PasswordHash, password) {
		if !h.requireAudit(w, r, "login_failed", map[string]string{
			"reason": "invalid password",
		}) {
			return
		}
		h.recordFailedAttempt(ip)
		h.showLoginForm(w, r, "Invalid username or password.")
		return
	}

	if !h.requireAudit(w, r, "login_success", map[string]string{}) {
		return
	}

	// Successful login -- reset attempts and create session.
	h.resetAttempts(ip)

	_, err = h.sm.CreateAdmin(w, adminAuth.PasswordIsBootstrap)
	if err != nil {
		h.logger.Error("failed to create admin session", h.adminLogAttrs(r, "error", err)...)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	h.logger.Info("admin login successful", h.adminLogAttrs(r)...)
	auth.RedirectSameOrigin(w, r, adminLoginSuccessRedirect(nextPath), http.StatusSeeOther)
}

func adminLoginSuccessRedirect(nextPath string) string {
	if nextPath == "" {
		return "/admin/"
	}
	return nextPath
}

// HandleLogout destroys the admin session and redirects to the login page.
// Requires a valid CSRF token to prevent cross-site logout attacks.
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
		h.recordInvalidAdminCSRF(r, "logout")
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	if !h.requireAudit(w, r, "logout", map[string]string{}) {
		return
	}

	h.sm.Delete(w, r)

	h.logger.Info("admin logout", h.adminLogAttrs(r)...)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// HandleNotFound renders a styled 404 for authenticated admin routes that do
// not match a concrete admin page or action.
func (h *AdminHandler) HandleNotFound(w http.ResponseWriter, r *http.Request) {
	if sess := h.requireAdmin(w, r); sess == nil {
		return
	}

	var buf bytes.Buffer
	if err := h.renderer.Render(&buf, "not_found.html", web.NotFoundData{ActiveNav: "admin"}); err != nil {
		h.logger.Error("admin not found: render failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(buf.Bytes())
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
	correlationID := adminRequestCorrelationID(r)

	csrfToken, ok := h.adminCSRFToken(w, r, sess, "dashboard")
	if !ok {
		return
	}

	// Check if this session is still constrained by the bootstrap password.
	bootstrapWarning := sess.AuthenticatedWithBootstrap
	var (
		adminAuth               *db.AdminAuth
		adminAuthLoadError      string
		stats                   *db.DashboardStatsResult
		dashboardStatsLoadError string
		feeds                   []db.FeedSyncStatus
		feedStatusLoadError     string
		queueStats              *adminQueueStats
		queueStatsLoadError     string
		daily                   []db.DailyScanStats
		scanCountLoadError      string
		widgetReads             sync.WaitGroup
	)

	widgetReads.Add(5)
	go func() {
		defer widgetReads.Done()
		var err error
		adminAuth, err = h.store.GetAdminAuth(ctx)
		if err != nil {
			h.logger.Error("admin dashboard: failed to check bootstrap flag", adminLogAttrsForCorrelationID(correlationID, "error", err)...)
			adminAuthLoadError = "Bootstrap password status could not be verified. Check the server logs and database connection before relying on this account state."
		}
	}()
	go func() {
		defer widgetReads.Done()
		var err error
		stats, err = h.dashboardStatsCache.Get(ctx, h.store.DashboardStats)
		if err != nil {
			h.logger.Error("admin dashboard: failed to load stats", adminLogAttrsForCorrelationID(correlationID, "error", err)...)
			stats = &db.DashboardStatsResult{BySeverity: map[string]int{}}
			dashboardStatsLoadError = "Dashboard stats could not be loaded. Check the server logs and database connection before relying on these totals."
		}
	}()
	go func() {
		defer widgetReads.Done()
		var err error
		feeds, err = h.store.ListFeedSyncStatuses(ctx)
		if err != nil {
			h.logger.Error("admin dashboard: failed to load feed statuses", adminLogAttrsForCorrelationID(correlationID, "error", err)...)
			feedStatusLoadError = "Feed status could not be loaded. Check the server logs and database connection before relying on feed health."
		}
	}()
	go func() {
		defer widgetReads.Done()
		var err error
		queueStats, err = h.store.QueueStats(ctx)
		if err != nil {
			h.logger.Error("admin dashboard: failed to load queue stats", adminLogAttrsForCorrelationID(correlationID, "error", err)...)
			queueStats = &adminQueueStats{}
			queueStatsLoadError = "Queue summary could not be loaded. Check the server logs and database connection before relying on queue counts."
		}
	}()
	go func() {
		defer widgetReads.Done()
		var err error
		daily, err = h.store.CountScansByDay(ctx, 7)
		if err != nil {
			h.logger.Error("admin dashboard: failed to load daily stats", adminLogAttrsForCorrelationID(correlationID, "error", err)...)
			scanCountLoadError = web.Message("dashboard.error.scan_activity")
		}
	}()
	widgetReads.Wait()

	if adminAuth != nil && adminAuth.PasswordIsBootstrap {
		bootstrapWarning = true
	}
	feedRows := h.adminFeedRows(feeds)

	totalScans7d := 0
	for _, day := range daily {
		totalScans7d += day.ScanCount
	}
	feedsHealthy := 0
	for _, row := range feedRows {
		if row.Status == "healthy" {
			feedsHealthy++
		}
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
		"FeedsHealthy":            feedsHealthy,
		"FeedsTotal":              len(feedRows),
		"QueueStats":              queueStats,
		"QueueStatsLoadError":     queueStatsLoadError,
		"TotalScans7d":            totalScans7d,
		"ScanCountLoadError":      scanCountLoadError,
		"AdminAuthLoadError":      adminAuthLoadError,
		"BootstrapWarning":        bootstrapWarning,
	}
	if err := h.renderer.Render(w, "admin/dashboard.html", data); err != nil {
		h.logger.Error("admin dashboard: render failed", h.adminLogAttrs(r, "error", err)...)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// adminFeedRow is a view model for feed status rows in admin templates.
type adminFeedRow struct {
	FeedName              string
	Status                string
	LastSyncAt            *time.Time
	LastSyncAtTime        time.Time
	LastSyncStatus        string
	EntriesSynced         int
	EntriesTotal          int
	RejectedCount         int
	RejectedClientIP      string
	RejectedAPIKeyID      int
	RejectedAPIKeyName    string
	RejectedCorrelationID string
	LastError             string
	DurationStr           string
	ConfigMode            string
	ConfigEnabled         bool
	APIKeyState           string
	APIKeyStateCode       string
	FeedKey               string
	SyncIntervalStr       string
	SyncIntervalCode      string
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
			shouldAudit = true
		}
	}
	return shouldAudit
}

func (h *AdminHandler) markLockoutAuditWritten(ip string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	now := time.Now()
	for _, key := range []string{ip, adminLoginAccountKey} {
		a, ok := h.loginAttempts[key]
		if !ok || !h.isAttemptLocked(key, now) {
			continue
		}
		if a.lockoutAuditedAt.IsZero() || a.lockoutAuditedAt.Before(a.lockedAt) {
			a.lockoutAuditedAt = now
		}
	}
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

func (h *AdminHandler) adminAuditEntry(r *http.Request, action string, details map[string]string) *adminAuditEntry {
	raw, _ := json.Marshal(details)
	return &adminAuditEntry{
		Action:        action,
		Details:       raw,
		IP:            clientIP(r),
		CorrelationID: adminRequestCorrelationID(r),
	}
}

func (h *AdminHandler) adminAuditContext() (context.Context, context.CancelFunc) {
	ctx := h.rootCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, adminAuditWriteTimeout)
}

func (h *AdminHandler) writeAdminAuditLog(entry *adminAuditEntry) error {
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

func (h *AdminHandler) adminLogAttrs(r *http.Request, attrs ...any) []any {
	return adminLogAttrsForCorrelationID(adminRequestCorrelationID(r), attrs...)
}

func adminLogAttrsForCorrelationID(correlationID string, attrs ...any) []any {
	out := make([]any, 0, len(attrs)+1)
	out = append(out, attrs...)
	out = append(out, slog.String("correlation_id", correlationID))
	return out
}

func adminRequestCorrelationID(r *http.Request) string {
	if r == nil {
		return ""
	}
	return requestctx.CorrelationIDFromContext(r.Context())
}

func (h *AdminHandler) rejectInvalidAdminCSRF(w http.ResponseWriter, r *http.Request, targetAction, redirectPath string) {
	h.recordInvalidAdminCSRF(r, targetAction)
	redirectAdminFormError(w, r, redirectPath, adminInvalidRequestMessage)
}

func (h *AdminHandler) recordInvalidAdminCSRF(r *http.Request, targetAction string) {
	path := r.URL.Path
	h.logger.Warn("admin CSRF validation failed",
		slog.String("target_action", targetAction),
		slog.String("path", path),
		slog.String("client_ip", clientIP(r)),
		slog.String("correlation_id", requestctx.CorrelationIDFromContext(r.Context())),
	)
	h.auditLogBestEffort(r, "admin_csrf_rejected", map[string]string{
		"target_action": targetAction,
		"path":          path,
	})
}

func (h *AdminHandler) requireAudit(w http.ResponseWriter, r *http.Request, action string, details map[string]string) bool {
	if err := h.auditLog(r, action, details); err != nil {
		http.Error(w, "failed to record audit log", http.StatusInternalServerError)
		return false
	}
	return true
}

// clientIP delegates to the shared request-context helper.
func clientIP(r *http.Request) string {
	return requestctx.ClientIP(r)
}
