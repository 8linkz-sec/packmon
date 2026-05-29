// Package admin implements the admin-only HTTP handlers for the Packmon
// server. All routes except the login page itself require an active
// admin session.
package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/server/middleware"
	"github.com/8linkz/packmon/internal/telemetry"
	"github.com/8linkz/packmon/internal/web"
)

const (
	// loginMaxAttempts is the number of allowed login attempts per IP
	// before a lockout is triggered.
	loginMaxAttempts = 5

	// loginLockoutDuration is how long an IP is locked out after
	// exceeding the maximum number of login attempts.
	loginLockoutDuration = 15 * time.Minute
)

// loginAttempt tracks failed login attempts for a single IP address.
type loginAttempt struct {
	count    int
	lockedAt time.Time
}

// FeedSyncFunc triggers an immediate feed synchronisation.
type FeedSyncFunc func(ctx context.Context, feedName string) error

// AdminHandler holds the dependencies for admin HTTP handlers.
type AdminHandler struct {
	store    db.Store
	sm       *auth.SessionManager
	renderer *web.Renderer
	logger   *slog.Logger
	cfg      *config.Config
	runtime  *config.RuntimeSettings
	syncFeed FeedSyncFunc

	// loginMu protects the loginAttempts map.
	loginMu       sync.Mutex
	loginAttempts map[string]*loginAttempt
}

// NewAdminHandler creates an AdminHandler with the given dependencies.
// The provided context controls the lifetime of the background cleanup
// goroutine; when the context is cancelled the goroutine exits.
func NewAdminHandler(ctx context.Context, store db.Store, sm *auth.SessionManager, renderer *web.Renderer, logger *slog.Logger, cfg *config.Config, runtime *config.RuntimeSettings, syncFeed FeedSyncFunc) *AdminHandler {
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
		syncFeed:      syncFeed,
		loginAttempts: make(map[string]*loginAttempt),
	}
	// Background goroutine to evict stale lockout entries.
	go h.cleanupAttempts(ctx)
	return h
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
	// If user already has a valid session, redirect to admin dashboard.
	if sess := h.sm.Get(r); sess != nil {
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
		"ActiveNav": "admin",
		"CSRFToken": csrfToken,
		"Error":     errorMsg,
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
		h.logger.Warn("login attempt from locked out IP", "ip", ip)
		h.auditLog(r, "login_lockout", map[string]string{
			"ip":     ip,
			"reason": "too many failed attempts",
		})
		h.showLoginForm(w, r, "Too many failed login attempts. Please try again later.")
		return
	}

	// Validate CSRF token against the session created when the form was rendered.
	sess := h.sm.Get(r)
	if sess == nil || !auth.ValidateCSRF(r, sess) {
		h.logger.Warn("CSRF validation failed on login", "ip", ip)
		h.showLoginForm(w, r, "Invalid request. Please try again.")
		return
	}

	// Destroy the pre-login CSRF session -- we will create a fresh one
	// on success or show a new form on failure.
	h.sm.Delete(w, r)

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	if username != "admin" {
		h.recordFailedAttempt(ip)
		h.auditLog(r, "login_failed", map[string]string{
			"ip":     ip,
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
		h.showLoginForm(w, r, "Admin account has not been configured.")
		return
	}

	if !auth.CheckPassword(adminAuth.PasswordHash, password) {
		h.recordFailedAttempt(ip)
		h.auditLog(r, "login_failed", map[string]string{
			"ip":     ip,
			"reason": "invalid password",
		})
		h.showLoginForm(w, r, "Invalid username or password.")
		return
	}

	// Successful login -- reset attempts and create session.
	h.resetAttempts(ip)

	newSess, err := h.sm.Create(w)
	if err != nil {
		h.logger.Error("failed to create admin session", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	newSess.Admin = true

	h.auditLog(r, "login_success", map[string]string{"ip": ip})

	h.logger.Info("admin login successful", "ip", ip)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
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

	h.auditLog(r, "logout", map[string]string{"ip": ip})

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

	// Check if the admin is still using the bootstrap password.
	bootstrapWarning := false
	adminAuth, err := h.store.GetAdminAuth(ctx)
	if err != nil {
		h.logger.Error("admin dashboard: failed to check bootstrap flag", "error", err)
	} else if adminAuth != nil && adminAuth.PasswordIsBootstrap {
		bootstrapWarning = true
	}

	stats, err := h.store.DashboardStats(ctx)
	if err != nil {
		h.logger.Error("admin dashboard: failed to load stats", "error", err)
		stats = &db.DashboardStatsResult{BySeverity: map[string]int{}}
	}

	feeds, err := h.store.ListFeedSyncStatuses(ctx)
	if err != nil {
		h.logger.Error("admin dashboard: failed to load feed statuses", "error", err)
	}

	feedRows := make([]adminFeedRow, 0, len(feeds))
	for _, f := range feeds {
		row := adminFeedRow{
			FeedName:     f.FeedName,
			Status:       adminFeedHealth(true, "", &f),
			EntriesTotal: f.EntriesTotal,
		}
		if f.LastSyncAt != nil {
			row.LastSyncAt = f.LastSyncAt
			row.LastSyncAtTime = *f.LastSyncAt
		}
		feedRows = append(feedRows, row)
	}

	queueStats, err := h.store.QueueStats(ctx)
	if err != nil {
		h.logger.Error("admin dashboard: failed to load queue stats", "error", err)
		queueStats = &db.QueueStatsResult{}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	data := map[string]any{
		"ActiveNav":        "admin",
		"CSRFToken":        csrfToken,
		"Stats":            stats,
		"Feeds":            feedRows,
		"QueueStats":       queueStats,
		"BootstrapWarning": bootstrapWarning,
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

// adminFeedHealth derives a health string from sync status for admin views.
func adminFeedHealth(enabled bool, mode config.FeedMode, s *db.FeedSyncStatus) string {
	if !enabled {
		return "disabled"
	}
	if s == nil || s.LastSyncAt == nil {
		if mode == config.FeedModeExternal {
			return "configured"
		}
		return "pending"
	}
	if s.LastSyncStatus == "error" {
		return "error"
	}
	if s.LastSyncStatus == "running" {
		return "pending"
	}
	if s.LastSyncStatus == "skipped" {
		return "warning"
	}
	if time.Since(*s.LastSyncAt) > 48*time.Hour {
		return "warning"
	}
	// A successful sync that persisted zero entries is not usable for lookups
	// (DESIGN.md 3.5: zero entries => unhealthy).
	if s.EntriesTotal == 0 && s.EntriesSynced == 0 {
		return "warning"
	}
	return "healthy"
}

// -- Rate limiting helpers ---------------------------------------------------

// isLockedOut returns true if the given IP has exceeded the maximum
// login attempts and the lockout has not expired.
func (h *AdminHandler) isLockedOut(ip string) bool {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	a, ok := h.loginAttempts[ip]
	if !ok {
		return false
	}

	if a.count >= loginMaxAttempts {
		if time.Since(a.lockedAt) < loginLockoutDuration {
			return true
		}
		// Lockout expired -- reset.
		delete(h.loginAttempts, ip)
		return false
	}

	return false
}

// recordFailedAttempt increments the failure count for the given IP.
// When the count reaches the threshold, the lockout timer starts.
func (h *AdminHandler) recordFailedAttempt(ip string) {
	telemetry.Default().IncAuthLoginFailures()

	h.loginMu.Lock()
	defer h.loginMu.Unlock()

	a, ok := h.loginAttempts[ip]
	if !ok {
		a = &loginAttempt{}
		h.loginAttempts[ip] = a
	}

	a.count++
	if a.count >= loginMaxAttempts {
		a.lockedAt = time.Now()
	}
}

// resetAttempts clears the failure count for the given IP after a
// successful login.
func (h *AdminHandler) resetAttempts(ip string) {
	h.loginMu.Lock()
	defer h.loginMu.Unlock()
	delete(h.loginAttempts, ip)
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
			h.loginMu.Lock()
			cutoff := time.Now().Add(-loginLockoutDuration)
			for ip, a := range h.loginAttempts {
				if !a.lockedAt.IsZero() && a.lockedAt.Before(cutoff) {
					delete(h.loginAttempts, ip)
				}
			}
			h.loginMu.Unlock()
		}
	}
}

// -- Helpers -----------------------------------------------------------------

// auditLog writes an entry to the admin audit log. Failures are logged
// but do not affect the caller.
func (h *AdminHandler) auditLog(r *http.Request, action string, details map[string]string) {
	raw, _ := json.Marshal(details)
	entry := &db.AdminAuditEntry{
		Action:  action,
		Details: raw,
		IP:      clientIP(r),
	}
	if err := h.store.InsertAdminAuditLog(r.Context(), entry); err != nil {
		h.logger.Warn("failed to write admin audit log",
			"action", action,
			"error", err,
		)
	}
}

// clientIP delegates to the shared middleware.ClientIP function which
// only trusts r.RemoteAddr to prevent X-Forwarded-For spoofing.
func clientIP(r *http.Request) string {
	return middleware.ClientIP(r)
}
