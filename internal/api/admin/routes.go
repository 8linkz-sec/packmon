package admin

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/web"
)

// RegisterRoutes registers all admin routes on the given mux. The
// session middleware protects every /admin/* route except /admin/login.
//
// The provided context controls the lifetime of background goroutines
// started by the admin handler (e.g. login-attempt cleanup).
//
// The wellKnownChangePassword handler implements the .well-known
// redirect for password managers (Bitwarden compatibility).
func RegisterRoutes(ctx context.Context, mux *http.ServeMux, store Store, sm *auth.SessionManager, logger *slog.Logger, cfg *config.Config, runtime *config.RuntimeSettings, syncFeed FeedSyncFunc, applyFeedConfig FeedConfigApplyFunc, resetFeedConfig FeedConfigResetFunc) {
	renderer := web.NewRendererWithLayoutLinks(web.TemplateFS(), false, adminLayoutLinks(cfg))
	h := NewAdminHandler(ctx, store, sm, renderer, logger, cfg, runtime, syncFeed)
	h.SetFeedConfigApplyFunc(applyFeedConfig)
	h.SetFeedConfigResetFunc(resetFeedConfig)

	// Login and logout are handled specially:
	// - GET /admin/login: show form (no session required)
	// - POST /admin/login: validate credentials (no session required)
	// - POST /admin/logout: destroy session (session required)
	mux.HandleFunc("GET /admin/login", h.HandleLogin)
	mux.HandleFunc("POST /admin/login", h.HandleLogin)
	mux.HandleFunc("POST /admin/logout", h.HandleLogout)

	// All other admin routes require an active session.
	// The session middleware is applied in the server package; here we
	// only register the route handlers.
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /admin/{$}", h.HandleDashboard)
	mux.HandleFunc("GET /admin/feeds", h.HandleAdminFeeds)
	mux.HandleFunc("POST /admin/feeds/save", h.HandleFeedConfigSave)
	mux.HandleFunc("POST /admin/feeds/reset", h.HandleFeedConfigReset)
	mux.HandleFunc("POST /admin/feeds/sync", h.HandleFeedSyncNow)
	mux.HandleFunc("GET /admin/queue", h.HandleAdminQueue)
	mux.HandleFunc("POST /admin/queue/purge", h.HandleQueuePurge)
	mux.HandleFunc("POST /admin/queue/priority", h.HandleQueuePriorityUpdate)
	mux.HandleFunc("POST /admin/queue/pause", h.HandleQueuePause)
	mux.HandleFunc("POST /admin/queue/resume", h.HandleQueueResume)
	mux.HandleFunc("POST /admin/queue/retry", h.HandleQueueRetry)
	mux.HandleFunc("POST /admin/queue/clear", h.HandleQueueClear)
	mux.HandleFunc("GET /admin/keys", h.HandleAdminKeys)
	mux.HandleFunc("POST /admin/keys/create", h.HandleKeyCreate)
	mux.HandleFunc("POST /admin/keys/revoke", h.HandleKeyRevoke)
	mux.HandleFunc("POST /admin/keys/delete", h.HandleKeyDelete)
	mux.HandleFunc("GET /admin/advisories", h.HandleAdminAdvisories)
	mux.HandleFunc("POST /admin/advisories/create", h.HandleAdvisoryCreate)
	mux.HandleFunc("POST /admin/advisories/delete", h.HandleAdvisoryDelete)
	mux.HandleFunc("GET /admin/audit", h.HandleAdminAudit)
	mux.HandleFunc("GET /admin/settings", h.HandleAdminSettings)
	mux.HandleFunc("POST /admin/settings/system", h.HandleSystemSettingsSave)
	mux.HandleFunc("POST /admin/settings/password", h.HandlePasswordChange)

	// Password-manager .well-known redirect (DESIGN.md Web UI).
	mux.HandleFunc("GET /.well-known/change-password", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
	})
}

func adminLayoutLinks(cfg *config.Config) web.LayoutLinks {
	if cfg == nil {
		return web.LayoutLinks{}
	}
	return web.LayoutLinks{
		PrivacyURL: cfg.Web.PrivacyURL,
		LegalURL:   cfg.Web.LegalURL,
	}
}
