package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/8linkz/packmon/internal/api/admin"
	v1 "github.com/8linkz/packmon/internal/api/v1"
	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/health"
	"github.com/8linkz/packmon/internal/web"
)

// registerRoutes wires all HTTP routes on the given mux.
func registerRoutes(mux *http.ServeMux, hc *health.Checker, cfg *config.Config, store db.Store, sm *auth.SessionManager, logger *slog.Logger, buildInfo BuildInfo) {
	api := v1.NewHandler(store, logger)

	// -- Operations (no auth required) ----------------------------------------
	mux.HandleFunc("GET /healthz", hc.LiveHandler())
	mux.HandleFunc("GET /readyz", hc.ReadyHandler())
	mux.HandleFunc("GET /version", versionHandler(buildInfo))

	// -- API v1 ---------------------------------------------------------------
	mux.HandleFunc("POST /api/v1/check", api.HandleCheck)
	mux.HandleFunc("GET /api/v1/feeds/status", api.HandleFeedStatus)
	mux.HandleFunc("POST /api/v1/feeds/{feed}/import", api.HandleFeedImport)
	// The {name...} wildcard must be at the end of the pattern in Go's
	// ServeMux. We register a single catch-all and dispatch to the detail
	// or refresh handler based on the HTTP method and whether the trailing
	// path segment is "refresh". See HandlePackageOrRefresh.
	mux.HandleFunc("GET /api/v1/packages/{ecosystem}/{rest...}", api.HandlePackageDetail)
	mux.HandleFunc("POST /api/v1/packages/{ecosystem}/{rest...}", api.HandlePackageOrRefresh)
	mux.HandleFunc("GET /api/v1/sync", api.HandleSync)

	// -- Admin (session-protected) --------------------------------------------
	admin.RegisterRoutes(mux, store, sm, logger, cfg)

	// -- Web GUI (public pages: dashboard, search, package, feeds) -----------
	renderer := web.NewRenderer(web.TemplateFS(), false)
	web.RegisterRoutes(mux, store, renderer, logger)
}

// BuildInfo is injected at build time via ldflags.
type BuildInfo struct {
	Version       string
	Commit        string
	Date          string
	SchemaVersion uint
}

func versionHandler(bi BuildInfo) http.HandlerFunc {
	payload, _ := json.Marshal(map[string]string{
		"version": bi.Version,
		"commit":  bi.Commit,
		"date":    bi.Date,
	})
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(payload)
	}
}
