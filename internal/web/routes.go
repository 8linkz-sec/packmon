package web

import (
	"io/fs"
	"log/slog"
	"net/http"
)

// RegisterRoutes registers all public (non-admin) web routes on the given
// mux. Static assets are served from the embedded filesystem at /static/.
//
// Admin routes are intentionally NOT registered here -- they are handled
// by the admin package which manages session-based authentication.
func RegisterRoutes(mux *http.ServeMux, store Store, renderer *Renderer, logger *slog.Logger) {
	// -- Public pages ----------------------------------------------------------
	mux.HandleFunc("GET /{$}", HandleDashboard(store, renderer, logger))
	mux.HandleFunc("GET /search", HandleSearch(store, renderer, logger))
	mux.HandleFunc("GET /feeds", HandleFeeds(store, renderer, logger))
	mux.HandleFunc("GET /package/{ecosystem}/{name...}", HandlePackage(store, renderer, logger))

	// -- Static assets from embedded FS ----------------------------------------
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		logger.Error("web: failed to create static sub-FS", "error", err)
		return
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// The /.well-known/change-password redirect for Bitwarden compatibility
	// is registered by the admin package, which also owns the login flow.
}

// TemplateFS returns the embedded filesystem containing templates and
// static assets. This is exposed so that callers (e.g. the server package)
// can create a Renderer from it.
func TemplateFS() fs.FS {
	return content
}
