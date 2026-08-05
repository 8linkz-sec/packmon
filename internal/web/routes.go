package web

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

const (
	staticAssetShortCache     = "public, max-age=3600"
	staticAssetVersionedCache = "public, max-age=31536000, immutable"
)

// RouteOptions contains optional behavior for callers that host the public UI.
type RouteOptions struct {
	Dashboard DashboardOptions
}

// NotFoundData is the view model for the public web 404 page.
type NotFoundData struct {
	ActiveNav string
}

// RegisterRoutes registers all public (non-admin) web routes on the given
// mux. Static assets are served from the embedded filesystem at /static/.
//
// Admin routes are intentionally NOT registered here -- they are handled
// by the admin package which manages session-based authentication.
func RegisterRoutes(mux *http.ServeMux, store Store, renderer *Renderer, logger *slog.Logger) {
	RegisterRoutesWithOptions(mux, store, renderer, logger, RouteOptions{})
}

// RegisterRoutesWithOptions registers public web routes with caller-specific
// options.
func RegisterRoutesWithOptions(mux *http.ServeMux, store Store, renderer *Renderer, logger *slog.Logger, options RouteOptions) {
	// -- Public pages ----------------------------------------------------------
	mux.HandleFunc("GET /{$}", HandleDashboardWithOptions(store, renderer, logger, options.Dashboard))
	mux.HandleFunc("GET /search", HandleSearch(store, renderer, logger))
	mux.HandleFunc("GET /feeds", HandleFeeds(store, renderer, logger))
	mux.HandleFunc("GET /privacy", HandlePrivacy(renderer, logger))
	mux.HandleFunc("GET /terms", HandleTerms(renderer, logger))
	mux.HandleFunc("GET /.well-known/security.txt", HandleSecurityTxt(logger))
	mux.HandleFunc("GET /package/{ecosystem}/{name...}", HandlePackage(store, renderer, logger))

	notFound := HandleNotFound(renderer, logger)
	mux.HandleFunc("GET /{path}", notFound)
	mux.HandleFunc("GET /search/{path...}", notFound)
	mux.HandleFunc("GET /feeds/{path...}", notFound)
	mux.HandleFunc("GET /privacy/{path...}", notFound)
	mux.HandleFunc("GET /terms/{path...}", notFound)
	mux.HandleFunc("GET /package/{path...}", notFound)

	// -- Static assets from embedded FS ----------------------------------------
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		logger.Error("web: failed to create static sub-FS", "error", err)
		return
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStaticAssets(http.FileServer(http.FS(staticFS)), newStaticAssetVersions(content))))

	// The /.well-known/change-password redirect for Bitwarden compatibility
	// is registered by the admin package, which also owns the login flow.
}

// TemplateFS returns the embedded filesystem containing templates and
// static assets. This is exposed so that callers (e.g. the server package)
// can create a Renderer from it.
func TemplateFS() fs.FS {
	return content
}

// HandleNotFound renders a styled 404 page for browser-facing public web
// routes without taking ownership of API, admin, static, or operations paths.
func HandleNotFound(renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static" {
			http.Redirect(w, r, "/static/", http.StatusMovedPermanently)
			return
		}
		if reservedPublicFallbackPath(r.URL.Path) || !acceptsHTML(r.Header.Get("Accept")) {
			http.NotFound(w, r)
			return
		}

		renderNotFoundPage(w, r, renderer, logger, NotFoundData{}, "")
	}
}

func renderNotFoundPage(w http.ResponseWriter, r *http.Request, renderer *Renderer, logger *slog.Logger, data NotFoundData, cacheControl string) {
	var buf bytes.Buffer
	if err := renderer.Render(&buf, "not_found.html", data); err != nil {
		logger.Error("not found: render failed", requestLogAttrs(r, "error", err)...)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write(buf.Bytes())
}

func cacheStaticAssets(next http.Handler, assets *staticAssetVersions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheControl := staticAssetShortCache
		if assets != nil && assets.matches(r.URL.Path, r.URL.Query().Get("v")) {
			cacheControl = staticAssetVersionedCache
		}
		w.Header().Set("Cache-Control", cacheControl)
		w.Header().Add("Vary", "Accept-Encoding")
		if shouldGzipStaticAsset(r) {
			gzipWriter := &gzipResponseWriter{ResponseWriter: w}
			next.ServeHTTP(gzipWriter, r)
			_ = gzipWriter.Close()
			return
		}
		next.ServeHTTP(w, r)
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer      *gzip.Writer
	wroteHeader bool
}

func (w *gzipResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if statusCode == http.StatusOK {
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Encoding", "gzip")
		w.writer = gzip.NewWriter(w.ResponseWriter)
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *gzipResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.writer != nil {
		return w.writer.Write(data)
	}
	return w.ResponseWriter.Write(data)
}

func (w *gzipResponseWriter) Close() error {
	if w.writer == nil {
		return nil
	}
	return w.writer.Close()
}

func shouldGzipStaticAsset(r *http.Request) bool {
	if r.Method != http.MethodGet || r.Header.Get("Range") != "" || !acceptsGzipEncoding(r.Header.Get("Accept-Encoding")) {
		return false
	}
	path := strings.ToLower(r.URL.Path)
	return strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".js")
}

func acceptsGzipEncoding(acceptEncoding string) bool {
	for _, encoding := range strings.Split(acceptEncoding, ",") {
		token, params, _ := strings.Cut(strings.TrimSpace(encoding), ";")
		if strings.EqualFold(strings.TrimSpace(token), "gzip") {
			return !encodingQualityZero(params)
		}
	}
	return false
}

func encodingQualityZero(params string) bool {
	for _, param := range strings.Split(params, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(param), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
			continue
		}
		quality, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return err == nil && quality <= 0
	}
	return false
}

func acceptsHTML(accept string) bool {
	accept = strings.ToLower(accept)
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func reservedPublicFallbackPath(path string) bool {
	first, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	switch first {
	case "admin", "api", "healthz", "metrics", "readyz", "static", "version", ".well-known", "favicon.ico", "robots.txt":
		return true
	default:
		return false
	}
}
