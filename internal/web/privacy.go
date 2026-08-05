package web

import (
	"log/slog"
	"net/http"
)

// PrivacyData is the view model for the built-in privacy notice.
type PrivacyData struct {
	ActiveNav string
}

// TermsData is the view model for the built-in terms hook page.
type TermsData struct {
	ActiveNav string
}

// HandlePrivacy serves the built-in Packmon privacy notice.
func HandlePrivacy(renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/privacy" {
			http.NotFound(w, r)
			return
		}
		data := PrivacyData{}
		if err := renderer.Render(w, "privacy.html", data); err != nil {
			logger.Error("privacy: render failed", requestLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

// HandleTerms serves the built-in operator-facing terms hook.
func HandleTerms(renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/terms" {
			http.NotFound(w, r)
			return
		}
		data := TermsData{}
		if err := renderer.Render(w, "terms.html", data); err != nil {
			logger.Error("terms: render failed", requestLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}
