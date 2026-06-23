package web

import (
	"log/slog"
	"net/http"
)

// PrivacyData is the view model for the built-in privacy notice.
type PrivacyData struct {
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
			logger.Error("privacy: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}
