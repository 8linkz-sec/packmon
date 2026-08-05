package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// HandleSecurityTxt serves the RFC 9116 security contact discovery file.
func HandleSecurityTxt(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/security.txt" {
			http.NotFound(w, r)
			return
		}

		expires := time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if _, err := fmt.Fprintf(w, "Contact: https://github.com/8linkz-sec/packmon/security/advisories/new\nPolicy: https://github.com/8linkz-sec/packmon/security/policy\nPreferred-Languages: en\nExpires: %s\n", expires); err != nil {
			logger.Error("security.txt: write failed", requestLogAttrs(r, "error", err)...)
		}
	}
}
