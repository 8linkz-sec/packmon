package web

import (
	"log/slog"
	"net/http"

	"github.com/8linkz/packmon/internal/db"
)

// ScansData is the view model for the scans template.
type ScansData struct {
	ActiveNav    string
	DailyStats   []DailyStatRow
	TotalScans7d int
	RecentScans  []db.ScanLogEntry
}

// HandleScans serves GET /scans.
func HandleScans(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		daily, err := store.CountScansByDay(ctx, 7)
		if err != nil {
			logger.Error("scans: failed to load daily stats", "error", err)
		}

		maxFindings := 0
		totalScans := 0
		for _, d := range daily {
			if d.FindingsCount > maxFindings {
				maxFindings = d.FindingsCount
			}
			totalScans += d.ScanCount
		}

		rows := make([]DailyStatRow, len(daily))
		for i, d := range daily {
			width := 0
			if maxFindings > 0 {
				width = (d.FindingsCount * 100) / maxFindings
			}
			if width < 2 && d.FindingsCount > 0 {
				width = 2
			}
			rows[i] = DailyStatRow{DailyScanStats: d, BarWidth: width}
		}

		scans, err := store.ListRecentScans(ctx, 50)
		if err != nil {
			logger.Error("scans: failed to load recent scans", "error", err)
		}

		data := ScansData{
			ActiveNav:    "scans",
			DailyStats:   rows,
			TotalScans7d: totalScans,
			RecentScans:  scans,
		}

		if err := renderer.Render(w, "scans.html", data); err != nil {
			logger.Error("scans: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}
