package web

import (
	"log/slog"
	"net/http"

	"github.com/8linkz/packmon/internal/db"
)

// DashboardData is the view model for the dashboard template.
type DashboardData struct {
	ActiveNav    string
	Stats        *db.DashboardStatsResult
	DailyStats   []DailyStatRow
	TotalScans7d int
	RecentScans  []db.ScanLogEntry
}

// DailyStatRow extends DailyScanStats with a computed bar width for the
// simple visual trend display.
type DailyStatRow struct {
	db.DailyScanStats
	BarWidth int // percentage 0-100
}

// HandleDashboard serves GET /.
func HandleDashboard(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only handle exact root path; let other routes fall through.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		ctx := r.Context()

		stats, err := store.DashboardStats(ctx)
		if err != nil {
			logger.Error("dashboard: failed to load stats", "error", err)
			stats = &db.DashboardStatsResult{BySeverity: map[string]int{}}
		}

		daily, err := store.CountScansByDay(ctx, 7)
		if err != nil {
			logger.Error("dashboard: failed to load daily stats", "error", err)
		}

		// Compute bar widths relative to max finding count.
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

		scans, err := store.ListRecentScans(ctx, 15)
		if err != nil {
			logger.Error("dashboard: failed to load recent scans", "error", err)
		}

		data := DashboardData{
			ActiveNav:    "dashboard",
			Stats:        stats,
			DailyStats:   rows,
			TotalScans7d: totalScans,
			RecentScans:  scans,
		}

		if err := renderer.Render(w, "dashboard.html", data); err != nil {
			logger.Error("dashboard: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}
