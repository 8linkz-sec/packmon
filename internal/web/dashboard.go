package web

import (
	"log/slog"
	"net/http"

	"github.com/8linkz/packmon/internal/db"
)

// DashboardData is the view model for the dashboard template.
type DashboardData struct {
	ActiveNav             string
	Stats                 *db.DashboardStatsResult
	TotalScans7d          int
	RecentVulnerabilities []db.RecentVulnerability
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

		// Quick scan count for the stats card.
		daily, err := store.CountScansByDay(ctx, 7)
		if err != nil {
			logger.Error("dashboard: failed to load daily stats", "error", err)
		}
		totalScans := 0
		for _, d := range daily {
			totalScans += d.ScanCount
		}

		recentVulns, err := store.ListRecentVulnerabilities(ctx, 7, 20)
		if err != nil {
			logger.Error("dashboard: failed to load recent vulnerabilities", "error", err)
		}

		data := DashboardData{
			ActiveNav:             "dashboard",
			Stats:                 stats,
			TotalScans7d:          totalScans,
			RecentVulnerabilities: recentVulns,
		}

		if err := renderer.Render(w, "dashboard.html", data); err != nil {
			logger.Error("dashboard: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}
