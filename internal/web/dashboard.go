package web

import (
	"log/slog"
	"net/http"

	"github.com/8linkz-sec/packmon/internal/db"
)

// DashboardData is the view model for the dashboard template.
type DashboardData struct {
	ActiveNav                      string
	Stats                          *db.DashboardStatsResult
	StatsLoadError                 string
	TotalScans7d                   int
	ScanCountLoadError             string
	RecentVulnerabilities          []db.RecentVulnerability
	RecentVulnerabilitiesLoadError string
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
		statsLoadError := ""
		if err != nil {
			logger.Error("dashboard: failed to load stats", "error", err)
			stats = &db.DashboardStatsResult{BySeverity: map[string]int{}}
			statsLoadError = "Dashboard metrics could not be loaded. Check the server logs and database connection before relying on these totals."
		}

		// Quick scan count for the stats card.
		daily, err := store.CountScansByDay(ctx, 7)
		scanCountLoadError := ""
		if err != nil {
			logger.Error("dashboard: failed to load daily stats", "error", err)
			scanCountLoadError = "Scan activity could not be loaded. Check the server logs and database connection before relying on recent scan counts."
		}
		totalScans := 0
		for _, d := range daily {
			totalScans += d.ScanCount
		}

		recentVulns, err := store.ListRecentVulnerabilities(ctx, 7, 20)
		recentVulnsLoadError := ""
		if err != nil {
			logger.Error("dashboard: failed to load recent vulnerabilities", "error", err)
			recentVulnsLoadError = "Recent vulnerabilities could not be loaded. Check the server logs and database connection before relying on this section."
		}

		data := DashboardData{
			ActiveNav:                      "dashboard",
			Stats:                          stats,
			StatsLoadError:                 statsLoadError,
			TotalScans7d:                   totalScans,
			ScanCountLoadError:             scanCountLoadError,
			RecentVulnerabilities:          recentVulns,
			RecentVulnerabilitiesLoadError: recentVulnsLoadError,
		}

		if err := renderer.Render(w, "dashboard.html", data); err != nil {
			logger.Error("dashboard: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}
