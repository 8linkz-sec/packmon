package web

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	"github.com/8linkz-sec/packmon/internal/db"
)

// DashboardData is the view model for the dashboard template.
//
// Scan counts and lifecycle totals are deliberately absent: they are
// operator-facing numbers and live on the admin dashboard.
type DashboardData struct {
	ActiveNav                      string
	Stats                          *db.DashboardStatsResult
	StatsLoadError                 string
	RecentVulnerabilities          []db.RecentVulnerability
	RecentVulnerabilitiesLoadError string
	LocalDBWarning                 string
}

// DashboardOptions contains caller-specific dashboard behavior. The server
// dashboard uses the defaults; the local CLI dashboard can add local DB state.
type DashboardOptions struct {
	ActiveNav      string
	LocalDBWarning func(context.Context) string
}

// DailyStatRow extends DailyScanStats with a computed bar width for the
// simple visual trend display.
type DailyStatRow struct {
	db.DailyScanStats
	BarWidth int // percentage 0-100
}

// HandleDashboard serves GET /.
func HandleDashboard(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return HandleDashboardWithOptions(store, renderer, logger, DashboardOptions{})
}

// HandleDashboardWithOptions serves GET / with caller-specific dashboard data.
func HandleDashboardWithOptions(store Store, renderer *Renderer, logger *slog.Logger, options DashboardOptions) http.HandlerFunc {
	activeNav := options.ActiveNav
	if activeNav == "" {
		activeNav = "dashboard"
	}
	statsCache := NewAggregateCache[*db.DashboardStatsResult](webAggregateCacheTTL)

	return func(w http.ResponseWriter, r *http.Request) {
		// Only handle exact root path; let other routes fall through.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		ctx := r.Context()

		var (
			stats                *db.DashboardStatsResult
			statsLoadError       string
			recentVulns          []db.RecentVulnerability
			recentVulnsLoadError string
			widgetReads          sync.WaitGroup
		)

		widgetReads.Add(2)
		go func() {
			defer widgetReads.Done()
			var err error
			stats, err = statsCache.Get(ctx, store.DashboardStats)
			if err != nil {
				logger.Error("dashboard: failed to load stats", contextLogAttrs(ctx, "error", err)...)
				stats = &db.DashboardStatsResult{BySeverity: map[string]int{}}
				statsLoadError = webMessage(webMessageKey("dashboard.error.stats"))
			}
		}()
		go func() {
			defer widgetReads.Done()
			var err error
			recentVulns, err = store.ListRecentVulnerabilities(ctx, 7, 20)
			if err != nil {
				logger.Error("dashboard: failed to load recent vulnerabilities", contextLogAttrs(ctx, "error", err)...)
				recentVulnsLoadError = webMessage(webMessageKey("dashboard.error.recent_vulnerabilities"))
			}
		}()
		widgetReads.Wait()

		localDBWarning := ""
		if options.LocalDBWarning != nil {
			localDBWarning = options.LocalDBWarning(ctx)
		}

		data := DashboardData{
			ActiveNav:                      activeNav,
			Stats:                          stats,
			StatsLoadError:                 statsLoadError,
			RecentVulnerabilities:          recentVulns,
			RecentVulnerabilitiesLoadError: recentVulnsLoadError,
			LocalDBWarning:                 localDBWarning,
		}

		if err := renderer.Render(w, "dashboard.html", data); err != nil {
			logger.Error("dashboard: render failed", requestLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}
