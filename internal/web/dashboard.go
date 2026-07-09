package web

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

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
	statsCache := newWebAggregateCache[*db.DashboardStatsResult](webAggregateCacheTTL)
	dailyCache := newWebAggregateCache[[]db.DailyScanStats](webAggregateCacheTTL)

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
			daily                []db.DailyScanStats
			scanCountLoadError   string
			recentVulns          []db.RecentVulnerability
			recentVulnsLoadError string
			widgetReads          sync.WaitGroup
		)

		widgetReads.Add(3)
		go func() {
			defer widgetReads.Done()
			var err error
			stats, err = statsCache.get(ctx, store.DashboardStats)
			if err != nil {
				logger.Error("dashboard: failed to load stats", contextLogAttrs(ctx, "error", err)...)
				stats = &db.DashboardStatsResult{BySeverity: map[string]int{}}
				statsLoadError = webMessage(webMessageKey("dashboard.error.stats"))
			}
		}()
		go func() {
			defer widgetReads.Done()
			var err error
			daily, err = dailyCache.get(ctx, func(ctx context.Context) ([]db.DailyScanStats, error) {
				return store.CountScansByDay(ctx, 7)
			})
			if err != nil {
				logger.Error("dashboard: failed to load daily stats", contextLogAttrs(ctx, "error", err)...)
				scanCountLoadError = webMessage(webMessageKey("dashboard.error.scan_activity"))
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

		totalScans := 0
		for _, d := range daily {
			totalScans += d.ScanCount
		}

		localDBWarning := ""
		if options.LocalDBWarning != nil {
			localDBWarning = options.LocalDBWarning(ctx)
		}

		data := DashboardData{
			ActiveNav:                      activeNav,
			Stats:                          stats,
			StatsLoadError:                 statsLoadError,
			TotalScans7d:                   totalScans,
			ScanCountLoadError:             scanCountLoadError,
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
