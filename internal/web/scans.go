package web

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/8linkz-sec/packmon/internal/db"
)

const recentScansPageSize = 50

// ScansData is the view model for the scans template.
type ScansData struct {
	ActiveNav            string
	AdminPage            bool
	AdminSection         string
	CSRFToken            string
	DailyStats           []DailyStatRow
	DailyStatsLoadError  string
	TotalScans7d         int
	RecentScans          []db.ScanLogEntry
	RecentScansLoadError string
	RecentScansHasPrev   bool
	RecentScansHasNext   bool
	RecentScansPrevURL   string
	RecentScansNextURL   string
}

// ScansStore is the persistence surface needed by the scans page.
type ScansStore interface {
	CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error)
	ListRecentScans(ctx context.Context, limit, offset int) ([]db.ScanLogEntry, error)
}

// ScansOptions customizes scans-page rendering for public or admin routes.
type ScansOptions struct {
	ActiveNav    string
	AdminPage    bool
	AdminSection string
	CSRFToken    string
}

// HandleScans serves GET /scans.
func HandleScans(store ScansStore, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return HandleScansWithOptions(store, renderer, logger, ScansOptions{ActiveNav: "scans"})
}

// HandleScansWithOptions serves the scans page with route-specific navigation
// state.
func HandleScansWithOptions(store ScansStore, renderer *Renderer, logger *slog.Logger, opts ScansOptions) http.HandlerFunc {
	dailyCache := NewAggregateCache[[]db.DailyScanStats](webAggregateCacheTTL)

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		activeNav := opts.ActiveNav
		if activeNav == "" {
			activeNav = "scans"
		}
		adminSection := opts.AdminSection
		if adminSection == "" && opts.AdminPage {
			adminSection = "scans"
		}

		daily, err := dailyCache.Get(ctx, func(ctx context.Context) ([]db.DailyScanStats, error) {
			return store.CountScansByDay(ctx, 7)
		})
		dailyStatsLoadError := ""
		if err != nil {
			logger.Error("scans: failed to load daily stats", requestLogAttrs(r, "error", err)...)
			dailyStatsLoadError = webMessage(webMessageKey("scans.error.activity"))
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

		scanOffset := parseScansOffset(r.URL.Query().Get("offset"))
		scans, err := store.ListRecentScans(ctx, recentScansPageSize+1, scanOffset)
		recentScansLoadError := ""
		hasNext := false
		if err != nil {
			logger.Error("scans: failed to load recent scans", requestLogAttrs(r, "error", err)...)
			recentScansLoadError = webMessage(webMessageKey("scans.error.recent"))
		}
		if len(scans) > recentScansPageSize {
			hasNext = true
			scans = scans[:recentScansPageSize]
		}

		data := ScansData{
			ActiveNav:            activeNav,
			AdminPage:            opts.AdminPage,
			AdminSection:         adminSection,
			CSRFToken:            opts.CSRFToken,
			DailyStats:           rows,
			DailyStatsLoadError:  dailyStatsLoadError,
			TotalScans7d:         totalScans,
			RecentScans:          scans,
			RecentScansLoadError: recentScansLoadError,
			RecentScansHasPrev:   scanOffset > 0,
			RecentScansHasNext:   hasNext,
			RecentScansPrevURL:   scansPageURL(r.URL.Path, max(scanOffset-recentScansPageSize, 0)),
			RecentScansNextURL:   scansPageURL(r.URL.Path, scanOffset+recentScansPageSize),
		}

		if err := renderer.Render(w, "scans.html", data); err != nil {
			logger.Error("scans: render failed", requestLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

func parseScansOffset(raw string) int {
	offset, err := strconv.Atoi(raw)
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}

func scansPageURL(path string, offset int) string {
	if path == "" {
		path = "/scans"
	}
	if offset <= 0 {
		return path
	}
	return path + "?offset=" + strconv.Itoa(offset)
}
