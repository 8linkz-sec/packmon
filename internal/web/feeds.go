package web

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

// FeedStatusData is the view model for the feeds template.
type FeedStatusData struct {
	ActiveNav string
	Feeds     []FeedRow
}

// FeedRow is the view model for one feed in the status table.
type FeedRow struct {
	FeedName       string
	Status         string
	LastSyncAt     *time.Time
	LastSyncAtTime time.Time // dereferenced for template convenience
	LastSyncStatus string
	EntriesSynced  int
	EntriesTotal   int
	LastError      string
	DurationStr    string
}

// HandleFeeds serves GET /feeds. When the query parameter partial=status
// is present, only the feed status table fragment is returned (for HTMX
// polling from the dashboard and feeds page).
func HandleFeeds(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		statuses, err := store.ListFeedSyncStatuses(ctx)
		if err != nil {
			logger.Error("feeds: failed to list statuses", "error", err)
		}

		rows := make([]FeedRow, 0, len(statuses))
		for _, s := range statuses {
			row := FeedRow{
				FeedName:       s.FeedName,
				Status:         feedHealthStatus(s),
				LastSyncAt:     s.LastSyncAt,
				LastSyncStatus: s.LastSyncStatus,
				EntriesSynced:  s.EntriesSynced,
				EntriesTotal:   s.EntriesTotal,
				LastError:      s.LastError,
			}
			if s.LastSyncAt != nil {
				row.LastSyncAtTime = *s.LastSyncAt
			}
			if s.LastSyncDuration != nil {
				row.DurationStr = s.LastSyncDuration.Round(time.Millisecond).String()
			}
			rows = append(rows, row)
		}

		data := FeedStatusData{
			ActiveNav: "feeds",
			Feeds:     rows,
		}

		// Partial response for HTMX polling.
		if r.URL.Query().Get("partial") == "status" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := renderer.RenderPartial(w, "feeds.html", "feed-status-partial", data); err != nil {
				logger.Error("feeds: partial render failed", "error", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
			return
		}

		if err := renderer.Render(w, "feeds.html", data); err != nil {
			logger.Error("feeds: render failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

// feedHealthStatus derives a health string from sync status.
// Duplicated from api/v1 to avoid a cross-package dependency; both use
// the same logic.
func feedHealthStatus(s db.FeedSyncStatus) string {
	if s.LastSyncStatus == "error" {
		return "error"
	}
	if s.LastSyncStatus == "disabled" {
		return "disabled"
	}
	if s.LastSyncStatus == "running" {
		return "pending"
	}
	if s.LastSyncStatus == "skipped" {
		return "warning"
	}
	if s.LastSyncAt == nil {
		return "error"
	}
	if time.Since(*s.LastSyncAt) > 48*time.Hour {
		return "warning"
	}
	if s.EntriesTotal == 0 && s.EntriesSynced == 0 {
		return "warning"
	}
	return "healthy"
}
