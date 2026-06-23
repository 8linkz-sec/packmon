package web

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	feedhealth "github.com/8linkz-sec/packmon/internal/feed"
	"github.com/8linkz-sec/packmon/internal/logsafe"
)

// FeedStatusData is the view model for the feeds template.
type FeedStatusData struct {
	ActiveNav string
	Feeds     []FeedRow
	LoadError string
}

// FeedRow is the view model for one feed in the status table.
type FeedRow struct {
	FeedName       string
	Status         string
	StatusReason   string
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
		loadError := ""
		if err != nil {
			logger.Error("feeds: failed to list statuses", "error", err)
			loadError = "Feed status could not be loaded. Check the server logs and database connection before relying on feed health."
		}

		rows := make([]FeedRow, 0, len(statuses))
		for _, s := range statuses {
			status, reason := feedHealth(s)
			row := FeedRow{
				FeedName:       s.FeedName,
				Status:         status,
				StatusReason:   reason,
				LastSyncAt:     s.LastSyncAt,
				LastSyncStatus: s.LastSyncStatus,
				EntriesSynced:  s.EntriesSynced,
				EntriesTotal:   s.EntriesTotal,
				LastError:      logsafe.RedactDiagnosticMessage(s.LastError),
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
			LoadError: loadError,
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
func feedHealth(s db.FeedSyncStatus) (string, string) {
	health := feedhealth.FeedStatusHealth(s, feedhealth.HealthOptions{})
	return health.Status, health.Reason
}
