package web

import (
	"log/slog"
	"net/http"
	"strings"
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
	RejectedCount  int
	LastError      string
	DurationStr    string
}

// HandleFeeds serves GET /feeds. When the query parameter partial=status is
// present on an HTMX request, only the feed status table fragment is returned
// (for HTMX polling from the dashboard and feeds page).
func HandleFeeds(store Store, renderer *Renderer, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		partial := r.URL.Query().Get("partial")
		if partial == "status" {
			w.Header().Add("Vary", "HX-Request")
		}

		statuses, err := store.ListFeedSyncStatuses(ctx)
		loadError := ""
		if err != nil {
			logger.Error("feeds: failed to list statuses", requestLogAttrs(r, "error", err)...)
			loadError = webMessage(webMessageKey("feeds.error.load_status"))
		}

		rows := make([]FeedRow, 0, len(statuses))
		for _, s := range statuses {
			// Synthetic pipeline statuses (e.g. alias-severity-propagation) are
			// recorded for observability but are not feeds, so keep them out of
			// the user-facing feed list.
			if feedhealth.IsSyntheticStatus(s.FeedName) {
				continue
			}
			status, reason := feedHealth(s)
			row := FeedRow{
				FeedName:       s.FeedName,
				Status:         status,
				StatusReason:   reason,
				LastSyncAt:     s.LastSyncAt,
				LastSyncStatus: s.LastSyncStatus,
				EntriesSynced:  s.EntriesSynced,
				EntriesTotal:   s.EntriesTotal,
				RejectedCount:  feedhealth.RejectedRecordCount(s),
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
		if partial == "status" && isHTMXRequest(r) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err := renderer.RenderPartial(w, "feeds.html", "feed-status-partial", data); err != nil {
				logger.Error("feeds: partial render failed", requestLogAttrs(r, "error", err)...)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
			return
		}

		if err := renderer.Render(w, "feeds.html", data); err != nil {
			logger.Error("feeds: render failed", requestLogAttrs(r, "error", err)...)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
	}
}

func isHTMXRequest(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("HX-Request")), "true")
}

// feedHealthStatus derives a health string from sync status.
func feedHealth(s db.FeedSyncStatus) (string, string) {
	health := feedhealth.FeedStatusHealth(s, feedhealth.HealthOptions{})
	return health.Status, health.Reason
}
