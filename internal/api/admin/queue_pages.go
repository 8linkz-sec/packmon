package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/web"
)

const adminQueuePageSize = 50

// HandleAdminQueue serves GET /admin/queue with queue stats and job list.
func (h *AdminHandler) HandleAdminQueue(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	ctx := r.Context()
	csrfToken, ok := h.adminCSRFToken(w, r, sess, "admin queue")
	if !ok {
		return
	}

	queueStats, err := h.store.QueueStats(ctx)
	queueStatsLoadError := ""
	if err != nil {
		h.logger.Error("admin queue: failed to load stats", h.adminLogAttrs(r, "error", err)...)
		queueStats = &adminQueueStats{}
		queueStatsLoadError = web.Message("admin.queue.error.stats_load")
	}

	queueStatus, queueStatusWarning := adminQueueStatusFilter(r.URL.Query().Get("status"))
	queueOffset := parseNonNegativeOffset(r.URL.Query().Get("offset"))
	jobs, queueHasNext, err := h.listQueueJobsPage(ctx, queueStatus, queueOffset)
	queueJobsLoadError := ""
	if err != nil {
		h.logger.Error("admin queue: failed to load jobs", h.adminLogAttrs(r, "error", err)...)
		queueJobsLoadError = web.Message("admin.queue.error.jobs_load")
	}
	jobViews := adminQueueJobViews(jobs)

	data := map[string]any{
		"ActiveNav":            "admin",
		"CSRFToken":            csrfToken,
		"QueueStats":           queueStats,
		"QueueStatsLoadError":  queueStatsLoadError,
		"Jobs":                 jobViews,
		"QueueJobsLoadError":   queueJobsLoadError,
		"QueueStatus":          queueStatus,
		"QueueStatusWarning":   queueStatusWarning,
		"QueueStatCards":       buildAdminQueueStatCards(queueStatus, queueStats),
		"QueueFilters":         buildAdminQueueFilters(queueStatus, queueStats),
		"QueuePurgeCount":      adminQueuePurgeCount(queueStats),
		"QueuePurgePhrase":     adminQueuePurgePhrase(queueStats),
		"QueueClearActions":    buildAdminQueueClearActions(queueStats),
		"QueuePriorityOptions": db.RefreshPriorityOptions(),
		"QueueHasPrevious":     queueOffset > 0,
		"QueueHasNext":         queueHasNext,
		"QueueCurrentOffset":   queueOffset,
		"QueuePreviousURL":     adminQueuePageURL(queueStatus, max(queueOffset-adminQueuePageSize, 0)),
		"QueueNextURL":         adminQueuePageURL(queueStatus, queueOffset+adminQueuePageSize),
		"QueuePageStart":       auditPageStart(queueOffset, len(jobViews)),
		"QueuePageEnd":         queueOffset + len(jobViews),
		"QueueEmptyState":      buildAdminQueueEmptyState(queueStatus, queueOffset),
		"Message":              r.URL.Query().Get("msg"),
		"Error":                r.URL.Query().Get("err"),
	}
	addAdminBootstrapPageState(data, h.adminBootstrapPageState(ctx, r, sess, "admin queue"))
	h.renderAdmin(w, "admin/queue.html", data)
}

func (h *AdminHandler) listQueueJobsPage(ctx context.Context, status string, offset int) ([]adminQueueJob, bool, error) {
	limit := adminQueuePageSize + 1
	var (
		jobs []adminQueueJob
		err  error
	)
	if pager, ok := h.store.(adminQueuePageStore); ok {
		jobs, err = pager.ListQueueJobsPage(ctx, status, limit, offset)
	} else {
		if offset > 0 {
			return nil, false, fmt.Errorf("admin queue pagination is not available for this store")
		}
		jobs, err = h.store.ListQueueJobs(ctx, status, limit)
	}
	if err != nil {
		return nil, false, err
	}
	if len(jobs) > adminQueuePageSize {
		return jobs[:adminQueuePageSize], true, nil
	}
	return jobs, false, nil
}

// HandleQueuePurge handles POST /admin/queue/purge to remove completed/errored jobs.
func (h *AdminHandler) HandleQueuePurge(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "queue_purge",
		bootstrapRedirectPath: "/admin/queue",
	}); !ok {
		return
	}

	audit := h.adminAuditEntry(r, "queue_purge", map[string]string{})
	var (
		purged int
		err    error
	)
	purged, err = h.store.PurgeQueueWithAudit(r.Context(), audit)
	if err != nil {
		h.logger.Error("admin queue purge failed", h.adminLogAttrs(r, "error", err)...)
		redirectQueue(w, r, queueMutationErrorMessage(err, web.Message("admin.queue.error.purge")), true)
		return
	}

	redirectQueue(w, r, web.Message("admin.queue.flash.purged", purged, adminQueueCountNoun(purged, web.Message("admin.queue.count.purge.singular"), web.Message("admin.queue.count.purge.plural"))), false)
}

// HandleQueuePriorityUpdate handles POST /admin/queue/priority.
func (h *AdminHandler) HandleQueuePriorityUpdate(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "queue_priority_update",
		bootstrapRedirectPath: "/admin/queue",
	}); !ok {
		return
	}

	jobID, ok := queueJobIDFromForm(w, r)
	if !ok {
		return
	}
	priority, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("priority")))
	if err != nil || !db.ValidRefreshPriority(priority) {
		redirectQueue(w, r, web.Message("admin.queue.error.invalid_priority"), true)
		return
	}

	audit := h.adminAuditEntry(r, "queue_priority_update", map[string]string{
		"job_id":   strconv.Itoa(jobID),
		"priority": strconv.Itoa(priority),
	})
	actionErr := h.store.UpdateQueueJobPriorityWithAudit(r.Context(), jobID, priority, audit)
	if actionErr != nil {
		h.logger.Error("admin queue priority update failed", h.adminLogAttrs(r, "job_id", jobID, "error", actionErr)...)
		redirectQueue(w, r, queueMutationErrorMessage(actionErr, web.Message("admin.queue.error.priority_update")), true)
		return
	}
	redirectQueue(w, r, web.Message("admin.queue.flash.priority_updated"), false)
}

// HandleQueuePause handles POST /admin/queue/pause.
func (h *AdminHandler) HandleQueuePause(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_pause", web.Message("admin.queue.flash.job_paused"), web.Message("admin.queue.error.job_pause"), func(ctx context.Context, jobID int, audit *adminAuditEntry) error {
		return h.store.PauseQueueJobWithAudit(ctx, jobID, audit)
	})
}

// HandleQueueResume handles POST /admin/queue/resume.
func (h *AdminHandler) HandleQueueResume(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_resume", web.Message("admin.queue.flash.job_resumed"), web.Message("admin.queue.error.job_resume"), func(ctx context.Context, jobID int, audit *adminAuditEntry) error {
		return h.store.ResumeQueueJobWithAudit(ctx, jobID, audit)
	})
}

// HandleQueueRetry handles POST /admin/queue/retry.
func (h *AdminHandler) HandleQueueRetry(w http.ResponseWriter, r *http.Request) {
	h.handleQueueJobAction(w, r, "queue_retry", web.Message("admin.queue.flash.job_retry"), web.Message("admin.queue.error.job_retry"), func(ctx context.Context, jobID int, audit *adminAuditEntry) error {
		return h.store.RetryQueueJobWithAudit(ctx, jobID, audit)
	})
}

// HandleQueueClear handles POST /admin/queue/clear.
func (h *AdminHandler) HandleQueueClear(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "queue_clear",
		bootstrapRedirectPath: "/admin/queue",
	}); !ok {
		return
	}

	status := strings.ToLower(strings.TrimSpace(r.PostForm.Get("status")))
	var statuses []string
	if status == "all" {
		statuses = db.ClearableRefreshStatuses()
	} else if normalized, ok := db.NormalizeRefreshStatus(status); ok && db.CanClearRefreshStatus(normalized) {
		status = normalized
		statuses = []string{normalized}
	} else {
		redirectQueue(w, r, web.Message("admin.queue.error.invalid_status"), true)
		return
	}

	audit := h.adminAuditEntry(r, "queue_clear", map[string]string{
		"status": status,
	})
	var (
		cleared int
		err     error
	)
	cleared, err = h.store.ClearQueueWithAudit(r.Context(), statuses, audit)
	if err != nil {
		h.logger.Error("admin queue clear failed", h.adminLogAttrs(r, "status", status, "error", err)...)
		redirectQueue(w, r, queueMutationErrorMessage(err, web.Message("admin.queue.error.clear")), true)
		return
	}
	redirectQueue(w, r, web.Message("admin.queue.flash.cleared", cleared, adminQueueCountNoun(cleared, web.Message("admin.queue.count.queue_job.singular"), web.Message("admin.queue.count.queue_jobs.plural"))), false)
}

func (h *AdminHandler) handleQueueJobAction(
	w http.ResponseWriter,
	r *http.Request,
	auditAction,
	message string,
	errorMessage string,
	auditedAction func(context.Context, int, *adminAuditEntry) error,
) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            auditAction,
		bootstrapRedirectPath: "/admin/queue",
	}); !ok {
		return
	}

	jobID, ok := queueJobIDFromForm(w, r)
	if !ok {
		return
	}
	audit := h.adminAuditEntry(r, auditAction, map[string]string{"job_id": strconv.Itoa(jobID)})
	err := auditedAction(r.Context(), jobID, audit)
	if err != nil {
		h.logger.Error("admin queue action failed", h.adminLogAttrs(r, "action", auditAction, "job_id", jobID, "error", err)...)
		redirectQueue(w, r, queueMutationErrorMessage(err, errorMessage), true)
		return
	}
	redirectQueue(w, r, message, false)
}

func queueMutationErrorMessage(err error, fallback string) string {
	if errors.Is(err, db.ErrAdminAuditLog) {
		return web.Message("admin.queue.error.audit_log")
	}
	return fallback
}

func queueJobIDFromForm(w http.ResponseWriter, r *http.Request) (int, bool) {
	jobID, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("job_id")))
	if err != nil || jobID <= 0 {
		redirectQueue(w, r, web.Message("admin.queue.error.invalid_job_id"), true)
		return 0, false
	}
	return jobID, true
}

func redirectQueue(w http.ResponseWriter, r *http.Request, message string, isError bool) {
	key := "msg"
	if isError {
		key = "err"
	}
	values := url.Values{key: {message}}
	status, offset := queueReturnState(r)
	if status != "" {
		values.Set("status", status)
	}
	if offset > 0 {
		values.Set("offset", strconv.Itoa(offset))
	}
	http.Redirect(w, r, "/admin/queue?"+values.Encode(), http.StatusSeeOther)
}

func queueReturnState(r *http.Request) (string, int) {
	if r == nil {
		return "", 0
	}
	status, warning := adminQueueStatusFilter(r.PostForm.Get("return_status"))
	if warning != "" {
		status = ""
	}
	return status, parseNonNegativeOffset(r.PostForm.Get("return_offset"))
}

type adminQueueFilterView struct {
	Label  string
	URL    string
	Active bool
}

type adminQueueStatCardView struct {
	Status     string
	Label      string
	Count      int
	URL        string
	AriaLabel  string
	CountClass string
	Active     bool
}

type adminQueueClearActionView struct {
	Status      string
	Label       string
	Count       int
	CountPhrase string
}

type adminQueueEmptyStateView struct {
	Title          string
	Message        string
	PrimaryURL     string
	PrimaryLabel   string
	SecondaryURL   string
	SecondaryLabel string
}

type adminQueueJobView struct {
	adminQueueJob
	StatusLabel string
	StatusClass string
	CanPause    bool
	CanResume   bool
	CanRetry    bool
}

func buildAdminQueueFilters(active string, stats *adminQueueStats) []adminQueueFilterView {
	filters := []struct {
		status string
		label  string
	}{
		{"", web.Message("admin.queue.filter.all")},
		{db.RefreshStatusPending, db.RefreshStatusLabel(db.RefreshStatusPending)},
		{db.RefreshStatusProcessing, db.RefreshStatusLabel(db.RefreshStatusProcessing)},
		{db.RefreshStatusPaused, db.RefreshStatusLabel(db.RefreshStatusPaused)},
		{db.RefreshStatusError, db.RefreshStatusLabel(db.RefreshStatusError)},
		{db.RefreshStatusDone, db.RefreshStatusLabel(db.RefreshStatusDone)},
	}
	out := make([]adminQueueFilterView, 0, len(filters))
	for _, filter := range filters {
		out = append(out, adminQueueFilterView{
			Label:  web.Message("admin.queue.filter.with_count", filter.label, adminQueueFilterCount(filter.status, stats)),
			URL:    adminQueueURL(filter.status, 0),
			Active: active == filter.status,
		})
	}
	return out
}

func buildAdminQueueStatCards(active string, stats *adminQueueStats) []adminQueueStatCardView {
	cards := []struct {
		status     string
		countClass string
	}{
		{db.RefreshStatusPending, "text-yellow-700"},
		{db.RefreshStatusProcessing, "text-blue-600"},
		{db.RefreshStatusDone, "text-green-600"},
		{db.RefreshStatusError, "text-red-600"},
		{db.RefreshStatusPaused, "text-gray-600"},
	}
	out := make([]adminQueueStatCardView, 0, len(cards))
	for _, card := range cards {
		label := db.RefreshStatusLabel(card.status)
		count := adminQueueFilterCount(card.status, stats)
		out = append(out, adminQueueStatCardView{
			Status:     card.status,
			Label:      label,
			Count:      count,
			URL:        adminQueueURL(card.status, 0),
			AriaLabel:  web.Message("admin.queue.stat.show_aria", label, count),
			CountClass: card.countClass,
			Active:     active == card.status,
		})
	}
	return out
}

func adminQueueFilterCount(status string, stats *adminQueueStats) int {
	if stats == nil {
		return 0
	}
	switch status {
	case "":
		return stats.Pending + stats.Processing + stats.Paused + stats.Error + stats.Done
	case db.RefreshStatusPending:
		return stats.Pending
	case db.RefreshStatusProcessing:
		return stats.Processing
	case db.RefreshStatusPaused:
		return stats.Paused
	case db.RefreshStatusError:
		return stats.Error
	case db.RefreshStatusDone:
		return stats.Done
	default:
		return 0
	}
}

func buildAdminQueueClearActions(stats *adminQueueStats) []adminQueueClearActionView {
	pendingCount := adminQueueFilterCount(db.RefreshStatusPending, stats)
	pausedCount := adminQueueFilterCount(db.RefreshStatusPaused, stats)
	return []adminQueueClearActionView{
		{
			Status:      db.RefreshStatusPending,
			Label:       db.RefreshStatusLabel(db.RefreshStatusPending),
			Count:       pendingCount,
			CountPhrase: adminQueueCountPhrase(pendingCount, web.Message("admin.queue.count.pending.singular"), web.Message("admin.queue.count.pending.plural")),
		},
		{
			Status:      db.RefreshStatusPaused,
			Label:       db.RefreshStatusLabel(db.RefreshStatusPaused),
			Count:       pausedCount,
			CountPhrase: adminQueueCountPhrase(pausedCount, web.Message("admin.queue.count.paused.singular"), web.Message("admin.queue.count.paused.plural")),
		},
	}
}

func adminQueuePurgeCount(stats *adminQueueStats) int {
	return adminQueueFilterCount(db.RefreshStatusDone, stats) + adminQueueFilterCount(db.RefreshStatusError, stats)
}

func adminQueuePurgePhrase(stats *adminQueueStats) string {
	return adminQueueCountPhrase(adminQueuePurgeCount(stats), web.Message("admin.queue.count.purge.singular"), web.Message("admin.queue.count.purge.plural"))
}

func adminQueueCountPhrase(count int, singular, plural string) string {
	return fmt.Sprintf("%d %s", count, adminQueueCountNoun(count, singular, plural))
}

func adminQueueCountNoun(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

func buildAdminQueueEmptyState(status string, offset int) adminQueueEmptyStateView {
	if offset > 0 {
		state := adminQueueEmptyStateView{
			Title:          web.Message("admin.queue.empty.page.title"),
			Message:        web.Message("admin.queue.empty.page.message"),
			PrimaryURL:     adminQueueURL(status, 0),
			PrimaryLabel:   web.Message("admin.queue.empty.page.primary"),
			SecondaryURL:   adminQueueURL("", 0),
			SecondaryLabel: web.Message("admin.queue.empty.view_all"),
		}
		if state.PrimaryURL == state.SecondaryURL {
			state.SecondaryURL = ""
			state.SecondaryLabel = ""
		}
		return state
	}
	if status != "" {
		return adminQueueEmptyStateView{
			Title:        web.Message("admin.queue.empty.filtered.title", db.RefreshStatusLabel(status)),
			Message:      web.Message("admin.queue.empty.filtered.message"),
			PrimaryURL:   adminQueueURL("", 0),
			PrimaryLabel: web.Message("admin.queue.empty.view_all"),
		}
	}
	return adminQueueEmptyStateView{
		Title:        web.Message("admin.queue.empty.all.title"),
		Message:      web.Message("admin.queue.empty.all.message"),
		PrimaryURL:   "/admin/feeds",
		PrimaryLabel: web.Message("admin.queue.empty.all.primary"),
	}
}

func adminQueueJobViews(jobs []adminQueueJob) []adminQueueJobView {
	views := make([]adminQueueJobView, 0, len(jobs))
	for _, job := range jobs {
		status, ok := db.NormalizeRefreshStatus(job.Status)
		if ok {
			job.Status = status
		}
		views = append(views, adminQueueJobView{
			adminQueueJob: job,
			StatusLabel:   db.RefreshStatusLabel(job.Status),
			StatusClass:   adminQueueStatusClass(job.Status),
			CanPause:      job.Status == db.RefreshStatusPending,
			CanResume:     job.Status == db.RefreshStatusPaused,
			CanRetry:      db.CanRetryRefreshStatus(job.Status),
		})
	}
	return views
}

func adminQueueStatusClass(status string) string {
	status, ok := db.NormalizeRefreshStatus(status)
	if !ok {
		return "pm-badge-status-error"
	}
	switch status {
	case db.RefreshStatusPending:
		return "pm-badge-status-pending"
	case db.RefreshStatusProcessing:
		return "pm-badge-status-running"
	case db.RefreshStatusDone:
		return "pm-badge-status-healthy"
	case db.RefreshStatusPaused:
		return "pm-badge-status-disabled"
	case db.RefreshStatusError:
		return "pm-badge-status-error"
	default:
		return "pm-badge-status-error"
	}
}

func adminQueueStatusFilter(raw string) (string, string) {
	if strings.TrimSpace(raw) == "" {
		return "", ""
	}
	status, ok := db.NormalizeRefreshStatus(raw)
	if !ok {
		return "", web.Message("admin.queue.error.status_filter_unknown")
	}
	return status, ""
}

func adminQueueURL(status string, offset int) string {
	return adminQueueURLWithOffset(status, offset, false)
}

func adminQueuePageURL(status string, offset int) string {
	return adminQueueURLWithOffset(status, offset, true)
}

func adminQueueURLWithOffset(status string, offset int, includeZeroOffset bool) string {
	parts := make([]string, 0, 2)
	if status != "" {
		parts = append(parts, "status="+url.QueryEscape(status))
	}
	if offset > 0 || includeZeroOffset {
		parts = append(parts, "offset="+strconv.Itoa(max(offset, 0)))
	}
	if len(parts) == 0 {
		return "/admin/queue"
	}
	return "/admin/queue?" + strings.Join(parts, "&")
}
