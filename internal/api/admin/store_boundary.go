package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type adminAuditEntry = db.AdminAuditEntry

type adminQueueStats struct {
	Pending    int
	Processing int
	Done       int
	Error      int
	Paused     int
}

type adminQueueJob struct {
	ID          int
	Ecosystem   string
	Name        string
	Source      string
	Priority    int
	Status      string
	RequestedAt time.Time
	ProcessedAt *time.Time
	Error       string
}

type adminQueuePageStore interface {
	ListQueueJobsPage(ctx context.Context, status string, limit, offset int) ([]adminQueueJob, error)
}

type dbAdminAuditLogPageStore interface {
	ListAdminAuditLogPage(ctx context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error)
}

type dbAdminStoreAdapter struct {
	db.Store
}

type dbQueuePageStore interface {
	ListQueueJobsPage(ctx context.Context, status string, limit, offset int) ([]db.RefreshJob, error)
}

func adaptAdminStore(store any) Store {
	if s, ok := store.(Store); ok {
		return s
	}
	if s, ok := store.(db.Store); ok {
		return dbAdminStoreAdapter{Store: s}
	}
	return nil
}

func adminAuditEntryToDB(entry *adminAuditEntry) *db.AdminAuditEntry {
	if entry == nil {
		return nil
	}
	out := *entry
	out.Details = append(json.RawMessage(nil), entry.Details...)
	return &out
}

func (s dbAdminStoreAdapter) InsertAdminAuditLog(ctx context.Context, entry *adminAuditEntry) error {
	return s.Store.InsertAdminAuditLog(ctx, adminAuditEntryToDB(entry))
}

func (s dbAdminStoreAdapter) UpsertManualAdvisoryWithAudit(ctx context.Context, advisory *db.ManualAdvisory, audit *adminAuditEntry) error {
	return s.Store.UpsertManualAdvisoryWithAudit(ctx, advisory, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) DeleteManualAdvisoryWithAudit(ctx context.Context, id string, audit *adminAuditEntry) error {
	return s.Store.DeleteManualAdvisoryWithAudit(ctx, id, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) CreateAPIKeyWithAudit(ctx context.Context, name, keyHash string, expiresAt *time.Time, audit *adminAuditEntry) (int, error) {
	return s.Store.CreateAPIKeyWithAudit(ctx, name, keyHash, expiresAt, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) RevokeAPIKeyWithAudit(ctx context.Context, keyID int, audit *adminAuditEntry) error {
	return s.Store.RevokeAPIKeyWithAudit(ctx, keyID, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) DeleteAPIKeyWithAudit(ctx context.Context, keyID int, audit *adminAuditEntry) error {
	return s.Store.DeleteAPIKeyWithAudit(ctx, keyID, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) UpsertAdminAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *adminAuditEntry) error {
	return s.Store.UpsertAdminAuthWithAudit(ctx, passwordHash, isBootstrap, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) ChangeAdminPasswordWithAudit(ctx context.Context, newHash, expectedOldHash string, audit *adminAuditEntry) error {
	return s.Store.ChangeAdminPasswordWithAudit(ctx, newHash, expectedOldHash, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) UpsertSystemSettingsWithAudit(ctx context.Context, settings *db.SystemSettings, audit *adminAuditEntry) error {
	return s.Store.UpsertSystemSettingsWithAudit(ctx, settings, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) UpsertFeedConfigWithAudit(ctx context.Context, cfg *db.FeedConfig, audit *adminAuditEntry) error {
	return s.Store.UpsertFeedConfigWithAudit(ctx, cfg, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) DeleteFeedConfigWithAudit(ctx context.Context, feedName string, expectedUpdatedAt *time.Time, audit *adminAuditEntry) error {
	return s.Store.DeleteFeedConfigWithAudit(ctx, feedName, expectedUpdatedAt, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) QueueStats(ctx context.Context) (*adminQueueStats, error) {
	stats, err := s.Store.QueueStats(ctx)
	if err != nil {
		return nil, err
	}
	return adminQueueStatsFromDB(stats), nil
}

func (s dbAdminStoreAdapter) ListQueueJobs(ctx context.Context, status string, limit int) ([]adminQueueJob, error) {
	jobs, err := s.Store.ListQueueJobs(ctx, status, limit)
	if err != nil {
		return nil, err
	}
	return adminQueueJobsFromDB(jobs), nil
}

func (s dbAdminStoreAdapter) ListQueueJobsPage(ctx context.Context, status string, limit, offset int) ([]adminQueueJob, error) {
	pager, ok := s.Store.(dbQueuePageStore)
	if !ok {
		if offset > 0 {
			return nil, fmt.Errorf("admin queue pagination is not available for this store")
		}
		return s.ListQueueJobs(ctx, status, limit)
	}
	jobs, err := pager.ListQueueJobsPage(ctx, status, limit, offset)
	if err != nil {
		return nil, err
	}
	return adminQueueJobsFromDB(jobs), nil
}

func (s dbAdminStoreAdapter) ListAdminAuditLogPage(ctx context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error) {
	pager, ok := s.Store.(dbAdminAuditLogPageStore)
	if !ok {
		if offset > 0 {
			return nil, fmt.Errorf("admin audit pagination is not available for this store")
		}
		return s.ListAdminAuditLog(ctx, limit)
	}
	return pager.ListAdminAuditLogPage(ctx, limit, offset)
}

func (s dbAdminStoreAdapter) PurgeQueueWithAudit(ctx context.Context, audit *adminAuditEntry) (int, error) {
	return s.Store.PurgeQueueWithAudit(ctx, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) UpdateQueueJobPriorityWithAudit(ctx context.Context, jobID, priority int, audit *adminAuditEntry) error {
	return s.Store.UpdateQueueJobPriorityWithAudit(ctx, jobID, priority, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) PauseQueueJobWithAudit(ctx context.Context, jobID int, audit *adminAuditEntry) error {
	return s.Store.PauseQueueJobWithAudit(ctx, jobID, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) ResumeQueueJobWithAudit(ctx context.Context, jobID int, audit *adminAuditEntry) error {
	return s.Store.ResumeQueueJobWithAudit(ctx, jobID, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) RetryQueueJobWithAudit(ctx context.Context, jobID int, audit *adminAuditEntry) error {
	return s.Store.RetryQueueJobWithAudit(ctx, jobID, adminAuditEntryToDB(audit))
}

func (s dbAdminStoreAdapter) ClearQueueWithAudit(ctx context.Context, statuses []string, audit *adminAuditEntry) (int, error) {
	return s.Store.ClearQueueWithAudit(ctx, statuses, adminAuditEntryToDB(audit))
}

func adminQueueStatsFromDB(stats *db.QueueStatsResult) *adminQueueStats {
	if stats == nil {
		return nil
	}
	return &adminQueueStats{
		Pending:    stats.Pending,
		Processing: stats.Processing,
		Done:       stats.Done,
		Error:      stats.Error,
		Paused:     stats.Paused,
	}
}

func adminQueueJobsFromDB(jobs []db.RefreshJob) []adminQueueJob {
	out := make([]adminQueueJob, 0, len(jobs))
	for _, job := range jobs {
		var processedAt *time.Time
		if job.ProcessedAt != nil {
			value := *job.ProcessedAt
			processedAt = &value
		}
		out = append(out, adminQueueJob{
			ID:          job.ID,
			Ecosystem:   job.Ecosystem,
			Name:        job.Name,
			Source:      job.Source,
			Priority:    job.Priority,
			Status:      job.Status,
			RequestedAt: job.RequestedAt,
			ProcessedAt: processedAt,
			Error:       job.Error,
		})
	}
	return out
}

// CountUnknownSeverityFindings delegates to the store's dedicated counter and
// falls back to the full dashboard aggregate for stores that lack it.
func (s dbAdminStoreAdapter) CountUnknownSeverityFindings(ctx context.Context) (int, error) {
	if counter, ok := s.Store.(interface {
		CountUnknownSeverityFindings(context.Context) (int, error)
	}); ok {
		return counter.CountUnknownSeverityFindings(ctx)
	}
	stats, err := s.DashboardStats(ctx)
	if err != nil || stats == nil {
		return 0, err
	}
	return stats.BySeverity["UNKNOWN"], nil
}
