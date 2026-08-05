package devstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/logsafe"
)

func (s *Store) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enqueueRefreshLocked(job)
}

func (s *Store) EnqueueRefreshWithAudit(_ context.Context, job *db.RefreshJob, audit db.RefreshEnqueueAuditBuilder) (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	created, position, err := s.enqueueRefreshLocked(job)
	if err != nil {
		return false, 0, err
	}
	if audit != nil {
		entry := audit(created, position)
		if err := s.insertAdminAuditLogLocked(&entry); err != nil {
			return false, 0, fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
	}
	return created, position, nil
}

func (s *Store) enqueueRefreshLocked(job *db.RefreshJob) (bool, int, error) {
	for i := range s.refreshJobs {
		existing := &s.refreshJobs[i]
		if existing.Ecosystem == job.Ecosystem && existing.Name == job.Name && existing.Source == job.Source &&
			db.IsActiveRefreshStatus(existing.Status) {
			if job.Priority < existing.Priority {
				existing.Priority = job.Priority
			}
			return false, s.queuePositionLocked(existing.ID), nil
		}
	}

	s.nextJobID++
	copyValue := cloneRefreshJob(*job)
	copyValue.ID = s.nextJobID
	copyValue.RequestedAt = time.Now().UTC()
	if copyValue.Status == "" {
		copyValue.Status = db.RefreshStatusPending
	} else if normalized, ok := db.NormalizeRefreshStatus(copyValue.Status); ok {
		copyValue.Status = normalized
	} else {
		copyValue.Status = db.RefreshStatusPending
	}
	s.refreshJobs = append(s.refreshJobs, copyValue)
	return true, s.queuePositionLocked(copyValue.ID), nil
}

func (s *Store) DequeueRefresh(_ context.Context, source string) (*db.RefreshJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bestIndex := -1
	for i := range s.refreshJobs {
		job := s.refreshJobs[i]
		if job.Status != db.RefreshStatusPending {
			continue
		}
		if source != "" && job.Source != source {
			continue
		}
		if bestIndex == -1 ||
			job.Priority < s.refreshJobs[bestIndex].Priority ||
			(job.Priority == s.refreshJobs[bestIndex].Priority && job.RequestedAt.Before(s.refreshJobs[bestIndex].RequestedAt)) {
			bestIndex = i
		}
	}
	if bestIndex == -1 {
		return nil, nil
	}

	now := time.Now().UTC()
	s.refreshJobs[bestIndex].Status = db.RefreshStatusProcessing
	s.refreshJobs[bestIndex].ProcessedAt = &now
	job := cloneRefreshJob(s.refreshJobs[bestIndex])
	return &job, nil
}

func (s *Store) CompleteRefresh(_ context.Context, jobID int, jobErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID != jobID {
			continue
		}
		completeRefreshJob(&s.refreshJobs[i], jobErr)
		return nil
	}
	return nil
}

func (s *Store) CompleteClaimedRefresh(_ context.Context, jobID int, claimedAt *time.Time, jobErr error) error {
	if claimedAt == nil {
		return fmt.Errorf("queue job %d missing claim timestamp", jobID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.refreshJobs {
		job := &s.refreshJobs[i]
		if job.ID != jobID {
			continue
		}
		if job.Status != db.RefreshStatusProcessing || job.ProcessedAt == nil || !job.ProcessedAt.Equal(*claimedAt) {
			return nil
		}
		completeRefreshJob(job, jobErr)
		return nil
	}
	return nil
}

func completeRefreshJob(job *db.RefreshJob, jobErr error) {
	now := time.Now().UTC()
	job.ProcessedAt = &now
	if jobErr != nil {
		job.Status = db.RefreshStatusError
		job.Error = logsafe.BoundedDiagnosticValue(jobErr.Error(), 512)
	} else {
		job.Status = db.RefreshStatusDone
		job.Error = ""
	}
}

func (s *Store) ResetStuckJobs(_ context.Context, source string, stuckThreshold time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	reset := 0
	for i := range s.refreshJobs {
		job := &s.refreshJobs[i]
		if job.Status != db.RefreshStatusProcessing || job.ProcessedAt == nil {
			continue
		}
		if source != "" && job.Source != source {
			continue
		}
		if now.Sub(*job.ProcessedAt) <= stuckThreshold {
			continue
		}
		job.Status = db.RefreshStatusPending
		job.ProcessedAt = nil
		job.Error = ""
		reset++
	}
	return reset, nil
}

func (s *Store) GetPackageCheckStatus(_ context.Context, ecosystem, name, source string) (*db.PackageCheckStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	status, ok := s.checkStatuses[packageCheckStatusKey(ecosystem, name, source)]
	if !ok {
		return nil, nil
	}
	copyValue := clonePackageCheckStatus(status)
	return &copyValue, nil
}

func (s *Store) UpsertPackageCheckStatus(_ context.Context, status *db.PackageCheckStatus) error {
	if status == nil || strings.TrimSpace(status.Ecosystem) == "" || strings.TrimSpace(status.Name) == "" || strings.TrimSpace(status.Source) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	copyValue := clonePackageCheckStatus(*status)
	if copyValue.CheckCount <= 0 {
		copyValue.CheckCount = 1
	}
	s.checkStatuses[packageCheckStatusKey(copyValue.Ecosystem, copyValue.Name, copyValue.Source)] = copyValue
	return nil
}

func (s *Store) PrunePackageCheckStatus(_ context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-retention)
	pruned := 0
	for key, status := range s.checkStatuses {
		if status.Source == "socket" && packageCheckStatusUpdatedAt(status).Before(cutoff) {
			delete(s.checkStatuses, key)
			pruned++
		}
	}
	return pruned, nil
}

func packageCheckStatusKey(ecosystem, name, source string) string {
	return ecosystem + "\x00" + name + "\x00" + source
}

func packageCheckStatusUpdatedAt(status db.PackageCheckStatus) time.Time {
	if status.LastCheckedAt != nil {
		return *status.LastCheckedAt
	}
	if status.NextCheckAt != nil {
		return *status.NextCheckAt
	}
	return time.Time{}
}

func (s *Store) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := &db.QueueStatsResult{}
	for _, job := range s.refreshJobs {
		switch job.Status {
		case db.RefreshStatusPending:
			stats.Pending++
		case db.RefreshStatusProcessing:
			stats.Processing++
		case db.RefreshStatusDone:
			stats.Done++
		case db.RefreshStatusError:
			stats.Error++
		case db.RefreshStatusPaused:
			stats.Paused++
		}
	}
	return stats, nil
}

func (s *Store) OldestQueueJobs(context.Context) (map[string]time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldest := make(map[string]time.Time)
	for _, job := range s.refreshJobs {
		if job.Source == "" || !db.IsDrainableRefreshStatus(job.Status) {
			continue
		}
		current, ok := oldest[job.Source]
		if !ok || job.RequestedAt.Before(current) {
			oldest[job.Source] = job.RequestedAt
		}
	}
	return oldest, nil
}

func (s *Store) ListQueueJobs(_ context.Context, status string, limit int) ([]db.RefreshJob, error) {
	return s.ListQueueJobsPage(context.Background(), status, limit, 0)
}

func (s *Store) ListQueueJobsPage(_ context.Context, status string, limit, offset int) ([]db.RefreshJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.RefreshJob, 0, len(s.refreshJobs))
	if offset < 0 {
		offset = 0
	}
	if normalized, ok := db.NormalizeRefreshStatus(status); ok {
		status = normalized
	} else {
		status = ""
	}
	for i, skipped := len(s.refreshJobs)-1, 0; i >= 0; i-- {
		if status != "" && s.refreshJobs[i].Status != status {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, cloneRefreshJob(s.refreshJobs[i]))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *Store) PurgeQueue(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.purgeQueueLocked(), nil
}

func (s *Store) PruneRefreshQueue(_ context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-retention)
	pruned := 0
	kept := s.refreshJobs[:0]
	for _, job := range s.refreshJobs {
		if db.IsTerminalRefreshStatus(job.Status) && refreshQueueTerminalTime(job).Before(cutoff) {
			pruned++
			continue
		}
		kept = append(kept, job)
	}
	s.refreshJobs = kept
	return pruned, nil
}

func refreshQueueTerminalTime(job db.RefreshJob) time.Time {
	if job.ProcessedAt != nil {
		return *job.ProcessedAt
	}
	return job.RequestedAt
}

func (s *Store) PurgeQueueWithAudit(_ context.Context, audit *db.AdminAuditEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	purgeStatuses := noopQueueStatusSet(db.TerminalRefreshStatuses())
	jobs := s.queueJobsForStatusesLocked(purgeStatuses)
	purged := len(jobs)
	if err := db.SetAdminAuditQueueJobsDetail(audit, "purged_jobs", jobs); err != nil {
		return 0, err
	}
	if err := db.SetAdminAuditDetail(audit, "purged", fmt.Sprint(purged)); err != nil {
		return 0, err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return 0, fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	return s.purgeQueueLocked(), nil
}

func (s *Store) purgeQueueLocked() int {
	purged := 0
	kept := s.refreshJobs[:0]
	for _, job := range s.refreshJobs {
		if db.IsTerminalRefreshStatus(job.Status) {
			purged++
			continue
		}
		kept = append(kept, job)
	}
	s.refreshJobs = kept
	return purged
}

func (s *Store) UpdateQueueJobPriority(_ context.Context, jobID, priority int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.updateQueueJobPriorityLocked(jobID, priority)
}

func (s *Store) UpdateQueueJobPriorityWithAudit(_ context.Context, jobID, priority int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.refreshJobs[index].Priority = priority
	return nil
}

func (s *Store) updateQueueJobPriorityLocked(jobID, priority int) error {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID == jobID {
			s.refreshJobs[i].Priority = priority
			return nil
		}
	}
	return fmt.Errorf("queue job %d not found", jobID)
}

func (s *Store) RetryQueueJob(_ context.Context, jobID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.retryQueueJobLocked(jobID)
}

func (s *Store) RetryQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.retryableQueueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.refreshJobs[index].Status = db.RefreshStatusPending
	s.refreshJobs[index].RequestedAt = time.Now().UTC()
	s.refreshJobs[index].ProcessedAt = nil
	s.refreshJobs[index].Error = ""
	return nil
}

func (s *Store) retryQueueJobLocked(jobID int) error {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID != jobID {
			continue
		}
		if db.CanRetryRefreshStatus(s.refreshJobs[i].Status) {
			s.refreshJobs[i].Status = db.RefreshStatusPending
			s.refreshJobs[i].RequestedAt = time.Now().UTC()
			s.refreshJobs[i].ProcessedAt = nil
			s.refreshJobs[i].Error = ""
			return nil
		}
		return fmt.Errorf("queue job %d is not retryable", jobID)
	}
	return fmt.Errorf("queue job %d not found", jobID)
}

func (s *Store) PauseQueueJob(_ context.Context, jobID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.pauseQueueJobLocked(jobID)
}

func (s *Store) PauseQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.pendingQueueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.refreshJobs[index].Status = db.RefreshStatusPaused
	return nil
}

func (s *Store) pauseQueueJobLocked(jobID int) error {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID != jobID {
			continue
		}
		if s.refreshJobs[i].Status != db.RefreshStatusPending {
			return fmt.Errorf("queue job %d is not pending", jobID)
		}
		s.refreshJobs[i].Status = db.RefreshStatusPaused
		return nil
	}
	return fmt.Errorf("queue job %d not found", jobID)
}

func (s *Store) ResumeQueueJob(_ context.Context, jobID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.resumeQueueJobLocked(jobID)
}

func (s *Store) ResumeQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.pausedQueueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.refreshJobs[index].Status = db.RefreshStatusPending
	s.refreshJobs[index].ProcessedAt = nil
	s.refreshJobs[index].Error = ""
	return nil
}

func (s *Store) resumeQueueJobLocked(jobID int) error {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID != jobID {
			continue
		}
		if s.refreshJobs[i].Status != db.RefreshStatusPaused {
			return fmt.Errorf("queue job %d is not paused", jobID)
		}
		s.refreshJobs[i].Status = db.RefreshStatusPending
		s.refreshJobs[i].ProcessedAt = nil
		s.refreshJobs[i].Error = ""
		return nil
	}
	return fmt.Errorf("queue job %d not found", jobID)
}

func (s *Store) ClearQueue(_ context.Context, statuses []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.clearQueueLocked(statuses), nil
}

func (s *Store) ClearQueueWithAudit(_ context.Context, statuses []string, audit *db.AdminAuditEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	allowed := normalizeNoopQueueStatuses(statuses)
	jobs := s.queueJobsForStatusesLocked(allowed)
	cleared := len(jobs)
	if err := db.SetAdminAuditQueueJobsDetail(audit, "cleared_jobs", jobs); err != nil {
		return 0, err
	}
	if err := db.SetAdminAuditDetail(audit, "cleared", fmt.Sprint(cleared)); err != nil {
		return 0, err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return 0, fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	return s.clearQueueWithAllowedLocked(allowed), nil
}

func (s *Store) clearQueueLocked(statuses []string) int {
	return s.clearQueueWithAllowedLocked(normalizeNoopQueueStatuses(statuses))
}

func normalizeNoopQueueStatuses(statuses []string) map[string]struct{} {
	return noopQueueStatusSet(db.NormalizeClearableRefreshStatuses(statuses))
}

func noopQueueStatusSet(statuses []string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(statuses))
	for _, status := range statuses {
		allowed[status] = struct{}{}
	}
	return allowed
}

func (s *Store) clearQueueWithAllowedLocked(allowed map[string]struct{}) int {
	if len(allowed) == 0 {
		return 0
	}

	cleared := 0
	kept := s.refreshJobs[:0]
	for _, job := range s.refreshJobs {
		if _, ok := allowed[job.Status]; ok {
			cleared++
			continue
		}
		kept = append(kept, job)
	}
	s.refreshJobs = kept
	return cleared
}

func (s *Store) queueJobsForStatusesLocked(allowed map[string]struct{}) []db.RefreshJob {
	if len(allowed) == 0 {
		return nil
	}
	jobs := make([]db.RefreshJob, 0)
	for _, job := range s.refreshJobs {
		if _, ok := allowed[job.Status]; ok {
			jobs = append(jobs, job)
		}
	}
	return jobs
}

func (s *Store) queueJobIndexLocked(jobID int) (int, error) {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID == jobID {
			return i, nil
		}
	}
	return -1, fmt.Errorf("queue job %d not found", jobID)
}

func (s *Store) pendingQueueJobIndexLocked(jobID int) (int, error) {
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return -1, err
	}
	if s.refreshJobs[index].Status != db.RefreshStatusPending {
		return -1, fmt.Errorf("queue job %d is not pending", jobID)
	}
	return index, nil
}

func (s *Store) pausedQueueJobIndexLocked(jobID int) (int, error) {
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return -1, err
	}
	if s.refreshJobs[index].Status != db.RefreshStatusPaused {
		return -1, fmt.Errorf("queue job %d is not paused", jobID)
	}
	return index, nil
}

func (s *Store) retryableQueueJobIndexLocked(jobID int) (int, error) {
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return -1, err
	}
	if db.CanRetryRefreshStatus(s.refreshJobs[index].Status) {
		return index, nil
	}
	return -1, fmt.Errorf("queue job %d is not retryable", jobID)
}

func (s *Store) queuePositionLocked(jobID int) int {
	var target *db.RefreshJob
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID == jobID {
			target = &s.refreshJobs[i]
			break
		}
	}
	if target == nil {
		return 0
	}
	if !db.IsDrainableRefreshStatus(target.Status) {
		return 0
	}

	position := 1
	for _, job := range s.refreshJobs {
		if !db.IsDrainableRefreshStatus(job.Status) || job.Source != target.Source || job.ID == target.ID {
			continue
		}
		if noopRefreshJobBefore(job, *target) {
			position++
		}
	}
	return position
}

func noopRefreshJobBefore(a, b db.RefreshJob) bool {
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	if !a.RequestedAt.Equal(b.RequestedAt) {
		return a.RequestedAt.Before(b.RequestedAt)
	}
	return a.ID < b.ID
}
