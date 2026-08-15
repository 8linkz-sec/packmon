package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/web"
)

type adminFlowStoreStub struct {
	db.Store
	mu             sync.Mutex
	adminAuth      *db.AdminAuth
	onGetAdminAuth func(*adminFlowStoreStub)
	apiKeys        []db.APIKey
	nextAPIKeyID   int
	audit          []db.AdminAuditLogEntry
	nextAuditID    int
	feedStatuses   map[string]db.FeedSyncStatus
	feedConfigs    map[string]db.FeedConfig
	systemSettings *db.SystemSettings
	manual         map[string]db.ManualAdvisory
	queueJobs      []db.RefreshJob
	nextJobID      int
	dashboard      *db.DashboardStatsResult
	dailyScans     []db.DailyScanStats
	recentScans    []db.ScanLogEntry

	listFeedConfigs      int
	dashboardStatsCalls  int
	unknownSeverityCalls int
	unknownSeverityCount int
}

func newAdminStoreStub() *adminFlowStoreStub {
	return &adminFlowStoreStub{
		feedStatuses: make(map[string]db.FeedSyncStatus),
		feedConfigs:  make(map[string]db.FeedConfig),
		manual:       make(map[string]db.ManualAdvisory),
		dashboard:    &db.DashboardStatsResult{BySeverity: map[string]int{}},
	}
}

func (s *adminFlowStoreStub) GetAdminAuth(context.Context) (*db.AdminAuth, error) {
	s.mu.Lock()
	if s.adminAuth == nil {
		s.mu.Unlock()
		return nil, nil
	}
	copyValue := *s.adminAuth
	onGetAdminAuth := s.onGetAdminAuth
	s.onGetAdminAuth = nil
	s.mu.Unlock()
	if onGetAdminAuth != nil {
		onGetAdminAuth(s)
	}
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertAdminAuth(_ context.Context, passwordHash string, isBootstrap bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertAdminAuthLocked(passwordHash, isBootstrap)
	return nil
}

func (s *adminFlowStoreStub) UpsertAdminAuthWithAudit(_ context.Context, passwordHash string, isBootstrap bool, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	s.upsertAdminAuthLocked(passwordHash, isBootstrap)
	return nil
}

func (s *adminFlowStoreStub) ChangeAdminPasswordWithAudit(_ context.Context, newHash, expectedOldHash string, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.adminAuth == nil || s.adminAuth.PasswordHash != expectedOldHash {
		return db.ErrAdminAuthConflict
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	s.upsertAdminAuthLocked(newHash, false)
	return nil
}

func (s *adminFlowStoreStub) upsertAdminAuthLocked(passwordHash string, isBootstrap bool) {
	now := time.Now().UTC()
	if s.adminAuth == nil {
		s.adminAuth = &db.AdminAuth{CreatedAt: now}
	}
	s.adminAuth.PasswordHash = passwordHash
	s.adminAuth.PasswordIsBootstrap = isBootstrap
	if isBootstrap {
		s.adminAuth.PasswordChangedAt = nil
	} else {
		s.adminAuth.PasswordChangedAt = &now
	}
}

func (s *adminFlowStoreStub) InsertAdminAuditLog(_ context.Context, entry *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.insertAdminAuditLogLocked(entry)
}

func (s *adminFlowStoreStub) insertAdminAuditLogLocked(entry *db.AdminAuditEntry) error {
	s.nextAuditID++
	previousDigest := ""
	if len(s.audit) > 0 {
		previousDigest = s.audit[len(s.audit)-1].RowDigest
	}
	auditEntry := db.AdminAuditLogEntry{
		ID:             s.nextAuditID,
		Action:         entry.Action,
		Details:        append([]byte(nil), entry.Details...),
		IP:             entry.IP,
		CorrelationID:  entry.CorrelationID,
		CreatedAt:      time.Now().UTC().Truncate(time.Microsecond),
		PreviousDigest: previousDigest,
	}
	auditEntry.RowDigest = db.ComputeAdminAuditDigest(auditEntry)
	auditEntry.IntegrityStatus = db.AdminAuditIntegrityStatus(auditEntry)
	s.audit = append(s.audit, auditEntry)
	if entry.Action == "login_success" && s.adminAuth != nil {
		now := time.Now().UTC()
		s.adminAuth.LastLoginAt = &now
	}
	return nil
}

func (s *adminFlowStoreStub) ListAdminAuditLog(_ context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.audit) {
		limit = len(s.audit)
	}
	out := make([]db.AdminAuditLogEntry, 0, limit)
	for i := len(s.audit) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.audit[i])
	}
	db.AnnotateAdminAuditIntegrity(out)
	return out, nil
}

func (s *adminFlowStoreStub) ListAdminAuditLogPage(_ context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.audit) {
		limit = len(s.audit)
	}
	if offset < 0 {
		offset = 0
	}

	out := make([]db.AdminAuditLogEntry, 0, limit)
	for i, skipped := len(s.audit)-1, 0; i >= 0 && len(out) < limit; i-- {
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, s.audit[i])
	}
	db.AnnotateAdminAuditIntegrity(out)
	return out, nil
}

func (s *adminFlowStoreStub) ListAPIKeys(context.Context) ([]db.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]db.APIKey(nil), s.apiKeys...)
	return out, nil
}

func (s *adminFlowStoreStub) ListAPIKeysPage(_ context.Context, limit, offset int) ([]db.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		return nil, nil
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(s.apiKeys) {
		return nil, nil
	}
	end := min(offset+limit, len(s.apiKeys))
	return append([]db.APIKey(nil), s.apiKeys[offset:end]...), nil
}

func (s *adminFlowStoreStub) CreateAPIKey(_ context.Context, name, keyHash string, expiresAt *time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createAPIKeyLocked(name, keyHash, expiresAt), nil
}

func (s *adminFlowStoreStub) CreateAPIKeyWithAudit(_ context.Context, name, keyHash string, expiresAt *time.Time, audit *db.AdminAuditEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keyID := s.nextAPIKeyID + 1
	if err := db.SetAdminAuditDetail(audit, "key_id", strconv.Itoa(keyID)); err != nil {
		return 0, err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return 0, err
	}
	return s.createAPIKeyLocked(name, keyHash, expiresAt), nil
}

func (s *adminFlowStoreStub) createAPIKeyLocked(name, keyHash string, expiresAt *time.Time) int {
	s.nextAPIKeyID++
	s.apiKeys = append(s.apiKeys, db.APIKey{
		ID:        s.nextAPIKeyID,
		Name:      name,
		KeyHash:   keyHash,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	})
	return s.nextAPIKeyID
}

func (s *adminFlowStoreStub) RevokeAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeAPIKeyLocked(keyID)
}

func (s *adminFlowStoreStub) RevokeAPIKeyWithAudit(_ context.Context, keyID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.apiKeyIndexLocked(keyID)
	if err != nil {
		return err
	}
	if s.apiKeys[index].RevokedAt != nil {
		return fmt.Errorf("api key %d already revoked", keyID)
	}
	if s.apiKeys[index].DeletedAt != nil {
		return fmt.Errorf("api key %d not found", keyID)
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	now := time.Now().UTC()
	s.apiKeys[index].RevokedAt = &now
	return nil
}

func (s *adminFlowStoreStub) revokeAPIKeyLocked(keyID int) error {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID == keyID {
			if s.apiKeys[i].RevokedAt != nil {
				return fmt.Errorf("api key %d already revoked", keyID)
			}
			if s.apiKeys[i].DeletedAt != nil {
				return fmt.Errorf("api key %d not found", keyID)
			}
			now := time.Now().UTC()
			s.apiKeys[i].RevokedAt = &now
			return nil
		}
	}
	return fmt.Errorf("api key %d not found", keyID)
}

func (s *adminFlowStoreStub) DeleteAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteAPIKeyLocked(keyID)
}

func (s *adminFlowStoreStub) DeleteAPIKeyWithAudit(_ context.Context, keyID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.apiKeyIndexLocked(keyID)
	if err != nil {
		return err
	}
	if s.apiKeys[index].RevokedAt == nil {
		return fmt.Errorf("api key %d is not revoked", keyID)
	}
	if s.apiKeys[index].DeletedAt != nil {
		return fmt.Errorf("api key %d not found", keyID)
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	now := time.Now().UTC()
	s.apiKeys[index].DeletedAt = &now
	s.apiKeys[index].Name = ""
	s.apiKeys[index].KeyHash = fmt.Sprintf("deleted:%d", keyID)
	return nil
}

func (s *adminFlowStoreStub) deleteAPIKeyLocked(keyID int) error {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID == keyID {
			if s.apiKeys[i].RevokedAt == nil {
				return fmt.Errorf("api key %d is not revoked", keyID)
			}
			if s.apiKeys[i].DeletedAt != nil {
				return fmt.Errorf("api key %d not found", keyID)
			}
			now := time.Now().UTC()
			s.apiKeys[i].DeletedAt = &now
			s.apiKeys[i].Name = ""
			s.apiKeys[i].KeyHash = fmt.Sprintf("deleted:%d", keyID)
			return nil
		}
	}
	return fmt.Errorf("api key %d not found", keyID)
}

func (s *adminFlowStoreStub) apiKeyIndexLocked(keyID int) (int, error) {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID == keyID {
			return i, nil
		}
	}
	return -1, fmt.Errorf("api key %d not found", keyID)
}

func (s *adminFlowStoreStub) GetFeedSyncStatus(_ context.Context, feedName string) (*db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.feedStatuses[config.NormalizeFeedName(feedName)]
	if !ok {
		return nil, nil
	}
	copyValue := status
	if status.Metadata != nil {
		copyValue.Metadata = append([]byte(nil), status.Metadata...)
	}
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *status
	if status.Metadata != nil {
		copyValue.Metadata = append([]byte(nil), status.Metadata...)
	}
	s.feedStatuses[config.NormalizeFeedName(status.FeedName)] = copyValue
	return nil
}

func (s *adminFlowStoreStub) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.FeedSyncStatus, 0, len(s.feedStatuses))
	for _, status := range s.feedStatuses {
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FeedName < out[j].FeedName })
	return out, nil
}

func (s *adminFlowStoreStub) GetFeedConfig(_ context.Context, feedName string) (*db.FeedConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.feedConfigs[config.NormalizeFeedName(feedName)]
	if !ok {
		return nil, nil
	}
	copyValue := cfg
	if cfg.SyncInterval != nil {
		duration := *cfg.SyncInterval
		copyValue.SyncInterval = &duration
	}
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertFeedConfig(_ context.Context, cfg *db.FeedConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertFeedConfigLocked(cfg)
	return nil
}

func (s *adminFlowStoreStub) UpsertFeedConfigWithAudit(_ context.Context, cfg *db.FeedConfig, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected, ok := expectedAdminFlowFeedConfigUpdatedAt(cfg); ok {
		if err := s.checkFeedConfigRevisionLocked(cfg.FeedName, expected); err != nil {
			return err
		}
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	s.upsertFeedConfigLocked(cfg)
	return nil
}

func (s *adminFlowStoreStub) upsertFeedConfigLocked(cfg *db.FeedConfig) {
	copyValue := *cfg
	copyValue.FeedName = config.NormalizeFeedName(cfg.FeedName)
	copyValue.UpdatedAt = time.Now().UTC()
	copyValue.ExpectedUpdatedAt = nil
	if cfg.SyncInterval != nil {
		duration := *cfg.SyncInterval
		copyValue.SyncInterval = &duration
	}
	s.feedConfigs[copyValue.FeedName] = copyValue
}

func (s *adminFlowStoreStub) DeleteFeedConfig(_ context.Context, feedName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteFeedConfigLocked(feedName)
	return nil
}

func (s *adminFlowStoreStub) DeleteFeedConfigWithAudit(_ context.Context, feedName string, expectedUpdatedAt *time.Time, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedUpdatedAt != nil {
		if err := s.checkFeedConfigRevisionLocked(feedName, *expectedUpdatedAt); err != nil {
			return err
		}
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	s.deleteFeedConfigLocked(feedName)
	return nil
}

func (s *adminFlowStoreStub) deleteFeedConfigLocked(feedName string) {
	delete(s.feedConfigs, config.NormalizeFeedName(feedName))
}

func (s *adminFlowStoreStub) ListFeedConfigs(context.Context) ([]db.FeedConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listFeedConfigs++
	out := make([]db.FeedConfig, 0, len(s.feedConfigs))
	for _, cfg := range s.feedConfigs {
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FeedName < out[j].FeedName })
	return out, nil
}

func expectedAdminFlowFeedConfigUpdatedAt(cfg *db.FeedConfig) (time.Time, bool) {
	if cfg == nil {
		return time.Time{}, false
	}
	if cfg.ExpectedUpdatedAt != nil {
		return *cfg.ExpectedUpdatedAt, true
	}
	if !cfg.UpdatedAt.IsZero() {
		return cfg.UpdatedAt, true
	}
	return time.Time{}, false
}

func (s *adminFlowStoreStub) checkFeedConfigRevisionLocked(feedName string, expected time.Time) error {
	current, found := s.feedConfigs[config.NormalizeFeedName(feedName)]
	if expected.IsZero() {
		if found {
			return db.ErrConflict
		}
		return nil
	}
	if !found || !current.UpdatedAt.Equal(expected.UTC()) {
		return db.ErrConflict
	}
	return nil
}

func (s *adminFlowStoreStub) GetSystemSettings(context.Context) (*db.SystemSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.systemSettings == nil {
		return nil, nil
	}
	copyValue := *s.systemSettings
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertSystemSettings(_ context.Context, settings *db.SystemSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *settings
	copyValue.UpdatedAt = time.Now().UTC()
	s.systemSettings = &copyValue
	return nil
}

func (s *adminFlowStoreStub) UpsertSystemSettingsWithAudit(_ context.Context, settings *db.SystemSettings, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected, ok := expectedAdminFlowSystemSettingsUpdatedAt(settings); ok {
		if s.systemSettings == nil {
			if !expected.IsZero() {
				return db.ErrConflict
			}
		} else if expected.IsZero() || !s.systemSettings.UpdatedAt.Equal(expected.UTC()) {
			return db.ErrConflict
		}
	}
	copyValue := *settings
	copyValue.UpdatedAt = time.Now().UTC()
	copyValue.ExpectedUpdatedAt = nil
	s.systemSettings = &copyValue
	return s.insertAdminAuditLogLocked(audit)
}

func expectedAdminFlowSystemSettingsUpdatedAt(settings *db.SystemSettings) (time.Time, bool) {
	if settings == nil {
		return time.Time{}, false
	}
	if settings.ExpectedUpdatedAt != nil {
		return *settings.ExpectedUpdatedAt, true
	}
	if !settings.UpdatedAt.IsZero() {
		return settings.UpdatedAt, true
	}
	return time.Time{}, false
}

func (s *adminFlowStoreStub) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dashboardStatsCalls++
	copyValue := *s.dashboard
	copyValue.BySeverity = map[string]int{}
	for severity, count := range s.dashboard.BySeverity {
		copyValue.BySeverity[severity] = count
	}
	return &copyValue, nil
}

func (s *adminFlowStoreStub) CountUnknownSeverityFindings(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unknownSeverityCalls++
	return s.unknownSeverityCount, nil
}

func (s *adminFlowStoreStub) CountScansByDay(context.Context, int) ([]db.DailyScanStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]db.DailyScanStats(nil), s.dailyScans...), nil
}

func (s *adminFlowStoreStub) ListRecentScans(_ context.Context, limit, offset int) ([]db.ScanLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scans := append([]db.ScanLogEntry(nil), s.recentScans...)
	if offset > 0 {
		if offset >= len(scans) {
			return []db.ScanLogEntry{}, nil
		}
		scans = scans[offset:]
	}
	if limit > 0 && len(scans) > limit {
		scans = scans[:limit]
	}
	return scans, nil
}

func (s *adminFlowStoreStub) UpsertManualAdvisory(_ context.Context, advisory *db.ManualAdvisory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *advisory
	s.manual[copyValue.ID] = copyValue
	return nil
}

func (s *adminFlowStoreStub) UpsertManualAdvisoryWithAudit(_ context.Context, advisory *db.ManualAdvisory, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.manual[advisory.ID]; ok && !advisory.UpdatedAt.IsZero() && !current.UpdatedAt.Equal(advisory.UpdatedAt) {
		return db.ErrConflict
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	copyValue := *advisory
	copyValue.UpdatedAt = time.Now().UTC()
	s.manual[copyValue.ID] = copyValue
	return nil
}

func (s *adminFlowStoreStub) DeleteManualAdvisory(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.manual[id]; !ok {
		return fmt.Errorf("manual advisory %s not found", id)
	}
	delete(s.manual, id)
	return nil
}

func (s *adminFlowStoreStub) DeleteManualAdvisoryWithAudit(_ context.Context, id string, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	if _, ok := s.manual[id]; !ok {
		return fmt.Errorf("manual advisory %s not found", id)
	}
	delete(s.manual, id)
	return nil
}

func (s *adminFlowStoreStub) ListManualAdvisories(context.Context, int) ([]db.ManualAdvisory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.ManualAdvisory, 0, len(s.manual))
	for _, advisory := range s.manual {
		out = append(out, advisory)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *adminFlowStoreStub) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := &db.QueueStatsResult{}
	for _, job := range s.queueJobs {
		switch job.Status {
		case "pending":
			stats.Pending++
		case "processing":
			stats.Processing++
		case "paused":
			stats.Paused++
		case "done":
			stats.Done++
		case "error":
			stats.Error++
		}
	}
	return stats, nil
}

func (s *adminFlowStoreStub) ListQueueJobs(_ context.Context, status string, limit int) ([]db.RefreshJob, error) {
	return s.ListQueueJobsPage(context.Background(), status, limit, 0)
}

func (s *adminFlowStoreStub) ListQueueJobsPage(_ context.Context, status string, limit, offset int) ([]db.RefreshJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.RefreshJob, 0, len(s.queueJobs))
	if offset < 0 {
		offset = 0
	}
	for i, skipped := len(s.queueJobs)-1, 0; i >= 0; i-- {
		job := s.queueJobs[i]
		if status != "" && job.Status != status {
			continue
		}
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, job)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *adminFlowStoreStub) PurgeQueue(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.purgeQueueLocked(), nil
}

func (s *adminFlowStoreStub) PurgeQueueWithAudit(_ context.Context, audit *db.AdminAuditEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	purged := s.countQueueStatusesLocked(map[string]struct{}{"done": {}, "error": {}})
	if err := db.SetAdminAuditDetail(audit, "purged", strconv.Itoa(purged)); err != nil {
		return 0, err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return 0, err
	}
	return s.purgeQueueLocked(), nil
}

func (s *adminFlowStoreStub) purgeQueueLocked() int {
	purged := 0
	kept := s.queueJobs[:0]
	for _, job := range s.queueJobs {
		if job.Status == "done" || job.Status == "error" {
			purged++
			continue
		}
		kept = append(kept, job)
	}
	s.queueJobs = kept
	return purged
}

func (s *adminFlowStoreStub) UpdateQueueJobPriority(_ context.Context, jobID, priority int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateQueueJobPriorityLocked(jobID, priority)
}

func (s *adminFlowStoreStub) UpdateQueueJobPriorityWithAudit(_ context.Context, jobID, priority int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	s.queueJobs[index].Priority = priority
	return nil
}

func (s *adminFlowStoreStub) updateQueueJobPriorityLocked(jobID, priority int) error {
	for i := range s.queueJobs {
		if s.queueJobs[i].ID == jobID {
			s.queueJobs[i].Priority = priority
			return nil
		}
	}
	return nil
}

func (s *adminFlowStoreStub) PauseQueueJob(ctx context.Context, jobID int) error {
	return s.setQueueStatus(ctx, jobID, "paused")
}

func (s *adminFlowStoreStub) PauseQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	s.queueJobs[index].Status = "paused"
	s.queueJobs[index].Error = ""
	return nil
}

func (s *adminFlowStoreStub) ResumeQueueJob(ctx context.Context, jobID int) error {
	return s.setQueueStatus(ctx, jobID, "pending")
}

func (s *adminFlowStoreStub) ResumeQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	s.queueJobs[index].Status = "pending"
	s.queueJobs[index].Error = ""
	return nil
}

func (s *adminFlowStoreStub) RetryQueueJob(ctx context.Context, jobID int) error {
	return s.setQueueStatus(ctx, jobID, "pending")
}

func (s *adminFlowStoreStub) RetryQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	s.queueJobs[index].Status = "pending"
	s.queueJobs[index].Error = ""
	return nil
}

func (s *adminFlowStoreStub) setQueueStatus(_ context.Context, jobID int, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.queueJobs {
		if s.queueJobs[i].ID == jobID {
			s.queueJobs[i].Status = status
			s.queueJobs[i].Error = ""
			return nil
		}
	}
	return nil
}

func (s *adminFlowStoreStub) ClearQueue(_ context.Context, statuses []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clearQueueLocked(statuses), nil
}

func (s *adminFlowStoreStub) ClearQueueWithAudit(_ context.Context, statuses []string, audit *db.AdminAuditEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed := queueStatusSet(statuses)
	cleared := s.countQueueStatusesLocked(allowed)
	if err := db.SetAdminAuditDetail(audit, "cleared", strconv.Itoa(cleared)); err != nil {
		return 0, err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return 0, err
	}
	return s.clearQueueWithAllowedLocked(allowed), nil
}

func (s *adminFlowStoreStub) clearQueueLocked(statuses []string) int {
	return s.clearQueueWithAllowedLocked(queueStatusSet(statuses))
}

func queueStatusSet(statuses []string) map[string]struct{} {
	allowed := map[string]struct{}{}
	for _, status := range statuses {
		allowed[status] = struct{}{}
	}
	return allowed
}

func (s *adminFlowStoreStub) clearQueueWithAllowedLocked(allowed map[string]struct{}) int {
	cleared := 0
	kept := s.queueJobs[:0]
	for _, job := range s.queueJobs {
		if _, ok := allowed[job.Status]; ok {
			cleared++
			continue
		}
		kept = append(kept, job)
	}
	s.queueJobs = kept
	return cleared
}

func (s *adminFlowStoreStub) countQueueStatusesLocked(allowed map[string]struct{}) int {
	count := 0
	for _, job := range s.queueJobs {
		if _, ok := allowed[job.Status]; ok {
			count++
		}
	}
	return count
}

func (s *adminFlowStoreStub) queueJobIndexLocked(jobID int) (int, error) {
	for i := range s.queueJobs {
		if s.queueJobs[i].ID == jobID {
			return i, nil
		}
	}
	return -1, fmt.Errorf("queue job %d not found", jobID)
}

func (s *adminFlowStoreStub) addQueueJob(status string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextJobID++
	s.queueJobs = append(s.queueJobs, db.RefreshJob{
		ID:          s.nextJobID,
		Ecosystem:   "npm",
		Name:        "left-pad",
		Source:      "socket",
		Priority:    db.RefreshPriorityNormal,
		Status:      status,
		RequestedAt: time.Now().UTC(),
	})
	return s.nextJobID
}

func newAdminFlowHandler(t *testing.T, store *adminFlowStoreStub, cfg *config.Config, syncFeed ...FeedSyncFunc) (*AdminHandler, *auth.SessionManager, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime := config.NewRuntimeSettingsFromConfig(cfg)
	var syncFn FeedSyncFunc
	if len(syncFeed) > 0 {
		syncFn = syncFeed[0]
	}
	handler := NewAdminHandler(ctx, store, sm, web.NewRendererWithLayoutLinks(web.TemplateFS(), false, web.LayoutLinks{}), logger, cfg, runtime, syncFn)
	handler.SetFeedConfigApplyFunc(func(context.Context, config.FeedSettings) error {
		return nil
	})
	handler.SetFeedConfigResetFunc(func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
		feed, ok := cfg.FeedSettings(feedName)
		return feed, ok, nil
	})
	return handler, sm, cancel
}

func adminFlowConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
		},
		DB:      config.DBConfig{Host: "db.internal", Name: "packmon", SSLMode: "disable"},
		Metrics: config.MetricsConfig{Host: "127.0.0.1", Port: 9090},
		Admin:   config.AdminConfig{SessionTimeout: time.Hour},
		Retention: config.RetentionConfig{
			ScanLog:       30 * 24 * time.Hour,
			AdminAuditLog: 30 * 24 * time.Hour,
		},
		FeedSync: config.FeedSyncConfig{
			Interval:  time.Hour,
			OnStartup: true,
		},
		// #nosec G101 -- this test fixture uses fake feed credentials.
		Feeds: config.FeedsConfig{
			OSVEnabled:           true,
			OSVMode:              config.FeedModeSelf,
			GHSAEnabled:          true,
			GHSAMode:             config.FeedModeSelf,
			OpenSSFEnabled:       true,
			OpenSSFMode:          config.FeedModeSelf,
			VulnCheckEnabled:     true,
			VulnCheckMode:        config.FeedModeExternal,
			VulnCheckAPIKey:      "runtime-vc-key",
			SocketEnabled:        false,
			SocketMode:           config.FeedModeSelf,
			ReversingLabsEnabled: false,
			ReversingLabsMode:    config.FeedModeSelf,
			CISAKEVEnabled:       true,
			CISAKEVMode:          config.FeedModeSelf,
			EPSSEnabled:          true,
			EPSSMode:             config.FeedModeSelf,
			NVDEnabled:           true,
			NVDMode:              config.FeedModeSelf,
		},
	}
}

func authenticatedAdminRequest(t *testing.T, sm *auth.SessionManager, method, target string) (*http.Request, *auth.Session) {
	t.Helper()

	rec := httptest.NewRecorder()
	sess, err := sm.CreateAdmin(rec, false)
	if err != nil {
		t.Fatalf("CreateAdmin session: %v", err)
	}

	req := httptest.NewRequest(method, target, nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req, sess
}

func authenticatedAdminFormRequest(t *testing.T, sm *auth.SessionManager, target string, values url.Values) (*http.Request, *auth.Session) {
	t.Helper()

	rec := httptest.NewRecorder()
	sess, err := sm.CreateAdmin(rec, false)
	if err != nil {
		t.Fatalf("CreateAdmin session: %v", err)
	}
	token, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}
	values.Set(auth.CSRFFieldName, token)

	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req, sess
}

func loginAdminFormRequest(t *testing.T, handler *AdminHandler, sm *auth.SessionManager, password, target string, values url.Values) (*http.Request, *auth.Session) {
	t.Helper()

	preAuthRec := httptest.NewRecorder()
	preAuthSess, err := sm.CreatePreAuth(preAuthRec)
	if err != nil {
		t.Fatalf("CreatePreAuth: %v", err)
	}
	csrfToken, err := auth.CSRFToken(preAuthSess)
	if err != nil {
		t.Fatalf("pre-auth CSRFToken: %v", err)
	}

	loginForm := url.Values{
		"username":         {"admin"},
		"password":         {password},
		auth.CSRFFieldName: {csrfToken},
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.RemoteAddr = "127.0.0.1:12345"
	for _, cookie := range preAuthRec.Result().Cookies() {
		loginReq.AddCookie(cookie)
	}
	loginRec := httptest.NewRecorder()
	handler.HandleLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusSeeOther || loginRec.Header().Get("Location") != "/admin/" {
		t.Fatalf("login status/location = %d %q, want 303 /admin/", loginRec.Code, loginRec.Header().Get("Location"))
	}

	var sessionCookie *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == auth.SessionCookieName && cookie.Value != "" {
			copyCookie := *cookie
			sessionCookie = &copyCookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("login did not set authenticated session cookie")
	}

	lookupReq := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	lookupReq.AddCookie(sessionCookie)
	sess := sm.Get(lookupReq)
	if sess == nil || !sess.Admin {
		t.Fatalf("login session = %+v, want admin session", sess)
	}

	token, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}
	values.Set(auth.CSRFFieldName, token)
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	return req, sess
}

func TestAdminPagesRenderWithAuthenticatedSession(t *testing.T) {
	store := newAdminStoreStub()
	now := time.Now().UTC()
	duration := 2 * time.Second
	if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{
		FeedName:         "osv",
		LastSyncAt:       &now,
		LastSyncDuration: &duration,
		LastSyncStatus:   "success",
		EntriesSynced:    3,
		EntriesTotal:     4,
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}
	store.dashboard = &db.DashboardStatsResult{
		TotalPackages:        2,
		TotalVulnerabilities: 1,
		TotalMalicious:       1,
		TotalSupplyChainRisk: 2,
		TotalLifecycle:       3,
		BySeverity:           map[string]int{"HIGH": 1, "UNKNOWN": 2},
	}
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false, CreatedAt: now}
	store.addQueueJob("pending")
	store.audit = append(store.audit, db.AdminAuditLogEntry{ID: 1, Action: "login_success", Details: []byte(`{"ip":"127.0.0.1"}`), CreatedAt: now})
	store.manual["manual:existing"] = db.ManualAdvisory{ID: "manual:existing", FindingType: "vulnerability", Ecosystem: "npm", Name: "left-pad", Severity: "HIGH", Summary: "manual"}

	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	for _, tt := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
		want   string
	}{
		{name: "dashboard", target: "/admin/", call: handler.HandleDashboard, want: "Dashboard"},
		{name: "feeds", target: "/admin/feeds", call: handler.HandleAdminFeeds, want: "OSV"},
		{name: "queue", target: "/admin/queue", call: handler.HandleAdminQueue, want: "left-pad"},
		{name: "keys", target: "/admin/keys", call: handler.HandleAdminKeys, want: "API Keys"},
		{name: "advisories", target: "/admin/advisories", call: handler.HandleAdminAdvisories, want: "manual:existing"},
		{name: "audit", target: "/admin/audit", call: handler.HandleAdminAudit, want: "login_success"},
		{name: "settings", target: "/admin/settings", call: handler.HandleAdminSettings, want: "development"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, tt.target)
			rec := httptest.NewRecorder()
			tt.call(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200; body=%s", tt.target, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.want) {
				t.Fatalf("%s body missing %q\nbody=%s", tt.target, tt.want, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range []string{
				`<nav aria-label="Admin" class="flex flex-wrap gap-2 text-sm">`,
				`href="/admin/advisories"`,
				`href="/admin/settings"`,
				`aria-current="page"`,
				`class="shrink-0 inline-flex min-h-8 items-center rounded-md border px-3 py-1.5 pm-focus-ring`,
			} {
				if !strings.Contains(body, want) {
					t.Fatalf("%s body missing responsive admin nav marker %q\nbody=%s", tt.target, want, body)
				}
			}
			if strings.Contains(body, `class="flex space-x-6 text-sm"`) {
				t.Fatalf("%s body still renders non-wrapping admin nav\nbody=%s", tt.target, body)
			}
			if tt.name == "dashboard" {
				for _, want := range []string{
					`href="/search?finding=malicious"`,
					`href="/search?finding=supply_chain_risk"`,
					`href="/search?finding=lifecycle"`,
					`border-danger`,
				} {
					if !strings.Contains(body, want) {
						t.Fatalf("admin dashboard body missing risk finding marker %q\nbody=%s", want, body)
					}
				}
			}
			if tt.name == "feeds" {
				for _, want := range []string{
					"data-feed-sync-now",
					`data-feed-sync-flash-target="#admin-feed-flash"`,
				} {
					if !strings.Contains(body, want) {
						t.Fatalf("%s body missing externalized htmx sync marker %q\nbody=%s", tt.target, want, body)
					}
				}
			}
			if tt.name == "keys" && !strings.Contains(body, "Maximum 365 days") {
				t.Fatalf("%s body missing API-key expiry duration hint\nbody=%s", tt.target, body)
			}
			if tt.name == "advisories" && !strings.Contains(body, "apply to all versions") {
				t.Fatalf("%s body missing manual vulnerability version-scope warning\nbody=%s", tt.target, body)
			}
			if tt.name == "advisories" && strings.Contains(body, `value="docker"`) {
				t.Fatalf("%s body exposes Docker as manual advisory scan coverage\nbody=%s", tt.target, body)
			}
			if tt.name == "advisories" && strings.Contains(body, `value="chocolatey"`) {
				t.Fatalf("%s body exposes Chocolatey as manual advisory scan coverage\nbody=%s", tt.target, body)
			}
		})
	}
}

func TestAdminAdvisoriesCreateFormIncludesStableManualID(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminAdvisories status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, `name="id" value="manual:`) {
		t.Fatalf("create form missing stable manual advisory ID\nbody=%s", body)
	}
}

func TestAdminAdvisoryCreateFormRendersConstraintCues(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminAdvisories status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	for _, want := range []string{
		`id="adv-ecosystem-help"`,
		`aria-describedby="adv-ecosystem-help"`,
		`id="adv-name-help"`,
		`maxlength="256"`,
		`aria-describedby="adv-name-help"`,
		`id="adv-severity-help"`,
		`aria-describedby="adv-severity-help"`,
		`id="adv-summary-help"`,
		`maxlength="1000"`,
		`aria-describedby="adv-summary-help"`,
		`id="adv-description-help"`,
		`maxlength="8000"`,
		`aria-describedby="adv-description-help"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("manual advisory create form missing constraint cue %q\nbody=%s", want, body)
		}
	}
}

func TestAdminSettingsPasswordFormRendersConfirmationCues(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings")
	rec := httptest.NewRecorder()
	handler.HandleAdminSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminSettings status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	for _, want := range []string{
		`data-password-confirm-form`,
		`id="password-confirm-help"`,
		`aria-describedby="password-length-help password-confirm-help"`,
		`data-password-confirm-source`,
		`data-password-confirm-target`,
		`data-password-mismatch-message="New passwords do not match."`,
		`autocomplete="current-password"`,
		`autocomplete="new-password"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("password form missing confirmation cue %q\nbody=%s", want, body)
		}
	}
}

func TestAdminDashboardUsesRuntimeFeedRowsAndPausedQueue(t *testing.T) {
	store := newAdminStoreStub()
	now := time.Now().UTC()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false, CreatedAt: now}
	store.dashboard = &db.DashboardStatsResult{BySeverity: map[string]int{}}
	store.addQueueJob("paused")
	cfg := adminFlowConfig()
	cfg.Feeds.ReversingLabsEnabled = true
	cfg.Feeds.ReversingLabsAPIKey = "runtime-reversinglabs-key"

	handler, sm, _ := newAdminFlowHandler(t, store, cfg)
	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")
	rec := httptest.NewRecorder()
	handler.HandleDashboard(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200; body=%s", rec.Code, body)
	}
	for _, want := range []string{
		"Queue Summary",
		">Paused</dt>",
		"ReversingLabs",
		"configured",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing runtime-aware marker %q\nbody=%s", want, body)
		}
	}
	for _, notWant := range []string{"Queue Pending", "Queue Paused"} {
		if strings.Contains(body, notWant) {
			t.Fatalf("dashboard body still duplicates queue metric %q in top-level cards\nbody=%s", notWant, body)
		}
	}
	rlRow := adminTableRowContaining(body, "ReversingLabs")
	if strings.Contains(rlRow, ">pending</bdi>") {
		t.Fatalf("dashboard ReversingLabs row status = pending, want configured\nrow=%s", rlRow)
	}
}

func TestAdminDashboardLoadsIndependentWidgetsConcurrently(t *testing.T) {
	base := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	base.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false, CreatedAt: time.Now().UTC()}
	base.dashboard = &db.DashboardStatsResult{BySeverity: map[string]int{}}

	store := &blockingAdminDashboardStore{
		adminFlowStoreStub: base,
		started:            make(chan string, 4),
		release:            make(chan struct{}),
	}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")
	rec := httptest.NewRecorder()
	done := make(chan int, 1)
	go func() {
		handler.HandleDashboard(rec, req)
		done <- rec.Code
	}()

	waitForStartedAdminDashboardReads(t, store.started, []string{"auth", "stats", "feeds", "queue"}, store.release)
	close(store.release)

	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("dashboard status = %d, want %d; body=%s", code, http.StatusOK, rec.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("admin dashboard handler did not finish after releasing concurrent store reads")
	}
}

type blockingAdminDashboardStore struct {
	*adminFlowStoreStub
	started chan string
	release chan struct{}
}

func (s *blockingAdminDashboardStore) GetAdminAuth(ctx context.Context) (*db.AdminAuth, error) {
	s.waitForAdminDashboardRelease(ctx, "auth")
	return s.adminFlowStoreStub.GetAdminAuth(ctx)
}

func (s *blockingAdminDashboardStore) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	s.waitForAdminDashboardRelease(ctx, "stats")
	return s.adminFlowStoreStub.DashboardStats(ctx)
}

func (s *blockingAdminDashboardStore) ListFeedSyncStatuses(ctx context.Context) ([]db.FeedSyncStatus, error) {
	s.waitForAdminDashboardRelease(ctx, "feeds")
	return s.adminFlowStoreStub.ListFeedSyncStatuses(ctx)
}

func (s *blockingAdminDashboardStore) QueueStats(ctx context.Context) (*db.QueueStatsResult, error) {
	s.waitForAdminDashboardRelease(ctx, "queue")
	return s.adminFlowStoreStub.QueueStats(ctx)
}

func (s *blockingAdminDashboardStore) waitForAdminDashboardRelease(ctx context.Context, name string) {
	select {
	case s.started <- name:
	case <-ctx.Done():
		return
	}
	select {
	case <-s.release:
	case <-ctx.Done():
	}
}

func waitForStartedAdminDashboardReads(t *testing.T, started <-chan string, want []string, release chan struct{}) {
	t.Helper()

	seen := make(map[string]bool, len(want))
	timeout := time.After(750 * time.Millisecond)
	for len(seen) < len(want) {
		select {
		case name := <-started:
			seen[name] = true
		case <-timeout:
			close(release)
			t.Fatalf("admin dashboard store reads did not start concurrently; saw %v, want %v", seen, want)
		}
	}
}

func TestAdminFeedsPageUsesDedicatedUnknownSeverityCount(t *testing.T) {
	store := newAdminStoreStub()
	store.unknownSeverityCount = 3
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds")
	rec := httptest.NewRecorder()

	handler.HandleAdminFeeds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("feeds status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.dashboardStatsCalls != 0 {
		t.Fatalf("DashboardStats calls = %d, want 0: the feeds page must not run the full dashboard aggregate for one number", store.dashboardStatsCalls)
	}
	if store.unknownSeverityCalls != 1 {
		t.Fatalf("CountUnknownSeverityFindings calls = %d, want 1", store.unknownSeverityCalls)
	}
}

func TestAdminDashboardStatsAreCachedAcrossRequests(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	for range 2 {
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")
		rec := httptest.NewRecorder()
		handler.HandleDashboard(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("dashboard status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.dashboardStatsCalls != 1 {
		t.Fatalf("DashboardStats calls = %d, want 1: repeated dashboard loads within the TTL must reuse the cached aggregate", store.dashboardStatsCalls)
	}
}

func TestAdminFeedsRuntimePartialSkipsFullPageOnlyQueries(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds?partial=runtime")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	handler.HandleAdminFeeds(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("runtime partial status = %d, want 200; body=%s", rec.Code, body)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.listFeedConfigs != 0 {
		t.Fatalf("ListFeedConfigs calls = %d, want 0 for runtime partial", store.listFeedConfigs)
	}
	if store.dashboardStatsCalls != 0 {
		t.Fatalf("DashboardStats calls = %d, want 0 for runtime partial", store.dashboardStatsCalls)
	}
}

func TestAdminFeedsPartialURLsWithoutHTMXRenderFullPage(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target string
	}{
		{name: "runtime", target: "/admin/feeds?partial=runtime"},
		{name: "flash", target: "/admin/feeds?partial=flash&msg=Saved"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newAdminStoreStub()
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
			req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, tt.target)
			rec := httptest.NewRecorder()

			handler.HandleAdminFeeds(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("admin feeds partial URL status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range []string{"<!DOCTYPE html>", `href="/admin/feeds"`, "Feed Configuration"} {
				if !strings.Contains(body, want) {
					t.Fatalf("admin feeds partial URL full page missing %q:\n%s", want, body)
				}
			}
		})
	}
}

func TestAdminFeedsPartialURLsWithHTMXRenderFragments(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target string
		want   string
	}{
		{name: "runtime", target: "/admin/feeds?partial=runtime", want: "Current Runtime"},
		{name: "flash", target: "/admin/feeds?partial=flash&msg=Saved", want: "Saved"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newAdminStoreStub()
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
			req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, tt.target)
			req.Header.Set("HX-Request", "true")
			rec := httptest.NewRecorder()

			handler.HandleAdminFeeds(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("admin feeds HTMX partial status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, "<!DOCTYPE html>") {
				t.Fatalf("admin feeds HTMX partial rendered full layout:\n%s", body)
			}
			if !strings.Contains(body, tt.want) {
				t.Fatalf("admin feeds HTMX partial missing %q:\n%s", tt.want, body)
			}
		})
	}
}

func TestRegisterRoutesRejectsUnknownAdminSubpaths(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := adminFlowConfig()
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	mux := http.NewServeMux()
	RegisterRoutes(ctx, mux, store, sm, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg, runtime, nil, nil, nil)

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/not-a-real-page")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown admin route status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func adminTableRowContaining(body, needle string) string {
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	start := strings.LastIndex(body[:idx], "<tr")
	end := strings.Index(body[idx:], "</tr>")
	if start < 0 || end < 0 {
		return ""
	}
	return body[start : idx+end+len("</tr>")]
}

func TestAdminKeyLifecycleUsesFlashAndAudit(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, sess := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":             {"ci"},
		"expires_in_days":  {validAPIKeyExpiryFormValue()},
		"current_password": {"current-password"},
	})
	rec := httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyCreate status = %d, want 303", rec.Code)
	}
	if newKey := sm.GetFlash(sess.ID, "newkey"); len(newKey) != 64 {
		t.Fatalf("flash newkey length = %d, want 64 hex chars", len(newKey))
	}

	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0].ExpiresAt == nil {
		t.Fatalf("keys after create = %+v, want one expiring key", keys)
	}
	keyID := strconv.Itoa(keys[0].ID)
	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(after create) error = %v", err)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"key_id":     keyID,
		"name":       "ci",
		"expires_at": keys[0].ExpiresAt.UTC().Format(time.RFC3339),
	})

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/revoke", url.Values{"key_id": {keyID}})
	rec = httptest.NewRecorder()
	handler.HandleKeyRevoke(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyRevoke status = %d, want 303", rec.Code)
	}
	keys, _ = store.ListAPIKeys(context.Background())
	if keys[0].RevokedAt == nil {
		t.Fatal("key RevokedAt = nil after revoke")
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/delete", url.Values{"key_id": {keyID}})
	rec = httptest.NewRecorder()
	handler.HandleKeyDelete(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyDelete status = %d, want 303", rec.Code)
	}
	keys, _ = store.ListAPIKeys(context.Background())
	if len(keys) != 1 || keys[0].DeletedAt == nil || keys[0].Name != "" || keys[0].KeyHash == "" || keys[0].KeyHash == "hash-ci" || keys[0].RevokedAt == nil || keys[0].ExpiresAt == nil {
		t.Fatalf("keys after delete = %+v, want soft-deleted lifecycle metadata retained with label/hash scrubbed", keys)
	}

	audit, err = store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	for _, want := range []string{"api_key_create", "api_key_revoke", "api_key_delete"} {
		if !adminFlowAuditContains(audit, want) {
			t.Fatalf("audit missing %q: %+v", want, audit)
		}
	}
}

func TestAdminKeyCreateValidationPreservesSafeFormValues(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	expiresAt := validAPIKeyExpiryFormValue()
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":             {" ci pipeline "},
		"expires_in_days":  {expiresAt},
		"current_password": {"wrong-password"},
	})
	rec := httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyCreate status = %d, want 303", rec.Code)
	}
	location := rec.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect Location %q: %v", location, err)
	}
	query := parsed.Query()
	if got := query.Get("name"); got != "ci pipeline" {
		t.Fatalf("redirect preserved name = %q, want normalized safe value", got)
	}
	if got := query.Get("expires_in_days"); got != expiresAt {
		t.Fatalf("redirect preserved expires_in_days = %q, want %q", got, expiresAt)
	}
	if strings.Contains(location, "wrong-password") || query.Has("current_password") {
		t.Fatalf("redirect Location leaked current_password: %q", location)
	}

	req, _ = authenticatedAdminRequest(t, sm, http.MethodGet, location)
	rec = httptest.NewRecorder()
	handler.HandleAdminKeys(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminKeys status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="name"`) || !strings.Contains(body, `value="ci pipeline"`) {
		t.Fatalf("admin keys page did not re-render preserved key name\nbody=%s", body)
	}
	if !strings.Contains(body, `name="expires_in_days"`) || !strings.Contains(body, `<option value="`+expiresAt+`" selected>`) {
		t.Fatalf("admin keys page did not re-render preserved expires_in_days selection\nbody=%s", body)
	}
	if strings.Contains(body, "wrong-password") || strings.Contains(body, `value="wrong-password"`) {
		t.Fatalf("admin keys page leaked current_password\nbody=%s", body)
	}
}

func TestHandleKeyRevokeDeleteEnforceGuardsMutateStateAndAudit(t *testing.T) {
	now := time.Date(2026, 6, 27, 9, 30, 0, 0, time.UTC)
	revokedAt := now.Add(time.Hour)

	type mutationCase struct {
		name            string
		target          string
		keyID           string
		auditAction     string
		successLocation string
		call            func(*AdminHandler, http.ResponseWriter, *http.Request)
		seed            func(*adminFlowStoreStub)
		assertUnchanged func(*testing.T, *adminFlowStoreStub)
		assertChanged   func(*testing.T, *adminFlowStoreStub)
		auditDetails    map[string]string
	}

	cases := []mutationCase{
		{
			name:            "revoke",
			target:          "/admin/keys/revoke",
			keyID:           "17",
			auditAction:     "api_key_revoke",
			successLocation: "/admin/keys?msg=Key+revoked",
			call: func(h *AdminHandler, w http.ResponseWriter, r *http.Request) {
				h.HandleKeyRevoke(w, r)
			},
			seed: func(store *adminFlowStoreStub) {
				store.apiKeys = []db.APIKey{{
					ID:        17,
					Name:      "ci-revoke",
					KeyHash:   "hash-revoke",
					CreatedAt: now,
				}}
			},
			assertUnchanged: func(t *testing.T, store *adminFlowStoreStub) {
				t.Helper()
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil {
					t.Fatalf("ListAPIKeys() error = %v", err)
				}
				if len(keys) != 1 || keys[0].ID != 17 || keys[0].Name != "ci-revoke" || keys[0].RevokedAt != nil || keys[0].DeletedAt != nil {
					t.Fatalf("keys after blocked revoke = %+v, want active key unchanged", keys)
				}
			},
			assertChanged: func(t *testing.T, store *adminFlowStoreStub) {
				t.Helper()
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil {
					t.Fatalf("ListAPIKeys() error = %v", err)
				}
				if len(keys) != 1 || keys[0].ID != 17 || keys[0].RevokedAt == nil || keys[0].DeletedAt != nil || keys[0].Name != "ci-revoke" {
					t.Fatalf("keys after revoke = %+v, want revoked key with metadata retained", keys)
				}
			},
			auditDetails: map[string]string{
				"key_id":     "17",
				"name":       "ci-revoke",
				"created_at": now.Format(time.RFC3339),
			},
		},
		{
			name:            "delete",
			target:          "/admin/keys/delete",
			keyID:           "18",
			auditAction:     "api_key_delete",
			successLocation: "/admin/keys?msg=Key+deleted",
			call: func(h *AdminHandler, w http.ResponseWriter, r *http.Request) {
				h.HandleKeyDelete(w, r)
			},
			seed: func(store *adminFlowStoreStub) {
				store.apiKeys = []db.APIKey{{
					ID:        18,
					Name:      "ci-delete",
					KeyHash:   "hash-delete",
					CreatedAt: now,
					RevokedAt: &revokedAt,
				}}
			},
			assertUnchanged: func(t *testing.T, store *adminFlowStoreStub) {
				t.Helper()
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil {
					t.Fatalf("ListAPIKeys() error = %v", err)
				}
				if len(keys) != 1 || keys[0].ID != 18 || keys[0].Name != "ci-delete" || keys[0].KeyHash != "hash-delete" || keys[0].RevokedAt == nil || keys[0].DeletedAt != nil {
					t.Fatalf("keys after blocked delete = %+v, want revoked key unchanged", keys)
				}
			},
			assertChanged: func(t *testing.T, store *adminFlowStoreStub) {
				t.Helper()
				keys, err := store.ListAPIKeys(context.Background())
				if err != nil {
					t.Fatalf("ListAPIKeys() error = %v", err)
				}
				if len(keys) != 1 || keys[0].ID != 18 || keys[0].Name != "" || keys[0].KeyHash == "" || keys[0].KeyHash == "hash-delete" || keys[0].RevokedAt == nil || keys[0].DeletedAt == nil {
					t.Fatalf("keys after delete = %+v, want soft-deleted key with label/hash scrubbed", keys)
				}
			},
			auditDetails: map[string]string{
				"key_id":     "18",
				"name":       "ci-delete",
				"created_at": now.Format(time.RFC3339),
				"revoked_at": revokedAt.Format(time.RFC3339),
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name+"/unauthenticated", func(t *testing.T) {
			store := newAdminStoreStub()
			tt.seed(store)
			handler, _, _ := newAdminFlowHandler(t, store, adminFlowConfig())

			req := httptest.NewRequest(http.MethodPost, tt.target, strings.NewReader(url.Values{"key_id": {tt.keyID}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			tt.call(handler, rec, req)

			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
				t.Fatalf("unauthenticated response = %d %q, want redirect to login", rec.Code, rec.Header().Get("Location"))
			}
			tt.assertUnchanged(t, store)
			audit, err := store.ListAdminAuditLog(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if len(audit) != 0 {
				t.Fatalf("audit after unauthenticated %s = %+v, want none", tt.name, audit)
			}
		})

		t.Run(tt.name+"/bad csrf", func(t *testing.T) {
			store := newAdminStoreStub()
			tt.seed(store)
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
			var logs bytes.Buffer
			handler.logger = slog.New(slog.NewTextHandler(&logs, nil))

			req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, tt.target)
			req.Body = io.NopCloser(strings.NewReader(url.Values{"key_id": {tt.keyID}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			tt.call(handler, rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("bad CSRF response = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.HasPrefix(got, "/admin/keys?") || !strings.Contains(got, "err=") {
				t.Fatalf("bad CSRF Location = %q, want keys error redirect", got)
			}
			tt.assertUnchanged(t, store)
			audit, err := store.ListAdminAuditLog(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if len(audit) != 1 || audit[0].Action != "admin_csrf_rejected" || adminFlowAuditContains(audit, tt.auditAction) {
				t.Fatalf("audit after bad CSRF %s = %+v, want csrf rejection only", tt.name, audit)
			}
			assertAdminAuditDetails(t, audit[0], map[string]string{
				"target_action": tt.auditAction,
				"path":          tt.target,
			})
			logText := logs.String()
			if !strings.Contains(logText, "admin CSRF validation failed") || !strings.Contains(logText, tt.auditAction) {
				t.Fatalf("CSRF warning log = %q, want validation warning with target action %q", logText, tt.auditAction)
			}
		})

		t.Run(tt.name+"/bootstrap password", func(t *testing.T) {
			store := newAdminStoreStub()
			tt.seed(store)
			store.adminAuth = &db.AdminAuth{PasswordHash: "bootstrap-hash", PasswordIsBootstrap: true, CreatedAt: now}
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, url.Values{"key_id": {tt.keyID}})
			rec := httptest.NewRecorder()
			tt.call(handler, rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("bootstrap response status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, "bootstrap+password") {
				t.Fatalf("bootstrap Location = %q, want rotation error", got)
			}
			tt.assertUnchanged(t, store)
			audit, err := store.ListAdminAuditLog(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if len(audit) != 1 || audit[0].Action != "bootstrap_rotation_required" || adminFlowAuditContains(audit, tt.auditAction) {
				t.Fatalf("audit after bootstrap-blocked %s = %+v, want bootstrap warning only", tt.name, audit)
			}
			assertAdminAuditDetails(t, audit[0], map[string]string{"path": tt.target})
		})

		t.Run(tt.name+"/success", func(t *testing.T) {
			store := newAdminStoreStub()
			tt.seed(store)
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, url.Values{"key_id": {tt.keyID}})
			rec := httptest.NewRecorder()
			tt.call(handler, rec, req)

			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != tt.successLocation {
				t.Fatalf("success response = %d %q, want %q", rec.Code, rec.Header().Get("Location"), tt.successLocation)
			}
			tt.assertChanged(t, store)
			audit, err := store.ListAdminAuditLog(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if len(audit) != 1 || audit[0].Action != tt.auditAction {
				t.Fatalf("audit after successful %s = %+v, want %s", tt.name, audit, tt.auditAction)
			}
			assertAdminAuditDetails(t, audit[0], tt.auditDetails)
		})
	}
}

func TestAdminKeyCreateRetryDoesNotMintDuplicateCredential(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	values := url.Values{
		"name":             {"ci-retry"},
		"expires_in_days":  {validAPIKeyExpiryFormValue()},
		"current_password": {"current-password"},
		"create_nonce":     {"retry-nonce"},
	}
	req, sess := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", values)
	sm.SetFlash(sess.ID, "api_key_create_nonce", "retry-nonce")
	cookies := req.Cookies()

	rec := httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/keys?msg=API+key+created" {
		t.Fatalf("first HandleKeyCreate status/location = %d %q, want key-created redirect", rec.Code, rec.Header().Get("Location"))
	}

	retryReq := httptest.NewRequest(http.MethodPost, "/admin/keys/create", strings.NewReader(values.Encode()))
	retryReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		retryReq.AddCookie(cookie)
	}
	retryRec := httptest.NewRecorder()
	handler.HandleKeyCreate(retryRec, retryReq)
	if retryRec.Code != http.StatusSeeOther || retryRec.Header().Get("Location") != "/admin/keys?msg=API+key+created" {
		t.Fatalf("retry HandleKeyCreate status/location = %d %q, want key-created redirect", retryRec.Code, retryRec.Header().Get("Location"))
	}

	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("keys after retried create = %+v, want exactly one key", keys)
	}
	if newKey := sm.GetFlash(sess.ID, "newkey"); len(newKey) != 64 {
		t.Fatalf("newkey flash after retry length = %d, want original key still available", len(newKey))
	}
}

func TestHandleKeyCreateRequiresCurrentPasswordStepUp(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	for _, tt := range []struct {
		name          string
		current       string
		wantAuditRows int
	}{
		{name: "missing current password", current: "", wantAuditRows: 1},
		{name: "wrong current password", current: "wrong-password", wantAuditRows: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			values := url.Values{
				"name":            {"ci"},
				"expires_in_days": {validAPIKeyExpiryFormValue()},
			}
			if tt.current != "" {
				values.Set("current_password", tt.current)
			}
			req, sess := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", values)
			rec := httptest.NewRecorder()
			handler.HandleKeyCreate(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("HandleKeyCreate status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, "Current+password+is+incorrect") {
				t.Fatalf("HandleKeyCreate Location = %q, want current-password error", got)
			}
			if newKey := sm.GetFlash(sess.ID, "newkey"); newKey != "" {
				t.Fatalf("newkey flash = %q, want empty after failed step-up", newKey)
			}
			keys, err := store.ListAPIKeys(context.Background())
			if err != nil {
				t.Fatalf("ListAPIKeys() error = %v", err)
			}
			if len(keys) != 0 {
				t.Fatalf("keys after failed step-up = %+v, want none", keys)
			}
			audit, err := store.ListAdminAuditLog(context.Background(), tt.wantAuditRows)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if len(audit) != tt.wantAuditRows || audit[0].Action != "api_key_create_failed" {
				t.Fatalf("audit after failed step-up = %+v, want latest api_key_create_failed", audit)
			}
			assertAdminAuditDetails(t, audit[0], map[string]string{"reason": "invalid current password"})
		})
	}

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":             {"ci"},
		"expires_in_days":  {validAPIKeyExpiryFormValue()},
		"current_password": {"current-password"},
	})
	rec := httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/keys?msg=API+key+created" {
		t.Fatalf("HandleKeyCreate with step-up status/location = %d %q, want key-created redirect", rec.Code, rec.Header().Get("Location"))
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("keys after successful step-up = %+v, want one key", keys)
	}
}

func TestHandleKeyRevokeDeleteAuditsIncludeKeyIdentity(t *testing.T) {
	store := newAdminStoreStub()
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	lastUsed := now.Add(30 * time.Minute)
	store.apiKeys = []db.APIKey{{
		ID:         17,
		Name:       "ci-pipeline",
		KeyHash:    "hash",
		CreatedAt:  now,
		LastUsedAt: &lastUsed,
	}}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/revoke", url.Values{"key_id": {"17"}})
	rec := httptest.NewRecorder()
	handler.HandleKeyRevoke(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyRevoke status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"key_id":       "17",
		"name":         "ci-pipeline",
		"created_at":   now.Format(time.RFC3339),
		"last_used_at": lastUsed.Format(time.RFC3339),
	})

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/delete", url.Values{"key_id": {"17"}})
	rec = httptest.NewRecorder()
	handler.HandleKeyDelete(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyDelete status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	audit, err = store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"key_id":       "17",
		"name":         "ci-pipeline",
		"created_at":   now.Format(time.RFC3339),
		"last_used_at": lastUsed.Format(time.RFC3339),
	})
}

func TestHandleKeyRevokeNoOpDoesNotAuditSuccess(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/revoke", url.Values{"key_id": {"404"}})
	rec := httptest.NewRecorder()
	handler.HandleKeyRevoke(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyRevoke status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+revoke") {
		t.Fatalf("Location = %q, want revoke failure", got)
	}
	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if adminFlowAuditContains(audit, "api_key_revoke") {
		t.Fatalf("audit contains api_key_revoke after no-op revoke: %+v", audit)
	}
}

func TestBootstrapPasswordBlocksAdminWritesUntilRotated(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: true, CreatedAt: time.Now().UTC()}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{"name": {"ci"}})
	rec := httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyCreate status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "bootstrap+password") {
		t.Fatalf("HandleKeyCreate Location = %q, want bootstrap rotation error", got)
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("keys after blocked create = %+v, want none", keys)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {"current-password"},
		"new_password":     {"new-password-123"},
		"confirm_password": {"new-password-123"},
	})
	rec = httptest.NewRecorder()
	handler.HandlePasswordChange(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandlePasswordChange status = %d, want 303", rec.Code)
	}
	authInfo, err := store.GetAdminAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if authInfo == nil || authInfo.PasswordIsBootstrap {
		t.Fatalf("admin auth after password change = %+v, want bootstrap flag cleared", authInfo)
	}
}

func TestPasswordChangeRejectsConcurrentRotationAfterCurrentPasswordCheck(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	oldHash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword(old) error = %v", err)
	}
	concurrentHash, err := auth.HashPassword("other-new-password")
	if err != nil {
		t.Fatalf("HashPassword(concurrent) error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: oldHash, CreatedAt: time.Now().UTC()}
	store.onGetAdminAuth = func(s *adminFlowStoreStub) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.upsertAdminAuthLocked(concurrentHash, false)
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {"current-password"},
		"new_password":     {"new-password-123"},
		"confirm_password": {"new-password-123"},
	})
	rec := httptest.NewRecorder()
	handler.HandlePasswordChange(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandlePasswordChange status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(strings.ToLower(got), "current+password") {
		t.Fatalf("HandlePasswordChange Location = %q, want stale current-password error", got)
	}
	authInfo, err := store.GetAdminAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if authInfo == nil || !auth.CheckPassword(authInfo.PasswordHash, "other-new-password") {
		t.Fatalf("admin auth after stale password change = %+v, want concurrent password retained", authInfo)
	}
	if auth.CheckPassword(authInfo.PasswordHash, "new-password-123") {
		t.Fatal("stale password change overwrote concurrent password rotation")
	}
	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if adminFlowAuditContains(audit, "password_change") {
		t.Fatalf("audit contains password_change after stale password change: %+v", audit)
	}
}

func TestBootstrapAuthenticatedSessionCannotWriteAfterBootstrapFlagCleared(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("bootstrap-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: true, CreatedAt: time.Now().UTC()}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	writeReq, _ := loginAdminFormRequest(t, handler, sm, "bootstrap-password", "/admin/keys/create", url.Values{
		"name": {"ci-after-rotation"},
	})
	rotatedHash, err := auth.HashPassword("rotated-password")
	if err != nil {
		t.Fatalf("HashPassword(rotated) error = %v", err)
	}
	if err := store.UpsertAdminAuth(context.Background(), rotatedHash, false); err != nil {
		t.Fatalf("UpsertAdminAuth() error = %v", err)
	}

	writeRec := httptest.NewRecorder()
	handler.HandleKeyCreate(writeRec, writeReq)
	if writeRec.Code != http.StatusSeeOther {
		t.Fatalf("old bootstrap session key create status = %d, want 303", writeRec.Code)
	}
	if got := writeRec.Header().Get("Location"); !strings.Contains(got, "bootstrap+password") {
		t.Fatalf("old bootstrap session key create Location = %q, want bootstrap rotation error", got)
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("API keys after old bootstrap-session write = %+v, want none", keys)
	}
}

func TestPasswordChangeInvalidatesPreExistingAdminSessions(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("old-password-123")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false, CreatedAt: time.Now().UTC()}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	rotateReq, _ := loginAdminFormRequest(t, handler, sm, "old-password-123", "/admin/settings/password", url.Values{
		"current_password": {"old-password-123"},
		"new_password":     {"new-password-123"},
		"confirm_password": {"new-password-123"},
	})
	staleReq, _ := loginAdminFormRequest(t, handler, sm, "old-password-123", "/admin/keys/create", url.Values{
		"name": {"stale-session"},
	})

	rotateRec := httptest.NewRecorder()
	handler.HandlePasswordChange(rotateRec, rotateReq)
	if rotateRec.Code != http.StatusSeeOther || rotateRec.Header().Get("Location") != "/admin/settings?msg=Password+changed+successfully" {
		t.Fatalf("password rotation status/location = %d %q", rotateRec.Code, rotateRec.Header().Get("Location"))
	}

	staleRec := httptest.NewRecorder()
	handler.HandleKeyCreate(staleRec, staleReq)
	if staleRec.Code != http.StatusSeeOther {
		t.Fatalf("stale session key create status = %d, want 303", staleRec.Code)
	}
	if got := staleRec.Header().Get("Location"); got != "/admin/login" {
		t.Fatalf("stale session key create Location = %q, want /admin/login", got)
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("API keys after stale-session write = %+v, want none", keys)
	}

	freshReq, _ := loginAdminFormRequest(t, handler, sm, "new-password-123", "/admin/keys/create", url.Values{
		"name":             {"fresh-session"},
		"expires_in_days":  {validAPIKeyExpiryFormValue()},
		"current_password": {"new-password-123"},
	})
	freshRec := httptest.NewRecorder()
	handler.HandleKeyCreate(freshRec, freshReq)
	if freshRec.Code != http.StatusSeeOther {
		t.Fatalf("fresh session key create status = %d, want 303", freshRec.Code)
	}
	if got := freshRec.Header().Get("Location"); got != "/admin/keys?msg=API+key+created" {
		t.Fatalf("fresh session key create Location = %q, want key-created redirect", got)
	}
	keys, err = store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("API keys after fresh-session write = %+v, want one key", keys)
	}
}

func TestPasswordChangeRejectsReusingCurrentPassword(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: true, CreatedAt: time.Now().UTC()}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := loginAdminFormRequest(t, handler, sm, "same-password", "/admin/settings/password", url.Values{
		"current_password": {"same-password"},
		"new_password":     {"same-password"},
		"confirm_password": {"same-password"},
	})
	rec := httptest.NewRecorder()
	handler.HandlePasswordChange(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandlePasswordChange status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "must+differ") {
		t.Fatalf("HandlePasswordChange Location = %q, want password-difference error", got)
	}
	authInfo, err := store.GetAdminAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if authInfo == nil || !authInfo.PasswordIsBootstrap || authInfo.PasswordChangedAt != nil {
		t.Fatalf("admin auth after rejected reuse = %+v, want unchanged bootstrap auth", authInfo)
	}
	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if !adminFlowAuditContains(audit, "password_change_failed") {
		t.Fatalf("audit after rejected reuse missing password_change_failed: %+v", audit)
	}
}

func TestPasswordChangeCurrentPasswordFailuresUseAdminLockout(t *testing.T) {
	store := newAdminStoreStub()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false, CreatedAt: time.Now().UTC()}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	ip := "192.0.2.92"

	for range loginMaxAttempts {
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
			"current_password": {"wrong-password"},
			"new_password":     {"new-password-123"},
			"confirm_password": {"new-password-123"},
		})
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()
		handler.HandlePasswordChange(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("wrong current password status = %d, want 303", rec.Code)
		}
	}

	if !handler.isLockedOut(ip) {
		t.Fatal("password-change reauthentication failures did not enter the admin lockout window")
	}

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {"current-password"},
		"new_password":     {"new-password-123"},
		"confirm_password": {"new-password-123"},
	})
	req.RemoteAddr = ip + ":12345"
	rec := httptest.NewRecorder()
	handler.HandlePasswordChange(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("locked-out password change status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Too+many+failed") {
		t.Fatalf("locked-out password change Location = %q, want lockout error", got)
	}

	authInfo, err := store.GetAdminAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if authInfo == nil || !auth.CheckPassword(authInfo.PasswordHash, "current-password") {
		t.Fatalf("admin auth after locked-out password change = %+v, want unchanged password", authInfo)
	}
	if auth.CheckPassword(authInfo.PasswordHash, "new-password-123") {
		t.Fatal("locked-out password change updated the admin password")
	}
}

func TestAdminFeedConfigSaveResetAndSyncNow(t *testing.T) {
	store := newAdminStoreStub()
	syncCalled := make(chan string, 1)
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig(), func(_ context.Context, feedName string) error {
		syncCalled <- feedName
		return nil
	})

	var applied config.FeedSettings
	handler.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		applied = feed
		return nil
	})
	var resetFeed string
	handler.SetFeedConfigResetFunc(func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
		resetFeed = feedName
		feed, ok := handler.cfg.FeedSettings(feedName)
		return feed, ok, nil
	})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"vulncheck"},
		"enabled":       {"on"},
		"mode":          {"self"},
		"api_key":       {"override-key"},
		"sync_interval": {"45m"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigSave status = %d, want 303", rec.Code)
	}
	if applied.Name != "vulncheck" || !applied.Enabled || applied.Mode != config.FeedModeSelf || applied.APIKey != "override-key" {
		t.Fatalf("applied feed = %+v, want saved vulncheck settings", applied)
	}
	override, err := store.GetFeedConfig(context.Background(), "vulncheck")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override == nil || override.APIKey != "override-key" {
		t.Fatalf("stored override = %+v, want api key override", override)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"vulncheck"}, "confirm_reset": {"on"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigReset status = %d, want 303", rec.Code)
	}
	if resetFeed != "vulncheck" {
		t.Fatalf("reset feed = %q, want vulncheck", resetFeed)
	}
	override, _ = store.GetFeedConfig(context.Background(), "vulncheck")
	if override != nil {
		t.Fatalf("override after reset = %+v, want nil", override)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleFeedSyncNow status = %d, want 200", rec.Code)
	}
	if trigger := rec.Header().Get("HX-Trigger"); !strings.Contains(trigger, "feed-runtime-refresh") {
		t.Fatalf("HX-Trigger = %q, want feed-runtime-refresh", trigger)
	}
	select {
	case got := <-syncCalled:
		if got != "osv" {
			t.Fatalf("sync feed = %q, want osv", got)
		}
	case <-time.After(time.Second):
		t.Fatal("sync callback was not called")
	}
	status, err := store.GetFeedSyncStatus(context.Background(), "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "running" {
		t.Fatalf("feed status = %+v, want running", status)
	}
}

func TestAdminSystemSettingsPasswordAndAdvisoryFlows(t *testing.T) {
	store := newAdminStoreStub()
	currentPassword := "current-password"
	hash, err := auth.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, CreatedAt: time.Now().UTC()}

	cfg := adminFlowConfig()
	handler, sm, _ := newAdminFlowHandler(t, store, cfg)

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":            {"HIGH"},
		"rate_limit_per_minute":      {"120"},
		"rate_limit_burst":           {"25"},
		"scan_log_retention_days":    {"45"},
		"admin_audit_retention_days": {"14"},
	})
	rec := httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleSystemSettingsSave status = %d, want 303", rec.Code)
	}
	settings, err := store.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings == nil || settings.BlockThreshold != "HIGH" || handler.runtime.BlockThreshold() != "HIGH" {
		t.Fatalf("settings = %+v runtime threshold=%q, want HIGH", settings, handler.runtime.BlockThreshold())
	}
	if settings.ScanLogRetention != 45*24*time.Hour || settings.AdminAuditRetention != 14*24*time.Hour {
		t.Fatalf("settings retention = scan %s admin %s, want 1080h/336h", settings.ScanLogRetention, settings.AdminAuditRetention)
	}
	runtimeRetention := handler.runtime.Retention()
	if runtimeRetention.ScanLog != 45*24*time.Hour || runtimeRetention.AdminAuditLog != 14*24*time.Hour {
		t.Fatalf("runtime retention = scan %s admin %s, want 1080h/336h", runtimeRetention.ScanLog, runtimeRetention.AdminAuditLog)
	}

	newPassword := "newpass12345"
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {currentPassword},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	rec = httptest.NewRecorder()
	handler.HandlePasswordChange(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandlePasswordChange status = %d, want 303", rec.Code)
	}
	adminAuth, err := store.GetAdminAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if adminAuth == nil || !auth.CheckPassword(adminAuth.PasswordHash, newPassword) {
		t.Fatal("new admin password was not stored")
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"id":           {"manual:one"},
		"finding_type": {"vulnerability"},
		"ecosystem":    {"npm"},
		"name":         {"left-pad"},
		"severity":     {"HIGH"},
		"summary":      {"manual vulnerability"},
	})
	rec = httptest.NewRecorder()
	handler.HandleAdvisoryCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryCreate status = %d, want 303", rec.Code)
	}
	advisories, err := store.ListManualAdvisories(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(advisories) != 1 || advisories[0].ID != "manual:one" {
		t.Fatalf("advisories = %+v, want manual:one", advisories)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{
		"id":         {"manual:one"},
		"confirm_id": {"manual:one"},
	})
	rec = httptest.NewRecorder()
	handler.HandleAdvisoryDelete(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryDelete status = %d, want 303", rec.Code)
	}
	advisories, _ = store.ListManualAdvisories(context.Background(), 10)
	if len(advisories) != 0 {
		t.Fatalf("advisories after delete = %+v, want empty", advisories)
	}
}

func TestHandleSystemSettingsSaveAuditsBeforeAndAfterValues(t *testing.T) {
	store := newAdminStoreStub()
	updatedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	store.systemSettings = &db.SystemSettings{
		BlockThreshold:      "LOW",
		RateLimitPerMinute:  60,
		RateLimitBurst:      10,
		ScanLogRetention:    30 * 24 * time.Hour,
		AdminAuditRetention: 30 * 24 * time.Hour,
		UpdatedAt:           updatedAt,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":            {"HIGH"},
		"rate_limit_per_minute":      {"120"},
		"rate_limit_burst":           {"25"},
		"scan_log_retention_days":    {"45"},
		"admin_audit_retention_days": {"14"},
		"updated_at":                 {updatedAt.Format(time.RFC3339Nano)},
	})
	rec := httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleSystemSettingsSave status = %d, want 303", rec.Code)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "system_settings_save" {
		t.Fatalf("audit = %+v, want system_settings_save", audit)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"previous_block_threshold":       "LOW",
		"previous_rate_limit_per_minute": "60",
		"previous_rate_limit_burst":      "10",
		"previous_scan_log_retention":    "720h0m0s",
		"previous_admin_audit_retention": "720h0m0s",
		"new_block_threshold":            "HIGH",
		"new_rate_limit_per_minute":      "120",
		"new_rate_limit_burst":           "25",
		"new_scan_log_retention":         "1080h0m0s",
		"new_admin_audit_retention":      "336h0m0s",
	})
}

func TestHandleSystemSettingsSaveRejectsStaleRevisionWithoutApplyingRuntime(t *testing.T) {
	store := newAdminStoreStub()
	formRevision := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Microsecond)
	concurrentRevision := formRevision.Add(time.Minute)
	store.systemSettings = &db.SystemSettings{
		BlockThreshold:     "LOW",
		RateLimitPerMinute: 60,
		RateLimitBurst:     10,
		UpdatedAt:          concurrentRevision,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	beforeThreshold := handler.runtime.BlockThreshold()

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":       {"HIGH"},
		"rate_limit_per_minute": {"120"},
		"rate_limit_burst":      {"25"},
		"updated_at":            {formRevision.Format(time.RFC3339Nano)},
	})
	rec := httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleSystemSettingsSave status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "System+settings+changed+while+you+were+editing") {
		t.Fatalf("Location = %q, want conflict message", got)
	}
	settings, err := store.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings == nil || settings.BlockThreshold != "LOW" || settings.RateLimitPerMinute != 60 || settings.RateLimitBurst != 10 {
		t.Fatalf("settings after stale save = %+v, want concurrent settings preserved", settings)
	}
	if handler.runtime.BlockThreshold() != beforeThreshold {
		t.Fatalf("runtime threshold = %q, want unchanged %q", handler.runtime.BlockThreshold(), beforeThreshold)
	}
	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit entries = %+v, want none on conflict", audit)
	}
}

func TestHandleAdminSettingsIncludesSystemSettingsRevision(t *testing.T) {
	store := newAdminStoreStub()
	updatedAt := time.Date(2026, 6, 27, 12, 45, 0, 654321000, time.UTC)
	store.systemSettings = &db.SystemSettings{
		BlockThreshold:     "HIGH",
		RateLimitPerMinute: 120,
		RateLimitBurst:     25,
		UpdatedAt:          updatedAt,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings")
	rec := httptest.NewRecorder()
	handler.HandleAdminSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminSettings status = %d, want 200", rec.Code)
	}
	want := `name="updated_at" value="` + updatedAt.Format(time.RFC3339Nano) + `"`
	if body := rec.Body.String(); !strings.Contains(body, want) {
		t.Fatalf("settings form missing system revision %q\nbody=%s", want, body)
	}
}

func TestHandleSystemSettingsSaveDoesNotPersistOrApplyWhenAuditFails(t *testing.T) {
	store := failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
	beforeThreshold := handler.runtime.BlockThreshold()

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":       {"HIGH"},
		"rate_limit_per_minute": {"120"},
		"rate_limit_burst":      {"25"},
	})
	rec := httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleSystemSettingsSave status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+record+audit") {
		t.Fatalf("Location = %q, want audit failure", got)
	}
	settings, err := store.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings != nil {
		t.Fatalf("settings = %+v, want no persisted settings when audit fails", settings)
	}
	if handler.runtime.BlockThreshold() != beforeThreshold {
		t.Fatalf("runtime threshold = %q, want unchanged %q", handler.runtime.BlockThreshold(), beforeThreshold)
	}
}

func TestHandleSystemSettingsSaveDoesNotAuditOrApplyWhenPersistFails(t *testing.T) {
	store := newAdminErrorStore()
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
	beforeThreshold := handler.runtime.BlockThreshold()

	store.fail = map[string]error{"UpsertSystemSettings": errors.New("settings down")}
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":       {"HIGH"},
		"rate_limit_per_minute": {"120"},
		"rate_limit_burst":      {"25"},
	})
	rec := httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleSystemSettingsSave status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+save") {
		t.Fatalf("Location = %q, want save failure", got)
	}
	settings, err := store.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings != nil {
		t.Fatalf("settings = %+v, want no persisted settings when save fails", settings)
	}
	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 0 {
		t.Fatalf("audit entries = %+v, want none when save fails", audit)
	}
	if handler.runtime.BlockThreshold() != beforeThreshold {
		t.Fatalf("runtime threshold = %q, want unchanged %q", handler.runtime.BlockThreshold(), beforeThreshold)
	}
}

func TestAdminFeedConfigSavePersistsOptionalNVDAPIKey(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	var applied config.FeedSettings
	handler.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		applied = feed
		return nil
	})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name": {"nvd"},
		"enabled":   {"on"},
		"mode":      {"self"},
		"api_key":   {"nvd-override-key"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigSave status = %d, want 303", rec.Code)
	}
	if applied.Name != "nvd" || applied.APIKey != "nvd-override-key" || applied.RequiresAPIKey {
		t.Fatalf("applied feed = %+v, want optional NVD api key override", applied)
	}
	override, err := store.GetFeedConfig(context.Background(), "nvd")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override == nil || override.APIKey != "nvd-override-key" {
		t.Fatalf("stored override = %+v, want NVD api key override", override)
	}
}

func TestHandleFeedConfigSaveAuditsBeforeAndAfterValues(t *testing.T) {
	store := newAdminStoreStub()
	previousInterval := time.Hour
	store.feedConfigs["osv"] = db.FeedConfig{
		FeedName:     "osv",
		Enabled:      false,
		Mode:         string(config.FeedModeExternal),
		SyncInterval: &previousInterval,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"osv"},
		"enabled":       {"on"},
		"mode":          {"self"},
		"sync_interval": {"2h"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigSave status = %d, want 303", rec.Code)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "feed_config_save" {
		t.Fatalf("audit = %+v, want feed_config_save", audit)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"feed":                   "osv",
		"previous_enabled":       "false",
		"previous_mode":          "external",
		"previous_sync_interval": "1h0m0s",
		"new_enabled":            "true",
		"new_mode":               "self",
		"new_sync_interval":      "2h0m0s",
	})
}

func TestHandleFeedConfigResetAuditsRemovedOverrideDetails(t *testing.T) {
	store := newAdminStoreStub()
	previousInterval := 90 * time.Minute
	store.feedConfigs["vulncheck"] = db.FeedConfig{
		FeedName:     "vulncheck",
		Enabled:      false,
		Mode:         string(config.FeedModeSelf),
		SyncInterval: &previousInterval,
		APIKey:       "reset-secret",
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
		"feed_name":     {"vulncheck"},
		"confirm_reset": {"on"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigReset status = %d, want 303", rec.Code)
	}
	if override, err := store.GetFeedConfig(context.Background(), "vulncheck"); err != nil || override != nil {
		t.Fatalf("GetFeedConfig() = %+v, %v; want nil nil", override, err)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "feed_config_reset" {
		t.Fatalf("audit = %+v, want feed_config_reset", audit)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"feed":                        "vulncheck",
		"previous_enabled":            "false",
		"previous_mode":               "self",
		"previous_sync_interval":      "1h30m0s",
		"previous_api_key_configured": "true",
		"new_enabled":                 "unset",
		"new_mode":                    "unset",
		"new_sync_interval":           "unset",
		"new_api_key_configured":      "unset",
	})
	if strings.Contains(string(audit[0].Details), "reset-secret") {
		t.Fatalf("audit details leaked API key: %s", string(audit[0].Details))
	}
}

func TestHandleAdvisoryCreateDefaultsToVulnerabilityAndAuditsCreate(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"ecosystem": {"npm"},
		"name":      {"left-pad"},
		"severity":  {"MEDIUM"},
		"summary":   {"manual vulnerability"},
	})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryCreate status = %d, want 303", rec.Code)
	}

	advisories, err := store.ListManualAdvisories(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(advisories) != 1 || advisories[0].FindingType != "vulnerability" {
		t.Fatalf("advisories = %+v, want one vulnerability advisory", advisories)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "advisory_create" {
		t.Fatalf("audit = %+v, want advisory_create", audit)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"finding_type": "vulnerability",
		"ecosystem":    "npm",
		"name":         "left-pad",
		"severity":     "MEDIUM",
	})
}

func TestHandleAdvisoryUpdateAuditsUpdateWithBeforeAndAfterDetails(t *testing.T) {
	store := newAdminStoreStub()
	updatedAt := time.Date(2026, 6, 27, 10, 30, 0, 123456000, time.UTC)
	store.manual["manual:existing"] = db.ManualAdvisory{
		ID:          "manual:existing",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "MEDIUM",
		Summary:     "old summary",
		Description: "old details",
		UpdatedAt:   updatedAt,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"id":           {"manual:existing"},
		"finding_type": {"malicious"},
		"ecosystem":    {"pypi"},
		"name":         {"evil-pkg"},
		"severity":     {"CRITICAL"},
		"risk_type":    {"malware"},
		"summary":      {"new summary"},
		"description":  {"new details"},
		"updated_at":   {updatedAt.Format(time.RFC3339Nano)},
	})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryCreate update status = %d, want 303", rec.Code)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "advisory_update" {
		t.Fatalf("audit = %+v, want advisory_update", audit)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"id":                    "manual:existing",
		"previous_finding_type": "vulnerability",
		"previous_ecosystem":    "npm",
		"previous_name":         "left-pad",
		"previous_severity":     "MEDIUM",
		"previous_summary":      "old summary",
		"new_finding_type":      "malicious",
		"new_ecosystem":         "pypi",
		"new_name":              "evil-pkg",
		"new_severity":          "CRITICAL",
		"new_risk_type":         "malware",
		"new_summary":           "new summary",
	})
}

func TestHandleAdminAdvisoriesEditIncludesRevision(t *testing.T) {
	store := newAdminStoreStub()
	updatedAt := time.Date(2026, 6, 27, 11, 15, 0, 987654000, time.UTC)
	store.manual["manual:existing"] = db.ManualAdvisory{
		ID:          "manual:existing",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "MEDIUM",
		Summary:     "old summary",
		UpdatedAt:   updatedAt,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?edit=manual:existing")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminAdvisories edit status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	want := `name="updated_at" value="` + updatedAt.Format(time.RFC3339Nano) + `"`
	if !strings.Contains(body, want) {
		t.Fatalf("edit form missing advisory revision %q\nbody=%s", want, body)
	}
}

func TestHandleAdvisoryUpdateRejectsStaleRevision(t *testing.T) {
	store := newAdminStoreStub()
	formUpdatedAt := time.Date(2026, 6, 27, 10, 30, 0, 0, time.UTC)
	currentUpdatedAt := formUpdatedAt.Add(time.Minute)
	store.manual["manual:existing"] = db.ManualAdvisory{
		ID:          "manual:existing",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "MEDIUM",
		Summary:     "concurrent summary",
		UpdatedAt:   currentUpdatedAt,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"id":           {"manual:existing"},
		"finding_type": {"vulnerability"},
		"ecosystem":    {"npm"},
		"name":         {"left-pad"},
		"severity":     {"HIGH"},
		"summary":      {"stale submit"},
		"updated_at":   {formUpdatedAt.Format(time.RFC3339Nano)},
	})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryCreate stale status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Advisory+changed+while+you+were+editing") {
		t.Fatalf("Location = %q, want stale advisory conflict", got)
	}
	if got := store.manual["manual:existing"].Summary; got != "concurrent summary" {
		t.Fatalf("manual summary = %q, want concurrent summary preserved", got)
	}
	if audit, _ := store.ListAdminAuditLog(context.Background(), 10); len(audit) != 0 {
		t.Fatalf("audit = %+v, want none for stale update", audit)
	}
}

func TestHandleAdvisoryDeleteRequiresConfirmationAndAuditsDeletedDetails(t *testing.T) {
	store := newAdminStoreStub()
	store.manual["manual:delete"] = db.ManualAdvisory{
		ID:          "manual:delete",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "delete me",
		Description: "deleted details",
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{
		"id": {"manual:delete"},
	})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryDelete(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryDelete without confirmation status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Confirm+advisory+ID") {
		t.Fatalf("Location = %q, want confirmation error", got)
	}
	if _, ok := store.manual["manual:delete"]; !ok {
		t.Fatal("advisory was deleted without matching confirmation")
	}
	if audit, _ := store.ListAdminAuditLog(context.Background(), 10); adminFlowAuditContains(audit, "advisory_delete") {
		t.Fatalf("audit = %+v, want no advisory_delete without confirmation", audit)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{
		"id":         {"manual:delete"},
		"confirm_id": {"manual:delete"},
	})
	rec = httptest.NewRecorder()
	handler.HandleAdvisoryDelete(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryDelete confirmed status = %d, want 303", rec.Code)
	}
	if _, ok := store.manual["manual:delete"]; ok {
		t.Fatal("confirmed advisory delete did not remove the advisory")
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "advisory_delete" {
		t.Fatalf("audit = %+v, want advisory_delete", audit)
	}
	assertAdminAuditDetails(t, audit[0], map[string]string{
		"id":           "manual:delete",
		"finding_type": "vulnerability",
		"ecosystem":    "npm",
		"name":         "left-pad",
		"severity":     "HIGH",
		"summary":      "delete me",
		"description":  "deleted details",
	})
}

func TestHandleAdvisoryDeleteUnknownDoesNotAuditSuccess(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{
		"id":         {"manual:missing"},
		"confirm_id": {"manual:missing"},
	})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryDelete(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryDelete unknown status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Advisory+not+found") {
		t.Fatalf("Location = %q, want not-found error", got)
	}
	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if adminFlowAuditContains(audit, "advisory_delete") {
		t.Fatalf("audit = %+v, want no advisory_delete for unknown advisory", audit)
	}
}

func TestHandleAdvisoryCreateDoesNotPersistWhenAuditFails(t *testing.T) {
	store := failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"id":        {"manual:audit-fails"},
		"ecosystem": {"npm"},
		"name":      {"left-pad"},
		"severity":  {"HIGH"},
		"summary":   {"manual vulnerability"},
	})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryCreate status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+record+audit") {
		t.Fatalf("Location = %q, want audit failure", got)
	}

	advisories, err := store.ListManualAdvisories(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(advisories) != 0 {
		t.Fatalf("advisories = %+v, want no persisted advisory when audit fails", advisories)
	}
}

func TestHandleKeyCreateDoesNotPersistWhenAuditFails(t *testing.T) {
	store := failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: false}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, sess := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":             {"ci"},
		"expires_in_days":  {validAPIKeyExpiryFormValue()},
		"current_password": {"current-password"},
	})
	rec := httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyCreate status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+record+audit") {
		t.Fatalf("Location = %q, want audit failure", got)
	}
	if newKey := sm.GetFlash(sess.ID, "newkey"); newKey != "" {
		t.Fatalf("newkey flash = %q, want empty when audit fails", newKey)
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("keys = %+v, want no persisted key when audit fails", keys)
	}
}

func TestHandleKeyRevokeDeleteDoNotMutateWhenAuditFails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	t.Run("revoke", func(t *testing.T) {
		store := failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}
		store.apiKeys = []db.APIKey{{ID: 17, Name: "ci", CreatedAt: now}}
		handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/revoke", url.Values{"key_id": {"17"}})
		rec := httptest.NewRecorder()
		handler.HandleKeyRevoke(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("HandleKeyRevoke status = %d, want 303", rec.Code)
		}
		if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+record+audit") {
			t.Fatalf("Location = %q, want audit failure", got)
		}
		keys, err := store.ListAPIKeys(context.Background())
		if err != nil {
			t.Fatalf("ListAPIKeys() error = %v", err)
		}
		if len(keys) != 1 || keys[0].RevokedAt != nil {
			t.Fatalf("keys after failed revoke audit = %+v, want active key preserved", keys)
		}
	})

	t.Run("delete", func(t *testing.T) {
		store := failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}
		revokedAt := now
		store.apiKeys = []db.APIKey{{ID: 18, Name: "ci-old", CreatedAt: now, RevokedAt: &revokedAt}}
		handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/delete", url.Values{"key_id": {"18"}})
		rec := httptest.NewRecorder()
		handler.HandleKeyDelete(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("HandleKeyDelete status = %d, want 303", rec.Code)
		}
		if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+record+audit") {
			t.Fatalf("Location = %q, want audit failure", got)
		}
		keys, err := store.ListAPIKeys(context.Background())
		if err != nil {
			t.Fatalf("ListAPIKeys() error = %v", err)
		}
		if len(keys) != 1 || keys[0].ID != 18 || keys[0].RevokedAt == nil {
			t.Fatalf("keys after failed delete audit = %+v, want revoked key preserved", keys)
		}
	})
}

func TestHandleQueueActionsDoNotMutateWhenAuditFails(t *testing.T) {
	cases := []struct {
		name       string
		target     string
		values     func(int) url.Values
		call       func(*AdminHandler, http.ResponseWriter, *http.Request)
		status     string
		wantStatus string
		priority   int
		wantJobs   int
	}{
		{
			name:       "purge",
			target:     "/admin/queue/purge",
			values:     func(int) url.Values { return url.Values{} },
			call:       func(h *AdminHandler, w http.ResponseWriter, r *http.Request) { h.HandleQueuePurge(w, r) },
			status:     "done",
			wantStatus: "done",
			priority:   3,
			wantJobs:   1,
		},
		{
			name:       "priority",
			target:     "/admin/queue/priority",
			values:     func(id int) url.Values { return url.Values{"job_id": {strconv.Itoa(id)}, "priority": {"1"}} },
			call:       func(h *AdminHandler, w http.ResponseWriter, r *http.Request) { h.HandleQueuePriorityUpdate(w, r) },
			status:     "pending",
			wantStatus: "pending",
			priority:   3,
			wantJobs:   1,
		},
		{
			name:       "pause",
			target:     "/admin/queue/pause",
			values:     func(id int) url.Values { return url.Values{"job_id": {strconv.Itoa(id)}} },
			call:       func(h *AdminHandler, w http.ResponseWriter, r *http.Request) { h.HandleQueuePause(w, r) },
			status:     "pending",
			wantStatus: "pending",
			priority:   3,
			wantJobs:   1,
		},
		{
			name:       "resume",
			target:     "/admin/queue/resume",
			values:     func(id int) url.Values { return url.Values{"job_id": {strconv.Itoa(id)}} },
			call:       func(h *AdminHandler, w http.ResponseWriter, r *http.Request) { h.HandleQueueResume(w, r) },
			status:     "paused",
			wantStatus: "paused",
			priority:   3,
			wantJobs:   1,
		},
		{
			name:       "retry",
			target:     "/admin/queue/retry",
			values:     func(id int) url.Values { return url.Values{"job_id": {strconv.Itoa(id)}} },
			call:       func(h *AdminHandler, w http.ResponseWriter, r *http.Request) { h.HandleQueueRetry(w, r) },
			status:     "error",
			wantStatus: "error",
			priority:   3,
			wantJobs:   1,
		},
		{
			name:       "clear",
			target:     "/admin/queue/clear",
			values:     func(int) url.Values { return url.Values{"status": {"pending"}} },
			call:       func(h *AdminHandler, w http.ResponseWriter, r *http.Request) { h.HandleQueueClear(w, r) },
			status:     "pending",
			wantStatus: "pending",
			priority:   3,
			wantJobs:   1,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			store := failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}
			jobID := store.addQueueJob(tt.status)
			handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, tt.values(jobID))
			rec := httptest.NewRecorder()
			tt.call(handler, rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("%s status = %d, want 303", tt.target, rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+record+audit") {
				t.Fatalf("Location = %q, want audit failure", got)
			}
			jobs, err := store.ListQueueJobs(context.Background(), "", 10)
			if err != nil {
				t.Fatalf("ListQueueJobs() error = %v", err)
			}
			if len(jobs) != tt.wantJobs {
				t.Fatalf("jobs after failed %s audit = %+v, want %d jobs", tt.name, jobs, tt.wantJobs)
			}
			if tt.wantJobs == 1 && (jobs[0].Status != tt.wantStatus || jobs[0].Priority != tt.priority) {
				t.Fatalf("job after failed %s audit = %+v, want status %q priority %d", tt.name, jobs[0], tt.wantStatus, tt.priority)
			}
		})
	}
}

func TestHandlePasswordChangeDoesNotUpdatePasswordWhenAuditFails(t *testing.T) {
	store := failingAuditStore{adminFlowStoreStub: newAdminStoreStub()}
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: true, CreatedAt: time.Now().UTC()}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {"current-password"},
		"new_password":     {"new-password-123"},
		"confirm_password": {"new-password-123"},
	})
	rec := httptest.NewRecorder()
	handler.HandlePasswordChange(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandlePasswordChange status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+record+audit") {
		t.Fatalf("Location = %q, want audit failure", got)
	}
	authInfo, err := store.GetAdminAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if authInfo == nil || !authInfo.PasswordIsBootstrap || authInfo.PasswordChangedAt != nil {
		t.Fatalf("admin auth after failed password audit = %+v, want bootstrap auth unchanged", authInfo)
	}
	if auth.CheckPassword(authInfo.PasswordHash, "new-password-123") {
		t.Fatal("new password became active even though audit failed")
	}
}

func TestAdminAdvisoryCreateRejectsInventoryOnlyEcosystems(t *testing.T) {
	for _, tt := range []struct {
		ecosystem domain.Ecosystem
		name      string
	}{
		{domain.EcosystemDocker, "alpine"},
		{domain.EcosystemChocolatey, "7zip"},
	} {
		t.Run(string(tt.ecosystem), func(t *testing.T) {
			if !tt.ecosystem.InventoryOnly() {
				t.Fatalf("%q is not inventory-only; update the test", tt.ecosystem)
			}
			store := newAdminStoreStub()
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
				"finding_type": {"vulnerability"},
				"ecosystem":    {string(tt.ecosystem)},
				"name":         {tt.name},
				"severity":     {"HIGH"},
				"summary":      {"inventory-only ecosystems must be rejected"},
			})
			rec := httptest.NewRecorder()
			handler.HandleAdvisoryCreate(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("HandleAdvisoryCreate status = %d, want 400; location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
			}
			if location := rec.Header().Get("Location"); location != "" {
				t.Fatalf("validation error redirected to %q", location)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "inventory-only and cannot be used") {
				t.Fatalf("body missing inventory-only error:\n%s", body)
			}
			if !strings.Contains(body, "Unsupported: "+string(tt.ecosystem)) {
				t.Fatalf("form does not echo %q as an unsupported ecosystem:\n%s", tt.ecosystem, body)
			}
			advisories, err := store.ListManualAdvisories(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListManualAdvisories() error = %v", err)
			}
			if len(advisories) != 0 {
				t.Fatalf("advisories = %+v, want no %s advisory", advisories, tt.ecosystem)
			}
		})
	}
}

func TestAdminAdvisoriesPaginationRendersReachableHistory(t *testing.T) {
	store := newAdminStoreStub()
	for i := 0; i < 105; i++ {
		id := fmt.Sprintf("manual:%03d", i)
		store.manual[id] = db.ManualAdvisory{
			ID:          id,
			FindingType: "vulnerability",
			Ecosystem:   "npm",
			Name:        fmt.Sprintf("pkg-%03d", i),
			Severity:    "LOW",
			Summary:     "manual advisory",
		}
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first advisory page status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `/admin/advisories?offset=100`) {
		t.Fatalf("first advisory page missing next-page link\nbody=%s", body)
	}

	req, _ = authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?offset=100")
	rec = httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second advisory page status = %d, want 200", rec.Code)
	}
	body = rec.Body.String()
	if !strings.Contains(body, "manual:104") {
		t.Fatalf("second advisory page missing older advisory\nbody=%s", body)
	}
	if !strings.Contains(body, `/admin/advisories?offset=0`) {
		t.Fatalf("second advisory page missing previous-page link\nbody=%s", body)
	}
}

func TestAdminAdvisoriesOutOfRangePageShowsRecoveryState(t *testing.T) {
	store := newAdminStoreStub()
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("manual:%03d", i)
		store.manual[id] = db.ManualAdvisory{
			ID:          id,
			FindingType: "vulnerability",
			Ecosystem:   "npm",
			Name:        fmt.Sprintf("pkg-%03d", i),
			Severity:    "LOW",
			Summary:     "manual advisory",
		}
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?offset=1000")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("out-of-range advisory page status = %d, want 200", rec.Code)
	}
	for _, want := range []string{
		"No manual advisories on this page.",
		"The current page is past the available manual advisories.",
		`href="/admin/advisories?offset=900"`,
		`href="/admin/advisories"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("out-of-range advisory page missing %q\nbody=%s", want, body)
		}
	}
	if strings.Contains(body, "No manual advisories yet.") {
		t.Fatalf("out-of-range advisory page rendered global empty state\nbody=%s", body)
	}
}

func TestAdminAdvisoriesListRevealsFullSummaryAndDescription(t *testing.T) {
	store := newAdminStoreStub()
	longSummary := "Manual coverage summary with enough detail to exceed the compact list preview and preserve the full operator context for review."
	description := "Operator rationale: created during upstream feed lag and should remain visible without entering edit mode."
	store.manual["manual:context"] = db.ManualAdvisory{
		ID:          "manual:context",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     longSummary,
		Description: description,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("advisory page status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<details",
		"Details",
		longSummary,
		description,
		"Manual coverage summary with enough detail",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("advisory page missing %q\nbody=%s", want, body)
		}
	}
}

func TestAdminAdvisoriesPaginationStateIsPreservedInActions(t *testing.T) {
	store := newAdminStoreStub()
	for i := 0; i < 105; i++ {
		id := fmt.Sprintf("manual:%03d", i)
		store.manual[id] = db.ManualAdvisory{
			ID:          id,
			FindingType: "vulnerability",
			Ecosystem:   "npm",
			Name:        fmt.Sprintf("pkg-%03d", i),
			Severity:    "LOW",
			Summary:     "manual advisory",
		}
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?offset=100")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second advisory page status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`name="return_offset" value="100"`,
		`href="/admin/advisories?edit=manual%3a100&amp;offset=100"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("second advisory page missing %q\nbody=%s", want, body)
		}
	}

	req, _ = authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?edit=manual:100&offset=100")
	rec = httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("edit advisory page status = %d, want 200", rec.Code)
	}
	body = rec.Body.String()
	if !strings.Contains(body, `href="/admin/advisories?offset=100"`) {
		t.Fatalf("edit advisory page missing offset-preserving cancel link\nbody=%s", body)
	}
}

func TestAdminAdvisoryMutationsPreserveReturnOffset(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"id":            {"manual:offset-create"},
		"finding_type":  {"vulnerability"},
		"ecosystem":     {"npm"},
		"name":          {"left-pad"},
		"severity":      {"HIGH"},
		"summary":       {"manual vulnerability"},
		"return_offset": {"100"},
	})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryCreate status = %d, want 303", rec.Code)
	}
	assertAdminAdvisoryRedirectQuery(t, rec.Header().Get("Location"), map[string]string{
		"msg":    "Advisory created",
		"offset": "100",
	})

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{
		"id":            {"manual:offset-create"},
		"confirm_id":    {"manual:offset-create"},
		"return_offset": {"100"},
	})
	rec = httptest.NewRecorder()
	handler.HandleAdvisoryDelete(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryDelete status = %d, want 303", rec.Code)
	}
	assertAdminAdvisoryRedirectQuery(t, rec.Header().Get("Location"), map[string]string{
		"msg":    "Advisory deleted",
		"offset": "100",
	})
}

func TestAdminAdvisoriesMissingEditShowsNotFoundError(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?edit=manual:missing")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("missing edit advisory status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Manual advisory not found", "Create Manual Advisory"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing edit advisory page missing %q\nbody=%s", want, body)
		}
	}
}

func assertAdminAdvisoryRedirectQuery(t *testing.T, location string, want map[string]string) {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("redirect location %q is not a URL: %v", location, err)
	}
	if parsed.Path != "/admin/advisories" {
		t.Fatalf("redirect path = %q, want /admin/advisories", parsed.Path)
	}
	query := parsed.Query()
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Fatalf("redirect query %s = %q, want %q in %q", key, got, value, location)
		}
	}
}

func TestAdminScansRouteRendersScanHistory(t *testing.T) {
	store := newAdminStoreStub()
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	store.dailyScans = []db.DailyScanStats{{Date: now, ScanCount: 2, FindingsCount: 5}}
	store.recentScans = []db.ScanLogEntry{{
		ScanID:        "scan-admin-history",
		ScannedAt:     now,
		PackagesCount: 12,
		FindingsCount: 5,
		DurationMs:    123,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := adminFlowConfig()
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	mux := http.NewServeMux()
	RegisterRoutes(ctx, mux, store, sm, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg, runtime, nil, nil, nil)

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/scans")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("/admin/scans status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"Scans", "scan-admin-history", "Recent Scans", "Scan Activity"} {
		if !strings.Contains(body, want) {
			t.Fatalf("/admin/scans missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `href="/scans"`) {
		t.Fatalf("/admin/scans should not link the unprotected /scans route:\n%s", body)
	}
}

func TestAdminNotFoundRendersStyledFallback(t *testing.T) {
	store := newAdminStoreStub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := adminFlowConfig()
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	mux := http.NewServeMux()
	RegisterRoutes(ctx, mux, store, sm, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg, runtime, nil, nil, nil)

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/missing-page")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/admin/missing-page status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("/admin/missing-page Content-Type = %q, want text/html", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("/admin/missing-page Cache-Control = %q, want no-store", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Page not found",
		`href="/admin/"`,
		`href="/search"`,
		`id="main-content"`,
		`href="/admin/" aria-current="page"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/admin/missing-page body missing %q:\n%s", want, body)
		}
	}
}

func TestAdminNotFoundKeepsMethodSpecificHandling(t *testing.T) {
	store := newAdminStoreStub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := adminFlowConfig()
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	mux := http.NewServeMux()
	RegisterRoutes(ctx, mux, store, sm, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg, runtime, nil, nil, nil)

	req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/missing-page")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /admin/missing-page status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Page not found") {
		t.Fatalf("POST /admin/missing-page rendered admin not-found fallback:\n%s", rec.Body.String())
	}
}

func TestAdminQueueActions(t *testing.T) {
	store := newAdminStoreStub()
	doneJob := store.addQueueJob("done")
	pendingJob := store.addQueueJob("pending")
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/queue/purge", url.Values{})
	rec := httptest.NewRecorder()
	handler.HandleQueuePurge(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleQueuePurge status = %d, want 303", rec.Code)
	}
	if jobs, _ := store.ListQueueJobs(context.Background(), "", 10); len(jobs) != 1 || jobs[0].ID == doneJob {
		t.Fatalf("jobs after purge = %+v, want done job removed", jobs)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/queue/priority", url.Values{
		"job_id":   {strconv.Itoa(pendingJob)},
		"priority": {"1"},
	})
	rec = httptest.NewRecorder()
	handler.HandleQueuePriorityUpdate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleQueuePriorityUpdate status = %d, want 303", rec.Code)
	}
	jobs, _ := store.ListQueueJobs(context.Background(), "", 10)
	if jobs[0].Priority != 1 {
		t.Fatalf("priority after update = %d, want 1", jobs[0].Priority)
	}

	for _, tt := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
		status string
	}{
		{name: "pause", target: "/admin/queue/pause", call: handler.HandleQueuePause, status: "paused"},
		{name: "resume", target: "/admin/queue/resume", call: handler.HandleQueueResume, status: "pending"},
		{name: "retry", target: "/admin/queue/retry", call: handler.HandleQueueRetry, status: "pending"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, url.Values{"job_id": {strconv.Itoa(pendingJob)}})
			rec := httptest.NewRecorder()
			tt.call(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("%s status = %d, want 303", tt.target, rec.Code)
			}
			jobs, _ := store.ListQueueJobs(context.Background(), "", 10)
			if jobs[0].Status != tt.status {
				t.Fatalf("job status = %q, want %q", jobs[0].Status, tt.status)
			}
		})
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/queue/clear", url.Values{"status": {"pending"}})
	rec = httptest.NewRecorder()
	handler.HandleQueueClear(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleQueueClear status = %d, want 303", rec.Code)
	}
	jobs, _ = store.ListQueueJobs(context.Background(), "", 10)
	if len(jobs) != 0 {
		t.Fatalf("jobs after clear = %+v, want empty", jobs)
	}
}

func TestAdminQueuePagePreservesReturnStateInActionForms(t *testing.T) {
	store := newAdminStoreStub()
	for i := 0; i < 55; i++ {
		store.addQueueJob("error")
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/queue?status=error&offset=50")
	rec := httptest.NewRecorder()
	handler.HandleAdminQueue(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminQueue status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`name="return_status" value="error"`,
		`name="return_offset" value="50"`,
		`action="/admin/queue/retry"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("queue page missing %q\nbody=%s", want, body)
		}
	}
}

func TestAdminQueuePageRendersHumanReadableStatusBadges(t *testing.T) {
	store := newAdminStoreStub()
	for _, status := range []string{"pending", "processing", "done", "error", "paused"} {
		store.addQueueJob(status)
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/queue")
	rec := httptest.NewRecorder()
	handler.HandleAdminQueue(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminQueue status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Pending", "Processing", "Done", "Error", "Paused"} {
		if count := strings.Count(body, ">"+want+"</bdi>"); count != 2 {
			t.Fatalf("queue page rendered %q badge count = %d, want 2\nbody=%s", want, count, body)
		}
	}
	for _, raw := range []string{"pending", "processing", "done", "error", "paused"} {
		if strings.Contains(body, ">"+raw+"</bdi>") {
			t.Fatalf("queue page rendered raw lowercase status badge %q\nbody=%s", raw, body)
		}
	}
}

func TestAdminQueueBulkConfirmationsExplainDestructiveConsequences(t *testing.T) {
	store := newAdminStoreStub()
	store.addQueueJob("done")
	store.addQueueJob("error")
	store.addQueueJob("pending")
	store.addQueueJob("paused")
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/queue")
	rec := httptest.NewRecorder()
	handler.HandleAdminQueue(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleAdminQueue status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"This removes completed and errored queue records from the admin queue history.",
		"This removes Pending refresh work from the queue; it will not be processed unless it is recreated.",
		"This removes Paused refresh work from the queue; it will not be processed unless it is recreated.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("queue page missing destructive consequence copy %q\nbody=%s", want, body)
		}
	}
}

func TestAdminQueueMutationsPreserveReturnState(t *testing.T) {
	for _, tt := range []struct {
		name      string
		status    string
		target    string
		form      url.Values
		call      func(*AdminHandler, http.ResponseWriter, *http.Request)
		wantQuery map[string]string
	}{
		{
			name:   "purge",
			status: "done",
			target: "/admin/queue/purge",
			form:   url.Values{},
			call: func(h *AdminHandler, w http.ResponseWriter, r *http.Request) {
				h.HandleQueuePurge(w, r)
			},
			wantQuery: map[string]string{"msg": "Purged 1 completed/errored job.", "status": "error", "offset": "50"},
		},
		{
			name:   "priority",
			status: "pending",
			target: "/admin/queue/priority",
			form:   url.Values{"priority": {"1"}},
			call: func(h *AdminHandler, w http.ResponseWriter, r *http.Request) {
				h.HandleQueuePriorityUpdate(w, r)
			},
			wantQuery: map[string]string{"msg": "Priority updated", "status": "error", "offset": "50"},
		},
		{
			name:   "pause",
			status: "pending",
			target: "/admin/queue/pause",
			form:   url.Values{},
			call: func(h *AdminHandler, w http.ResponseWriter, r *http.Request) {
				h.HandleQueuePause(w, r)
			},
			wantQuery: map[string]string{"msg": "Job paused", "status": "error", "offset": "50"},
		},
		{
			name:   "resume",
			status: "paused",
			target: "/admin/queue/resume",
			form:   url.Values{},
			call: func(h *AdminHandler, w http.ResponseWriter, r *http.Request) {
				h.HandleQueueResume(w, r)
			},
			wantQuery: map[string]string{"msg": "Job resumed", "status": "error", "offset": "50"},
		},
		{
			name:   "retry",
			status: "error",
			target: "/admin/queue/retry",
			form:   url.Values{},
			call: func(h *AdminHandler, w http.ResponseWriter, r *http.Request) {
				h.HandleQueueRetry(w, r)
			},
			wantQuery: map[string]string{"msg": "Job queued for retry", "status": "error", "offset": "50"},
		},
		{
			name:   "clear",
			status: "pending",
			target: "/admin/queue/clear",
			form:   url.Values{"status": {"pending"}},
			call: func(h *AdminHandler, w http.ResponseWriter, r *http.Request) {
				h.HandleQueueClear(w, r)
			},
			wantQuery: map[string]string{"msg": "Cleared 1 queue job.", "status": "error", "offset": "50"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newAdminStoreStub()
			jobID := store.addQueueJob(tt.status)
			handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
			form := cloneURLValues(tt.form)
			if tt.target != "/admin/queue/purge" && tt.target != "/admin/queue/clear" {
				form.Set("job_id", strconv.Itoa(jobID))
			}
			form.Set("return_status", "error")
			form.Set("return_offset", "50")

			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, form)
			rec := httptest.NewRecorder()
			tt.call(handler, rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("%s status = %d, want 303", tt.target, rec.Code)
			}
			assertAdminQueueRedirectQuery(t, rec.Header().Get("Location"), tt.wantQuery)
		})
	}
}

func cloneURLValues(values url.Values) url.Values {
	out := make(url.Values, len(values))
	for key, vals := range values {
		out[key] = append([]string(nil), vals...)
	}
	return out
}

func assertAdminQueueRedirectQuery(t *testing.T, location string, want map[string]string) {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("redirect location %q is not a URL: %v", location, err)
	}
	if parsed.Path != "/admin/queue" {
		t.Fatalf("redirect path = %q, want /admin/queue", parsed.Path)
	}
	query := parsed.Query()
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Fatalf("redirect query %s = %q, want %q in %q", key, got, value, location)
		}
	}
}

func adminFlowAuditContains(entries []db.AdminAuditLogEntry, action string) bool {
	for _, entry := range entries {
		if entry.Action == action {
			return true
		}
	}
	return false
}

// validAPIKeyExpiryFormValue returns a valid value for the create form's
// expires_in_days dropdown (a whole number of days within the allowed lifetime).
func validAPIKeyExpiryFormValue() string {
	return "30"
}

func assertAdminAuditDetails(t *testing.T, entry db.AdminAuditLogEntry, want map[string]string) {
	t.Helper()

	var got map[string]string
	if err := json.Unmarshal(entry.Details, &got); err != nil {
		t.Fatalf("audit details JSON = %q: %v", string(entry.Details), err)
	}
	for key, wantValue := range want {
		if got[key] != wantValue {
			t.Fatalf("audit detail %q = %q, want %q; all details=%v", key, got[key], wantValue, got)
		}
	}
}
