package admin

import (
	"context"
	"encoding/json"
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
	"github.com/8linkz-sec/packmon/internal/web"
)

type adminFlowStoreStub struct {
	db.Store
	mu             sync.Mutex
	adminAuth      *db.AdminAuth
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

	listFeedConfigs     int
	dashboardStatsCalls int
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
	defer s.mu.Unlock()
	if s.adminAuth == nil {
		return nil, nil
	}
	copyValue := *s.adminAuth
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
	copyValue := *cfg
	copyValue.FeedName = config.NormalizeFeedName(cfg.FeedName)
	copyValue.UpdatedAt = time.Now().UTC()
	if cfg.SyncInterval != nil {
		duration := *cfg.SyncInterval
		copyValue.SyncInterval = &duration
	}
	s.feedConfigs[copyValue.FeedName] = copyValue
	return nil
}

func (s *adminFlowStoreStub) DeleteFeedConfig(_ context.Context, feedName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.feedConfigs, config.NormalizeFeedName(feedName))
	return nil
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

func (s *adminFlowStoreStub) UpsertManualAdvisory(_ context.Context, advisory *db.ManualAdvisory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *advisory
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
		Priority:    3,
		Status:      status,
		RequestedAt: time.Now().UTC(),
	})
	return s.nextJobID
}

func newAdminFlowHandler(t *testing.T, store *adminFlowStoreStub, cfg *config.Config, syncFeed ...FeedSyncFunc) (*AdminHandler, *auth.SessionManager, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sm := auth.NewSessionManager(ctx, time.Hour, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	var syncFn FeedSyncFunc
	if len(syncFeed) > 0 {
		syncFn = syncFeed[0]
	}
	handler := NewAdminHandler(ctx, store, sm, web.NewRenderer(web.TemplateFS(), false), logger, cfg, runtime, syncFn)
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
	sess, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create session: %v", err)
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
	sess, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create session: %v", err)
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
		if cookie.Name == auth.SessionCookieName && cookie.Value != "" && cookie.MaxAge > 0 {
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

	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

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
				`class="shrink-0 inline-flex min-h-11 items-center rounded-md px-3 py-2`,
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
					`border-red-200`,
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
			if tt.name == "keys" && !strings.Contains(body, "Use RFC3339 UTC") {
				t.Fatalf("%s body missing API-key expiry timezone hint\nbody=%s", tt.target, body)
			}
			if tt.name == "advisories" && !strings.Contains(body, "apply to all versions") {
				t.Fatalf("%s body missing manual vulnerability version-scope warning\nbody=%s", tt.target, body)
			}
		})
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
		"Queue Paused",
		"ReversingLabs",
		"configured",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard body missing runtime-aware marker %q\nbody=%s", want, body)
		}
	}
	rlRow := adminTableRowContaining(body, "ReversingLabs")
	if strings.Contains(rlRow, ">pending</span>") {
		t.Fatalf("dashboard ReversingLabs row status = pending, want configured\nrow=%s", rlRow)
	}
}

func TestAdminFeedsRuntimePartialSkipsFullPageOnlyQueries(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds?partial=runtime")
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
	sm := auth.NewSessionManager(ctx, time.Hour, false)
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
		"expires_at":       {validAPIKeyExpiryFormValue()},
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
	if len(keys) != 1 || keys[0].DeletedAt == nil || keys[0].Name != "ci" || keys[0].KeyHash == "" || keys[0].RevokedAt == nil || keys[0].ExpiresAt == nil {
		t.Fatalf("keys after delete = %+v, want soft-deleted lifecycle metadata retained", keys)
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
				"name":       {"ci"},
				"expires_at": {validAPIKeyExpiryFormValue()},
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
		"expires_at":       {validAPIKeyExpiryFormValue()},
		"current_password": {"current-password"},
	})
	rec := httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/keys?msg=Key+created" {
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
		"expires_at":       {validAPIKeyExpiryFormValue()},
		"current_password": {"new-password-123"},
	})
	freshRec := httptest.NewRecorder()
	handler.HandleKeyCreate(freshRec, freshReq)
	if freshRec.Code != http.StatusSeeOther {
		t.Fatalf("fresh session key create status = %d, want 303", freshRec.Code)
	}
	if got := freshRec.Header().Get("Location"); got != "/admin/keys?msg=Key+created" {
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
	handler.SetFeedConfigResetFunc(func(_ context.Context, feedName string) error {
		resetFeed = feedName
		return nil
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
		"block_threshold":       {"HIGH"},
		"rate_limit_per_minute": {"120"},
		"rate_limit_burst":      {"25"},
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
	store.systemSettings = &db.SystemSettings{
		BlockThreshold:     "LOW",
		RateLimitPerMinute: 60,
		RateLimitBurst:     10,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

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
		"new_block_threshold":            "HIGH",
		"new_rate_limit_per_minute":      "120",
		"new_rate_limit_burst":           "25",
	})
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
	store.manual["manual:existing"] = db.ManualAdvisory{
		ID:          "manual:existing",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "MEDIUM",
		Summary:     "old summary",
		Description: "old details",
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
		"expires_at":       {validAPIKeyExpiryFormValue()},
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

func adminFlowAuditContains(entries []db.AdminAuditLogEntry, action string) bool {
	for _, entry := range entries {
		if entry.Action == action {
			return true
		}
	}
	return false
}

func validAPIKeyExpiryFormValue() string {
	return time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
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
