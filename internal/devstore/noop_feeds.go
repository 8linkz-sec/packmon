package devstore

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func (*Store) SetCISAKEV(context.Context, []string) (int, error) { return 0, nil }

func (*Store) ClearCISAKEV(context.Context, []string) (int, error) { return 0, nil }

func (*Store) ReplaceCISAKEV(context.Context, []string) (int, int, error) { return 0, 0, nil }

func (*Store) SetEPSSScores(context.Context, []db.EPSSEntry) (int, error) { return 0, nil }

func (*Store) ReplaceEPSSScores(context.Context, []db.EPSSEntry) (int, int, error) {
	return 0, 0, nil
}

func (*Store) EnrichVulnCheck(context.Context, []db.VulnCheckEntry) (int, error) { return 0, nil }

func (s *Store) ImportVulnCheckWithAudit(_ context.Context, _ string, _ []db.VulnCheckEntry, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status != nil {
		if err := s.upsertFeedSyncStatusLocked(status); err != nil {
			return 0, err
		}
	}
	if audit != nil {
		entry := audit(0, 0)
		if err := s.insertAdminAuditLogLocked(&entry); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func (s *Store) ImportCISAKEVWithAudit(_ context.Context, _ string, _ []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status != nil {
		if err := s.upsertFeedSyncStatusLocked(status); err != nil {
			return 0, err
		}
	}
	if audit != nil {
		entry := audit(0, 0)
		if err := s.insertAdminAuditLogLocked(&entry); err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func (s *Store) ReplaceCISAKEVWithAudit(_ context.Context, _ string, _ []string, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status != nil {
		if err := s.upsertFeedSyncStatusLocked(status); err != nil {
			return 0, 0, err
		}
	}
	if audit != nil {
		entry := audit(0, 0)
		if err := s.insertAdminAuditLogLocked(&entry); err != nil {
			return 0, 0, err
		}
	}
	return 0, 0, nil
}

func (s *Store) ImportEPSSWithAudit(_ context.Context, _ string, _ []db.EPSSEntry, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if status != nil {
		if err := s.upsertFeedSyncStatusLocked(status); err != nil {
			return 0, 0, err
		}
	}
	if audit != nil {
		entry := audit(0, 0)
		if err := s.insertAdminAuditLogLocked(&entry); err != nil {
			return 0, 0, err
		}
	}
	return 0, 0, nil
}

func (s *Store) GetFeedSyncStatus(_ context.Context, feedName string) (*db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	status, ok := s.feedStatuses[feedName]
	if !ok {
		return nil, nil
	}
	copyValue := cloneFeedSyncStatus(status)
	return &copyValue, nil
}

func (s *Store) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.upsertFeedSyncStatusLocked(status)
}

func (s *Store) upsertFeedSyncStatusLocked(status *db.FeedSyncStatus) error {
	if status == nil || strings.TrimSpace(status.FeedName) == "" {
		return nil
	}

	copyValue := cloneFeedSyncStatus(*status)
	if copyValue.UpdatedAt.IsZero() {
		copyValue.UpdatedAt = time.Now().UTC()
	}
	s.feedStatuses[copyValue.FeedName] = copyValue
	return nil
}

func (s *Store) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.FeedSyncStatus, 0, len(s.feedStatuses))
	for _, status := range s.feedStatuses {
		out = append(out, cloneFeedSyncStatus(status))
	}

	slices.SortFunc(out, func(a, b db.FeedSyncStatus) int {
		return strings.Compare(a.FeedName, b.FeedName)
	})
	return out, nil
}

func (s *Store) GetFeedConfig(_ context.Context, feedName string) (*db.FeedConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.feedConfigs[strings.ToLower(strings.TrimSpace(feedName))]
	if !ok {
		return nil, nil
	}
	copyValue := item
	if item.SyncInterval != nil {
		duration := *item.SyncInterval
		copyValue.SyncInterval = &duration
	}
	return &copyValue, nil
}

func (s *Store) UpsertFeedConfig(_ context.Context, cfg *db.FeedConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upsertFeedConfigLocked(cfg)
	return nil
}

func (s *Store) UpsertFeedConfigWithAudit(_ context.Context, cfg *db.FeedConfig, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if expected, ok := expectedNoopFeedConfigUpdatedAt(cfg); ok {
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

func (s *Store) upsertFeedConfigLocked(cfg *db.FeedConfig) {
	if cfg == nil || strings.TrimSpace(cfg.FeedName) == "" {
		return
	}

	copyValue := *cfg
	copyValue.FeedName = strings.ToLower(strings.TrimSpace(copyValue.FeedName))
	copyValue.UpdatedAt = time.Now().UTC()
	copyValue.ExpectedUpdatedAt = nil
	if cfg.SyncInterval != nil {
		duration := *cfg.SyncInterval
		copyValue.SyncInterval = &duration
	}
	s.feedConfigs[copyValue.FeedName] = copyValue
}

func (s *Store) DeleteFeedConfig(_ context.Context, feedName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deleteFeedConfigLocked(feedName)
	return nil
}

func (s *Store) DeleteFeedConfigWithAudit(_ context.Context, feedName string, expectedUpdatedAt *time.Time, audit *db.AdminAuditEntry) error {
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

func (s *Store) deleteFeedConfigLocked(feedName string) {
	delete(s.feedConfigs, strings.ToLower(strings.TrimSpace(feedName)))
}

func (s *Store) ListFeedConfigs(context.Context) ([]db.FeedConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.FeedConfig, 0, len(s.feedConfigs))
	for _, item := range s.feedConfigs {
		copyValue := item
		if item.SyncInterval != nil {
			duration := *item.SyncInterval
			copyValue.SyncInterval = &duration
		}
		out = append(out, copyValue)
	}

	slices.SortFunc(out, func(a, b db.FeedConfig) int {
		return strings.Compare(a.FeedName, b.FeedName)
	})
	return out, nil
}

func expectedNoopFeedConfigUpdatedAt(cfg *db.FeedConfig) (time.Time, bool) {
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

func (s *Store) checkFeedConfigRevisionLocked(feedName string, expected time.Time) error {
	current, found := s.feedConfigs[strings.ToLower(strings.TrimSpace(feedName))]
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

func (s *Store) GetSystemSettings(context.Context) (*db.SystemSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.systemConfig == nil {
		return nil, nil
	}
	copyValue := *s.systemConfig
	return &copyValue, nil
}

func (s *Store) UpsertSystemSettings(_ context.Context, settings *db.SystemSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upsertSystemSettingsLocked(settings)
	return nil
}

func (s *Store) UpsertSystemSettingsWithAudit(_ context.Context, settings *db.SystemSettings, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if expected, ok := expectedNoopSystemSettingsUpdatedAt(settings); ok {
		if s.systemConfig == nil {
			if !expected.IsZero() {
				return db.ErrConflict
			}
		} else if expected.IsZero() || !s.systemConfig.UpdatedAt.Equal(expected.UTC()) {
			return db.ErrConflict
		}
	}
	s.upsertSystemSettingsLocked(settings)
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	return nil
}

func (s *Store) upsertSystemSettingsLocked(settings *db.SystemSettings) {
	if settings == nil {
		return
	}
	copyValue := *settings
	copyValue.UpdatedAt = time.Now().UTC()
	copyValue.ExpectedUpdatedAt = nil
	s.systemConfig = &copyValue
}

func expectedNoopSystemSettingsUpdatedAt(settings *db.SystemSettings) (time.Time, bool) {
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
