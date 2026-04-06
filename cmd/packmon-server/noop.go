package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

// noopStore satisfies db.Store using in-memory data structures. It is used
// during development when no PostgreSQL instance is available so that the
// Phase 4 web and admin flows remain usable without external services.
type noopStore struct {
	mu sync.Mutex

	adminAuth    *db.AdminAuth
	apiKeys      []db.APIKey
	auditLog     []db.AdminAuditLogEntry
	feedConfigs  map[string]db.FeedConfig
	feedStatuses map[string]db.FeedSyncStatus
	malicious    map[string]db.MaliciousFinding
	scanLogs     []db.ScanLogEntry
	refreshJobs  []db.RefreshJob
	nextAPIKeyID int
	nextAuditID  int
	nextManualID int
	nextJobID    int
}

var _ db.Store = (*noopStore)(nil)

func newNoopStore() *noopStore {
	return &noopStore{
		feedConfigs:  make(map[string]db.FeedConfig),
		feedStatuses: make(map[string]db.FeedSyncStatus),
		malicious:    make(map[string]db.MaliciousFinding),
	}
}

func (*noopStore) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func (s *noopStore) FindMalicious(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	findings := make([]domain.Finding, 0)
	for _, mf := range s.malicious {
		if mf.Ecosystem != ecosystem || mf.Name != name {
			continue
		}

		// If version is specified and the finding has a versions list, check membership.
		if version != "" && len(mf.Versions) > 0 {
			versionsJSON := string(mf.Versions)
			var versions []string
			if err := json.Unmarshal([]byte(versionsJSON), &versions); err == nil && len(versions) > 0 {
				found := false
				for _, v := range versions {
					if v == version {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
		}

		title := mf.Summary
		if title == "" {
			title = fmt.Sprintf("manual advisory for %s", mf.Name)
		}

		findings = append(findings, domain.Finding{
			Name:       mf.Name,
			Ecosystem:  domain.Ecosystem(mf.Ecosystem),
			Type:       domain.FindingTypeMalicious,
			Severity:   domain.Severity(mf.Severity),
			AdvisoryID: mf.ID,
			Title:      title,
			RiskType:   mf.RiskType,
			Source:     mf.Source,
		})
	}

	return findings, nil
}

func (*noopStore) FindVulnerabilitiesBatch(_ context.Context, _ []db.PackageQuery) ([]domain.Finding, error) {
	return nil, nil
}

func (s *noopStore) FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	var all []domain.Finding
	for _, pkg := range packages {
		findings, err := s.FindMalicious(ctx, pkg.Ecosystem, pkg.Name, pkg.Version)
		if err != nil {
			return nil, err
		}
		all = append(all, findings...)
	}
	return all, nil
}

func (*noopStore) PropagateSeverityViaAliases(context.Context) (int, error)     { return 0, nil }
func (*noopStore) UpsertVulnerability(context.Context, *db.Vulnerability) error { return nil }

func (s *noopStore) UpsertMaliciousFinding(_ context.Context, mf *db.MaliciousFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	copyValue := *mf
	if copyValue.ID == "" {
		s.nextManualID++
		copyValue.ID = fmt.Sprintf("manual-%d", s.nextManualID)
	}
	if copyValue.Source == "" {
		copyValue.Source = "manual"
	}
	s.malicious[copyValue.ID] = copyValue
	return nil
}

func (*noopStore) DeleteVulnerability(context.Context, string) error { return nil }

func (s *noopStore) DeleteMaliciousFinding(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.malicious, id)
	return nil
}

func (s *noopStore) ListMaliciousFindings(_ context.Context, source string, limit int) ([]db.MaliciousFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.MaliciousFinding, 0, len(s.malicious))
	for _, finding := range s.malicious {
		if source != "" && finding.Source != source {
			continue
		}
		out = append(out, finding)
	}

	slices.SortFunc(out, func(a, b db.MaliciousFinding) int {
		if a.ID == b.ID {
			return 0
		}
		if a.ID > b.ID {
			return -1
		}
		return 1
	})

	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}

	return out, nil
}

func (*noopStore) SetCISAKEV(context.Context, []string) (int, error) { return 0, nil }

func (*noopStore) ClearCISAKEV(context.Context, []string) (int, error) { return 0, nil }

func (*noopStore) SetEPSSScores(context.Context, []db.EPSSEntry) (int, error) { return 0, nil }

func (*noopStore) EnrichVulnCheck(context.Context, []db.VulnCheckEntry) (int, error) { return 0, nil }

func (*noopStore) FindUnknownSeverityCVEAliases(context.Context) ([]db.UnknownCVEAlias, error) {
	return nil, nil
}

func (*noopStore) UpdateSeverityByCVE(context.Context, string, string, float64) error { return nil }

func (s *noopStore) GetFeedSyncStatus(_ context.Context, feedName string) (*db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	status, ok := s.feedStatuses[feedName]
	if !ok {
		return nil, nil
	}
	copyValue := status
	return &copyValue, nil
}

func (s *noopStore) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if status == nil || strings.TrimSpace(status.FeedName) == "" {
		return nil
	}

	copyValue := *status
	if copyValue.Metadata != nil {
		copyValue.Metadata = append(json.RawMessage(nil), copyValue.Metadata...)
	}
	s.feedStatuses[copyValue.FeedName] = copyValue
	return nil
}

func (s *noopStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.FeedSyncStatus, 0, len(s.feedStatuses))
	for _, status := range s.feedStatuses {
		out = append(out, status)
	}

	slices.SortFunc(out, func(a, b db.FeedSyncStatus) int {
		return strings.Compare(a.FeedName, b.FeedName)
	})
	return out, nil
}

func (s *noopStore) GetFeedConfig(_ context.Context, feedName string) (*db.FeedConfig, error) {
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

func (s *noopStore) UpsertFeedConfig(_ context.Context, cfg *db.FeedConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cfg == nil || strings.TrimSpace(cfg.FeedName) == "" {
		return nil
	}

	copyValue := *cfg
	copyValue.FeedName = strings.ToLower(strings.TrimSpace(copyValue.FeedName))
	copyValue.UpdatedAt = time.Now().UTC()
	if cfg.SyncInterval != nil {
		duration := *cfg.SyncInterval
		copyValue.SyncInterval = &duration
	}
	s.feedConfigs[copyValue.FeedName] = copyValue
	return nil
}

func (s *noopStore) DeleteFeedConfig(_ context.Context, feedName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.feedConfigs, strings.ToLower(strings.TrimSpace(feedName)))
	return nil
}

func (s *noopStore) ListFeedConfigs(context.Context) ([]db.FeedConfig, error) {
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

func (s *noopStore) ExportSync(_ context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapshot := opts.SnapshotAt.UTC()
	if snapshot.IsZero() {
		snapshot = time.Now().UTC()
	}

	ecosystems := make(map[string]struct{}, len(opts.Ecosystems))
	for _, eco := range opts.Ecosystems {
		ecosystems[strings.TrimSpace(eco)] = struct{}{}
	}

	out := &db.SyncExport{
		SyncedAt:        snapshot,
		Vulnerabilities: []db.SyncVulnerability{},
		Malicious:       make([]db.SyncMalicious, 0, len(s.malicious)),
		Truncated:       false,
	}

	for _, finding := range s.malicious {
		if len(ecosystems) > 0 {
			if _, ok := ecosystems[finding.Ecosystem]; !ok {
				continue
			}
		}

		versions := ""
		if len(finding.Versions) > 0 {
			versions = string(finding.Versions)
		}

		out.Malicious = append(out.Malicious, db.SyncMalicious{
			ID:        finding.ID,
			Ecosystem: finding.Ecosystem,
			Name:      finding.Name,
			Versions:  versions,
			RiskType:  finding.RiskType,
			Severity:  finding.Severity,
			Summary:   finding.Summary,
		})
	}

	slices.SortFunc(out.Malicious, func(a, b db.SyncMalicious) int {
		if a.Ecosystem != b.Ecosystem {
			return strings.Compare(a.Ecosystem, b.Ecosystem)
		}
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.ID, b.ID)
	})

	return out, nil
}

func (s *noopStore) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.refreshJobs {
		existing := &s.refreshJobs[i]
		if existing.Ecosystem == job.Ecosystem && existing.Name == job.Name && existing.Source == job.Source &&
			(existing.Status == "pending" || existing.Status == "processing") {
			if job.Priority < existing.Priority {
				existing.Priority = job.Priority
			}
			return false, s.queuePositionLocked(existing.ID), nil
		}
	}

	s.nextJobID++
	copyValue := *job
	copyValue.ID = s.nextJobID
	copyValue.RequestedAt = time.Now().UTC()
	if copyValue.Status == "" {
		copyValue.Status = "pending"
	}
	s.refreshJobs = append(s.refreshJobs, copyValue)
	return true, s.queuePositionLocked(copyValue.ID), nil
}

func (s *noopStore) DequeueRefresh(_ context.Context, source string) (*db.RefreshJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bestIndex := -1
	for i := range s.refreshJobs {
		job := s.refreshJobs[i]
		if job.Status != "pending" {
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
	s.refreshJobs[bestIndex].Status = "processing"
	s.refreshJobs[bestIndex].ProcessedAt = &now
	job := s.refreshJobs[bestIndex]
	return &job, nil
}

func (s *noopStore) CompleteRefresh(_ context.Context, jobID int, jobErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID != jobID {
			continue
		}
		now := time.Now().UTC()
		s.refreshJobs[i].ProcessedAt = &now
		if jobErr != nil {
			s.refreshJobs[i].Status = "error"
			s.refreshJobs[i].Error = jobErr.Error()
		} else {
			s.refreshJobs[i].Status = "done"
			s.refreshJobs[i].Error = ""
		}
		return nil
	}
	return nil
}

func (s *noopStore) ResetStuckJobs(_ context.Context, source string, stuckThreshold time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	reset := 0
	for i := range s.refreshJobs {
		job := &s.refreshJobs[i]
		if job.Status != "processing" || job.ProcessedAt == nil {
			continue
		}
		if source != "" && job.Source != source {
			continue
		}
		if now.Sub(*job.ProcessedAt) <= stuckThreshold {
			continue
		}
		job.Status = "pending"
		job.ProcessedAt = nil
		job.Error = ""
		reset++
	}
	return reset, nil
}

func (*noopStore) GetPackageCheckStatus(context.Context, string, string, string) (*db.PackageCheckStatus, error) {
	return nil, nil
}

func (*noopStore) UpsertPackageCheckStatus(context.Context, *db.PackageCheckStatus) error {
	return nil
}

func (s *noopStore) InsertScanLog(_ context.Context, entry *db.ScanLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.scanLogs = append(s.scanLogs, *entry)
	return nil
}

func (s *noopStore) ListRecentScans(_ context.Context, limit int) ([]db.ScanLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > len(s.scanLogs) {
		limit = len(s.scanLogs)
	}

	out := make([]db.ScanLogEntry, 0, limit)
	for i := len(s.scanLogs) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.scanLogs[i])
	}
	return out, nil
}

func (*noopStore) ListRecentVulnerabilities(context.Context, int, int) ([]db.RecentVulnerability, error) {
	return nil, nil
}

func (s *noopStore) CountScansByDay(_ context.Context, days int) ([]db.DailyScanStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if days <= 0 {
		days = 7
	}

	startDay := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	byDay := make(map[string]*db.DailyScanStats, days)
	for i := 0; i < days; i++ {
		day := startDay.AddDate(0, 0, i)
		byDay[day.Format("2006-01-02")] = &db.DailyScanStats{Date: day}
	}

	for _, entry := range s.scanLogs {
		key := entry.ScannedAt.UTC().Format("2006-01-02")
		row, ok := byDay[key]
		if !ok {
			continue
		}
		row.ScanCount++
		row.FindingsCount += entry.FindingsCount
	}

	out := make([]db.DailyScanStats, 0, days)
	for i := 0; i < days; i++ {
		day := startDay.AddDate(0, 0, i).Format("2006-01-02")
		out = append(out, *byDay[day])
	}
	return out, nil
}

func (s *noopStore) SearchPackages(_ context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := strings.TrimSpace(strings.ToLower(params.Query))
	severity := strings.ToUpper(strings.TrimSpace(params.Severity))
	findingType := strings.ToLower(strings.TrimSpace(params.FindingType))
	limit := params.Limit
	if query == "" && severity == "" && findingType == "" {
		return []db.PackageSearchResult{}, nil
	}

	type key struct {
		ecosystem string
		name      string
	}

	results := make(map[key]*db.PackageSearchResult)
	if findingType == "" || findingType == "malicious" {
		for _, mf := range s.malicious {
			if query != "" && !strings.Contains(strings.ToLower(mf.Name), query) {
				continue
			}
			if severity != "" && strings.ToUpper(strings.TrimSpace(mf.Severity)) != severity {
				continue
			}

			k := key{ecosystem: mf.Ecosystem, name: mf.Name}
			if existing, ok := results[k]; ok {
				existing.FindingsCount++
				continue
			}
			results[k] = &db.PackageSearchResult{
				Ecosystem:          mf.Ecosystem,
				Name:               mf.Name,
				FindingsCount:      1,
				VulnerabilityCount: 0,
				VulnerabilityIDs:   "",
				Sources:            mf.Source,
			}
		}
	}

	out := make([]db.PackageSearchResult, 0, len(results))
	for _, result := range results {
		out = append(out, *result)
	}

	slices.SortFunc(out, func(a, b db.PackageSearchResult) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.Ecosystem, b.Ecosystem)
	})

	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *noopStore) FindAPIKeyByHash(_ context.Context, keyHash string) (*db.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, apiKey := range s.apiKeys {
		if apiKey.KeyHash == keyHash && apiKey.RevokedAt == nil {
			copyValue := apiKey
			return &copyValue, nil
		}
	}
	return nil, nil
}

func (s *noopStore) TouchAPIKeyLastUsed(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.apiKeys {
		if s.apiKeys[i].ID != keyID {
			continue
		}
		now := time.Now().UTC()
		s.apiKeys[i].LastUsedAt = &now
		return nil
	}
	return nil
}

func (s *noopStore) ListAPIKeys(context.Context) ([]db.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := append([]db.APIKey(nil), s.apiKeys...)
	slices.Reverse(out)
	return out, nil
}

func (s *noopStore) CreateAPIKey(_ context.Context, name, keyHash string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextAPIKeyID++
	s.apiKeys = append(s.apiKeys, db.APIKey{
		ID:        s.nextAPIKeyID,
		Name:      name,
		KeyHash:   keyHash,
		CreatedAt: time.Now().UTC(),
	})
	return s.nextAPIKeyID, nil
}

func (s *noopStore) RevokeAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.apiKeys {
		if s.apiKeys[i].ID != keyID || s.apiKeys[i].RevokedAt != nil {
			continue
		}
		now := time.Now().UTC()
		s.apiKeys[i].RevokedAt = &now
		break
	}
	return nil
}

func (s *noopStore) DeleteAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.apiKeys {
		if s.apiKeys[i].ID != keyID {
			continue
		}
		if s.apiKeys[i].RevokedAt == nil {
			return fmt.Errorf("api key %d is not revoked", keyID)
		}
		s.apiKeys = append(s.apiKeys[:i], s.apiKeys[i+1:]...)
		return nil
	}
	return fmt.Errorf("api key %d not found", keyID)
}

func (s *noopStore) GetAdminAuth(context.Context) (*db.AdminAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.adminAuth == nil {
		return nil, nil
	}
	copyValue := *s.adminAuth
	return &copyValue, nil
}

func (s *noopStore) UpsertAdminAuth(_ context.Context, passwordHash string, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	if s.adminAuth == nil {
		s.adminAuth = &db.AdminAuth{
			PasswordHash: passwordHash,
			CreatedAt:    now,
		}
		return nil
	}

	s.adminAuth.PasswordHash = passwordHash
	s.adminAuth.PasswordChangedAt = &now
	return nil
}

func (s *noopStore) InsertAdminAuditLog(_ context.Context, entry *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextAuditID++
	now := time.Now().UTC()
	s.auditLog = append(s.auditLog, db.AdminAuditLogEntry{
		ID:        s.nextAuditID,
		Action:    entry.Action,
		Details:   append(json.RawMessage(nil), entry.Details...),
		IP:        entry.IP,
		CreatedAt: now,
	})

	if entry.Action == "login_success" && s.adminAuth != nil {
		s.adminAuth.LastLoginAt = &now
	}

	return nil
}

func (s *noopStore) ListAdminAuditLog(_ context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > len(s.auditLog) {
		limit = len(s.auditLog)
	}

	out := make([]db.AdminAuditLogEntry, 0, limit)
	for i := len(s.auditLog) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.auditLog[i])
	}
	return out, nil
}

func (s *noopStore) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := &db.QueueStatsResult{}
	for _, job := range s.refreshJobs {
		switch job.Status {
		case "pending":
			stats.Pending++
		case "processing":
			stats.Processing++
		case "done":
			stats.Done++
		case "error":
			stats.Error++
		}
	}
	return stats, nil
}

func (s *noopStore) ListQueueJobs(_ context.Context, status string, limit int) ([]db.RefreshJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.RefreshJob, 0, len(s.refreshJobs))
	for i := len(s.refreshJobs) - 1; i >= 0; i-- {
		if status != "" && s.refreshJobs[i].Status != status {
			continue
		}
		out = append(out, s.refreshJobs[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *noopStore) PurgeQueue(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	purged := 0
	kept := s.refreshJobs[:0]
	for _, job := range s.refreshJobs {
		if job.Status == "done" || job.Status == "error" {
			purged++
			continue
		}
		kept = append(kept, job)
	}
	s.refreshJobs = kept
	return purged, nil
}

func (s *noopStore) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := &db.DashboardStatsResult{
		BySeverity: make(map[string]int),
	}

	packages := make(map[string]struct{})
	for _, mf := range s.malicious {
		stats.TotalMalicious++
		key := mf.Ecosystem + "/" + mf.Name
		packages[key] = struct{}{}

		severity := strings.ToUpper(strings.TrimSpace(mf.Severity))
		if severity == "" {
			severity = "UNKNOWN"
		}
		stats.BySeverity[severity]++
	}
	stats.TotalPackages = len(packages)
	return stats, nil
}

func (s *noopStore) queuePositionLocked(jobID int) int {
	position := 0
	for _, job := range s.refreshJobs {
		if job.Status != "pending" && job.Status != "processing" {
			continue
		}
		position++
		if job.ID == jobID {
			return position
		}
	}
	return position
}

func (*noopStore) Close() error { return nil }

// noopPinger satisfies health.Pinger and always succeeds.
type noopPinger struct{}

func (*noopPinger) Ping(context.Context) error { return nil }
