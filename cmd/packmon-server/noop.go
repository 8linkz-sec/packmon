package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	pkgid "github.com/8linkz-sec/packmon/internal/packageid"
	versionpkg "github.com/8linkz-sec/packmon/internal/version"
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
	systemConfig *db.SystemSettings
	vulnerable   map[string]db.Vulnerability
	malicious    map[string]db.MaliciousFinding
	maliciousDel map[string]db.SyncMalicious
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
		vulnerable:   make(map[string]db.Vulnerability),
		malicious:    make(map[string]db.MaliciousFinding),
		maliciousDel: make(map[string]db.SyncMalicious),
	}
}

func (s *noopStore) FindVulnerabilities(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = pkgid.NormalizeName(ecosystem, name)
	findings := make([]domain.Finding, 0)
	for _, vuln := range s.vulnerable {
		for _, pkg := range vuln.AffectedPackages {
			if pkg.Ecosystem != ecosystem || pkg.Name != name {
				continue
			}
			if !noopVulnerabilityAffectsVersion(pkg.Ecosystem, version, string(pkg.VersionRanges), string(pkg.VersionsAffected)) {
				continue
			}
			source := "unknown"
			if len(vuln.Sources) > 0 && strings.TrimSpace(vuln.Sources[0].Source) != "" {
				source = vuln.Sources[0].Source
			}
			title := vuln.Summary
			if title == "" {
				title = vuln.ID
			}
			findings = append(findings, domain.Finding{
				Name:       name,
				Version:    version,
				Ecosystem:  domain.Ecosystem(ecosystem),
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.Severity(strings.ToUpper(strings.TrimSpace(vuln.Severity))),
				AdvisoryID: vuln.ID,
				Title:      title,
				FixedVersion: versionpkg.ExtractFixedVersionConstraint(
					string(pkg.VersionRanges),
				),
				Source: source,
			})
		}
	}
	return findings, nil
}

func noopVulnerabilityAffectsVersion(ecosystem, version, rangesJSON, versionsJSON string) bool {
	if strings.TrimSpace(version) == "" {
		return true
	}
	rangesJSON = strings.TrimSpace(rangesJSON)
	if rangesJSON == "" || rangesJSON == "null" {
		rangesJSON = "[]"
	}
	versionsJSON = strings.TrimSpace(versionsJSON)
	if versionsJSON == "" || versionsJSON == "null" {
		versionsJSON = "[]"
	}
	affected, err := versionpkg.VersionAffected(version, rangesJSON, versionsJSON, ecosystem)
	if err != nil {
		return true
	}
	return affected
}

func (s *noopStore) FindMalicious(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = pkgid.NormalizeName(ecosystem, name)
	findings := make([]domain.Finding, 0)
	for _, mf := range s.malicious {
		if mf.Ecosystem != ecosystem || mf.Name != name {
			continue
		}

		if !noopMaliciousAffectsVersion(mf.Ecosystem, version, string(mf.VersionRanges), string(mf.Versions)) {
			continue
		}

		title := mf.Summary
		if title == "" {
			title = fmt.Sprintf("manual advisory for %s", mf.Name)
		}

		findings = append(findings, domain.Finding{
			Name:       mf.Name,
			Version:    version,
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

func noopMaliciousAffectsVersion(ecosystem, version, rangesJSON, versionsJSON string) bool {
	if strings.TrimSpace(version) == "" {
		return true
	}
	rangesJSON = strings.TrimSpace(rangesJSON)
	if rangesJSON == "" || rangesJSON == "null" {
		rangesJSON = "[]"
	}
	versionsJSON = strings.TrimSpace(versionsJSON)
	if versionsJSON == "" || versionsJSON == "null" {
		versionsJSON = "[]"
	}
	affected, err := versionpkg.VersionAffected(version, rangesJSON, versionsJSON, ecosystem)
	if err != nil {
		return true
	}
	return affected
}

func (s *noopStore) FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	var all []domain.Finding
	for _, pkg := range packages {
		findings, err := s.FindVulnerabilities(ctx, pkg.Ecosystem, pkg.Name, pkg.Version)
		if err != nil {
			return nil, err
		}
		all = append(all, findings...)
	}
	return all, nil
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

func (*noopStore) FindReputationFindingsBatch(context.Context, []db.PackageQuery, string) ([]domain.Finding, error) {
	return nil, nil
}

func (*noopStore) FindLifecycleFindingsBatch(context.Context, []db.PackageQuery, time.Time) ([]domain.Finding, error) {
	return nil, nil
}

func (*noopStore) PropagateSeverityViaAliases(context.Context) (int, error) { return 0, nil }

func (s *noopStore) UpsertVulnerability(_ context.Context, vuln *db.Vulnerability) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.upsertVulnerabilityLocked(vuln)
}

func (s *noopStore) upsertVulnerabilityLocked(vuln *db.Vulnerability) error {
	if vuln == nil || strings.TrimSpace(vuln.ID) == "" {
		return nil
	}
	copyValue := cloneVulnerability(*vuln)
	for i := range copyValue.AffectedPackages {
		copyValue.AffectedPackages[i].Name = pkgid.NormalizeName(copyValue.AffectedPackages[i].Ecosystem, copyValue.AffectedPackages[i].Name)
	}
	s.vulnerable[copyValue.ID] = copyValue
	return nil
}

func (s *noopStore) UpsertMaliciousFinding(_ context.Context, mf *db.MaliciousFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.upsertMaliciousFindingLocked(mf)
}

func (s *noopStore) upsertMaliciousFindingLocked(mf *db.MaliciousFinding) error {
	copyValue := cloneMaliciousFinding(*mf)
	if copyValue.ID == "" {
		s.nextManualID++
		copyValue.ID = fmt.Sprintf("manual-%d", s.nextManualID)
	}
	if copyValue.Source == "" {
		copyValue.Source = "manual"
	}
	copyValue.Name = pkgid.NormalizeName(copyValue.Ecosystem, copyValue.Name)
	s.malicious[copyValue.ID] = copyValue
	delete(s.maliciousDel, copyValue.ID)
	return nil
}

func (s *noopStore) ImportVulnerabilityFeed(_ context.Context, _ string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	imported := 0
	for i := range items {
		if err := s.upsertVulnerabilityLocked(&items[i]); err != nil {
			return imported, 0, err
		}
		imported++
	}
	deleted := 0
	for _, id := range deleteIDs {
		delete(s.vulnerable, id)
		deleted++
	}
	if status != nil {
		if err := s.upsertFeedSyncStatusLocked(status); err != nil {
			return imported, deleted, err
		}
	}
	return imported, deleted, nil
}

func (s *noopStore) ImportMaliciousFeed(_ context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	imported := 0
	for i := range items {
		if err := s.upsertMaliciousFindingLocked(&items[i]); err != nil {
			return imported, 0, err
		}
		imported++
	}
	deleted := 0
	for _, id := range deleteIDs {
		if finding, ok := s.malicious[id]; ok && (feed == "" || finding.Source == feed) {
			s.maliciousDel[id] = noopMaliciousTombstone(finding)
			delete(s.malicious, id)
		}
		deleted++
	}
	if status != nil {
		if err := s.upsertFeedSyncStatusLocked(status); err != nil {
			return imported, deleted, err
		}
	}
	return imported, deleted, nil
}

func (*noopStore) MarkPackageReputationDue(context.Context, *db.PackageReputation) (bool, error) {
	return false, nil
}

func (*noopStore) ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error) {
	return nil, nil
}

func (*noopStore) UpsertPackageReputation(context.Context, *db.PackageReputation) error {
	return nil
}

func (*noopStore) UpsertLifecycleProducts(context.Context, []db.LifecycleProduct) error {
	return nil
}

func (s *noopStore) DeleteVulnerability(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.vulnerable, id)
	return nil
}

func (s *noopStore) DeleteMaliciousFinding(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if finding, ok := s.malicious[id]; ok {
		s.maliciousDel[id] = noopMaliciousTombstone(finding)
	}
	delete(s.malicious, id)
	return nil
}

func (s *noopStore) DeleteMaliciousFindingsNotInSource(_ context.Context, source string, ids []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keepIDs := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		keepIDs[id] = struct{}{}
	}
	pruned := 0
	for id, finding := range s.malicious {
		if finding.Source != source {
			continue
		}
		if _, keep := keepIDs[id]; keep {
			continue
		}
		s.maliciousDel[id] = noopMaliciousTombstone(finding)
		delete(s.malicious, id)
		pruned++
	}
	return pruned, nil
}

func (s *noopStore) ListMaliciousFindings(_ context.Context, source string, limit int) ([]db.MaliciousFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.MaliciousFinding, 0, len(s.malicious))
	for _, finding := range s.malicious {
		if source != "" && finding.Source != source {
			continue
		}
		out = append(out, cloneMaliciousFinding(finding))
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

func (s *noopStore) UpsertManualAdvisory(_ context.Context, advisory *db.ManualAdvisory) error {
	if advisory == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upsertManualAdvisoryLocked(advisory)
}

func (s *noopStore) UpsertManualAdvisoryWithAudit(_ context.Context, advisory *db.ManualAdvisory, audit *db.AdminAuditEntry) error {
	if advisory == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	return s.upsertManualAdvisoryLocked(advisory)
}

func (s *noopStore) upsertManualAdvisoryLocked(advisory *db.ManualAdvisory) error {
	findingType := normalizeManualAdvisoryType(advisory.FindingType)
	if findingType == "malicious" {
		finding := manualAdvisoryToMaliciousFinding(advisory)
		finding.Name = pkgid.NormalizeName(finding.Ecosystem, finding.Name)
		s.malicious[finding.ID] = cloneMaliciousFinding(*finding)
		delete(s.maliciousDel, finding.ID)
		delete(s.vulnerable, advisory.ID)
		return nil
	}

	vuln := manualAdvisoryToVulnerability(advisory)
	copyValue := cloneVulnerability(*vuln)
	for i := range copyValue.AffectedPackages {
		copyValue.AffectedPackages[i].Name = pkgid.NormalizeName(copyValue.AffectedPackages[i].Ecosystem, copyValue.AffectedPackages[i].Name)
	}
	s.vulnerable[copyValue.ID] = copyValue
	if finding, ok := s.malicious[advisory.ID]; ok && finding.Source == "manual" {
		s.maliciousDel[advisory.ID] = noopMaliciousTombstone(finding)
		delete(s.malicious, advisory.ID)
	}
	return nil
}

func (s *noopStore) DeleteManualAdvisory(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteManualAdvisoryLocked(id)
}

func (s *noopStore) DeleteManualAdvisoryWithAudit(_ context.Context, id string, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.manualAdvisoryByIDLocked(id); !ok {
		return fmt.Errorf("manual advisory %s not found", id)
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return err
	}
	return s.deleteManualAdvisoryLocked(id)
}

func (s *noopStore) deleteManualAdvisoryLocked(id string) error {
	deleted := false
	if finding, ok := s.malicious[id]; ok && finding.Source == "manual" {
		s.maliciousDel[id] = noopMaliciousTombstone(finding)
		delete(s.malicious, id)
		deleted = true
	}
	if vuln, ok := s.vulnerable[id]; ok && vulnerabilityHasManualSource(vuln) {
		delete(s.vulnerable, id)
		deleted = true
	}
	if !deleted {
		return fmt.Errorf("manual advisory %s not found", id)
	}
	return nil
}

func (s *noopStore) GetManualAdvisory(_ context.Context, id string) (*db.ManualAdvisory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	advisory, ok := s.manualAdvisoryByIDLocked(id)
	if !ok {
		return nil, nil
	}
	return &advisory, nil
}

func (s *noopStore) manualAdvisoryByIDLocked(id string) (db.ManualAdvisory, bool) {
	if finding, ok := s.malicious[id]; ok && finding.Source == "manual" {
		return db.ManualAdvisory{
			ID:          finding.ID,
			FindingType: "malicious",
			Ecosystem:   finding.Ecosystem,
			Name:        finding.Name,
			Severity:    finding.Severity,
			RiskType:    finding.RiskType,
			Summary:     finding.Summary,
			Description: finding.Description,
		}, true
	}
	if vuln, ok := s.vulnerable[id]; ok && vulnerabilityHasManualSource(vuln) {
		for _, pkg := range vuln.AffectedPackages {
			return db.ManualAdvisory{
				ID:          vuln.ID,
				FindingType: "vulnerability",
				Ecosystem:   pkg.Ecosystem,
				Name:        pkg.Name,
				Severity:    vuln.Severity,
				RiskType:    "",
				Summary:     vuln.Summary,
				Description: vuln.Details,
			}, true
		}
	}
	return db.ManualAdvisory{}, false
}

func (s *noopStore) ListManualAdvisories(_ context.Context, limit int) ([]db.ManualAdvisory, error) {
	return s.ListManualAdvisoriesPage(context.Background(), limit, 0)
}

func (s *noopStore) ListManualAdvisoriesPage(_ context.Context, limit, offset int) ([]db.ManualAdvisory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.ManualAdvisory, 0, len(s.malicious)+len(s.vulnerable))
	for _, finding := range s.malicious {
		if finding.Source != "manual" {
			continue
		}
		out = append(out, db.ManualAdvisory{
			ID:          finding.ID,
			FindingType: "malicious",
			Ecosystem:   finding.Ecosystem,
			Name:        finding.Name,
			Severity:    finding.Severity,
			RiskType:    finding.RiskType,
			Summary:     finding.Summary,
			Description: finding.Description,
		})
	}
	for _, vuln := range s.vulnerable {
		if !vulnerabilityHasManualSource(vuln) {
			continue
		}
		for _, pkg := range vuln.AffectedPackages {
			out = append(out, db.ManualAdvisory{
				ID:          vuln.ID,
				FindingType: "vulnerability",
				Ecosystem:   pkg.Ecosystem,
				Name:        pkg.Name,
				Severity:    vuln.Severity,
				RiskType:    "",
				Summary:     vuln.Summary,
				Description: vuln.Details,
			})
		}
	}

	slices.SortFunc(out, func(a, b db.ManualAdvisory) int {
		if a.ID == b.ID {
			return strings.Compare(a.FindingType, b.FindingType)
		}
		if a.ID > b.ID {
			return -1
		}
		return 1
	})
	if offset < 0 {
		offset = 0
	}
	if offset >= len(out) {
		return nil, nil
	}
	out = out[offset:]
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func normalizeManualAdvisoryType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "vulnerability":
		return "vulnerability"
	default:
		return "malicious"
	}
}

func manualAdvisoryToVulnerability(advisory *db.ManualAdvisory) *db.Vulnerability {
	now := time.Now().UTC()
	severity := strings.ToUpper(strings.TrimSpace(advisory.Severity))
	if severity == "" {
		severity = "UNKNOWN"
	}
	return &db.Vulnerability{
		ID:        strings.TrimSpace(advisory.ID),
		Summary:   strings.TrimSpace(advisory.Summary),
		Details:   strings.TrimSpace(advisory.Description),
		Severity:  severity,
		Published: now,
		Modified:  now,
		Aliases: []db.VulnerabilityAlias{
			{AliasID: strings.TrimSpace(advisory.ID)},
		},
		Sources: []db.VulnerabilitySource{
			{
				Source:   "manual",
				SourceID: strings.TrimSpace(advisory.ID),
			},
		},
		AffectedPackages: []db.AffectedPackage{
			{
				Ecosystem:        strings.TrimSpace(advisory.Ecosystem),
				Name:             strings.TrimSpace(advisory.Name),
				VersionRanges:    json.RawMessage("[]"),
				VersionsAffected: json.RawMessage("[]"),
			},
		},
	}
}

func manualAdvisoryToMaliciousFinding(advisory *db.ManualAdvisory) *db.MaliciousFinding {
	riskType := strings.TrimSpace(advisory.RiskType)
	if riskType == "" {
		riskType = "other"
	}
	severity := strings.ToUpper(strings.TrimSpace(advisory.Severity))
	if severity == "" {
		severity = "CRITICAL"
	}
	return &db.MaliciousFinding{
		ID:          strings.TrimSpace(advisory.ID),
		Ecosystem:   strings.TrimSpace(advisory.Ecosystem),
		Name:        strings.TrimSpace(advisory.Name),
		Source:      "manual",
		RiskType:    riskType,
		Severity:    severity,
		Summary:     strings.TrimSpace(advisory.Summary),
		Description: strings.TrimSpace(advisory.Description),
		CreatedBy:   "admin",
	}
}

func vulnerabilityHasManualSource(vuln db.Vulnerability) bool {
	for _, source := range vuln.Sources {
		if source.Source == "manual" {
			return true
		}
	}
	return false
}

func cloneVulnerability(vuln db.Vulnerability) db.Vulnerability {
	copyValue := vuln
	copyValue.Aliases = append([]db.VulnerabilityAlias(nil), vuln.Aliases...)
	copyValue.Sources = append([]db.VulnerabilitySource(nil), vuln.Sources...)
	copyValue.References = append([]db.VulnerabilityReference(nil), vuln.References...)
	copyValue.AffectedPackages = append([]db.AffectedPackage(nil), vuln.AffectedPackages...)
	for i := range copyValue.Sources {
		if copyValue.Sources[i].RawJSON != nil {
			copyValue.Sources[i].RawJSON = append(json.RawMessage(nil), copyValue.Sources[i].RawJSON...)
		}
	}
	for i := range copyValue.AffectedPackages {
		if copyValue.AffectedPackages[i].VersionRanges != nil {
			copyValue.AffectedPackages[i].VersionRanges = append(json.RawMessage(nil), copyValue.AffectedPackages[i].VersionRanges...)
		}
		if copyValue.AffectedPackages[i].VersionsAffected != nil {
			copyValue.AffectedPackages[i].VersionsAffected = append(json.RawMessage(nil), copyValue.AffectedPackages[i].VersionsAffected...)
		}
	}
	return copyValue
}

func cloneMaliciousFinding(finding db.MaliciousFinding) db.MaliciousFinding {
	copyValue := finding
	copyValue.VersionRanges = cloneRawMessage(finding.VersionRanges)
	copyValue.Versions = cloneRawMessage(finding.Versions)
	copyValue.ReferenceURLs = cloneRawMessage(finding.ReferenceURLs)
	copyValue.Published = cloneTimePtr(finding.Published)
	return copyValue
}

func cloneFeedSyncStatus(status db.FeedSyncStatus) db.FeedSyncStatus {
	copyValue := status
	copyValue.LastSyncAt = cloneTimePtr(status.LastSyncAt)
	copyValue.LastSyncDuration = cloneDurationPtr(status.LastSyncDuration)
	copyValue.Metadata = cloneRawMessage(status.Metadata)
	return copyValue
}

func cloneAdminAuditLogEntry(entry db.AdminAuditLogEntry) db.AdminAuditLogEntry {
	copyValue := entry
	copyValue.Details = cloneRawMessage(entry.Details)
	return copyValue
}

func cloneRawMessage(value json.RawMessage) json.RawMessage {
	if value == nil {
		return nil
	}
	return append(json.RawMessage(nil), value...)
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneDurationPtr(value *time.Duration) *time.Duration {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func (*noopStore) SetCISAKEV(context.Context, []string) (int, error) { return 0, nil }

func (*noopStore) ClearCISAKEV(context.Context, []string) (int, error) { return 0, nil }

func (*noopStore) SetEPSSScores(context.Context, []db.EPSSEntry) (int, error) { return 0, nil }

func (*noopStore) ReplaceEPSSScores(context.Context, []db.EPSSEntry) (int, int, error) {
	return 0, 0, nil
}

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
	copyValue := cloneFeedSyncStatus(status)
	return &copyValue, nil
}

func (s *noopStore) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.upsertFeedSyncStatusLocked(status)
}

func (s *noopStore) upsertFeedSyncStatusLocked(status *db.FeedSyncStatus) error {
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

func (s *noopStore) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
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

func (s *noopStore) GetSystemSettings(context.Context) (*db.SystemSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.systemConfig == nil {
		return nil, nil
	}
	copyValue := *s.systemConfig
	return &copyValue, nil
}

func (s *noopStore) UpsertSystemSettings(_ context.Context, settings *db.SystemSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if settings == nil {
		return nil
	}
	copyValue := *settings
	copyValue.UpdatedAt = time.Now().UTC()
	s.systemConfig = &copyValue
	return nil
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
		versionRanges := ""
		if len(finding.VersionRanges) > 0 {
			versionRanges = string(finding.VersionRanges)
		}
		referenceURLs := ""
		if len(finding.ReferenceURLs) > 0 {
			referenceURLs = string(finding.ReferenceURLs)
		}

		out.Malicious = append(out.Malicious, db.SyncMalicious{
			ID:            finding.ID,
			Ecosystem:     finding.Ecosystem,
			Name:          finding.Name,
			VersionRanges: versionRanges,
			Versions:      versions,
			ReferenceURLs: referenceURLs,
			RiskType:      finding.RiskType,
			Severity:      finding.Severity,
			Summary:       finding.Summary,
			Source:        finding.Source,
		})
	}
	if opts.Since != nil {
		for _, tombstone := range s.maliciousDel {
			if len(ecosystems) > 0 {
				if _, ok := ecosystems[tombstone.Ecosystem]; !ok {
					continue
				}
			}
			out.Malicious = append(out.Malicious, tombstone)
		}
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

func noopMaliciousTombstone(finding db.MaliciousFinding) db.SyncMalicious {
	versions := ""
	if len(finding.Versions) > 0 {
		versions = string(finding.Versions)
	}
	versionRanges := ""
	if len(finding.VersionRanges) > 0 {
		versionRanges = string(finding.VersionRanges)
	}
	referenceURLs := ""
	if len(finding.ReferenceURLs) > 0 {
		referenceURLs = string(finding.ReferenceURLs)
	}
	return db.SyncMalicious{
		ID:            finding.ID,
		Ecosystem:     finding.Ecosystem,
		Name:          finding.Name,
		VersionRanges: versionRanges,
		Versions:      versions,
		ReferenceURLs: referenceURLs,
		RiskType:      finding.RiskType,
		Severity:      finding.Severity,
		Summary:       finding.Summary,
		Source:        finding.Source,
		Withdrawn:     true,
	}
}

func (s *noopStore) EnqueueRefresh(_ context.Context, job *db.RefreshJob) (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.refreshJobs {
		existing := &s.refreshJobs[i]
		if existing.Ecosystem == job.Ecosystem && existing.Name == job.Name && existing.Source == job.Source &&
			(existing.Status == "pending" || existing.Status == "processing" || existing.Status == "paused") {
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
		completeRefreshJob(&s.refreshJobs[i], jobErr)
		return nil
	}
	return nil
}

func (s *noopStore) CompleteClaimedRefresh(_ context.Context, jobID int, claimedAt *time.Time, jobErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.refreshJobs {
		job := &s.refreshJobs[i]
		if job.ID != jobID {
			continue
		}
		if claimedAt == nil || job.Status != "processing" || job.ProcessedAt == nil || !job.ProcessedAt.Equal(*claimedAt) {
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
		job.Status = "error"
		job.Error = jobErr.Error()
	} else {
		job.Status = "done"
		job.Error = ""
	}
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

	if entry != nil && entry.IdempotencyKey != "" {
		for _, existing := range s.scanLogs {
			if existing.IdempotencyKey == entry.IdempotencyKey {
				return nil
			}
		}
	}
	s.scanLogs = append(s.scanLogs, *entry)
	return nil
}

func (s *noopStore) GetScanLogByIdempotencyKey(_ context.Context, key string) (*db.ScanLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.scanLogs {
		if s.scanLogs[i].IdempotencyKey == key {
			entry := s.scanLogs[i]
			return &entry, nil
		}
	}
	return nil, nil
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

func (s *noopStore) PruneScanLogs(_ context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-retention)
	kept := s.scanLogs[:0]
	pruned := 0
	for _, entry := range s.scanLogs {
		if entry.ScannedAt.Before(cutoff) {
			pruned++
			continue
		}
		kept = append(kept, entry)
	}
	s.scanLogs = kept
	return pruned, nil
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

	results := make(map[noopPackageSearchKey]*db.PackageSearchResult)
	if findingType == "" || findingType == "vulnerability" {
		for _, vuln := range s.vulnerable {
			if vuln.Withdrawn != nil {
				continue
			}
			vulnSeverity := noopNormalizeSeverity(vuln.Severity)
			if severity != "" && vulnSeverity != severity {
				continue
			}
			seenPackages := make(map[noopPackageSearchKey]struct{})
			for _, affected := range vuln.AffectedPackages {
				if query != "" && !strings.Contains(strings.ToLower(affected.Name), query) {
					continue
				}
				k := noopPackageSearchKey{ecosystem: affected.Ecosystem, name: affected.Name}
				if _, seen := seenPackages[k]; seen {
					continue
				}
				seenPackages[k] = struct{}{}

				result := noopPackageSearchResult(results, k)
				result.FindingsCount++
				result.VulnerabilityCount++
				result.VulnerabilityIDs = noopMergeCSV(result.VulnerabilityIDs, vuln.ID)
				result.FindingTypes = noopMergeCSV(result.FindingTypes, "vulnerability")
				for _, source := range noopVulnerabilitySources(vuln) {
					result.Sources = noopMergeCSV(result.Sources, source)
				}
			}
		}
	}

	if findingType == "" || findingType == "malicious" {
		for _, mf := range s.malicious {
			if query != "" && !strings.Contains(strings.ToLower(mf.Name), query) {
				continue
			}
			if severity != "" && noopNormalizeSeverity(mf.Severity) != severity {
				continue
			}

			k := noopPackageSearchKey{ecosystem: mf.Ecosystem, name: mf.Name}
			result := noopPackageSearchResult(results, k)
			result.FindingsCount++
			result.FindingTypes = noopMergeCSV(result.FindingTypes, "malicious")
			result.Sources = noopMergeCSV(result.Sources, noopSourceLabel(mf.Source))
		}
	}

	out := make([]db.PackageSearchResult, 0, len(results))
	for _, result := range results {
		result.VulnerabilityIDs = db.FormatSearchVulnerabilityIDPreview(result.VulnerabilityIDs, result.VulnerabilityCount)
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

type noopPackageSearchKey struct {
	ecosystem string
	name      string
}

func noopPackageSearchResult(results map[noopPackageSearchKey]*db.PackageSearchResult, k noopPackageSearchKey) *db.PackageSearchResult {
	if existing, ok := results[k]; ok {
		return existing
	}
	result := &db.PackageSearchResult{
		Ecosystem: k.ecosystem,
		Name:      k.name,
	}
	results[k] = result
	return result
}

func noopVulnerabilitySources(vuln db.Vulnerability) []string {
	if len(vuln.Sources) == 0 {
		return []string{"unknown"}
	}
	out := make([]string, 0, len(vuln.Sources))
	for _, source := range vuln.Sources {
		out = append(out, noopSourceLabel(source.Source))
	}
	return out
}

func noopSourceLabel(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "unknown"
	}
	return source
}

func noopMergeCSV(current, incoming string) string {
	values := make(map[string]struct{})
	for _, raw := range strings.Split(current, ",") {
		value := strings.TrimSpace(raw)
		if value != "" {
			values[value] = struct{}{}
		}
	}
	for _, raw := range strings.Split(incoming, ",") {
		value := strings.TrimSpace(raw)
		if value != "" {
			values[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}

func (s *noopStore) FindAPIKeyByHash(_ context.Context, keyHash string) (*db.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, apiKey := range s.apiKeys {
		if apiKey.RevokedAt == nil &&
			apiKey.DeletedAt == nil &&
			!apiKey.IsExpired(time.Now().UTC()) &&
			subtle.ConstantTimeCompare([]byte(apiKey.KeyHash), []byte(keyHash)) == 1 {
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
		if s.apiKeys[i].DeletedAt != nil {
			return nil
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

func (s *noopStore) CreateAPIKey(_ context.Context, name, keyHash string, expiresAt *time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.createAPIKeyLocked(name, keyHash, expiresAt), nil
}

func (s *noopStore) CreateAPIKeyWithAudit(_ context.Context, name, keyHash string, expiresAt *time.Time, audit *db.AdminAuditEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextAPIKeyID + 1
	if err := db.SetAdminAuditDetail(audit, "key_id", fmt.Sprint(id)); err != nil {
		return 0, err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return 0, fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	return s.createAPIKeyLocked(name, keyHash, expiresAt), nil
}

func (s *noopStore) createAPIKeyLocked(name, keyHash string, expiresAt *time.Time) int {
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

func (s *noopStore) RevokeAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.revokeAPIKeyLocked(keyID)
}

func (s *noopStore) RevokeAPIKeyWithAudit(_ context.Context, keyID int, audit *db.AdminAuditEntry) error {
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
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	now := time.Now().UTC()
	s.apiKeys[index].RevokedAt = &now
	return nil
}

func (s *noopStore) revokeAPIKeyLocked(keyID int) error {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID != keyID {
			continue
		}
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
	return fmt.Errorf("api key %d not found", keyID)
}

func (s *noopStore) DeleteAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.deleteAPIKeyLocked(keyID)
}

func (s *noopStore) DeleteAPIKeyWithAudit(_ context.Context, keyID int, audit *db.AdminAuditEntry) error {
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
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	now := time.Now().UTC()
	s.apiKeys[index].DeletedAt = &now
	return nil
}

func (s *noopStore) deleteAPIKeyLocked(keyID int) error {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID != keyID {
			continue
		}
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
	return fmt.Errorf("api key %d not found", keyID)
}

func (s *noopStore) apiKeyIndexLocked(keyID int) (int, error) {
	for i := range s.apiKeys {
		if s.apiKeys[i].ID == keyID {
			return i, nil
		}
	}
	return -1, fmt.Errorf("api key %d not found", keyID)
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

func (s *noopStore) UpsertAdminAuth(_ context.Context, passwordHash string, isBootstrap bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upsertAdminAuthLocked(passwordHash, isBootstrap)
	return nil
}

func (s *noopStore) UpsertAdminAuthWithAudit(_ context.Context, passwordHash string, isBootstrap bool, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.upsertAdminAuthLocked(passwordHash, isBootstrap)
	return nil
}

func (s *noopStore) upsertAdminAuthLocked(passwordHash string, isBootstrap bool) {
	now := time.Now().UTC()
	if s.adminAuth == nil {
		s.adminAuth = &db.AdminAuth{
			PasswordHash:        passwordHash,
			PasswordIsBootstrap: isBootstrap,
			CreatedAt:           now,
			PasswordChangedAt:   nil,
			LastLoginAt:         nil,
		}
		return
	}

	s.adminAuth.PasswordHash = passwordHash
	s.adminAuth.PasswordIsBootstrap = isBootstrap
	if isBootstrap {
		s.adminAuth.PasswordChangedAt = nil
	} else {
		s.adminAuth.PasswordChangedAt = &now
	}
}

func (s *noopStore) InsertAdminAuditLog(_ context.Context, entry *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.insertAdminAuditLogLocked(entry)
}

func (s *noopStore) insertAdminAuditLogLocked(entry *db.AdminAuditEntry) error {
	if entry == nil {
		return nil
	}
	s.nextAuditID++
	now := time.Now().UTC().Truncate(time.Microsecond)
	previousDigest := ""
	if len(s.auditLog) > 0 {
		previousDigest = s.auditLog[len(s.auditLog)-1].RowDigest
	}
	auditEntry := db.AdminAuditLogEntry{
		ID:             s.nextAuditID,
		Action:         entry.Action,
		Details:        append(json.RawMessage(nil), entry.Details...),
		IP:             entry.IP,
		CreatedAt:      now,
		PreviousDigest: previousDigest,
	}
	auditEntry.RowDigest = db.ComputeAdminAuditDigest(auditEntry)
	auditEntry.IntegrityStatus = db.AdminAuditIntegrityStatus(auditEntry)
	s.auditLog = append(s.auditLog, auditEntry)

	if entry.Action == "login_success" && s.adminAuth != nil {
		s.adminAuth.LastLoginAt = &now
	}

	return nil
}

func (s *noopStore) ListAdminAuditLog(_ context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	return s.ListAdminAuditLogPage(context.Background(), limit, 0)
}

func (s *noopStore) ListAdminAuditLogPage(_ context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || limit > len(s.auditLog) {
		limit = len(s.auditLog)
	}
	if offset < 0 {
		offset = 0
	}

	out := make([]db.AdminAuditLogEntry, 0, limit)
	for i, skipped := len(s.auditLog)-1, 0; i >= 0 && len(out) < limit; i-- {
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, cloneAdminAuditLogEntry(s.auditLog[i]))
	}
	db.AnnotateAdminAuditIntegrity(out)
	return out, nil
}

func (s *noopStore) PruneAdminAuditLogs(_ context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-retention)
	kept := s.auditLog[:0]
	pruned := 0
	for _, entry := range s.auditLog {
		if entry.CreatedAt.Before(cutoff) {
			pruned++
			continue
		}
		kept = append(kept, entry)
	}
	s.auditLog = kept
	return pruned, nil
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
		case "paused":
			stats.Paused++
		}
	}
	return stats, nil
}

func (s *noopStore) OldestQueueJobs(context.Context) (map[string]time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldest := make(map[string]time.Time)
	for _, job := range s.refreshJobs {
		if job.Source == "" || (job.Status != "pending" && job.Status != "processing") {
			continue
		}
		current, ok := oldest[job.Source]
		if !ok || job.RequestedAt.Before(current) {
			oldest[job.Source] = job.RequestedAt
		}
	}
	return oldest, nil
}

func (s *noopStore) ListQueueJobs(_ context.Context, status string, limit int) ([]db.RefreshJob, error) {
	return s.ListQueueJobsPage(context.Background(), status, limit, 0)
}

func (s *noopStore) ListQueueJobsPage(_ context.Context, status string, limit, offset int) ([]db.RefreshJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.RefreshJob, 0, len(s.refreshJobs))
	if offset < 0 {
		offset = 0
	}
	for i, skipped := len(s.refreshJobs)-1, 0; i >= 0; i-- {
		if status != "" && s.refreshJobs[i].Status != status {
			continue
		}
		if skipped < offset {
			skipped++
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

	return s.purgeQueueLocked(), nil
}

func (s *noopStore) PruneRefreshQueue(_ context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-retention)
	pruned := 0
	kept := s.refreshJobs[:0]
	for _, job := range s.refreshJobs {
		if (job.Status == "done" || job.Status == "error") && refreshQueueTerminalTime(job).Before(cutoff) {
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

func (s *noopStore) PurgeQueueWithAudit(_ context.Context, audit *db.AdminAuditEntry) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	purgeStatuses := map[string]struct{}{"done": {}, "error": {}}
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

func (s *noopStore) purgeQueueLocked() int {
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
	return purged
}

func (s *noopStore) UpdateQueueJobPriority(_ context.Context, jobID, priority int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.updateQueueJobPriorityLocked(jobID, priority)
}

func (s *noopStore) UpdateQueueJobPriorityWithAudit(_ context.Context, jobID, priority int, audit *db.AdminAuditEntry) error {
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

func (s *noopStore) updateQueueJobPriorityLocked(jobID, priority int) error {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID == jobID {
			s.refreshJobs[i].Priority = priority
			return nil
		}
	}
	return fmt.Errorf("queue job %d not found", jobID)
}

func (s *noopStore) RetryQueueJob(_ context.Context, jobID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.retryQueueJobLocked(jobID)
}

func (s *noopStore) RetryQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.retryableQueueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.refreshJobs[index].Status = "pending"
	s.refreshJobs[index].RequestedAt = time.Now().UTC()
	s.refreshJobs[index].ProcessedAt = nil
	s.refreshJobs[index].Error = ""
	return nil
}

func (s *noopStore) retryQueueJobLocked(jobID int) error {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID != jobID {
			continue
		}
		switch s.refreshJobs[i].Status {
		case "done", "error", "paused":
			s.refreshJobs[i].Status = "pending"
			s.refreshJobs[i].RequestedAt = time.Now().UTC()
			s.refreshJobs[i].ProcessedAt = nil
			s.refreshJobs[i].Error = ""
			return nil
		default:
			return fmt.Errorf("queue job %d is not retryable", jobID)
		}
	}
	return fmt.Errorf("queue job %d not found", jobID)
}

func (s *noopStore) PauseQueueJob(_ context.Context, jobID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.pauseQueueJobLocked(jobID)
}

func (s *noopStore) PauseQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.pendingQueueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.refreshJobs[index].Status = "paused"
	return nil
}

func (s *noopStore) pauseQueueJobLocked(jobID int) error {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID != jobID {
			continue
		}
		if s.refreshJobs[i].Status != "pending" {
			return fmt.Errorf("queue job %d is not pending", jobID)
		}
		s.refreshJobs[i].Status = "paused"
		return nil
	}
	return fmt.Errorf("queue job %d not found", jobID)
}

func (s *noopStore) ResumeQueueJob(_ context.Context, jobID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.resumeQueueJobLocked(jobID)
}

func (s *noopStore) ResumeQueueJobWithAudit(_ context.Context, jobID int, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.pausedQueueJobIndexLocked(jobID)
	if err != nil {
		return err
	}
	if err := s.insertAdminAuditLogLocked(audit); err != nil {
		return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
	}
	s.refreshJobs[index].Status = "pending"
	s.refreshJobs[index].ProcessedAt = nil
	s.refreshJobs[index].Error = ""
	return nil
}

func (s *noopStore) resumeQueueJobLocked(jobID int) error {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID != jobID {
			continue
		}
		if s.refreshJobs[i].Status != "paused" {
			return fmt.Errorf("queue job %d is not paused", jobID)
		}
		s.refreshJobs[i].Status = "pending"
		s.refreshJobs[i].ProcessedAt = nil
		s.refreshJobs[i].Error = ""
		return nil
	}
	return fmt.Errorf("queue job %d not found", jobID)
}

func (s *noopStore) ClearQueue(_ context.Context, statuses []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.clearQueueLocked(statuses), nil
}

func (s *noopStore) ClearQueueWithAudit(_ context.Context, statuses []string, audit *db.AdminAuditEntry) (int, error) {
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

func (s *noopStore) clearQueueLocked(statuses []string) int {
	return s.clearQueueWithAllowedLocked(normalizeNoopQueueStatuses(statuses))
}

func normalizeNoopQueueStatuses(statuses []string) map[string]struct{} {
	allowed := map[string]struct{}{}
	for _, status := range statuses {
		status = strings.ToLower(strings.TrimSpace(status))
		switch status {
		case "pending", "paused", "done", "error":
			allowed[status] = struct{}{}
		}
	}
	return allowed
}

func (s *noopStore) clearQueueWithAllowedLocked(allowed map[string]struct{}) int {
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

func (s *noopStore) queueJobsForStatusesLocked(allowed map[string]struct{}) []db.RefreshJob {
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

func (s *noopStore) queueJobIndexLocked(jobID int) (int, error) {
	for i := range s.refreshJobs {
		if s.refreshJobs[i].ID == jobID {
			return i, nil
		}
	}
	return -1, fmt.Errorf("queue job %d not found", jobID)
}

func (s *noopStore) pendingQueueJobIndexLocked(jobID int) (int, error) {
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return -1, err
	}
	if s.refreshJobs[index].Status != "pending" {
		return -1, fmt.Errorf("queue job %d is not pending", jobID)
	}
	return index, nil
}

func (s *noopStore) pausedQueueJobIndexLocked(jobID int) (int, error) {
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return -1, err
	}
	if s.refreshJobs[index].Status != "paused" {
		return -1, fmt.Errorf("queue job %d is not paused", jobID)
	}
	return index, nil
}

func (s *noopStore) retryableQueueJobIndexLocked(jobID int) (int, error) {
	index, err := s.queueJobIndexLocked(jobID)
	if err != nil {
		return -1, err
	}
	switch s.refreshJobs[index].Status {
	case "done", "error", "paused":
		return index, nil
	default:
		return -1, fmt.Errorf("queue job %d is not retryable", jobID)
	}
}

func (s *noopStore) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := &db.DashboardStatsResult{
		BySeverity: make(map[string]int),
	}

	packages := make(map[string]struct{})
	for _, vuln := range s.vulnerable {
		if vuln.Withdrawn != nil {
			continue
		}
		stats.TotalVulnerabilities++
		for _, affected := range vuln.AffectedPackages {
			key := affected.Ecosystem + "/" + affected.Name
			packages[key] = struct{}{}
		}
		stats.BySeverity[noopNormalizeSeverity(vuln.Severity)]++
	}
	for _, mf := range s.malicious {
		stats.TotalMalicious++
		key := mf.Ecosystem + "/" + mf.Name
		packages[key] = struct{}{}
		stats.BySeverity[noopNormalizeSeverity(mf.Severity)]++
	}
	stats.TotalPackages = len(packages)
	return stats, nil
}

func (s *noopStore) ScanTotals(context.Context) (*db.ScanTotals, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	totals := &db.ScanTotals{}
	for _, entry := range s.scanLogs {
		totals.PackagesScanned += entry.PackagesCount
		totals.Findings += entry.FindingsCount
	}
	return totals, nil
}

func (s *noopStore) queuePositionLocked(jobID int) int {
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
	if !noopRefreshJobActive(target.Status) {
		return 0
	}

	position := 1
	for _, job := range s.refreshJobs {
		if !noopRefreshJobActive(job.Status) || job.Source != target.Source || job.ID == target.ID {
			continue
		}
		if noopRefreshJobBefore(job, *target) {
			position++
		}
	}
	return position
}

func noopRefreshJobActive(status string) bool {
	return status == "pending" || status == "processing"
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

func noopNormalizeSeverity(severity string) string {
	normalized := strings.ToUpper(strings.TrimSpace(severity))
	if normalized == "" {
		return "UNKNOWN"
	}
	return normalized
}

func (*noopStore) Close() error { return nil }

// noopPinger satisfies health.Pinger and always succeeds.
type noopPinger struct{}

func (*noopPinger) Ping(context.Context) error { return nil }
