package devstore

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	pkgid "github.com/8linkz-sec/packmon/internal/packageid"
	versionpkg "github.com/8linkz-sec/packmon/internal/version"
)

func (s *Store) FindVulnerabilities(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
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
	rangesJSON, versionsJSON = db.NormalizeVersionConstraintJSON(rangesJSON, versionsJSON)
	affected, err := versionpkg.VersionAffected(version, rangesJSON, versionsJSON, ecosystem)
	if err != nil {
		return true
	}
	return affected
}

func (s *Store) FindMalicious(_ context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
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
	rangesJSON, versionsJSON = db.NormalizeVersionConstraintJSON(rangesJSON, versionsJSON)
	affected, err := versionpkg.VersionAffected(version, rangesJSON, versionsJSON, ecosystem)
	if err != nil {
		return true
	}
	return affected
}

func (s *Store) FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
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

func (s *Store) FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
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

func (*Store) FindReputationFindingsBatch(context.Context, []db.PackageQuery, string) ([]domain.Finding, error) {
	return nil, nil
}

func (*Store) FindLifecycleFindingsBatch(context.Context, []db.PackageQuery, time.Time) ([]domain.Finding, error) {
	return nil, nil
}

func (*Store) PropagateSeverityViaAliases(context.Context) (int, error) { return 0, nil }

func (s *Store) UpsertVulnerability(_ context.Context, vuln *db.Vulnerability) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.upsertVulnerabilityLocked(vuln)
}

func (s *Store) upsertVulnerabilityLocked(vuln *db.Vulnerability) error {
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

func (s *Store) UpsertMaliciousFinding(_ context.Context, mf *db.MaliciousFinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.upsertMaliciousFindingLocked(mf)
}

func (s *Store) upsertMaliciousFindingLocked(mf *db.MaliciousFinding) error {
	copyValue := cloneMaliciousFinding(*mf)
	if copyValue.ID == "" {
		s.nextManualID++
		copyValue.ID = fmt.Sprintf("%s%d", domain.ManualAdvisoryIDPrefix, s.nextManualID)
	}
	if copyValue.Source == "" {
		copyValue.Source = domain.ManualAdvisorySource
	}
	copyValue.Name = pkgid.NormalizeName(copyValue.Ecosystem, copyValue.Name)
	s.malicious[copyValue.ID] = copyValue
	delete(s.maliciousDel, copyValue.ID)
	return nil
}

func (s *Store) ImportVulnerabilityFeed(_ context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.importVulnerabilityFeedLocked(feed, items, deleteIDs, status)
}

func (s *Store) ImportVulnerabilityFeedWithAudit(_ context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	imported, deleted, err := s.importVulnerabilityFeedLocked(feed, items, deleteIDs, status)
	if err != nil {
		return imported, deleted, err
	}
	if audit != nil {
		if err := s.insertAdminAuditLogLocked(audit(imported, deleted)); err != nil {
			return imported, deleted, err
		}
	}
	return imported, deleted, nil
}

func (s *Store) importVulnerabilityFeedLocked(feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	imported := 0
	for i := range items {
		if err := s.upsertVulnerabilityLocked(&items[i]); err != nil {
			return imported, 0, err
		}
		imported++
	}
	deleted := 0
	for _, id := range deleteIDs {
		if err := s.deleteVulnerabilityForSourceLocked(id, feed); err != nil {
			return imported, deleted, err
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

func (s *Store) ImportMaliciousFeed(_ context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.importMaliciousFeedLocked(feed, items, deleteIDs, status)
}

func (s *Store) ImportMaliciousFeedWithAudit(_ context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	imported, deleted, err := s.importMaliciousFeedLocked(feed, items, deleteIDs, status)
	if err != nil {
		return imported, deleted, err
	}
	if audit != nil {
		if err := s.insertAdminAuditLogLocked(audit(imported, deleted)); err != nil {
			return imported, deleted, err
		}
	}
	return imported, deleted, nil
}

func (s *Store) importMaliciousFeedLocked(feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
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

func (*Store) MarkPackageReputationDue(context.Context, *db.PackageReputation) (bool, error) {
	return false, nil
}

func (*Store) ListDuePackageReputations(context.Context, string, string, string, int) ([]db.PackageReputation, error) {
	return nil, nil
}

func (*Store) UpsertPackageReputation(context.Context, *db.PackageReputation) error {
	return nil
}

func (*Store) PrunePackageReputation(context.Context, string, time.Duration) (int, error) {
	return 0, nil
}

func (*Store) ReplaceLifecycleProducts(context.Context, []db.LifecycleProduct) (int, error) {
	return 0, nil
}

func (s *Store) DeleteVulnerability(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.vulnerable, id)
	return nil
}

func (s *Store) DeleteVulnerabilityForSource(_ context.Context, id, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteVulnerabilityForSourceLocked(id, source)
}

func (s *Store) deleteVulnerabilityForSourceLocked(id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("devstore: source-scoped vulnerability delete requires source: %w", db.ErrSourceScopedDeleteSourceRequired)
	}

	vuln, ok := s.vulnerable[id]
	if !ok {
		return nil
	}

	keptSources := make([]db.VulnerabilitySource, 0, len(vuln.Sources))
	for _, item := range vuln.Sources {
		if strings.TrimSpace(item.Source) == source {
			continue
		}
		keptSources = append(keptSources, item)
	}
	if len(keptSources) == len(vuln.Sources) {
		return nil
	}
	if len(keptSources) == 0 {
		delete(s.vulnerable, id)
		return nil
	}

	vuln.Sources = keptSources
	s.vulnerable[id] = vuln
	return nil
}

func (s *Store) DeleteMaliciousFinding(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if finding, ok := s.malicious[id]; ok {
		s.maliciousDel[id] = noopMaliciousTombstone(finding)
	}
	delete(s.malicious, id)
	return nil
}

func (s *Store) DeleteMaliciousFindingForSource(_ context.Context, id, source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("devstore: source-scoped malicious finding delete requires source: %w", db.ErrSourceScopedDeleteSourceRequired)
	}

	finding, ok := s.malicious[id]
	if !ok {
		return nil
	}
	if strings.TrimSpace(finding.Source) != source {
		return nil
	}

	s.maliciousDel[id] = noopMaliciousTombstone(finding)
	delete(s.malicious, id)
	return nil
}

func (s *Store) DeleteMaliciousFindingsNotInSource(_ context.Context, source string, ids []string) (int, error) {
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

func (s *Store) ListMaliciousFindings(_ context.Context, source string, limit int) ([]db.MaliciousFinding, error) {
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

func (*Store) FindUnknownSeverityCVEIDs(context.Context, string, int) ([]string, error) {
	return nil, nil
}

func (*Store) UpdateSeverityByCVE(context.Context, string, string, float64) error { return nil }
