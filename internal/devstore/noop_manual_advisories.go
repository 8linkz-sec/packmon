package devstore

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	pkgid "github.com/8linkz-sec/packmon/internal/packageid"
)

func (s *Store) UpsertManualAdvisory(_ context.Context, advisory *db.ManualAdvisory) error {
	if advisory == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upsertManualAdvisoryLocked(advisory)
}

func (s *Store) UpsertManualAdvisoryWithAudit(_ context.Context, advisory *db.ManualAdvisory, audit *db.AdminAuditEntry) error {
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

func (s *Store) upsertManualAdvisoryLocked(advisory *db.ManualAdvisory) error {
	findingType, ok := domain.ParseManualAdvisoryFindingType(advisory.FindingType)
	if !ok {
		return fmt.Errorf("manual advisory finding type %q is not supported", advisory.FindingType)
	}
	if findingType == domain.FindingTypeMalicious {
		finding := db.ManualAdvisoryToMaliciousFinding(advisory)
		finding.Name = pkgid.NormalizeName(finding.Ecosystem, finding.Name)
		s.malicious[finding.ID] = cloneMaliciousFinding(*finding)
		delete(s.maliciousDel, finding.ID)
		delete(s.vulnerable, advisory.ID)
		return nil
	}

	vuln := db.ManualAdvisoryToVulnerability(advisory)
	copyValue := cloneVulnerability(*vuln)
	for i := range copyValue.AffectedPackages {
		copyValue.AffectedPackages[i].Name = pkgid.NormalizeName(copyValue.AffectedPackages[i].Ecosystem, copyValue.AffectedPackages[i].Name)
	}
	s.vulnerable[copyValue.ID] = copyValue
	if finding, ok := s.malicious[advisory.ID]; ok && finding.Source == domain.ManualAdvisorySource {
		s.maliciousDel[advisory.ID] = noopMaliciousTombstone(finding)
		delete(s.malicious, advisory.ID)
	}
	return nil
}

func (s *Store) DeleteManualAdvisory(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteManualAdvisoryLocked(id)
}

func (s *Store) DeleteManualAdvisoryWithAudit(_ context.Context, id string, audit *db.AdminAuditEntry) error {
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

func (s *Store) deleteManualAdvisoryLocked(id string) error {
	deleted := false
	if finding, ok := s.malicious[id]; ok && finding.Source == domain.ManualAdvisorySource {
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

func (s *Store) GetManualAdvisory(_ context.Context, id string) (*db.ManualAdvisory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	advisory, ok := s.manualAdvisoryByIDLocked(id)
	if !ok {
		return nil, nil
	}
	return &advisory, nil
}

func (s *Store) manualAdvisoryByIDLocked(id string) (db.ManualAdvisory, bool) {
	if finding, ok := s.malicious[id]; ok && finding.Source == domain.ManualAdvisorySource {
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

func (s *Store) ListManualAdvisories(_ context.Context, limit int) ([]db.ManualAdvisory, error) {
	return s.ListManualAdvisoriesPage(context.Background(), limit, 0)
}

func (s *Store) ListManualAdvisoriesPage(_ context.Context, limit, offset int) ([]db.ManualAdvisory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]db.ManualAdvisory, 0, len(s.malicious)+len(s.vulnerable))
	for _, finding := range s.malicious {
		if finding.Source != domain.ManualAdvisorySource {
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

func vulnerabilityHasManualSource(vuln db.Vulnerability) bool {
	for _, source := range vuln.Sources {
		if source.Source == domain.ManualAdvisorySource {
			return true
		}
	}
	return false
}
