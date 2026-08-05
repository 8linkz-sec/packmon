package devstore

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func (s *Store) ExportSync(_ context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
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
