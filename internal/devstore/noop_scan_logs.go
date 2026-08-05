package devstore

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func (s *Store) InsertScanLog(_ context.Context, entry *db.ScanLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry != nil && entry.IdempotencyKey != "" {
		for _, existing := range s.scanLogs {
			if existing.IdempotencyKey == entry.IdempotencyKey {
				return nil
			}
		}
	}
	s.scanLogs = append(s.scanLogs, cloneScanLogEntry(*entry))
	return nil
}

func (s *Store) GetScanLogByIdempotencyKey(_ context.Context, key string) (*db.ScanLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.scanLogs {
		if s.scanLogs[i].IdempotencyKey == key {
			entry := cloneScanLogEntry(s.scanLogs[i])
			return &entry, nil
		}
	}
	return nil, nil
}

func (s *Store) ListRecentScans(_ context.Context, limit, offset int) ([]db.ScanLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if offset < 0 {
		offset = 0
	}
	if offset >= len(s.scanLogs) {
		return []db.ScanLogEntry{}, nil
	}
	if limit <= 0 || limit > len(s.scanLogs) {
		limit = len(s.scanLogs)
	}

	out := make([]db.ScanLogEntry, 0, limit)
	for i, skipped := len(s.scanLogs)-1, 0; i >= 0 && len(out) < limit; i-- {
		if skipped < offset {
			skipped++
			continue
		}
		out = append(out, cloneScanLogEntry(s.scanLogs[i]))
	}
	return out, nil
}

func (s *Store) PruneScanLogs(_ context.Context, retention time.Duration) (int, error) {
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

func (*Store) ListRecentVulnerabilities(context.Context, int, int) ([]db.RecentVulnerability, error) {
	return nil, nil
}

func (s *Store) CountScansByDay(_ context.Context, days int) ([]db.DailyScanStats, error) {
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

func (s *Store) SearchPackages(_ context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := strings.TrimSpace(strings.ToLower(params.Query))
	severity := strings.ToUpper(strings.TrimSpace(params.Severity))
	findingType := strings.ToLower(strings.TrimSpace(params.FindingType))
	if query == "" && severity == "" && findingType == "" {
		return []db.PackageSearchResult{}, nil
	}

	results := make(map[noopPackageSearchKey]*db.PackageSearchResult)
	if findingType == "" || findingType == "vulnerability" {
		collectNoopVulnerabilitySearch(results, s.vulnerable, query, severity)
	}

	if findingType == "" || findingType == "malicious" {
		collectNoopMaliciousSearch(results, s.malicious, query, severity)
	}

	return finalizeNoopPackageSearchResults(results, params.Limit, params.Offset), nil
}

func collectNoopVulnerabilitySearch(results map[noopPackageSearchKey]*db.PackageSearchResult, vulnerabilities map[string]db.Vulnerability, query, severity string) {
	for _, vuln := range vulnerabilities {
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

func collectNoopMaliciousSearch(results map[noopPackageSearchKey]*db.PackageSearchResult, malicious map[string]db.MaliciousFinding, query, severity string) {
	for _, mf := range malicious {
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

func finalizeNoopPackageSearchResults(results map[noopPackageSearchKey]*db.PackageSearchResult, limit, offset int) []db.PackageSearchResult {
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

	if offset < 0 {
		offset = 0
	}
	if offset >= len(out) {
		return []db.PackageSearchResult{}
	}
	out = out[offset:]
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
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

func (s *Store) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
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

func (s *Store) ScanTotals(context.Context) (*db.ScanTotals, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	totals := &db.ScanTotals{}
	for _, entry := range s.scanLogs {
		totals.PackagesScanned += entry.PackagesCount
		totals.Findings += entry.FindingsCount
	}
	return totals, nil
}

func noopNormalizeSeverity(severity string) string {
	normalized := strings.ToUpper(strings.TrimSpace(severity))
	if normalized == "" {
		return "UNKNOWN"
	}
	return normalized
}
