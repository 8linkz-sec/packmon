package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type searchKey struct {
	ecosystem string
	name      string
}

// HasAdvisoryData reports whether the local database contains synced
// vulnerability or malicious-package data. This is used to decide
// whether local scan fallback is safe.
func (s *Store) HasAdvisoryData(ctx context.Context) (bool, error) {
	const query = `
		SELECT
			(SELECT COUNT(*) FROM vulnerabilities_local) +
			(SELECT COUNT(*) FROM malicious_local)`

	var count int
	if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return false, fmt.Errorf("sqlite: advisory data count: %w", err)
	}
	return count > 0, nil
}

// ListRecentScans returns the most recent local scan-history entries.
func (s *Store) ListRecentScans(ctx context.Context, limit int) ([]db.ScanLogEntry, error) {
	entries, err := s.GetRecentScans(ctx, "", limit)
	if err != nil {
		return nil, err
	}

	out := make([]db.ScanLogEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, db.ScanLogEntry{
			ScanID:        fmt.Sprintf("local-%d", entry.ID),
			RepoName:      entry.RepoName,
			Branch:        entry.Branch,
			ScannedAt:     entry.ScannedAt,
			PackagesCount: entry.PackagesCount,
			FindingsCount: entry.FindingsCount,
		})
	}

	return out, nil
}

// CountScansByDay returns scan and finding totals for the last N days,
// including today, oldest first.
func (s *Store) CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error) {
	if days <= 0 {
		days = 7
	}

	startDay := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	const query = `
		SELECT substr(scanned_at, 1, 10) AS day, COUNT(*), COALESCE(SUM(findings_count), 0)
		FROM scan_history
		WHERE scanned_at >= ?
		GROUP BY day
		ORDER BY day ASC`

	rows, err := s.db.QueryContext(ctx, query, startDay.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("sqlite: count scans by day: %w", err)
	}
	defer closeSilently(rows)

	type aggregate struct {
		scans    int
		findings int
	}

	byDay := make(map[string]aggregate, days)
	for rows.Next() {
		var (
			day      string
			scans    int
			findings int
		)
		if err := rows.Scan(&day, &scans, &findings); err != nil {
			return nil, fmt.Errorf("sqlite: scan daily stats row: %w", err)
		}
		byDay[day] = aggregate{scans: scans, findings: findings}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate daily stats: %w", err)
	}

	out := make([]db.DailyScanStats, 0, days)
	for i := 0; i < days; i++ {
		day := startDay.AddDate(0, 0, i)
		key := day.Format("2006-01-02")
		agg := byDay[key]
		out = append(out, db.DailyScanStats{
			Date:          day,
			ScanCount:     agg.scans,
			FindingsCount: agg.findings,
		})
	}

	return out, nil
}

// SearchPackages searches local vulnerability and malicious-package data
// for packages matching the optional name query and/or severity filter.
func (s *Store) SearchPackages(ctx context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	query := strings.TrimSpace(params.Query)
	severity := strings.ToUpper(strings.TrimSpace(params.Severity))
	findingType := strings.ToLower(strings.TrimSpace(params.FindingType))
	limit := params.Limit
	if query == "" && severity == "" && findingType == "" {
		return []db.PackageSearchResult{}, nil
	}
	if limit <= 0 {
		limit = 50
	}

	results := make(map[searchKey]*db.PackageSearchResult)
	like := ""
	if query != "" {
		like = "%" + strings.ToLower(query) + "%"
	}

	if findingType == "" || findingType == "vulnerability" {
		if err := s.collectSearchResults(ctx, results, `
			SELECT ecosystem, name, COUNT(*) AS findings_count, COUNT(*) AS vulnerability_count, COALESCE(GROUP_CONCAT(DISTINCT id), '')
			FROM vulnerabilities_local
			WHERE (? = '' OR lower(name) LIKE ?)
			  AND (? = '' OR upper(coalesce(severity, 'UNKNOWN')) = ?)
			GROUP BY ecosystem, name
			ORDER BY name ASC
			LIMIT ?`, like, like, severity, severity, limit); err != nil {
			return nil, err
		}
	}

	if findingType == "" || findingType == "malicious" {
		if err := s.collectSearchResults(ctx, results, `
			SELECT ecosystem, name, COUNT(*) AS findings_count, 0 AS vulnerability_count, '' AS vulnerability_ids
			FROM malicious_local
			WHERE (? = '' OR lower(name) LIKE ?)
			  AND (? = '' OR upper(coalesce(severity, 'UNKNOWN')) = ?)
			GROUP BY ecosystem, name
			ORDER BY name ASC
			LIMIT ?`, like, like, severity, severity, limit); err != nil {
			return nil, err
		}
	}

	out := make([]db.PackageSearchResult, 0, len(results))
	for _, result := range results {
		result.VulnerabilityIDs = joinLocalCSV(result.VulnerabilityIDs)
		result.Sources = "local"
		out = append(out, *result)
	}

	for i := 1; i < len(out); i++ {
		current := out[i]
		j := i - 1
		for j >= 0 && (out[j].Name > current.Name || (out[j].Name == current.Name && out[j].Ecosystem > current.Ecosystem)) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = current
	}

	if len(out) > limit {
		out = out[:limit]
	}

	return out, nil
}

func (s *Store) collectSearchResults(ctx context.Context, acc map[searchKey]*db.PackageSearchResult, query string, args ...any) error {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("sqlite: search packages: %w", err)
	}
	defer closeSilently(rows)

	for rows.Next() {
		var (
			ecosystem          string
			name               string
			findingsCount      int
			vulnerabilityCount int
			vulnerabilityIDs   string
		)
		if err := rows.Scan(&ecosystem, &name, &findingsCount, &vulnerabilityCount, &vulnerabilityIDs); err != nil {
			return fmt.Errorf("sqlite: scan package search row: %w", err)
		}

		k := searchKey{ecosystem: ecosystem, name: name}
		if existing, ok := acc[k]; ok {
			existing.FindingsCount += findingsCount
			existing.VulnerabilityCount += vulnerabilityCount
			existing.VulnerabilityIDs = mergeLocalCSV(existing.VulnerabilityIDs, vulnerabilityIDs)
			continue
		}
		acc[k] = &db.PackageSearchResult{
			Ecosystem:          ecosystem,
			Name:               name,
			FindingsCount:      findingsCount,
			VulnerabilityCount: vulnerabilityCount,
			VulnerabilityIDs:   vulnerabilityIDs,
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: iterate package search rows: %w", err)
	}

	return nil
}

func mergeLocalCSV(current, incoming string) string {
	set := make(map[string]struct{})
	for _, part := range strings.Split(current, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			set[part] = struct{}{}
		}
	}
	for _, part := range strings.Split(incoming, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			set[part] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for part := range set {
		out = append(out, part)
	}
	for i := 1; i < len(out); i++ {
		current := out[i]
		j := i - 1
		for j >= 0 && out[j] > current {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = current
	}
	return strings.Join(out, ", ")
}

func joinLocalCSV(current string) string {
	if current == "" {
		return ""
	}
	return mergeLocalCSV("", current)
}

// DashboardStats returns aggregate counts for the local dashboard.
func (s *Store) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	stats := &db.DashboardStatsResult{
		BySeverity: map[string]int{},
	}

	const uniquePackagesQuery = `
		SELECT COUNT(*)
		FROM (
			SELECT ecosystem, name FROM vulnerabilities_local
			UNION
			SELECT ecosystem, name FROM malicious_local
		)`

	if err := s.db.QueryRowContext(ctx, uniquePackagesQuery).Scan(&stats.TotalPackages); err != nil {
		return nil, fmt.Errorf("sqlite: dashboard total packages: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT id) FROM vulnerabilities_local`).Scan(&stats.TotalVulnerabilities); err != nil {
		return nil, fmt.Errorf("sqlite: dashboard total vulnerabilities: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM malicious_local`).Scan(&stats.TotalMalicious); err != nil {
		return nil, fmt.Errorf("sqlite: dashboard total malicious: %w", err)
	}

	if err := s.collectSeverityCounts(ctx, stats.BySeverity, `SELECT severity, COUNT(*) FROM (SELECT DISTINCT id, severity FROM vulnerabilities_local) GROUP BY severity`); err != nil {
		return nil, err
	}
	if err := s.collectSeverityCounts(ctx, stats.BySeverity, `SELECT severity, COUNT(*) FROM malicious_local GROUP BY severity`); err != nil {
		return nil, err
	}

	return stats, nil
}

func (s *Store) collectSeverityCounts(ctx context.Context, acc map[string]int, query string) error {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("sqlite: dashboard severities: %w", err)
	}
	defer closeSilently(rows)

	for rows.Next() {
		var (
			severity sql.NullString
			count    int
		)
		if err := rows.Scan(&severity, &count); err != nil {
			return fmt.Errorf("sqlite: scan severity row: %w", err)
		}

		key := strings.ToUpper(strings.TrimSpace(severity.String))
		if key == "" {
			key = "UNKNOWN"
		}
		acc[key] += count
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlite: iterate severities: %w", err)
	}

	return nil
}

// ListFeedSyncStatuses returns no feed data for the local SQLite store.
func (s *Store) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	return []db.FeedSyncStatus{}, nil
}

func (s *Store) ListRecentVulnerabilities(context.Context, int, int) ([]db.RecentVulnerability, error) {
	return nil, nil
}
