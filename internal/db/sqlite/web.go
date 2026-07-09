package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	lifecyclepolicy "github.com/8linkz-sec/packmon/internal/lifecycle"
)

type searchKey struct {
	ecosystem string
	name      string
	version   string
}

var nowUTC = func() time.Time {
	return time.Now().UTC()
}

// HasAdvisoryData reports whether the local database contains synced finding
// data that the local scanner can query. This is used to decide whether local
// scan fallback is safe.
func (s *Store) HasAdvisoryData(ctx context.Context) (bool, error) {
	const query = `
		SELECT
			(SELECT COUNT(*) FROM vulnerabilities_local) +
			(SELECT COUNT(*) FROM malicious_local) +
			(SELECT COUNT(*) FROM reputation_findings_local) +
			(SELECT COUNT(*) FROM lifecycle_releases_local)`

	var count int
	if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return false, fmt.Errorf("sqlite: advisory data count: %w", err)
	}
	return count > 0, nil
}

// ListRecentScans returns the most recent local scan-history entries.
func (s *Store) ListRecentScans(ctx context.Context, limit, offset int) ([]db.ScanLogEntry, error) {
	entries, err := s.getRecentScansPage(ctx, "", limit, offset)
	if err != nil {
		return nil, err
	}

	out := make([]db.ScanLogEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, db.ScanLogEntry{
			ScanID:        fmt.Sprintf("local-%d", entry.ID),
			RepoName:      entry.RepoName,
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

	startDay := nowUTC().UTC().Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
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
	defer ioutils.CloseSilently(rows)

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

// SearchPackages searches local vulnerability, malicious-package, reputation,
// and lifecycle data for packages matching the optional name query and/or
// severity filter.
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
	offset := params.Offset
	if offset < 0 {
		offset = 0
	}
	collectorLimit := localSearchCollectorLimit(limit, offset)

	results := make(map[searchKey]*db.PackageSearchResult)
	like, sqlLimit := localSearchSQLNameFilter(query, collectorLimit)
	opts := localPackageSearchOptions{
		nameQuery:   strings.ToLower(query),
		severity:    severity,
		findingType: findingType,
		like:        like,
		sqlLimit:    sqlLimit,
	}

	for _, collector := range []localPackageSearchCollector{
		s.collectVulnerabilitySearchResults,
		s.collectMaliciousSearchResults,
		s.collectReputationSearchResults,
		s.collectLifecycleSearchResults,
	} {
		if err := collector(ctx, results, opts); err != nil {
			return nil, err
		}
	}

	return limitLocalSearchResults(localSearchResults(results), limit, offset), nil
}

type localPackageSearchOptions struct {
	nameQuery   string
	severity    string
	findingType string
	like        string
	sqlLimit    int
}

type localPackageSearchCollector func(context.Context, map[searchKey]*db.PackageSearchResult, localPackageSearchOptions) error

func (s *Store) collectVulnerabilitySearchResults(ctx context.Context, results map[searchKey]*db.PackageSearchResult, opts localPackageSearchOptions) error {
	if opts.findingType != "" && opts.findingType != "vulnerability" {
		return nil
	}
	return s.collectSearchResults(ctx, results, opts.nameQuery, `
		SELECT ecosystem, name, '' AS version, COUNT(*) AS findings_count, COUNT(*) AS vulnerability_count,
			COALESCE((
				SELECT GROUP_CONCAT(id, ', ')
				FROM (
					SELECT DISTINCT preview.id AS id
					FROM vulnerabilities_local preview
					WHERE preview.ecosystem = vulnerabilities_local.ecosystem
					  AND preview.name = vulnerabilities_local.name
					  AND (? = '' OR lower(preview.name) LIKE ?)
					  AND (? = '' OR upper(coalesce(preview.severity, 'UNKNOWN')) = ?)
					ORDER BY preview.id
					LIMIT ?
				)
			), ''),
			'vulnerability' AS finding_types
		FROM vulnerabilities_local
		WHERE (? = '' OR lower(name) LIKE ?)
		  AND (? = '' OR upper(coalesce(severity, 'UNKNOWN')) = ?)
		GROUP BY ecosystem, name
		ORDER BY name ASC
		LIMIT ?`,
		opts.like, opts.like, opts.severity, opts.severity, db.SearchVulnerabilityIDPreviewLimit,
		opts.like, opts.like, opts.severity, opts.severity, opts.sqlLimit)
}

func (s *Store) collectMaliciousSearchResults(ctx context.Context, results map[searchKey]*db.PackageSearchResult, opts localPackageSearchOptions) error {
	if opts.findingType != "" && opts.findingType != "malicious" {
		return nil
	}
	return s.collectSearchResults(ctx, results, opts.nameQuery, `
		SELECT ecosystem, name, '' AS version, COUNT(*) AS findings_count, 0 AS vulnerability_count, '' AS vulnerability_ids, 'malicious' AS finding_types
		FROM malicious_local
		WHERE (? = '' OR lower(name) LIKE ?)
		  AND (? = '' OR upper(coalesce(severity, 'UNKNOWN')) = ?)
		GROUP BY ecosystem, name
		ORDER BY name ASC
		LIMIT ?`, opts.like, opts.like, opts.severity, opts.severity, opts.sqlLimit)
}

func (s *Store) collectReputationSearchResults(ctx context.Context, results map[searchKey]*db.PackageSearchResult, opts localPackageSearchOptions) error {
	if opts.findingType == "" || opts.findingType == "malicious" {
		if err := s.collectSearchResults(ctx, results, opts.nameQuery, `
			SELECT ecosystem, name, version, COUNT(*) AS findings_count, 0 AS vulnerability_count, '' AS vulnerability_ids, 'malicious' AS finding_types
			FROM reputation_findings_local
			WHERE type = 'malicious'
			  AND (? = '' OR lower(name) LIKE ?)
			  AND (? = '' OR upper(coalesce(severity, 'UNKNOWN')) = ?)
			GROUP BY ecosystem, name, version
			ORDER BY name ASC
			LIMIT ?`, opts.like, opts.like, opts.severity, opts.severity, opts.sqlLimit); err != nil {
			return err
		}
	}

	if opts.findingType == "" || opts.findingType == "supply_chain_risk" {
		if err := s.collectSearchResults(ctx, results, opts.nameQuery, `
			SELECT ecosystem, name, version, COUNT(*) AS findings_count, 0 AS vulnerability_count, '' AS vulnerability_ids, 'supply_chain_risk' AS finding_types
			FROM reputation_findings_local
			WHERE type = 'supply_chain_risk'
			  AND (? = '' OR lower(name) LIKE ?)
			  AND (? = '' OR upper(coalesce(severity, 'UNKNOWN')) = ?)
			GROUP BY ecosystem, name, version
			ORDER BY name ASC
			LIMIT ?`, opts.like, opts.like, opts.severity, opts.severity, opts.sqlLimit); err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) collectLifecycleSearchResults(ctx context.Context, results map[searchKey]*db.PackageSearchResult, opts localPackageSearchOptions) error {
	if opts.findingType == "" || opts.findingType == "supply_chain_risk" {
		if err := s.collectSearchResults(ctx, results, opts.nameQuery, `
			WITH lifecycle_findings AS (
				SELECT ecosystem, name, COALESCE(NULLIF(latest, ''), cycle) AS version, ? AS severity
				FROM lifecycle_releases_local
				WHERE is_eol = 1 OR (eol_from IS NOT NULL AND eol_from <= date('now'))
			)
			SELECT ecosystem, name, version, COUNT(*) AS findings_count, 0 AS vulnerability_count, '' AS vulnerability_ids, 'supply_chain_risk' AS finding_types
			FROM lifecycle_findings
			WHERE (? = '' OR lower(name) LIKE ?)
			  AND (? = '' OR severity = ?)
			GROUP BY ecosystem, name, version
			ORDER BY name ASC
			LIMIT ?`, string(lifecyclepolicy.SeverityEOL), opts.like, opts.like, opts.severity, opts.severity, opts.sqlLimit); err != nil {
			return err
		}
	}

	if opts.findingType == "" || opts.findingType == "lifecycle" {
		if err := s.collectSearchResults(ctx, results, opts.nameQuery, `
			WITH lifecycle_findings AS (
				SELECT ecosystem, name, COALESCE(NULLIF(latest, ''), cycle) AS version,
					CASE
						WHEN eol_from IS NOT NULL AND eol_from > date('now') AND eol_from <= date('now', '+' || ? || ' days') THEN ?
						WHEN is_eoas = 1 OR (eoas_from IS NOT NULL AND eoas_from <= date('now')) THEN ?
						ELSE ''
					END AS severity
				FROM lifecycle_releases_local
				WHERE NOT (is_eol = 1 OR (eol_from IS NOT NULL AND eol_from <= date('now')))
			)
			SELECT ecosystem, name, version, COUNT(*) AS findings_count, 0 AS vulnerability_count, '' AS vulnerability_ids, 'lifecycle' AS finding_types
			FROM lifecycle_findings
			WHERE severity <> ''
			  AND (? = '' OR lower(name) LIKE ?)
			  AND (? = '' OR severity = ?)
			GROUP BY ecosystem, name, version
			ORDER BY name ASC
			LIMIT ?`,
			lifecyclepolicy.EOLSoonDays,
			string(lifecyclepolicy.SeverityEOLSoon),
			string(lifecyclepolicy.SeveritySecuritySupportOnly),
			opts.like, opts.like, opts.severity, opts.severity, opts.sqlLimit); err != nil {
			return err
		}
	}

	return nil
}

func localSearchResults(results map[searchKey]*db.PackageSearchResult) []db.PackageSearchResult {
	out := make([]db.PackageSearchResult, 0, len(results))
	for _, result := range results {
		result.VulnerabilityIDs = joinLocalCSV(result.VulnerabilityIDs)
		result.VulnerabilityIDs = db.FormatSearchVulnerabilityIDPreview(result.VulnerabilityIDs, result.VulnerabilityCount)
		result.FindingTypes = joinLocalCSV(result.FindingTypes)
		result.Sources = "local"
		out = append(out, *result)
	}
	return out
}

func limitLocalSearchResults(out []db.PackageSearchResult, limit, offset int) []db.PackageSearchResult {
	for i := 1; i < len(out); i++ {
		current := out[i]
		j := i - 1
		for j >= 0 && (out[j].Name > current.Name ||
			(out[j].Name == current.Name && out[j].Ecosystem > current.Ecosystem) ||
			(out[j].Name == current.Name && out[j].Ecosystem == current.Ecosystem && out[j].Version > current.Version)) {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = current
	}

	if offset < 0 {
		offset = 0
	}
	if offset >= len(out) {
		return []db.PackageSearchResult{}
	}
	if offset > 0 {
		out = out[offset:]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func localSearchCollectorLimit(limit, offset int) int {
	if offset <= 0 {
		return limit
	}
	maxInt := int(^uint(0) >> 1)
	if limit > maxInt-offset {
		return maxInt
	}
	return limit + offset
}

func localSearchSQLNameFilter(query string, limit int) (string, int) {
	if query == "" {
		return "", limit
	}
	for _, r := range query {
		if r > 0x7f {
			return "", -1
		}
	}
	return "%" + strings.ToLower(query) + "%", limit
}

func (s *Store) collectSearchResults(ctx context.Context, acc map[searchKey]*db.PackageSearchResult, nameQuery, query string, args ...any) error {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("sqlite: search packages: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		var (
			ecosystem          string
			name               string
			version            string
			findingsCount      int
			vulnerabilityCount int
			vulnerabilityIDs   string
			findingTypes       string
		)
		if err := rows.Scan(&ecosystem, &name, &version, &findingsCount, &vulnerabilityCount, &vulnerabilityIDs, &findingTypes); err != nil {
			return fmt.Errorf("sqlite: scan package search row: %w", err)
		}
		if nameQuery != "" && !strings.Contains(strings.ToLower(name), nameQuery) {
			continue
		}

		k := searchKey{ecosystem: ecosystem, name: name, version: version}
		if existing, ok := acc[k]; ok {
			existing.FindingsCount += findingsCount
			existing.VulnerabilityCount += vulnerabilityCount
			existing.VulnerabilityIDs = mergeLocalCSV(existing.VulnerabilityIDs, vulnerabilityIDs)
			existing.FindingTypes = mergeLocalCSV(existing.FindingTypes, findingTypes)
			continue
		}
		acc[k] = &db.PackageSearchResult{
			Ecosystem:          ecosystem,
			Name:               name,
			Version:            version,
			FindingsCount:      findingsCount,
			VulnerabilityCount: vulnerabilityCount,
			VulnerabilityIDs:   vulnerabilityIDs,
			FindingTypes:       findingTypes,
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
	var reputationMalicious int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM reputation_findings_local WHERE type = 'malicious'`).Scan(&reputationMalicious); err != nil {
		return nil, fmt.Errorf("sqlite: dashboard reputation malicious: %w", err)
	}
	stats.TotalMalicious += reputationMalicious
	if err := s.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM reputation_findings_local WHERE type = 'supply_chain_risk')
			+
			(SELECT COUNT(*) FROM lifecycle_releases_local
			 WHERE is_eol != 0
			    OR (eol_from IS NOT NULL AND date(eol_from) <= date('now')))`).Scan(&stats.TotalSupplyChainRisk); err != nil {
		return nil, fmt.Errorf("sqlite: dashboard total supply-chain risk: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM lifecycle_releases_local
		WHERE NOT (
			is_eol != 0
			OR (eol_from IS NOT NULL AND date(eol_from) <= date('now'))
		)
		AND (
			(eol_from IS NOT NULL AND date(eol_from) > date('now') AND date(eol_from) <= date('now', '+90 day'))
			OR is_eoas != 0
			OR (eoas_from IS NOT NULL AND date(eoas_from) <= date('now'))
		)`).Scan(&stats.TotalLifecycle); err != nil {
		return nil, fmt.Errorf("sqlite: dashboard total lifecycle: %w", err)
	}

	if err := s.collectSeverityCounts(ctx, stats.BySeverity, `SELECT severity, COUNT(*) FROM (SELECT DISTINCT id, severity FROM vulnerabilities_local) GROUP BY severity`); err != nil {
		return nil, err
	}
	if err := s.collectSeverityCounts(ctx, stats.BySeverity, `SELECT severity, COUNT(*) FROM malicious_local GROUP BY severity`); err != nil {
		return nil, err
	}
	if err := s.collectSeverityCounts(ctx, stats.BySeverity, `SELECT severity, COUNT(*) FROM reputation_findings_local GROUP BY severity`); err != nil {
		return nil, err
	}

	return stats, nil
}

func (s *Store) collectSeverityCounts(ctx context.Context, acc map[string]int, query string) error {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("sqlite: dashboard severities: %w", err)
	}
	defer ioutils.CloseSilently(rows)

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
