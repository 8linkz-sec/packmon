package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	lifecyclepolicy "github.com/8linkz-sec/packmon/internal/lifecycle"
	"github.com/jackc/pgx/v5"
)

const countScansByDaySQL = `
	WITH bounds AS (
		SELECT (date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AS today_start
	),
	days AS (
		SELECT generate_series(
			today_start - (($1 - 1) * INTERVAL '1 day'),
			today_start,
			INTERVAL '1 day'
		) AS day
		FROM bounds
	)
	SELECT
		to_char(days.day AT TIME ZONE 'UTC', 'YYYY-MM-DD'),
		COUNT(scan_log.id)::int,
		COALESCE(SUM(scan_log.findings_count), 0)::int
	FROM days
	LEFT JOIN scan_log
		ON scan_log.scanned_at >= days.day
		AND scan_log.scanned_at < days.day + INTERVAL '1 day'
	GROUP BY days.day
	ORDER BY days.day ASC`

func (s *Store) ListRecentVulnerabilities(ctx context.Context, days, limit int) ([]db.RecentVulnerability, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	if days <= 0 {
		days = 7
	}

	rows, err := s.pool.Query(ctx, `
		SELECT v.id, v.summary, v.severity,
			COALESCE(ap.ecosystem, '') AS ecosystem,
			COALESCE(ap.name, '') AS name,
			COALESCE(ap.version_ranges::text, '[]') AS version_ranges,
			COALESCE(ap.versions_affected::text, '[]') AS versions_affected,
			v.published
		FROM vulnerabilities v
		LEFT JOIN LATERAL (
			SELECT ap.ecosystem, ap.name, ap.version_ranges, ap.versions_affected
			FROM affected_packages ap
			WHERE ap.vulnerability_id = v.id
			ORDER BY
				CASE
					WHEN jsonb_typeof(ap.version_ranges) = 'array' THEN jsonb_array_length(ap.version_ranges)
					ELSE 0
				END DESC,
				CASE
					WHEN jsonb_typeof(ap.versions_affected) = 'array' THEN jsonb_array_length(ap.versions_affected)
					ELSE 0
				END DESC,
				ap.id ASC
			LIMIT 1
		) ap ON true
		WHERE v.published >= NOW() - make_interval(days => $1)
		  AND v.withdrawn IS NULL
		ORDER BY v.published DESC, v.id DESC
		LIMIT $2`, days, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list recent vulnerabilities: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	var out []db.RecentVulnerability
	for rows.Next() {
		var r db.RecentVulnerability
		var versionRanges, versionsAffected string
		if err := rows.Scan(&r.ID, &r.Summary, &r.Severity, &r.Ecosystem, &r.Name, &versionRanges, &versionsAffected, &r.PublishedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan recent vulnerability row: %w", err)
		}
		r.Affected = summarizeAffectedVersions(versionRanges, versionsAffected)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CountScansByDay(ctx context.Context, days int) ([]db.DailyScanStats, error) {
	if days <= 0 {
		days = 7
	}

	rows, err := s.pool.Query(ctx, countScansByDaySQL, days)
	if err != nil {
		return nil, fmt.Errorf("postgres: count scans by day: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.DailyScanStats, 0, days)
	for rows.Next() {
		var (
			dayText       string
			scanCount     int
			findingsCount int
		)
		if err := rows.Scan(&dayText, &scanCount, &findingsCount); err != nil {
			return nil, fmt.Errorf("postgres: scan daily stats row: %w", err)
		}

		day, err := time.Parse("2006-01-02", dayText)
		if err != nil {
			return nil, fmt.Errorf("postgres: parse daily stats date %q: %w", dayText, err)
		}

		out = append(out, db.DailyScanStats{
			Date:          day.UTC(),
			ScanCount:     scanCount,
			FindingsCount: findingsCount,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate daily stats: %w", err)
	}
	return out, nil
}

func (s *Store) ScanTotals(ctx context.Context) (*db.ScanTotals, error) {
	totals := &db.ScanTotals{}
	if err := s.pool.QueryRow(ctx, `
		SELECT packages_scanned::int, findings::int
		FROM scan_log_totals
		WHERE id = TRUE`).Scan(&totals.PackagesScanned, &totals.Findings); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return totals, nil
		}
		return nil, fmt.Errorf("postgres: scan totals: %w", err)
	}
	return totals, nil
}

func (s *Store) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	stats := &db.DashboardStatsResult{
		BySeverity: make(map[string]int),
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*)
			 FROM (
				SELECT ap.ecosystem, ap.name
				FROM affected_packages ap
				INNER JOIN vulnerabilities v ON v.id = ap.vulnerability_id
				WHERE v.withdrawn IS NULL
				UNION
				SELECT ecosystem, name FROM malicious_findings WHERE removed_at IS NULL
				UNION
				SELECT ecosystem, name
				FROM package_reputation_cache
				WHERE status IN ('malicious', 'removed', 'risk')
				UNION
				SELECT m.ecosystem, m.name
				FROM lifecycle_package_map m
				INNER JOIN lifecycle_releases r ON r.product_slug = m.product_slug
				WHERE r.is_eol
				   OR (r.eol_from IS NOT NULL AND r.eol_from <= CURRENT_DATE)
				   OR (r.eol_from IS NOT NULL AND r.eol_from > CURRENT_DATE AND r.eol_from <= CURRENT_DATE + ($1::int * INTERVAL '1 day'))
				   OR r.is_eoas
				   OR (r.eoas_from IS NOT NULL AND r.eoas_from <= CURRENT_DATE)
			 ) AS packages)::int,
			(SELECT COUNT(*) FROM vulnerabilities WHERE withdrawn IS NULL)::int,
			(
				(SELECT COUNT(*) FROM malicious_findings WHERE removed_at IS NULL)
				+
				(SELECT COUNT(*) FROM package_reputation_cache WHERE status = 'malicious')
			)::int,
			(
				(SELECT COUNT(*) FROM package_reputation_cache WHERE status IN ('removed', 'risk'))
				+
				(SELECT COUNT(*)
				 FROM lifecycle_package_map m
				 INNER JOIN lifecycle_releases r ON r.product_slug = m.product_slug
				 WHERE r.is_eol
				    OR (r.eol_from IS NOT NULL AND r.eol_from <= CURRENT_DATE))
			)::int,
			(SELECT COUNT(*)
			 FROM lifecycle_package_map m
			 INNER JOIN lifecycle_releases r ON r.product_slug = m.product_slug
			 WHERE NOT (r.is_eol OR (r.eol_from IS NOT NULL AND r.eol_from <= CURRENT_DATE))
			   AND (
					(r.eol_from IS NOT NULL AND r.eol_from > CURRENT_DATE AND r.eol_from <= CURRENT_DATE + ($1::int * INTERVAL '1 day'))
					OR r.is_eoas
					OR (r.eoas_from IS NOT NULL AND r.eoas_from <= CURRENT_DATE)
			   ))::int`, lifecyclepolicy.EOLSoonDays).Scan(
		&stats.TotalPackages,
		&stats.TotalVulnerabilities,
		&stats.TotalMalicious,
		&stats.TotalSupplyChainRisk,
		&stats.TotalLifecycle,
	); err != nil {
		return nil, fmt.Errorf("postgres: dashboard totals: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT severity, COUNT(*)::int
		FROM (
			SELECT id, severity
			FROM vulnerabilities
			WHERE withdrawn IS NULL
			UNION ALL
			SELECT id, severity
			FROM malicious_findings
			WHERE removed_at IS NULL
			UNION ALL
			SELECT 'reputation:' || id::text AS id, severity
			FROM package_reputation_cache
			WHERE status IN ('malicious', 'removed', 'risk')
		) current_findings
		GROUP BY severity`)
	if err != nil {
		return nil, fmt.Errorf("postgres: dashboard severities: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		var (
			severity string
			count    int
		)
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("postgres: scan dashboard severity row: %w", err)
		}
		stats.BySeverity[normalizeSeverity(severity)] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate dashboard severities: %w", err)
	}
	return stats, nil
}
