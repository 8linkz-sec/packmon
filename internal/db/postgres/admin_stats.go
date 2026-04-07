package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) InsertScanLog(ctx context.Context, entry *db.ScanLogEntry) error {
	const query = `
		INSERT INTO scan_log (
			scan_id, repo_name, branch, commit, scanned_at,
			packages_count, findings_count, duration_ms, client_ip, user_agent
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::inet, $10)`

	_, err := s.pool.Exec(ctx, query,
		entry.ScanID,
		nullableString(entry.RepoName),
		nullableString(entry.Branch),
		nullableString(entry.Commit),
		entry.ScannedAt,
		entry.PackagesCount,
		entry.FindingsCount,
		entry.DurationMs,
		entry.ClientIP,
		nullableString(entry.UserAgent),
	)
	if err != nil {
		return fmt.Errorf("postgres: insert scan log: %w", err)
	}
	return nil
}

func (s *Store) ListRecentScans(ctx context.Context, limit int) ([]db.ScanLogEntry, error) {
	limit = clampLimit(limit, 15, 100)

	rows, err := s.pool.Query(ctx, `
		SELECT scan_id, repo_name, branch, commit, scanned_at, packages_count, findings_count, duration_ms,
		       COALESCE(client_ip::text, ''), COALESCE(user_agent, '')
		FROM scan_log
		ORDER BY scanned_at DESC, id DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list recent scans: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.ScanLogEntry, 0)
	for rows.Next() {
		var entry db.ScanLogEntry
		if err := rows.Scan(
			&entry.ScanID,
			&entry.RepoName,
			&entry.Branch,
			&entry.Commit,
			&entry.ScannedAt,
			&entry.PackagesCount,
			&entry.FindingsCount,
			&entry.DurationMs,
			&entry.ClientIP,
			&entry.UserAgent,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan recent scan row: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate recent scans: %w", err)
	}
	return out, nil
}

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
				jsonb_array_length(ap.version_ranges) DESC,
				jsonb_array_length(ap.versions_affected) DESC,
				ap.id ASC
			LIMIT 1
		) ap ON true
		WHERE v.published >= NOW() - make_interval(days => $1)
		ORDER BY v.published DESC, v.id DESC
		LIMIT $2`, days, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list recent vulnerabilities: %w", err)
	}
	defer closeSilently(rows)

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

	const query = `
		WITH days AS (
			SELECT generate_series(
				(timezone('UTC', NOW())::date - ($1 - 1)),
				timezone('UTC', NOW())::date,
				'1 day'::interval
			)::date AS day
		)
		SELECT
			days.day::text,
			COUNT(scan_log.id)::int,
			COALESCE(SUM(scan_log.findings_count), 0)::int
		FROM days
		LEFT JOIN scan_log
			ON timezone('UTC', scan_log.scanned_at)::date = days.day
		GROUP BY days.day
		ORDER BY days.day ASC`

	rows, err := s.pool.Query(ctx, query, days)
	if err != nil {
		return nil, fmt.Errorf("postgres: count scans by day: %w", err)
	}
	defer closeSilently(rows)

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

func (s *Store) SearchPackages(ctx context.Context, params db.PackageSearchParams) ([]db.PackageSearchResult, error) {
	query := strings.TrimSpace(params.Query)
	severity := strings.ToUpper(strings.TrimSpace(params.Severity))
	if severity != "" {
		severity = normalizeSeverity(severity)
	}
	findingType := strings.ToLower(strings.TrimSpace(params.FindingType))
	limit := clampLimit(params.Limit, 50, 200)
	if query == "" && severity == "" && findingType == "" {
		return []db.PackageSearchResult{}, nil
	}

	results := make(map[string]*db.PackageSearchResult)
	like := ""
	if query != "" {
		like = "%" + query + "%"
	}

	const vulnerabilityQuery = `
		SELECT
			ap.ecosystem,
			ap.name,
			COUNT(DISTINCT ap.vulnerability_id)::int,
			COUNT(DISTINCT ap.vulnerability_id)::int,
			COALESCE(string_agg(DISTINCT v.id, ', ' ORDER BY v.id), ''),
			COALESCE(string_agg(DISTINCT COALESCE(vs.source, 'unknown'), ', ' ORDER BY COALESCE(vs.source, 'unknown')), '')
		FROM affected_packages ap
		INNER JOIN vulnerabilities v ON v.id = ap.vulnerability_id
		LEFT JOIN vulnerability_sources vs ON vs.vulnerability_id = ap.vulnerability_id
		WHERE ($1 = '' OR ap.name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(v.severity, 'UNKNOWN')) = $2)
		GROUP BY ap.ecosystem, ap.name
		ORDER BY ap.name ASC, ap.ecosystem ASC
		LIMIT $3`

	if findingType == "" || findingType == "vulnerability" {
		if err := s.collectSearchResults(ctx, results, vulnerabilityQuery, like, severity, limit); err != nil {
			return nil, err
		}
	}

	const maliciousQuery = `
		SELECT
			ecosystem,
			name,
			COUNT(*)::int,
			0::int,
			''::text,
			COALESCE(string_agg(DISTINCT source, ', ' ORDER BY source), '')
		FROM malicious_findings
		WHERE ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(severity, 'UNKNOWN')) = $2)
		GROUP BY ecosystem, name
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	if findingType == "" || findingType == "malicious" {
		if err := s.collectSearchResults(ctx, results, maliciousQuery, like, severity, limit); err != nil {
			return nil, err
		}
	}

	out := make([]db.PackageSearchResult, 0, len(results))
	for _, result := range results {
		result.VulnerabilityIDs = joinSortedCSV(result.VulnerabilityIDs)
		result.Sources = joinSortedCSV(result.Sources)
		out = append(out, *result)
	}
	sortSearchResults(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) collectSearchResults(ctx context.Context, acc map[string]*db.PackageSearchResult, query string, args ...any) error {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("postgres: search packages: %w", err)
	}
	defer closeSilently(rows)

	for rows.Next() {
		var (
			ecosystem          string
			name               string
			findingsCount      int
			vulnerabilityCount int
			vulnerabilityIDs   string
			sources            string
		)
		if err := rows.Scan(&ecosystem, &name, &findingsCount, &vulnerabilityCount, &vulnerabilityIDs, &sources); err != nil {
			return fmt.Errorf("postgres: scan package search row: %w", err)
		}

		key := ecosystem + "\x00" + name
		if existing, ok := acc[key]; ok {
			existing.FindingsCount += findingsCount
			existing.VulnerabilityCount += vulnerabilityCount
			existing.VulnerabilityIDs = mergeCSV(existing.VulnerabilityIDs, vulnerabilityIDs)
			existing.Sources = mergeCSV(existing.Sources, sources)
			continue
		}
		acc[key] = &db.PackageSearchResult{
			Ecosystem:          ecosystem,
			Name:               name,
			FindingsCount:      findingsCount,
			VulnerabilityCount: vulnerabilityCount,
			VulnerabilityIDs:   vulnerabilityIDs,
			Sources:            sources,
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: iterate package search rows: %w", err)
	}
	return nil
}

func (s *Store) FindAPIKeyByHash(ctx context.Context, keyHash string) (*db.APIKey, error) {
	key, err := scanAPIKey(s.pool.QueryRow(ctx, `
		SELECT id, name, key_hash, created_at, revoked_at, last_used_at
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL`, keyHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find API key by hash: %w", err)
	}
	return key, nil
}

func (s *Store) TouchAPIKeyLastUsed(ctx context.Context, keyID int) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, keyID)
	if err != nil {
		return fmt.Errorf("postgres: touch API key last used: %w", err)
	}
	return nil
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]db.APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, key_hash, created_at, revoked_at, last_used_at
		FROM api_keys
		ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list API keys: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.APIKey, 0)
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan API key row: %w", err)
		}
		out = append(out, *key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate API keys: %w", err)
	}
	return out, nil
}

func (s *Store) CreateAPIKey(ctx context.Context, name, keyHash string) (int, error) {
	var id int
	err := s.pool.QueryRow(ctx,
		`INSERT INTO api_keys (name, key_hash) VALUES ($1, $2) RETURNING id`,
		name, keyHash,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("postgres: create API key: %w", err)
	}
	return id, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, keyID int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
		keyID,
	)
	if err != nil {
		return fmt.Errorf("postgres: revoke API key %d: %w", keyID, err)
	}
	return nil
}

func (s *Store) DeleteAPIKey(ctx context.Context, keyID int) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM api_keys WHERE id = $1 AND revoked_at IS NOT NULL`,
		keyID,
	)
	if err != nil {
		return fmt.Errorf("postgres: delete API key %d: %w", keyID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: delete API key %d: key not found or not revoked", keyID)
	}
	return nil
}

func (s *Store) GetAdminAuth(ctx context.Context) (*db.AdminAuth, error) {
	const query = `
		SELECT password_hash, password_is_bootstrap, created_at, password_changed_at, last_login_at
		FROM admin_auth
		WHERE id = 1`

	var (
		authInfo          db.AdminAuth
		passwordChangedAt *time.Time
		lastLoginAt       *time.Time
	)

	err := s.pool.QueryRow(ctx, query).Scan(
		&authInfo.PasswordHash,
		&authInfo.PasswordIsBootstrap,
		&authInfo.CreatedAt,
		&passwordChangedAt,
		&lastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get admin auth: %w", err)
	}

	authInfo.PasswordChangedAt = passwordChangedAt
	authInfo.LastLoginAt = lastLoginAt
	return &authInfo, nil
}

func (s *Store) UpsertAdminAuth(ctx context.Context, passwordHash string, isBootstrap bool) error {
	const query = `
		INSERT INTO admin_auth (id, username, password_hash, password_is_bootstrap)
		VALUES (1, 'admin', $1, $2)
		ON CONFLICT (id) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			password_is_bootstrap = EXCLUDED.password_is_bootstrap,
			password_changed_at = NOW()`

	_, err := s.pool.Exec(ctx, query, passwordHash, isBootstrap)
	if err != nil {
		return fmt.Errorf("postgres: upsert admin auth: %w", err)
	}
	return nil
}

func (s *Store) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO admin_audit_log (action, details, ip) VALUES ($1, $2, NULLIF($3, '')::inet)`,
			entry.Action,
			normalizeJSON(entry.Details, nil),
			entry.IP,
		); err != nil {
			return fmt.Errorf("insert admin audit log: %w", err)
		}

		if entry.Action == "login_success" {
			if _, err := tx.Exec(ctx, `UPDATE admin_auth SET last_login_at = NOW() WHERE id = 1`); err != nil {
				return fmt.Errorf("update admin last_login_at: %w", err)
			}
		}
		return nil
	})
}

func (s *Store) ListAdminAuditLog(ctx context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	limit = clampLimit(limit, 100, 200)

	rows, err := s.pool.Query(ctx, `
		SELECT id, action, details::text, COALESCE(ip::text, ''), created_at
		FROM admin_audit_log
		ORDER BY created_at DESC, id DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: list admin audit log: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.AdminAuditLogEntry, 0)
	for rows.Next() {
		var (
			item       db.AdminAuditLogEntry
			detailsRaw *string
		)
		if err := rows.Scan(&item.ID, &item.Action, &detailsRaw, &item.IP, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan admin audit row: %w", err)
		}
		if detailsRaw != nil {
			item.Details = []byte(*detailsRaw)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate admin audit log: %w", err)
	}
	return out, nil
}

func (s *Store) QueueStats(ctx context.Context) (*db.QueueStatsResult, error) {
	stats := &db.QueueStatsResult{}
	if err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'pending')::int,
			COUNT(*) FILTER (WHERE status = 'processing')::int,
			COUNT(*) FILTER (WHERE status = 'done')::int,
			COUNT(*) FILTER (WHERE status = 'error')::int
		FROM refresh_queue`).Scan(&stats.Pending, &stats.Processing, &stats.Done, &stats.Error); err != nil {
		return nil, fmt.Errorf("postgres: queue stats: %w", err)
	}
	return stats, nil
}

func (s *Store) ListQueueJobs(ctx context.Context, status string, limit int) ([]db.RefreshJob, error) {
	limit = clampLimit(limit, 50, 1000)

	query := `
		SELECT id, ecosystem, name, source, priority, status, requested_at, processed_at, error
		FROM refresh_queue`
	args := []any{}
	if status != "" {
		query += ` WHERE status = $1`
		args = append(args, status)
	}
	query += fmt.Sprintf(` ORDER BY requested_at DESC, id DESC LIMIT $%d`, len(args)+1)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list queue jobs: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.RefreshJob, 0)
	for rows.Next() {
		var (
			item        db.RefreshJob
			processedAt *time.Time
			errorText   *string
		)
		if err := rows.Scan(
			&item.ID,
			&item.Ecosystem,
			&item.Name,
			&item.Source,
			&item.Priority,
			&item.Status,
			&item.RequestedAt,
			&processedAt,
			&errorText,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan queue job row: %w", err)
		}
		item.ProcessedAt = processedAt
		if errorText != nil {
			item.Error = *errorText
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate queue jobs: %w", err)
	}
	return out, nil
}

func (s *Store) PurgeQueue(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM refresh_queue WHERE status IN ('done', 'error')`)
	if err != nil {
		return 0, fmt.Errorf("postgres: purge queue: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) DashboardStats(ctx context.Context) (*db.DashboardStatsResult, error) {
	stats := &db.DashboardStatsResult{
		BySeverity: make(map[string]int),
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*)
			 FROM (
				SELECT ecosystem, name FROM affected_packages
				UNION
				SELECT ecosystem, name FROM malicious_findings
			 ) AS packages)::int,
			(SELECT COUNT(*) FROM vulnerabilities)::int,
			(SELECT COUNT(*) FROM malicious_findings)::int`).Scan(
		&stats.TotalPackages,
		&stats.TotalVulnerabilities,
		&stats.TotalMalicious,
	); err != nil {
		return nil, fmt.Errorf("postgres: dashboard totals: %w", err)
	}

	// Only count vulnerability severities for the dashboard chart.
	// Malicious findings are always CRITICAL and shown separately in
	// the "Malicious Packages" card to avoid inflating the severity
	// distribution.
	rows, err := s.pool.Query(ctx, `
		SELECT severity, COUNT(*)::int
		FROM vulnerabilities
		GROUP BY severity`)
	if err != nil {
		return nil, fmt.Errorf("postgres: dashboard severities: %w", err)
	}
	defer closeSilently(rows)

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
