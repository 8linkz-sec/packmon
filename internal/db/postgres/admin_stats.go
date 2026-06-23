package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	lifecyclepolicy "github.com/8linkz-sec/packmon/internal/lifecycle"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Store) InsertScanLog(ctx context.Context, entry *db.ScanLogEntry) error {
	feedVersionsJSON, err := scanLogJSON(entry.FeedVersions, map[string]string{})
	if err != nil {
		return err
	}
	findingIDsJSON, err := scanLogJSON(entry.FindingIDs, []string{})
	if err != nil {
		return err
	}
	findingSeveritiesJSON, err := scanLogJSON(entry.FindingSeverities, []string{})
	if err != nil {
		return err
	}

	const query = `
		WITH inserted AS (
		INSERT INTO scan_log (
			scan_id, repo_name, branch, commit, scanned_at,
			packages_count, findings_count, duration_ms, client_ip, user_agent,
			api_key_id, api_key_name, correlation_id, idempotency_key, request_digest, result_digest,
			findings_blocking, block_threshold, feed_status, feed_versions, finding_ids, finding_severities,
			manual_advisories_count
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::inet, $10,
			NULLIF($11, 0), NULLIF($12, ''), $13, NULLIF($14, ''), $15, $16, $17, $18, $19,
			$20::jsonb, $21::jsonb, $22::jsonb, $23
		)
		ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
		RETURNING packages_count, findings_count
		)
		INSERT INTO scan_log_totals (id, packages_scanned, findings)
		SELECT TRUE, packages_count, findings_count
		FROM inserted
		ON CONFLICT (id) DO UPDATE SET
			packages_scanned = scan_log_totals.packages_scanned + EXCLUDED.packages_scanned,
			findings = scan_log_totals.findings + EXCLUDED.findings,
			updated_at = NOW()`

	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query,
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
			entry.APIKeyID,
			entry.APIKeyName,
			entry.CorrelationID,
			entry.IdempotencyKey,
			entry.RequestDigest,
			entry.ResultDigest,
			entry.FindingsBlocking,
			entry.BlockThreshold,
			entry.FeedStatus,
			string(feedVersionsJSON),
			string(findingIDsJSON),
			string(findingSeveritiesJSON),
			entry.ManualAdvisoriesCount,
		); err != nil {
			return fmt.Errorf("postgres: insert scan log: %w", err)
		}

		return nil
	})
}

func (s *Store) GetScanLogByIdempotencyKey(ctx context.Context, key string) (*db.ScanLogEntry, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, nil
	}
	var entry db.ScanLogEntry
	err := s.pool.QueryRow(ctx, `
		SELECT scan_id, COALESCE(request_digest, ''), COALESCE(result_digest, '')
		FROM scan_log
		WHERE idempotency_key = $1
		ORDER BY id DESC
		LIMIT 1`, key).Scan(&entry.ScanID, &entry.RequestDigest, &entry.ResultDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get scan log by idempotency key: %w", err)
	}
	entry.IdempotencyKey = key
	return &entry, nil
}

func (s *Store) ListRecentScans(ctx context.Context, limit int) ([]db.ScanLogEntry, error) {
	limit = clampLimit(limit, 15, 100)

	rows, err := s.pool.Query(ctx, `
		SELECT scan_id, COALESCE(repo_name, ''), COALESCE(branch, ''), COALESCE(commit, ''), scanned_at, packages_count, findings_count, duration_ms,
		       COALESCE(client_ip::text, ''), COALESCE(user_agent, ''), COALESCE(api_key_id, 0), COALESCE(api_key_name, ''),
		       COALESCE(correlation_id, ''), COALESCE(idempotency_key, ''), COALESCE(request_digest, ''), COALESCE(result_digest, ''),
		       findings_blocking, COALESCE(block_threshold, ''), COALESCE(feed_status, ''),
		       COALESCE(feed_versions, '{}'::jsonb)::text, COALESCE(finding_ids, '[]'::jsonb)::text,
		       COALESCE(finding_severities, '[]'::jsonb)::text, manual_advisories_count
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
		var feedVersionsJSON string
		var findingIDsJSON string
		var findingSeveritiesJSON string
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
			&entry.APIKeyID,
			&entry.APIKeyName,
			&entry.CorrelationID,
			&entry.IdempotencyKey,
			&entry.RequestDigest,
			&entry.ResultDigest,
			&entry.FindingsBlocking,
			&entry.BlockThreshold,
			&entry.FeedStatus,
			&feedVersionsJSON,
			&findingIDsJSON,
			&findingSeveritiesJSON,
			&entry.ManualAdvisoriesCount,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan recent scan row: %w", err)
		}
		if err := decodeScanLogJSON(feedVersionsJSON, &entry.FeedVersions); err != nil {
			return nil, fmt.Errorf("postgres: decode scan log feed versions: %w", err)
		}
		if err := decodeScanLogJSON(findingIDsJSON, &entry.FindingIDs); err != nil {
			return nil, fmt.Errorf("postgres: decode scan log finding ids: %w", err)
		}
		if err := decodeScanLogJSON(findingSeveritiesJSON, &entry.FindingSeverities); err != nil {
			return nil, fmt.Errorf("postgres: decode scan log finding severities: %w", err)
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate recent scans: %w", err)
	}
	return out, nil
}

func (s *Store) PruneScanLogs(ctx context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	var removed int
	var packagesScanned int
	var findings int
	if err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			WITH deleted AS (
				DELETE FROM scan_log
				WHERE scanned_at < $1
				RETURNING packages_count, findings_count
			)
			SELECT
				COUNT(*)::int,
				COALESCE(SUM(packages_count), 0)::int,
				COALESCE(SUM(findings_count), 0)::int
			FROM deleted`, cutoff).Scan(&removed, &packagesScanned, &findings); err != nil {
			return fmt.Errorf("postgres: prune scan logs: %w", err)
		}
		if removed == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_log_totals (id, packages_scanned, findings)
			VALUES (TRUE, 0, 0)
			ON CONFLICT (id) DO NOTHING`); err != nil {
			return fmt.Errorf("postgres: ensure scan totals row: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE scan_log_totals
			SET
				packages_scanned = GREATEST(0, packages_scanned - $1),
				findings = GREATEST(0, findings - $2),
				updated_at = NOW()
			WHERE id = TRUE`, packagesScanned, findings); err != nil {
			return fmt.Errorf("postgres: decrement scan totals: %w", err)
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return removed, nil
}

func scanLogJSON(value, fallback any) ([]byte, error) {
	switch typed := value.(type) {
	case map[string]string:
		if typed == nil {
			value = fallback
		}
	case []string:
		if typed == nil {
			value = fallback
		}
	}
	out, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode scan log json: %w", err)
	}
	return out, nil
}

func decodeScanLogJSON(raw string, target any) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = "null"
	}
	return json.Unmarshal([]byte(raw), target)
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
			''::text AS version,
			COUNT(DISTINCT ap.vulnerability_id)::int,
			COUNT(DISTINCT ap.vulnerability_id)::int,
			COALESCE((
				SELECT string_agg(preview_id, ', ' ORDER BY preview_id)
				FROM (
					SELECT DISTINCT v_preview.id AS preview_id
					FROM affected_packages ap_preview
					INNER JOIN vulnerabilities v_preview ON v_preview.id = ap_preview.vulnerability_id
					WHERE ap_preview.ecosystem = ap.ecosystem
					  AND ap_preview.name = ap.name
					  AND ($1 = '' OR ap_preview.name ILIKE $1)
					  AND ($2 = '' OR UPPER(COALESCE(v_preview.severity, 'UNKNOWN')) = $2)
					  AND v_preview.withdrawn IS NULL
					ORDER BY v_preview.id
					LIMIT $4
				) preview
			), ''),
			COALESCE(string_agg(DISTINCT COALESCE(vs.source, 'unknown'), ', ' ORDER BY COALESCE(vs.source, 'unknown')), ''),
			'vulnerability'::text
		FROM affected_packages ap
		INNER JOIN vulnerabilities v ON v.id = ap.vulnerability_id
		LEFT JOIN vulnerability_sources vs ON vs.vulnerability_id = ap.vulnerability_id
		WHERE ($1 = '' OR ap.name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(v.severity, 'UNKNOWN')) = $2)
		  AND v.withdrawn IS NULL
		GROUP BY ap.ecosystem, ap.name
		ORDER BY ap.name ASC, ap.ecosystem ASC
		LIMIT $3`

	if findingType == "" || findingType == "vulnerability" {
		if err := s.collectSearchResults(ctx, results, vulnerabilityQuery, like, severity, limit, db.SearchVulnerabilityIDPreviewLimit); err != nil {
			return nil, err
		}
	}

	const maliciousQuery = `
		SELECT
			ecosystem,
			name,
			''::text AS version,
			COUNT(*)::int,
			0::int,
			''::text,
			COALESCE(string_agg(DISTINCT source, ', ' ORDER BY source), ''),
			'malicious'::text
		FROM malicious_findings
		WHERE ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(severity, 'UNKNOWN')) = $2)
		  AND removed_at IS NULL
		GROUP BY ecosystem, name
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	if findingType == "" || findingType == "malicious" {
		if err := s.collectSearchResults(ctx, results, maliciousQuery, like, severity, limit); err != nil {
			return nil, err
		}
	}

	const reputationMaliciousQuery = `
		SELECT
			ecosystem,
			name,
			version,
			COUNT(*)::int,
			0::int,
			''::text,
			COALESCE(string_agg(DISTINCT source, ', ' ORDER BY source), ''),
			'malicious'::text
		FROM package_reputation_cache
		WHERE status = 'malicious'
		  AND ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(severity, 'UNKNOWN')) = $2)
		GROUP BY ecosystem, name, version
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	if findingType == "" || findingType == "malicious" {
		if err := s.collectSearchResults(ctx, results, reputationMaliciousQuery, like, severity, limit); err != nil {
			return nil, err
		}
	}

	const supplyChainQuery = `
		SELECT
			ecosystem,
			name,
			version,
			COUNT(*)::int,
			0::int,
			''::text,
			COALESCE(string_agg(DISTINCT source, ', ' ORDER BY source), ''),
			'supply_chain_risk'::text
		FROM package_reputation_cache
		WHERE status IN ('removed', 'risk')
		  AND ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR UPPER(COALESCE(severity, 'UNKNOWN')) = $2)
		GROUP BY ecosystem, name, version
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	if findingType == "" || findingType == "supply_chain_risk" {
		if err := s.collectSearchResults(ctx, results, supplyChainQuery, like, severity, limit); err != nil {
			return nil, err
		}
	}

	const lifecycleSupplyChainQuery = `
		WITH lifecycle_findings AS (
			SELECT
				m.ecosystem,
				m.name,
				COALESCE(NULLIF(r.latest, ''), r.cycle) AS version,
				$4::text AS severity
			FROM lifecycle_package_map m
			INNER JOIN lifecycle_releases r ON r.product_slug = m.product_slug
			WHERE r.is_eol OR (r.eol_from IS NOT NULL AND r.eol_from <= CURRENT_DATE)
		)
		SELECT
			ecosystem,
			name,
			version,
			COUNT(*)::int,
			0::int,
			''::text,
			'endoflife.date'::text,
			'supply_chain_risk'::text
		FROM lifecycle_findings
		WHERE ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR severity = $2)
		GROUP BY ecosystem, name, version
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	if findingType == "" || findingType == "supply_chain_risk" {
		if err := s.collectSearchResults(ctx, results, lifecycleSupplyChainQuery,
			like, severity, limit, string(lifecyclepolicy.SeverityEOL)); err != nil {
			return nil, err
		}
	}

	const lifecycleQuery = `
		WITH lifecycle_findings AS (
			SELECT
				m.ecosystem,
				m.name,
				COALESCE(NULLIF(r.latest, ''), r.cycle) AS version,
				CASE
					WHEN r.eol_from IS NOT NULL AND r.eol_from > CURRENT_DATE AND r.eol_from <= CURRENT_DATE + ($4::int * INTERVAL '1 day') THEN $5::text
					WHEN r.is_eoas OR (r.eoas_from IS NOT NULL AND r.eoas_from <= CURRENT_DATE) THEN $6::text
					ELSE ''
				END AS severity
			FROM lifecycle_package_map m
			INNER JOIN lifecycle_releases r ON r.product_slug = m.product_slug
			WHERE NOT (r.is_eol OR (r.eol_from IS NOT NULL AND r.eol_from <= CURRENT_DATE))
		)
		SELECT
			ecosystem,
			name,
			version,
			COUNT(*)::int,
			0::int,
			''::text,
			'endoflife.date'::text,
			'lifecycle'::text
		FROM lifecycle_findings
		WHERE severity <> ''
		  AND ($1 = '' OR name ILIKE $1)
		  AND ($2 = '' OR severity = $2)
		GROUP BY ecosystem, name, version
		ORDER BY name ASC, ecosystem ASC
		LIMIT $3`

	if findingType == "" || findingType == "lifecycle" {
		if err := s.collectSearchResults(ctx, results, lifecycleQuery,
			like, severity, limit,
			lifecyclepolicy.EOLSoonDays,
			string(lifecyclepolicy.SeverityEOLSoon),
			string(lifecyclepolicy.SeveritySecuritySupportOnly)); err != nil {
			return nil, err
		}
	}

	out := make([]db.PackageSearchResult, 0, len(results))
	for _, result := range results {
		result.VulnerabilityIDs = joinSortedCSV(result.VulnerabilityIDs)
		result.VulnerabilityIDs = db.FormatSearchVulnerabilityIDPreview(result.VulnerabilityIDs, result.VulnerabilityCount)
		result.Sources = joinSortedCSV(result.Sources)
		result.FindingTypes = joinSortedCSV(result.FindingTypes)
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
			version            string
			findingsCount      int
			vulnerabilityCount int
			vulnerabilityIDs   string
			sources            string
			findingTypes       string
		)
		if err := rows.Scan(&ecosystem, &name, &version, &findingsCount, &vulnerabilityCount, &vulnerabilityIDs, &sources, &findingTypes); err != nil {
			return fmt.Errorf("postgres: scan package search row: %w", err)
		}

		key := ecosystem + "\x00" + name + "\x00" + version
		if existing, ok := acc[key]; ok {
			existing.FindingsCount += findingsCount
			existing.VulnerabilityCount += vulnerabilityCount
			existing.VulnerabilityIDs = mergeCSV(existing.VulnerabilityIDs, vulnerabilityIDs)
			existing.Sources = mergeCSV(existing.Sources, sources)
			existing.FindingTypes = mergeCSV(existing.FindingTypes, findingTypes)
			continue
		}
		acc[key] = &db.PackageSearchResult{
			Ecosystem:          ecosystem,
			Name:               name,
			Version:            version,
			FindingsCount:      findingsCount,
			VulnerabilityCount: vulnerabilityCount,
			VulnerabilityIDs:   vulnerabilityIDs,
			Sources:            sources,
			FindingTypes:       findingTypes,
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: iterate package search rows: %w", err)
	}
	return nil
}

func (s *Store) FindAPIKeyByHash(ctx context.Context, keyHash string) (*db.APIKey, error) {
	key, err := scanAPIKey(s.pool.QueryRow(ctx, `
		SELECT id, name, key_hash, created_at, revoked_at, last_used_at, expires_at, deleted_at
		FROM api_keys
		WHERE key_hash = $1
		  AND revoked_at IS NULL
		  AND deleted_at IS NULL
		  AND (expires_at IS NULL OR expires_at > NOW())`, keyHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: find API key by hash: %w", err)
	}
	return key, nil
}

func (s *Store) TouchAPIKeyLastUsed(ctx context.Context, keyID int) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1 AND deleted_at IS NULL`, keyID)
	if err != nil {
		return fmt.Errorf("postgres: touch API key last used: %w", err)
	}
	return nil
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]db.APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, key_hash, created_at, revoked_at, last_used_at, expires_at, deleted_at
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

func (s *Store) CreateAPIKey(ctx context.Context, name, keyHash string, expiresAt *time.Time) (int, error) {
	return createAPIKeyTx(ctx, s.pool, name, keyHash, expiresAt)
}

func (s *Store) CreateAPIKeyWithAudit(ctx context.Context, name, keyHash string, expiresAt *time.Time, audit *db.AdminAuditEntry) (int, error) {
	var id int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		id, err = createAPIKeyTx(ctx, tx, name, keyHash, expiresAt)
		if err != nil {
			return err
		}
		if err := db.SetAdminAuditDetail(audit, "key_id", strconv.Itoa(id)); err != nil {
			return fmt.Errorf("postgres: encode API key create audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	return id, err
}

type postgresQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func createAPIKeyTx(ctx context.Context, q postgresQuerier, name, keyHash string, expiresAt *time.Time) (int, error) {
	var id int
	err := q.QueryRow(ctx,
		`INSERT INTO api_keys (name, key_hash, expires_at) VALUES ($1, $2, $3) RETURNING id`,
		name, keyHash, expiresAt,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("postgres: create API key: %w", err)
	}
	return id, nil
}

func (s *Store) RevokeAPIKey(ctx context.Context, keyID int) error {
	return revokeAPIKeyTx(ctx, s.pool, keyID)
}

func (s *Store) RevokeAPIKeyWithAudit(ctx context.Context, keyID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := revokeAPIKeyTx(ctx, tx, keyID); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

type postgresExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type postgresQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func revokeAPIKeyTx(ctx context.Context, execer postgresExecer, keyID int) error {
	tag, err := execer.Exec(ctx,
		`UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL AND deleted_at IS NULL`,
		keyID,
	)
	if err != nil {
		return fmt.Errorf("postgres: revoke API key %d: %w", keyID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: revoke API key %d: key not found or already revoked", keyID)
	}
	return nil
}

func (s *Store) DeleteAPIKey(ctx context.Context, keyID int) error {
	return deleteAPIKeyTx(ctx, s.pool, keyID)
}

func (s *Store) DeleteAPIKeyWithAudit(ctx context.Context, keyID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := deleteAPIKeyTx(ctx, tx, keyID); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func deleteAPIKeyTx(ctx context.Context, execer postgresExecer, keyID int) error {
	tag, err := execer.Exec(ctx,
		`UPDATE api_keys SET deleted_at = NOW() WHERE id = $1 AND revoked_at IS NOT NULL AND deleted_at IS NULL`,
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
	return upsertAdminAuthTx(ctx, s.pool, passwordHash, isBootstrap)
}

func (s *Store) UpsertAdminAuthWithAudit(ctx context.Context, passwordHash string, isBootstrap bool, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := upsertAdminAuthTx(ctx, tx, passwordHash, isBootstrap); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func upsertAdminAuthTx(ctx context.Context, execer postgresExecer, passwordHash string, isBootstrap bool) error {
	const query = `
		INSERT INTO admin_auth (id, username, password_hash, password_is_bootstrap)
		VALUES (1, 'admin', $1, $2)
		ON CONFLICT (id) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			password_is_bootstrap = EXCLUDED.password_is_bootstrap,
			password_changed_at = NOW()`

	_, err := execer.Exec(ctx, query, passwordHash, isBootstrap)
	if err != nil {
		return fmt.Errorf("postgres: upsert admin auth: %w", err)
	}
	return nil
}

func (s *Store) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return insertAdminAuditLogTx(ctx, tx, entry)
	})
}

func insertAdminAuditLogTx(ctx context.Context, tx pgx.Tx, entry *db.AdminAuditEntry) error {
	if _, err := tx.Exec(ctx, `LOCK TABLE admin_audit_log IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("lock admin audit log: %w", err)
	}

	var id int
	if err := tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('admin_audit_log', 'id'))::int`).Scan(&id); err != nil {
		return fmt.Errorf("reserve admin audit id: %w", err)
	}

	previousDigest := ""
	err := tx.QueryRow(ctx, `
		SELECT row_digest
		FROM admin_audit_log
		ORDER BY id DESC
		LIMIT 1`).Scan(&previousDigest)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read previous admin audit digest: %w", err)
	}

	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	var (
		detailsText string
		ipText      string
	)
	if err := tx.QueryRow(ctx,
		`INSERT INTO admin_audit_log (id, action, details, ip, created_at, previous_digest, row_digest)
		 VALUES ($1, $2, $3, NULLIF($4, '')::inet, $5, $6, '')
		 RETURNING COALESCE(details::text, ''), COALESCE(ip::text, ''), created_at`,
		id,
		entry.Action,
		normalizeJSON(entry.Details, nil),
		entry.IP,
		createdAt,
		previousDigest,
	).Scan(&detailsText, &ipText, &createdAt); err != nil {
		return fmt.Errorf("insert admin audit log: %w", err)
	}

	auditEntry := db.AdminAuditLogEntry{
		ID:             id,
		Action:         entry.Action,
		Details:        json.RawMessage(detailsText),
		IP:             ipText,
		CreatedAt:      createdAt,
		PreviousDigest: previousDigest,
	}
	rowDigest := db.ComputeAdminAuditDigest(auditEntry)
	if _, err := tx.Exec(ctx, `UPDATE admin_audit_log SET row_digest = $1 WHERE id = $2`, rowDigest, id); err != nil {
		return fmt.Errorf("update admin audit digest: %w", err)
	}

	if entry.Action == "login_success" {
		if _, err := tx.Exec(ctx, `UPDATE admin_auth SET last_login_at = NOW() WHERE id = 1`); err != nil {
			return fmt.Errorf("update admin last_login_at: %w", err)
		}
	}
	return nil
}

func (s *Store) ListAdminAuditLog(ctx context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	return s.ListAdminAuditLogPage(ctx, limit, 0)
}

func (s *Store) ListAdminAuditLogPage(ctx context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error) {
	limit = clampLimit(limit, 100, 200)
	if offset < 0 {
		offset = 0
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, action, details::text, COALESCE(ip::text, ''), created_at, previous_digest, row_digest
		FROM admin_audit_log
		ORDER BY created_at DESC, id DESC
		LIMIT $1 OFFSET $2`, limit, offset)
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
		if err := rows.Scan(&item.ID, &item.Action, &detailsRaw, &item.IP, &item.CreatedAt, &item.PreviousDigest, &item.RowDigest); err != nil {
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
	db.AnnotateAdminAuditIntegrity(out)
	return out, nil
}

func (s *Store) PruneAdminAuditLogs(ctx context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	tag, err := s.pool.Exec(ctx, `DELETE FROM admin_audit_log WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune admin audit logs: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) QueueStats(ctx context.Context) (*db.QueueStatsResult, error) {
	stats := &db.QueueStatsResult{}
	if err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status = 'pending')::int,
			COUNT(*) FILTER (WHERE status = 'processing')::int,
			COUNT(*) FILTER (WHERE status = 'done')::int,
			COUNT(*) FILTER (WHERE status = 'error')::int,
			COUNT(*) FILTER (WHERE status = 'paused')::int
		FROM refresh_queue`).Scan(&stats.Pending, &stats.Processing, &stats.Done, &stats.Error, &stats.Paused); err != nil {
		return nil, fmt.Errorf("postgres: queue stats: %w", err)
	}
	return stats, nil
}

func (s *Store) OldestQueueJobs(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT source, MIN(requested_at)
		FROM refresh_queue
		WHERE status IN ('pending', 'processing')
		  AND source <> ''
		GROUP BY source`)
	if err != nil {
		return nil, fmt.Errorf("postgres: oldest queue jobs: %w", err)
	}
	defer closeSilently(rows)

	out := make(map[string]time.Time)
	for rows.Next() {
		var source string
		var requestedAt time.Time
		if err := rows.Scan(&source, &requestedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan oldest queue job: %w", err)
		}
		out[source] = requestedAt
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate oldest queue jobs: %w", err)
	}
	return out, nil
}

func (s *Store) ListQueueJobs(ctx context.Context, status string, limit int) ([]db.RefreshJob, error) {
	return s.ListQueueJobsPage(ctx, status, limit, 0)
}

func (s *Store) ListQueueJobsPage(ctx context.Context, status string, limit, offset int) ([]db.RefreshJob, error) {
	limit = clampLimit(limit, 50, 1000)
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, ecosystem, name, source, priority, status, requested_at, processed_at, error
		FROM refresh_queue`
	args := []any{}
	if status != "" {
		query += ` WHERE status = $1`
		args = append(args, status)
	}
	query += fmt.Sprintf(` ORDER BY requested_at DESC, id DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, limit, offset)

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
	return purgeQueueTx(ctx, s.pool)
}

func (s *Store) PruneRefreshQueue(ctx context.Context, retention time.Duration) (int, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM refresh_queue
		WHERE status IN ('done', 'error')
		  AND COALESCE(processed_at, requested_at) < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune refresh queue: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) PurgeQueueWithAudit(ctx context.Context, audit *db.AdminAuditEntry) (int, error) {
	var purged int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		jobs, err := queueJobsForStatusesTx(ctx, tx, []string{"done", "error"})
		if err != nil {
			return err
		}
		if err := db.SetAdminAuditQueueJobsDetail(audit, "purged_jobs", jobs); err != nil {
			return fmt.Errorf("postgres: encode queue purge audit job details: %w", err)
		}
		purged, err = purgeQueueTx(ctx, tx)
		if err != nil {
			return err
		}
		if err := db.SetAdminAuditDetail(audit, "purged", strconv.Itoa(purged)); err != nil {
			return fmt.Errorf("postgres: encode queue purge audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	return purged, err
}

func purgeQueueTx(ctx context.Context, execer postgresExecer) (int, error) {
	tag, err := execer.Exec(ctx, `DELETE FROM refresh_queue WHERE status IN ('done', 'error')`)
	if err != nil {
		return 0, fmt.Errorf("postgres: purge queue: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) UpdateQueueJobPriority(ctx context.Context, jobID, priority int) error {
	return updateQueueJobPriorityTx(ctx, s.pool, jobID, priority)
}

func (s *Store) UpdateQueueJobPriorityWithAudit(ctx context.Context, jobID, priority int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := updateQueueJobPriorityTx(ctx, tx, jobID, priority); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func updateQueueJobPriorityTx(ctx context.Context, execer postgresExecer, jobID, priority int) error {
	tag, err := execer.Exec(ctx, `UPDATE refresh_queue SET priority = $2 WHERE id = $1`, jobID, priority)
	if err != nil {
		return fmt.Errorf("postgres: update queue job %d priority: %w", jobID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: update queue job %d priority: job not found", jobID)
	}
	return nil
}

func (s *Store) RetryQueueJob(ctx context.Context, jobID int) error {
	return retryQueueJobTx(ctx, s.pool, jobID)
}

func (s *Store) RetryQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := retryQueueJobTx(ctx, tx, jobID); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func retryQueueJobTx(ctx context.Context, execer postgresExecer, jobID int) error {
	tag, err := execer.Exec(ctx, `
		UPDATE refresh_queue
		SET status = 'pending', requested_at = NOW(), processed_at = NULL, error = NULL
		WHERE id = $1 AND status IN ('done', 'error', 'paused')`, jobID)
	if err != nil {
		return fmt.Errorf("postgres: retry queue job %d: %w", jobID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: retry queue job %d: job not found or not retryable", jobID)
	}
	return nil
}

func (s *Store) PauseQueueJob(ctx context.Context, jobID int) error {
	return pauseQueueJobTx(ctx, s.pool, jobID)
}

func (s *Store) PauseQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := pauseQueueJobTx(ctx, tx, jobID); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func pauseQueueJobTx(ctx context.Context, execer postgresExecer, jobID int) error {
	tag, err := execer.Exec(ctx, `UPDATE refresh_queue SET status = 'paused' WHERE id = $1 AND status = 'pending'`, jobID)
	if err != nil {
		return fmt.Errorf("postgres: pause queue job %d: %w", jobID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: pause queue job %d: job not found or not pending", jobID)
	}
	return nil
}

func (s *Store) ResumeQueueJob(ctx context.Context, jobID int) error {
	return resumeQueueJobTx(ctx, s.pool, jobID)
}

func (s *Store) ResumeQueueJobWithAudit(ctx context.Context, jobID int, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := resumeQueueJobTx(ctx, tx, jobID); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
}

func resumeQueueJobTx(ctx context.Context, execer postgresExecer, jobID int) error {
	tag, err := execer.Exec(ctx, `UPDATE refresh_queue SET status = 'pending', processed_at = NULL, error = NULL WHERE id = $1 AND status = 'paused'`, jobID)
	if err != nil {
		return fmt.Errorf("postgres: resume queue job %d: %w", jobID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("postgres: resume queue job %d: job not found or not paused", jobID)
	}
	return nil
}

func (s *Store) ClearQueue(ctx context.Context, statuses []string) (int, error) {
	return clearQueueTx(ctx, s.pool, statuses)
}

func (s *Store) ClearQueueWithAudit(ctx context.Context, statuses []string, audit *db.AdminAuditEntry) (int, error) {
	var cleared int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		normalized := normalizeQueueStatuses(statuses)
		jobs, err := queueJobsForStatusesTx(ctx, tx, normalized)
		if err != nil {
			return err
		}
		if err := db.SetAdminAuditQueueJobsDetail(audit, "cleared_jobs", jobs); err != nil {
			return fmt.Errorf("postgres: encode queue clear audit job details: %w", err)
		}
		cleared, err = clearQueueTx(ctx, tx, normalized)
		if err != nil {
			return err
		}
		if err := db.SetAdminAuditDetail(audit, "cleared", strconv.Itoa(cleared)); err != nil {
			return fmt.Errorf("postgres: encode queue clear audit details: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	return cleared, err
}

func queueJobsForStatusesTx(ctx context.Context, queryer postgresQueryer, statuses []string) ([]db.RefreshJob, error) {
	statuses = normalizeQueueStatuses(statuses)
	if len(statuses) == 0 {
		return nil, nil
	}

	placeholders := make([]string, 0, len(statuses))
	args := make([]any, 0, len(statuses))
	for i, status := range statuses {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
		args = append(args, status)
	}

	query := fmt.Sprintf(`
		SELECT id, ecosystem, name, source, priority, status, requested_at, processed_at, error
		FROM refresh_queue
		WHERE status IN (%s)
		ORDER BY id`, strings.Join(placeholders, ", "))
	rows, err := queryer.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list queue jobs for audit: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.RefreshJob, 0)
	for rows.Next() {
		var (
			job         db.RefreshJob
			processedAt *time.Time
			errorText   *string
		)
		if err := rows.Scan(
			&job.ID,
			&job.Ecosystem,
			&job.Name,
			&job.Source,
			&job.Priority,
			&job.Status,
			&job.RequestedAt,
			&processedAt,
			&errorText,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan queue audit job row: %w", err)
		}
		job.ProcessedAt = processedAt
		if errorText != nil {
			job.Error = *errorText
		}
		out = append(out, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate queue audit jobs: %w", err)
	}
	return out, nil
}

func clearQueueTx(ctx context.Context, execer postgresExecer, statuses []string) (int, error) {
	statuses = normalizeQueueStatuses(statuses)
	if len(statuses) == 0 {
		return 0, nil
	}

	placeholders := make([]string, 0, len(statuses))
	args := make([]any, 0, len(statuses))
	for i, status := range statuses {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
		args = append(args, status)
	}

	query := fmt.Sprintf(`DELETE FROM refresh_queue WHERE status IN (%s)`, strings.Join(placeholders, ", "))
	tag, err := execer.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("postgres: clear queue: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func normalizeQueueStatuses(statuses []string) []string {
	allowed := map[string]struct{}{
		"pending": {},
		"paused":  {},
		"done":    {},
		"error":   {},
	}
	seen := make(map[string]struct{}, len(statuses))
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		status = strings.ToLower(strings.TrimSpace(status))
		if _, ok := allowed[status]; !ok {
			continue
		}
		if _, ok := seen[status]; ok {
			continue
		}
		seen[status] = struct{}{}
		out = append(out, status)
	}
	return out
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
