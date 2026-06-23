package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/findinglinks"
	"github.com/8linkz-sec/packmon/internal/packageid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// normalizePackageName canonicalizes package names for ecosystems whose
// registry identity is case-insensitive.
func normalizePackageName(ecosystem, name string) string {
	return packageid.NormalizeName(ecosystem, name)
}

func validateMaliciousFindingVersions(id string, raw json.RawMessage) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("malicious finding %s versions must be null or an array of strings: %w", id, err)
	}
	return nil
}

func (s *Store) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	name = normalizePackageName(ecosystem, name)
	const query = `
		SELECT
			v.id,
			v.summary,
			v.severity,
			COALESCE(vr.refs_json, '[]') AS refs_json,
			COALESCE(vs.source, '') AS source,
			ap.version_ranges::text,
			ap.versions_affected::text
		FROM vulnerabilities v
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT COALESCE(
				json_agg(
					json_build_object(
						'type', COALESCE(ref_type, ''),
						'url', url
					)
					ORDER BY sort_order, id
				)::text,
				'[]'
			) AS refs_json
			FROM (
				SELECT 0 AS sort_order, id, type AS ref_type, url
				FROM vulnerability_references
				WHERE vulnerability_id = v.id
				UNION ALL
				SELECT 1 AS sort_order, id, 'VULNCHECK' AS ref_type,
					COALESCE(NULLIF(TRIM(url), ''), 'https://vulncheck.com/') AS url
				FROM vulnerability_sources
				WHERE vulnerability_id = v.id AND source = 'vulncheck'
			) refs
		) vr ON true
		LEFT JOIN LATERAL (
			SELECT source FROM vulnerability_sources
			WHERE vulnerability_id = v.id ORDER BY id LIMIT 1
		) vs ON true
		WHERE ap.ecosystem = $1 AND ap.name = $2
		  AND v.withdrawn IS NULL
		ORDER BY v.modified DESC, v.id`

	rows, err := s.pool.Query(ctx, query, ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("postgres: find vulnerabilities: %w", err)
	}
	defer closeSilently(rows)

	findings := make([]domain.Finding, 0)
	for rows.Next() {
		var (
			advisoryID       string
			summary          string
			severity         string
			refsJSON         string
			source           string
			versionRangesRaw string
			versionsRaw      string
		)

		if err := rows.Scan(&advisoryID, &summary, &severity, &refsJSON, &source, &versionRangesRaw, &versionsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan vulnerability row: %w", err)
		}

		fixedVersion := extractFixedVersion(versionRangesRaw)
		if version != "" {
			affected, err := versionAffectedWithEcosystem(version, versionRangesRaw, versionsRaw, ecosystem)
			if err == nil && !affected {
				continue
			}
		}

		title := summary
		if title == "" {
			title = advisoryID
		}
		if source == "" {
			source = "unknown"
		}
		resources := buildFindingResources(advisoryID, refsJSON)
		primaryURL := ""
		if len(resources) > 0 {
			primaryURL = resources[0].URL
		}

		findings = append(findings, domain.Finding{
			Name:         name,
			Version:      version,
			Ecosystem:    domain.Ecosystem(ecosystem),
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.Severity(normalizeSeverity(severity)),
			AdvisoryID:   advisoryID,
			Title:        title,
			URL:          primaryURL,
			Resources:    resources,
			FixedVersion: fixedVersion,
			Source:       source,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate vulnerabilities: %w", err)
	}
	return findings, nil
}

func (s *Store) FindMalicious(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	name = normalizePackageName(ecosystem, name)
	const query = `
		SELECT id, severity, summary, risk_type, source,
			COALESCE(version_ranges::text, ''),
			COALESCE(versions::text, ''),
			reference_urls::text
		FROM malicious_findings
		WHERE ecosystem = $1 AND name = $2
		  AND removed_at IS NULL
		ORDER BY updated_at DESC, id DESC`

	rows, err := s.pool.Query(ctx, query, ecosystem, name)
	if err != nil {
		return nil, fmt.Errorf("postgres: find malicious findings: %w", err)
	}
	defer closeSilently(rows)

	findings := make([]domain.Finding, 0)
	for rows.Next() {
		var (
			id               string
			severity         string
			summary          string
			riskType         string
			source           string
			versionRangesRaw string
			versionsRaw      string
			referenceURLsRaw string
		)

		if err := rows.Scan(&id, &severity, &summary, &riskType, &source, &versionRangesRaw, &versionsRaw, &referenceURLsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan malicious row: %w", err)
		}
		if !maliciousFindingAffectsVersion(ecosystem, version, versionRangesRaw, versionsRaw) {
			continue
		}

		title := summary
		if title == "" {
			title = fmt.Sprintf("malicious package: %s (%s)", name, riskType)
		}
		if source == "" {
			source = "unknown"
		}

		findings = append(findings, domain.Finding{
			Name:       name,
			Ecosystem:  domain.Ecosystem(ecosystem),
			Type:       db.FindingTypeForMaliciousRiskType(riskType),
			Severity:   domain.Severity(normalizeSeverity(severity)),
			AdvisoryID: id,
			Title:      title,
			URL:        extractFirstURL(referenceURLsRaw),
			RiskType:   riskType,
			Source:     source,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate malicious findings: %w", err)
	}
	return findings, nil
}

func maliciousFindingAffectsVersion(ecosystem, version, rangesJSON, versionsJSON string) bool {
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
	affected, err := versionAffectedWithEcosystem(version, rangesJSON, versionsJSON, ecosystem)
	if err != nil {
		return true
	}
	return affected
}

func (s *Store) FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	type ecoName struct{ ecosystem, name string }
	seen := make(map[ecoName]struct{}, len(packages))
	var args []any
	var placeholders []string
	paramIdx := 1
	for _, pkg := range packages {
		normalizedName := normalizePackageName(pkg.Ecosystem, pkg.Name)
		key := ecoName{ecosystem: pkg.Ecosystem, name: normalizedName}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d)", paramIdx, paramIdx+1))
		args = append(args, pkg.Ecosystem, normalizedName)
		paramIdx += 2
	}

	query := `
		SELECT
			v.id, v.summary, v.severity,
			COALESCE(vr.refs_json, '[]') AS refs_json,
			COALESCE(vs.source, '') AS source,
			ap.ecosystem, ap.name, ap.version_ranges::text, ap.versions_affected::text
		FROM vulnerabilities v
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT COALESCE(
				json_agg(
					json_build_object(
						'type', COALESCE(ref_type, ''),
						'url', url
					)
					ORDER BY sort_order, id
				)::text,
				'[]'
			) AS refs_json
			FROM (
				SELECT
					CASE UPPER(COALESCE(type, ''))
						WHEN 'ADVISORY' THEN 0
						WHEN 'REPORT' THEN 1
						WHEN 'ARTICLE' THEN 2
						WHEN 'WEB' THEN 3
						WHEN 'PACKAGE' THEN 8
						ELSE 9
					END AS sort_order,
					id,
					type AS ref_type,
					url
				FROM vulnerability_references
				WHERE vulnerability_id = v.id
				UNION ALL
				SELECT 50 AS sort_order, id, 'VULNCHECK' AS ref_type,
					COALESCE(NULLIF(TRIM(url), ''), 'https://vulncheck.com/') AS url
				FROM vulnerability_sources
				WHERE vulnerability_id = v.id AND source = 'vulncheck'
			) refs
		) vr ON true
		LEFT JOIN LATERAL (
			SELECT source FROM vulnerability_sources
			WHERE vulnerability_id = v.id ORDER BY id LIMIT 1
		) vs ON true
		WHERE (ap.ecosystem, ap.name) IN (VALUES ` + strings.Join(placeholders, ", ") + `)
		  AND v.withdrawn IS NULL
		ORDER BY v.modified DESC, v.id`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: find vulnerabilities batch: %w", err)
	}
	defer closeSilently(rows)

	type pkgVersions struct{ versions []string }
	versionMap := make(map[ecoName]*pkgVersions, len(packages))
	for _, pkg := range packages {
		key := ecoName{ecosystem: pkg.Ecosystem, name: normalizePackageName(pkg.Ecosystem, pkg.Name)}
		entry, ok := versionMap[key]
		if !ok {
			entry = &pkgVersions{}
			versionMap[key] = entry
		}
		if pkg.Version != "" {
			entry.versions = append(entry.versions, pkg.Version)
		}
	}

	var findings []domain.Finding
	for rows.Next() {
		var advisoryID, summary, severity, refsJSON, source, ecosystem, name, versionRangesRaw, versionsRaw string
		if err := rows.Scan(&advisoryID, &summary, &severity, &refsJSON, &source, &ecosystem, &name, &versionRangesRaw, &versionsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan vulnerability batch row: %w", err)
		}
		fixedVersion := extractFixedVersion(versionRangesRaw)
		title := summary
		if title == "" {
			title = advisoryID
		}
		if source == "" {
			source = "unknown"
		}
		resources := buildFindingResources(advisoryID, refsJSON)
		primaryURL := ""
		if len(resources) > 0 {
			primaryURL = resources[0].URL
		}
		key := ecoName{ecosystem: ecosystem, name: normalizePackageName(ecosystem, name)}
		entry := versionMap[key]
		if entry != nil && len(entry.versions) > 0 {
			for _, version := range entry.versions {
				affected, matchErr := versionAffectedWithEcosystem(version, versionRangesRaw, versionsRaw, ecosystem)
				if matchErr == nil && !affected {
					continue
				}
				findings = append(findings, domain.Finding{
					Name: name, Version: version, Ecosystem: domain.Ecosystem(ecosystem),
					Type: domain.FindingTypeVulnerability, Severity: domain.Severity(normalizeSeverity(severity)),
					AdvisoryID: advisoryID, Title: title, URL: primaryURL, Resources: resources, FixedVersion: fixedVersion, Source: source,
				})
			}
		} else {
			findings = append(findings, domain.Finding{
				Name: name, Ecosystem: domain.Ecosystem(ecosystem),
				Type: domain.FindingTypeVulnerability, Severity: domain.Severity(normalizeSeverity(severity)),
				AdvisoryID: advisoryID, Title: title, URL: primaryURL, Resources: resources, FixedVersion: fixedVersion, Source: source,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate vulnerabilities batch: %w", err)
	}
	return findings, nil
}

func (s *Store) FindMaliciousBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	type ecoName struct{ ecosystem, name string }
	seen := make(map[ecoName]struct{}, len(packages))
	var args []any
	var placeholders []string
	paramIdx := 1
	for _, pkg := range packages {
		normalizedName := normalizePackageName(pkg.Ecosystem, pkg.Name)
		key := ecoName{ecosystem: pkg.Ecosystem, name: normalizedName}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d)", paramIdx, paramIdx+1))
		args = append(args, pkg.Ecosystem, normalizedName)
		paramIdx += 2
	}

	query := `
		SELECT id, ecosystem, name, severity, summary, risk_type, source,
			COALESCE(version_ranges::text, ''),
			COALESCE(versions::text, ''),
			COALESCE(reference_urls::text, '[]')
		FROM malicious_findings
		WHERE (ecosystem, name) IN (VALUES ` + strings.Join(placeholders, ", ") + `)
		  AND removed_at IS NULL
		ORDER BY updated_at DESC, id DESC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: find malicious batch: %w", err)
	}
	defer closeSilently(rows)

	type pkgVersions struct{ versions []string }
	versionMap := make(map[ecoName]*pkgVersions, len(packages))
	for _, pkg := range packages {
		key := ecoName{ecosystem: pkg.Ecosystem, name: normalizePackageName(pkg.Ecosystem, pkg.Name)}
		entry, ok := versionMap[key]
		if !ok {
			entry = &pkgVersions{}
			versionMap[key] = entry
		}
		if pkg.Version != "" {
			entry.versions = append(entry.versions, pkg.Version)
		}
	}

	var findings []domain.Finding
	for rows.Next() {
		var id, ecosystem, name, severity, summary, riskType, source, versionRangesRaw, versionsRaw, referenceURLsRaw string
		if err := rows.Scan(&id, &ecosystem, &name, &severity, &summary, &riskType, &source, &versionRangesRaw, &versionsRaw, &referenceURLsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan malicious batch row: %w", err)
		}
		title := summary
		if title == "" {
			title = fmt.Sprintf("malicious package: %s (%s)", name, riskType)
		}
		if source == "" {
			source = "unknown"
		}

		key := ecoName{ecosystem: ecosystem, name: normalizePackageName(ecosystem, name)}
		entry := versionMap[key]
		if entry != nil && len(entry.versions) > 0 {
			for _, version := range entry.versions {
				if !maliciousFindingAffectsVersion(ecosystem, version, versionRangesRaw, versionsRaw) {
					continue
				}
				findings = append(findings, domain.Finding{
					Name: name, Version: version, Ecosystem: domain.Ecosystem(ecosystem),
					Type: db.FindingTypeForMaliciousRiskType(riskType), Severity: domain.Severity(normalizeSeverity(severity)),
					AdvisoryID: id, Title: title, URL: extractFirstURL(referenceURLsRaw), RiskType: riskType, Source: source,
				})
			}
		} else {
			findings = append(findings, domain.Finding{
				Name: name, Ecosystem: domain.Ecosystem(ecosystem),
				Type: db.FindingTypeForMaliciousRiskType(riskType), Severity: domain.Severity(normalizeSeverity(severity)),
				AdvisoryID: id, Title: title, URL: extractFirstURL(referenceURLsRaw), RiskType: riskType, Source: source,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate malicious batch: %w", err)
	}
	return findings, nil
}

func (s *Store) UpsertVulnerability(ctx context.Context, vuln *db.Vulnerability) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return upsertVulnerabilityTx(ctx, tx, vuln)
	})
}

func upsertVulnerabilityTx(ctx context.Context, tx pgx.Tx, vuln *db.Vulnerability) error {
	const upsertVulnerability = `
			INSERT INTO vulnerabilities (
				id, summary, details, severity, cvss_score, epss_score, epss_percentile,
				cisa_kev, exploit_exists, published, modified, withdrawn
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
			)
			ON CONFLICT (id) DO UPDATE SET
				summary = CASE WHEN EXCLUDED.summary != '' THEN EXCLUDED.summary ELSE vulnerabilities.summary END,
				details = CASE WHEN EXCLUDED.details IS NOT NULL AND EXCLUDED.details != '' THEN EXCLUDED.details ELSE vulnerabilities.details END,
				severity = CASE
					WHEN (
						CASE EXCLUDED.severity
							WHEN 'CRITICAL' THEN 4
							WHEN 'HIGH' THEN 3
							WHEN 'MEDIUM' THEN 2
							WHEN 'LOW' THEN 1
							ELSE 0
						END
					) > (
						CASE vulnerabilities.severity
							WHEN 'CRITICAL' THEN 4
							WHEN 'HIGH' THEN 3
							WHEN 'MEDIUM' THEN 2
							WHEN 'LOW' THEN 1
							ELSE 0
						END
					) THEN EXCLUDED.severity
					ELSE vulnerabilities.severity
				END,
				cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
				published = EXCLUDED.published,
				modified = EXCLUDED.modified,
				withdrawn = EXCLUDED.withdrawn,
				updated_at = NOW()
			WHERE vulnerabilities.summary IS DISTINCT FROM (CASE WHEN EXCLUDED.summary != '' THEN EXCLUDED.summary ELSE vulnerabilities.summary END)
			   OR vulnerabilities.details IS DISTINCT FROM (CASE WHEN EXCLUDED.details IS NOT NULL AND EXCLUDED.details != '' THEN EXCLUDED.details ELSE vulnerabilities.details END)
			   OR vulnerabilities.severity IS DISTINCT FROM (
					CASE
						WHEN (
							CASE EXCLUDED.severity
								WHEN 'CRITICAL' THEN 4
								WHEN 'HIGH' THEN 3
								WHEN 'MEDIUM' THEN 2
								WHEN 'LOW' THEN 1
								ELSE 0
							END
						) > (
							CASE vulnerabilities.severity
								WHEN 'CRITICAL' THEN 4
								WHEN 'HIGH' THEN 3
								WHEN 'MEDIUM' THEN 2
								WHEN 'LOW' THEN 1
								ELSE 0
							END
						) THEN EXCLUDED.severity
						ELSE vulnerabilities.severity
					END
			   )
			   OR vulnerabilities.cvss_score IS DISTINCT FROM COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score)
			   OR vulnerabilities.published IS DISTINCT FROM EXCLUDED.published
			   OR vulnerabilities.modified IS DISTINCT FROM EXCLUDED.modified
			   OR vulnerabilities.withdrawn IS DISTINCT FROM EXCLUDED.withdrawn`

	if _, err := tx.Exec(ctx, upsertVulnerability,
		vuln.ID,
		vuln.Summary,
		nullableString(vuln.Details),
		normalizeVulnerabilitySeverity(vuln.Severity),
		vuln.CVSSScore,
		vuln.EPSSScore,
		vuln.EPSSPercentile,
		vuln.CISAKEV,
		vuln.ExploitExists,
		vuln.Published,
		vuln.Modified,
		vuln.Withdrawn,
	); err != nil {
		return fmt.Errorf("upsert vulnerability core: %w", err)
	}

	for _, source := range vuln.Sources {
		const upsertSource = `
				INSERT INTO vulnerability_sources (vulnerability_id, source, source_id, url, raw_json)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (vulnerability_id, source) DO UPDATE SET
					source_id = EXCLUDED.source_id,
					url = EXCLUDED.url,
					raw_json = EXCLUDED.raw_json,
					updated_at = NOW()
				WHERE vulnerability_sources.source_id IS DISTINCT FROM EXCLUDED.source_id
				   OR vulnerability_sources.url IS DISTINCT FROM EXCLUDED.url
				   OR vulnerability_sources.raw_json IS DISTINCT FROM EXCLUDED.raw_json`

		if _, err := tx.Exec(ctx, upsertSource,
			vuln.ID,
			source.Source,
			source.SourceID,
			nullableString(source.URL),
			normalizeJSON(source.RawJSON, nil),
		); err != nil {
			return fmt.Errorf("upsert vulnerability source %s: %w", source.Source, err)
		}
	}

	if _, err := tx.Exec(ctx, `DELETE FROM vulnerability_aliases WHERE vulnerability_id = $1`, vuln.ID); err != nil {
		return fmt.Errorf("delete vulnerability aliases: %w", err)
	}
	for _, alias := range vuln.Aliases {
		if alias.AliasID == "" {
			continue
		}
		// Use composite unique constraint (vulnerability_id, alias_id)
		// so the same alias can be linked to multiple vulnerabilities
		// without silently moving it (ARCH-H3 fix).
		const insertAlias = `
				INSERT INTO vulnerability_aliases (vulnerability_id, alias_id)
				VALUES ($1, $2)
				ON CONFLICT (vulnerability_id, alias_id) DO NOTHING`
		if _, err := tx.Exec(ctx, insertAlias, vuln.ID, alias.AliasID); err != nil {
			return fmt.Errorf("insert alias %s: %w", alias.AliasID, err)
		}
	}

	if _, err := tx.Exec(ctx, `DELETE FROM vulnerability_references WHERE vulnerability_id = $1`, vuln.ID); err != nil {
		return fmt.Errorf("delete vulnerability references: %w", err)
	}
	for _, ref := range vuln.References {
		if !shouldStoreVulnerabilityReference(ref.URL) {
			continue
		}
		const insertReference = `
				INSERT INTO vulnerability_references (vulnerability_id, type, url, source)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (vulnerability_id, url) DO UPDATE SET
					type = EXCLUDED.type,
					source = EXCLUDED.source`
		if _, err := tx.Exec(ctx, insertReference,
			vuln.ID,
			nullableString(ref.Type),
			ref.URL,
			nullableString(ref.Source),
		); err != nil {
			return fmt.Errorf("insert reference %s: %w", ref.URL, err)
		}
	}

	for _, pkg := range vuln.AffectedPackages {
		name := normalizePackageName(pkg.Ecosystem, pkg.Name)
		const insertPackage = `
				INSERT INTO affected_packages (
					vulnerability_id, ecosystem, name, version_ranges, versions_affected
				) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (vulnerability_id, ecosystem, name) DO UPDATE SET
					version_ranges = EXCLUDED.version_ranges,
					versions_affected = EXCLUDED.versions_affected,
					updated_at = NOW()
				WHERE affected_packages.version_ranges IS DISTINCT FROM EXCLUDED.version_ranges
				   OR affected_packages.versions_affected IS DISTINCT FROM EXCLUDED.versions_affected`

		if _, err := tx.Exec(ctx, insertPackage,
			vuln.ID,
			pkg.Ecosystem,
			name,
			normalizeJSON(pkg.VersionRanges, []byte("[]")),
			normalizeJSON(pkg.VersionsAffected, []byte("[]")),
		); err != nil {
			return fmt.Errorf("insert affected package %s/%s: %w", pkg.Ecosystem, name, err)
		}
	}

	return nil
}

func (s *Store) UpsertMaliciousFinding(ctx context.Context, mf *db.MaliciousFinding) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return upsertMaliciousFindingTx(ctx, tx, mf)
	})
}

func (s *Store) ImportVulnerabilityFeed(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	imported := 0
	deleted := 0
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		for i := range items {
			if err := upsertVulnerabilityTx(ctx, tx, &items[i]); err != nil {
				return fmt.Errorf("import vulnerability %s: %w", items[i].ID, err)
			}
			imported++
		}
		for _, id := range deleteIDs {
			if err := deleteVulnerabilityForSourceTx(ctx, tx, id, feed); err != nil {
				return fmt.Errorf("delete imported vulnerability %s: %w", id, err)
			}
			deleted++
		}
		if status != nil {
			if err := upsertFeedSyncStatusTx(ctx, tx, status); err != nil {
				return err
			}
		}
		return nil
	})
	return imported, deleted, err
}

func (s *Store) ImportMaliciousFeed(ctx context.Context, feed string, items []db.MaliciousFinding, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	imported := 0
	deleted := 0
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		for i := range items {
			if err := upsertMaliciousFindingTx(ctx, tx, &items[i]); err != nil {
				return fmt.Errorf("import malicious finding %s: %w", items[i].ID, err)
			}
			imported++
		}
		for _, id := range deleteIDs {
			if err := deleteMaliciousFindingForSourceTx(ctx, tx, id, feed); err != nil {
				return fmt.Errorf("delete imported malicious finding %s: %w", id, err)
			}
			deleted++
		}
		if status != nil {
			if err := upsertFeedSyncStatusTx(ctx, tx, status); err != nil {
				return err
			}
		}
		return nil
	})
	return imported, deleted, err
}

func upsertMaliciousFindingTx(ctx context.Context, tx pgx.Tx, mf *db.MaliciousFinding) error {
	if err := validateMaliciousFindingVersions(mf.ID, mf.Versions); err != nil {
		return err
	}

	const query = `
		INSERT INTO malicious_findings (
			id, ecosystem, name, version_ranges, versions, source, risk_type, severity,
			summary, description, reference_urls, origin_ref, published, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13, $14
		)
		ON CONFLICT (id) DO UPDATE SET
			ecosystem = EXCLUDED.ecosystem,
			name = EXCLUDED.name,
			version_ranges = EXCLUDED.version_ranges,
			versions = EXCLUDED.versions,
			source = EXCLUDED.source,
			risk_type = EXCLUDED.risk_type,
			severity = EXCLUDED.severity,
			summary = EXCLUDED.summary,
			description = EXCLUDED.description,
			reference_urls = EXCLUDED.reference_urls,
			origin_ref = EXCLUDED.origin_ref,
			published = EXCLUDED.published,
			created_by = EXCLUDED.created_by,
			removed_at = NULL,
			updated_at = NOW()`

	_, err := tx.Exec(ctx, query,
		mf.ID,
		mf.Ecosystem,
		normalizePackageName(mf.Ecosystem, mf.Name),
		normalizeJSON(mf.VersionRanges, nil),
		normalizeJSON(mf.Versions, nil),
		mf.Source,
		mf.RiskType,
		normalizeSeverity(mf.Severity),
		mf.Summary,
		nullableString(mf.Description),
		normalizeJSON(mf.ReferenceURLs, []byte("[]")),
		nullableString(mf.OriginRef),
		mf.Published,
		nullableString(mf.CreatedBy),
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert malicious finding %s: %w", mf.ID, err)
	}
	return nil
}

func (s *Store) DeleteVulnerability(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE vulnerabilities
		SET withdrawn = COALESCE(withdrawn, NOW()),
		    updated_at = NOW()
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete vulnerability %s: %w", id, err)
	}
	return nil
}

func (s *Store) DeleteVulnerabilityForSource(ctx context.Context, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return s.DeleteVulnerability(ctx, id)
	}

	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return deleteVulnerabilityForSourceTx(ctx, tx, id, source)
	})
}

func deleteVulnerabilityForSourceTx(ctx context.Context, tx pgx.Tx, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		if _, err := tx.Exec(ctx, `
			UPDATE vulnerabilities
			SET withdrawn = COALESCE(withdrawn, NOW()),
			    updated_at = NOW()
			WHERE id = $1`, id); err != nil {
			return fmt.Errorf("withdraw vulnerability %s: %w", id, err)
		}
		return nil
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM vulnerability_sources
		WHERE vulnerability_id = $1 AND source = $2`, id, source); err != nil {
		return fmt.Errorf("delete vulnerability source %s/%s: %w", id, source, err)
	}

	var remaining int
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*)::int
		FROM vulnerability_sources
		WHERE vulnerability_id = $1`, id).Scan(&remaining); err != nil {
		return fmt.Errorf("count vulnerability sources %s: %w", id, err)
	}
	if remaining > 0 {
		return nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE vulnerabilities
		SET withdrawn = COALESCE(withdrawn, NOW()),
		    updated_at = NOW()
		WHERE id = $1`, id); err != nil {
		return fmt.Errorf("withdraw vulnerability %s after source delete: %w", id, err)
	}
	return nil
}

func (s *Store) DeleteMaliciousFinding(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE malicious_findings
		SET removed_at = COALESCE(removed_at, NOW()),
		    updated_at = NOW()
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete malicious finding %s: %w", id, err)
	}
	return nil
}

func (s *Store) DeleteMaliciousFindingForSource(ctx context.Context, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return s.DeleteMaliciousFinding(ctx, id)
	}

	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return deleteMaliciousFindingForSourceTx(ctx, tx, id, source)
	})
}

func deleteMaliciousFindingForSourceTx(ctx context.Context, execer postgresExecer, id, source string) error {
	source = strings.TrimSpace(source)
	query := `
		UPDATE malicious_findings
		SET removed_at = COALESCE(removed_at, NOW()),
		    updated_at = NOW()
		WHERE id = $1`
	args := []any{id}
	if source != "" {
		query += ` AND source = $2`
		args = append(args, source)
	}
	if _, err := execer.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("postgres: delete malicious finding %s for source %s: %w", id, source, err)
	}
	return nil
}

func (s *Store) DeleteMaliciousFindingsNotInSource(ctx context.Context, source string, ids []string) (int, error) {
	cmd, err := s.pool.Exec(ctx, `
		UPDATE malicious_findings
		SET removed_at = COALESCE(removed_at, NOW()),
		    updated_at = NOW()
		WHERE source = $1
		  AND removed_at IS NULL
		  AND NOT (id = ANY($2))`, source, ids)
	if err != nil {
		return 0, fmt.Errorf("postgres: prune malicious findings for source %s: %w", source, err)
	}
	return int(cmd.RowsAffected()), nil
}

func (s *Store) ListMaliciousFindings(ctx context.Context, source string, limit int) ([]db.MaliciousFinding, error) {
	limit = clampLimit(limit, 100, 500)

	query := `
		SELECT
			id, ecosystem, name, COALESCE(version_ranges::text, ''), COALESCE(versions::text, ''), source, risk_type, severity,
			summary, description, COALESCE(reference_urls::text, '[]'), origin_ref, published, created_by
		FROM malicious_findings`
	args := []any{}
	if source != "" {
		query += ` WHERE source = $1 AND removed_at IS NULL`
		args = append(args, source)
	} else {
		query += ` WHERE removed_at IS NULL`
	}
	query += fmt.Sprintf(` ORDER BY updated_at DESC, created_at DESC, id DESC LIMIT $%d`, len(args)+1)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list malicious findings: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.MaliciousFinding, 0)
	for rows.Next() {
		var (
			item             db.MaliciousFinding
			versionRangesRaw *string
			versionsRaw      *string
			referenceURLsRaw *string
			description      *string
			originRef        *string
			createdBy        *string
			published        *time.Time
		)

		if err := rows.Scan(
			&item.ID,
			&item.Ecosystem,
			&item.Name,
			&versionRangesRaw,
			&versionsRaw,
			&item.Source,
			&item.RiskType,
			&item.Severity,
			&item.Summary,
			&description,
			&referenceURLsRaw,
			&originRef,
			&published,
			&createdBy,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan malicious finding row: %w", err)
		}

		if versionRangesRaw != nil {
			item.VersionRanges = json.RawMessage(*versionRangesRaw)
		}
		if versionsRaw != nil {
			item.Versions = json.RawMessage(*versionsRaw)
		}
		if referenceURLsRaw != nil {
			item.ReferenceURLs = json.RawMessage(*referenceURLsRaw)
		}
		if description != nil {
			item.Description = *description
		}
		if originRef != nil {
			item.OriginRef = *originRef
		}
		if published != nil {
			item.Published = published
		}
		if createdBy != nil {
			item.CreatedBy = *createdBy
		}

		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate malicious findings: %w", err)
	}
	return out, nil
}

func (s *Store) SetCISAKEV(ctx context.Context, cveIDs []string) (int, error) {
	return setCISAKEV(ctx, s.pool, cveIDs)
}

func (s *Store) ClearCISAKEV(ctx context.Context, keepIDs []string) (int, error) {
	return clearCISAKEV(ctx, s.pool, keepIDs)
}

func (s *Store) ReplaceCISAKEV(ctx context.Context, cveIDs []string) (int, int, error) {
	var updated, cleared int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		updated, err = setCISAKEV(ctx, tx, cveIDs)
		if err != nil {
			return err
		}
		cleared, err = clearCISAKEV(ctx, tx, cveIDs)
		return err
	})
	if err != nil {
		return 0, 0, fmt.Errorf("postgres: replace CISA KEV: %w", err)
	}
	return updated, cleared, nil
}

type cisaKEVExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

func setCISAKEV(ctx context.Context, exec cisaKEVExecutor, cveIDs []string) (int, error) {
	const query = `
		WITH targets AS (
			SELECT id
			FROM vulnerabilities
			WHERE id = ANY($1)
			UNION
			SELECT vulnerability_id
			FROM vulnerability_aliases
			WHERE alias_id = ANY($1)
		)
		UPDATE vulnerabilities v
		SET cisa_kev = TRUE, updated_at = NOW()
		FROM targets t
		WHERE v.id = t.id AND v.cisa_kev = FALSE`

	tag, err := exec.Exec(ctx, query, cveIDs)
	if err != nil {
		return 0, fmt.Errorf("postgres: set CISA KEV: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func clearCISAKEV(ctx context.Context, exec cisaKEVExecutor, keepIDs []string) (int, error) {
	const query = `
		WITH keep AS (
			SELECT id
			FROM vulnerabilities
			WHERE id = ANY($1)
			UNION
			SELECT vulnerability_id
			FROM vulnerability_aliases
			WHERE alias_id = ANY($1)
		)
		UPDATE vulnerabilities v
		SET cisa_kev = FALSE, updated_at = NOW()
		WHERE v.cisa_kev = TRUE
		  AND NOT EXISTS (SELECT 1 FROM keep WHERE keep.id = v.id)`

	tag, err := exec.Exec(ctx, query, keepIDs)
	if err != nil {
		return 0, fmt.Errorf("postgres: clear CISA KEV: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) PropagateSeverityViaAliases(ctx context.Context) (int, error) {
	// Find vulnerabilities with UNKNOWN severity that share an alias with
	// a vulnerability that has a known severity, and copy it over.
	const query = `
		UPDATE vulnerabilities v
		SET severity = donor.severity, updated_at = NOW()
		FROM (
			SELECT DISTINCT ON (unknown_id)
				va1.vulnerability_id AS unknown_id,
				v2.severity
			FROM vulnerability_aliases va1
			INNER JOIN vulnerability_aliases va2 ON va2.alias_id = va1.alias_id
				AND va2.vulnerability_id != va1.vulnerability_id
			INNER JOIN vulnerabilities v1 ON v1.id = va1.vulnerability_id
			INNER JOIN vulnerabilities v2 ON v2.id = va2.vulnerability_id
			WHERE v1.severity = 'UNKNOWN'
			  AND v2.severity != 'UNKNOWN'
			ORDER BY unknown_id,
				CASE v2.severity
					WHEN 'CRITICAL' THEN 1
					WHEN 'HIGH' THEN 2
					WHEN 'MEDIUM' THEN 3
					WHEN 'LOW' THEN 4
					ELSE 5
				END
		) donor
		WHERE v.id = donor.unknown_id`

	tag, err := s.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("postgres: propagate severity via aliases: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) SetEPSSScores(ctx context.Context, scores []db.EPSSEntry) (int, error) {
	return setEPSSScores(ctx, s.pool, scores)
}

type epssScoreExecer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func setEPSSScores(ctx context.Context, exec epssScoreExecer, scores []db.EPSSEntry) (int, error) {
	if len(scores) == 0 {
		return 0, nil
	}

	const batchSize = 5000
	updated := 0

	for i := 0; i < len(scores); i += batchSize {
		end := i + batchSize
		if end > len(scores) {
			end = len(scores)
		}
		batch := scores[i:end]

		cveIDs := make([]string, len(batch))
		epssScores := make([]float64, len(batch))
		percentiles := make([]float64, len(batch))
		for j, s := range batch {
			cveIDs[j] = s.CVEID
			epssScores[j] = s.Score
			percentiles[j] = s.Percentile
		}

		const query = `
			WITH data AS (
				SELECT
					unnest($1::text[]) AS cve_id,
					unnest($2::float8[])::real AS score,
					unnest($3::float8[])::real AS percentile
			),
			raw_targets AS (
				SELECT v.id, d.score, d.percentile
				FROM data d
				INNER JOIN vulnerabilities v ON v.id = d.cve_id
				UNION
				SELECT va.vulnerability_id, d.score, d.percentile
				FROM data d
				INNER JOIN vulnerability_aliases va ON va.alias_id = d.cve_id
			),
			targets AS (
				SELECT DISTINCT ON (id) id, score, percentile
				FROM raw_targets
				ORDER BY id
			)
			UPDATE vulnerabilities v
			SET epss_score = t.score, epss_percentile = t.percentile, updated_at = NOW()
			FROM targets t
			WHERE v.id = t.id
			  AND (v.epss_score IS DISTINCT FROM t.score
			       OR v.epss_percentile IS DISTINCT FROM t.percentile)`

		tag, err := exec.Exec(ctx, query, cveIDs, epssScores, percentiles)
		if err != nil {
			return updated, fmt.Errorf("postgres: set EPSS scores batch: %w", err)
		}
		updated += int(tag.RowsAffected())
	}

	return updated, nil
}

func (s *Store) ReplaceEPSSScores(ctx context.Context, scores []db.EPSSEntry) (updated, cleared int, err error) {
	updated, cleared, _, err = s.ReplaceEPSSScoresStream(ctx, func(yield func([]db.EPSSEntry) error) error {
		return yield(scores)
	})
	return updated, cleared, err
}

func (s *Store) ReplaceEPSSScoresStream(ctx context.Context, stream func(func([]db.EPSSEntry) error) error) (updated, cleared, total int, err error) {
	err = withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, execErr := tx.Exec(ctx, `CREATE TEMP TABLE packmon_epss_keep (cve_id text PRIMARY KEY) ON COMMIT DROP`); execErr != nil {
			return fmt.Errorf("postgres: create EPSS keep table: %w", execErr)
		}

		err = stream(func(batch []db.EPSSEntry) error {
			batchUpdated, setErr := setEPSSScores(ctx, tx, batch)
			if setErr != nil {
				return setErr
			}
			if insertErr := insertEPSSKeepIDs(ctx, tx, batch); insertErr != nil {
				return insertErr
			}
			updated += batchUpdated
			total += len(batch)
			return nil
		})
		if err != nil {
			return err
		}

		const clearQuery = `
			WITH keep AS (
				SELECT v.id
				FROM vulnerabilities v
				INNER JOIN packmon_epss_keep k ON k.cve_id = v.id
				UNION
				SELECT va.vulnerability_id
				FROM vulnerability_aliases va
				INNER JOIN packmon_epss_keep k ON k.cve_id = va.alias_id
			)
			UPDATE vulnerabilities v
			SET epss_score = NULL, epss_percentile = NULL, updated_at = NOW()
			WHERE (v.epss_score IS NOT NULL OR v.epss_percentile IS NOT NULL)
			  AND NOT EXISTS (SELECT 1 FROM keep WHERE keep.id = v.id)`

		tag, execErr := tx.Exec(ctx, clearQuery)
		if execErr != nil {
			return fmt.Errorf("postgres: clear stale EPSS scores: %w", execErr)
		}
		cleared = int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return updated, cleared, total, err
	}
	return updated, cleared, total, nil
}

func insertEPSSKeepIDs(ctx context.Context, exec epssScoreExecer, scores []db.EPSSEntry) error {
	if len(scores) == 0 {
		return nil
	}
	cveIDs := make([]string, len(scores))
	for i, score := range scores {
		cveIDs[i] = score.CVEID
	}
	const query = `
		INSERT INTO packmon_epss_keep (cve_id)
		SELECT DISTINCT unnest($1::text[])
		ON CONFLICT (cve_id) DO NOTHING`
	if _, err := exec.Exec(ctx, query, cveIDs); err != nil {
		return fmt.Errorf("postgres: record EPSS keep IDs: %w", err)
	}
	return nil
}

func (s *Store) EnrichVulnCheck(ctx context.Context, entries []db.VulnCheckEntry) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}

	const batchSize = 5000
	updated := 0

	for i := 0; i < len(entries); i += batchSize {
		end := i + batchSize
		if end > len(entries) {
			end = len(entries)
		}
		batch := entries[i:end]

		// Batch the vulnerability UPDATE using unnest arrays.
		cveIDs := make([]string, len(batch))
		cvssScores := make([]*float64, len(batch))
		exploitFlags := make([]bool, len(batch))
		for j, e := range batch {
			cveIDs[j] = e.CVEID
			cvssScores[j] = e.CVSSScore
			exploitFlags[j] = e.ExploitExists
		}

		const batchUpdate = `
			WITH data AS (
				SELECT
					unnest($1::text[]) AS cve_id,
					unnest($2::float8[])::real AS cvss_score,
					unnest($3::bool[]) AS exploit_exists
			),
			raw_targets AS (
				SELECT v.id, d.cvss_score, d.exploit_exists
				FROM data d
				INNER JOIN vulnerabilities v ON v.id = d.cve_id
				UNION
				SELECT va.vulnerability_id, d.cvss_score, d.exploit_exists
				FROM data d
				INNER JOIN vulnerability_aliases va ON va.alias_id = d.cve_id
			),
			targets AS (
				SELECT DISTINCT ON (id) id, cvss_score, exploit_exists
				FROM raw_targets
				ORDER BY id
			)
			UPDATE vulnerabilities v
			SET
				cvss_score = COALESCE(t.cvss_score, v.cvss_score),
				exploit_exists = v.exploit_exists OR t.exploit_exists,
				updated_at = NOW()
			FROM targets t
			WHERE v.id = t.id
			  AND ((t.cvss_score IS NOT NULL AND v.cvss_score IS DISTINCT FROM t.cvss_score)
			       OR (t.exploit_exists = TRUE AND v.exploit_exists = FALSE))`

		// Source upserts still require per-entry execution because each
		// carries its own raw_json blob that cannot be efficiently unnested.
		batchUpdated := 0
		err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, batchUpdate, cveIDs, cvssScores, exploitFlags)
			if err != nil {
				return fmt.Errorf("batch update: %w", err)
			}
			batchUpdated = int(tag.RowsAffected())

			const upsertSource = `
				WITH targets AS (
					SELECT id
					FROM vulnerabilities
					WHERE id = $1
					UNION
					SELECT vulnerability_id
					FROM vulnerability_aliases
					WHERE alias_id = $1
				)
				INSERT INTO vulnerability_sources (vulnerability_id, source, source_id, url, raw_json)
				SELECT id, 'vulncheck', $1, $2, $3
				FROM targets
				ON CONFLICT (vulnerability_id, source) DO UPDATE SET
					source_id = EXCLUDED.source_id,
					url = EXCLUDED.url,
					raw_json = EXCLUDED.raw_json,
					updated_at = NOW()
				WHERE vulnerability_sources.source_id IS DISTINCT FROM EXCLUDED.source_id
				   OR vulnerability_sources.url IS DISTINCT FROM EXCLUDED.url
				   OR vulnerability_sources.raw_json IS DISTINCT FROM EXCLUDED.raw_json`

			for _, entry := range batch {
				if _, err := tx.Exec(ctx, upsertSource,
					entry.CVEID,
					nullableString(entry.SourceURL),
					normalizeJSON(entry.RawJSON, nil),
				); err != nil {
					return fmt.Errorf("upsert VulnCheck source for %s: %w", entry.CVEID, err)
				}
			}
			return nil
		})
		if err != nil {
			return updated, fmt.Errorf("postgres: enrich VulnCheck batch: %w", err)
		}
		updated += batchUpdated
	}

	return updated, nil
}

func (s *Store) FindUnknownSeverityCVEAliases(ctx context.Context) ([]db.UnknownCVEAlias, error) {
	const query = `
		SELECT va.vulnerability_id, va.alias_id
		FROM vulnerability_aliases va
		INNER JOIN vulnerabilities v ON v.id = va.vulnerability_id
		WHERE (v.severity = 'UNKNOWN' OR (v.severity = 'LOW' AND v.cvss_score IS NULL))
		  AND va.alias_id LIKE 'CVE-%'`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("postgres: find unknown severity CVE aliases: %w", err)
	}
	defer closeSilently(rows)

	var results []db.UnknownCVEAlias
	for rows.Next() {
		var a db.UnknownCVEAlias
		if err := rows.Scan(&a.VulnerabilityID, &a.CVEID); err != nil {
			return nil, fmt.Errorf("postgres: scan unknown CVE alias row: %w", err)
		}
		results = append(results, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate unknown CVE aliases: %w", err)
	}
	return results, nil
}

func (s *Store) UpdateSeverityByCVE(ctx context.Context, cveID, severity string, cvssScore float64) error {
	const query = `
		UPDATE vulnerabilities v
		SET severity = $2, cvss_score = $3, updated_at = NOW()
		FROM vulnerability_aliases va
		WHERE va.alias_id = $1 AND va.vulnerability_id = v.id
		  AND (v.severity = 'UNKNOWN' OR (v.severity = 'LOW' AND v.cvss_score IS NULL))`

	_, err := s.pool.Exec(ctx, query, cveID, severity, cvssScore)
	if err != nil {
		return fmt.Errorf("postgres: update severity by CVE %s: %w", cveID, err)
	}
	return nil
}

func extractFirstURL(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var urls []string
	if err := json.Unmarshal([]byte(raw), &urls); err != nil {
		return ""
	}
	if len(urls) == 0 {
		return ""
	}
	return urls[0]
}

func buildFindingResources(advisoryID, raw string) []domain.ResourceLink {
	return findinglinks.ResourceLinksFromVulnerabilityReferences(advisoryID, raw)
}

type findingReference = findinglinks.VulnerabilityReference

func canonicalFindingResource(advisoryID string) (domain.ResourceLink, int, bool) {
	return findinglinks.CanonicalVulnerabilityResource(advisoryID)
}

func classifyFindingResource(advisoryID string, ref findingReference) (domain.ResourceLink, int, bool) {
	return findinglinks.ClassifyVulnerabilityResource(advisoryID, ref)
}

func shouldStoreVulnerabilityReference(rawURL string) bool {
	return findinglinks.ShouldStoreVulnerabilityReference(rawURL)
}

func isBlockedReferenceHost(host string) bool {
	return findinglinks.IsBlockedReferenceHost(host)
}

func resourceScore(advisoryID, label string) int {
	return findinglinks.ResourceScore(advisoryID, label)
}
