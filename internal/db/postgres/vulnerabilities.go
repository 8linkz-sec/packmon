package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
	"github.com/jackc/pgx/v5"
)

var ghsaIDPattern = regexp.MustCompile(`GHSA-[A-Za-z0-9-]+`)

// normalizePackageName lowercases the package name for ecosystems where
// names are case-insensitive (NuGet). For all other ecosystems the name
// is returned unchanged.
func normalizePackageName(ecosystem, name string) string {
	if strings.EqualFold(ecosystem, "nuget") {
		return strings.ToLower(name)
	}
	return name
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
						'type', COALESCE(type, ''),
						'url', url
					)
					ORDER BY id
				)::text,
				'[]'
			) AS refs_json
			FROM vulnerability_references
			WHERE vulnerability_id = v.id
		) vr ON true
		LEFT JOIN LATERAL (
			SELECT source FROM vulnerability_sources
			WHERE vulnerability_id = v.id ORDER BY id LIMIT 1
		) vs ON true
		WHERE ap.ecosystem = $1 AND ap.name = $2
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
	// versions is a JSONB array of affected versions. NULL means all
	// versions are affected. When a specific version is requested, only
	// return findings where versions IS NULL or the array contains
	// that version.
	const query = `
		SELECT id, severity, summary, risk_type, source, reference_urls::text
		FROM malicious_findings
		WHERE ecosystem = $1 AND name = $2
		  AND removed_at IS NULL
		  AND (versions IS NULL OR versions = 'null'::jsonb OR $3 = '' OR versions @> to_jsonb($3::text))
		ORDER BY updated_at DESC, id DESC`

	rows, err := s.pool.Query(ctx, query, ecosystem, name, version)
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
			referenceURLsRaw string
		)

		if err := rows.Scan(&id, &severity, &summary, &riskType, &source, &referenceURLsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan malicious row: %w", err)
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
			Type:       domain.FindingTypeMalicious,
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
			COALESCE(vr.url, '') AS ref_url,
			COALESCE(vs.source, '') AS source,
			ap.ecosystem, ap.name, ap.version_ranges::text, ap.versions_affected::text
		FROM vulnerabilities v
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT url FROM vulnerability_references
			WHERE vulnerability_id = v.id
			ORDER BY
				CASE UPPER(COALESCE(type, ''))
					WHEN 'ADVISORY' THEN 0
					WHEN 'REPORT' THEN 1
					WHEN 'ARTICLE' THEN 2
					WHEN 'WEB' THEN 3
					WHEN 'PACKAGE' THEN 8
					ELSE 9
				END,
				id
			LIMIT 1
		) vr ON true
		LEFT JOIN LATERAL (
			SELECT source FROM vulnerability_sources
			WHERE vulnerability_id = v.id ORDER BY id LIMIT 1
		) vs ON true
		WHERE (ap.ecosystem, ap.name) IN (VALUES ` + strings.Join(placeholders, ", ") + `)
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
		var advisoryID, summary, severity, url, source, ecosystem, name, versionRangesRaw, versionsRaw string
		if err := rows.Scan(&advisoryID, &summary, &severity, &url, &source, &ecosystem, &name, &versionRangesRaw, &versionsRaw); err != nil {
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
					AdvisoryID: advisoryID, Title: title, URL: url, FixedVersion: fixedVersion, Source: source,
				})
			}
		} else {
			findings = append(findings, domain.Finding{
				Name: name, Ecosystem: domain.Ecosystem(ecosystem),
				Type: domain.FindingTypeVulnerability, Severity: domain.Severity(normalizeSeverity(severity)),
				AdvisoryID: advisoryID, Title: title, URL: url, FixedVersion: fixedVersion, Source: source,
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
		var id, ecosystem, name, severity, summary, riskType, source, versionsRaw, referenceURLsRaw string
		if err := rows.Scan(&id, &ecosystem, &name, &severity, &summary, &riskType, &source, &versionsRaw, &referenceURLsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan malicious batch row: %w", err)
		}
		title := summary
		if title == "" {
			title = fmt.Sprintf("malicious package: %s (%s)", name, riskType)
		}
		if source == "" {
			source = "unknown"
		}

		var findingVersions []string
		hasVersionList := false
		trimmed := strings.TrimSpace(versionsRaw)
		if trimmed != "" && trimmed != "null" {
			if err := json.Unmarshal([]byte(trimmed), &findingVersions); err == nil && len(findingVersions) > 0 {
				hasVersionList = true
			}
		}

		key := ecoName{ecosystem: ecosystem, name: normalizePackageName(ecosystem, name)}
		entry := versionMap[key]
		if entry != nil && len(entry.versions) > 0 {
			for _, version := range entry.versions {
				if hasVersionList {
					found := false
					for _, v := range findingVersions {
						if v == version {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}
				findings = append(findings, domain.Finding{
					Name: name, Version: version, Ecosystem: domain.Ecosystem(ecosystem),
					Type: domain.FindingTypeMalicious, Severity: domain.Severity(normalizeSeverity(severity)),
					AdvisoryID: id, Title: title, URL: extractFirstURL(referenceURLsRaw), RiskType: riskType, Source: source,
				})
			}
		} else {
			findings = append(findings, domain.Finding{
				Name: name, Ecosystem: domain.Ecosystem(ecosystem),
				Type: domain.FindingTypeMalicious, Severity: domain.Severity(normalizeSeverity(severity)),
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
					WHEN vulnerabilities.severity = 'UNKNOWN' THEN EXCLUDED.severity
					WHEN EXCLUDED.severity = 'UNKNOWN' THEN vulnerabilities.severity
					ELSE EXCLUDED.severity
				END,
				cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
				published = EXCLUDED.published,
				modified = EXCLUDED.modified,
				withdrawn = EXCLUDED.withdrawn,
				updated_at = NOW()`

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
					updated_at = NOW()`

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

		if _, err := tx.Exec(ctx, `DELETE FROM affected_packages WHERE vulnerability_id = $1`, vuln.ID); err != nil {
			return fmt.Errorf("delete affected packages: %w", err)
		}
		for _, pkg := range vuln.AffectedPackages {
			const insertPackage = `
				INSERT INTO affected_packages (
					vulnerability_id, ecosystem, name, version_ranges, versions_affected
				) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (vulnerability_id, ecosystem, name) DO UPDATE SET
					version_ranges = EXCLUDED.version_ranges,
					versions_affected = EXCLUDED.versions_affected`

			if _, err := tx.Exec(ctx, insertPackage,
				vuln.ID,
				pkg.Ecosystem,
				pkg.Name,
				normalizeJSON(pkg.VersionRanges, []byte("[]")),
				normalizeJSON(pkg.VersionsAffected, []byte("[]")),
			); err != nil {
				return fmt.Errorf("insert affected package %s/%s: %w", pkg.Ecosystem, pkg.Name, err)
			}
		}

		return nil
	})
}

func (s *Store) UpsertMaliciousFinding(ctx context.Context, mf *db.MaliciousFinding) error {
	const query = `
		INSERT INTO malicious_findings (
			id, ecosystem, name, versions, source, risk_type, severity,
			summary, description, reference_urls, origin_ref, published, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (id) DO UPDATE SET
			ecosystem = EXCLUDED.ecosystem,
			name = EXCLUDED.name,
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

	_, err := s.pool.Exec(ctx, query,
		mf.ID,
		mf.Ecosystem,
		mf.Name,
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
	_, err := s.pool.Exec(ctx, `DELETE FROM vulnerabilities WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete vulnerability %s: %w", id, err)
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
			id, ecosystem, name, COALESCE(versions::text, ''), source, risk_type, severity,
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

	tag, err := s.pool.Exec(ctx, query, cveIDs)
	if err != nil {
		return 0, fmt.Errorf("postgres: set CISA KEV: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *Store) ClearCISAKEV(ctx context.Context, keepIDs []string) (int, error) {
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

	tag, err := s.pool.Exec(ctx, query, keepIDs)
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
					unnest($2::float8[]) AS score,
					unnest($3::float8[]) AS percentile
			),
			targets AS (
				SELECT v.id, d.score, d.percentile
				FROM data d
				INNER JOIN vulnerabilities v ON v.id = d.cve_id
				UNION
				SELECT va.vulnerability_id, d.score, d.percentile
				FROM data d
				INNER JOIN vulnerability_aliases va ON va.alias_id = d.cve_id
			)
			UPDATE vulnerabilities v
			SET epss_score = t.score, epss_percentile = t.percentile, updated_at = NOW()
			FROM targets t
			WHERE v.id = t.id`

		tag, err := s.pool.Exec(ctx, query, cveIDs, epssScores, percentiles)
		if err != nil {
			return updated, fmt.Errorf("postgres: set EPSS scores batch: %w", err)
		}
		updated += int(tag.RowsAffected())
	}

	return updated, nil
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
					unnest($2::float8[]) AS cvss_score,
					unnest($3::bool[]) AS exploit_exists
			),
			targets AS (
				SELECT v.id, d.cvss_score, d.exploit_exists
				FROM data d
				INNER JOIN vulnerabilities v ON v.id = d.cve_id
				UNION
				SELECT va.vulnerability_id, d.cvss_score, d.exploit_exists
				FROM data d
				INNER JOIN vulnerability_aliases va ON va.alias_id = d.cve_id
			)
			UPDATE vulnerabilities v
			SET
				cvss_score = COALESCE(t.cvss_score, v.cvss_score),
				exploit_exists = v.exploit_exists OR t.exploit_exists,
				updated_at = NOW()
			FROM targets t
			WHERE v.id = t.id`

		tag, err := s.pool.Exec(ctx, batchUpdate, cveIDs, cvssScores, exploitFlags)
		if err != nil {
			return updated, fmt.Errorf("postgres: enrich VulnCheck batch update: %w", err)
		}
		updated += int(tag.RowsAffected())

		// Source upserts still require per-entry execution because each
		// carries its own raw_json blob that cannot be efficiently unnested.
		err = withTx(ctx, s.pool, func(tx pgx.Tx) error {
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
					updated_at = NOW()`

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
			return updated, fmt.Errorf("postgres: enrich VulnCheck sources: %w", err)
		}
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

type findingReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type resourceCandidate struct {
	link  domain.ResourceLink
	score int
}

func buildFindingResources(advisoryID, raw string) []domain.ResourceLink {
	selected := make(map[string]resourceCandidate)
	if link, score, ok := canonicalFindingResource(advisoryID); ok {
		selected[link.Label] = resourceCandidate{link: link, score: score}
	}

	if strings.TrimSpace(raw) == "" {
		return sortedResourceCandidates(selected)
	}

	var refs []findingReference
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return sortedResourceCandidates(selected)
	}

	for _, ref := range refs {
		link, score, ok := classifyFindingResource(advisoryID, ref)
		if !ok {
			continue
		}
		existing, exists := selected[link.Label]
		if !exists || score < existing.score {
			selected[link.Label] = resourceCandidate{link: link, score: score}
		}
	}

	return sortedResourceCandidates(selected)
}

func sortedResourceCandidates(selected map[string]resourceCandidate) []domain.ResourceLink {
	if len(selected) == 0 {
		return nil
	}
	labels := make([]string, 0, len(selected))
	for label := range selected {
		labels = append(labels, label)
	}

	sort.Slice(labels, func(i, j int) bool {
		left := selected[labels[i]]
		right := selected[labels[j]]
		if left.score != right.score {
			return left.score < right.score
		}
		return labels[i] < labels[j]
	})

	out := make([]domain.ResourceLink, 0, len(labels))
	for _, label := range labels {
		out = append(out, selected[label].link)
	}
	return out
}

func canonicalFindingResource(advisoryID string) (domain.ResourceLink, int, bool) {
	switch {
	case strings.HasPrefix(advisoryID, "GHSA-"):
		return domain.ResourceLink{
			Label: "GHSA",
			URL:   "https://github.com/advisories/" + advisoryID,
		}, 5, true
	case strings.HasPrefix(advisoryID, "RUSTSEC-"):
		return domain.ResourceLink{
			Label: "RustSec",
			URL:   "https://rustsec.org/advisories/" + advisoryID + ".html",
		}, 5, true
	case strings.HasPrefix(advisoryID, "CVE-"):
		return domain.ResourceLink{
			Label: "NVD",
			URL:   "https://nvd.nist.gov/vuln/detail/" + advisoryID,
		}, 5, true
	default:
		return domain.ResourceLink{}, 0, false
	}
}

func classifyFindingResource(advisoryID string, ref findingReference) (domain.ResourceLink, int, bool) {
	if strings.TrimSpace(ref.URL) == "" {
		return domain.ResourceLink{}, 0, false
	}
	if !shouldStoreVulnerabilityReference(ref.URL) {
		return domain.ResourceLink{}, 0, false
	}
	if strings.EqualFold(strings.TrimSpace(ref.Type), "PACKAGE") {
		return domain.ResourceLink{}, 0, false
	}

	parsed, err := url.Parse(ref.URL)
	if err != nil {
		return domain.ResourceLink{}, 0, false
	}

	host := strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "www.")
	if isGenericReferenceLandingPage(host, parsed) {
		return domain.ResourceLink{}, 0, false
	}
	path := strings.ToLower(parsed.EscapedPath())
	link := domain.ResourceLink{URL: ref.URL}

	switch {
	case isBlockedReferenceHost(host):
		return domain.ResourceLink{}, 0, false
	case host == "github.com" && strings.Contains(path, "/security/advisories/"):
		link.Label = "GHSA"
		score := 10
		if ghsaID := ghsaIDPattern.FindString(ref.URL); strings.EqualFold(ghsaID, advisoryID) {
			score = 0
		}
		return link, score, true
	case host == "nvd.nist.gov":
		return domain.ResourceLink{Label: "NVD", URL: ref.URL}, resourceScore(advisoryID, "NVD"), true
	case host == "rustsec.org" && strings.Contains(path, "/advisories/"):
		return domain.ResourceLink{Label: "RustSec", URL: ref.URL}, resourceScore(advisoryID, "RustSec"), true
	case host == "osv.dev":
		return domain.ResourceLink{Label: "OSV", URL: ref.URL}, resourceScore(advisoryID, "OSV"), true
	case host == "huntr.com" || host == "huntr.dev":
		return domain.ResourceLink{Label: "Huntr", URL: ref.URL}, resourceScore(advisoryID, "Huntr"), true
	case host == "cve.org" || host == "cve.mitre.org":
		return domain.ResourceLink{Label: "CVE", URL: ref.URL}, resourceScore(advisoryID, "CVE"), true
	case host == "github.com":
		return domain.ResourceLink{Label: "GitHub", URL: ref.URL}, resourceScore(advisoryID, "GitHub"), true
	case host != "":
		return domain.ResourceLink{Label: host, URL: ref.URL}, resourceScore(advisoryID, host), true
	default:
		return domain.ResourceLink{}, 0, false
	}
}

func shouldStoreVulnerabilityReference(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return false
	}
	if containsBlockedReferenceValue(rawURL) {
		return false
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		// Keep unknown-but-non-empty URLs; we only want to block known-bad hosts.
		return true
	}

	return !isBlockedReferenceHost(strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "www."))
}

func containsBlockedReferenceValue(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.Contains(lower, "packetstormsecurity.com") || strings.Contains(lower, "packetstorm.news")
}

func isGenericReferenceLandingPage(host string, parsed *url.URL) bool {
	path := strings.Trim(strings.ToLower(parsed.EscapedPath()), "/")
	if path == "" && parsed.RawQuery == "" && parsed.Fragment == "" {
		return true
	}

	if host == "github.com" && parsed.RawQuery == "" && parsed.Fragment == "" {
		segments := strings.Split(path, "/")
		if len(segments) == 2 && segments[0] != "" && segments[1] != "" && segments[0] != "advisories" {
			return true
		}
	}

	return false
}

func isBlockedReferenceHost(host string) bool {
	switch host {
	case "packetstormsecurity.com", "packetstorm.news":
		return true
	default:
		return false
	}
}

func resourceScore(advisoryID, label string) int {
	preferred := ""
	switch {
	case strings.HasPrefix(advisoryID, "GHSA-"):
		preferred = "GHSA"
	case strings.HasPrefix(advisoryID, "RUSTSEC-"):
		preferred = "RustSec"
	case strings.HasPrefix(advisoryID, "CVE-"):
		preferred = "NVD"
	}

	if label == preferred {
		return 0
	}

	switch label {
	case "GHSA":
		return 10
	case "NVD":
		return 20
	case "RustSec":
		return 30
	case "OSV":
		return 40
	case "Huntr":
		return 50
	case "CVE":
		return 60
	case "GitHub":
		return 70
	default:
		return 100
	}
}
