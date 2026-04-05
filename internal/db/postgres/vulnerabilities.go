package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
	"github.com/jackc/pgx/v5"
)

func (s *Store) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	const query = `
		SELECT
			v.id,
			v.summary,
			v.severity,
			COALESCE((
				SELECT url
				FROM vulnerability_references vr
				WHERE vr.vulnerability_id = v.id
				ORDER BY vr.id
				LIMIT 1
			), '') AS ref_url,
			COALESCE((
				SELECT source
				FROM vulnerability_sources vs
				WHERE vs.vulnerability_id = v.id
				ORDER BY vs.id
				LIMIT 1
			), '') AS source,
			ap.version_ranges::text,
			ap.versions_affected::text
		FROM vulnerabilities v
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
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
			url              string
			source           string
			versionRangesRaw string
			versionsRaw      string
		)

		if err := rows.Scan(&advisoryID, &summary, &severity, &url, &source, &versionRangesRaw, &versionsRaw); err != nil {
			return nil, fmt.Errorf("postgres: scan vulnerability row: %w", err)
		}

		fixedVersion := extractFixedVersion(versionRangesRaw)
		if version != "" {
			affected, err := versionAffected(version, versionRangesRaw, versionsRaw)
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

		findings = append(findings, domain.Finding{
			Name:         name,
			Version:      version,
			Ecosystem:    domain.Ecosystem(ecosystem),
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.Severity(normalizeSeverity(severity)),
			AdvisoryID:   advisoryID,
			Title:        title,
			URL:          url,
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
	// versions is a JSONB array of affected versions. NULL means all
	// versions are affected. When a specific version is requested, only
	// return findings where versions IS NULL or the array contains
	// that version.
	const query = `
		SELECT id, severity, summary, risk_type, source, reference_urls::text
		FROM malicious_findings
		WHERE ecosystem = $1 AND name = $2
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
				summary = EXCLUDED.summary,
				details = EXCLUDED.details,
				severity = EXCLUDED.severity,
				cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
				published = EXCLUDED.published,
				modified = EXCLUDED.modified,
				withdrawn = EXCLUDED.withdrawn,
				updated_at = NOW()`

		if _, err := tx.Exec(ctx, upsertVulnerability,
			vuln.ID,
			vuln.Summary,
			nullableString(vuln.Details),
			normalizeSeverity(vuln.Severity),
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
			const insertAlias = `
				INSERT INTO vulnerability_aliases (vulnerability_id, alias_id)
				VALUES ($1, $2)
				ON CONFLICT (alias_id) DO UPDATE SET
					vulnerability_id = EXCLUDED.vulnerability_id`
			if _, err := tx.Exec(ctx, insertAlias, vuln.ID, alias.AliasID); err != nil {
				return fmt.Errorf("insert alias %s: %w", alias.AliasID, err)
			}
		}

		if _, err := tx.Exec(ctx, `DELETE FROM vulnerability_references WHERE vulnerability_id = $1`, vuln.ID); err != nil {
			return fmt.Errorf("delete vulnerability references: %w", err)
		}
		for _, ref := range vuln.References {
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
	_, err := s.pool.Exec(ctx, `DELETE FROM malicious_findings WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete malicious finding %s: %w", id, err)
	}
	return nil
}

func (s *Store) ListMaliciousFindings(ctx context.Context, source string, limit int) ([]db.MaliciousFinding, error) {
	limit = clampLimit(limit, 100, 500)

	query := `
		SELECT
			id, ecosystem, name, versions::text, source, risk_type, severity,
			summary, description, reference_urls::text, origin_ref, published, created_by
		FROM malicious_findings`
	args := []any{}
	if source != "" {
		query += ` WHERE source = $1`
		args = append(args, source)
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

func (s *Store) SetEPSSScores(ctx context.Context, scores []db.EPSSEntry) (int, error) {
	updated := 0
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		const query = `
			WITH targets AS (
				SELECT id
				FROM vulnerabilities
				WHERE id = $1
				UNION
				SELECT vulnerability_id
				FROM vulnerability_aliases
				WHERE alias_id = $1
			)
			UPDATE vulnerabilities v
			SET epss_score = $2, epss_percentile = $3, updated_at = NOW()
			FROM targets t
			WHERE v.id = t.id`

		for _, score := range scores {
			tag, err := tx.Exec(ctx, query, score.CVEID, score.Score, score.Percentile)
			if err != nil {
				return fmt.Errorf("set EPSS score for %s: %w", score.CVEID, err)
			}
			updated += int(tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("postgres: set EPSS scores: %w", err)
	}
	return updated, nil
}

func (s *Store) EnrichVulnCheck(ctx context.Context, entries []db.VulnCheckEntry) (int, error) {
	updated := 0
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		const updateVulnerability = `
			WITH targets AS (
				SELECT id
				FROM vulnerabilities
				WHERE id = $1
				UNION
				SELECT vulnerability_id
				FROM vulnerability_aliases
				WHERE alias_id = $1
			)
			UPDATE vulnerabilities v
			SET
				cvss_score = COALESCE($2, v.cvss_score),
				exploit_exists = v.exploit_exists OR $3,
				updated_at = NOW()
			FROM targets t
			WHERE v.id = t.id`

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

		for _, entry := range entries {
			tag, err := tx.Exec(ctx, updateVulnerability, entry.CVEID, entry.CVSSScore, entry.ExploitExists)
			if err != nil {
				return fmt.Errorf("update vulnerability enrichment for %s: %w", entry.CVEID, err)
			}
			updated += int(tag.RowsAffected())

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
		return 0, fmt.Errorf("postgres: enrich VulnCheck: %w", err)
	}
	return updated, nil
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
