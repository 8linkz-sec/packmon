package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/findinglinks"
	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/8linkz-sec/packmon/internal/packageid"
	"github.com/jackc/pgx/v5"
)

// normalizePackageName canonicalizes package names for ecosystems whose
// registry identity is case-insensitive.
func normalizePackageName(ecosystem, name string) string {
	return packageid.NormalizeName(ecosystem, name)
}

type storedVersionRange struct {
	Events []storedVersionEvent `json:"events"`
}

type storedVersionEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

func validateStoredStringArrayJSON(id, field string, raw json.RawMessage, allowNull bool) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	if trimmed == "null" {
		if allowNull {
			return nil
		}
		return fmt.Errorf("%s %s must be an array of strings", id, field)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("%s %s must be an array of strings: %w", id, field, err)
	}
	return nil
}

func validateStoredVersionRangesJSON(id, field string, raw json.RawMessage, allowNull bool) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil
	}
	if trimmed == "null" {
		if allowNull {
			return nil
		}
		return fmt.Errorf("%s %s must be an array of range objects", id, field)
	}
	var ranges []storedVersionRange
	if err := json.Unmarshal(raw, &ranges); err != nil {
		return fmt.Errorf("%s %s must be an array of range objects: %w", id, field, err)
	}
	for i, versionRange := range ranges {
		if len(versionRange.Events) == 0 {
			return fmt.Errorf("%s %s[%d].events must not be empty", id, field, i)
		}
		for j, event := range versionRange.Events {
			if strings.TrimSpace(event.Introduced) == "" &&
				strings.TrimSpace(event.Fixed) == "" &&
				strings.TrimSpace(event.LastAffected) == "" &&
				strings.TrimSpace(event.Limit) == "" {
				return fmt.Errorf("%s %s[%d].events[%d] must set introduced, fixed, last_affected, or limit", id, field, i, j)
			}
		}
	}
	return nil
}

func vulnerabilityReferencesLateralSQL(vulnerabilityIDExpr string) string {
	return fmt.Sprintf(`
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
				WHERE vulnerability_id = %[1]s
				UNION ALL
				SELECT 50 AS sort_order, id, 'VULNCHECK' AS ref_type,
					COALESCE(NULLIF(TRIM(url), ''), 'https://vulncheck.com/') AS url
				FROM vulnerability_sources
				WHERE vulnerability_id = %[1]s AND source = 'vulncheck'
			) refs
		) vr ON true`, vulnerabilityIDExpr)
}

func (s *Store) FindVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]domain.Finding, error) {
	name = normalizePackageName(ecosystem, name)
	query := `
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
		` + vulnerabilityReferencesLateralSQL("v.id") + `
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
	defer ioutils.CloseSilently(rows)

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

type packageLookupKey struct {
	ecosystem string
	name      string
}

func packageKey(pkg db.PackageQuery) packageLookupKey {
	return packageLookupKey{
		ecosystem: pkg.Ecosystem,
		name:      normalizePackageName(pkg.Ecosystem, pkg.Name),
	}
}

func packageLookupValues(packages []db.PackageQuery) (string, []any) {
	seen := make(map[packageLookupKey]struct{}, len(packages))
	args := make([]any, 0, len(packages)*2)
	placeholders := make([]string, 0, len(packages))
	paramIdx := 1
	for _, pkg := range packages {
		key := packageKey(pkg)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		placeholders = append(placeholders, fmt.Sprintf("($%d, $%d)", paramIdx, paramIdx+1))
		args = append(args, key.ecosystem, key.name)
		paramIdx += 2
	}
	return strings.Join(placeholders, ", "), args
}

func packageVersionsByKey(packages []db.PackageQuery) map[packageLookupKey][]string {
	versionMap := make(map[packageLookupKey][]string, len(packages))
	for _, pkg := range packages {
		key := packageKey(pkg)
		if _, ok := versionMap[key]; !ok {
			versionMap[key] = nil
		}
		if pkg.Version != "" {
			versionMap[key] = append(versionMap[key], pkg.Version)
		}
	}
	return versionMap
}

type vulnerabilityRow struct {
	advisoryID       string
	summary          string
	severity         string
	refsJSON         string
	source           string
	ecosystem        string
	name             string
	versionRangesRaw string
	versionsRaw      string
}

type vulnerabilityRowScanner interface {
	Scan(dest ...any) error
}

func scanVulnerabilityRow(scanner vulnerabilityRowScanner) (vulnerabilityRow, error) {
	var row vulnerabilityRow
	if err := scanner.Scan(
		&row.advisoryID,
		&row.summary,
		&row.severity,
		&row.refsJSON,
		&row.source,
		&row.ecosystem,
		&row.name,
		&row.versionRangesRaw,
		&row.versionsRaw,
	); err != nil {
		return vulnerabilityRow{}, err
	}
	return row, nil
}

func findingsFromVulnerabilityRow(row vulnerabilityRow, versions []string) []domain.Finding {
	fixedVersion := extractFixedVersion(row.versionRangesRaw)
	title := row.summary
	if title == "" {
		title = row.advisoryID
	}
	source := row.source
	if source == "" {
		source = "unknown"
	}
	resources := buildFindingResources(row.advisoryID, row.refsJSON)
	primaryURL := ""
	if len(resources) > 0 {
		primaryURL = resources[0].URL
	}

	findingForVersion := func(version string) domain.Finding {
		return domain.Finding{
			Name:         row.name,
			Version:      version,
			Ecosystem:    domain.Ecosystem(row.ecosystem),
			Type:         domain.FindingTypeVulnerability,
			Severity:     domain.Severity(normalizeSeverity(row.severity)),
			AdvisoryID:   row.advisoryID,
			Title:        title,
			URL:          primaryURL,
			Resources:    resources,
			FixedVersion: fixedVersion,
			Source:       source,
		}
	}

	if len(versions) == 0 {
		return []domain.Finding{findingForVersion("")}
	}

	findings := make([]domain.Finding, 0, len(versions))
	for _, version := range versions {
		affected, matchErr := versionAffectedWithEcosystem(version, row.versionRangesRaw, row.versionsRaw, row.ecosystem)
		if matchErr == nil && !affected {
			continue
		}
		findings = append(findings, findingForVersion(version))
	}
	return findings
}

func (s *Store) FindVulnerabilitiesBatch(ctx context.Context, packages []db.PackageQuery) ([]domain.Finding, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	lookupValues, args := packageLookupValues(packages)
	if lookupValues == "" {
		return nil, nil
	}

	query := `
		SELECT
			v.id, v.summary, v.severity,
			COALESCE(vr.refs_json, '[]') AS refs_json,
			COALESCE(vs.source, '') AS source,
			ap.ecosystem, ap.name, ap.version_ranges::text, ap.versions_affected::text
		FROM vulnerabilities v
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
		` + vulnerabilityReferencesLateralSQL("v.id") + `
		LEFT JOIN LATERAL (
			SELECT source FROM vulnerability_sources
			WHERE vulnerability_id = v.id ORDER BY id LIMIT 1
		) vs ON true
		WHERE (ap.ecosystem, ap.name) IN (VALUES ` + lookupValues + `)
		  AND v.withdrawn IS NULL
		ORDER BY v.modified DESC, v.id`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: find vulnerabilities batch: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	versionMap := packageVersionsByKey(packages)
	var findings []domain.Finding
	for rows.Next() {
		row, err := scanVulnerabilityRow(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan vulnerability batch row: %w", err)
		}
		key := packageLookupKey{ecosystem: row.ecosystem, name: normalizePackageName(row.ecosystem, row.name)}
		findings = append(findings, findingsFromVulnerabilityRow(row, versionMap[key])...)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate vulnerabilities batch: %w", err)
	}
	return findings, nil
}

func (s *Store) UpsertVulnerability(ctx context.Context, vuln *db.Vulnerability) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return upsertVulnerabilityTx(ctx, tx, vuln)
	})
}

func upsertVulnerabilityTx(ctx context.Context, tx pgx.Tx, vuln *db.Vulnerability) error {
	severity, err := normalizeVulnerabilitySeverity(vuln.Severity)
	if err != nil {
		return err
	}
	for _, source := range vuln.Sources {
		if strings.EqualFold(strings.TrimSpace(source.Source), "manual") {
			if _, err := normalizeManualAdvisoryID(vuln.ID); err != nil {
				return err
			}
			if _, err := normalizeManualAdvisoryID(source.SourceID); err != nil {
				return err
			}
		}
	}

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
		severity,
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

	referenceSources := vulnerabilityReferenceSources(vuln)
	if len(referenceSources) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM vulnerability_references WHERE vulnerability_id = $1 AND source = ANY($2)`, vuln.ID, referenceSources); err != nil {
			return fmt.Errorf("delete source-scoped vulnerability references: %w", err)
		}
	}
	for _, ref := range vuln.References {
		if !shouldStoreVulnerabilityReference(ref.URL) {
			continue
		}
		const insertReference = `
				INSERT INTO vulnerability_references (vulnerability_id, type, url, source)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (vulnerability_id, source, url) DO UPDATE SET
					type = EXCLUDED.type,
					source = EXCLUDED.source`
		if _, err := tx.Exec(ctx, insertReference,
			vuln.ID,
			nullableString(ref.Type),
			ref.URL,
			vulnerabilityReferenceSource(vuln, ref),
		); err != nil {
			return fmt.Errorf("insert reference %s: %w", ref.URL, err)
		}
	}

	for _, pkg := range vuln.AffectedPackages {
		ecosystem, err := normalizeStoredEcosystem(pkg.Ecosystem)
		if err != nil {
			return err
		}
		name := normalizePackageName(ecosystem, pkg.Name)
		if err := validateStoredVersionRangesJSON(vuln.ID, "version_ranges", pkg.VersionRanges, false); err != nil {
			return fmt.Errorf("insert affected package %s/%s: %w", ecosystem, name, err)
		}
		if err := validateStoredStringArrayJSON(vuln.ID, "versions_affected", pkg.VersionsAffected, false); err != nil {
			return fmt.Errorf("insert affected package %s/%s: %w", ecosystem, name, err)
		}
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
			ecosystem,
			name,
			normalizeJSON(pkg.VersionRanges, []byte("[]")),
			normalizeJSON(pkg.VersionsAffected, []byte("[]")),
		); err != nil {
			return fmt.Errorf("insert affected package %s/%s: %w", ecosystem, name, err)
		}
	}

	return nil
}

func vulnerabilityReferenceSources(vuln *db.Vulnerability) []string {
	seen := make(map[string]struct{}, len(vuln.Sources)+len(vuln.References))
	sources := make([]string, 0, len(vuln.Sources)+len(vuln.References))
	for _, source := range vuln.Sources {
		name := strings.TrimSpace(source.Source)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		sources = append(sources, name)
	}
	for _, ref := range vuln.References {
		name := strings.TrimSpace(ref.Source)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		sources = append(sources, name)
	}
	return sources
}

func vulnerabilityReferenceSource(vuln *db.Vulnerability, ref db.VulnerabilityReference) string {
	if source := strings.TrimSpace(ref.Source); source != "" {
		return source
	}
	if len(vuln.Sources) == 1 {
		return strings.TrimSpace(vuln.Sources[0].Source)
	}
	return ""
}

func (s *Store) ImportVulnerabilityFeed(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus) (int, int, error) {
	return s.importVulnerabilityFeed(ctx, feed, items, deleteIDs, status, nil)
}

func (s *Store) ImportVulnerabilityFeedWithAudit(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
	return s.importVulnerabilityFeed(ctx, feed, items, deleteIDs, status, audit)
}

func (s *Store) importVulnerabilityFeed(ctx context.Context, feed string, items []db.Vulnerability, deleteIDs []string, status *db.FeedSyncStatus, audit func(imported, deleted int) *db.AdminAuditEntry) (int, int, error) {
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
		if audit != nil {
			if err := insertAdminAuditLogTx(ctx, tx, audit(imported, deleted)); err != nil {
				return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
			}
		}
		return nil
	})
	return imported, deleted, err
}

func (s *Store) DeleteVulnerability(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE vulnerabilities
		SET withdrawn = COALESCE(withdrawn, NOW()),
		    updated_at = NOW()
		WHERE id = $1
		  AND withdrawn IS NULL`, id)
	if err != nil {
		return fmt.Errorf("postgres: delete vulnerability %s: %w", id, err)
	}
	return nil
}

func (s *Store) DeleteVulnerabilityForSource(ctx context.Context, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("postgres: source-scoped vulnerability delete requires source: %w", db.ErrSourceScopedDeleteSourceRequired)
	}

	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return deleteVulnerabilityForSourceTx(ctx, tx, id, source)
	})
}

func deleteVulnerabilityForSourceTx(ctx context.Context, tx pgx.Tx, id, source string) error {
	source = strings.TrimSpace(source)
	if source == "" {
		return fmt.Errorf("postgres: source-scoped vulnerability delete requires source: %w", db.ErrSourceScopedDeleteSourceRequired)
	}

	var lockedID string
	err := tx.QueryRow(ctx, `
		SELECT id
		FROM vulnerabilities
		WHERE id = $1
		FOR UPDATE`, id).Scan(&lockedID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return fmt.Errorf("lock vulnerability %s before source delete: %w", id, err)
	}

	if _, err := tx.Exec(ctx, `
		DELETE FROM vulnerability_sources
		WHERE vulnerability_id = $1 AND source = $2`, id, source); err != nil {
		return fmt.Errorf("delete vulnerability source %s/%s: %w", id, source, err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE vulnerabilities
		SET withdrawn = COALESCE(withdrawn, NOW()),
		    updated_at = NOW()
		WHERE id = $1
		  AND withdrawn IS NULL
		  AND NOT EXISTS (
			SELECT 1
			FROM vulnerability_sources
			WHERE vulnerability_id = $1
		  )`, id); err != nil {
		return fmt.Errorf("withdraw vulnerability %s after source delete: %w", id, err)
	}
	return nil
}

func extractFirstURL(raw string) string {
	return findinglinks.FirstSafeHTTPURLFromJSON(raw)
}

func buildFindingResources(advisoryID, raw string) []domain.ResourceLink {
	return findinglinks.ResourceLinksFromVulnerabilityReferences(advisoryID, raw)
}

func shouldStoreVulnerabilityReference(rawURL string) bool {
	return findinglinks.ShouldStoreVulnerabilityReference(rawURL)
}
