package postgres

import (
	"context"
	"fmt"
)

// RepairGHSAAffectedPackages backfills missing affected_packages rows from the
// stored GHSA raw JSON. This repairs older advisories that were imported while
// the GHSA ecosystem mapper did not recognize "GitHub Actions".
func (s *Store) RepairGHSAAffectedPackages(ctx context.Context) (int, error) {
	const query = `
		WITH candidates AS (
			SELECT
				vs.vulnerability_id,
				CASE lower(aff.item->'package'->>'ecosystem')
					WHEN 'npm' THEN 'npm'
					WHEN 'pip' THEN 'pypi'
					WHEN 'pypi' THEN 'pypi'
					WHEN 'go' THEN 'go'
					WHEN 'maven' THEN 'maven'
					WHEN 'nuget' THEN 'nuget'
					WHEN 'composer' THEN 'composer'
					WHEN 'packagist' THEN 'composer'
					WHEN 'rubygems' THEN 'gem'
					WHEN 'crates.io' THEN 'cargo'
					WHEN 'pub' THEN 'pub'
					WHEN 'swifturl' THEN 'swiftpm'
					WHEN 'hex' THEN 'hex'
					WHEN 'actions' THEN 'actions'
					WHEN 'github actions' THEN 'actions'
					WHEN 'rust' THEN 'cargo'
					WHEN 'cargo' THEN 'cargo'
					ELSE NULL
				END AS ecosystem,
				aff.item->'package'->>'name' AS name,
				COALESCE(aff.item->'ranges', '[]'::jsonb) AS version_ranges,
				COALESCE(aff.item->'versions', '[]'::jsonb) AS versions_affected
			FROM vulnerability_sources vs
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(vs.raw_json->'affected', '[]'::jsonb)) AS aff(item)
			WHERE vs.source = 'ghsa'
			  AND NOT EXISTS (
				SELECT 1
				FROM affected_packages ap
				WHERE ap.vulnerability_id = vs.vulnerability_id
			  )
		),
		deduped AS (
			SELECT DISTINCT ON (vulnerability_id, ecosystem, name)
				vulnerability_id,
				ecosystem,
				name,
				version_ranges,
				versions_affected
			FROM candidates
			WHERE ecosystem IS NOT NULL
			  AND ecosystem <> ''
			  AND name <> ''
			ORDER BY
				vulnerability_id,
				ecosystem,
				name,
				jsonb_array_length(version_ranges) DESC,
				jsonb_array_length(versions_affected) DESC
		),
		repaired AS (
			INSERT INTO affected_packages (
				vulnerability_id, ecosystem, name, version_ranges, versions_affected
			)
			SELECT
				vulnerability_id,
				ecosystem,
				name,
				version_ranges,
				versions_affected
			FROM deduped
			ON CONFLICT (vulnerability_id, ecosystem, name) DO UPDATE SET
				version_ranges = EXCLUDED.version_ranges,
				versions_affected = EXCLUDED.versions_affected
			RETURNING 1
		)
		SELECT COUNT(*) FROM repaired`

	var repaired int
	if err := s.pool.QueryRow(ctx, query).Scan(&repaired); err != nil {
		return 0, fmt.Errorf("postgres: repair GHSA affected packages: %w", err)
	}
	return repaired, nil
}
