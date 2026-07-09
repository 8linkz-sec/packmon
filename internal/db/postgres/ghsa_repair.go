package postgres

import (
	"context"
	"fmt"
)

// RepairGHSAAffectedPackages reconciles affected_packages rows from stored
// GHSA raw JSON. This repairs older advisories that were imported while the
// GHSA ecosystem mapper did not recognize "GitHub Actions", and refreshes rows
// whose duplicate affected entries were previously collapsed by the unique
// package key.
func (s *Store) RepairGHSAAffectedPackages(ctx context.Context) (int, error) {
	const query = `
	WITH candidates AS (
		SELECT
			vs.vulnerability_id,
			aff.ordinality AS affected_ordinal,
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
			COALESCE(aff.item->'versions', '[]'::jsonb) AS versions_affected,
			(regexp_match(
				COALESCE(aff.item->'database_specific'->>'last_known_affected_version_range', ''),
				'(^|,)\s*<=\s*([^,\s]+)'
			))[2] AS last_affected_bound,
			(regexp_match(
				COALESCE(aff.item->'database_specific'->>'last_known_affected_version_range', ''),
				'(^|,)\s*<\s*([^=,\s]+)'
			))[2] AS fixed_bound
			FROM vulnerability_sources vs
			CROSS JOIN LATERAL jsonb_array_elements(COALESCE(vs.raw_json->'affected', '[]'::jsonb))
				WITH ORDINALITY AS aff(item, ordinality)
			WHERE vs.source = 'ghsa'
			  AND vs.raw_json IS NOT NULL
		),
		normalized AS (
			SELECT
				vulnerability_id,
				affected_ordinal,
				ecosystem,
				name,
				version_ranges,
				versions_affected,
				last_affected_bound,
				fixed_bound
			FROM candidates
			WHERE ecosystem IS NOT NULL
			  AND ecosystem <> ''
			  AND name <> ''
		),
		keys AS (
			SELECT DISTINCT vulnerability_id, ecosystem, name
			FROM normalized
		),
		range_items AS (
			SELECT
				n.vulnerability_id,
				n.ecosystem,
				n.name,
				n.affected_ordinal,
				r.ordinality AS range_ordinal,
				CASE
					WHEN jsonb_array_length(COALESCE(r.item->'events', '[]'::jsonb)) > 0
					  AND NOT EXISTS (
						SELECT 1
						FROM jsonb_array_elements(COALESCE(r.item->'events', '[]'::jsonb)) AS event(item)
						WHERE NULLIF(event.item->>'fixed', '') IS NOT NULL
						   OR NULLIF(event.item->>'last_affected', '') IS NOT NULL
					  )
					  AND n.last_affected_bound IS NOT NULL
						THEN jsonb_set(
							r.item,
							'{events}',
							COALESCE(r.item->'events', '[]'::jsonb) ||
								jsonb_build_array(jsonb_build_object('last_affected', n.last_affected_bound))
						)
					WHEN jsonb_array_length(COALESCE(r.item->'events', '[]'::jsonb)) > 0
					  AND NOT EXISTS (
						SELECT 1
						FROM jsonb_array_elements(COALESCE(r.item->'events', '[]'::jsonb)) AS event(item)
						WHERE NULLIF(event.item->>'fixed', '') IS NOT NULL
						   OR NULLIF(event.item->>'last_affected', '') IS NOT NULL
					  )
					  AND n.fixed_bound IS NOT NULL
						THEN jsonb_set(
							r.item,
							'{events}',
							COALESCE(r.item->'events', '[]'::jsonb) ||
								jsonb_build_array(jsonb_build_object('fixed', n.fixed_bound))
						)
					ELSE r.item
				END AS range_item
			FROM normalized n
			CROSS JOIN LATERAL jsonb_array_elements(
				CASE WHEN jsonb_typeof(n.version_ranges) = 'array' THEN n.version_ranges ELSE '[]'::jsonb END
			) WITH ORDINALITY AS r(item, ordinality)
		),
		ranges AS (
			SELECT
				vulnerability_id,
				ecosystem,
				name,
				jsonb_agg(range_item ORDER BY affected_ordinal, range_ordinal) AS version_ranges
			FROM range_items
			GROUP BY vulnerability_id, ecosystem, name
		),
		version_items AS (
			SELECT
				n.vulnerability_id,
				n.ecosystem,
				n.name,
				v.item AS version_item
			FROM normalized n
			CROSS JOIN LATERAL jsonb_array_elements(
				CASE WHEN jsonb_typeof(n.versions_affected) = 'array' THEN n.versions_affected ELSE '[]'::jsonb END
			) AS v(item)
		),
		versions AS (
			SELECT
				vulnerability_id,
				ecosystem,
				name,
				jsonb_agg(DISTINCT version_item) AS versions_affected
			FROM version_items
			GROUP BY vulnerability_id, ecosystem, name
		),
		deduped AS (
			SELECT
				k.vulnerability_id,
				k.ecosystem,
				k.name,
				COALESCE(r.version_ranges, '[]'::jsonb) AS version_ranges,
				COALESCE(v.versions_affected, '[]'::jsonb) AS versions_affected
			FROM keys k
			LEFT JOIN ranges r USING (vulnerability_id, ecosystem, name)
			LEFT JOIN versions v USING (vulnerability_id, ecosystem, name)
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
				versions_affected = EXCLUDED.versions_affected,
				updated_at = NOW()
			WHERE affected_packages.version_ranges IS DISTINCT FROM EXCLUDED.version_ranges
			   OR affected_packages.versions_affected IS DISTINCT FROM EXCLUDED.versions_affected
			RETURNING 1
		)
		SELECT COUNT(*) FROM repaired`

	var repaired int
	if err := s.pool.QueryRow(ctx, query).Scan(&repaired); err != nil {
		return 0, fmt.Errorf("postgres: repair GHSA affected packages: %w", err)
	}
	return repaired, nil
}
