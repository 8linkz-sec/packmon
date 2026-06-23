package postgres

import (
	"context"
	"fmt"
)

// RepairCaseInsensitivePackageNames reconciles legacy rows written before
// package names were canonicalized at write boundaries.
func (s *Store) RepairCaseInsensitivePackageNames(ctx context.Context) (int, error) {
	affected, err := s.repairAffectedPackageNames(ctx)
	if err != nil {
		return 0, err
	}
	malicious, err := s.repairMaliciousPackageNames(ctx)
	if err != nil {
		return 0, err
	}
	return affected + malicious, nil
}

func (s *Store) repairAffectedPackageNames(ctx context.Context) (int, error) {
	const query = `
	WITH normalized AS (
		SELECT
			id,
			vulnerability_id,
			ecosystem,
			name,
			CASE
				WHEN lower(ecosystem) = 'nuget' THEN lower(name)
				WHEN lower(ecosystem) = 'pypi' THEN regexp_replace(lower(name), '[-_.]+', '-', 'g')
				ELSE name
			END AS normalized_name,
			version_ranges,
			versions_affected
		FROM affected_packages
		WHERE lower(ecosystem) IN ('pypi', 'nuget')
	),
	changed_groups AS (
		SELECT vulnerability_id, ecosystem, normalized_name AS name
		FROM normalized
		GROUP BY vulnerability_id, ecosystem, normalized_name
		HAVING bool_or(name IS DISTINCT FROM normalized_name) OR count(*) > 1
	),
	range_items AS (
		SELECT
			n.vulnerability_id,
			n.ecosystem,
			n.normalized_name AS name,
			r.item AS item
		FROM normalized n
		INNER JOIN changed_groups g
			ON g.vulnerability_id = n.vulnerability_id
			AND g.ecosystem = n.ecosystem
			AND g.name = n.normalized_name
		CROSS JOIN LATERAL jsonb_array_elements(
			CASE WHEN jsonb_typeof(n.version_ranges) = 'array' THEN n.version_ranges ELSE '[]'::jsonb END
		) AS r(item)
	),
	merged_ranges AS (
		SELECT vulnerability_id, ecosystem, name, jsonb_agg(DISTINCT item) AS version_ranges
		FROM range_items
		GROUP BY vulnerability_id, ecosystem, name
	),
	version_items AS (
		SELECT
			n.vulnerability_id,
			n.ecosystem,
			n.normalized_name AS name,
			v.item AS item
		FROM normalized n
		INNER JOIN changed_groups g
			ON g.vulnerability_id = n.vulnerability_id
			AND g.ecosystem = n.ecosystem
			AND g.name = n.normalized_name
		CROSS JOIN LATERAL jsonb_array_elements(
			CASE WHEN jsonb_typeof(n.versions_affected) = 'array' THEN n.versions_affected ELSE '[]'::jsonb END
		) AS v(item)
	),
	merged_versions AS (
		SELECT vulnerability_id, ecosystem, name, jsonb_agg(DISTINCT item) AS versions_affected
		FROM version_items
		GROUP BY vulnerability_id, ecosystem, name
	),
	merged AS (
		SELECT
			g.vulnerability_id,
			g.ecosystem,
			g.name,
			COALESCE(r.version_ranges, '[]'::jsonb) AS version_ranges,
			COALESCE(v.versions_affected, '[]'::jsonb) AS versions_affected
		FROM changed_groups g
		LEFT JOIN merged_ranges r USING (vulnerability_id, ecosystem, name)
		LEFT JOIN merged_versions v USING (vulnerability_id, ecosystem, name)
	),
	upserted AS (
		INSERT INTO affected_packages (
			vulnerability_id, ecosystem, name, version_ranges, versions_affected
		)
		SELECT vulnerability_id, ecosystem, name, version_ranges, versions_affected
		FROM merged
		ON CONFLICT (vulnerability_id, ecosystem, name) DO UPDATE SET
			version_ranges = EXCLUDED.version_ranges,
			versions_affected = EXCLUDED.versions_affected,
			updated_at = NOW()
		WHERE affected_packages.version_ranges IS DISTINCT FROM EXCLUDED.version_ranges
		   OR affected_packages.versions_affected IS DISTINCT FROM EXCLUDED.versions_affected
		RETURNING 1
	),
	deleted AS (
		DELETE FROM affected_packages ap
		USING normalized n
		INNER JOIN changed_groups g
			ON g.vulnerability_id = n.vulnerability_id
			AND g.ecosystem = n.ecosystem
			AND g.name = n.normalized_name
		WHERE ap.id = n.id
		  AND n.name IS DISTINCT FROM n.normalized_name
		RETURNING 1
	)
	SELECT
		(SELECT count(*) FROM upserted) +
		(SELECT count(*) FROM deleted)`

	var repaired int
	if err := s.pool.QueryRow(ctx, query).Scan(&repaired); err != nil {
		return 0, fmt.Errorf("postgres: repair affected package names: %w", err)
	}
	return repaired, nil
}

func (s *Store) repairMaliciousPackageNames(ctx context.Context) (int, error) {
	const query = `
	WITH normalized AS (
		SELECT
			id,
			CASE
				WHEN lower(ecosystem) = 'nuget' THEN lower(name)
				WHEN lower(ecosystem) = 'pypi' THEN regexp_replace(lower(name), '[-_.]+', '-', 'g')
				ELSE name
			END AS normalized_name
		FROM malicious_findings
		WHERE lower(ecosystem) IN ('pypi', 'nuget')
	),
	repaired AS (
		UPDATE malicious_findings mf
		SET name = n.normalized_name,
			updated_at = NOW()
		FROM normalized n
		WHERE mf.id = n.id
		  AND mf.name IS DISTINCT FROM n.normalized_name
		RETURNING 1
	)
	SELECT count(*) FROM repaired`

	var repaired int
	if err := s.pool.QueryRow(ctx, query).Scan(&repaired); err != nil {
		return 0, fmt.Errorf("postgres: repair malicious package names: %w", err)
	}
	return repaired, nil
}
