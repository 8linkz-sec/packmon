package postgres

import (
	"context"
	"fmt"
	"strconv"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

// RepairCaseInsensitivePackageNames reconciles legacy rows written before
// package names were canonicalized at write boundaries.
func (s *Store) RepairCaseInsensitivePackageNames(ctx context.Context) (int, error) {
	var repaired int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLocksTx(ctx, tx, "", true); err != nil {
			return err
		}
		affected, err := repairAffectedPackageNames(ctx, tx)
		if err != nil {
			return err
		}
		malicious, err := repairMaliciousPackageNames(ctx, tx)
		if err != nil {
			return err
		}
		repaired = affected + malicious
		return nil
	})
	if err != nil {
		return 0, err
	}
	s.invalidateDashboardStats()
	return repaired, nil
}

// RepairCaseInsensitivePackageNamesWithAudit reconciles legacy package-name
// rows and writes the required startup repair audit row in the same transaction.
func (s *Store) RepairCaseInsensitivePackageNamesWithAudit(ctx context.Context, audit *db.AdminAuditEntry) (int, error) {
	var repaired int
	err := withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLocksTx(ctx, tx, "", true); err != nil {
			return err
		}
		affected, err := repairAffectedPackageNames(ctx, tx)
		if err != nil {
			return err
		}
		malicious, err := repairMaliciousPackageNames(ctx, tx)
		if err != nil {
			return err
		}
		repaired = affected + malicious
		if err := db.SetAdminAuditDetail(audit, "repaired", strconv.Itoa(repaired)); err != nil {
			return fmt.Errorf("postgres: prepare package name repair audit: %w", err)
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	s.invalidateDashboardStats()
	return repaired, nil
}

// repairAffectedPackageNamesSQL folds affected_packages names into the
// canonical identity (canonicalPackageNameSQL, the SQL form of
// packageid.NormalizeName) for every ecosystem: legacy mixed-case GitHub
// Actions names and names with surrounding whitespace, including the
// lower-cased but untrimmed names an earlier pypi/nuget-only repair left
// behind. Rows of one advisory that collide on the canonical name are merged
// into a single canonical row (union of their version ranges and versions),
// and the non-canonical rows are deleted. Names that would canonicalize to an
// empty string are left alone.
const repairAffectedPackageNamesSQL = `
	WITH changed AS (
		SELECT id, vulnerability_id, ecosystem, normalized_name, version_ranges, versions_affected
		FROM (
			SELECT
				id,
				vulnerability_id,
				ecosystem,
				name,
				` + canonicalPackageNameSQL + ` AS normalized_name,
				version_ranges,
				versions_affected
			FROM (
				SELECT id, vulnerability_id, ecosystem, name, name AS raw_name, version_ranges, versions_affected
				FROM affected_packages
			) src
		) canonical
		WHERE name IS DISTINCT FROM normalized_name
		  AND normalized_name <> ''
	),
	changed_groups AS (
		SELECT DISTINCT vulnerability_id, ecosystem, normalized_name AS name
		FROM changed
	),
	members AS (
		SELECT vulnerability_id, ecosystem, normalized_name AS name, version_ranges, versions_affected
		FROM changed
		UNION ALL
		SELECT ap.vulnerability_id, ap.ecosystem, ap.name, ap.version_ranges, ap.versions_affected
		FROM changed_groups g
		INNER JOIN affected_packages ap
			ON ap.vulnerability_id = g.vulnerability_id
			AND ap.ecosystem = g.ecosystem
			AND ap.name = g.name
	),
	range_items AS (
		SELECT m.vulnerability_id, m.ecosystem, m.name, r.item AS item
		FROM members m
		CROSS JOIN LATERAL jsonb_array_elements(
			CASE WHEN jsonb_typeof(m.version_ranges) = 'array' THEN m.version_ranges ELSE '[]'::jsonb END
		) AS r(item)
	),
	merged_ranges AS (
		SELECT vulnerability_id, ecosystem, name, jsonb_agg(DISTINCT item) AS version_ranges
		FROM range_items
		GROUP BY vulnerability_id, ecosystem, name
	),
	version_items AS (
		SELECT m.vulnerability_id, m.ecosystem, m.name, v.item AS item
		FROM members m
		CROSS JOIN LATERAL jsonb_array_elements(
			CASE WHEN jsonb_typeof(m.versions_affected) = 'array' THEN m.versions_affected ELSE '[]'::jsonb END
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
		USING changed c
		WHERE ap.id = c.id
		RETURNING 1
	)
	SELECT
		(SELECT count(*) FROM upserted) +
		(SELECT count(*) FROM deleted)`

func repairAffectedPackageNames(ctx context.Context, querier postgresQueryRower) (int, error) {
	var repaired int
	if err := querier.QueryRow(ctx, repairAffectedPackageNamesSQL).Scan(&repaired); err != nil {
		return 0, fmt.Errorf("postgres: repair affected package names: %w", err)
	}
	return repaired, nil
}

// repairMaliciousPackageNamesSQL renames malicious_findings rows to the
// canonical package identity (canonicalPackageNameSQL) for every ecosystem.
// Rows are keyed by id, so there is nothing to merge; updated_at moves so the
// renamed rows reach local clients through the next delta sync.
const repairMaliciousPackageNamesSQL = `
	WITH normalized AS (
		SELECT id, normalized_name
		FROM (
			SELECT
				id,
				name,
				` + canonicalPackageNameSQL + ` AS normalized_name
			FROM (
				SELECT id, ecosystem, name, name AS raw_name
				FROM malicious_findings
			) src
		) canonical
		WHERE name IS DISTINCT FROM normalized_name
		  AND normalized_name <> ''
	),
	repaired AS (
		UPDATE malicious_findings mf
		SET name = n.normalized_name,
			updated_at = NOW()
		FROM normalized n
		WHERE mf.id = n.id
		RETURNING 1
	)
	SELECT count(*) FROM repaired`

func repairMaliciousPackageNames(ctx context.Context, querier postgresQueryRower) (int, error) {
	var repaired int
	if err := querier.QueryRow(ctx, repairMaliciousPackageNamesSQL).Scan(&repaired); err != nil {
		return 0, fmt.Errorf("postgres: repair malicious package names: %w", err)
	}
	return repaired, nil
}
