package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/jackc/pgx/v5"
)

// normalizedManualAdvisory validates an operator advisory and returns a copy
// carrying the normalized ID. The persisted rows use that ID, so the lock, the
// revision check, and the counterpart cleanup must use it as well; the
// caller's advisory is left untouched.
func normalizedManualAdvisory(advisory *db.ManualAdvisory) (*db.ManualAdvisory, error) {
	id, err := normalizeManualAdvisoryID(advisory.ID)
	if err != nil {
		return nil, err
	}
	if _, ok := domain.ParseManualAdvisoryFindingType(advisory.FindingType); !ok {
		return nil, fmt.Errorf("postgres: unsupported manual advisory finding type %q", advisory.FindingType)
	}
	normalized := *advisory
	normalized.ID = id
	return &normalized, nil
}

func (s *Store) UpsertManualAdvisory(ctx context.Context, advisory *db.ManualAdvisory) error {
	if advisory == nil {
		return nil
	}
	advisory, err := normalizedManualAdvisory(advisory)
	if err != nil {
		return err
	}
	err = withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLockTx(ctx, tx); err != nil {
			return err
		}
		if err := acquireManualAdvisoryLockTx(ctx, tx, advisory.ID); err != nil {
			return err
		}
		return upsertManualAdvisoryTx(ctx, tx, advisory)
	})
	if err == nil {
		s.invalidateDashboardStats()
	}
	return err
}

func (s *Store) UpsertManualAdvisoryWithAudit(ctx context.Context, advisory *db.ManualAdvisory, audit *db.AdminAuditEntry) error {
	if advisory == nil {
		return nil
	}
	advisory, err := normalizedManualAdvisory(advisory)
	if err != nil {
		return err
	}
	err = withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLockTx(ctx, tx); err != nil {
			return err
		}
		if err := acquireManualAdvisoryLockTx(ctx, tx, advisory.ID); err != nil {
			return err
		}
		if err := checkManualAdvisoryRevisionTx(ctx, tx, advisory); err != nil {
			return err
		}
		if err := upsertManualAdvisoryTx(ctx, tx, advisory); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	if err == nil {
		s.invalidateDashboardStats()
	}
	return err
}

func upsertManualAdvisoryTx(ctx context.Context, tx pgx.Tx, advisory *db.ManualAdvisory) error {
	findingType, ok := domain.ParseManualAdvisoryFindingType(advisory.FindingType)
	if !ok {
		return fmt.Errorf("postgres: unsupported manual advisory finding type %q", advisory.FindingType)
	}
	switch findingType {
	case domain.FindingTypeVulnerability:
		if err := upsertManualVulnerabilityTx(ctx, tx, db.ManualAdvisoryToVulnerability(advisory)); err != nil {
			return err
		}
		_, err := deleteManualMaliciousFindingTx(ctx, tx, advisory.ID)
		return err
	case domain.FindingTypeMalicious:
		if err := upsertMaliciousFindingTx(ctx, tx, db.ManualAdvisoryToMaliciousFinding(advisory)); err != nil {
			return err
		}
		_, err := deleteManualVulnerabilityTx(ctx, tx, advisory.ID)
		return err
	default:
		return fmt.Errorf("postgres: unsupported manual advisory finding type %q", advisory.FindingType)
	}
}

// upsertManualVulnerabilityTx persists an operator vulnerability advisory with
// replace semantics. The shared feed merge (upsertVulnerabilityTx) keeps the
// previous details when a field is cleared, never lowers severity, and only
// adds affected packages. Those rules protect feed data from weaker feeds, but
// an operator edit is authoritative: after the merge, the advisory's summary,
// details, and severity are overwritten and affected packages the edit no
// longer names are removed, so the stored advisory (and the audit record of
// the edit) is exactly what the operator submitted.
func upsertManualVulnerabilityTx(ctx context.Context, tx pgx.Tx, vuln *db.Vulnerability) error {
	severity, err := normalizeVulnerabilitySeverity(vuln.Severity)
	if err != nil {
		return err
	}
	ecosystems, names, err := manualVulnerabilityPackageKeys(vuln)
	if err != nil {
		return err
	}
	if err := upsertVulnerabilityTx(ctx, tx, vuln); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE vulnerabilities
		SET summary = $2,
		    details = $3::text,
		    severity = $4,
		    updated_at = NOW()
		WHERE id = $1
		  AND (summary IS DISTINCT FROM $2
		       OR details IS DISTINCT FROM $3::text
		       OR severity IS DISTINCT FROM $4)`,
		vuln.ID, vuln.Summary, nullableString(vuln.Details), severity,
	); err != nil {
		return fmt.Errorf("postgres: replace manual vulnerability %s: %w", vuln.ID, err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM affected_packages ap
		WHERE ap.vulnerability_id = $1
		  AND NOT EXISTS (
			SELECT 1
			FROM unnest($2::text[], $3::text[]) AS keep(ecosystem, name)
			WHERE keep.ecosystem = ap.ecosystem
			  AND keep.name = ap.name
		  )`,
		vuln.ID, ecosystems, names,
	); err != nil {
		return fmt.Errorf("postgres: replace manual vulnerability %s affected packages: %w", vuln.ID, err)
	}
	return nil
}

// manualVulnerabilityPackageKeys returns the canonical ecosystem/name pairs a
// manual vulnerability keeps, normalized exactly as upsertVulnerabilityTx
// stores them.
func manualVulnerabilityPackageKeys(vuln *db.Vulnerability) ([]string, []string, error) {
	ecosystems := make([]string, 0, len(vuln.AffectedPackages))
	names := make([]string, 0, len(vuln.AffectedPackages))
	for _, pkg := range vuln.AffectedPackages {
		ecosystem, err := normalizeStoredEcosystem(pkg.Ecosystem)
		if err != nil {
			return nil, nil, err
		}
		ecosystems = append(ecosystems, ecosystem)
		names = append(names, normalizePackageName(ecosystem, pkg.Name))
	}
	return ecosystems, names, nil
}

func (s *Store) DeleteManualAdvisory(ctx context.Context, id string) error {
	id, err := normalizeManualAdvisoryID(id)
	if err != nil {
		return err
	}
	err = withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLockTx(ctx, tx); err != nil {
			return err
		}
		if err := acquireManualAdvisoryLockTx(ctx, tx, id); err != nil {
			return err
		}
		return deleteManualAdvisoryTx(ctx, tx, id)
	})
	if err == nil {
		s.invalidateDashboardStats()
	}
	return err
}

func (s *Store) DeleteManualAdvisoryWithAudit(ctx context.Context, id string, audit *db.AdminAuditEntry) error {
	id, err := normalizeManualAdvisoryID(id)
	if err != nil {
		return err
	}
	err = withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := acquireMaliciousMutationLockTx(ctx, tx); err != nil {
			return err
		}
		if err := acquireManualAdvisoryLockTx(ctx, tx, id); err != nil {
			return err
		}
		if err := deleteManualAdvisoryTx(ctx, tx, id); err != nil {
			return err
		}
		if err := insertAdminAuditLogTx(ctx, tx, audit); err != nil {
			return fmt.Errorf("%w: %v", db.ErrAdminAuditLog, err)
		}
		return nil
	})
	if err == nil {
		s.invalidateDashboardStats()
	}
	return err
}

func deleteManualAdvisoryTx(ctx context.Context, tx pgx.Tx, id string) error {
	deletedMalicious, err := deleteManualMaliciousFindingTx(ctx, tx, id)
	if err != nil {
		return err
	}
	deletedVulnerability, err := deleteManualVulnerabilityTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if deletedMalicious+deletedVulnerability == 0 {
		return fmt.Errorf("postgres: delete manual advisory %s: not found", id)
	}
	return nil
}

func (s *Store) ListManualAdvisories(ctx context.Context, limit int) ([]db.ManualAdvisory, error) {
	return s.ListManualAdvisoriesPage(ctx, limit, 0)
}

func (s *Store) ListManualAdvisoriesPage(ctx context.Context, limit, offset int) ([]db.ManualAdvisory, error) {
	limit = clampLimit(limit, 100, 500)
	if offset < 0 {
		offset = 0
	}

	const query = `
		SELECT finding_type, id, ecosystem, name, severity, risk_type, summary, description, updated_at
		FROM (
			SELECT
				'malicious'::text AS finding_type,
				id,
				ecosystem,
				name,
				severity,
				COALESCE(risk_type, '') AS risk_type,
				summary,
				COALESCE(description, '') AS description,
				updated_at
			FROM malicious_findings
			WHERE source = $3 AND removed_at IS NULL

			UNION ALL

			SELECT
				'vulnerability'::text AS finding_type,
				v.id,
				ap.ecosystem,
				ap.name,
				v.severity,
				''::text AS risk_type,
				v.summary,
				COALESCE(v.details, '') AS description,
				v.updated_at
			FROM vulnerability_sources vs
			INNER JOIN vulnerabilities v ON v.id = vs.vulnerability_id
			INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
			WHERE vs.source = $3
			  AND vs.raw_json IS NOT NULL
			  AND v.withdrawn IS NULL
		) manual
		ORDER BY updated_at DESC, id DESC
		LIMIT $1 OFFSET $2`

	rows, err := s.pool.Query(ctx, query, limit, offset, domain.ManualAdvisorySource)
	if err != nil {
		return nil, fmt.Errorf("postgres: list manual advisories: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.ManualAdvisory, 0)
	for rows.Next() {
		var item db.ManualAdvisory
		if err := rows.Scan(
			&item.FindingType,
			&item.ID,
			&item.Ecosystem,
			&item.Name,
			&item.Severity,
			&item.RiskType,
			&item.Summary,
			&item.Description,
			&item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan manual advisory row: %w", err)
		}
		item.Severity = normalizeSeverity(item.Severity)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate manual advisories: %w", err)
	}
	return out, nil
}

func (s *Store) GetManualAdvisory(ctx context.Context, id string) (*db.ManualAdvisory, error) {
	const query = `
		SELECT finding_type, id, ecosystem, name, severity, risk_type, summary, description, updated_at
		FROM (
			SELECT
				'malicious'::text AS finding_type,
				id,
				ecosystem,
				name,
				severity,
				COALESCE(risk_type, '') AS risk_type,
				summary,
				COALESCE(description, '') AS description,
				updated_at
			FROM malicious_findings
			WHERE source = $2 AND removed_at IS NULL

			UNION ALL

			SELECT
				'vulnerability'::text AS finding_type,
				v.id,
				ap.ecosystem,
				ap.name,
				v.severity,
				''::text AS risk_type,
				v.summary,
				COALESCE(v.details, '') AS description,
				v.updated_at
			FROM vulnerability_sources vs
			INNER JOIN vulnerabilities v ON v.id = vs.vulnerability_id
			INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
			WHERE vs.source = $2
			  AND vs.raw_json IS NOT NULL
			  AND v.withdrawn IS NULL
		) manual
		WHERE id = $1
		ORDER BY updated_at DESC, id DESC
		LIMIT 1`

	var item db.ManualAdvisory
	err := s.pool.QueryRow(ctx, query, strings.TrimSpace(id), domain.ManualAdvisorySource).Scan(
		&item.FindingType,
		&item.ID,
		&item.Ecosystem,
		&item.Name,
		&item.Severity,
		&item.RiskType,
		&item.Summary,
		&item.Description,
		&item.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get manual advisory %s: %w", id, err)
	}
	item.Severity = normalizeSeverity(item.Severity)
	return &item, nil
}

func deleteManualMaliciousFindingTx(ctx context.Context, tx pgx.Tx, id string) (int, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE malicious_findings
		SET removed_at = COALESCE(removed_at, NOW()),
		    updated_at = NOW()
		WHERE id = $1 AND source = $2 AND removed_at IS NULL`, id, domain.ManualAdvisorySource)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete manual malicious finding %s: %w", id, err)
	}
	return int(tag.RowsAffected()), nil
}

func deleteManualVulnerabilityTx(ctx context.Context, tx pgx.Tx, id string) (int, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE vulnerabilities v
		SET withdrawn = COALESCE(withdrawn, NOW()),
		    updated_at = NOW()
		WHERE v.id = $1
		  AND v.withdrawn IS NULL
		  AND EXISTS (
			SELECT 1 FROM vulnerability_sources vs
			WHERE vs.vulnerability_id = v.id
			  AND vs.source = $2
			  AND vs.raw_json IS NOT NULL
		  )`, id, domain.ManualAdvisorySource)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete manual vulnerability %s: %w", id, err)
	}
	return int(tag.RowsAffected()), nil
}

func acquireManualAdvisoryLockTx(ctx context.Context, tx pgx.Tx, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, manualAdvisoryLockKey(id)); err != nil {
		return fmt.Errorf("postgres: acquire manual advisory lock %s: %w", id, err)
	}
	return nil
}

func manualAdvisoryLockKey(id string) int64 {
	sum := sha256.Sum256([]byte("packmon:manual_advisory:" + strings.TrimSpace(id)))
	// The wrap-around is intended: PostgreSQL advisory locks take a signed 64-bit
	// key and only its uniqueness matters, not its numeric value.
	//nolint:gosec // G115: deliberate reinterpretation of hash bits as a lock key.
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func checkManualAdvisoryRevisionTx(ctx context.Context, tx pgx.Tx, advisory *db.ManualAdvisory) error {
	if advisory == nil || advisory.UpdatedAt.IsZero() {
		return nil
	}
	current, found, err := getManualAdvisoryUpdatedAtTx(ctx, tx, advisory.ID)
	if err != nil {
		return err
	}
	if !found || !current.Equal(advisory.UpdatedAt) {
		return db.ErrConflict
	}
	return nil
}

func getManualAdvisoryUpdatedAtTx(ctx context.Context, tx pgx.Tx, id string) (time.Time, bool, error) {
	const query = `
		SELECT updated_at
		FROM (
			SELECT id, updated_at
			FROM malicious_findings
			WHERE source = $2 AND removed_at IS NULL

			UNION ALL

			SELECT v.id, v.updated_at
			FROM vulnerability_sources vs
			INNER JOIN vulnerabilities v ON v.id = vs.vulnerability_id
			WHERE vs.source = $2
			  AND vs.raw_json IS NOT NULL
			  AND v.withdrawn IS NULL
		) manual
		WHERE id = $1
		ORDER BY updated_at DESC, id DESC
		LIMIT 1`
	var updatedAt time.Time
	err := tx.QueryRow(ctx, query, strings.TrimSpace(id), domain.ManualAdvisorySource).Scan(&updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("postgres: get manual advisory revision %s: %w", id, err)
	}
	return updatedAt, true, nil
}
