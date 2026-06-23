package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) UpsertManualAdvisory(ctx context.Context, advisory *db.ManualAdvisory) error {
	if advisory == nil {
		return nil
	}
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return upsertManualAdvisoryTx(ctx, tx, advisory)
	})
}

func (s *Store) UpsertManualAdvisoryWithAudit(ctx context.Context, advisory *db.ManualAdvisory, audit *db.AdminAuditEntry) error {
	if advisory == nil {
		return nil
	}
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := upsertManualAdvisoryTx(ctx, tx, advisory); err != nil {
			return err
		}
		return insertAdminAuditLogTx(ctx, tx, audit)
	})
}

func upsertManualAdvisoryTx(ctx context.Context, tx pgx.Tx, advisory *db.ManualAdvisory) error {
	switch normalizeManualAdvisoryType(advisory.FindingType) {
	case "vulnerability":
		if err := upsertVulnerabilityTx(ctx, tx, manualAdvisoryToVulnerability(advisory)); err != nil {
			return err
		}
		_, err := deleteManualMaliciousFindingTx(ctx, tx, advisory.ID)
		return err
	default:
		if err := upsertMaliciousFindingTx(ctx, tx, manualAdvisoryToMaliciousFinding(advisory)); err != nil {
			return err
		}
		_, err := deleteManualVulnerabilityTx(ctx, tx, advisory.ID)
		return err
	}
}

func (s *Store) DeleteManualAdvisory(ctx context.Context, id string) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		return deleteManualAdvisoryTx(ctx, tx, id)
	})
}

func (s *Store) DeleteManualAdvisoryWithAudit(ctx context.Context, id string, audit *db.AdminAuditEntry) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := deleteManualAdvisoryTx(ctx, tx, id); err != nil {
			return err
		}
		return insertAdminAuditLogTx(ctx, tx, audit)
	})
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
			WHERE source = 'manual' AND removed_at IS NULL

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
			FROM vulnerabilities v
			INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
			WHERE v.withdrawn IS NULL
			  AND EXISTS (
				SELECT 1 FROM vulnerability_sources vs
				WHERE vs.vulnerability_id = v.id AND vs.source = 'manual'
			)
		) manual
		ORDER BY updated_at DESC, id DESC
		LIMIT $1 OFFSET $2`

	rows, err := s.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: list manual advisories: %w", err)
	}
	defer closeSilently(rows)

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
			WHERE source = 'manual' AND removed_at IS NULL

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
			FROM vulnerabilities v
			INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
			WHERE v.withdrawn IS NULL
			  AND EXISTS (
				SELECT 1 FROM vulnerability_sources vs
				WHERE vs.vulnerability_id = v.id AND vs.source = 'manual'
			)
		) manual
		WHERE id = $1
		ORDER BY updated_at DESC, id DESC
		LIMIT 1`

	var item db.ManualAdvisory
	err := s.pool.QueryRow(ctx, query, id).Scan(
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
		WHERE id = $1 AND source = 'manual' AND removed_at IS NULL`, id)
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
			WHERE vs.vulnerability_id = v.id AND vs.source = 'manual'
		  )`, id)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete manual vulnerability %s: %w", id, err)
	}
	return int(tag.RowsAffected()), nil
}

func normalizeManualAdvisoryType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "vulnerability":
		return "vulnerability"
	default:
		return "malicious"
	}
}

func manualAdvisoryToVulnerability(advisory *db.ManualAdvisory) *db.Vulnerability {
	now := time.Now().UTC()
	severity := strings.ToUpper(strings.TrimSpace(advisory.Severity))
	if severity == "" {
		severity = "UNKNOWN"
	}
	raw, _ := json.Marshal(map[string]string{
		"finding_type": "vulnerability",
		"created_by":   "admin",
	})

	id := strings.TrimSpace(advisory.ID)
	return &db.Vulnerability{
		ID:        id,
		Summary:   strings.TrimSpace(advisory.Summary),
		Details:   strings.TrimSpace(advisory.Description),
		Severity:  severity,
		Published: now,
		Modified:  now,
		Aliases: []db.VulnerabilityAlias{
			{AliasID: id},
		},
		Sources: []db.VulnerabilitySource{
			{
				Source:   "manual",
				SourceID: id,
				RawJSON:  raw,
			},
		},
		AffectedPackages: []db.AffectedPackage{
			{
				Ecosystem:        strings.TrimSpace(advisory.Ecosystem),
				Name:             strings.TrimSpace(advisory.Name),
				VersionRanges:    json.RawMessage("[]"),
				VersionsAffected: json.RawMessage("[]"),
			},
		},
	}
}

func manualAdvisoryToMaliciousFinding(advisory *db.ManualAdvisory) *db.MaliciousFinding {
	riskType := strings.TrimSpace(advisory.RiskType)
	if riskType == "" {
		riskType = "other"
	}
	severity := strings.ToUpper(strings.TrimSpace(advisory.Severity))
	if severity == "" {
		severity = "CRITICAL"
	}
	return &db.MaliciousFinding{
		ID:          strings.TrimSpace(advisory.ID),
		Ecosystem:   strings.TrimSpace(advisory.Ecosystem),
		Name:        strings.TrimSpace(advisory.Name),
		Source:      "manual",
		RiskType:    riskType,
		Severity:    severity,
		Summary:     strings.TrimSpace(advisory.Summary),
		Description: strings.TrimSpace(advisory.Description),
		CreatedBy:   "admin",
	}
}
