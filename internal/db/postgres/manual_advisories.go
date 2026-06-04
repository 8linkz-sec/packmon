package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/jackc/pgx/v5"
)

func (s *Store) UpsertManualAdvisory(ctx context.Context, advisory *db.ManualAdvisory) error {
	if advisory == nil {
		return nil
	}

	switch normalizeManualAdvisoryType(advisory.FindingType) {
	case "vulnerability":
		if err := s.UpsertVulnerability(ctx, manualAdvisoryToVulnerability(advisory)); err != nil {
			return err
		}
		return s.deleteManualMaliciousFinding(ctx, advisory.ID)
	default:
		if err := s.UpsertMaliciousFinding(ctx, manualAdvisoryToMaliciousFinding(advisory)); err != nil {
			return err
		}
		return s.deleteManualVulnerability(ctx, advisory.ID)
	}
}

func (s *Store) DeleteManualAdvisory(ctx context.Context, id string) error {
	return withTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE malicious_findings
			SET removed_at = COALESCE(removed_at, NOW()),
			    updated_at = NOW()
			WHERE id = $1 AND source = 'manual'`, id); err != nil {
			return fmt.Errorf("delete manual malicious finding %s: %w", id, err)
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM vulnerabilities v
			WHERE v.id = $1
			  AND EXISTS (
				SELECT 1 FROM vulnerability_sources vs
				WHERE vs.vulnerability_id = v.id AND vs.source = 'manual'
			  )`, id); err != nil {
			return fmt.Errorf("delete manual vulnerability %s: %w", id, err)
		}
		return nil
	})
}

func (s *Store) ListManualAdvisories(ctx context.Context, limit int) ([]db.ManualAdvisory, error) {
	limit = clampLimit(limit, 100, 500)

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
				'vulnerability'::text AS risk_type,
				v.summary,
				COALESCE(v.details, '') AS description,
				v.updated_at
			FROM vulnerabilities v
			INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
			WHERE EXISTS (
				SELECT 1 FROM vulnerability_sources vs
				WHERE vs.vulnerability_id = v.id AND vs.source = 'manual'
			)
		) manual
		ORDER BY updated_at DESC, id DESC
		LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
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

func (s *Store) deleteManualMaliciousFinding(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE malicious_findings
		SET removed_at = COALESCE(removed_at, NOW()),
		    updated_at = NOW()
		WHERE id = $1 AND source = 'manual'`, id); err != nil {
		return fmt.Errorf("postgres: delete manual malicious finding %s: %w", id, err)
	}
	return nil
}

func (s *Store) deleteManualVulnerability(ctx context.Context, id string) error {
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM vulnerabilities v
		WHERE v.id = $1
		  AND EXISTS (
			SELECT 1 FROM vulnerability_sources vs
			WHERE vs.vulnerability_id = v.id AND vs.source = 'manual'
		  )`, id); err != nil {
		return fmt.Errorf("postgres: delete manual vulnerability %s: %w", id, err)
	}
	return nil
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
