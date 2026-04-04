package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

// ExportSync returns the flattened vulnerability and malicious data consumed by
// the local SQLite sync endpoint.
func (s *Store) ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	snapshot := opts.SnapshotAt.UTC()
	if snapshot.IsZero() {
		snapshot = time.Now().UTC()
	}

	vulns, err := s.exportSyncVulnerabilities(ctx, opts, snapshot)
	if err != nil {
		return nil, err
	}

	malicious, err := s.exportSyncMalicious(ctx, opts, snapshot)
	if err != nil {
		return nil, err
	}

	return &db.SyncExport{
		SyncedAt:        snapshot,
		Vulnerabilities: vulns,
		Malicious:       malicious,
		Truncated:       false,
	}, nil
}

func (s *Store) exportSyncVulnerabilities(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time) ([]db.SyncVulnerability, error) {
	query := `
		SELECT
			v.id,
			ap.ecosystem,
			ap.name,
			ap.version_ranges::text,
			v.severity,
			v.cvss_score,
			v.epss_score,
			v.cisa_kev,
			v.summary,
			(v.withdrawn IS NOT NULL) AS withdrawn
		FROM vulnerabilities v
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
		WHERE v.updated_at <= $1`

	args := []any{snapshot}
	if opts.Since != nil {
		since := opts.Since.UTC()
		query += fmt.Sprintf(` AND v.updated_at > $%d`, len(args)+1)
		args = append(args, since)
	}
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ap.ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	query += ` ORDER BY ap.ecosystem ASC, ap.name ASC, v.id ASC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: export sync vulnerabilities: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.SyncVulnerability, 0)
	for rows.Next() {
		var item db.SyncVulnerability
		if err := rows.Scan(
			&item.ID,
			&item.Ecosystem,
			&item.Name,
			&item.VersionRanges,
			&item.Severity,
			&item.CVSSScore,
			&item.EPSSScore,
			&item.CISAKEV,
			&item.Summary,
			&item.Withdrawn,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan sync vulnerability row: %w", err)
		}
		item.Severity = normalizeSeverity(item.Severity)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate sync vulnerability rows: %w", err)
	}

	return out, nil
}

func (s *Store) exportSyncMalicious(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time) ([]db.SyncMalicious, error) {
	query := `
		SELECT
			id,
			ecosystem,
			name,
			COALESCE(versions::text, ''),
			risk_type,
			severity,
			summary
		FROM malicious_findings
		WHERE updated_at <= $1`

	args := []any{snapshot}
	if opts.Since != nil {
		since := opts.Since.UTC()
		query += fmt.Sprintf(` AND updated_at > $%d`, len(args)+1)
		args = append(args, since)
	}
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	query += ` ORDER BY ecosystem ASC, name ASC, id ASC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: export sync malicious findings: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.SyncMalicious, 0)
	for rows.Next() {
		var item db.SyncMalicious
		if err := rows.Scan(
			&item.ID,
			&item.Ecosystem,
			&item.Name,
			&item.Versions,
			&item.RiskType,
			&item.Severity,
			&item.Summary,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan sync malicious row: %w", err)
		}
		item.Severity = normalizeSeverity(item.Severity)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate sync malicious rows: %w", err)
	}

	return out, nil
}
