package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/domain"
)

// ExportSync returns the flattened vulnerability and malicious data consumed by
// the local SQLite sync endpoint.
func (s *Store) ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	snapshot := opts.SnapshotAt.UTC()
	if snapshot.IsZero() {
		snapshot = time.Now().UTC()
	}
	cursor := opts.EffectiveCursor()

	vulns, err := s.exportSyncVulnerabilities(ctx, syncOptionsWithOffset(opts, cursor.Vulnerabilities), snapshot)
	if err != nil {
		return nil, err
	}

	malicious, err := s.exportSyncMalicious(ctx, syncOptionsWithOffset(opts, cursor.Malicious), snapshot)
	if err != nil {
		return nil, err
	}

	reputation, err := s.exportSyncReputation(ctx, syncOptionsWithOffset(opts, cursor.Reputation), snapshot)
	if err != nil {
		return nil, err
	}

	lifecycle, err := s.exportSyncLifecycle(ctx, syncOptionsWithOffset(opts, cursor.Lifecycle), snapshot)
	if err != nil {
		return nil, err
	}

	// When pagination is active, signal that more data may follow if
	// any result set filled the limit exactly.
	truncated := opts.Limit > 0 &&
		(len(vulns) == opts.Limit || len(malicious) == opts.Limit || len(reputation) == opts.Limit || len(lifecycle) == opts.Limit)
	var nextCursor *db.SyncCursor
	if truncated {
		nextCursor = &db.SyncCursor{
			Vulnerabilities: cursor.Vulnerabilities + len(vulns),
			Malicious:       cursor.Malicious + len(malicious),
			Reputation:      cursor.Reputation + len(reputation),
			Lifecycle:       cursor.Lifecycle + len(lifecycle),
		}
	}

	return &db.SyncExport{
		SyncedAt:        snapshot,
		Vulnerabilities: vulns,
		Malicious:       malicious,
		Reputation:      reputation,
		Lifecycle:       lifecycle,
		Truncated:       truncated,
		NextCursor:      nextCursor,
	}, nil
}

func syncOptionsWithOffset(opts db.SyncExportOptions, offset int) db.SyncExportOptions {
	opts.Offset = offset
	opts.Cursor = db.SyncCursor{}
	return opts
}

func (s *Store) exportSyncVulnerabilities(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time) ([]db.SyncVulnerability, error) {
	query := `
		SELECT
			v.id,
			ap.ecosystem,
			ap.name,
			ap.version_ranges::text,
			ap.versions_affected::text,
			COALESCE(vr.refs_json, '[]') AS refs_json,
			v.severity,
			v.cvss_score,
			v.epss_score,
			v.cisa_kev,
			v.summary,
			(v.withdrawn IS NOT NULL) AS withdrawn
		FROM vulnerabilities v
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
		LEFT JOIN LATERAL (
			SELECT COALESCE(
				json_agg(
					json_build_object(
						'type', COALESCE(type, ''),
						'url', url
					)
					ORDER BY id
				)::text,
				'[]'
			) AS refs_json
			FROM vulnerability_references
			WHERE vulnerability_id = v.id
		) vr ON true
		WHERE v.updated_at <= $1`

	args := []any{snapshot}
	if opts.Since != nil {
		since := opts.Since.UTC()
		query += fmt.Sprintf(` AND v.updated_at >= $%d`, len(args)+1)
		args = append(args, since)
	}
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ap.ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	query += ` ORDER BY ap.ecosystem ASC, ap.name ASC, v.id ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, opts.Limit)
		if opts.Offset > 0 {
			query += fmt.Sprintf(` OFFSET $%d`, len(args)+1)
			args = append(args, opts.Offset)
		}
	}

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
			&item.VersionsAffected,
			&item.References,
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

func (s *Store) exportSyncReputation(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time) ([]db.SyncReputationFinding, error) {
	query := `
		SELECT
			ecosystem, name, version, source, status, severity, summary, description,
			reference_urls::text, evidence::text, last_checked_at, next_check_at, last_error, updated_at
		FROM package_reputation_cache
		WHERE source = $2
		  AND status IN ('malicious', 'removed', 'risk', 'clean', 'not_found', 'unsupported', 'error')
		  AND updated_at <= $1`

	args := []any{snapshot, db.ReputationSourceReversingLabs}
	if opts.Since != nil {
		since := opts.Since.UTC()
		query += fmt.Sprintf(` AND updated_at >= $%d`, len(args)+1)
		args = append(args, since)
	}
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	query += ` ORDER BY ecosystem ASC, name ASC, version ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, opts.Limit)
		if opts.Offset > 0 {
			query += fmt.Sprintf(` OFFSET $%d`, len(args)+1)
			args = append(args, opts.Offset)
		}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: export sync reputation findings: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.SyncReputationFinding, 0)
	for rows.Next() {
		rep, err := scanPackageReputation(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan sync reputation row: %w", err)
		}
		out = append(out, reputationSyncFinding(rep))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate sync reputation rows: %w", err)
	}

	return out, nil
}

func reputationSyncFinding(rep db.PackageReputation) db.SyncReputationFinding {
	item := db.SyncReputationFinding{
		ID:        reputationFindingID(rep.Ecosystem, rep.Name, rep.Version),
		Ecosystem: rep.Ecosystem,
		Name:      rep.Name,
		Version:   rep.Version,
		Summary:   rep.Summary,
	}

	switch rep.Status {
	case "malicious":
		item.Type = string(domain.FindingTypeMalicious)
		item.RiskType = "malware"
		item.Severity = normalizeReputationSeverity(rep.Severity)
	case "removed":
		item.Type = string(domain.FindingTypeSupplyChainRisk)
		item.RiskType = "removed_package"
		item.Severity = normalizeReputationSeverity(rep.Severity)
	case "risk":
		item.Type = string(domain.FindingTypeSupplyChainRisk)
		item.RiskType = "malware_history"
		item.Severity = normalizeReputationSeverity(rep.Severity)
	default:
		item.Withdrawn = true
	}
	return item
}

func (s *Store) exportSyncMalicious(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time) ([]db.SyncMalicious, error) {
	query := `
		SELECT
			id,
			ecosystem,
			name,
			COALESCE(versions::text, ''),
			COALESCE(reference_urls::text, '[]'),
			risk_type,
			severity,
			summary,
			(removed_at IS NOT NULL) AS withdrawn
		FROM malicious_findings
		WHERE updated_at <= $1`

	args := []any{snapshot}
	if opts.Since != nil {
		since := opts.Since.UTC()
		query += fmt.Sprintf(` AND updated_at >= $%d`, len(args)+1)
		args = append(args, since)
	} else {
		query += ` AND removed_at IS NULL`
	}
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	query += ` ORDER BY ecosystem ASC, name ASC, id ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, opts.Limit)
		if opts.Offset > 0 {
			query += fmt.Sprintf(` OFFSET $%d`, len(args)+1)
			args = append(args, opts.Offset)
		}
	}

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
			&item.ReferenceURLs,
			&item.RiskType,
			&item.Severity,
			&item.Summary,
			&item.Withdrawn,
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

func (s *Store) exportSyncLifecycle(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time) ([]db.SyncLifecycleRelease, error) {
	query := `
		SELECT
			'endoflife:' || m.ecosystem || ':' || m.name || ':' || p.product_slug || ':' || r.cycle AS id,
			m.ecosystem,
			m.name,
			p.product_slug,
			p.name AS product_label,
			r.cycle,
			r.latest,
			r.release_date,
			r.is_lts,
			r.lts_from,
			r.is_eoas,
			r.eoas_from,
			r.is_eol,
			r.eol_from,
			r.is_discontinued,
			r.discontinued_from,
			r.is_eoes,
			r.eoes_from,
			r.is_maintained
		FROM lifecycle_package_map m
		INNER JOIN lifecycle_products p ON p.product_slug = m.product_slug
		INNER JOIN lifecycle_releases r ON r.product_slug = p.product_slug
		WHERE GREATEST(m.updated_at, p.updated_at, r.updated_at) <= $1`

	args := []any{snapshot}
	if opts.Since != nil {
		since := opts.Since.UTC()
		query += fmt.Sprintf(` AND GREATEST(m.updated_at, p.updated_at, r.updated_at) >= $%d`, len(args)+1)
		args = append(args, since)
	}
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND m.ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	query += ` ORDER BY m.ecosystem ASC, m.name ASC, p.product_slug ASC, r.cycle ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, opts.Limit)
		if opts.Offset > 0 {
			query += fmt.Sprintf(` OFFSET $%d`, len(args)+1)
			args = append(args, opts.Offset)
		}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: export sync lifecycle releases: %w", err)
	}
	defer closeSilently(rows)

	out := make([]db.SyncLifecycleRelease, 0)
	for rows.Next() {
		var item db.SyncLifecycleRelease
		if err := rows.Scan(
			&item.ID,
			&item.Ecosystem,
			&item.Name,
			&item.ProductSlug,
			&item.ProductLabel,
			&item.Cycle,
			&item.Latest,
			&item.ReleaseDate,
			&item.IsLTS,
			&item.LTSFrom,
			&item.IsEOAS,
			&item.EOASFrom,
			&item.IsEOL,
			&item.EOLFrom,
			&item.IsDiscontinued,
			&item.DiscontinuedFrom,
			&item.IsEOES,
			&item.EOESFrom,
			&item.IsMaintained,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan sync lifecycle row: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate sync lifecycle rows: %w", err)
	}

	return out, nil
}
