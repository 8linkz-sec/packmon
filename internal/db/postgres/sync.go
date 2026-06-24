package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// ExportSync returns the flattened vulnerability and malicious data consumed by
// the local SQLite sync endpoint.
func (s *Store) ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	snapshot, snapshotXID, err := s.resolveSyncSnapshot(ctx, opts)
	if err != nil {
		return nil, err
	}
	cursor := opts.EffectiveCursor()

	var vulns []db.SyncVulnerability
	if !cursor.VulnerabilitiesDone {
		vulns, err = s.exportSyncVulnerabilities(ctx, syncOptionsWithOffset(opts, cursor.Vulnerabilities), snapshot, snapshotXID)
		if err != nil {
			return nil, err
		}
	}

	var malicious []db.SyncMalicious
	if !cursor.MaliciousDone {
		malicious, err = s.exportSyncMalicious(ctx, syncOptionsWithOffset(opts, cursor.Malicious), snapshot, snapshotXID)
		if err != nil {
			return nil, err
		}
	}

	var reputation []db.SyncReputationFinding
	if !cursor.ReputationDone {
		reputation, err = s.exportSyncReputation(ctx, syncOptionsWithOffset(opts, cursor.Reputation), snapshot, snapshotXID)
		if err != nil {
			return nil, err
		}
	}

	var lifecycle []db.SyncLifecycleRelease
	if !cursor.LifecycleDone {
		lifecycle, err = s.exportSyncLifecycle(ctx, syncOptionsWithOffset(opts, cursor.Lifecycle), snapshot, snapshotXID)
		if err != nil {
			return nil, err
		}
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
		setNextDatasetCursor(nextCursor, cursor.VulnerabilitiesDone, len(vulns), opts.Limit, func() {
			nextCursor.VulnerabilitiesDone = true
		}, func() {
			last := vulns[len(vulns)-1]
			nextCursor.VulnerabilitiesCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.ID)
		})
		setNextDatasetCursor(nextCursor, cursor.MaliciousDone, len(malicious), opts.Limit, func() {
			nextCursor.MaliciousDone = true
		}, func() {
			last := malicious[len(malicious)-1]
			nextCursor.MaliciousCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.ID)
		})
		setNextDatasetCursor(nextCursor, cursor.ReputationDone, len(reputation), opts.Limit, func() {
			nextCursor.ReputationDone = true
		}, func() {
			last := reputation[len(reputation)-1]
			nextCursor.ReputationCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.Version)
		})
		setNextDatasetCursor(nextCursor, cursor.LifecycleDone, len(lifecycle), opts.Limit, func() {
			nextCursor.LifecycleDone = true
		}, func() {
			last := lifecycle[len(lifecycle)-1]
			nextCursor.LifecycleCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.ProductSlug, last.Cycle)
		})
	}

	return &db.SyncExport{
		SyncedAt:        snapshot,
		SyncedXID:       snapshotXID,
		Vulnerabilities: vulns,
		Malicious:       malicious,
		Reputation:      reputation,
		Lifecycle:       lifecycle,
		Truncated:       truncated,
		NextCursor:      nextCursor,
	}, nil
}

func (s *Store) resolveSyncSnapshot(ctx context.Context, opts db.SyncExportOptions) (time.Time, uint64, error) {
	snapshot := opts.SnapshotAt.UTC()
	snapshotXID := opts.SnapshotXID
	if !snapshot.IsZero() {
		if snapshotXID == 0 {
			var rawXID string
			if err := s.pool.QueryRow(ctx, `SELECT txid_snapshot_xmin(txid_current_snapshot())::text`).Scan(&rawXID); err != nil {
				return time.Time{}, 0, fmt.Errorf("postgres: read sync snapshot xid: %w", err)
			}
			var err error
			snapshotXID, err = parsePostgresSyncXID(rawXID)
			if err != nil {
				return time.Time{}, 0, fmt.Errorf("postgres: parse sync snapshot xid: %w", err)
			}
		}
		return snapshot, snapshotXID, nil
	}

	var rawXID string
	if err := s.pool.QueryRow(ctx, `
		SELECT clock_timestamp(), txid_snapshot_xmin(txid_current_snapshot())::text`).Scan(&snapshot, &rawXID); err != nil {
		return time.Time{}, 0, fmt.Errorf("postgres: read sync snapshot: %w", err)
	}
	snapshotXID, err := parsePostgresSyncXID(rawXID)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("postgres: parse sync snapshot xid: %w", err)
	}
	return snapshot.UTC(), snapshotXID, nil
}

func parsePostgresSyncXID(raw string) (uint64, error) {
	xid, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	return xid, nil
}

func syncOptionsWithOffset(opts db.SyncExportOptions, offset int) db.SyncExportOptions {
	opts.Offset = offset
	return opts
}

func setNextDatasetCursor(next *db.SyncCursor, alreadyDone bool, rowCount, limit int, markDone, setCursor func()) {
	if alreadyDone {
		markDone()
		return
	}
	if rowCount == limit {
		setCursor()
		return
	}
	markDone()
}

func encodeSyncCursorKey(values ...string) string {
	payload, _ := json.Marshal(values)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeSyncCursorKey(raw string, wantParts int) ([]string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode sync cursor: %w", err)
	}
	var values []string
	if err := json.Unmarshal(payload, &values); err != nil {
		return nil, fmt.Errorf("parse sync cursor: %w", err)
	}
	if len(values) != wantParts {
		return nil, fmt.Errorf("sync cursor has %d parts, want %d", len(values), wantParts)
	}
	return values, nil
}

func addSyncWindowFilters(query *string, args *[]any, opts db.SyncExportOptions, snapshotXID uint64, updatedExpr, xidExpr string) {
	if snapshotXID > 0 {
		*query += fmt.Sprintf(` AND %s < $%d::bigint`, xidExpr, len(*args)+1)
		*args = append(*args, strconv.FormatUint(snapshotXID, 10))
	}
	if opts.Since == nil {
		return
	}

	since := opts.Since.UTC()
	if opts.SinceXID > 0 {
		*query += fmt.Sprintf(` AND (%s >= $%d OR %s >= $%d::bigint)`, updatedExpr, len(*args)+1, xidExpr, len(*args)+2)
		*args = append(*args, since, strconv.FormatUint(opts.SinceXID, 10))
		return
	}
	*query += fmt.Sprintf(` AND %s >= $%d`, updatedExpr, len(*args)+1)
	*args = append(*args, since)
}

func (s *Store) exportSyncVulnerabilities(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncVulnerability, error) {
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
			v.epss_percentile,
			v.cisa_kev,
			v.summary,
			COALESCE(NULLIF(TRIM(vs.source), ''), 'unknown') AS source,
			(v.withdrawn IS NOT NULL) AS withdrawn
		FROM vulnerabilities v
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
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
				SELECT 0 AS sort_order, id, type AS ref_type, url
				FROM vulnerability_references
				WHERE vulnerability_id = v.id
				UNION ALL
				SELECT 1 AS sort_order, id, 'VULNCHECK' AS ref_type,
					COALESCE(NULLIF(TRIM(url), ''), 'https://vulncheck.com/') AS url
				FROM vulnerability_sources
				WHERE vulnerability_id = v.id AND source = 'vulncheck'
			) refs
		) vr ON true
		LEFT JOIN LATERAL (
			SELECT source FROM vulnerability_sources
			WHERE vulnerability_id = v.id ORDER BY id LIMIT 1
		) vs ON true
		WHERE GREATEST(v.updated_at, ap.updated_at) <= $1`

	args := []any{snapshot}
	addSyncWindowFilters(&query, &args, opts, snapshotXID,
		`GREATEST(v.updated_at, ap.updated_at)`,
		`GREATEST((v.xmin::text)::bigint, (ap.xmin::text)::bigint)`,
	)
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ap.ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	if opts.Cursor.VulnerabilitiesCursor != "" {
		cursor, err := decodeSyncCursorKey(opts.Cursor.VulnerabilitiesCursor, 3)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid vulnerability sync cursor: %w", err)
		}
		query += fmt.Sprintf(` AND (ap.ecosystem, ap.name, v.id) > ($%d, $%d, $%d)`, len(args)+1, len(args)+2, len(args)+3)
		args = append(args, cursor[0], cursor[1], cursor[2])
	}
	query += ` ORDER BY ap.ecosystem ASC, ap.name ASC, v.id ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, opts.Limit)
		if opts.Offset > 0 && opts.Cursor.VulnerabilitiesCursor == "" {
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
			&item.EPSSPercentile,
			&item.CISAKEV,
			&item.Summary,
			&item.Source,
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

func (s *Store) exportSyncReputation(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncReputationFinding, error) {
	query := `
		SELECT
			ecosystem, name, version, source, status, severity, summary, description,
			reference_urls::text, evidence::text, last_checked_at, next_check_at, last_error, updated_at
		FROM package_reputation_cache prc
		WHERE source = $2
		  AND status IN ('malicious', 'removed', 'risk')
		  AND updated_at <= $1`

	args := []any{snapshot, db.ReputationSourceReversingLabs}
	addSyncWindowFilters(&query, &args, opts, snapshotXID,
		`updated_at`,
		`(prc.xmin::text)::bigint`,
	)
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	if opts.Cursor.ReputationCursor != "" {
		cursor, err := decodeSyncCursorKey(opts.Cursor.ReputationCursor, 3)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid reputation sync cursor: %w", err)
		}
		query += fmt.Sprintf(` AND (ecosystem, name, version) > ($%d, $%d, $%d)`, len(args)+1, len(args)+2, len(args)+3)
		args = append(args, cursor[0], cursor[1], cursor[2])
	}
	query += ` ORDER BY ecosystem ASC, name ASC, version ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, opts.Limit)
		if opts.Offset > 0 && opts.Cursor.ReputationCursor == "" {
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
	if !item.Withdrawn {
		item.Severity = string(domain.NormalizeFindingSeverity(domain.Finding{
			Type:     domain.FindingType(item.Type),
			RiskType: item.RiskType,
			Severity: domain.Severity(item.Severity),
		}))
	}
	return item
}

func (s *Store) exportSyncMalicious(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncMalicious, error) {
	query := `
		SELECT
			id,
			ecosystem,
			name,
			COALESCE(version_ranges::text, ''),
			COALESCE(versions::text, ''),
			COALESCE(reference_urls::text, '[]'),
			risk_type,
			severity,
			summary,
			COALESCE(NULLIF(TRIM(source), ''), 'unknown') AS source,
			(removed_at IS NOT NULL) AS withdrawn
		FROM malicious_findings mf
		WHERE updated_at <= $1`

	args := []any{snapshot}
	addSyncWindowFilters(&query, &args, opts, snapshotXID,
		`updated_at`,
		`(mf.xmin::text)::bigint`,
	)
	if opts.Since == nil {
		query += ` AND removed_at IS NULL`
	}
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	if opts.Cursor.MaliciousCursor != "" {
		cursor, err := decodeSyncCursorKey(opts.Cursor.MaliciousCursor, 3)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid malicious sync cursor: %w", err)
		}
		query += fmt.Sprintf(` AND (ecosystem, name, id) > ($%d, $%d, $%d)`, len(args)+1, len(args)+2, len(args)+3)
		args = append(args, cursor[0], cursor[1], cursor[2])
	}
	query += ` ORDER BY ecosystem ASC, name ASC, id ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, opts.Limit)
		if opts.Offset > 0 && opts.Cursor.MaliciousCursor == "" {
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
			&item.VersionRanges,
			&item.Versions,
			&item.ReferenceURLs,
			&item.RiskType,
			&item.Severity,
			&item.Summary,
			&item.Source,
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

func (s *Store) exportSyncLifecycle(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncLifecycleRelease, error) {
	args := []any{snapshot}
	activeFilters := []string{
		"m.updated_at <= $1",
		"p.updated_at <= $1",
		"r.updated_at <= $1",
	}
	tombstoneFilters := []string{
		"t.updated_at <= $1",
	}
	if snapshotXID > 0 {
		args = append(args, strconv.FormatUint(snapshotXID, 10))
		activeFilters = append(activeFilters,
			fmt.Sprintf("(m.xmin::text)::bigint < $%d::bigint", len(args)),
			fmt.Sprintf("(p.xmin::text)::bigint < $%d::bigint", len(args)),
			fmt.Sprintf("(r.xmin::text)::bigint < $%d::bigint", len(args)),
		)
		tombstoneFilters = append(tombstoneFilters,
			fmt.Sprintf("(t.xmin::text)::bigint < $%d::bigint", len(args)),
		)
	}
	if opts.Since != nil {
		since := opts.Since.UTC()
		args = append(args, since)
		sinceArg := len(args)
		if opts.SinceXID > 0 {
			args = append(args, strconv.FormatUint(opts.SinceXID, 10))
			sinceXIDArg := len(args)
			activeFilters = append(activeFilters, fmt.Sprintf(`(
				m.updated_at >= $%[1]d OR
				p.updated_at >= $%[1]d OR
				r.updated_at >= $%[1]d OR
				(m.xmin::text)::bigint >= $%[2]d::bigint OR
				(p.xmin::text)::bigint >= $%[2]d::bigint OR
				(r.xmin::text)::bigint >= $%[2]d::bigint
			)`, sinceArg, sinceXIDArg))
			tombstoneFilters = append(tombstoneFilters, fmt.Sprintf(`(
				t.updated_at >= $%[1]d OR
				(t.xmin::text)::bigint >= $%[2]d::bigint
			)`, sinceArg, sinceXIDArg))
		} else {
			activeFilters = append(activeFilters, fmt.Sprintf(`(
				m.updated_at >= $%[1]d OR
				p.updated_at >= $%[1]d OR
				r.updated_at >= $%[1]d
			)`, sinceArg))
			tombstoneFilters = append(tombstoneFilters, fmt.Sprintf("t.updated_at >= $%d", sinceArg))
		}
	}

	query := `
		WITH lifecycle_rows AS (
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
			r.is_maintained,
			false AS withdrawn
		FROM lifecycle_package_map m
		INNER JOIN lifecycle_products p ON p.product_slug = m.product_slug
		INNER JOIN lifecycle_releases r ON r.product_slug = p.product_slug
		WHERE ` + strings.Join(activeFilters, " AND ")

	if opts.Since != nil {
		query += `
		UNION ALL
		SELECT
			t.id,
			t.ecosystem,
			t.name,
			t.product_slug,
			'' AS product_label,
			t.cycle,
			'' AS latest,
			NULL::date AS release_date,
			false AS is_lts,
			NULL::date AS lts_from,
			false AS is_eoas,
			NULL::date AS eoas_from,
			false AS is_eol,
			NULL::date AS eol_from,
			false AS is_discontinued,
			NULL::date AS discontinued_from,
			NULL::boolean AS is_eoes,
			NULL::date AS eoes_from,
			false AS is_maintained,
			true AS withdrawn
		FROM lifecycle_sync_tombstones t
		WHERE ` + strings.Join(tombstoneFilters, " AND ")
	}

	query += `
		)
		SELECT
			id,
			ecosystem,
			name,
			product_slug,
			product_label,
			cycle,
			latest,
			release_date,
			is_lts,
			lts_from,
			is_eoas,
			eoas_from,
			is_eol,
			eol_from,
			is_discontinued,
			discontinued_from,
			is_eoes,
			eoes_from,
			is_maintained,
			withdrawn
		FROM lifecycle_rows
		WHERE TRUE`
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	if opts.Cursor.LifecycleCursor != "" {
		cursor, err := decodeSyncCursorKey(opts.Cursor.LifecycleCursor, 4)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid lifecycle sync cursor: %w", err)
		}
		query += fmt.Sprintf(` AND (ecosystem, name, product_slug, cycle) > ($%d, $%d, $%d, $%d)`, len(args)+1, len(args)+2, len(args)+3, len(args)+4)
		args = append(args, cursor[0], cursor[1], cursor[2], cursor[3])
	}
	query += ` ORDER BY ecosystem ASC, name ASC, product_slug ASC, cycle ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, opts.Limit)
		if opts.Offset > 0 && opts.Cursor.LifecycleCursor == "" {
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
			&item.Withdrawn,
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
