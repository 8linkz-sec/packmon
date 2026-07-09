package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/ioutils"
)

// ExportSync returns the flattened vulnerability, malicious, reputation, and
// lifecycle data consumed by the local SQLite sync endpoint.
func (s *Store) ExportSync(ctx context.Context, opts db.SyncExportOptions) (*db.SyncExport, error) {
	snapshot, snapshotXID, err := s.resolveSyncSnapshot(ctx, opts)
	if err != nil {
		return nil, err
	}
	cursor := opts.EffectiveCursor()

	datasets, err := exportSyncDatasets(ctx, opts, cursor, snapshot, snapshotXID, syncDatasetExporters{
		vulnerabilities: s.exportSyncVulnerabilities,
		malicious:       s.exportSyncMalicious,
		reputation:      s.exportSyncReputation,
		lifecycle:       s.exportSyncLifecycle,
	})
	if err != nil {
		return nil, err
	}
	vulns := datasets.vulnerabilities
	malicious := datasets.malicious
	reputation := datasets.reputation
	lifecycle := datasets.lifecycle

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

type syncDatasetExporters struct {
	vulnerabilities func(context.Context, db.SyncExportOptions, time.Time, uint64) ([]db.SyncVulnerability, error)
	malicious       func(context.Context, db.SyncExportOptions, time.Time, uint64) ([]db.SyncMalicious, error)
	reputation      func(context.Context, db.SyncExportOptions, time.Time, uint64) ([]db.SyncReputationFinding, error)
	lifecycle       func(context.Context, db.SyncExportOptions, time.Time, uint64) ([]db.SyncLifecycleRelease, error)
}

type syncDatasets struct {
	vulnerabilities []db.SyncVulnerability
	malicious       []db.SyncMalicious
	reputation      []db.SyncReputationFinding
	lifecycle       []db.SyncLifecycleRelease
}

type syncDatasetExportError struct {
	order int
	err   error
}

func exportSyncDatasets(ctx context.Context, opts db.SyncExportOptions, cursor db.SyncCursor, snapshot time.Time, snapshotXID uint64, exporters syncDatasetExporters) (syncDatasets, error) {
	var (
		wg       sync.WaitGroup
		errCh    = make(chan syncDatasetExportError, 4)
		datasets syncDatasets
	)

	if !cursor.VulnerabilitiesDone {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			datasets.vulnerabilities, err = exporters.vulnerabilities(ctx, syncOptionsWithOffset(opts, cursor.Vulnerabilities), snapshot, snapshotXID)
			if err != nil {
				errCh <- syncDatasetExportError{order: 0, err: err}
			}
		}()
	}
	if !cursor.MaliciousDone {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			datasets.malicious, err = exporters.malicious(ctx, syncOptionsWithOffset(opts, cursor.Malicious), snapshot, snapshotXID)
			if err != nil {
				errCh <- syncDatasetExportError{order: 1, err: err}
			}
		}()
	}
	if !cursor.ReputationDone {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			datasets.reputation, err = exporters.reputation(ctx, syncOptionsWithOffset(opts, cursor.Reputation), snapshot, snapshotXID)
			if err != nil {
				errCh <- syncDatasetExportError{order: 2, err: err}
			}
		}()
	}
	if !cursor.LifecycleDone {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			datasets.lifecycle, err = exporters.lifecycle(ctx, syncOptionsWithOffset(opts, cursor.Lifecycle), snapshot, snapshotXID)
			if err != nil {
				errCh <- syncDatasetExportError{order: 3, err: err}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	firstErrOrder := 4
	var firstErr error
	for datasetErr := range errCh {
		if datasetErr.order < firstErrOrder {
			firstErrOrder = datasetErr.order
			firstErr = datasetErr.err
		}
	}
	if firstErr != nil {
		return syncDatasets{}, firstErr
	}
	return datasets, nil
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

type syncVulnerabilityQueryArgs struct {
	args           []any
	sinceArg       int
	sinceXIDArg    int
	snapshotXIDArg int
}

func newSyncVulnerabilityQueryArgs(opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) syncVulnerabilityQueryArgs {
	queryArgs := syncVulnerabilityQueryArgs{
		args: []any{snapshot},
	}
	if opts.Since != nil {
		queryArgs.sinceArg = queryArgs.appendArg(opts.Since.UTC())
		if opts.SinceXID > 0 {
			queryArgs.sinceXIDArg = queryArgs.appendArg(strconv.FormatUint(opts.SinceXID, 10))
		}
	}
	if snapshotXID > 0 {
		queryArgs.snapshotXIDArg = queryArgs.appendArg(strconv.FormatUint(snapshotXID, 10))
	}
	return queryArgs
}

func (q *syncVulnerabilityQueryArgs) appendArg(value any) int {
	q.args = append(q.args, value)
	return len(q.args)
}

func (q syncVulnerabilityQueryArgs) changedIDsCTE() string {
	if q.sinceArg == 0 {
		return ""
	}

	vulnerabilityUpperFilter := q.vulnerabilityChangedIDUpperFilter("v")
	affectedUpperFilter := q.vulnerabilityChangedIDUpperFilter("ap")
	query := fmt.Sprintf(`
	WITH changed_vulnerability_ids AS (
		SELECT v.id
		FROM vulnerabilities v
		WHERE v.updated_at >= $%[1]d
		  AND v.updated_at <= $1%[2]s
		UNION
		SELECT ap.vulnerability_id AS id
		FROM affected_packages ap
		WHERE ap.updated_at >= $%[1]d
		  AND ap.updated_at <= $1%[3]s`, q.sinceArg, vulnerabilityUpperFilter, affectedUpperFilter)
	if q.sinceXIDArg > 0 {
		query += fmt.Sprintf(`
		UNION
		SELECT v.id
		FROM vulnerabilities v
		WHERE (v.xmin::text)::bigint >= $%[1]d::bigint
		  AND v.updated_at <= $1%[2]s
		UNION
		SELECT ap.vulnerability_id AS id
		FROM affected_packages ap
		WHERE (ap.xmin::text)::bigint >= $%[1]d::bigint
		  AND ap.updated_at <= $1%[3]s`, q.sinceXIDArg, vulnerabilityUpperFilter, affectedUpperFilter)
	}
	query += `
	)`
	return query
}

func (q syncVulnerabilityQueryArgs) vulnerabilityChangedIDUpperFilter(alias string) string {
	if q.snapshotXIDArg == 0 {
		return ""
	}
	return fmt.Sprintf(`
		  AND (%s.xmin::text)::bigint < $%d::bigint`, alias, q.snapshotXIDArg)
}

func (q syncVulnerabilityQueryArgs) addSnapshotXIDFilters(query *string) {
	if q.snapshotXIDArg == 0 {
		return
	}
	*query += fmt.Sprintf(` AND (v.xmin::text)::bigint < $%[1]d::bigint AND (ap.xmin::text)::bigint < $%[1]d::bigint`, q.snapshotXIDArg)
}

func exportSyncVulnerabilitiesBaseSQL(delta bool) string {
	fromSQL := `FROM vulnerabilities v`
	if delta {
		fromSQL = `FROM vulnerabilities v
	INNER JOIN changed_vulnerability_ids changed ON changed.id = v.id`
	}
	return `
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
	` + fromSQL + `
	INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
	` + vulnerabilityReferencesLateralSQL("v.id") + `
	LEFT JOIN LATERAL (
		SELECT source FROM vulnerability_sources
		WHERE vulnerability_id = v.id ORDER BY id LIMIT 1
	) vs ON true
	WHERE v.updated_at <= $1
	  AND ap.updated_at <= $1`
}

func buildExportSyncVulnerabilitiesQuery(opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (string, []any, error) {
	queryArgs := newSyncVulnerabilityQueryArgs(opts, snapshot, snapshotXID)
	query := queryArgs.changedIDsCTE() + exportSyncVulnerabilitiesBaseSQL(opts.Since != nil)
	queryArgs.addSnapshotXIDFilters(&query)
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ap.ecosystem = ANY($%d)`, len(queryArgs.args)+1)
		queryArgs.args = append(queryArgs.args, opts.Ecosystems)
	}
	if opts.Cursor.VulnerabilitiesCursor != "" {
		cursor, err := decodeSyncCursorKey(opts.Cursor.VulnerabilitiesCursor, 3)
		if err != nil {
			return "", nil, fmt.Errorf("postgres: invalid vulnerability sync cursor: %w", err)
		}
		query += fmt.Sprintf(` AND (ap.ecosystem, ap.name, v.id) > ($%d, $%d, $%d)`, len(queryArgs.args)+1, len(queryArgs.args)+2, len(queryArgs.args)+3)
		queryArgs.args = append(queryArgs.args, cursor[0], cursor[1], cursor[2])
	}
	query += ` ORDER BY ap.ecosystem ASC, ap.name ASC, v.id ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(queryArgs.args)+1)
		queryArgs.args = append(queryArgs.args, opts.Limit)
		if opts.Offset > 0 && opts.Cursor.VulnerabilitiesCursor == "" {
			query += fmt.Sprintf(` OFFSET $%d`, len(queryArgs.args)+1)
			queryArgs.args = append(queryArgs.args, opts.Offset)
		}
	}
	return query, queryArgs.args, nil
}

func (s *Store) exportSyncVulnerabilities(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncVulnerability, error) {
	query, args, err := buildExportSyncVulnerabilitiesQuery(opts, snapshot, snapshotXID)
	if err != nil {
		return nil, err
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: export sync vulnerabilities: %w", err)
	}
	defer ioutils.CloseSilently(rows)

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
	defer ioutils.CloseSilently(rows)

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

	mapping, ok := reversingLabsReputationStatusMapping(rep.Status, rep.Severity)
	if !ok {
		item.Withdrawn = true
		return item
	}
	item.Type = string(mapping.findingType)
	item.RiskType = mapping.riskType
	item.Severity = string(mapping.severity)
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
	defer ioutils.CloseSilently(rows)

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

type syncLifecycleQueryArgs struct {
	args             []any
	activeFilters    []string
	tombstoneFilters []string
}

func newSyncLifecycleQueryArgs(opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) syncLifecycleQueryArgs {
	queryArgs := syncLifecycleQueryArgs{
		args: []any{snapshot},
		activeFilters: []string{
			"m.updated_at <= $1",
			"p.updated_at <= $1",
			"r.updated_at <= $1",
		},
		tombstoneFilters: []string{
			"t.updated_at <= $1",
		},
	}
	queryArgs.addSnapshotXID(snapshotXID)
	queryArgs.addDeltaWindow(opts)
	return queryArgs
}

func (q *syncLifecycleQueryArgs) appendArg(value any) int {
	q.args = append(q.args, value)
	return len(q.args)
}

func (q *syncLifecycleQueryArgs) addSnapshotXID(snapshotXID uint64) {
	if snapshotXID == 0 {
		return
	}

	xidArg := q.appendArg(strconv.FormatUint(snapshotXID, 10))
	q.activeFilters = append(q.activeFilters,
		fmt.Sprintf("(m.xmin::text)::bigint < $%d::bigint", xidArg),
		fmt.Sprintf("(p.xmin::text)::bigint < $%d::bigint", xidArg),
		fmt.Sprintf("(r.xmin::text)::bigint < $%d::bigint", xidArg),
	)
	q.tombstoneFilters = append(q.tombstoneFilters,
		fmt.Sprintf("(t.xmin::text)::bigint < $%d::bigint", xidArg),
	)
}

func (q *syncLifecycleQueryArgs) addDeltaWindow(opts db.SyncExportOptions) {
	if opts.Since == nil {
		return
	}

	sinceArg := q.appendArg(opts.Since.UTC())
	if opts.SinceXID > 0 {
		sinceXIDArg := q.appendArg(strconv.FormatUint(opts.SinceXID, 10))
		q.activeFilters = append(q.activeFilters, fmt.Sprintf(`(
				m.updated_at >= $%[1]d OR
				p.updated_at >= $%[1]d OR
				r.updated_at >= $%[1]d OR
				(m.xmin::text)::bigint >= $%[2]d::bigint OR
				(p.xmin::text)::bigint >= $%[2]d::bigint OR
				(r.xmin::text)::bigint >= $%[2]d::bigint
			)`, sinceArg, sinceXIDArg))
		q.tombstoneFilters = append(q.tombstoneFilters, fmt.Sprintf(`(
				t.updated_at >= $%[1]d OR
				(t.xmin::text)::bigint >= $%[2]d::bigint
			)`, sinceArg, sinceXIDArg))
		return
	}

	q.activeFilters = append(q.activeFilters, fmt.Sprintf(`(
				m.updated_at >= $%[1]d OR
				p.updated_at >= $%[1]d OR
				r.updated_at >= $%[1]d
			)`, sinceArg))
	q.tombstoneFilters = append(q.tombstoneFilters, fmt.Sprintf("t.updated_at >= $%d", sinceArg))
}

func buildExportSyncLifecycleQuery(opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (string, []any, error) {
	queryArgs := newSyncLifecycleQueryArgs(opts, snapshot, snapshotXID)
	query := buildSyncLifecycleRowsQuery(queryArgs.activeFilters, queryArgs.tombstoneFilters, opts.Since != nil)

	if err := addSyncLifecycleResultFilters(&query, &queryArgs.args, opts); err != nil {
		return "", nil, err
	}
	addSyncLifecyclePagination(&query, &queryArgs.args, opts)
	return query, queryArgs.args, nil
}

func buildSyncLifecycleRowsQuery(activeFilters, tombstoneFilters []string, includeTombstones bool) string {
	query := `
		WITH lifecycle_rows AS (` + syncLifecycleActiveRowsSQL(activeFilters)
	if includeTombstones {
		query += `
		UNION ALL` + syncLifecycleTombstoneRowsSQL(tombstoneFilters)
	}
	query += `
		)
` + syncLifecycleOuterSelectSQL()
	return query
}

func syncLifecycleActiveRowsSQL(filters []string) string {
	return `
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
		WHERE ` + strings.Join(filters, " AND ")
}

func syncLifecycleTombstoneRowsSQL(filters []string) string {
	return `
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
		WHERE ` + strings.Join(filters, " AND ")
}

func syncLifecycleOuterSelectSQL() string {
	return `		SELECT
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
}

func addSyncLifecycleResultFilters(query *string, args *[]any, opts db.SyncExportOptions) error {
	if len(opts.Ecosystems) > 0 {
		*query += fmt.Sprintf(` AND ecosystem = ANY($%d)`, len(*args)+1)
		*args = append(*args, opts.Ecosystems)
	}
	return addSyncLifecycleCursorFilter(query, args, opts.Cursor.LifecycleCursor)
}

func addSyncLifecycleCursorFilter(query *string, args *[]any, rawCursor string) error {
	if rawCursor == "" {
		return nil
	}

	cursor, err := decodeSyncCursorKey(rawCursor, 4)
	if err != nil {
		return fmt.Errorf("postgres: invalid lifecycle sync cursor: %w", err)
	}
	*query += fmt.Sprintf(` AND (ecosystem, name, product_slug, cycle) > ($%d, $%d, $%d, $%d)`, len(*args)+1, len(*args)+2, len(*args)+3, len(*args)+4)
	*args = append(*args, cursor[0], cursor[1], cursor[2], cursor[3])
	return nil
}

func addSyncLifecyclePagination(query *string, args *[]any, opts db.SyncExportOptions) {
	*query += ` ORDER BY ecosystem ASC, name ASC, product_slug ASC, cycle ASC`
	if opts.Limit <= 0 {
		return
	}
	*query += fmt.Sprintf(` LIMIT $%d`, len(*args)+1)
	*args = append(*args, opts.Limit)
	if opts.Offset > 0 && opts.Cursor.LifecycleCursor == "" {
		*query += fmt.Sprintf(` OFFSET $%d`, len(*args)+1)
		*args = append(*args, opts.Offset)
	}
}

func (s *Store) exportSyncLifecycle(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) ([]db.SyncLifecycleRelease, error) {
	query, args, err := buildExportSyncLifecycleQuery(opts, snapshot, snapshotXID)
	if err != nil {
		return nil, err
	}
	return s.querySyncLifecycleRows(ctx, query, args)
}

func (s *Store) querySyncLifecycleRows(ctx context.Context, query string, args []any) ([]db.SyncLifecycleRelease, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: export sync lifecycle releases: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	out := make([]db.SyncLifecycleRelease, 0)
	for rows.Next() {
		item, err := scanSyncLifecycleRelease(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan sync lifecycle row: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate sync lifecycle rows: %w", err)
	}

	return out, nil
}

type syncLifecycleRowScanner interface {
	Scan(dest ...any) error
}

func scanSyncLifecycleRelease(row syncLifecycleRowScanner) (db.SyncLifecycleRelease, error) {
	var item db.SyncLifecycleRelease
	if err := row.Scan(
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
		return db.SyncLifecycleRelease{}, err
	}
	return item, nil
}
