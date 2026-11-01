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
	paging := syncVulnerabilityPagingFor(syncOptionsWithOffset(opts, cursor.Vulnerabilities))
	truncated, nextCursor := nextSyncExportCursor(cursor, paging, datasets, opts.Limit)
	complete := syncPageVulnerabilityAffectedComplete(opts, cursor, datasets)
	var withoutAffected []string
	if complete {
		withoutAffected = datasets.vulnerabilitiesWithoutAffected
	}

	return &db.SyncExport{
		SyncedAt:                       snapshot,
		SyncedXID:                      snapshotXID,
		Vulnerabilities:                datasets.vulnerabilities,
		Malicious:                      datasets.malicious,
		Reputation:                     datasets.reputation,
		Lifecycle:                      datasets.lifecycle,
		Truncated:                      truncated,
		NextCursor:                     nextCursor,
		VulnerabilityAffectedComplete:  complete,
		VulnerabilitiesWithoutAffected: withoutAffected,
	}, nil
}

// syncVulnerabilityPaging selects how the vulnerability dataset is paged.
type syncVulnerabilityPaging int

const (
	// syncVulnerabilityRowKeyset pages affected-package rows in (ecosystem,
	// name, id) order with the legacy three-part row cursor or a dataset
	// offset. Full exports use it, and so does a delta that continues a legacy
	// row cursor an older server issued.
	syncVulnerabilityRowKeyset syncVulnerabilityPaging = iota
	// syncVulnerabilityDeltaRowOffset pages the rows of a delta by legacy
	// offset in advisory order (id, ecosystem, name), the order of an
	// advisory-paged first page, so an offset-only client continues where that
	// page ended. Offset pages can split an advisory.
	syncVulnerabilityDeltaRowOffset
	// syncVulnerabilityAdvisoryPages pages a delta by whole advisories in ID
	// order behind an advisory cursor (see
	// buildExportSyncVulnerabilityAdvisoryPageQuery).
	syncVulnerabilityAdvisoryPages
	// syncVulnerabilityAdvisorySplit continues, behind an advisory row cursor,
	// an advisory of a delta whose rows alone exceed
	// db.SyncVulnerabilityPageByteBudget, in (ecosystem, name) row order (see
	// buildExportSyncSplitAdvisoryQuery). Its pages never carry
	// vulnerability_affected_complete.
	syncVulnerabilityAdvisorySplit
)

// syncVulnerabilityPagingFor returns the vulnerability paging of a request,
// given the vulnerability dataset options (Offset set to the dataset offset,
// see syncOptionsWithOffset). A keyset cursor string wins over a dataset
// offset, as for every dataset.
func syncVulnerabilityPagingFor(opts db.SyncExportOptions) syncVulnerabilityPaging {
	if opts.Since == nil {
		return syncVulnerabilityRowKeyset
	}
	if raw := opts.Cursor.VulnerabilitiesCursor; raw != "" {
		if _, ok := db.DecodeSyncAdvisoryCursor(raw); ok {
			return syncVulnerabilityAdvisoryPages
		}
		if _, _, _, ok := db.DecodeSyncAdvisoryRowCursor(raw); ok {
			return syncVulnerabilityAdvisorySplit
		}
		return syncVulnerabilityRowKeyset
	}
	if opts.Offset > 0 || opts.Cursor.Vulnerabilities > 0 {
		return syncVulnerabilityDeltaRowOffset
	}
	return syncVulnerabilityAdvisoryPages
}

// syncVulnerabilityAffectedComplete reports whether this page may promise
// vulnerability_affected_complete: every vulnerability on it carries its
// complete current affected set (within the requested ecosystems). Every page
// of an advisory-paged delta qualifies: a page is one statement, never splits
// an advisory, and the delta query sends each changed vulnerability with all
// of its current affected packages. A vulnerability changed between pages is
// either delivered whole on a later page or sync, or excluded whole by the
// snapshot bound. A full export bounds affected rows by the snapshot, and the
// legacy row-cursor and offset pages of a delta can split an advisory, so
// they never carry the flag, and neither do the pages that continue a split
// advisory (syncVulnerabilityAdvisorySplit).
func syncVulnerabilityAffectedComplete(opts db.SyncExportOptions, cursor db.SyncCursor) bool {
	return !cursor.VulnerabilitiesDone && syncVulnerabilityPagingFor(syncOptionsWithOffset(opts, cursor.Vulnerabilities)) == syncVulnerabilityAdvisoryPages
}

// syncPageVulnerabilityAffectedComplete reports whether an exported page
// carries vulnerability_affected_complete: its paging allows the flag and the
// page did not start splitting an advisory that exceeds the byte budget.
func syncPageVulnerabilityAffectedComplete(opts db.SyncExportOptions, cursor db.SyncCursor, datasets syncDatasets) bool {
	return syncVulnerabilityAffectedComplete(opts, cursor) && !datasets.vulnerabilitiesSplit
}

// nextSyncExportCursor reports whether more data may follow this page and
// returns the per-dataset cursor of the next page. The other row-paged
// datasets keep the full-page heuristic: a dataset that filled the limit may
// continue. The vulnerability page reports itself whether it may continue
// (see syncVulnerabilityPageBuilder): an advisory page may hold fewer rows
// than the limit (the next advisory did not fit the rows or the byte budget)
// or more (its only advisory has more rows than the limit), and it continues
// with the cursor the page computed, or else after its last advisory.
func nextSyncExportCursor(cursor db.SyncCursor, paging syncVulnerabilityPaging, datasets syncDatasets, limit int) (bool, *db.SyncCursor) {
	vulns := datasets.vulnerabilities
	malicious := datasets.malicious
	reputation := datasets.reputation
	lifecycle := datasets.lifecycle

	if limit <= 0 {
		return false, nil
	}
	// When pagination is active, signal that more data may follow if
	// any result set may continue.
	if !datasets.vulnerabilitiesHaveMore && len(malicious) != limit && len(reputation) != limit && len(lifecycle) != limit {
		return false, nil
	}
	nextCursor := &db.SyncCursor{
		Vulnerabilities: cursor.Vulnerabilities + len(vulns),
		Malicious:       cursor.Malicious + len(malicious),
		Reputation:      cursor.Reputation + len(reputation),
		Lifecycle:       cursor.Lifecycle + len(lifecycle),
	}
	switch {
	case cursor.VulnerabilitiesDone || !datasets.vulnerabilitiesHaveMore:
		nextCursor.VulnerabilitiesDone = true
	case datasets.vulnerabilitiesNextCursor != "" && (paging == syncVulnerabilityAdvisoryPages || paging == syncVulnerabilityAdvisorySplit):
		nextCursor.VulnerabilitiesCursor = datasets.vulnerabilitiesNextCursor
	case paging == syncVulnerabilityAdvisoryPages:
		// The page may end with, or only hold, advisories without rows.
		lastID := datasets.vulnerabilitiesLastAdvisoryID
		if lastID == "" {
			lastID = vulns[len(vulns)-1].ID
		}
		nextCursor.VulnerabilitiesCursor = db.EncodeSyncAdvisoryCursor(lastID)
	case paging == syncVulnerabilityDeltaRowOffset:
		// Continue by offset only: a row cursor would switch the order.
	default:
		last := vulns[len(vulns)-1]
		nextCursor.VulnerabilitiesCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.ID)
	}
	setNextDatasetCursor(nextCursor, cursor.MaliciousDone, len(malicious), limit, func() {
		nextCursor.MaliciousDone = true
	}, func() {
		last := malicious[len(malicious)-1]
		nextCursor.MaliciousCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.ID)
	})
	setNextDatasetCursor(nextCursor, cursor.ReputationDone, len(reputation), limit, func() {
		nextCursor.ReputationDone = true
	}, func() {
		last := reputation[len(reputation)-1]
		nextCursor.ReputationCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.Version)
	})
	setNextDatasetCursor(nextCursor, cursor.LifecycleDone, len(lifecycle), limit, func() {
		nextCursor.LifecycleDone = true
	}, func() {
		last := lifecycle[len(lifecycle)-1]
		nextCursor.LifecycleCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.ProductSlug, last.Cycle)
	})
	return true, nextCursor
}

// syncVulnerabilityPage is one exported page of the vulnerability dataset.
// hasMore reports that the dataset may continue on the next page.
type syncVulnerabilityPage struct {
	rows    []db.SyncVulnerability
	hasMore bool
	// withoutAffected lists the advisories of an advisory page that have no
	// in-scope affected row, and lastAdvisoryID is the last advisory the page
	// holds, with or without rows; the advisory cursor continues after it.
	withoutAffected []string
	lastAdvisoryID  string
	// nextCursor, when set, is the vulnerabilities_cursor of the next page,
	// and split reports that the page holds part of an advisory whose rows
	// exceed the byte budget (see syncVulnerabilityPageBuilder).
	nextCursor string
	split      bool
}

func newSyncAdvisoryPage() syncVulnerabilityPage {
	return syncVulnerabilityPage{rows: make([]db.SyncVulnerability, 0)}
}

// add records one scanned row of an advisory page. A marker row (an advisory
// without in-scope affected rows, see
// buildExportSyncVulnerabilityAdvisoryPageQuery) lists the advisory instead
// of becoming a package row.
func (p *syncVulnerabilityPage) add(item db.SyncVulnerability, withoutAffected bool) {
	p.lastAdvisoryID = item.ID
	if withoutAffected {
		p.withoutAffected = append(p.withoutAffected, item.ID)
		return
	}
	p.rows = append(p.rows, item)
}

type syncDatasetExporters struct {
	vulnerabilities func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncVulnerabilityPage, error)
	malicious       func(context.Context, db.SyncExportOptions, time.Time, uint64) ([]db.SyncMalicious, error)
	reputation      func(context.Context, db.SyncExportOptions, time.Time, uint64) ([]db.SyncReputationFinding, error)
	lifecycle       func(context.Context, db.SyncExportOptions, time.Time, uint64) ([]db.SyncLifecycleRelease, error)
}

type syncDatasets struct {
	vulnerabilities         []db.SyncVulnerability
	vulnerabilitiesHaveMore bool
	// The remaining vulnerability fields carry the advisory-page fields of
	// syncVulnerabilityPage.
	vulnerabilitiesWithoutAffected []string
	vulnerabilitiesLastAdvisoryID  string
	vulnerabilitiesNextCursor      string
	vulnerabilitiesSplit           bool
	malicious                      []db.SyncMalicious
	reputation                     []db.SyncReputationFinding
	lifecycle                      []db.SyncLifecycleRelease
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
			page, err := exporters.vulnerabilities(ctx, syncOptionsWithOffset(opts, cursor.Vulnerabilities), snapshot, snapshotXID)
			datasets.vulnerabilities, datasets.vulnerabilitiesHaveMore = page.rows, page.hasMore
			datasets.vulnerabilitiesWithoutAffected = page.withoutAffected
			datasets.vulnerabilitiesLastAdvisoryID = page.lastAdvisoryID
			datasets.vulnerabilitiesNextCursor, datasets.vulnerabilitiesSplit = page.nextCursor, page.split
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

// addSnapshotXIDFilters bounds the exported rows by the snapshot watermark.
// A delta bounds only the vulnerability row: the changed-ID CTE already
// applied the snapshot to decide which vulnerabilities changed, and each of
// them is then exported with its complete current affected set (see
// exportSyncVulnerabilitiesBaseSQL).
func (q syncVulnerabilityQueryArgs) addSnapshotXIDFilters(query *string, delta bool) {
	if q.snapshotXIDArg == 0 {
		return
	}
	*query += fmt.Sprintf(` AND (v.xmin::text)::bigint < $%d::bigint`, q.snapshotXIDArg)
	if !delta {
		*query += fmt.Sprintf(` AND (ap.xmin::text)::bigint < $%d::bigint`, q.snapshotXIDArg)
	}
}

// syncVulnerabilityColumnsSQL is the exported column list of one affected
// package row, in the order scanSyncVulnerabilityDest scans it. The affected
// columns are COALESCEd because an advisory page LEFT JOINs the affected
// packages, and its marker row for an advisory without in-scope affected rows
// carries none.
const syncVulnerabilityColumnsSQL = `
		v.id,
		COALESCE(ap.ecosystem, ''),
		COALESCE(ap.name, ''),
		COALESCE(ap.version_ranges::text, '[]'),
		COALESCE(ap.versions_affected::text, '[]'),
		COALESCE(vr.refs_json, '[]') AS refs_json,
		v.severity,
		v.cvss_score,
		v.epss_score,
		v.epss_percentile,
		v.cisa_kev,
		v.summary,
		COALESCE(NULLIF(TRIM(vs.source), ''), 'unknown') AS source,
		(v.withdrawn IS NOT NULL) AS withdrawn`

// syncVulnerabilityDetailJoinsSQL joins the references and the first source
// of each exported vulnerability.
func syncVulnerabilityDetailJoinsSQL() string {
	return `
	` + vulnerabilityReferencesLateralSQL("v.id") + `
	LEFT JOIN LATERAL (
		SELECT source FROM vulnerability_sources
		WHERE vulnerability_id = v.id ORDER BY id LIMIT 1
	) vs ON true`
}

// exportSyncVulnerabilitiesBaseSQL selects one row per affected package for
// row paging (full exports and legacy delta pages). A delta joins the
// changed-ID CTE and exports every current affected package of each selected
// vulnerability, without a per-row snapshot bound. A package changed after
// the snapshot is sent now and again by the next delta, which is idempotent.
// The full export keeps the row-level bound.
func exportSyncVulnerabilitiesBaseSQL(delta bool) string {
	fromSQL := `FROM vulnerabilities v`
	affectedBound := `
	  AND ap.updated_at <= $1`
	if delta {
		fromSQL = `FROM vulnerabilities v
	INNER JOIN changed_vulnerability_ids changed ON changed.id = v.id`
		affectedBound = ""
	}
	return `
	SELECT` + syncVulnerabilityColumnsSQL + `
	` + fromSQL + `
	INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id` + syncVulnerabilityDetailJoinsSQL() + `
	WHERE v.updated_at <= $1` + affectedBound
}

// buildExportSyncVulnerabilityAdvisoryPageQuery builds one page of a delta
// paged by whole advisories, as a single statement so every advisory on the
// page is read from one snapshot. page_candidates lists the changed
// advisories after the cursor in ID order with the running count of their
// in-scope affected rows; the page takes advisories while that count stays
// within the row limit, and always the first one, so an advisory with more
// rows than the limit is a page of its own instead of being split. It then
// exports every in-scope affected row of the page's advisories and reports in
// has_more whether a candidate advisory was left for the next page. Like
// every delta, only the vulnerability row is bounded by the snapshot after the
// changed-ID CTE, so each advisory carries its complete current affected set.
//
// Both steps LEFT JOIN the in-scope affected packages, so a changed advisory
// without any (it lost every package, or every package in the requested
// ecosystems) is not dropped: it counts as one row and comes back as one
// marker row with without_affected set and no package, which the exporter
// lists in VulnerabilitiesWithoutAffected instead of exporting. The exporter
// also bounds the page by bytes (syncVulnerabilityPageBuilder) and may end it
// earlier than this query, at an advisory boundary or, for an oversized first
// advisory, inside it.
func buildExportSyncVulnerabilityAdvisoryPageQuery(opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (string, []any, error) {
	queryArgs := newSyncVulnerabilityQueryArgs(opts, snapshot, snapshotXID)
	candidateFilters := ""
	queryArgs.addSnapshotXIDFilters(&candidateFilters, true)
	affectedJoin := `
		LEFT JOIN affected_packages ap ON ap.vulnerability_id = v.id`
	if len(opts.Ecosystems) > 0 {
		affectedJoin += fmt.Sprintf(` AND ap.ecosystem = ANY($%d)`, queryArgs.appendArg(opts.Ecosystems))
	}
	if raw := opts.Cursor.VulnerabilitiesCursor; raw != "" {
		afterID, ok := db.DecodeSyncAdvisoryCursor(raw)
		if !ok {
			return "", nil, fmt.Errorf("postgres: invalid vulnerability sync cursor: not an advisory cursor")
		}
		candidateFilters += fmt.Sprintf(` AND v.id > $%d`, queryArgs.appendArg(afterID))
	}
	candidateLimit, pageFilter := "", "TRUE"
	if opts.Limit > 0 {
		limitArg := queryArgs.appendArg(opts.Limit)
		// Every advisory has at least one row (a marker row when it has no
		// in-scope affected row), so a page holds at most Limit advisories;
		// one more candidate tells whether more follow.
		candidateLimit = fmt.Sprintf(`
		LIMIT $%d::bigint + 1`, limitArg)
		pageFilter = fmt.Sprintf(`page_position = 1 OR cumulative_rows <= $%d::bigint`, limitArg)
	}

	query := queryArgs.changedIDsCTE() + `,
	page_candidates AS (
		SELECT
			v.id,
			SUM(COUNT(*)) OVER (ORDER BY v.id) AS cumulative_rows,
			ROW_NUMBER() OVER (ORDER BY v.id) AS page_position
		FROM vulnerabilities v
		INNER JOIN changed_vulnerability_ids changed ON changed.id = v.id` + affectedJoin + `
		WHERE v.updated_at <= $1` + candidateFilters + `
		GROUP BY v.id
		ORDER BY v.id` + candidateLimit + `
	),
	page_vulnerabilities AS (
		SELECT id FROM page_candidates WHERE ` + pageFilter + `
	)
	SELECT` + syncVulnerabilityColumnsSQL + `,
		(ap.vulnerability_id IS NULL) AS without_affected,
		(SELECT COUNT(*) FROM page_candidates) > (SELECT COUNT(*) FROM page_vulnerabilities) AS has_more
	FROM vulnerabilities v
	INNER JOIN page_vulnerabilities page ON page.id = v.id` + affectedJoin + syncVulnerabilityDetailJoinsSQL() + `
	ORDER BY v.id ASC, ap.ecosystem ASC, ap.name ASC`
	return query, queryArgs.args, nil
}

func buildExportSyncVulnerabilitiesQuery(opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (string, []any, error) {
	paging := syncVulnerabilityPagingFor(opts)
	switch paging {
	case syncVulnerabilityAdvisoryPages:
		return buildExportSyncVulnerabilityAdvisoryPageQuery(opts, snapshot, snapshotXID)
	case syncVulnerabilityAdvisorySplit:
		return buildExportSyncSplitAdvisoryQuery(opts, snapshot, snapshotXID)
	}
	queryArgs := newSyncVulnerabilityQueryArgs(opts, snapshot, snapshotXID)
	query := queryArgs.changedIDsCTE() + exportSyncVulnerabilitiesBaseSQL(opts.Since != nil)
	queryArgs.addSnapshotXIDFilters(&query, opts.Since != nil)
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
	if paging == syncVulnerabilityDeltaRowOffset {
		query += ` ORDER BY v.id ASC, ap.ecosystem ASC, ap.name ASC`
	} else {
		query += ` ORDER BY ap.ecosystem ASC, ap.name ASC, v.id ASC`
	}
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

func scanSyncVulnerabilityDest(item *db.SyncVulnerability) []any {
	return []any{
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
	}
}

// buildExportSyncSplitAdvisoryQuery continues an advisory of a delta whose
// rows alone exceed the byte budget: the in-scope affected rows of that one
// advisory after the advisory row cursor, in (ecosystem, name) order, with one
// row more than the limit to tell whether more follow. The vulnerability row
// stays bounded by the pinned snapshot like every delta page, so an advisory
// that changed after the snapshot returns no further rows here and reaches
// the client again with the next delta.
func buildExportSyncSplitAdvisoryQuery(opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (string, []any, error) {
	id, ecosystem, name, ok := db.DecodeSyncAdvisoryRowCursor(opts.Cursor.VulnerabilitiesCursor)
	if !ok {
		return "", nil, fmt.Errorf("postgres: invalid vulnerability sync cursor: not an advisory row cursor")
	}
	queryArgs := syncVulnerabilityQueryArgs{args: []any{snapshot}}
	if snapshotXID > 0 {
		queryArgs.snapshotXIDArg = queryArgs.appendArg(strconv.FormatUint(snapshotXID, 10))
	}
	query := `
	SELECT` + syncVulnerabilityColumnsSQL + `
	FROM vulnerabilities v
	INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id` + syncVulnerabilityDetailJoinsSQL() + fmt.Sprintf(`
	WHERE v.id = $%d
	  AND (ap.ecosystem, ap.name) > ($%d, $%d)
	  AND v.updated_at <= $1`, queryArgs.appendArg(id), queryArgs.appendArg(ecosystem), queryArgs.appendArg(name))
	queryArgs.addSnapshotXIDFilters(&query, true)
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ap.ecosystem = ANY($%d)`, queryArgs.appendArg(opts.Ecosystems))
	}
	query += `
	ORDER BY ap.ecosystem ASC, ap.name ASC`
	if opts.Limit > 0 {
		query += fmt.Sprintf(`
	LIMIT $%d::bigint + 1`, queryArgs.appendArg(opts.Limit))
	}
	return query, queryArgs.args, nil
}

func (s *Store) exportSyncVulnerabilities(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (syncVulnerabilityPage, error) {
	query, args, err := buildExportSyncVulnerabilitiesQuery(opts, snapshot, snapshotXID)
	if err != nil {
		return syncVulnerabilityPage{}, err
	}
	paging := syncVulnerabilityPagingFor(opts)
	splitID := ""
	if paging == syncVulnerabilityAdvisorySplit {
		splitID, _, _, _ = db.DecodeSyncAdvisoryRowCursor(opts.Cursor.VulnerabilitiesCursor)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return syncVulnerabilityPage{}, fmt.Errorf("postgres: export sync vulnerabilities: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	builder := newSyncVulnerabilityPageBuilder(paging, opts.Limit, splitID, db.SyncVulnerabilityPageByteBudget)
	for rows.Next() {
		var (
			item                     db.SyncVulnerability
			withoutAffected, hasMore bool
		)
		dest := scanSyncVulnerabilityDest(&item)
		if paging == syncVulnerabilityAdvisoryPages {
			dest = append(dest, &withoutAffected, &hasMore)
		}
		if err := rows.Scan(dest...); err != nil {
			return syncVulnerabilityPage{}, fmt.Errorf("postgres: scan sync vulnerability row: %w", err)
		}
		item.Severity = normalizeSeverity(item.Severity)
		if !builder.add(item, withoutAffected, hasMore) {
			// The page is full; the rest of the result is not exported.
			break
		}
	}
	if err := rows.Err(); err != nil {
		return syncVulnerabilityPage{}, fmt.Errorf("postgres: iterate sync vulnerability rows: %w", err)
	}
	return builder.finish(), nil
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
