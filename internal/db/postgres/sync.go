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
	return newSyncExport(opts, cursor, snapshot, snapshotXID, datasets), nil
}

// newSyncExport assembles the export of one page from its datasets: the
// pagination state of the next page, the completeness flag of a whole-advisory
// delta page with its advisories without affected rows, and the split markers
// of a page that holds rows of an advisory split over several pages.
func newSyncExport(opts db.SyncExportOptions, cursor db.SyncCursor, snapshot time.Time, snapshotXID uint64, datasets syncDatasets) *db.SyncExport {
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
		VulnerabilitySplitAdvisory:     datasets.vulnerabilitiesSplitAdvisory,
		VulnerabilitySplitStart:        datasets.vulnerabilitiesSplitAdvisory != "" && datasets.vulnerabilitiesSplitStart,
		VulnerabilitySplitComplete:     datasets.vulnerabilitiesSplitAdvisory != "" && datasets.vulnerabilitiesSplitComplete,
	}
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
	// vulnerability_affected_complete; they name the split advisory, and the
	// last of them may report the split complete
	// (buildSyncSplitAdvisoryUnchangedQuery).
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
// snapshot bound. A full export bounds affected rows by the snapshot
// timestamp, and the legacy row-cursor and offset pages of a delta can split
// an advisory, so they never carry the flag, and neither do the pages that
// continue a split advisory (syncVulnerabilityAdvisorySplit).
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
// returns the per-dataset cursor of the next page. Every dataset page reports
// itself whether it may continue. The other row-paged datasets
// (syncRowPageBuilder) continue after their last row when the page filled the
// limit or was cut by its byte budget, so such a page may hold fewer rows than
// the limit and still continue. The vulnerability page (see
// syncVulnerabilityPageBuilder) may hold fewer rows than the limit (the next
// advisory did not fit the rows or the byte budget) or more (its only
// advisory has more rows than the limit), and it continues with the cursor
// the page computed, or else after its last advisory.
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
	if !datasets.vulnerabilitiesHaveMore && !datasets.maliciousHaveMore && !datasets.reputationHaveMore && !datasets.lifecycleHaveMore {
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
	setNextDatasetCursor(nextCursor, cursor.MaliciousDone, datasets.maliciousHaveMore, func() {
		nextCursor.MaliciousDone = true
	}, func() {
		last := malicious[len(malicious)-1]
		nextCursor.MaliciousCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.ID)
	})
	setNextDatasetCursor(nextCursor, cursor.ReputationDone, datasets.reputationHaveMore, func() {
		nextCursor.ReputationDone = true
	}, func() {
		last := reputation[len(reputation)-1]
		nextCursor.ReputationCursor = encodeSyncCursorKey(last.Ecosystem, last.Name, last.Version)
	})
	setNextDatasetCursor(nextCursor, cursor.LifecycleDone, datasets.lifecycleHaveMore, func() {
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
	// splitAdvisoryID names the advisory a split page holds rows of, on the
	// page that starts the split and on every page that continues it.
	// splitStart marks the page that starts the split, splitLast the page
	// that exhausts the advisory's rows, and splitComplete reports that the
	// split pages delivered every current affected row of it (see
	// buildSyncSplitAdvisoryUnchangedQuery).
	splitAdvisoryID string
	splitStart      bool
	splitLast       bool
	splitComplete   bool
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
	malicious       func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncMalicious], error)
	reputation      func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncReputationFinding], error)
	lifecycle       func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncLifecycleRelease], error)
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
	vulnerabilitiesSplitAdvisory   string
	vulnerabilitiesSplitStart      bool
	vulnerabilitiesSplitComplete   bool
	// Each other dataset carries the rows and hasMore of its syncRowPage.
	malicious          []db.SyncMalicious
	maliciousHaveMore  bool
	reputation         []db.SyncReputationFinding
	reputationHaveMore bool
	lifecycle          []db.SyncLifecycleRelease
	lifecycleHaveMore  bool
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
			datasets.vulnerabilitiesSplitAdvisory = page.splitAdvisoryID
			datasets.vulnerabilitiesSplitStart, datasets.vulnerabilitiesSplitComplete = page.splitStart, page.splitComplete
			if err != nil {
				errCh <- syncDatasetExportError{order: 0, err: err}
			}
		}()
	}
	if !cursor.MaliciousDone {
		wg.Add(1)
		go func() {
			defer wg.Done()
			page, err := exporters.malicious(ctx, syncOptionsWithOffset(opts, cursor.Malicious), snapshot, snapshotXID)
			datasets.malicious, datasets.maliciousHaveMore = page.rows, page.hasMore
			if err != nil {
				errCh <- syncDatasetExportError{order: 1, err: err}
			}
		}()
	}
	if !cursor.ReputationDone {
		wg.Add(1)
		go func() {
			defer wg.Done()
			page, err := exporters.reputation(ctx, syncOptionsWithOffset(opts, cursor.Reputation), snapshot, snapshotXID)
			datasets.reputation, datasets.reputationHaveMore = page.rows, page.hasMore
			if err != nil {
				errCh <- syncDatasetExportError{order: 2, err: err}
			}
		}()
	}
	if !cursor.LifecycleDone {
		wg.Add(1)
		go func() {
			defer wg.Done()
			page, err := exporters.lifecycle(ctx, syncOptionsWithOffset(opts, cursor.Lifecycle), snapshot, snapshotXID)
			datasets.lifecycle, datasets.lifecycleHaveMore = page.rows, page.hasMore
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

// setNextDatasetCursor marks a dataset done unless its page reported that it
// continues (hasMore), in which case setCursor continues it after the last row
// of the page. A page that continues always holds at least one row.
func setNextDatasetCursor(next *db.SyncCursor, alreadyDone, hasMore bool, markDone, setCursor func()) {
	if alreadyDone || !hasMore {
		markDone()
		return
	}
	setCursor()
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

// addSyncWindowFilters bounds a delta of a row-paged dataset by the snapshot
// transaction ID and the since window: the row's transaction ID column (xmin)
// must predate the snapshot ID, and the row must have changed at or after the
// since timestamp or the since transaction ID (see syncXIDBeforeSQL and
// syncXIDAtOrAfterSQL for the epoch-safe comparisons). A full export gets
// neither; the caller bounds it by the snapshot timestamp only (see
// syncXIDBeforeSQL for why it carries no transaction ID bound).
func addSyncWindowFilters(query *string, args *[]any, opts db.SyncExportOptions, snapshotXID uint64, updatedExpr, xidColumn string) {
	if opts.Since == nil {
		return
	}
	if snapshotXID > 0 {
		*query += ` AND ` + syncXIDBeforeSQL(xidColumn, fmt.Sprintf("$%d", len(*args)+1))
		*args = append(*args, strconv.FormatUint(snapshotXID, 10))
	}

	since := opts.Since.UTC()
	if opts.SinceXID > 0 {
		*query += fmt.Sprintf(` AND (%s >= $%d OR %s)`, updatedExpr, len(*args)+1, syncXIDAtOrAfterSQL(xidColumn, fmt.Sprintf("$%d", len(*args)+2)))
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

// newSyncVulnerabilityQueryArgs binds the snapshot timestamp and, for a
// delta, the since window and the snapshot transaction ID. A full export binds
// no transaction ID (see syncXIDBeforeSQL).
func newSyncVulnerabilityQueryArgs(opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) syncVulnerabilityQueryArgs {
	queryArgs := syncVulnerabilityQueryArgs{
		args: []any{snapshot},
	}
	if opts.Since == nil {
		return queryArgs
	}
	queryArgs.sinceArg = queryArgs.appendArg(opts.Since.UTC())
	if opts.SinceXID > 0 {
		queryArgs.sinceXIDArg = queryArgs.appendArg(strconv.FormatUint(opts.SinceXID, 10))
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

// changedIDsCTE selects the vulnerabilities a delta exports: those whose
// vulnerability row or any affected row changed at or after the since
// timestamp or the since transaction ID (syncXIDAtOrAfterSQL), each bounded by
// the snapshot (vulnerabilityChangedIDUpperFilter).
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
		sinceXID := fmt.Sprintf("$%d", q.sinceXIDArg)
		query += fmt.Sprintf(`
		UNION
		SELECT v.id
		FROM vulnerabilities v
		WHERE %[1]s
		  AND v.updated_at <= $1%[3]s
		UNION
		SELECT ap.vulnerability_id AS id
		FROM affected_packages ap
		WHERE %[2]s
		  AND ap.updated_at <= $1%[4]s`, syncXIDAtOrAfterSQL("v.xmin", sinceXID), syncXIDAtOrAfterSQL("ap.xmin", sinceXID), vulnerabilityUpperFilter, affectedUpperFilter)
	}
	query += `
	)`
	return query
}

// vulnerabilityChangedIDUpperFilter ignores, for the changed-ID CTE, row
// versions a transaction at or after the snapshot wrote (syncXIDBeforeSQL);
// the next delta, whose since_xid is this snapshot ID, selects them.
func (q syncVulnerabilityQueryArgs) vulnerabilityChangedIDUpperFilter(alias string) string {
	if q.snapshotXIDArg == 0 {
		return ""
	}
	return `
		  AND ` + syncXIDBeforeSQL(alias+".xmin", fmt.Sprintf("$%d", q.snapshotXIDArg))
}

// addSnapshotXIDFilters bounds the vulnerability row of a delta by the
// snapshot watermark (syncXIDBeforeSQL), on the split continuation query as
// well. Only the vulnerability row is bounded: the changed-ID CTE already
// applied the snapshot to decide which vulnerabilities changed, and each of
// them is then exported with its complete current affected set (see
// exportSyncVulnerabilitiesBaseSQL). A full export binds no snapshot
// transaction ID, so this adds nothing to it (see syncXIDBeforeSQL).
func (q syncVulnerabilityQueryArgs) addSnapshotXIDFilters(query *string) {
	if q.snapshotXIDArg == 0 {
		return
	}
	*query += ` AND ` + syncXIDBeforeSQL("v.xmin", fmt.Sprintf("$%d", q.snapshotXIDArg))
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
// The full export keeps the row-level snapshot timestamp bound.
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
	queryArgs.addSnapshotXIDFilters(&candidateFilters)
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
	queryArgs.addSnapshotXIDFilters(&query)
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
	rows.Close()
	page := builder.finish()
	if page.splitLast {
		page.splitComplete, err = s.syncSplitAdvisoryUnchanged(ctx, page.splitAdvisoryID, snapshot, snapshotXID)
		if err != nil {
			return syncVulnerabilityPage{}, err
		}
	}
	return page, nil
}

// buildSyncSplitAdvisoryUnchangedQuery builds the check behind
// vulnerability_split_complete on the last page of a split advisory: neither
// the advisory's vulnerability row nor any of its affected rows (in any
// ecosystem) has a version written after the pinned snapshot, by timestamp or
// by transaction ID.
//
// The split pages cover the advisory's rows in (ecosystem, name) order, each
// page the key range after the previous page's last row, every page in its own
// statement over the current affected rows. When nothing of the advisory
// changed after the snapshot, every affected row that exists now existed
// unchanged while each page ran, so the page covering its key range delivered
// it, and a row no split page delivered no longer exists. A vulnerability row
// changed after the snapshot ends the split early (the split query excludes
// it), and an affected row inserted, re-inserted, or updated after the
// snapshot may have been missed; both fail the check, so the client keeps
// upserting and the next delta delivers the advisory again. Without a
// snapshot transaction ID the check cannot prove this, and ok is false.
//
// Both rows are tested with syncXIDAtOrAfterSQL, which fails toward
// "changed": the vulnerability row must provably predate the snapshot (NOT
// at or after it), so a snapshot more than 2^31 transactions old, or one from
// the future, fails the check.
func buildSyncSplitAdvisoryUnchangedQuery(id string, snapshot time.Time, snapshotXID uint64) (query string, args []any, ok bool) {
	if snapshotXID == 0 {
		return "", nil, false
	}
	return `
	SELECT EXISTS (
		SELECT 1 FROM vulnerabilities v
		WHERE v.id = $2
		  AND v.updated_at <= $1
		  AND NOT ` + syncXIDAtOrAfterSQL("v.xmin", "$3") + `
	) AND NOT EXISTS (
		SELECT 1 FROM affected_packages ap
		WHERE ap.vulnerability_id = $2
		  AND (ap.updated_at > $1 OR ` + syncXIDAtOrAfterSQL("ap.xmin", "$3") + `)
	)`, []any{snapshot, id, strconv.FormatUint(snapshotXID, 10)}, true
}

// Sync transaction ID windows. A row's xmin is a 32-bit transaction ID, while
// the since and snapshot watermarks are 64-bit, epoch-extended IDs
// (txid_snapshot_xmin), so past the first transaction ID epoch (about 4
// billion transactions) a plain comparison of the two is meaningless. The
// filters therefore compare the xmin with a watermark modulo 2^32, within the
// window from the watermark up to the statement's next transaction ID
// (syncXIDWindowWidthSQL): every row version the statement sees and a
// transaction at or after the watermark wrote has a 64-bit ID in that window,
// so its 32-bit xmin lies at the same distance from the watermark's low 32
// bits. A frozen tuple keeps its raw, possibly ancient xmin (as do the
// special IDs 0 to 2), which may alias into the window; the window spans only
// the transactions since the watermark, so that is rare, and both conditions
// then treat the row like one written in the window: a delta's since leg
// delivers it once more, a delta's snapshot bound defers it to the next delta
// (whose since_xid window covers it), and the split completeness check fails,
// so none of them skips the row. The window is used only while it is at most
// 2^31 - 1 transactions wide (PostgreSQL never lets a live transaction ID age
// past 2^31); a watermark older than that, or one from the future (a forged
// value or a server restored from a backup), makes both conditions true for
// every row, which errs toward delivering rows, never toward skipping them.

// syncXIDDistanceSQL returns the distance, modulo 2^32, from the low 32 bits
// of the 64-bit transaction ID watermark in arg to the 32-bit transaction ID
// column.
func syncXIDDistanceSQL(column, arg string) string {
	return fmt.Sprintf(`((((%s::text)::bigint - %s::bigint) %% 4294967296 + 4294967296) %% 4294967296)`, column, arg)
}

// syncXIDWindowWidthSQL returns the number of transaction IDs from the 64-bit
// watermark in arg up to the next transaction ID of the statement's snapshot
// (txid_snapshot_xmax), or outOfRange when that window is negative or wider
// than 2^31 - 1. It is an uncorrelated scalar subquery, so PostgreSQL
// evaluates it once per statement rather than once per row.
func syncXIDWindowWidthSQL(arg, outOfRange string) string {
	return fmt.Sprintf(`(SELECT CASE WHEN xid_window.width BETWEEN 0 AND 2147483647 THEN xid_window.width ELSE %s END FROM (SELECT txid_snapshot_xmax(txid_current_snapshot()) - %s::bigint AS width) xid_window)`, outOfRange, arg)
}

// syncXIDAtOrAfterSQL returns a condition that holds for every row version
// whose 32-bit transaction ID column a transaction at or after the 64-bit
// watermark in arg wrote: a delta's "changed since" leg and the split
// completeness check. It fails toward true: an out-of-range window counts
// every row as changed (width 2^32 exceeds every distance).
func syncXIDAtOrAfterSQL(column, arg string) string {
	return syncXIDDistanceSQL(column, arg) + ` < ` + syncXIDWindowWidthSQL(arg, "4294967296")
}

// syncXIDBeforeSQL returns a condition that holds for every row version whose
// 32-bit transaction ID column a transaction before the 64-bit watermark in
// arg wrote, and fails only for row versions in the window from the watermark
// to the statement's next transaction ID: the snapshot upper bound. Such a
// row is excluded now and matched by syncXIDAtOrAfterSQL with the same
// watermark on the next delta (whose since_xid is this snapshot ID), so the
// two never leave a gap. It fails toward true: with an out-of-range window no
// row is excluded (width 0 never exceeds a distance), because a row delivered
// beyond the snapshot is only delivered again by the next delta.
//
// Only deltas use it. A full export (no since window) carries no transaction
// ID bound at all, only updated_at <= snapshot: deferring an aliased frozen
// row to the next delta is safe only for a client that runs one, while a
// one-shot full sync (a fresh cache in CI) never does. Without the bound a
// full export may also deliver row versions of transactions still in flight
// at the snapshot whose updated_at predates it; their transaction ID is at or
// after the snapshot ID (the oldest transaction running at the snapshot), so
// the next delta, whose since_xid is that ID, delivers them again, and local
// upserts are idempotent. Full exports page by keyset cursor or offset, never
// split an advisory, and send no lifecycle tombstones, so none of their
// paging depends on the bound.
func syncXIDBeforeSQL(column, arg string) string {
	return syncXIDDistanceSQL(column, arg) + ` >= ` + syncXIDWindowWidthSQL(arg, "0")
}

// syncSplitAdvisoryUnchanged reports whether the split pages of the advisory
// delivered every current affected row of it (see
// buildSyncSplitAdvisoryUnchangedQuery).
func (s *Store) syncSplitAdvisoryUnchanged(ctx context.Context, id string, snapshot time.Time, snapshotXID uint64) (bool, error) {
	query, args, ok := buildSyncSplitAdvisoryUnchangedQuery(id, snapshot, snapshotXID)
	if !ok {
		return false, nil
	}
	var unchanged bool
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&unchanged); err != nil {
		return false, fmt.Errorf("postgres: check split sync advisory: %w", err)
	}
	return unchanged, nil
}

func (s *Store) exportSyncReputation(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (syncRowPage[db.SyncReputationFinding], error) {
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
		`prc.xmin`,
	)
	if len(opts.Ecosystems) > 0 {
		query += fmt.Sprintf(` AND ecosystem = ANY($%d)`, len(args)+1)
		args = append(args, opts.Ecosystems)
	}
	if opts.Cursor.ReputationCursor != "" {
		cursor, err := decodeSyncCursorKey(opts.Cursor.ReputationCursor, 3)
		if err != nil {
			return syncRowPage[db.SyncReputationFinding]{}, fmt.Errorf("postgres: invalid reputation sync cursor: %w", err)
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
		return syncRowPage[db.SyncReputationFinding]{}, fmt.Errorf("postgres: export sync reputation findings: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	builder := newSyncRowPageBuilder(opts.Limit, db.SyncReputationPageByteBudget, syncReputationWireBytes)
	for rows.Next() {
		rep, err := scanPackageReputation(rows)
		if err != nil {
			return syncRowPage[db.SyncReputationFinding]{}, fmt.Errorf("postgres: scan sync reputation row: %w", err)
		}
		if !builder.add(reputationSyncFinding(rep)) {
			// The page is full; the rest of the result is not exported.
			break
		}
	}
	if err := rows.Err(); err != nil {
		return syncRowPage[db.SyncReputationFinding]{}, fmt.Errorf("postgres: iterate sync reputation rows: %w", err)
	}

	return builder.finish(), nil
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

func (s *Store) exportSyncMalicious(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (syncRowPage[db.SyncMalicious], error) {
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
		`mf.xmin`,
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
			return syncRowPage[db.SyncMalicious]{}, fmt.Errorf("postgres: invalid malicious sync cursor: %w", err)
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
		return syncRowPage[db.SyncMalicious]{}, fmt.Errorf("postgres: export sync malicious findings: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	builder := newSyncRowPageBuilder(opts.Limit, db.SyncMaliciousPageByteBudget, syncMaliciousWireBytes)
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
			return syncRowPage[db.SyncMalicious]{}, fmt.Errorf("postgres: scan sync malicious row: %w", err)
		}
		item.Severity = normalizeSeverity(item.Severity)
		if !builder.add(item) {
			// The page is full; the rest of the result is not exported.
			break
		}
	}
	if err := rows.Err(); err != nil {
		return syncRowPage[db.SyncMalicious]{}, fmt.Errorf("postgres: iterate sync malicious rows: %w", err)
	}

	return builder.finish(), nil
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
	if opts.Since != nil {
		// A full export carries no transaction ID bound (see syncXIDBeforeSQL).
		queryArgs.addSnapshotXID(snapshotXID)
	}
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

	xidArg := fmt.Sprintf("$%d", q.appendArg(strconv.FormatUint(snapshotXID, 10)))
	q.activeFilters = append(q.activeFilters,
		syncXIDBeforeSQL("m.xmin", xidArg),
		syncXIDBeforeSQL("p.xmin", xidArg),
		syncXIDBeforeSQL("r.xmin", xidArg),
	)
	q.tombstoneFilters = append(q.tombstoneFilters,
		syncXIDBeforeSQL("t.xmin", xidArg),
	)
}

func (q *syncLifecycleQueryArgs) addDeltaWindow(opts db.SyncExportOptions) {
	if opts.Since == nil {
		return
	}

	sinceArg := q.appendArg(opts.Since.UTC())
	if opts.SinceXID > 0 {
		sinceXIDArg := fmt.Sprintf("$%d", q.appendArg(strconv.FormatUint(opts.SinceXID, 10)))
		q.activeFilters = append(q.activeFilters, fmt.Sprintf(`(
				m.updated_at >= $%[1]d OR
				p.updated_at >= $%[1]d OR
				r.updated_at >= $%[1]d OR
				%[2]s OR
				%[3]s OR
				%[4]s
			)`, sinceArg, syncXIDAtOrAfterSQL("m.xmin", sinceXIDArg), syncXIDAtOrAfterSQL("p.xmin", sinceXIDArg), syncXIDAtOrAfterSQL("r.xmin", sinceXIDArg)))
		q.tombstoneFilters = append(q.tombstoneFilters, fmt.Sprintf(`(
				t.updated_at >= $%[1]d OR
				%[2]s
			)`, sinceArg, syncXIDAtOrAfterSQL("t.xmin", sinceXIDArg)))
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

func (s *Store) exportSyncLifecycle(ctx context.Context, opts db.SyncExportOptions, snapshot time.Time, snapshotXID uint64) (syncRowPage[db.SyncLifecycleRelease], error) {
	query, args, err := buildExportSyncLifecycleQuery(opts, snapshot, snapshotXID)
	if err != nil {
		return syncRowPage[db.SyncLifecycleRelease]{}, err
	}
	return s.querySyncLifecycleRows(ctx, query, args, newSyncRowPageBuilder(opts.Limit, db.SyncLifecyclePageByteBudget, syncLifecycleWireBytes))
}

func (s *Store) querySyncLifecycleRows(ctx context.Context, query string, args []any, builder *syncRowPageBuilder[db.SyncLifecycleRelease]) (syncRowPage[db.SyncLifecycleRelease], error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return syncRowPage[db.SyncLifecycleRelease]{}, fmt.Errorf("postgres: export sync lifecycle releases: %w", err)
	}
	defer ioutils.CloseSilently(rows)

	for rows.Next() {
		item, err := scanSyncLifecycleRelease(rows)
		if err != nil {
			return syncRowPage[db.SyncLifecycleRelease]{}, fmt.Errorf("postgres: scan sync lifecycle row: %w", err)
		}
		if !builder.add(item) {
			// The page is full; the rest of the result is not exported.
			break
		}
	}
	if err := rows.Err(); err != nil {
		return syncRowPage[db.SyncLifecycleRelease]{}, fmt.Errorf("postgres: iterate sync lifecycle rows: %w", err)
	}

	return builder.finish(), nil
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
