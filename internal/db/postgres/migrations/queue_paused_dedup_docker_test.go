//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type queueMigrationRow struct {
	ecosystem   string
	name        string
	source      string
	priority    int
	status      string
	requestedAt time.Time
	processedAt sql.NullTime
	errorText   sql.NullString
}

func TestQueuePausedDedupMigrationRoundTripAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	applyEmbeddedMigrationForTest(t, ctx, db, 1, MigrationDirectionUp)
	// The initial predicate itself prevents pending/processing duplicates. The
	// upgrade nevertheless has an explicit deterministic repair order for a
	// database whose legacy index is absent, so remove it before constructing
	// that recoverable catalog state.
	execOK(t, ctx, db, `DROP INDEX idx_queue_dedup`)
	wantAfterUp := seedQueueMigrationRows(t, ctx, db)

	up := applyEmbeddedMigrationForTest(t, ctx, db, 2, MigrationDirectionUp)
	assertCleanMigration(t, ctx, db, up)
	assertQueueRows(t, ctx, db, wantAfterUp)
	assertQueueDedupIndex(t, ctx, db, []string{"pending", "processing", "paused"})
	assertQueueUpCollisionMatrix(t, ctx, db)
	wantBeforeDown := readQueueRows(t, ctx, db)

	down := applyEmbeddedMigrationForTest(t, ctx, db, 2, MigrationDirectionDown)
	assertCleanMigrationAndDelete(t, ctx, db, down)
	assertCurrentMigration(t, ctx, db, 1)
	assertQueueRows(t, ctx, db, wantBeforeDown)
	assertQueueDedupIndex(t, ctx, db, []string{"pending", "processing"})

	// The legacy predicate rejects both active states but permits paused work
	// for the same coordinates. Give the permitted duplicate a stable ID so
	// the subsequent re-upgrade can prove that it is the row deleted by 002.
	expectSQLState(t, "23505", execSQL(ctx, db, `INSERT INTO refresh_queue(id, ecosystem, name, source, status) VALUES(700, 'npm', 'proc-package', 'socket', 'pending')`))
	expectSQLState(t, "23505", execSQL(ctx, db, `INSERT INTO refresh_queue(id, ecosystem, name, source, status) VALUES(701, 'npm', 'proc-package', 'socket', 'processing')`))
	execOK(t, ctx, db, `INSERT INTO refresh_queue(id, ecosystem, name, source, priority, status, requested_at, error) VALUES(702, 'npm', 'proc-package', 'socket', 0, 'paused', '2025-12-31T00:00:00Z', 'legacy-paused')`)

	execOK(t, ctx, db, `DROP INDEX idx_queue_dedup`)
	down = applyEmbeddedMigrationForTest(t, ctx, db, 2, MigrationDirectionDown)
	assertCleanMigrationAndDelete(t, ctx, db, down)
	assertCurrentMigration(t, ctx, db, 1)
	assertQueueDedupIndex(t, ctx, db, []string{"pending", "processing"})
	if _, ok := readQueueRows(t, ctx, db)[702]; !ok {
		t.Fatal("repeated 002 down removed permitted paused row 702")
	}

	up = applyEmbeddedMigrationForTest(t, ctx, db, 2, MigrationDirectionUp)
	assertCleanMigration(t, ctx, db, up)
	assertQueueDedupIndex(t, ctx, db, []string{"pending", "processing", "paused"})
	assertQueueRows(t, ctx, db, wantBeforeDown)
}

func TestQueuePausedDedupMigrationFailureRollsBackAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	db, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(db)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := ensureVersionTable(ctx, db); err != nil {
		t.Fatalf("ensureVersionTable() error = %v", err)
	}
	applyEmbeddedMigrationForTest(t, ctx, db, 1, MigrationDirectionUp)
	seedQueueFailureRows(t, ctx, db)
	wantRows := readQueueRows(t, ctx, db)

	embedded, err := ReadEmbeddedMigration(2, MigrationDirectionUp)
	if err != nil {
		t.Fatalf("read migration 002 up: %v", err)
	}
	const createNeedle = "\nCREATE UNIQUE INDEX idx_queue_dedup"
	if count := strings.Count(embedded.SQL, createNeedle); count != 1 {
		t.Fatalf("002 up CREATE needle count = %d, want exactly 1", count)
	}
	injectedSQL := strings.Replace(embedded.SQL, createNeedle, `
DO $$ BEGIN
    RAISE EXCEPTION 'injected post-delete failure';
END $$;

CREATE UNIQUE INDEX idx_queue_dedup`, 1)
	injected := migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: injectedSQL}
	err = applyMigration(ctx, db, injected)
	if err == nil || !strings.Contains(err.Error(), "injected post-delete failure") {
		t.Fatalf("apply injected 002 error = %v, want injected post-delete failure", err)
	}

	assertDirtyMigration(t, ctx, db, injected)
	assertQueueRows(t, ctx, db, wantRows)
	assertQueueDedupIndex(t, ctx, db, []string{"pending", "processing"})
}

func seedQueueFailureRows(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	execOK(t, ctx, db, `
		INSERT INTO refresh_queue(id, ecosystem, name, source, priority, status, requested_at, error)
		VALUES
			(801, 'npm', 'failure-package', 'socket', 2, 'pending', '2026-02-03T04:05:06Z', 'pending-survivor'),
			(802, 'npm', 'failure-package', 'socket', 0, 'paused', '2026-02-03T04:04:06Z', 'paused-loser'),
			(803, 'npm', 'failure-paused', 'socket', 2, 'paused', '2026-02-03T04:05:06Z', 'later-priority'),
			(804, 'npm', 'failure-paused', 'socket', 1, 'paused', '2026-02-03T04:06:06Z', 'priority-survivor'),
			(805, 'npm', 'failure-terminal', 'socket', 0, 'done', '2026-02-03T04:05:06Z', NULL),
			(806, 'npm', 'failure-terminal', 'socket', 0, 'error', '2026-02-03T04:05:06Z', 'terminal-error')`)
}

func seedQueueMigrationRows(t *testing.T, ctx context.Context, db *sql.DB) map[int]queueMigrationRow {
	t.Helper()
	base := time.Date(2026, time.February, 3, 4, 5, 6, 0, time.UTC)
	processed := base.Add(20 * time.Minute)
	rows := map[int]queueMigrationRow{
		101: {"npm", "proc-package", "socket", 3, "processing", base.Add(5 * time.Minute), sql.NullTime{Time: processed, Valid: true}, sql.NullString{String: "processing-note", Valid: true}},
		102: {"npm", "proc-package", "socket", 0, "pending", base, sql.NullTime{}, sql.NullString{}},
		103: {"npm", "proc-package", "socket", 0, "paused", base.Add(-time.Minute), sql.NullTime{}, sql.NullString{String: "paused-note", Valid: true}},
		201: {"npm", "pending-package", "socket", 3, "pending", base.Add(5 * time.Minute), sql.NullTime{}, sql.NullString{}},
		202: {"npm", "pending-package", "socket", 0, "paused", base, sql.NullTime{}, sql.NullString{}},
		301: {"npm", "priority-package", "socket", 2, "paused", base, sql.NullTime{}, sql.NullString{String: "higher-priority-number", Valid: true}},
		302: {"npm", "priority-package", "socket", 1, "paused", base.Add(time.Minute), sql.NullTime{}, sql.NullString{String: "lower-priority-number", Valid: true}},
		401: {"npm", "requested-package", "socket", 1, "paused", base.Add(2 * time.Minute), sql.NullTime{}, sql.NullString{String: "later", Valid: true}},
		402: {"npm", "requested-package", "socket", 1, "paused", base.Add(time.Minute), sql.NullTime{}, sql.NullString{String: "earlier", Valid: true}},
		501: {"npm", "id-package", "socket", 1, "paused", base, sql.NullTime{}, sql.NullString{String: "lower-id", Valid: true}},
		502: {"npm", "id-package", "socket", 1, "paused", base, sql.NullTime{}, sql.NullString{String: "higher-id", Valid: true}},
		601: {"npm", "terminal-package", "socket", 0, "done", base, sql.NullTime{Time: processed, Valid: true}, sql.NullString{}},
		602: {"npm", "terminal-package", "socket", 0, "error", base, sql.NullTime{Time: processed, Valid: true}, sql.NullString{String: "terminal-error", Valid: true}},
	}
	for id, row := range rows {
		_, err := db.ExecContext(ctx, `
			INSERT INTO refresh_queue(id, ecosystem, name, source, priority, status, requested_at, processed_at, error)
			VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			id, row.ecosystem, row.name, row.source, row.priority, row.status, row.requestedAt, nullableTimeValue(row.processedAt), nullableStringValue(row.errorText))
		if err != nil {
			t.Fatalf("seed queue row %d: %v", id, err)
		}
	}
	return map[int]queueMigrationRow{
		101: rows[101],
		201: rows[201],
		302: rows[302],
		402: rows[402],
		501: rows[501],
		601: rows[601],
		602: rows[602],
	}
}

func assertQueueUpCollisionMatrix(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for id, status := range map[int]string{710: "pending", 711: "processing", 712: "paused"} {
		expectSQLState(t, "23505", execSQL(ctx, db, `INSERT INTO refresh_queue(id, ecosystem, name, source, status) VALUES($1, 'npm', 'proc-package', 'socket', $2)`, id, status))
	}
	for id, coordinates := range map[int][3]string{
		720: {"pypi", "proc-package", "socket"},
		721: {"npm", "different-name", "socket"},
		722: {"npm", "proc-package", "different-source"},
	} {
		execOK(t, ctx, db, `INSERT INTO refresh_queue(id, ecosystem, name, source, status) VALUES($1, $2, $3, $4, 'pending')`, id, coordinates[0], coordinates[1], coordinates[2])
	}
	execOK(t, ctx, db, `INSERT INTO refresh_queue(id, ecosystem, name, source, status) VALUES(730, 'npm', 'proc-package', 'socket', 'done'), (731, 'npm', 'proc-package', 'socket', 'error')`)
}

func assertQueueDedupIndex(t *testing.T, ctx context.Context, db *sql.DB, statuses []string) {
	t.Helper()
	var table, keys, predicate string
	var unique, valid, ready bool
	if err := db.QueryRowContext(ctx, `
		SELECT tbl.relname, i.indisunique,
			(SELECT string_agg(pg_get_indexdef(i.indexrelid, key_no, true), '|' ORDER BY key_no)
			 FROM generate_series(1, i.indnkeyatts) key_no),
			COALESCE(pg_get_expr(i.indpred, i.indrelid), ''), i.indisvalid, i.indisready
		FROM pg_index i
		JOIN pg_class idx ON idx.oid = i.indexrelid
		JOIN pg_class tbl ON tbl.oid = i.indrelid
		WHERE idx.oid = to_regclass('public.idx_queue_dedup')`).Scan(&table, &unique, &keys, &predicate, &valid, &ready); err != nil {
		t.Fatalf("inspect idx_queue_dedup: %v", err)
	}
	wantPredicate := "status=anyarray['" + strings.Join(statuses, "','") + "']"
	if table != "refresh_queue" || !unique || keys != "ecosystem|name|source" || normalizeCatalogPredicate(predicate) != wantPredicate || !valid || !ready {
		t.Fatalf("idx_queue_dedup = table:%s unique:%v keys:%s predicate:%s valid:%v ready:%v, want statuses %v", table, unique, keys, predicate, valid, ready, statuses)
	}
}

func readQueueRows(t *testing.T, ctx context.Context, db *sql.DB) map[int]queueMigrationRow {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT id, ecosystem, name, source, priority, status, requested_at, processed_at, error
		FROM refresh_queue ORDER BY id`)
	if err != nil {
		t.Fatalf("read queue rows: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	got := make(map[int]queueMigrationRow)
	for rows.Next() {
		var id int
		var row queueMigrationRow
		if err := rows.Scan(&id, &row.ecosystem, &row.name, &row.source, &row.priority, &row.status, &row.requestedAt, &row.processedAt, &row.errorText); err != nil {
			t.Fatalf("scan queue row: %v", err)
		}
		row.requestedAt = row.requestedAt.UTC()
		if row.processedAt.Valid {
			row.processedAt.Time = row.processedAt.Time.UTC()
		}
		got[id] = row
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate queue rows: %v", err)
	}
	return got
}

func assertQueueRows(t *testing.T, ctx context.Context, db *sql.DB, want map[int]queueMigrationRow) {
	t.Helper()
	got := readQueueRows(t, ctx, db)
	if !maps.Equal(got, want) {
		t.Fatalf("queue rows = %#v, want %#v", got, want)
	}
}

func assertDirtyMigration(t *testing.T, ctx context.Context, db *sql.DB, migration migrationFile) {
	t.Helper()
	wantChecksum := migrationChecksum(migration.sql)
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT name, checksum, dirty, applied_at FROM schema_migrations WHERE version = $1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read dirty metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != wantChecksum || !dirty || appliedAt.Valid {
		t.Fatalf("dirty metadata = name:%q checksum:%q dirty:%v applied:%v", name, checksum, dirty, appliedAt.Valid)
	}
	var eventName, eventChecksum string
	var finished sql.NullTime
	var success, eventDirty bool
	if err := db.QueryRowContext(ctx, `SELECT name, checksum, finished_at, success, dirty FROM schema_migration_events WHERE version = $1 ORDER BY id DESC LIMIT 1`, migration.version).Scan(&eventName, &eventChecksum, &finished, &success, &eventDirty); err != nil {
		t.Fatalf("read dirty event for %s: %v", migration.name, err)
	}
	if eventName != migration.name || eventChecksum != wantChecksum || !finished.Valid || success || !eventDirty {
		t.Fatalf("dirty event = name:%q checksum:%q finished:%v success:%v dirty:%v", eventName, eventChecksum, finished.Valid, success, eventDirty)
	}
}

func nullableTimeValue(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

func nullableStringValue(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}
