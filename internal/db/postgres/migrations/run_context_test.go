package migrations

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// The RunContextWithOptions tests below drive the real migrator against a
// scripted database/sql driver. The database reports schema version
// ExpectedVersion-1 with matching metadata, so a run applies exactly the newest
// embedded migration. Like pgx, the driver refuses work on a done context.

type scriptedMigrationEvent struct {
	query       string
	ctxErr      error
	hasDeadline bool
}

type scriptedMigrationDB struct {
	mu     sync.Mutex
	events []scriptedMigrationEvent

	// lockWait runs inside pg_advisory_lock; migrationStatement runs for every
	// statement that is not migrator bookkeeping.
	lockWait           func(context.Context) error
	migrationStatement func(context.Context) error
	unlockErr          error

	// invalidIndex is reported INVALID by the catalog until a statement that
	// builds it has run, so the concurrent-index repair step rebuilds it.
	invalidIndex string
	indexRebuilt bool
}

func (db *scriptedMigrationDB) indexValid(name string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	return name != db.invalidIndex || db.indexRebuilt
}

func (db *scriptedMigrationDB) noteStatement(query string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.invalidIndex != "" && strings.Contains(query, "CREATE INDEX") && strings.Contains(query, db.invalidIndex) {
		db.indexRebuilt = true
	}
}

func (db *scriptedMigrationDB) record(ctx context.Context, query string) error {
	_, hasDeadline := ctx.Deadline()
	db.mu.Lock()
	db.events = append(db.events, scriptedMigrationEvent{query: query, ctxErr: ctx.Err(), hasDeadline: hasDeadline})
	db.mu.Unlock()
	return ctx.Err()
}

func (db *scriptedMigrationDB) snapshot() []scriptedMigrationEvent {
	db.mu.Lock()
	defer db.mu.Unlock()
	return append([]scriptedMigrationEvent(nil), db.events...)
}

// lastEvent returns the index and value of the last event whose query
// contains substr.
func (db *scriptedMigrationDB) lastEvent(t *testing.T, substr string) (int, scriptedMigrationEvent) {
	t.Helper()
	events := db.snapshot()
	for i := len(events) - 1; i >= 0; i-- {
		if strings.Contains(events[i].query, substr) {
			return i, events[i]
		}
	}
	t.Fatalf("no recorded query contains %q", substr)
	return -1, scriptedMigrationEvent{}
}

func isScriptedMigrationStatement(query string) bool {
	return !strings.Contains(query, "schema_migration") && !strings.Contains(query, "pg_advisory")
}

func useScriptedMigrationDB(t *testing.T, db *scriptedMigrationDB) {
	t.Helper()
	original := openMigrationDB
	t.Cleanup(func() { openMigrationDB = original })
	openMigrationDB = func(string) (*sql.DB, error) {
		return sql.OpenDB(scriptedConnector{db: db}), nil
	}
}

type scriptedConnector struct{ db *scriptedMigrationDB }

func (c scriptedConnector) Connect(context.Context) (driver.Conn, error) {
	return &scriptedConn{db: c.db}, nil
}

func (scriptedConnector) Driver() driver.Driver { return scriptedDriver{} }

type scriptedDriver struct{}

func (scriptedDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("scripted driver opens through its connector")
}

type scriptedConn struct{ db *scriptedMigrationDB }

func (*scriptedConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("scripted driver does not prepare statements")
}

func (*scriptedConn) Close() error { return nil }

func (c *scriptedConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *scriptedConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if err := c.db.record(ctx, "BEGIN"); err != nil {
		return nil, err
	}
	return c, nil
}

// ResetSession and IsValid mirror pgx, so database/sql keeps the connection
// after a rollback.
func (*scriptedConn) ResetSession(context.Context) error { return nil }

func (*scriptedConn) IsValid() bool { return true }

func (c *scriptedConn) ExecContext(ctx context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if err := c.db.record(ctx, query); err != nil {
		return nil, err
	}
	switch {
	case strings.Contains(query, "pg_advisory_lock") && c.db.lockWait != nil:
		if err := c.db.lockWait(ctx); err != nil {
			return nil, err
		}
	case isScriptedMigrationStatement(query) && c.db.migrationStatement != nil:
		if err := c.db.migrationStatement(ctx); err != nil {
			return nil, err
		}
	}
	c.db.noteStatement(query)
	return driver.RowsAffected(1), nil
}

func (c *scriptedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.db.record(ctx, query); err != nil {
		return nil, err
	}
	switch {
	case strings.Contains(query, "pg_advisory_unlock"):
		if c.db.unlockErr != nil {
			return nil, c.db.unlockErr
		}
		return scriptedRows([]any{true}), nil
	case strings.Contains(query, "SELECT version, dirty"):
		return scriptedRows([]any{int64(ExpectedVersion - 1), false}), nil
	case strings.Contains(query, "SELECT name, checksum, dirty"):
		version, ok := args[0].Value.(int64)
		if !ok {
			return nil, fmt.Errorf("scripted metadata query version arg %T", args[0].Value)
		}
		migrations, err := embeddedUpMigrations()
		if err != nil {
			return nil, err
		}
		for _, migration := range migrations {
			if int64(migration.version) == version {
				return scriptedRows([]any{migration.name, migrationChecksum(migration.sql), false}), nil
			}
		}
		return nil, fmt.Errorf("scripted metadata query for unknown version %d", version)
	case strings.Contains(query, "RETURNING id"):
		return scriptedRows([]any{int64(7)}), nil
	case strings.Contains(query, "FROM pg_index"):
		name, _ := args[0].Value.(string)
		return scriptedRows([]any{c.db.indexValid(strings.Trim(name, `"`))}), nil
	case strings.Contains(query, "to_regclass($1::text) IS NOT NULL"):
		return scriptedRows([]any{true}), nil
	}
	return nil, fmt.Errorf("scripted driver has no answer for query %q", query)
}

// The connection doubles as its own driver.Tx.
func (c *scriptedConn) Commit() error {
	return c.db.record(context.Background(), "COMMIT")
}

func (c *scriptedConn) Rollback() error {
	return c.db.record(context.Background(), "ROLLBACK")
}

type scriptedResultRows struct {
	values []any
	done   bool
}

func scriptedRows(values []any) driver.Rows {
	return &scriptedResultRows{values: values}
}

func (r *scriptedResultRows) Columns() []string {
	columns := make([]string, len(r.values))
	for i := range columns {
		columns[i] = fmt.Sprintf("c%d", i)
	}
	return columns
}

func (*scriptedResultRows) Close() error { return nil }

func (r *scriptedResultRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	for i, value := range r.values {
		dest[i] = value
	}
	return nil
}

func TestRunContextWithOptionsMigrationOutlivesSetupTimeout(t *testing.T) {
	const setupTimeout = 20 * time.Millisecond
	db := &scriptedMigrationDB{
		migrationStatement: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * setupTimeout):
				return nil
			}
		},
		// The concurrent-index repair step rebuilds this 049 index before the
		// pending migration runs; the slow rebuild must outlive the timeout too.
		invalidIndex: "idx_malicious_active_search_order",
	}
	useScriptedMigrationDB(t, db)

	if err := RunContextWithOptions(context.Background(), "scripted", RunOptions{SetupTimeout: setupTimeout}); err != nil {
		t.Fatalf("RunContextWithOptions() error = %v, want the slow repair and migration to finish", err)
	}

	if !db.indexValid(db.invalidIndex) {
		t.Fatal("concurrent-index repair did not rebuild the INVALID index")
	}
	if _, rebuild := db.lastEvent(t, "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_active_search_order"); rebuild.hasDeadline || rebuild.ctxErr != nil {
		t.Fatalf("index rebuild ran with deadline=%v ctxErr=%v, want neither", rebuild.hasDeadline, rebuild.ctxErr)
	}

	if _, lock := db.lastEvent(t, "pg_advisory_lock"); !lock.hasDeadline {
		t.Fatal("advisory lock acquisition ran without the setup deadline")
	}
	statements := 0
	for _, event := range db.snapshot() {
		if !isScriptedMigrationStatement(event.query) || event.query == "BEGIN" || event.query == "COMMIT" || event.query == "ROLLBACK" {
			continue
		}
		statements++
		if event.hasDeadline {
			t.Fatalf("migration statement ran with a deadline: %.60q", event.query)
		}
	}
	if statements == 0 {
		t.Fatal("no migration statement was executed")
	}
	if _, finished := db.lastEvent(t, "success = true"); finished.ctxErr != nil {
		t.Fatalf("success bookkeeping ran on a done context: %v", finished.ctxErr)
	}
	db.lastEvent(t, "pg_advisory_unlock")
}

func TestRunContextWithOptionsSetupTimeoutBoundsLockWait(t *testing.T) {
	db := &scriptedMigrationDB{
		lockWait: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				return errors.New("advisory lock wait was not bounded by the setup timeout")
			}
		},
	}
	useScriptedMigrationDB(t, db)

	err := RunContextWithOptions(context.Background(), "scripted", RunOptions{SetupTimeout: 20 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "acquire advisory lock") {
		t.Fatalf("RunContextWithOptions() error = %v, want advisory lock deadline", err)
	}
}

func TestRunContextWithOptionsCancelledRunStillRecordsFailureAndReleasesLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db := &scriptedMigrationDB{
		migrationStatement: func(stmtCtx context.Context) error {
			cancel()
			<-stmtCtx.Done()
			return stmtCtx.Err()
		},
	}
	useScriptedMigrationDB(t, db)

	err := RunContextWithOptions(ctx, "scripted", RunOptions{SetupTimeout: time.Second})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "migrations: apply ") {
		t.Fatalf("RunContextWithOptions() error = %v, want the cancelled migration error", err)
	}

	failureIndex, failure := db.lastEvent(t, "success = $2")
	if failure.ctxErr != nil {
		t.Fatalf("failure bookkeeping ran on a done context: %v", failure.ctxErr)
	}
	if !failure.hasDeadline {
		t.Fatal("failure bookkeeping ran without its own deadline")
	}
	if rollbackIndex, _ := db.lastEvent(t, "ROLLBACK"); rollbackIndex > failureIndex {
		t.Fatal("migration transaction rolled back after the failure bookkeeping")
	}
	unlockIndex, unlock := db.lastEvent(t, "pg_advisory_unlock")
	if unlock.ctxErr != nil {
		t.Fatalf("advisory lock release ran on a done context: %v", unlock.ctxErr)
	}
	if !unlock.hasDeadline {
		t.Fatal("advisory lock release ran without its own deadline")
	}
	if unlockIndex < failureIndex {
		t.Fatal("advisory lock released before the failure bookkeeping")
	}
}

func TestRunContextWithOptionsKeepsMigrationAndLockReleaseErrors(t *testing.T) {
	migrationErr := errors.New("scripted migration failure")
	unlockErr := errors.New("scripted unlock failure")
	db := &scriptedMigrationDB{
		migrationStatement: func(context.Context) error { return migrationErr },
		unlockErr:          unlockErr,
	}
	useScriptedMigrationDB(t, db)

	err := RunContextWithOptions(context.Background(), "scripted", RunOptions{})
	if !errors.Is(err, migrationErr) {
		t.Fatalf("RunContextWithOptions() error = %v, want the migration error", err)
	}
	if !errors.Is(err, unlockErr) || !strings.Contains(err.Error(), "release advisory lock") {
		t.Fatalf("RunContextWithOptions() error = %v, want the lock release error too", err)
	}
}

func TestMigrationConnConfigCancelsQueriesOnTheServer(t *testing.T) {
	t.Parallel()

	cfg, err := migrationConnConfig("postgres://packmon:packmon@127.0.0.1:5432/packmon?sslmode=disable")
	if err != nil {
		t.Fatalf("migrationConnConfig() error = %v", err)
	}
	handler, ok := cfg.BuildContextWatcherHandler(&pgconn.PgConn{}).(*pgconn.CancelRequestContextWatcherHandler)
	if !ok {
		t.Fatalf("context watcher handler = %T, want *pgconn.CancelRequestContextWatcherHandler", cfg.BuildContextWatcherHandler(&pgconn.PgConn{}))
	}
	if handler.DeadlineDelay <= 0 {
		t.Fatalf("cancel request deadline delay = %s, want a grace period", handler.DeadlineDelay)
	}
}
