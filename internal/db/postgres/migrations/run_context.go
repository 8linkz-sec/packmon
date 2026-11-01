package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/stdlib"
)

// RunOptions tunes RunContextWithOptions.
type RunOptions struct {
	// SetupTimeout bounds opening the migration connection and acquiring the
	// migration advisory lock. Zero leaves both bounded by ctx alone. The
	// migrations themselves always run on ctx alone, so a long index build or
	// data repair is not cut off by a connect timeout.
	SetupTimeout time.Duration
}

const (
	// migrationCleanupTimeout bounds the failure bookkeeping and the
	// advisory-lock release. Both run on a context detached from the caller's
	// cancellation so a cancelled or expired run still records finished_at
	// and releases the lock.
	migrationCleanupTimeout = 15 * time.Second

	// migrationCancelGracePeriod is how long a cancelled statement waits for
	// PostgreSQL to acknowledge the cancel request before the client closes
	// the connection.
	migrationCancelGracePeriod = 10 * time.Second
)

// openMigrationDB opens the database handle the migrator runs on. Tests
// replace it with a scripted driver.
var openMigrationDB = func(dsn string) (*sql.DB, error) {
	cfg, err := migrationConnConfig(dsn)
	if err != nil {
		return nil, err
	}
	return stdlib.OpenDB(*cfg), nil
}

// migrationConnConfig parses dsn for the migrator. On cancellation pgx
// normally closes the connection, which would abandon the session that holds
// the advisory lock and leave the cleanup below nothing to run on. The
// migrator asks PostgreSQL to cancel the running statement instead, keeping
// the session usable for the failure bookkeeping and the lock release.
func migrationConnConfig(dsn string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.BuildContextWatcherHandler = func(conn *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{
			Conn:          conn,
			DeadlineDelay: migrationCancelGracePeriod,
		}
	}
	return cfg, nil
}

// connectAndLockMigrations opens the migration connection and takes the
// migration advisory lock, both bounded by setupTimeout when it is positive.
func connectAndLockMigrations(ctx context.Context, db *sql.DB, setupTimeout time.Duration) (*sql.Conn, error) {
	setupCtx, cancel := ctx, context.CancelFunc(func() {})
	if setupTimeout > 0 {
		setupCtx, cancel = context.WithTimeout(ctx, setupTimeout)
	}
	defer cancel()

	conn, err := db.Conn(setupCtx)
	if err != nil {
		return nil, fmt.Errorf("migrations: connect db: %w", err)
	}
	if err := acquireMigrationLock(setupCtx, conn); err != nil {
		ioutils.CloseSilently(conn)
		return nil, err
	}
	return conn, nil
}

// migrationCleanupContext returns a context for bookkeeping that must run even
// after ctx is cancelled or expired.
func migrationCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), migrationCleanupTimeout)
}

// beginMigrationTx starts a transaction whose statements still honor ctx but
// whose rollback is not tied to it. database/sql rolls a transaction back
// asynchronously when its BeginTx context ends, which could race the failure
// bookkeeping on the same connection; detaching the transaction leaves the
// rollback to the caller's deferred Rollback, which runs first.
func beginMigrationTx(ctx context.Context, db migrationConn) (*sql.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return db.BeginTx(context.WithoutCancel(ctx), nil)
}
