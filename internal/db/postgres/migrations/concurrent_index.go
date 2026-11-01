package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// An interrupted CREATE INDEX CONCURRENTLY (connection drop, cancel, crash)
// leaves an INVALID index behind: PostgreSQL keeps maintaining it on writes but
// never uses it for reads. IF NOT EXISTS then skips the build on a retry, so the
// migrator guards every concurrent index build of a no-transaction migration:
// it drops an INVALID index of the same name before the build, checks that the
// build left a valid index, and on every migrate run rebuilds INVALID and
// recreates missing indexes of migrations that are already applied.

// indexState is the catalog state of a named index.
type indexState int

const (
	indexMissing indexState = iota
	indexValid
	indexInvalid
)

func (s indexState) String() string {
	switch s {
	case indexMissing:
		return "missing or not an index"
	case indexValid:
		return "valid"
	case indexInvalid:
		return "INVALID"
	default:
		return "unknown"
	}
}

// noTransactionConn runs the statements of a no-transaction migration and
// reads the catalog state of the indexes they build concurrently and of the
// tables they build them on.
type noTransactionConn interface {
	sqlExecutor
	indexState(ctx context.Context, name string) (indexState, error)
	tableExists(ctx context.Context, name string) (bool, error)
}

type rowQueryExecutor interface {
	sqlExecutor
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// catalogStatementConn adapts a database connection to noTransactionConn by
// reading index validity from pg_index.
type catalogStatementConn struct {
	db rowQueryExecutor
}

func (c catalogStatementConn) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.db.ExecContext(ctx, query, args...)
}

func (c catalogStatementConn) indexState(ctx context.Context, name string) (indexState, error) {
	var valid sql.NullBool
	if err := c.db.QueryRowContext(ctx, `
		SELECT (
			SELECT i.indisvalid
			FROM pg_index i
			WHERE i.indexrelid = to_regclass($1::text)
		)`, quoteIdentifier(name)).Scan(&valid); err != nil {
		return indexMissing, err
	}
	switch {
	case !valid.Valid:
		return indexMissing, nil
	case valid.Bool:
		return indexValid, nil
	default:
		return indexInvalid, nil
	}
}

func (c catalogStatementConn) tableExists(ctx context.Context, name string) (bool, error) {
	var exists bool
	if err := c.db.QueryRowContext(ctx, `SELECT to_regclass($1::text) IS NOT NULL`, quoteIdentifier(name)).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// concurrentIndexBuild is a CREATE INDEX CONCURRENTLY statement with plain,
// unqualified index and table names (folded to lower case as PostgreSQL does).
type concurrentIndexBuild struct {
	name        string
	table       string
	ifNotExists bool
}

var concurrentIndexBuildPattern = regexp.MustCompile(`(?is)^CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+(IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)\s+ON\s+(?:ONLY\s+)?([a-z_][a-z0-9_]*)\s*(?:\(|\s|$)`)

// parseConcurrentIndexBuild recognizes a concurrent index build after any
// leading comments. Unnamed builds and quoted or schema-qualified index or
// table names are not recognized; TestEmbeddedConcurrentIndexBuildsAreRecognized
// keeps shipped migrations within that shape.
func parseConcurrentIndexBuild(statement string) (concurrentIndexBuild, bool) {
	body, ok := stripLeadingSQLComments(statement)
	if !ok {
		return concurrentIndexBuild{}, false
	}
	match := concurrentIndexBuildPattern.FindStringSubmatch(body)
	if match == nil {
		return concurrentIndexBuild{}, false
	}
	return concurrentIndexBuild{
		name:        strings.ToLower(match[2]),
		table:       strings.ToLower(match[3]),
		ifNotExists: match[1] != "",
	}, true
}

// stripLeadingSQLComments returns statement without its leading line and block
// comments. ok is false for an unterminated block comment.
func stripLeadingSQLComments(statement string) (body string, ok bool) {
	body = strings.TrimSpace(statement)
	for {
		switch {
		case strings.HasPrefix(body, "--"):
			end := strings.IndexByte(body, '\n')
			if end < 0 {
				return "", true
			}
			body = strings.TrimSpace(body[end+1:])
		case strings.HasPrefix(body, "/*"):
			end := strings.Index(body[2:], "*/")
			if end < 0 {
				return "", false
			}
			body = strings.TrimSpace(body[2+end+2:])
		default:
			return body, true
		}
	}
}

// quoteIdentifier quotes a name accepted by parseConcurrentIndexBuild,
// which only contains lower-case letters, digits, and underscores.
func quoteIdentifier(name string) string {
	return `"` + name + `"`
}

// applyNoTransactionStatement runs one statement of a no-transaction migration.
// A concurrent index build first replaces an INVALID index of the same name and
// must leave a valid index behind.
func applyNoTransactionStatement(ctx context.Context, db noTransactionConn, migration migrationFile, statement string) error {
	build, isBuild := parseConcurrentIndexBuild(statement)
	if isBuild {
		if err := dropInvalidIndex(ctx, db, build.name); err != nil {
			return fmt.Errorf("migrations: apply %s: %w", migration.name, err)
		}
	}
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("migrations: apply %s: %w", migration.name, err)
	}
	if isBuild {
		if err := requireValidIndex(ctx, db, build.name); err != nil {
			return fmt.Errorf("migrations: apply %s: %w", migration.name, err)
		}
	}
	return nil
}

func dropInvalidIndex(ctx context.Context, db noTransactionConn, name string) error {
	state, err := db.indexState(ctx, name)
	if err != nil {
		return fmt.Errorf("read state of index %s: %w", name, err)
	}
	if state != indexInvalid {
		return nil
	}
	drop := `DROP INDEX CONCURRENTLY IF EXISTS ` + quoteIdentifier(name) // #nosec G202 -- name comes from an embedded migration and is restricted to [a-z0-9_] by parseConcurrentIndexBuild.
	if _, err := db.ExecContext(ctx, drop); err != nil {
		return fmt.Errorf("drop INVALID index %s: %w", name, err)
	}
	return nil
}

func requireValidIndex(ctx context.Context, db noTransactionConn, name string) error {
	state, err := db.indexState(ctx, name)
	if err != nil {
		return fmt.Errorf("read state of index %s: %w", name, err)
	}
	if state != indexValid {
		return fmt.Errorf("index %s is %s after its concurrent build, want a valid index", name, state)
	}
	return nil
}

// repairInvalidConcurrentIndexes rebuilds, concurrently and outside a
// transaction, every INVALID or missing index that an already applied
// no-transaction migration builds concurrently. Only the index build itself is
// rerun, never the migration's other statements; valid indexes are left alone.
// A missing index is never intended at an applied version: the down migration
// that drops one also lowers the schema version. Recreating it also covers a
// rebuild interrupted between its drop and its build. A missing index whose
// table is missing too is left alone: that is schema loss no index build can
// repair, not a lost index.
func repairInvalidConcurrentIndexes(ctx context.Context, db noTransactionConn, migrations []migrationFile, current int) error {
	for _, migration := range migrations {
		if migration.version > current {
			break
		}
		if migrationRunsInTransaction(migration) {
			continue
		}
		statements, err := splitSQLStatements(migration.sql)
		if err != nil {
			return fmt.Errorf("migrations: parse %s: %w", migration.name, err)
		}
		for _, statement := range statements {
			build, ok := parseConcurrentIndexBuild(statement)
			if !ok {
				continue
			}
			state, err := db.indexState(ctx, build.name)
			if err != nil {
				return fmt.Errorf("migrations: read state of index %s from %s: %w", build.name, migration.name, err)
			}
			switch state {
			case indexInvalid:
				if err := rebuildInvalidIndex(ctx, db, build.name, statement); err != nil {
					return fmt.Errorf("migrations: rebuild INVALID index %s from %s: %w; rerun packmon-server migrate to retry the rebuild", build.name, migration.name, err)
				}
			case indexMissing:
				exists, err := db.tableExists(ctx, build.table)
				if err != nil {
					return fmt.Errorf("migrations: read state of table %s for index %s from %s: %w", build.table, build.name, migration.name, err)
				}
				if !exists {
					continue
				}
				if err := buildIndex(ctx, db, build.name, statement); err != nil {
					return fmt.Errorf("migrations: recreate missing index %s from %s: %w; rerun packmon-server migrate to retry the build", build.name, migration.name, err)
				}
			}
		}
	}
	return nil
}

func rebuildInvalidIndex(ctx context.Context, db noTransactionConn, name, statement string) error {
	drop := `DROP INDEX CONCURRENTLY IF EXISTS ` + quoteIdentifier(name) // #nosec G202 -- name comes from an embedded migration and is restricted to [a-z0-9_] by parseConcurrentIndexBuild.
	if _, err := db.ExecContext(ctx, drop); err != nil {
		return fmt.Errorf("drop: %w", err)
	}
	return buildIndex(ctx, db, name, statement)
}

// buildIndex runs a migration's own concurrent index build, which is safe while
// the name is free, and requires a valid index afterwards.
func buildIndex(ctx context.Context, db noTransactionConn, name, statement string) error {
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("build: %w", err)
	}
	return requireValidIndex(ctx, db, name)
}

// migrationIsRetrySafeIndexBuild reports whether a no-transaction migration only
// builds indexes concurrently with IF NOT EXISTS. Rerunning such a migration
// after an interruption is safe: finished builds are skipped and the guard in
// applyNoTransactionStatement replaces an INVALID index.
func migrationIsRetrySafeIndexBuild(migration migrationFile) bool {
	if migrationRunsInTransaction(migration) {
		return false
	}
	statements, err := splitSQLStatements(migration.sql)
	if err != nil {
		return false
	}
	builds := 0
	for _, statement := range statements {
		body, ok := stripLeadingSQLComments(statement)
		if !ok {
			return false
		}
		if body == "" {
			continue
		}
		build, ok := parseConcurrentIndexBuild(statement)
		if !ok || !build.ifNotExists {
			return false
		}
		builds++
	}
	return builds > 0
}

// dirtyDatabaseError refuses a dirty database. For a migration that only builds
// indexes concurrently it names the retry path instead of a backup restore.
func dirtyDatabaseError(version int, migrations []migrationFile) error {
	for _, migration := range migrations {
		if migration.version != version || !migrationIsRetrySafeIndexBuild(migration) {
			continue
		}
		return fmt.Errorf("migrations: database is dirty at version %d; %s only builds indexes concurrently and is safe to retry: "+
			"after confirming no other migrate run is active, clear the marker with DELETE FROM schema_migrations WHERE version = %d AND dirty "+
			"and rerun packmon-server migrate, which replaces any INVALID index the interrupted run left behind", version, migration.name, version)
	}
	return fmt.Errorf("migrations: database is dirty at version %d", version)
}
