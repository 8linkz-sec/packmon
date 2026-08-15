// Package migrations embeds SQL migration files and provides a helper to run
// them against a PostgreSQL database.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"fmt"
	iofs "io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/8linkz-sec/packmon/internal/ioutils"
	_ "github.com/jackc/pgx/v5/stdlib" // register "pgx" driver
)

//go:embed *.sql
var fs embed.FS

// ExpectedVersion is the schema version that this binary expects.
// It must match the highest migration number embedded in the binary.
const ExpectedVersion = 47

const (
	migrationAdvisoryLockKey int64 = 0x7061636b6d6f6e // ASCII "packmon"
	noTransactionDirective         = "packmon:migration no-transaction"
)

var historicalMigrationChecksums = map[string]map[string]struct{}{
	"010_affected_packages_updated_at.up.sql": {
		"db8f58df8d5022eb21bad847c61bcaf7453c4f96ba1cafe12d719498b0974f30": {},
	},
	"011_sync_keyset_and_lifecycle_tombstones.up.sql": {
		"58a98c9d3ce3813e770acc5739522e76822fa34d7621b13f3d41a788277a8f22": {},
	},
	"021_package_search_trigram_indexes.up.sql": {
		"f5f140894c5bd39ea76bf2a57f0fec96b933f19e3a7eb7c36f7043bab24a38e1": {},
	},
}

type migrationFile struct {
	version   int
	name      string
	direction MigrationDirection
	sql       string
}

// MigrationDirection identifies whether an embedded migration file is an up or
// down migration.
type MigrationDirection string

const (
	// MigrationDirectionUp identifies forward schema migrations.
	MigrationDirectionUp MigrationDirection = "up"
	// MigrationDirectionDown identifies rollback schema migrations.
	MigrationDirectionDown MigrationDirection = "down"
)

// EmbeddedMigration is a read-only view of a SQL migration embedded in the
// binary. Down migrations are exposed for review and verification; they are not
// applied by normal server startup.
type EmbeddedMigration struct {
	Version   int
	Name      string
	Direction MigrationDirection
	SQL       string
}

type migrationConn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// Run applies all pending migrations to the database at the given DSN.
// The DSN must be a valid PostgreSQL connection string
// (e.g. "postgres://user:pass@host:5432/dbname?sslmode=prefer").
//
// Run is safe to call as an explicit migration step: if the database is
// already at the latest version, it returns nil without changes.
func Run(dsn string) (err error) {
	return RunContext(context.Background(), dsn)
}

// RunContext applies all pending migrations with caller-controlled cancellation.
func RunContext(ctx context.Context, dsn string) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("migrations: open db: %w", err)
	}
	defer ioutils.CloseSilently(db)

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrations: connect db: %w", err)
	}
	defer ioutils.CloseSilently(conn)

	if err := acquireMigrationLock(ctx, conn); err != nil {
		return err
	}
	defer func() {
		if unlockErr := releaseMigrationLock(ctx, conn); unlockErr != nil && err == nil {
			err = unlockErr
		}
	}()

	if err := ensureVersionTable(ctx, conn); err != nil {
		return err
	}

	current, dirty, hasVersion, err := currentVersion(ctx, conn)
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("migrations: database is dirty at version %d", current)
	}
	if hasVersion && current > ExpectedVersion {
		return fmt.Errorf("migrations: database schema version %d is newer than binary expected version %d", current, ExpectedVersion)
	}

	migrations, err := embeddedUpMigrations()
	if err != nil {
		return err
	}
	if hasVersion {
		if err := backfillAppliedMigrationMetadata(ctx, conn, migrations, current); err != nil {
			return err
		}
		if err := validateAppliedMigrationMetadata(ctx, conn, migrations, current); err != nil {
			return err
		}
	}
	for _, migration := range migrations {
		if hasVersion && migration.version <= current {
			continue
		}
		if err := applyMigration(ctx, conn, migration); err != nil {
			return err
		}
	}

	return nil
}

// Version returns the current schema version of the database, or an
// error if the version cannot be determined. If dirty is true, the
// database is in a partially-applied migration state and should not
// be used.
func Version(dsn string) (version uint, dirty bool, err error) {
	return VersionContext(context.Background(), dsn)
}

// VersionContext is Version with caller-controlled cancellation.
func VersionContext(ctx context.Context, dsn string) (version uint, dirty bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return 0, false, fmt.Errorf("migrations: open db: %w", err)
	}
	defer ioutils.CloseSilently(db)

	hasTable, err := versionTableExists(ctx, db)
	if err != nil {
		return 0, false, err
	}
	if !hasTable {
		return 0, false, fmt.Errorf("migrations: no schema version found (database has not been migrated)")
	}
	current, dirty, hasVersion, err := currentVersion(ctx, db)
	if err != nil {
		return 0, false, err
	}
	if !hasVersion {
		return 0, false, fmt.Errorf("migrations: no schema version found (database has not been migrated)")
	}
	if current < 0 {
		return 0, dirty, fmt.Errorf("migrations: invalid negative schema version %d", current)
	}

	return uint(current), dirty, nil
}

func ensureVersionTable(ctx context.Context, db migrationConn) error {
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint not null primary key,
			name text,
			checksum text,
			applied_at timestamptz,
			dirty boolean not null
		)`)
	if err != nil {
		return fmt.Errorf("migrations: ensure version table: %w", err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migration_events (
			id bigserial primary key,
			version bigint not null,
			name text not null,
			checksum text,
			started_at timestamptz not null,
			finished_at timestamptz,
			success boolean not null default false,
			dirty boolean not null default true
		)`); err != nil {
		return fmt.Errorf("migrations: ensure migration event table: %w", err)
	}
	for _, index := range []string{
		`CREATE INDEX IF NOT EXISTS idx_schema_migration_events_version ON schema_migration_events(version, id)`,
		`CREATE INDEX IF NOT EXISTS idx_schema_migration_events_started_at ON schema_migration_events(started_at DESC, id DESC)`,
	} {
		if _, err := db.ExecContext(ctx, index); err != nil {
			return fmt.Errorf("migrations: ensure migration event index: %w", err)
		}
	}
	for _, column := range []string{
		`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS name text`,
		`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum text`,
		`ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS applied_at timestamptz`,
	} {
		if _, err := db.ExecContext(ctx, column); err != nil {
			return fmt.Errorf("migrations: extend version table: %w", err)
		}
	}
	return nil
}

func acquireMigrationLock(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey); err != nil {
		return fmt.Errorf("migrations: acquire advisory lock: %w", err)
	}
	return nil
}

func releaseMigrationLock(ctx context.Context, conn *sql.Conn) error {
	var unlocked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey).Scan(&unlocked); err != nil {
		return fmt.Errorf("migrations: release advisory lock: %w", err)
	}
	if !unlocked {
		return fmt.Errorf("migrations: release advisory lock: lock was not held")
	}
	return nil
}

func versionTableExists(ctx context.Context, db *sql.DB) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("migrations: check version table: %w", err)
	}
	return exists, nil
}

func currentVersion(ctx context.Context, db migrationConn) (version int, dirty, ok bool, err error) {
	err = db.QueryRowContext(ctx, `
		SELECT version, dirty
		FROM schema_migrations
		ORDER BY version DESC
		LIMIT 1`).Scan(&version, &dirty)
	if err == sql.ErrNoRows {
		return 0, false, false, nil
	}
	if err != nil {
		return 0, false, false, fmt.Errorf("migrations: read version: %w", err)
	}
	return version, dirty, true, nil
}

// EmbeddedMigrations returns embedded migrations for the requested direction in
// their safe application order: up migrations from oldest to newest, and down
// migrations from newest to oldest.
func EmbeddedMigrations(direction MigrationDirection) ([]EmbeddedMigration, error) {
	migrations, err := embeddedMigrationFiles(direction)
	if err != nil {
		return nil, err
	}
	out := make([]EmbeddedMigration, 0, len(migrations))
	for _, migration := range migrations {
		out = append(out, EmbeddedMigration{
			Version:   migration.version,
			Name:      migration.name,
			Direction: migration.direction,
			SQL:       migration.sql,
		})
	}
	return out, nil
}

// ReadEmbeddedMigration returns one embedded migration by schema version and
// direction.
func ReadEmbeddedMigration(version int, direction MigrationDirection) (EmbeddedMigration, error) {
	if version <= 0 {
		return EmbeddedMigration{}, fmt.Errorf("migrations: invalid migration version %d", version)
	}
	migrations, err := EmbeddedMigrations(direction)
	if err != nil {
		return EmbeddedMigration{}, err
	}
	for _, migration := range migrations {
		if migration.Version == version {
			return migration, nil
		}
	}
	return EmbeddedMigration{}, fmt.Errorf("migrations: %s migration %03d not found", direction, version)
}

func embeddedUpMigrations() ([]migrationFile, error) {
	return embeddedMigrationFiles(MigrationDirectionUp)
}

func embeddedMigrationFiles(direction MigrationDirection) ([]migrationFile, error) {
	suffix, err := migrationDirectionSuffix(direction)
	if err != nil {
		return nil, err
	}
	entries, err := iofs.ReadDir(fs, ".")
	if err != nil {
		return nil, fmt.Errorf("migrations: read embedded migrations: %w", err)
	}

	migrations := make([]migrationFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		version, err := parseMigrationVersion(name)
		if err != nil {
			return nil, err
		}
		data, err := fs.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("migrations: read %s: %w", name, err)
		}
		migrations = append(migrations, migrationFile{
			version:   version,
			name:      name,
			direction: direction,
			sql:       string(data),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		if direction == MigrationDirectionDown {
			return migrations[i].version > migrations[j].version
		}
		return migrations[i].version < migrations[j].version
	})
	return migrations, nil
}

func migrationDirectionSuffix(direction MigrationDirection) (string, error) {
	switch direction {
	case MigrationDirectionUp, MigrationDirectionDown:
		return "." + string(direction) + ".sql", nil
	default:
		return "", fmt.Errorf("migrations: invalid migration direction %q", direction)
	}
}

func parseMigrationVersion(name string) (int, error) {
	base := filepath.Base(name)
	if len(base) < 3 {
		return 0, fmt.Errorf("migrations: migration filename %q is too short", base)
	}
	version, err := strconv.Atoi(base[:3])
	if err != nil {
		return 0, fmt.Errorf("migrations: migration filename %q does not start with a numeric version: %w", base, err)
	}
	return version, nil
}

func migrationChecksum(migrationSQL string) string {
	sum := sha256.Sum256([]byte(migrationSQL))
	return fmt.Sprintf("%x", sum)
}

func migrationChecksumMatches(migration migrationFile, checksum string) bool {
	if checksum == migrationChecksum(migration.sql) {
		return true
	}
	historicalChecksums := historicalMigrationChecksums[migration.name]
	_, ok := historicalChecksums[checksum]
	return ok
}

func backfillAppliedMigrationMetadata(ctx context.Context, db migrationConn, migrations []migrationFile, current int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations: backfill migration metadata: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, migration := range migrations {
		if migration.version > current {
			break
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO schema_migrations(version, name, checksum, dirty, applied_at)
			VALUES($1, $2, $3, false, now())
			ON CONFLICT (version) DO UPDATE
			SET name = COALESCE(schema_migrations.name, EXCLUDED.name),
				checksum = COALESCE(schema_migrations.checksum, EXCLUDED.checksum),
				applied_at = COALESCE(schema_migrations.applied_at, EXCLUDED.applied_at)
			WHERE schema_migrations.name IS NULL
				OR schema_migrations.checksum IS NULL
				OR schema_migrations.applied_at IS NULL`,
			migration.version, migration.name, migrationChecksum(migration.sql)); err != nil {
			return fmt.Errorf("migrations: backfill metadata for %s: %w", migration.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrations: backfill migration metadata: %w", err)
	}
	return nil
}

func validateAppliedMigrationMetadata(ctx context.Context, db migrationConn, migrations []migrationFile, current int) error {
	for _, migration := range migrations {
		if migration.version > current {
			break
		}

		var name sql.NullString
		var checksum sql.NullString
		var dirty bool
		err := db.QueryRowContext(ctx, `
			SELECT name, checksum, dirty
			FROM schema_migrations
			WHERE version = $1`, migration.version).Scan(&name, &checksum, &dirty)
		if err == sql.ErrNoRows {
			return fmt.Errorf("migrations: missing metadata for applied migration %s", migration.name)
		}
		if err != nil {
			return fmt.Errorf("migrations: read metadata for %s: %w", migration.name, err)
		}
		if dirty {
			return fmt.Errorf("migrations: database is dirty at version %d", migration.version)
		}
		if !name.Valid || strings.TrimSpace(name.String) == "" {
			return fmt.Errorf("migrations: missing name for applied migration version %03d", migration.version)
		}
		if name.String != migration.name {
			return fmt.Errorf("migrations: migration version %03d name mismatch: database has %q, binary has %q", migration.version, name.String, migration.name)
		}
		if !checksum.Valid || strings.TrimSpace(checksum.String) == "" {
			return fmt.Errorf("migrations: missing checksum for applied migration %s", migration.name)
		}
		if !migrationChecksumMatches(migration, checksum.String) {
			return fmt.Errorf("migrations: migration %s checksum mismatch", migration.name)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db migrationConn, migration migrationFile) (err error) {
	eventID, err := startMigrationEventAndMarkDirty(ctx, db, migration)
	if err != nil {
		return err
	}
	migrationDirty := true
	migrationSucceeded := false
	defer func() {
		if migrationSucceeded {
			return
		}
		if finishErr := finishMigrationEvent(ctx, db, eventID, false, migrationDirty); finishErr != nil && err == nil {
			err = finishErr
		}
	}()

	if !migrationRunsInTransaction(migration) {
		if err := applyMigrationWithoutTransaction(ctx, db, migration); err != nil {
			return err
		}
		if err := finishSuccessfulMigrationEvent(ctx, db, eventID, migration); err != nil {
			return err
		}
		migrationDirty = false
		migrationSucceeded = true
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations: begin %s: %w", migration.name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, migration.sql); err != nil {
		return fmt.Errorf("migrations: apply %s: %w", migration.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrations: commit %s: %w", migration.name, err)
	}
	if err := finishSuccessfulMigrationEvent(ctx, db, eventID, migration); err != nil {
		return err
	}
	migrationDirty = false
	migrationSucceeded = true
	return nil
}

func startMigrationEventAndMarkDirty(ctx context.Context, db migrationConn, migration migrationFile) (int64, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("migrations: start %s: %w", migration.name, err)
	}
	defer func() { _ = tx.Rollback() }()

	var eventID int64
	checksum := migrationChecksum(migration.sql)
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO schema_migration_events(version, name, checksum, started_at, success, dirty)
		VALUES($1, $2, $3, now(), false, true)
		RETURNING id`, migration.version, migration.name, checksum).Scan(&eventID); err != nil {
		return 0, fmt.Errorf("migrations: record start event for %s: %w", migration.name, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO schema_migrations(version, name, checksum, dirty, applied_at)
		VALUES($1, $2, $3, true, NULL)
		ON CONFLICT (version) DO UPDATE
		SET name = EXCLUDED.name,
			checksum = EXCLUDED.checksum,
			dirty = true,
			applied_at = NULL`, migration.version, migration.name, checksum); err != nil {
		return 0, fmt.Errorf("migrations: mark %s dirty: %w", migration.name, err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("migrations: start %s: %w", migration.name, err)
	}
	return eventID, nil
}

func finishSuccessfulMigrationEvent(ctx context.Context, db migrationConn, eventID int64, migration migrationFile) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations: mark %s clean: %w", migration.name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		UPDATE schema_migrations
		SET name = $2,
			checksum = $3,
			dirty = false,
			applied_at = now()
		WHERE version = $1`, migration.version, migration.name, migrationChecksum(migration.sql)); err != nil {
		return fmt.Errorf("migrations: mark %s clean: %w", migration.name, err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE schema_migration_events
		SET finished_at = now(),
			success = true,
			dirty = false
		WHERE id = $1`, eventID); err != nil {
		return fmt.Errorf("migrations: record finish event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrations: mark %s clean: %w", migration.name, err)
	}
	return nil
}

func finishMigrationEvent(ctx context.Context, db migrationConn, eventID int64, success, dirty bool) error {
	if _, err := db.ExecContext(ctx, `
		UPDATE schema_migration_events
		SET finished_at = now(),
			success = $2,
			dirty = $3
		WHERE id = $1`, eventID, success, dirty); err != nil {
		return fmt.Errorf("migrations: record finish event: %w", err)
	}
	return nil
}

func migrationRunsInTransaction(migration migrationFile) bool {
	return !strings.Contains(migration.sql, noTransactionDirective)
}

func applyMigrationWithoutTransaction(ctx context.Context, db sqlExecutor, migration migrationFile) error {
	statements, err := splitSQLStatements(migration.sql)
	if err != nil {
		return fmt.Errorf("migrations: parse %s: %w", migration.name, err)
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrations: apply %s: %w", migration.name, err)
		}
	}
	return nil
}

func splitSQLStatements(migrationSQL string) ([]string, error) {
	const (
		stateNormal = iota
		stateSingleQuote
		stateDoubleQuote
		stateLineComment
		stateBlockComment
		stateDollarQuote
	)

	var statements []string
	var statement strings.Builder
	state := stateNormal
	dollarTag := ""

	for i := 0; i < len(migrationSQL); i++ {
		ch := migrationSQL[i]

		switch state {
		case stateNormal:
			switch {
			case ch == '\'':
				state = stateSingleQuote
				statement.WriteByte(ch)
			case ch == '"':
				state = stateDoubleQuote
				statement.WriteByte(ch)
			case ch == '-' && i+1 < len(migrationSQL) && migrationSQL[i+1] == '-':
				state = stateLineComment
				statement.WriteString("--")
				i++
			case ch == '/' && i+1 < len(migrationSQL) && migrationSQL[i+1] == '*':
				state = stateBlockComment
				statement.WriteString("/*")
				i++
			case ch == '$':
				tag, ok := readDollarQuoteTag(migrationSQL[i:])
				if ok {
					state = stateDollarQuote
					dollarTag = tag
					statement.WriteString(tag)
					i += len(tag) - 1
				} else {
					statement.WriteByte(ch)
				}
			case ch == ';':
				trimmed := strings.TrimSpace(statement.String())
				if trimmed != "" {
					statements = append(statements, trimmed)
				}
				statement.Reset()
			default:
				statement.WriteByte(ch)
			}
		case stateSingleQuote:
			statement.WriteByte(ch)
			if ch == '\'' {
				if i+1 < len(migrationSQL) && migrationSQL[i+1] == '\'' {
					statement.WriteByte(migrationSQL[i+1])
					i++
					continue
				}
				state = stateNormal
			}
		case stateDoubleQuote:
			statement.WriteByte(ch)
			if ch == '"' {
				if i+1 < len(migrationSQL) && migrationSQL[i+1] == '"' {
					statement.WriteByte(migrationSQL[i+1])
					i++
					continue
				}
				state = stateNormal
			}
		case stateLineComment:
			statement.WriteByte(ch)
			if ch == '\n' {
				state = stateNormal
			}
		case stateBlockComment:
			statement.WriteByte(ch)
			if ch == '*' && i+1 < len(migrationSQL) && migrationSQL[i+1] == '/' {
				statement.WriteByte('/')
				i++
				state = stateNormal
			}
		case stateDollarQuote:
			if strings.HasPrefix(migrationSQL[i:], dollarTag) {
				statement.WriteString(dollarTag)
				i += len(dollarTag) - 1
				state = stateNormal
				dollarTag = ""
				continue
			}
			statement.WriteByte(ch)
		}
	}

	if state == stateSingleQuote || state == stateDoubleQuote || state == stateBlockComment || state == stateDollarQuote {
		return nil, fmt.Errorf("unterminated SQL statement")
	}
	trimmed := strings.TrimSpace(statement.String())
	if trimmed != "" {
		statements = append(statements, trimmed)
	}
	return statements, nil
}

func readDollarQuoteTag(input string) (string, bool) {
	if input == "" || input[0] != '$' {
		return "", false
	}
	for i := 1; i < len(input); i++ {
		ch := input[i]
		if ch == '$' {
			return input[:i+1], true
		}
		if !isDollarQuoteTagChar(ch) {
			return "", false
		}
	}
	return "", false
}

func isDollarQuoteTagChar(ch byte) bool {
	return ch == '_' ||
		(ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9')
}

// markDirty and markDirtyWithChecksum seed a dirty schema_migrations row.
// Production marks dirty through startMigrationEventAndMarkDirty; these exist so
// the Docker-backed migration tests can construct a dirty database directly.
// The `unused` linter does not see build-tagged files, so without this reference
// it reports both as dead in an untagged build -- and a //nolint:unused directive
// would in turn be flagged as redundant once the tagged build is linted.
var _ = markDirty

func markDirty(ctx context.Context, db migrationConn, version int, name string) error {
	return markDirtyWithChecksum(ctx, db, version, name, "")
}

func markDirtyWithChecksum(ctx context.Context, db migrationConn, version int, name, checksum string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations: mark %s dirty: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()

	var checksumValue any
	if checksum != "" {
		checksumValue = checksum
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO schema_migrations(version, name, checksum, dirty, applied_at)
		VALUES($1, $2, $3, true, NULL)
		ON CONFLICT (version) DO UPDATE
		SET name = EXCLUDED.name,
			checksum = EXCLUDED.checksum,
			dirty = true,
			applied_at = NULL`, version, name, checksumValue); err != nil {
		return fmt.Errorf("migrations: mark %s dirty: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrations: mark %s dirty: %w", name, err)
	}
	return nil
}
