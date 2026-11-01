package migrations

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// scriptedIndexConn records executed statements and answers index-state
// lookups from a per-index script; the last scripted state repeats.
type scriptedIndexConn struct {
	statements []string
	states     map[string][]indexState
	lookups    []string
	lookupErr  error
	execErr    map[string]error
	// failOnce fails the first statement containing the key, then is consumed.
	failOnce      map[string]error
	missingTables map[string]bool
	tableLookups  []string
}

func (c *scriptedIndexConn) tableExists(_ context.Context, name string) (bool, error) {
	c.tableLookups = append(c.tableLookups, name)
	return !c.missingTables[name], nil
}

func (c *scriptedIndexConn) ExecContext(_ context.Context, query string, _ ...any) (sql.Result, error) {
	query = strings.TrimSpace(query)
	c.statements = append(c.statements, query)
	for fragment, err := range c.failOnce {
		if strings.Contains(query, fragment) {
			delete(c.failOnce, fragment)
			return nil, err
		}
	}
	for fragment, err := range c.execErr {
		if strings.Contains(query, fragment) {
			return nil, err
		}
	}
	return nil, nil
}

func (c *scriptedIndexConn) indexState(_ context.Context, name string) (indexState, error) {
	c.lookups = append(c.lookups, name)
	if c.lookupErr != nil {
		return indexMissing, c.lookupErr
	}
	script := c.states[name]
	if len(script) == 0 {
		return indexMissing, nil
	}
	state := script[0]
	if len(script) > 1 {
		c.states[name] = script[1:]
	}
	return state, nil
}

func TestParseConcurrentIndexBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		statement string
		want      concurrentIndexBuild
		wantOK    bool
	}{
		{
			name:      "if not exists",
			statement: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x)",
			want:      concurrentIndexBuild{name: "idx_a", table: "t", ifNotExists: true},
			wantOK:    true,
		},
		{
			name:      "leading directive and line comments",
			statement: "-- packmon:migration no-transaction\n-- another note\nCREATE INDEX CONCURRENTLY IF NOT EXISTS idx_b\n    ON t (x)\n    WHERE y IS NULL",
			want:      concurrentIndexBuild{name: "idx_b", table: "t", ifNotExists: true},
			wantOK:    true,
		},
		{
			name:      "leading block comment",
			statement: "/* note; with text */ create index concurrently if not exists idx_c on t using gin (x)",
			want:      concurrentIndexBuild{name: "idx_c", table: "t", ifNotExists: true},
			wantOK:    true,
		},
		{
			name:      "unique without if not exists folds case",
			statement: "CREATE UNIQUE INDEX CONCURRENTLY Idx_D ON Some_Table(x)",
			want:      concurrentIndexBuild{name: "idx_d", table: "some_table"},
			wantOK:    true,
		},
		{
			name:      "only table",
			statement: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_j ON ONLY t (x)",
			want:      concurrentIndexBuild{name: "idx_j", table: "t", ifNotExists: true},
			wantOK:    true,
		},
		{name: "schema qualified table", statement: "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_k ON public.t(x)"},
		{name: "quoted table", statement: `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_l ON "T"(x)`},
		{name: "non concurrent index", statement: "CREATE INDEX IF NOT EXISTS idx_e ON t(x)"},
		{name: "drop index", statement: "DROP INDEX CONCURRENTLY IF EXISTS idx_f"},
		{name: "unnamed index", statement: "CREATE INDEX CONCURRENTLY ON t(x)"},
		{name: "schema qualified name", statement: "CREATE INDEX CONCURRENTLY IF NOT EXISTS public.idx_g ON t(x)"},
		{name: "quoted name", statement: `CREATE INDEX CONCURRENTLY IF NOT EXISTS "Idx_H" ON t(x)`},
		{name: "other statement", statement: "ALTER TABLE t ADD COLUMN x int"},
		{name: "unterminated block comment", statement: "/* CREATE INDEX CONCURRENTLY idx_i ON t(x)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseConcurrentIndexBuild(tt.statement)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("parseConcurrentIndexBuild(%q) = %+v, %v; want %+v, %v", tt.statement, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestEmbeddedConcurrentIndexBuildsAreRecognized keeps every shipped
// concurrent index build under the invalid-index guard: a statement the parser
// cannot name would silently skip the drop-and-verify handling.
func TestEmbeddedConcurrentIndexBuildsAreRecognized(t *testing.T) {
	t.Parallel()

	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations() error = %v", err)
	}
	concurrentCreate := regexp.MustCompile(`(?is)^CREATE\b.*\bCONCURRENTLY\b`)
	seen := map[string]bool{}
	for _, migration := range migrations {
		statements, err := splitSQLStatements(migration.sql)
		if err != nil {
			t.Fatalf("split %s: %v", migration.name, err)
		}
		for _, statement := range statements {
			body, ok := stripLeadingSQLComments(statement)
			if !ok || !concurrentCreate.MatchString(body) {
				continue
			}
			if migrationRunsInTransaction(migration) {
				t.Fatalf("%s builds an index concurrently inside a transaction: %q", migration.name, body)
			}
			build, ok := parseConcurrentIndexBuild(statement)
			if !ok {
				t.Fatalf("%s: concurrent index build is not recognized by the invalid-index guard: %q", migration.name, body)
			}
			if seen[build.name] {
				t.Fatalf("%s: concurrent index %s is built by more than one migration", migration.name, build.name)
			}
			seen[build.name] = true
		}
	}
	for _, name := range []string{
		"idx_affected_packages_updated_at",
		"idx_malicious_findings_name_trgm",
		"idx_malicious_active_search_order",
		"idx_malicious_active_severity_search",
	} {
		if !seen[name] {
			t.Fatalf("concurrent index %s not found among embedded migrations; seen %v", name, seen)
		}
	}
}

func TestApplyMigrationWithoutTransactionReplacesInvalidIndexBeforeBuild(t *testing.T) {
	t.Parallel()

	conn := &scriptedIndexConn{states: map[string][]indexState{
		"idx_a": {indexInvalid, indexValid},
		"idx_b": {indexValid},
	}}
	migration := migrationFile{
		name: "077_indexes.up.sql",
		sql: `-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_b ON t(y);`,
	}

	if err := applyMigrationWithoutTransaction(context.Background(), conn, migration); err != nil {
		t.Fatalf("applyMigrationWithoutTransaction() error = %v", err)
	}
	want := []string{
		`DROP INDEX CONCURRENTLY IF EXISTS "idx_a"`,
		"-- packmon:migration no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_b ON t(y)",
	}
	assertStatements(t, conn.statements, want)
	if got := strings.Join(conn.lookups, ","); got != "idx_a,idx_a,idx_b,idx_b" {
		t.Fatalf("index lookups = %s, want a pre-build and a post-build lookup per index", got)
	}
}

func TestApplyMigrationWithoutTransactionRejectsIndexNotValidAfterBuild(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		after indexState
		want  string
	}{
		{name: "invalid", after: indexInvalid, want: "INVALID"},
		{name: "missing", after: indexMissing, want: "missing"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conn := &scriptedIndexConn{states: map[string][]indexState{
				"idx_a": {indexMissing, tc.after},
			}}
			migration := migrationFile{
				name: "077_indexes.up.sql",
				sql: `-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_b ON t(y);`,
			}

			err := applyMigrationWithoutTransaction(context.Background(), conn, migration)
			if err == nil {
				t.Fatal("applyMigrationWithoutTransaction() error = nil, want index validity error")
			}
			for _, part := range []string{"apply 077_indexes.up.sql", "index idx_a", tc.want} {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("applyMigrationWithoutTransaction() error = %v, want %q", err, part)
				}
			}
			if len(conn.statements) != 1 {
				t.Fatalf("executed %d statements after the failed check, want only the first build: %#v", len(conn.statements), conn.statements)
			}
		})
	}
}

func TestApplyMigrationWithoutTransactionPropagatesIndexLookupErrors(t *testing.T) {
	t.Parallel()

	conn := &scriptedIndexConn{lookupErr: errors.New("catalog unavailable")}
	migration := migrationFile{
		name: "077_indexes.up.sql",
		sql:  "-- packmon:migration no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x);",
	}
	err := applyMigrationWithoutTransaction(context.Background(), conn, migration)
	if err == nil || !strings.Contains(err.Error(), "catalog unavailable") || !strings.Contains(err.Error(), "idx_a") {
		t.Fatalf("applyMigrationWithoutTransaction() error = %v, want wrapped lookup error naming idx_a", err)
	}
	if len(conn.statements) != 0 {
		t.Fatalf("executed statements after a failed lookup: %#v", conn.statements)
	}
}

func TestApplyMigrationWithoutTransactionStopsWhenInvalidIndexDropFails(t *testing.T) {
	t.Parallel()

	conn := &scriptedIndexConn{
		states:  map[string][]indexState{"idx_a": {indexInvalid}},
		execErr: map[string]error{"DROP INDEX": errors.New("lock timeout")},
	}
	migration := migrationFile{
		name: "077_indexes.up.sql",
		sql:  "-- packmon:migration no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x);",
	}
	err := applyMigrationWithoutTransaction(context.Background(), conn, migration)
	if err == nil || !strings.Contains(err.Error(), "drop INVALID index idx_a") || !strings.Contains(err.Error(), "lock timeout") {
		t.Fatalf("applyMigrationWithoutTransaction() error = %v, want drop failure", err)
	}
	assertStatements(t, conn.statements, []string{`DROP INDEX CONCURRENTLY IF EXISTS "idx_a"`})
}

func TestRepairInvalidConcurrentIndexesRebuildsInvalidAndMissingAppliedIndexes(t *testing.T) {
	t.Parallel()

	migrations := []migrationFile{
		{version: 1, name: "001_mixed.up.sql", sql: `-- packmon:migration no-transaction
ALTER TABLE t ADD COLUMN x int;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_b ON t(y);
CREATE INDEX CONCURRENTLY idx_e ON t(v);`},
		{version: 2, name: "002_transactional.up.sql", sql: `CREATE INDEX IF NOT EXISTS idx_c ON t(z);`},
		{version: 3, name: "003_pending.up.sql", sql: `-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_d ON t(w);`},
	}
	conn := &scriptedIndexConn{states: map[string][]indexState{
		"idx_a": {indexValid},
		"idx_b": {indexInvalid, indexValid},
		"idx_c": {indexInvalid},
		"idx_d": {indexInvalid},
		"idx_e": {indexMissing, indexValid},
	}}

	if err := repairInvalidConcurrentIndexes(context.Background(), conn, migrations, 2); err != nil {
		t.Fatalf("repairInvalidConcurrentIndexes() error = %v", err)
	}
	assertStatements(t, conn.statements, []string{
		`DROP INDEX CONCURRENTLY IF EXISTS "idx_b"`,
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_b ON t(y)",
		"CREATE INDEX CONCURRENTLY idx_e ON t(v)",
	})
	if got := strings.Join(conn.lookups, ","); got != "idx_a,idx_b,idx_b,idx_e,idx_e" {
		t.Fatalf("index lookups = %s, want only applied concurrent indexes", got)
	}
	if got := strings.Join(conn.tableLookups, ","); got != "t" {
		t.Fatalf("table lookups = %s, want only the missing index's table", got)
	}
}

// TestRepairInvalidConcurrentIndexesSkipsMissingIndexOfMissingTable keeps the
// repair to lost indexes: without the table no index build can help, so the
// migrator neither builds nor fails on it.
func TestRepairInvalidConcurrentIndexesSkipsMissingIndexOfMissingTable(t *testing.T) {
	t.Parallel()

	migrations := []migrationFile{
		{version: 1, name: "001_index.up.sql", sql: `-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON gone(x);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_b ON t(y);`},
	}
	conn := &scriptedIndexConn{
		states:        map[string][]indexState{"idx_a": {indexMissing}, "idx_b": {indexMissing, indexValid}},
		missingTables: map[string]bool{"gone": true},
	}
	if err := repairInvalidConcurrentIndexes(context.Background(), conn, migrations, 1); err != nil {
		t.Fatalf("repairInvalidConcurrentIndexes() error = %v", err)
	}
	assertStatements(t, conn.statements, []string{"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_b ON t(y)"})
	if got := strings.Join(conn.tableLookups, ","); got != "gone,t" {
		t.Fatalf("table lookups = %s, want gone,t", got)
	}
}

// TestRepairInvalidConcurrentIndexesRecreatesIndexLostByInterruptedRebuild
// covers a rebuild whose drop committed but whose build failed before its
// catalog entry: the index is then missing, and the next migrate run must build
// it instead of leaving it lost.
func TestRepairInvalidConcurrentIndexesRecreatesIndexLostByInterruptedRebuild(t *testing.T) {
	t.Parallel()

	migrations := []migrationFile{
		{version: 1, name: "001_index.up.sql", sql: `-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x);`},
	}
	build := "-- packmon:migration no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x)"
	conn := &scriptedIndexConn{
		states:   map[string][]indexState{"idx_a": {indexInvalid, indexMissing, indexValid}},
		failOnce: map[string]error{"CREATE INDEX": errors.New("connection reset")},
	}

	err := repairInvalidConcurrentIndexes(context.Background(), conn, migrations, 1)
	if err == nil || !strings.Contains(err.Error(), "rebuild INVALID index idx_a") || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("first repairInvalidConcurrentIndexes() error = %v, want interrupted rebuild", err)
	}
	if err := repairInvalidConcurrentIndexes(context.Background(), conn, migrations, 1); err != nil {
		t.Fatalf("second repairInvalidConcurrentIndexes() error = %v", err)
	}
	assertStatements(t, conn.statements, []string{`DROP INDEX CONCURRENTLY IF EXISTS "idx_a"`, build, build})
	if got := strings.Join(conn.lookups, ","); got != "idx_a,idx_a,idx_a" {
		t.Fatalf("index lookups = %s, want invalid, missing, then valid", got)
	}
}

func TestRepairInvalidConcurrentIndexesReportsFailedRebuild(t *testing.T) {
	t.Parallel()

	migrations := []migrationFile{
		{version: 1, name: "001_index.up.sql", sql: `-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_a ON t(x);`},
	}
	for _, tc := range []struct {
		name string
		conn *scriptedIndexConn
		want []string
	}{
		{
			name: "still invalid",
			conn: &scriptedIndexConn{states: map[string][]indexState{"idx_a": {indexInvalid}}},
			want: []string{"rebuild INVALID index idx_a from 001_index.up.sql", "INVALID", "rerun"},
		},
		{
			name: "missing stays missing",
			conn: &scriptedIndexConn{states: map[string][]indexState{"idx_a": {indexMissing}}},
			want: []string{"recreate missing index idx_a from 001_index.up.sql", "missing or not an index", "rerun"},
		},
		{
			name: "build fails",
			conn: &scriptedIndexConn{
				states:  map[string][]indexState{"idx_a": {indexInvalid}},
				execErr: map[string]error{"CREATE INDEX": errors.New("canceling statement")},
			},
			want: []string{"rebuild INVALID index idx_a from 001_index.up.sql", "canceling statement"},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := repairInvalidConcurrentIndexes(context.Background(), tc.conn, migrations, 1)
			if err == nil {
				t.Fatal("repairInvalidConcurrentIndexes() error = nil, want rebuild failure")
			}
			for _, part := range tc.want {
				if !strings.Contains(err.Error(), part) {
					t.Fatalf("repairInvalidConcurrentIndexes() error = %v, want %q", err, part)
				}
			}
		})
	}
}

func TestMigrationIsRetrySafeIndexBuild(t *testing.T) {
	t.Parallel()

	read := func(name string) migrationFile {
		t.Helper()
		data, err := fs.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return migrationFile{name: name, sql: string(data)}
	}
	tests := []struct {
		name      string
		migration migrationFile
		want      bool
	}{
		{name: "049 only builds indexes concurrently", migration: read("049_malicious_active_search_indexes.up.sql"), want: true},
		{name: "010 also adds a column", migration: read("010_affected_packages_updated_at.up.sql")},
		{name: "011 also creates a table", migration: read("011_sync_keyset_and_lifecycle_tombstones.up.sql")},
		{name: "021 also creates an extension", migration: read("021_package_search_trigram_indexes.up.sql")},
		{name: "050 runs in a transaction", migration: read("050_version_range_boundary_values.up.sql")},
		{name: "build without if not exists", migration: migrationFile{sql: "-- packmon:migration no-transaction\nCREATE INDEX CONCURRENTLY idx_a ON t(x);"}},
		{name: "directive only", migration: migrationFile{sql: "-- packmon:migration no-transaction\n"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := migrationIsRetrySafeIndexBuild(tt.migration); got != tt.want {
				t.Fatalf("migrationIsRetrySafeIndexBuild(%s) = %v, want %v", tt.migration.name, got, tt.want)
			}
		})
	}
}

func TestDirtyDatabaseErrorNamesRetryPathForConcurrentIndexMigrations(t *testing.T) {
	t.Parallel()

	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations() error = %v", err)
	}
	got := dirtyDatabaseError(49, migrations).Error()
	for _, part := range []string{
		"migrations: database is dirty at version 49",
		"049_malicious_active_search_indexes.up.sql",
		"safe to retry",
		"DELETE FROM schema_migrations WHERE version = 49 AND dirty",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("dirtyDatabaseError(49) = %q, want %q", got, part)
		}
	}
	if got := dirtyDatabaseError(50, migrations).Error(); got != "migrations: database is dirty at version 50" {
		t.Fatalf("dirtyDatabaseError(50) = %q, want the plain dirty error", got)
	}
	if got := dirtyDatabaseError(999, migrations).Error(); got != "migrations: database is dirty at version 999" {
		t.Fatalf("dirtyDatabaseError(999) = %q, want the plain dirty error", got)
	}
}

func TestIndexStateString(t *testing.T) {
	t.Parallel()

	for state, want := range map[indexState]string{
		indexMissing:   "missing or not an index",
		indexValid:     "valid",
		indexInvalid:   "INVALID",
		indexState(42): "unknown",
	} {
		if got := state.String(); got != want {
			t.Fatalf("indexState(%d).String() = %q, want %q", state, got, want)
		}
	}
}

func assertStatements(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("executed %d statements, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("statement %d = %q, want %q", i, got[i], want[i])
		}
	}
}
