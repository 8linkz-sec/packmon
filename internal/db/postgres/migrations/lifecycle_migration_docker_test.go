//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f119F122ColumnExpectation struct {
	name       string
	dataType   string
	nullable   string
	defaultSQL string
}

type f119F122IndexExpectation struct {
	name   string
	table  string
	unique bool
	keys   string
}

func TestLifecycleMigration007ContractsAgainstPostgres(t *testing.T) {
	up := f119F122ReadMigration(t, 7, MigrationDirectionUp)
	down := f119F122ReadMigration(t, 7, MigrationDirectionDown)
	f119F122AssertStatementMarkers(t, up.sql, []string{
		"CREATE TABLE lifecycle_products (",
		"CREATE TABLE lifecycle_releases (",
		"CREATE TABLE lifecycle_package_map (",
		"CREATE INDEX lifecycle_package_map_lookup_idx",
		"CREATE INDEX idx_lifecycle_package_map_product_slug",
	})
	f119F122AssertStatementMarkers(t, down.sql, []string{
		"DROP INDEX IF EXISTS idx_lifecycle_package_map_product_slug",
		"DROP INDEX IF EXISTS lifecycle_package_map_lookup_idx",
		"DROP TABLE IF EXISTS lifecycle_package_map",
		"DROP TABLE IF EXISTS lifecycle_releases",
		"DROP TABLE IF EXISTS lifecycle_products",
	})

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
	applyEmbeddedMigrationsRangeForTest(t, ctx, db, 1, 6)
	execOK(t, ctx, db, `INSERT INTO api_keys(id, name, key_hash, created_at, expires_at) VALUES(901, 'lifecycle-sentinel', 'hash-lifecycle-sentinel', '2026-05-06T07:08:09.456Z', '2027-05-06T07:08:09.456Z')`)
	execOK(t, ctx, db, `INSERT INTO system_settings(id, block_threshold, rate_limit_per_minute, rate_limit_burst, updated_at) VALUES(1, 'MEDIUM', 137, 29, '2026-06-07T08:09:10.567Z')`)
	var events []f119F122MigrationEventExpectation

	t.Run("failed_up_rolls_back_and_records_dirty_event", func(t *testing.T) {
		injected := f119F122InjectFinalFailure(up)
		err := applyMigration(ctx, db, injected)
		expectSQLState(t, "42P01", err)
		events = append(events, f119F122EventExpectation(injected, false, true))
		f119F122AssertFailedMigrationState(t, ctx, db, injected)
		f119F122AssertLifecycleObjects(t, ctx, db, false)
		f119F122AssertUnrelatedSentinels(t, ctx, db)
	})

	t.Run("upgrade_catalog_defaults_and_flattened_identities", func(t *testing.T) {
		if err := applyMigration(ctx, db, up); err != nil {
			t.Fatalf("apply migration %s: %v", up.name, err)
		}
		events = append(events, f119F122EventExpectation(up, true, false))
		assertCleanMigration(t, ctx, db, up)
		f119F122AssertLifecycleObjects(t, ctx, db, true)
		f119F122AssertLifecycleCatalog(t, ctx, db)
		f119F122SeedLifecycleDefaults(t, ctx, db)
		f119F122AssertLifecycleDefaults(t, ctx, db)
		want := []string{
			"map:npm|shared-package|alpha",
			"map:npm|shared-package|beta",
			"product:alpha",
			"product:beta",
			"release:alpha|1",
			"release:beta|1",
		}
		if got := f119F122ReadLifecycleIdentities(t, ctx, db); !slices.Equal(got, want) {
			t.Fatalf("flattened lifecycle identities = %v, want %v", got, want)
		}
		f119F122AssertUnrelatedSentinels(t, ctx, db)
	})

	t.Run("uniqueness_foreign_keys_and_independent_cascades", func(t *testing.T) {
		for _, statement := range []string{
			`INSERT INTO lifecycle_products(product_slug, name) VALUES('alpha', 'duplicate')`,
			`INSERT INTO lifecycle_releases(product_slug, cycle) VALUES('alpha', '1')`,
			`INSERT INTO lifecycle_package_map(ecosystem, name, product_slug) VALUES('npm', 'shared-package', 'alpha')`,
		} {
			expectSQLState(t, "23505", execSQL(ctx, db, statement))
		}
		for _, statement := range []string{
			`INSERT INTO lifecycle_releases(product_slug, cycle) VALUES('missing-product', '1')`,
			`INSERT INTO lifecycle_package_map(ecosystem, name, product_slug) VALUES('npm', 'orphan', 'missing-product')`,
		} {
			expectSQLState(t, "23503", execSQL(ctx, db, statement))
		}
		for _, statement := range []string{
			`INSERT INTO lifecycle_products(product_slug, name) VALUES(NULL, 'null slug')`,
			`INSERT INTO lifecycle_releases(product_slug, cycle) VALUES('beta', NULL)`,
			`INSERT INTO lifecycle_package_map(ecosystem, name, product_slug) VALUES(NULL, 'null ecosystem', 'beta')`,
		} {
			expectSQLState(t, "23502", execSQL(ctx, db, statement))
		}

		execOK(t, ctx, db, `INSERT INTO lifecycle_products(product_slug, name) VALUES('release-parent', 'Release parent'), ('map-parent', 'Map parent')`)
		execOK(t, ctx, db, `INSERT INTO lifecycle_releases(product_slug, cycle) VALUES('release-parent', 'only-release')`)
		execOK(t, ctx, db, `INSERT INTO lifecycle_package_map(ecosystem, name, product_slug) VALUES('pypi', 'only-map', 'map-parent')`)
		execOK(t, ctx, db, `DELETE FROM lifecycle_products WHERE product_slug IN ('alpha', 'release-parent', 'map-parent')`)
		f119F122AssertLifecycleCount(t, ctx, db, "lifecycle_releases", "product_slug IN ('alpha', 'release-parent')", 0)
		f119F122AssertLifecycleCount(t, ctx, db, "lifecycle_package_map", "product_slug IN ('alpha', 'map-parent')", 0)
		want := []string{
			"map:npm|shared-package|beta",
			"product:beta",
			"release:beta|1",
		}
		if got := f119F122ReadLifecycleIdentities(t, ctx, db); !slices.Equal(got, want) {
			t.Fatalf("sibling lifecycle identities after independent cascades = %v, want %v", got, want)
		}
		f119F122AssertUnrelatedSentinels(t, ctx, db)
	})

	t.Run("failed_down_rolls_back_and_records_dirty_event", func(t *testing.T) {
		want := f119F122ReadLifecycleIdentities(t, ctx, db)
		injected := f119F122InjectFinalFailure(down)
		err := applyMigration(ctx, db, injected)
		expectSQLState(t, "42P01", err)
		events = append(events, f119F122EventExpectation(injected, false, true))
		f119F122AssertFailedMigrationState(t, ctx, db, injected)
		f119F122AssertLifecycleCatalog(t, ctx, db)
		if got := f119F122ReadLifecycleIdentities(t, ctx, db); !slices.Equal(got, want) {
			t.Fatalf("lifecycle identities after failed 007 down = %v, want %v", got, want)
		}
		f119F122AssertUnrelatedSentinels(t, ctx, db)
	})

	t.Run("populated_downgrade_removes_only_lifecycle_objects", func(t *testing.T) {
		if err := applyMigration(ctx, db, down); err != nil {
			t.Fatalf("apply migration %s: %v", down.name, err)
		}
		events = append(events, f119F122EventExpectation(down, true, false))
		assertCleanMigrationAndDelete(t, ctx, db, down)
		assertCurrentMigration(t, ctx, db, 6)
		f119F122AssertLifecycleObjects(t, ctx, db, false)
		f119F122AssertUnrelatedSentinels(t, ctx, db)
	})

	t.Run("repeated_down_and_reapply_restore_empty_schema", func(t *testing.T) {
		if err := applyMigration(ctx, db, down); err != nil {
			t.Fatalf("repeat 007 down: %v", err)
		}
		events = append(events, f119F122EventExpectation(down, true, false))
		assertCleanMigrationAndDelete(t, ctx, db, down)
		assertCurrentMigration(t, ctx, db, 6)
		f119F122AssertUnrelatedSentinels(t, ctx, db)

		if err := applyMigration(ctx, db, up); err != nil {
			t.Fatalf("reapply migration %s: %v", up.name, err)
		}
		events = append(events, f119F122EventExpectation(up, true, false))
		assertCleanMigration(t, ctx, db, up)
		assertCurrentMigration(t, ctx, db, 7)
		f119F122AssertLifecycleCatalog(t, ctx, db)
		if got := f119F122ReadLifecycleIdentities(t, ctx, db); len(got) != 0 {
			t.Fatalf("lifecycle identities after reapply = %v, want empty", got)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin reapply usability transaction: %v", err)
		}
		for _, statement := range []string{
			`INSERT INTO lifecycle_products(product_slug, name) VALUES('transactional', 'Transactional')`,
			`INSERT INTO lifecycle_releases(product_slug, cycle) VALUES('transactional', '1')`,
			`INSERT INTO lifecycle_package_map(ecosystem, name, product_slug) VALUES('npm', 'transactional', 'transactional')`,
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				t.Fatalf("execute reapply usability statement %q: %v", statement, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit reapply usability transaction: %v", err)
		}
		want := []string{
			"map:npm|transactional|transactional",
			"product:transactional",
			"release:transactional|1",
		}
		if got := f119F122ReadLifecycleIdentities(t, ctx, db); !slices.Equal(got, want) {
			t.Fatalf("transactional lifecycle identities = %v, want %v", got, want)
		}
		execOK(t, ctx, db, `DELETE FROM lifecycle_products WHERE product_slug = 'transactional'`)
		if got := f119F122ReadLifecycleIdentities(t, ctx, db); len(got) != 0 {
			t.Fatalf("lifecycle identities after transactional cleanup = %v, want empty", got)
		}
		f119F122AssertUnrelatedSentinels(t, ctx, db)
		f119F122AssertMigrationEvents(t, ctx, db, 7, events, 6)
	})
}

func f119F122AssertStatementMarkers(t *testing.T, migrationSQL string, want []string) {
	t.Helper()
	statements, err := splitSQLStatements(migrationSQL)
	if err != nil {
		t.Fatalf("splitSQLStatements() error = %v", err)
	}
	if len(statements) != len(want) {
		t.Fatalf("splitSQLStatements() count = %d, want %d: %#v", len(statements), len(want), statements)
	}
	for i := range want {
		if !strings.HasPrefix(strings.TrimSpace(statements[i]), want[i]) {
			t.Fatalf("statement %d = %q, want prefix %q", i+1, statements[i], want[i])
		}
	}
}

func f119F122AssertLifecycleObjects(t *testing.T, ctx context.Context, db *sql.DB, wantPresent bool) {
	t.Helper()
	wantTables := []string{"lifecycle_package_map", "lifecycle_products", "lifecycle_releases"}
	gotTables := queryStrings(t, ctx, db, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = ANY($1::text[])
		ORDER BY table_name`, wantTables)
	if wantPresent && !slices.Equal(gotTables, wantTables) {
		t.Fatalf("lifecycle tables = %v, want %v", gotTables, wantTables)
	}
	if !wantPresent && len(gotTables) != 0 {
		t.Fatalf("lifecycle tables = %v, want none", gotTables)
	}
	wantIndexes := []string{"idx_lifecycle_package_map_product_slug", "lifecycle_package_map_lookup_idx"}
	gotIndexes := queryStrings(t, ctx, db, `
		SELECT indexname FROM pg_indexes
		WHERE schemaname = 'public' AND indexname = ANY($1::text[])
		ORDER BY indexname`, wantIndexes)
	if wantPresent && !slices.Equal(gotIndexes, wantIndexes) {
		t.Fatalf("lifecycle explicit indexes = %v, want %v", gotIndexes, wantIndexes)
	}
	if !wantPresent && len(gotIndexes) != 0 {
		t.Fatalf("lifecycle explicit indexes = %v, want none", gotIndexes)
	}
}

func f119F122AssertLifecycleCatalog(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	f119F122AssertColumns(t, ctx, db, "lifecycle_products", []f119F122ColumnExpectation{
		{"product_slug", "text", "NO", ""},
		{"name", "text", "NO", ""},
		{"category", "text", "NO", "''::text"},
		{"source", "text", "NO", "'endoflife.date'::text"},
		{"identifiers", "jsonb", "NO", "'[]'::jsonb"},
		{"raw", "jsonb", "NO", "'{}'::jsonb"},
		{"updated_at", "timestamp with time zone", "NO", "now()"},
	})
	f119F122AssertColumns(t, ctx, db, "lifecycle_releases", []f119F122ColumnExpectation{
		{"product_slug", "text", "NO", ""},
		{"cycle", "text", "NO", ""},
		{"latest", "text", "NO", "''::text"},
		{"release_date", "date", "YES", ""},
		{"is_lts", "boolean", "NO", "false"},
		{"lts_from", "date", "YES", ""},
		{"is_eoas", "boolean", "NO", "false"},
		{"eoas_from", "date", "YES", ""},
		{"is_eol", "boolean", "NO", "false"},
		{"eol_from", "date", "YES", ""},
		{"is_discontinued", "boolean", "NO", "false"},
		{"discontinued_from", "date", "YES", ""},
		{"is_eoes", "boolean", "YES", ""},
		{"eoes_from", "date", "YES", ""},
		{"is_maintained", "boolean", "NO", "false"},
		{"raw", "jsonb", "NO", "'{}'::jsonb"},
		{"updated_at", "timestamp with time zone", "NO", "now()"},
	})
	f119F122AssertColumns(t, ctx, db, "lifecycle_package_map", []f119F122ColumnExpectation{
		{"ecosystem", "text", "NO", ""},
		{"name", "text", "NO", ""},
		{"product_slug", "text", "NO", ""},
		{"purl_type", "text", "NO", "''::text"},
		{"purl_namespace", "text", "NO", "''::text"},
		{"purl_name", "text", "NO", "''::text"},
		{"source", "text", "NO", "'endoflife.date'::text"},
		{"updated_at", "timestamp with time zone", "NO", "now()"},
	})

	wantPKs := []string{
		"lifecycle_package_map_pkey|lifecycle_package_map|ecosystem|name|product_slug",
		"lifecycle_products_pkey|lifecycle_products|product_slug",
		"lifecycle_releases_pkey|lifecycle_releases|product_slug|cycle",
	}
	gotPKs := queryStrings(t, ctx, db, `
		SELECT constraint_name || '|' || table_name || '|' || string_agg(column_name, '|' ORDER BY ordinal_position)
		FROM information_schema.key_column_usage
		WHERE table_schema = 'public' AND constraint_name IN (
			'lifecycle_products_pkey', 'lifecycle_releases_pkey', 'lifecycle_package_map_pkey')
		GROUP BY constraint_name, table_name ORDER BY constraint_name`)
	if !slices.Equal(gotPKs, wantPKs) {
		t.Fatalf("lifecycle primary keys = %v, want %v", gotPKs, wantPKs)
	}

	wantFKs := []string{
		"lifecycle_package_map_product_slug_fkey|lifecycle_package_map|product_slug|lifecycle_products|product_slug|CASCADE",
		"lifecycle_releases_product_slug_fkey|lifecycle_releases|product_slug|lifecycle_products|product_slug|CASCADE",
	}
	gotFKs := queryStrings(t, ctx, db, `
		SELECT child_constraint.conname || '|' || child.relname || '|' || child_column.attname || '|' || parent.relname || '|' || parent_column.attname || '|' ||
			CASE child_constraint.confdeltype WHEN 'c' THEN 'CASCADE' ELSE child_constraint.confdeltype::text END
		FROM pg_constraint child_constraint
		JOIN pg_class child ON child.oid = child_constraint.conrelid
		JOIN pg_class parent ON parent.oid = child_constraint.confrelid
		JOIN pg_attribute child_column ON child_column.attrelid = child.oid AND child_column.attnum = child_constraint.conkey[1]
		JOIN pg_attribute parent_column ON parent_column.attrelid = parent.oid AND parent_column.attnum = child_constraint.confkey[1]
		WHERE child_constraint.conname IN ('lifecycle_releases_product_slug_fkey', 'lifecycle_package_map_product_slug_fkey')
		ORDER BY child_constraint.conname`)
	if !slices.Equal(gotFKs, wantFKs) {
		t.Fatalf("lifecycle foreign keys = %v, want %v", gotFKs, wantFKs)
	}

	wantIndexes := []f119F122IndexExpectation{
		{"idx_lifecycle_package_map_product_slug", "lifecycle_package_map", false, "product_slug"},
		{"lifecycle_package_map_lookup_idx", "lifecycle_package_map", false, "ecosystem|name"},
		{"lifecycle_package_map_pkey", "lifecycle_package_map", true, "ecosystem|name|product_slug"},
		{"lifecycle_products_pkey", "lifecycle_products", true, "product_slug"},
		{"lifecycle_releases_pkey", "lifecycle_releases", true, "product_slug|cycle"},
	}
	gotIndexes := f119F122ReadLifecycleIndexes(t, ctx, db)
	if !reflect.DeepEqual(gotIndexes, wantIndexes) {
		t.Fatalf("lifecycle indexes = %#v, want %#v", gotIndexes, wantIndexes)
	}
}

func f119F122AssertColumns(t *testing.T, ctx context.Context, db *sql.DB, table string, want []f119F122ColumnExpectation) {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT column_name, data_type, is_nullable, COALESCE(column_default, '')
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1
		ORDER BY ordinal_position`, table)
	if err != nil {
		t.Fatalf("read %s columns: %v", table, err)
	}
	defer ioutils.CloseSilently(rows)
	var got []f119F122ColumnExpectation
	for rows.Next() {
		var column f119F122ColumnExpectation
		if err := rows.Scan(&column.name, &column.dataType, &column.nullable, &column.defaultSQL); err != nil {
			t.Fatalf("scan %s column: %v", table, err)
		}
		got = append(got, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s columns: %v", table, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s columns = %#v, want %#v", table, got, want)
	}
}

func f119F122ReadLifecycleIndexes(t *testing.T, ctx context.Context, db *sql.DB) []f119F122IndexExpectation {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		SELECT index_class.relname, table_class.relname, idx.indisunique,
			(SELECT string_agg(pg_get_indexdef(idx.indexrelid, key_no, true), '|' ORDER BY key_no)
			 FROM generate_series(1, idx.indnkeyatts) key_no),
			idx.indisvalid, idx.indisready, idx.indpred IS NULL
		FROM pg_index idx
		JOIN pg_class index_class ON index_class.oid = idx.indexrelid
		JOIN pg_class table_class ON table_class.oid = idx.indrelid
		WHERE index_class.relname IN (
			'idx_lifecycle_package_map_product_slug', 'lifecycle_package_map_lookup_idx',
			'lifecycle_package_map_pkey', 'lifecycle_products_pkey', 'lifecycle_releases_pkey')
		ORDER BY index_class.relname`)
	if err != nil {
		t.Fatalf("read lifecycle indexes: %v", err)
	}
	defer ioutils.CloseSilently(rows)
	var result []f119F122IndexExpectation
	for rows.Next() {
		var index f119F122IndexExpectation
		var valid, ready, noPredicate bool
		if err := rows.Scan(&index.name, &index.table, &index.unique, &index.keys, &valid, &ready, &noPredicate); err != nil {
			t.Fatalf("scan lifecycle index: %v", err)
		}
		if !valid || !ready || !noPredicate {
			t.Fatalf("lifecycle index %s valid:%v ready:%v no-predicate:%v", index.name, valid, ready, noPredicate)
		}
		result = append(result, index)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate lifecycle indexes: %v", err)
	}
	return result
}

func f119F122SeedLifecycleDefaults(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	execOK(t, ctx, db, `INSERT INTO lifecycle_products(product_slug, name) VALUES('alpha', 'Alpha'), ('beta', 'Beta')`)
	execOK(t, ctx, db, `INSERT INTO lifecycle_releases(product_slug, cycle) VALUES('alpha', '1'), ('beta', '1')`)
	execOK(t, ctx, db, `INSERT INTO lifecycle_package_map(ecosystem, name, product_slug) VALUES('npm', 'shared-package', 'alpha'), ('npm', 'shared-package', 'beta')`)
}

func f119F122AssertLifecycleDefaults(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var category, source, identifiers, raw string
	var productUpdated time.Time
	if err := db.QueryRowContext(ctx, `SELECT category, source, identifiers::text, raw::text, updated_at FROM lifecycle_products WHERE product_slug = 'alpha'`).Scan(&category, &source, &identifiers, &raw, &productUpdated); err != nil {
		t.Fatalf("read lifecycle product defaults: %v", err)
	}
	if category != "" || source != "endoflife.date" || identifiers != "[]" || raw != "{}" || productUpdated.IsZero() {
		t.Fatalf("product defaults = category:%q source:%q identifiers:%q raw:%q updated:%v", category, source, identifiers, raw, productUpdated)
	}

	var latest, releaseRaw string
	var releaseDate, ltsFrom, eoasFrom, eolFrom, discontinuedFrom, eoesFrom sql.NullTime
	var isLTS, isEOAS, isEOL, isDiscontinued, isMaintained bool
	var isEOES sql.NullBool
	var releaseUpdated time.Time
	if err := db.QueryRowContext(ctx, `
		SELECT latest, release_date, is_lts, lts_from, is_eoas, eoas_from, is_eol, eol_from,
			is_discontinued, discontinued_from, is_eoes, eoes_from, is_maintained, raw::text, updated_at
		FROM lifecycle_releases WHERE product_slug = 'alpha' AND cycle = '1'`).Scan(
		&latest, &releaseDate, &isLTS, &ltsFrom, &isEOAS, &eoasFrom, &isEOL, &eolFrom,
		&isDiscontinued, &discontinuedFrom, &isEOES, &eoesFrom, &isMaintained, &releaseRaw, &releaseUpdated,
	); err != nil {
		t.Fatalf("read lifecycle release defaults: %v", err)
	}
	if latest != "" || releaseDate.Valid || isLTS || ltsFrom.Valid || isEOAS || eoasFrom.Valid || isEOL || eolFrom.Valid || isDiscontinued || discontinuedFrom.Valid || isEOES.Valid || eoesFrom.Valid || isMaintained || releaseRaw != "{}" || releaseUpdated.IsZero() {
		t.Fatalf("release defaults = latest:%q date:%v lts:%v/%v eoas:%v/%v eol:%v/%v discontinued:%v/%v eoes:%v/%v maintained:%v raw:%q updated:%v", latest, releaseDate.Valid, isLTS, ltsFrom.Valid, isEOAS, eoasFrom.Valid, isEOL, eolFrom.Valid, isDiscontinued, discontinuedFrom.Valid, isEOES, eoesFrom.Valid, isMaintained, releaseRaw, releaseUpdated)
	}

	var purlType, purlNamespace, purlName, mapSource string
	var mapUpdated time.Time
	if err := db.QueryRowContext(ctx, `SELECT purl_type, purl_namespace, purl_name, source, updated_at FROM lifecycle_package_map WHERE ecosystem = 'npm' AND name = 'shared-package' AND product_slug = 'alpha'`).Scan(&purlType, &purlNamespace, &purlName, &mapSource, &mapUpdated); err != nil {
		t.Fatalf("read lifecycle map defaults: %v", err)
	}
	if purlType != "" || purlNamespace != "" || purlName != "" || mapSource != "endoflife.date" || mapUpdated.IsZero() {
		t.Fatalf("map defaults = type:%q namespace:%q name:%q source:%q updated:%v", purlType, purlNamespace, purlName, mapSource, mapUpdated)
	}
}

func f119F122ReadLifecycleIdentities(t *testing.T, ctx context.Context, db *sql.DB) []string {
	t.Helper()
	return queryStrings(t, ctx, db, `
		SELECT identity FROM (
			SELECT 'product:' || product_slug AS identity FROM lifecycle_products
			UNION ALL SELECT 'release:' || product_slug || '|' || cycle FROM lifecycle_releases
			UNION ALL SELECT 'map:' || ecosystem || '|' || name || '|' || product_slug FROM lifecycle_package_map
		) identities ORDER BY identity`)
}

func f119F122AssertLifecycleCount(t *testing.T, ctx context.Context, db *sql.DB, table, predicate string, want int) {
	t.Helper()
	var got int
	query := "SELECT COUNT(*) FROM " + table + " WHERE " + predicate // #nosec G202 -- fixed test-only table and predicates supplied by this file.
	if err := db.QueryRowContext(ctx, query).Scan(&got); err != nil {
		t.Fatalf("count %s rows matching %q: %v", table, predicate, err)
	}
	if got != want {
		t.Fatalf("%s rows matching %q = %d, want %d", table, predicate, got, want)
	}
}

func f119F122AssertUnrelatedSentinels(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var name, hash string
	var createdAt, expiresAt time.Time
	var revokedAt, lastUsedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT name, key_hash, created_at, revoked_at, last_used_at, expires_at FROM api_keys WHERE id = 901`).Scan(&name, &hash, &createdAt, &revokedAt, &lastUsedAt, &expiresAt); err != nil {
		t.Fatalf("read lifecycle sentinel API key: %v", err)
	}
	wantCreated := time.Date(2026, time.May, 6, 7, 8, 9, 456000000, time.UTC)
	wantExpires := time.Date(2027, time.May, 6, 7, 8, 9, 456000000, time.UTC)
	if name != "lifecycle-sentinel" || hash != "hash-lifecycle-sentinel" || !createdAt.Equal(wantCreated) || revokedAt.Valid || lastUsedAt.Valid || !expiresAt.Equal(wantExpires) {
		t.Fatalf("lifecycle sentinel = name:%q hash:%q created:%s revoked:%v used:%v expires:%s", name, hash, createdAt, revokedAt, lastUsedAt, expiresAt)
	}

	var id, rateLimitPerMinute, rateLimitBurst int
	var blockThreshold string
	var updatedAt time.Time
	if err := db.QueryRowContext(ctx, `SELECT id, block_threshold, rate_limit_per_minute, rate_limit_burst, updated_at FROM system_settings`).Scan(&id, &blockThreshold, &rateLimitPerMinute, &rateLimitBurst, &updatedAt); err != nil {
		t.Fatalf("read system settings sentinel: %v", err)
	}
	wantUpdated := time.Date(2026, time.June, 7, 8, 9, 10, 567000000, time.UTC)
	if id != 1 || blockThreshold != "MEDIUM" || rateLimitPerMinute != 137 || rateLimitBurst != 29 || !updatedAt.Equal(wantUpdated) {
		t.Fatalf("system settings sentinel = id:%d threshold:%q per-minute:%d burst:%d updated:%s", id, blockThreshold, rateLimitPerMinute, rateLimitBurst, updatedAt)
	}
}
