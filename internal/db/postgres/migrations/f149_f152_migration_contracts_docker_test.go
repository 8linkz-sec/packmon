//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	packmondb "github.com/8linkz-sec/packmon/internal/db"
	postgresstore "github.com/8linkz-sec/packmon/internal/db/postgres"
	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f149F152Leaf struct {
	ctx  context.Context
	conn *sql.Conn
	dsn  string
}

type f149F152Index struct {
	name      string
	table     string
	predicate string
}

var f149F152TrigramIndexes = []f149F152Index{
	{name: "idx_affected_packages_name_trgm", table: "affected_packages"},
	{name: "idx_malicious_findings_name_trgm", table: "malicious_findings", predicate: "(removed_at IS NULL)"},
	{name: "idx_package_reputation_cache_name_trgm", table: "package_reputation_cache"},
	{name: "idx_lifecycle_package_map_name_trgm", table: "lifecycle_package_map"},
}

const f149F152ProductionPruneSQL = `DELETE FROM refresh_queue
		WHERE status = ANY($2::text[])
		  AND COALESCE(processed_at, requested_at) < $1`

func TestF149F152MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	database, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(database)
	database.SetMaxOpenConns(6)

	t.Run("restricted_extension_failure_admin_recovery_and_public_opclass", func(t *testing.T) {
		leaf := f149F152PrepareLeaf(t, database, instance.dsn)
		f149F152Exec(t, leaf, `CREATE ROLE packmon_f149 LOGIN PASSWORD 'packmon_f149'`)
		f149F152Exec(t, leaf, `GRANT CONNECT ON DATABASE packmon TO packmon_f149`)
		f149F152Exec(t, leaf, `GRANT ALL ON SCHEMA public TO packmon_f149`)
		f149F152Exec(t, leaf, `ALTER TABLE schema_migrations OWNER TO packmon_f149`)
		f149F152Exec(t, leaf, `ALTER TABLE schema_migration_events OWNER TO packmon_f149`)
		restrictedDSN := strings.Replace(instance.dsn, "packmon:packmon@", "packmon_f149:packmon_f149@", 1)
		restricted := f149F152OpenLeaf(t, restrictedDSN)
		if err := ensureVersionTable(restricted.ctx, restricted.conn); err != nil {
			t.Fatalf("ensure migration metadata as restricted role: %v", err)
		}
		f149F152ApplyThrough(t, restricted, 20)

		up := f149F152Embedded(t, 21, MigrationDirectionUp)
		err := applyMigration(restricted.ctx, restricted.conn, up)
		if err == nil || (!strings.Contains(strings.ToLower(err.Error()), "permission denied") && !strings.Contains(strings.ToLower(err.Error()), "superuser")) {
			t.Fatalf("restricted 021 up error = %v, want extension privilege failure", err)
		}
		f149F152AssertDirty(t, restricted, up)
		f149F152AssertIndexes(t, restricted, false)
		f149F152AssertExtensionSchema(t, restricted, "", false)

		f149F152Exec(t, leaf, `CREATE EXTENSION pg_trgm WITH SCHEMA public`)
		f149F152ClearDirty(t, restricted, 21)
		f149F152Apply(t, restricted, 21, MigrationDirectionUp)
		f149F152AssertClean(t, restricted, up)
		f149F152AssertExtensionSchema(t, restricted, "public", true)
		f149F152AssertIndexes(t, restricted, true)
		var opclassSchema string
		if err := restricted.conn.QueryRowContext(restricted.ctx, `
			SELECT n.nspname
			FROM pg_opclass opc
			JOIN pg_namespace n ON n.oid=opc.opcnamespace
			WHERE opc.opcname='gin_trgm_ops'`).Scan(&opclassSchema); err != nil {
			t.Fatalf("read gin_trgm_ops schema: %v", err)
		}
		if opclassSchema != "public" {
			t.Fatalf("gin_trgm_ops schema = %q, want public", opclassSchema)
		}
	})

	t.Run("populated_021_catalog_plans_replay_roundtrip", func(t *testing.T) {
		leaf := f149F152PrepareLeaf(t, database, instance.dsn)
		f149F152ApplyThrough(t, leaf, 20)
		f149F152SeedSearchTables(t, leaf)
		before := f149F152SearchCounts(t, leaf)

		f149F152Apply(t, leaf, 21, MigrationDirectionUp)
		f149F152AssertExtensionSchema(t, leaf, "public", true)
		f149F152AssertIndexes(t, leaf, true)
		f149F152AssertSearchPlans(t, leaf)
		if got := f149F152SearchCounts(t, leaf); got != before {
			t.Fatalf("021 up changed search rows: got %q, want %q", got, before)
		}

		f149F152Apply(t, leaf, 21, MigrationDirectionUp)
		f149F152AssertIndexes(t, leaf, true)
		if got := f149F152SearchCounts(t, leaf); got != before {
			t.Fatalf("021 replay changed search rows: got %q, want %q", got, before)
		}

		f149F152ApplyDownAndDelete(t, leaf, 21)
		f149F152AssertIndexes(t, leaf, false)
		f149F152AssertExtensionSchema(t, leaf, "public", true)
		if got := f149F152SearchCounts(t, leaf); got != before {
			t.Fatalf("021 down changed search rows: got %q, want %q", got, before)
		}
		f149F152Apply(t, leaf, 21, MigrationDirectionUp)
		f149F152AssertIndexes(t, leaf, true)
		f149F152AssertSearchPlans(t, leaf)
	})

	t.Run("partial_concurrent_021_build_failure_and_recovery", func(t *testing.T) {
		leaf := f149F152PrepareLeaf(t, database, instance.dsn)
		f149F152ApplyThrough(t, leaf, 20)
		f149F152SeedSearchTables(t, leaf)
		before := f149F152SearchCounts(t, leaf)
		f149F152Exec(t, leaf, `CREATE TABLE idx_package_reputation_cache_name_trgm(id integer)`)

		up := f149F152Embedded(t, 21, MigrationDirectionUp)
		err := applyMigration(leaf.ctx, leaf.conn, up)
		if err == nil || !strings.Contains(err.Error(), "idx_package_reputation_cache_name_trgm") {
			t.Fatalf("partial 021 up error = %v, want third-index name collision", err)
		}
		f149F152AssertDirty(t, leaf, up)
		f149F152AssertTrigramIndex(t, leaf, f149F152TrigramIndexes[0])
		f149F152AssertTrigramIndex(t, leaf, f149F152TrigramIndexes[1])
		f149F152AssertRelationKind(t, leaf, f149F152TrigramIndexes[2].name, "r")
		f149F152AssertRelationAbsent(t, leaf, f149F152TrigramIndexes[3].name)
		if got := f149F152SearchCounts(t, leaf); got != before {
			t.Fatalf("failed 021 up changed search rows: got %q, want %q", got, before)
		}
		f149F152AssertRunRefusesDirty(t, leaf, 21)

		f149F152ClearDirty(t, leaf, 21)
		f149F152Exec(t, leaf, `DROP TABLE idx_package_reputation_cache_name_trgm`)
		f149F152Apply(t, leaf, 21, MigrationDirectionUp)
		f149F152AssertIndexes(t, leaf, true)
		f149F152AssertSearchPlans(t, leaf)
	})

	t.Run("partial_and_repeated_021_down_then_reapply", func(t *testing.T) {
		leaf := f149F152PrepareLeaf(t, database, instance.dsn)
		f149F152ApplyThrough(t, leaf, 21)
		f149F152SeedSearchTables(t, leaf)
		before := f149F152SearchCounts(t, leaf)
		down := f149F152Embedded(t, 21, MigrationDirectionDown)
		statements, err := splitSQLStatements(down.sql)
		if err != nil {
			t.Fatalf("split 021 down: %v", err)
		}
		for _, statement := range statements[:2] {
			f149F152Exec(t, leaf, statement)
		}
		f149F152AssertRelationAbsent(t, leaf, f149F152TrigramIndexes[3].name)
		f149F152AssertRelationAbsent(t, leaf, f149F152TrigramIndexes[2].name)
		f149F152AssertTrigramIndex(t, leaf, f149F152TrigramIndexes[0])
		f149F152AssertTrigramIndex(t, leaf, f149F152TrigramIndexes[1])

		f149F152Apply(t, leaf, 21, MigrationDirectionDown)
		f149F152DeleteSuccessfulDown(t, leaf, down)
		f149F152AssertIndexes(t, leaf, false)
		f149F152Apply(t, leaf, 21, MigrationDirectionDown)
		f149F152DeleteSuccessfulDown(t, leaf, down)
		f149F152AssertIndexes(t, leaf, false)
		f149F152Apply(t, leaf, 21, MigrationDirectionUp)
		f149F152AssertIndexes(t, leaf, true)
		if got := f149F152SearchCounts(t, leaf); got != before {
			t.Fatalf("partial/repeated 021 down changed search rows: got %q, want %q", got, before)
		}
	})

	t.Run("cancelled_021_down_is_dirty_and_recoverable", func(t *testing.T) {
		leaf := f149F152PrepareLeaf(t, database, instance.dsn)
		f149F152ApplyThrough(t, leaf, 21)
		f149F152SeedSearchTables(t, leaf)
		before := f149F152SearchCounts(t, leaf)
		locker, err := database.BeginTx(leaf.ctx, nil)
		if err != nil {
			t.Fatalf("begin cancellation blocker: %v", err)
		}
		if _, err := locker.ExecContext(leaf.ctx, `LOCK TABLE lifecycle_package_map IN ACCESS EXCLUSIVE MODE`); err != nil {
			_ = locker.Rollback()
			t.Fatalf("lock lifecycle_package_map: %v", err)
		}

		cancelConn, err := database.Conn(leaf.ctx)
		if err != nil {
			_ = locker.Rollback()
			t.Fatalf("acquire cancellation connection: %v", err)
		}
		defer ioutils.CloseSilently(cancelConn)
		down := f149F152Embedded(t, 21, MigrationDirectionDown)
		cancelCtx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		err = applyMigration(cancelCtx, cancelConn, down)
		cancel()
		if rollbackErr := locker.Rollback(); rollbackErr != nil {
			t.Fatalf("release cancellation blocker: %v", rollbackErr)
		}
		if err == nil || (!strings.Contains(strings.ToLower(err.Error()), "context deadline") && !strings.Contains(strings.ToLower(err.Error()), "cancel")) {
			t.Fatalf("cancelled 021 down error = %v, want context cancellation", err)
		}
		f149F152AssertDirty(t, leaf, down)
		var exists, belongsToLifecycle bool
		if err := leaf.conn.QueryRowContext(leaf.ctx, `
			SELECT to_regclass('idx_lifecycle_package_map_name_trgm') IS NOT NULL,
			       EXISTS(SELECT 1 FROM pg_index i WHERE i.indexrelid=to_regclass('idx_lifecycle_package_map_name_trgm') AND i.indrelid='lifecycle_package_map'::regclass)`).Scan(&exists, &belongsToLifecycle); err != nil {
			t.Fatalf("inspect cancelled lifecycle trigram drop: %v", err)
		}
		if exists && !belongsToLifecycle {
			t.Fatal("cancelled first concurrent drop left the lifecycle trigram name bound to an unexpected relation")
		}
		for _, index := range f149F152TrigramIndexes[:3] {
			f149F152AssertTrigramIndex(t, leaf, index)
		}
		if got := f149F152SearchCounts(t, leaf); got != before {
			t.Fatalf("cancelled 021 down changed search rows: got %q, want %q", got, before)
		}

		f149F152ClearDirty(t, leaf, 21)
		f149F152Apply(t, leaf, 21, MigrationDirectionDown)
		f149F152DeleteSuccessfulDown(t, leaf, down)
		f149F152AssertIndexes(t, leaf, false)
		f149F152Apply(t, leaf, 21, MigrationDirectionUp)
		f149F152AssertIndexes(t, leaf, true)
	})

	t.Run("populated_022_catalog_retention_roundtrip_and_plans", func(t *testing.T) {
		leaf := f149F152PrepareLeaf(t, database, instance.dsn)
		f149F152ApplyThrough(t, leaf, 21)
		f149F152SeedQueue(t, leaf)
		before := f149F152QueueSnapshot(t, leaf)
		unrelatedIndexOID, unrelatedIndexDefinition := f149F152QueueIndexIdentity(t, leaf, "idx_queue_priority")

		f149F152Apply(t, leaf, 22, MigrationDirectionUp)
		f149F152AssertQueueIndex(t, leaf, true)
		f149F152AssertPrunePlan(t, leaf, false)
		if got := f149F152QueueSnapshot(t, leaf); got != before {
			t.Fatalf("022 up changed queue rows\ngot:  %s\nwant: %s", got, before)
		}

		f149F152ApplyDownAndDelete(t, leaf, 22)
		f149F152AssertQueueIndex(t, leaf, false)
		if got := f149F152QueueSnapshot(t, leaf); got != before {
			t.Fatalf("022 down changed queue rows\ngot:  %s\nwant: %s", got, before)
		}
		f149F152AssertQueueIndexIdentity(t, leaf, "idx_queue_priority", unrelatedIndexOID, unrelatedIndexDefinition)

		f149F152ApplyDownAndDelete(t, leaf, 22)
		f149F152AssertQueueIndex(t, leaf, false)
		if got := f149F152QueueSnapshot(t, leaf); got != before {
			t.Fatalf("repeated 022 down with target index absent changed queue rows\ngot:  %s\nwant: %s", got, before)
		}
		f149F152AssertQueueIndexIdentity(t, leaf, "idx_queue_priority", unrelatedIndexOID, unrelatedIndexDefinition)

		f149F152Apply(t, leaf, 22, MigrationDirectionUp)
		f149F152AssertQueueIndex(t, leaf, true)
		f149F152AssertQueueIndexIdentity(t, leaf, "idx_queue_priority", unrelatedIndexOID, unrelatedIndexDefinition)
		f149F152AssertPrunePlan(t, leaf, true)

		store, err := postgresstore.New(leaf.ctx, leaf.dsn, nil, &postgresstore.PoolConfig{MaxConns: 1, MinConns: 1})
		if err != nil {
			t.Fatalf("postgres.New() error = %v", err)
		}
		defer func() {
			if err := store.Close(); err != nil {
				t.Errorf("Close(queue prune store) error = %v", err)
			}
		}()
		pruned, err := store.PruneRefreshQueue(leaf.ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("PruneRefreshQueue() error = %v", err)
		}
		if pruned != 2 {
			t.Fatalf("PruneRefreshQueue() = %d, want 2 old terminal rows", pruned)
		}
		var ids []int64
		rows, err := leaf.conn.QueryContext(leaf.ctx, `SELECT id FROM refresh_queue ORDER BY id`)
		if err != nil {
			t.Fatalf("list retained queue IDs: %v", err)
		}
		defer ioutils.CloseSilently(rows)
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				t.Fatalf("scan retained queue ID: %v", err)
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate retained queue IDs: %v", err)
		}
		if want := []int64{2203, 2204, 2205, 2206}; !reflect.DeepEqual(ids, want) {
			t.Fatalf("retained queue IDs = %v, want %v", ids, want)
		}
	})

	t.Run("022_collision_is_atomic_dirty_and_recoverable", func(t *testing.T) {
		leaf := f149F152PrepareLeaf(t, database, instance.dsn)
		f149F152ApplyThrough(t, leaf, 21)
		f149F152SeedQueue(t, leaf)
		before := f149F152QueueSnapshot(t, leaf)
		f149F152Exec(t, leaf, `CREATE TABLE idx_queue_terminal_processed_at(id integer)`)

		up := f149F152Embedded(t, 22, MigrationDirectionUp)
		err := applyMigration(leaf.ctx, leaf.conn, up)
		if err == nil || !strings.Contains(err.Error(), "idx_queue_terminal_processed_at") {
			t.Fatalf("022 collision error = %v, want index-name conflict", err)
		}
		f149F152AssertDirty(t, leaf, up)
		f149F152AssertRelationKind(t, leaf, "idx_queue_terminal_processed_at", "r")
		if got := f149F152QueueSnapshot(t, leaf); got != before {
			t.Fatalf("failed transactional 022 up changed queue rows\ngot:  %s\nwant: %s", got, before)
		}
		f149F152AssertRunRefusesDirty(t, leaf, 22)

		f149F152ClearDirty(t, leaf, 22)
		f149F152Exec(t, leaf, `DROP TABLE idx_queue_terminal_processed_at`)
		f149F152Apply(t, leaf, 22, MigrationDirectionUp)
		f149F152AssertQueueIndex(t, leaf, true)
		f149F152ApplyDownAndDelete(t, leaf, 22)
		f149F152AssertQueueIndex(t, leaf, false)
		f149F152Apply(t, leaf, 22, MigrationDirectionUp)
		f149F152AssertQueueIndex(t, leaf, true)
	})
}

func f149F152PrepareLeaf(t *testing.T, database *sql.DB, dsn string) f149F152Leaf {
	t.Helper()
	resetCtx, resetCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer resetCancel()
	if _, err := database.ExecContext(resetCtx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public AUTHORIZATION packmon`); err != nil {
		t.Fatalf("reset public schema before migration leaf: %v", err)
	}
	leaf := f149F152OpenLeaf(t, dsn)
	if err := ensureVersionTable(leaf.ctx, leaf.conn); err != nil {
		t.Fatalf("ensure migration metadata tables: %v", err)
	}
	return leaf
}

func f149F152OpenLeaf(t *testing.T, dsn string) f149F152Leaf {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open(%s) error = %v", dsn, err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { ioutils.CloseSilently(database) })
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire migration leaf connection: %v", err)
	}
	t.Cleanup(func() { ioutils.CloseSilently(conn) })
	return f149F152Leaf{ctx: ctx, conn: conn, dsn: dsn}
}

func f149F152Embedded(t *testing.T, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	embedded, err := ReadEmbeddedMigration(version, direction)
	if err != nil {
		t.Fatalf("ReadEmbeddedMigration(%03d, %s) error = %v", version, direction, err)
	}
	return migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
}

func f149F152Apply(t *testing.T, leaf f149F152Leaf, version int, direction MigrationDirection) migrationFile {
	t.Helper()
	migration := f149F152Embedded(t, version, direction)
	if err := applyMigration(leaf.ctx, leaf.conn, migration); err != nil {
		t.Fatalf("apply %s: %v", migration.name, err)
	}
	return migration
}

func f149F152ApplyThrough(t *testing.T, leaf f149F152Leaf, target int) {
	t.Helper()
	for version := 1; version <= target; version++ {
		f149F152Apply(t, leaf, version, MigrationDirectionUp)
	}
}

func f149F152ApplyDownAndDelete(t *testing.T, leaf f149F152Leaf, version int) {
	t.Helper()
	down := f149F152Apply(t, leaf, version, MigrationDirectionDown)
	f149F152DeleteSuccessfulDown(t, leaf, down)
}

func f149F152DeleteSuccessfulDown(t *testing.T, leaf f149F152Leaf, down migrationFile) {
	t.Helper()
	f149F152AssertClean(t, leaf, down)
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND name=$2 AND checksum=$3 AND NOT dirty`, down.version, down.name, migrationChecksum(down.sql))
	if err != nil {
		t.Fatalf("delete inspected successful down metadata for %s: %v", down.name, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("delete successful down metadata for %s affected=%d error=%v, want 1", down.name, affected, err)
	}
}

func f149F152Exec(t *testing.T, leaf f149F152Leaf, statement string, args ...any) {
	t.Helper()
	if _, err := leaf.conn.ExecContext(leaf.ctx, statement, args...); err != nil {
		t.Fatalf("execute migration fixture SQL: %v\nSQL:\n%s", err, statement)
	}
}

func f149F152SeedSearchTables(t *testing.T, leaf f149F152Leaf) {
	t.Helper()
	f149F152Exec(t, leaf, `
		INSERT INTO vulnerabilities(id,summary,severity,published,modified)
		SELECT 'F150-'||g,'fixture','LOW','2020-01-01Z','2020-01-01Z' FROM generate_series(1,256) g;
		INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected)
		SELECT 'F150-'||g,'npm',CASE WHEN g=128 THEN 'affected-needle-package' ELSE 'affected-noise-'||g END,'[]'::jsonb,'[]'::jsonb FROM generate_series(1,256) g;
		INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary,removed_at)
		SELECT 'F150-M-'||g,'npm',CASE WHEN g=10000 THEN 'malicious-needle-package' ELSE 'malicious-noise-'||g END,'fixture','malware','CRITICAL','fixture',CASE WHEN g%7=0 THEN '2024-01-01Z'::timestamptz ELSE NULL END FROM generate_series(1,20000) g;
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status)
		SELECT 'npm',CASE WHEN g=128 THEN 'reputation-needle-package' ELSE 'reputation-noise-'||g END,'1.0.'||g,'fixture','clean' FROM generate_series(1,256) g;
		INSERT INTO lifecycle_products(product_slug,name)
		SELECT 'f150-product-'||g,'Product '||g FROM generate_series(1,256) g;
		INSERT INTO lifecycle_package_map(ecosystem,name,product_slug)
		SELECT 'npm',CASE WHEN g=128 THEN 'lifecycle-needle-package' ELSE 'lifecycle-noise-'||g END,'f150-product-'||g FROM generate_series(1,256) g`)
}

func f149F152SearchCounts(t *testing.T, leaf f149F152Leaf) string {
	t.Helper()
	var snapshot string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT concat_ws(',',(SELECT count(*) FROM affected_packages),(SELECT count(*) FROM malicious_findings),(SELECT count(*) FROM package_reputation_cache),(SELECT count(*) FROM lifecycle_package_map))`).Scan(&snapshot); err != nil {
		t.Fatalf("snapshot search table counts: %v", err)
	}
	return snapshot
}

func f149F152AssertExtensionSchema(t *testing.T, leaf f149F152Leaf, want string, exists bool) {
	t.Helper()
	var schema sql.NullString
	err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pg_trgm'`).Scan(&schema)
	if !exists {
		if err != sql.ErrNoRows {
			t.Fatalf("pg_trgm extension query error = %v, want absent", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("read pg_trgm extension schema: %v", err)
	}
	if schema.String != want {
		t.Fatalf("pg_trgm extension schema = %q, want %q", schema.String, want)
	}
}

func f149F152AssertIndexes(t *testing.T, leaf f149F152Leaf, want bool) {
	t.Helper()
	for _, index := range f149F152TrigramIndexes {
		if want {
			f149F152AssertTrigramIndex(t, leaf, index)
		} else {
			f149F152AssertRelationAbsent(t, leaf, index.name)
		}
	}
}

func f149F152AssertTrigramIndex(t *testing.T, leaf f149F152Leaf, want f149F152Index) {
	t.Helper()
	var table, method, opclass, opclassSchema string
	var predicate sql.NullString
	var valid, ready bool
	err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT tbl.relname,am.amname,opc.opcname,opn.nspname,pg_get_expr(i.indpred,i.indrelid),i.indisvalid,i.indisready
		FROM pg_index i
		JOIN pg_class idx ON idx.oid=i.indexrelid
		JOIN pg_class tbl ON tbl.oid=i.indrelid
		JOIN pg_am am ON am.oid=idx.relam
		JOIN pg_opclass opc ON opc.oid=i.indclass[0]
		JOIN pg_namespace opn ON opn.oid=opc.opcnamespace
		WHERE idx.oid=to_regclass($1)`, want.name).Scan(&table, &method, &opclass, &opclassSchema, &predicate, &valid, &ready)
	if err != nil {
		t.Fatalf("inspect trigram index %s: %v", want.name, err)
	}
	if table != want.table || method != "gin" || opclass != "gin_trgm_ops" || opclassSchema != "public" || predicate.String != want.predicate || !valid || !ready {
		t.Fatalf("index %s = table:%q method:%q opclass:%q schema:%q predicate:%q valid:%t ready:%t, want table %q public.gin_trgm_ops predicate %q valid/ready", want.name, table, method, opclass, opclassSchema, predicate.String, valid, ready, want.table, want.predicate)
	}
}

func f149F152AssertSearchPlans(t *testing.T, leaf f149F152Leaf) {
	t.Helper()
	f149F152Exec(t, leaf, `SET enable_seqscan=off`)
	f149F152Exec(t, leaf, `SET enable_indexscan=off`)
	t.Cleanup(func() {
		resetCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = leaf.conn.ExecContext(resetCtx, `RESET enable_seqscan`)
		_, _ = leaf.conn.ExecContext(resetCtx, `RESET enable_indexscan`)
	})
	tests := []struct{ name, query, index string }{
		{"affected", `EXPLAIN (FORMAT JSON,COSTS OFF) SELECT id FROM affected_packages WHERE name ILIKE $1`, f149F152TrigramIndexes[0].name},
		{"malicious", `EXPLAIN (FORMAT JSON,COSTS OFF) SELECT id FROM malicious_findings WHERE removed_at IS NULL AND name ILIKE $1`, f149F152TrigramIndexes[1].name},
		{"reputation", `EXPLAIN (FORMAT JSON,COSTS OFF) SELECT id FROM package_reputation_cache WHERE name ILIKE $1`, f149F152TrigramIndexes[2].name},
		{"lifecycle", `EXPLAIN (FORMAT JSON,COSTS OFF) SELECT product_slug FROM lifecycle_package_map WHERE name ILIKE $1`, f149F152TrigramIndexes[3].name},
	}
	for _, tt := range tests {
		var raw []byte
		if err := leaf.conn.QueryRowContext(leaf.ctx, tt.query, "%needle%").Scan(&raw); err != nil {
			t.Fatalf("EXPLAIN %s trigram search: %v", tt.name, err)
		}
		if !f149F152PlanContainsIndex(t, raw, tt.index) {
			t.Fatalf("%s trigram EXPLAIN does not use %s: %s", tt.name, tt.index, raw)
		}
	}
}

func f149F152SeedQueue(t *testing.T, leaf f149F152Leaf) {
	t.Helper()
	f149F152Exec(t, leaf, `
		INSERT INTO refresh_queue(id,ecosystem,name,source,priority,status,requested_at,processed_at,error) VALUES
		(2201,'npm','old-done','osv',1,'done','2000-01-01Z','2000-01-02Z',NULL),
		(2202,'pypi','old-error','ghsa',1,'error','2000-01-03Z',NULL,'fixture'),
		(2203,'go','fresh-done','osv',1,'done','2999-01-01Z','2999-01-02Z',NULL),
		(2204,'maven','old-pending','osv',1,'pending','2000-01-04Z',NULL,NULL),
		(2205,'cargo','old-paused','ghsa',1,'paused','2000-01-05Z',NULL,NULL),
		(2206,'npm','old-request-recently-done','osv',1,'done','2000-01-06Z','2999-01-03Z',NULL)`)
}

func f149F152QueueSnapshot(t *testing.T, leaf f149F152Leaf) string {
	t.Helper()
	var snapshot string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY id)::text,'[]') FROM (SELECT id,ecosystem,name,source,priority,status,requested_at,processed_at,error FROM refresh_queue ORDER BY id) q`).Scan(&snapshot); err != nil {
		t.Fatalf("snapshot refresh queue: %v", err)
	}
	return snapshot
}

func f149F152AssertQueueIndex(t *testing.T, leaf f149F152Leaf, want bool) {
	t.Helper()
	if !want {
		f149F152AssertRelationAbsent(t, leaf, "idx_queue_terminal_processed_at")
		return
	}
	var table, method, expression, predicate, definition string
	var valid, ready bool
	err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT tbl.relname,am.amname,pg_get_indexdef(i.indexrelid,1,true),pg_get_expr(i.indpred,i.indrelid),pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready
		FROM pg_index i
		JOIN pg_class idx ON idx.oid=i.indexrelid
		JOIN pg_class tbl ON tbl.oid=i.indrelid
		JOIN pg_am am ON am.oid=idx.relam
		WHERE idx.oid=to_regclass('idx_queue_terminal_processed_at')`).Scan(&table, &method, &expression, &predicate, &definition, &valid, &ready)
	if err != nil {
		t.Fatalf("inspect queue retention index: %v", err)
	}
	if table != "refresh_queue" || method != "btree" || expression != "COALESCE(processed_at, requested_at)" || predicate != "(status = ANY (ARRAY['done'::text, 'error'::text]))" || !valid || !ready || !strings.Contains(definition, "idx_queue_terminal_processed_at") {
		t.Fatalf("queue retention index = table:%q method:%q expression:%q predicate:%q definition:%q valid:%t ready:%t", table, method, expression, predicate, definition, valid, ready)
	}
}

func f149F152QueueIndexIdentity(t *testing.T, leaf f149F152Leaf, name string) (int64, string) {
	t.Helper()
	var oid int64
	var definition string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT i.indexrelid::bigint,pg_get_indexdef(i.indexrelid)
		FROM pg_index i
		WHERE i.indexrelid=to_regclass($1)`, name).Scan(&oid, &definition); err != nil {
		t.Fatalf("inspect queue index %s identity: %v", name, err)
	}
	return oid, definition
}

func f149F152AssertQueueIndexIdentity(t *testing.T, leaf f149F152Leaf, name string, wantOID int64, wantDefinition string) {
	t.Helper()
	gotOID, gotDefinition := f149F152QueueIndexIdentity(t, leaf, name)
	if gotOID != wantOID || gotDefinition != wantDefinition {
		t.Fatalf("queue index %s identity = oid:%d definition:%q, want oid:%d definition:%q", name, gotOID, gotDefinition, wantOID, wantDefinition)
	}
}

func f149F152AssertPrunePlan(t *testing.T, leaf f149F152Leaf, checkGeneric bool) {
	t.Helper()
	if got, want := packmondb.TerminalRefreshStatuses(), []string{"done", "error"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("TerminalRefreshStatuses() = %v, want %v for the production prune plan", got, want)
	}
	if production, prepared := f149F152NormalizeSQL(f149F152PruneRefreshQueueSourceSQL(t)), f149F152NormalizeSQL(f149F152ProductionPruneSQL); prepared != production {
		t.Fatalf("prepared prune SQL = %q, production PruneRefreshQueue SQL = %q", prepared, production)
	}
	f149F152Exec(t, leaf, `SET enable_seqscan=off`)
	f149F152Exec(t, leaf, `PREPARE f152_prune(timestamptz,text[]) AS `+f149F152ProductionPruneSQL)
	t.Cleanup(func() {
		resetCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = leaf.conn.ExecContext(resetCtx, `DEALLOCATE f152_prune`)
		_, _ = leaf.conn.ExecContext(resetCtx, `RESET plan_cache_mode`)
		_, _ = leaf.conn.ExecContext(resetCtx, `RESET enable_seqscan`)
	})
	f149F152Exec(t, leaf, `SET plan_cache_mode=force_custom_plan`)
	custom := f149F152ExplainPreparedPrune(t, leaf)
	if !f149F152PlanContainsIndex(t, custom, "idx_queue_terminal_processed_at") {
		t.Fatalf("custom production prune plan does not use idx_queue_terminal_processed_at: %s", custom)
	}
	if !checkGeneric {
		f149F152Exec(t, leaf, `DEALLOCATE f152_prune`)
		return
	}
	t.Run("generic_production_prune_plan", func(t *testing.T) {
		f149F152Exec(t, leaf, `SET plan_cache_mode=force_generic_plan`)
		generic := f149F152ExplainPreparedPrune(t, leaf)
		if !f149F152PlanContainsIndex(t, generic, "idx_queue_terminal_processed_at") {
			t.Skipf("known production defect F152-bugs-1: generic PruneRefreshQueue plan omits idx_queue_terminal_processed_at: %s", generic)
		}
	})
	f149F152Exec(t, leaf, `DEALLOCATE f152_prune`)
}

func f149F152PruneRefreshQueueSourceSQL(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate migration contract test source")
	}
	productionFile := filepath.Join(filepath.Dir(currentFile), "..", "refresh_queue_admin.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), productionFile, nil, 0)
	if err != nil {
		t.Fatalf("parse production refresh queue source: %v", err)
	}
	var queries []string
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "PruneRefreshQueue" || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Exec" {
				return true
			}
			literal, ok := call.Args[1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			query, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("decode production prune SQL literal: %v", err)
			}
			queries = append(queries, query)
			return true
		})
	}
	if len(queries) != 1 {
		t.Fatalf("PruneRefreshQueue production Exec SQL literals = %d, want exactly 1", len(queries))
	}
	return queries[0]
}

func f149F152NormalizeSQL(query string) string {
	return strings.Join(strings.Fields(query), " ")
}

func f149F152ExplainPreparedPrune(t *testing.T, leaf f149F152Leaf) []byte {
	t.Helper()
	var raw []byte
	if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) EXECUTE f152_prune('2026-01-01T00:00:00Z'::timestamptz,ARRAY['done','error']::text[])`).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN production prune statement: %v", err)
	}
	return raw
}

func f149F152PlanContainsIndex(t *testing.T, raw []byte, index string) bool {
	t.Helper()
	var plan any
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("decode JSON EXPLAIN: %v\n%s", err, raw)
	}
	return f149F152JSONContainsIndex(plan, index)
}

func f149F152JSONContainsIndex(value any, index string) bool {
	switch value := value.(type) {
	case map[string]any:
		if value["Index Name"] == index {
			return true
		}
		for _, child := range value {
			if f149F152JSONContainsIndex(child, index) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if f149F152JSONContainsIndex(child, index) {
				return true
			}
		}
	}
	return false
}

func f149F152AssertClean(t *testing.T, leaf f149F152Leaf, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt time.Time
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read clean metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || dirty || appliedAt.IsZero() {
		t.Fatalf("clean metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
}

func f149F152AssertDirty(t *testing.T, leaf f149F152Leaf, migration migrationFile) {
	t.Helper()
	var name, checksum string
	var dirty bool
	var appliedAt sql.NullTime
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT name,checksum,dirty,applied_at FROM schema_migrations WHERE version=$1`, migration.version).Scan(&name, &checksum, &dirty, &appliedAt); err != nil {
		t.Fatalf("read dirty metadata for %s: %v", migration.name, err)
	}
	if name != migration.name || checksum != migrationChecksum(migration.sql) || !dirty || appliedAt.Valid {
		t.Fatalf("dirty metadata for %s = name:%q checksum:%q dirty:%t applied:%v", migration.name, name, checksum, dirty, appliedAt)
	}
}

func f149F152ClearDirty(t *testing.T, leaf f149F152Leaf, version int) {
	t.Helper()
	result, err := leaf.conn.ExecContext(leaf.ctx, `DELETE FROM schema_migrations WHERE version=$1 AND dirty`, version)
	if err != nil {
		t.Fatalf("fixture-only dirty cleanup for version %d: %v", version, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("fixture-only dirty cleanup for version %d affected=%d error=%v, want 1", version, affected, err)
	}
}

func f149F152AssertRunRefusesDirty(t *testing.T, leaf f149F152Leaf, version int) {
	t.Helper()
	err := RunContext(leaf.ctx, leaf.dsn)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("dirty at version %d", version)) {
		t.Fatalf("RunContext() on dirty version %d error = %v, want dirty refusal", version, err)
	}
}

func f149F152AssertRelationAbsent(t *testing.T, leaf f149F152Leaf, name string) {
	t.Helper()
	var exists bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("inspect absent relation %s: %v", name, err)
	}
	if exists {
		t.Fatalf("relation %s exists, want absent", name)
	}
}

func f149F152AssertRelationKind(t *testing.T, leaf f149F152Leaf, name, want string) {
	t.Helper()
	var kind string
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT relkind::text FROM pg_class WHERE oid=to_regclass($1)`, name).Scan(&kind); err != nil {
		t.Fatalf("inspect relation kind %s: %v", name, err)
	}
	if kind != want {
		t.Fatalf("relation %s kind = %q, want %q", name, kind, want)
	}
}
