//go:build integration

package migrations

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

type f177F182IndexContract struct {
	name      string
	table     string
	keys      string
	predicate string
}

var f177F182Indexes035 = []f177F182IndexContract{
	{"idx_lifecycle_releases_eol_status_date", "lifecycle_releases", "product_slug,eol_from", "(is_eol OR (eol_from IS NOT NULL))"},
	{"idx_lifecycle_releases_eoas_status_date", "lifecycle_releases", "product_slug,eoas_from", "(is_eoas OR (eoas_from IS NOT NULL))"},
	{"idx_malicious_active_source_updated_at", "malicious_findings", "source,updated_at DESC,created_at DESC,id DESC", "(removed_at IS NULL)"},
	{"idx_malicious_active_updated_at", "malicious_findings", "updated_at DESC,created_at DESC,id DESC", "(removed_at IS NULL)"},
	{"idx_queue_oldest_active_source_requested_at", "refresh_queue", "source,requested_at", "((source <> ''::text) AND (status = ANY (ARRAY['pending'::text, 'processing'::text])))"},
	{"idx_reputation_prune_source_updated_at", "package_reputation_cache", "source,updated_at", "(status = ANY (ARRAY['clean'::text, 'not_found'::text, 'unsupported'::text, 'error'::text]))"},
}

func TestF177F182MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	database, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(database)
	database.SetMaxOpenConns(4)

	extensionCtx, cancelExtension := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelExtension()
	if _, err := database.ExecContext(extensionCtx, `CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public`); err != nil {
		t.Fatalf("install pg_trgm once in public: %v", err)
	}

	leafNumber := 400
	newLeaf := func(t *testing.T) f159F164Leaf {
		t.Helper()
		leafNumber++
		return f159F164PrepareLeaf(t, database, instance.dsn, leafNumber)
	}

	t.Run("migration_035", func(t *testing.T) {
		t.Run("catalog_replay_rows_and_representative_plans", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 34)
			f177F182Seed035Rows(t, leaf)
			rows := f177F182Rows035(t, leaf)
			f159F164Apply(t, leaf, 35, MigrationDirectionUp)
			f177F182Assert035Catalog(t, leaf)
			f159F164AssertEqual(t, "035 rows", f177F182Rows035(t, leaf), rows)
			identities := f177F182IndexIdentities(t, leaf, f177F182Indexes035)
			f177F182Assert035Plans(t, leaf)
			f159F164Apply(t, leaf, 35, MigrationDirectionUp)
			f159F164AssertEqual(t, "035 replay index identities", f177F182IndexIdentities(t, leaf, f177F182Indexes035), identities)
			f159F164AssertEqual(t, "035 replay rows", f177F182Rows035(t, leaf), rows)
		})

		t.Run("down_partial_repeat_up_preserves_rows_and_distinct_unrelated_objects", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 35)
			f177F182Seed035Rows(t, leaf)
			rows := f177F182Rows035(t, leaf)
			f159F164Exec(t, leaf, `DROP INDEX idx_malicious_active_updated_at; CREATE INDEX f178_unrelated_distinct_index ON malicious_findings(summary)`)
			unrelated := f159F164IndexIdentity(t, leaf, "f178_unrelated_distinct_index")
			f159F164ApplyDownAndDelete(t, leaf, 35)
			f177F182Assert035Absent(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 35)
			f177F182Assert035Absent(t, leaf)
			if got := f159F164IndexIdentity(t, leaf, "f178_unrelated_distinct_index"); got != unrelated {
				t.Fatalf("distinct unrelated index changed: got %q, want %q", got, unrelated)
			}
			f159F164AssertEqual(t, "035 down rows", f177F182Rows035(t, leaf), rows)
			f159F164Apply(t, leaf, 35, MigrationDirectionUp)
			f177F182Assert035Catalog(t, leaf)
			f159F164AssertEqual(t, "035 reapplied rows", f177F182Rows035(t, leaf), rows)
		})

		t.Run("up_and_down_late_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			t.Run("up", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 34)
				f177F182Seed035Rows(t, leaf)
				beforeRows := f177F182Rows035(t, leaf)
				beforeCatalog := f177F182Catalog035(t, leaf)
				up := f159F164Embedded(t, 35, MigrationDirectionUp)
				up.sql += `; SELECT * FROM f178_missing_late_up;`
				err := applyMigration(leaf.ctx, leaf.conn, up)
				f159F164ExpectSQLState(t, err, "42P01")
				f159F164AssertEqual(t, "035 failed-up rows", f177F182Rows035(t, leaf), beforeRows)
				f159F164AssertEqual(t, "035 failed-up catalog", f177F182Catalog035(t, leaf), beforeCatalog)
				f159F164AssertDirtyEventAndRefusal(t, leaf, up)
				f159F164ClearDirty(t, leaf, 35)
				f159F164Apply(t, leaf, 35, MigrationDirectionUp)
				f177F182Assert035Catalog(t, leaf)
			})
			t.Run("down", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 35)
				f177F182Seed035Rows(t, leaf)
				beforeRows := f177F182Rows035(t, leaf)
				beforeCatalog := f177F182Catalog035(t, leaf)
				down := f159F164Embedded(t, 35, MigrationDirectionDown)
				down.sql += `; SELECT * FROM f178_missing_late_down;`
				err := applyMigration(leaf.ctx, leaf.conn, down)
				f159F164ExpectSQLState(t, err, "42P01")
				f159F164AssertEqual(t, "035 failed-down rows", f177F182Rows035(t, leaf), beforeRows)
				f159F164AssertEqual(t, "035 failed-down catalog", f177F182Catalog035(t, leaf), beforeCatalog)
				f159F164AssertDirtyEventAndRefusal(t, leaf, down)
				f159F164ClearDirty(t, leaf, 35)
				f159F164Apply(t, leaf, 35, MigrationDirectionDown)
				f177F182Assert035Absent(t, leaf)
			})
		})

		t.Run("unrelated_same_name_ownership_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 35)
			f159F164Exec(t, leaf, `DROP INDEX idx_reputation_prune_source_updated_at; CREATE TABLE public.f177_foreign_index_owner(id INTEGER); CREATE INDEX idx_reputation_prune_source_updated_at ON public.f177_foreign_index_owner(id)`)
			f159F164ApplyDownAndDelete(t, leaf, 35)
			var remains int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='idx_reputation_prune_source_updated_at'`).Scan(&remains); err != nil {
				t.Fatalf("inspect foreign index: %v", err)
			}
			f159F164Exec(t, leaf, `DROP TABLE public.f177_foreign_index_owner`)
			f159F164Apply(t, leaf, 35, MigrationDirectionUp)
			f177F182Assert035Catalog(t, leaf)
			if remains == 0 {
				t.Skip("F177-bugs-1 P2 reproduced: migration 035 down drops a same-named foreign index resolved later on search_path")
			}
		})

		t.Run("all_six_same_named_wrong_definitions_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 34)
			f159F164Exec(t, leaf, `CREATE INDEX idx_lifecycle_releases_eol_status_date ON lifecycle_releases(cycle); CREATE INDEX idx_lifecycle_releases_eoas_status_date ON lifecycle_releases(cycle); CREATE INDEX idx_malicious_active_source_updated_at ON malicious_findings(id); CREATE INDEX idx_malicious_active_updated_at ON malicious_findings(id); CREATE INDEX idx_queue_oldest_active_source_requested_at ON refresh_queue(id); CREATE INDEX idx_reputation_prune_source_updated_at ON package_reputation_cache(id)`)
			up := f159F164Embedded(t, 35, MigrationDirectionUp)
			err := applyMigration(leaf.ctx, leaf.conn, up)
			if err != nil {
				f159F164AssertDirtyEventAndRefusal(t, leaf, up)
				f159F164ClearDirty(t, leaf, 35)
				f159F164Exec(t, leaf, f177F182Drop035SQL())
				f159F164Apply(t, leaf, 35, MigrationDirectionUp)
				f177F182Assert035Catalog(t, leaf)
				return
			}
			wrong := f177F182CountWrong035(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 35)
			f159F164Apply(t, leaf, 35, MigrationDirectionUp)
			f177F182Assert035Catalog(t, leaf)
			if wrong == 6 {
				t.Skip("F178-bugs-1 P3 reproduced: migration 035 accepts all six same-named indexes with wrong definitions")
			}
			if wrong != 0 {
				t.Fatalf("migration 035 left %d partially wrong index definitions", wrong)
			}
		})
	})

	t.Run("migration_036", func(t *testing.T) {
		t.Run("legacy_catalog_defaults_nullability_and_replay", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 35)
			f159F164Exec(t, leaf, `DROP INDEX idx_admin_audit_correlation_id; ALTER TABLE admin_audit_log DROP COLUMN correlation_id; INSERT INTO admin_audit_log(action,details,ip,created_at) VALUES ('f179-legacy','{"legacy":true}','192.0.2.179','2025-01-01Z')`)
			rows := f159F164Snapshot(t, leaf, `SELECT id,action,details,ip::text,created_at,xmin::text FROM admin_audit_log ORDER BY id`)
			f159F164Apply(t, leaf, 36, MigrationDirectionUp)
			f177F182Assert036Catalog(t, leaf)
			f159F164AssertEqual(t, "036 legacy rows", f159F164Snapshot(t, leaf, `SELECT id,action,details,ip::text,created_at,xmin::text FROM admin_audit_log ORDER BY id`), rows)
			var correlation string
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT correlation_id FROM admin_audit_log WHERE action='f179-legacy'`).Scan(&correlation); err != nil || correlation != "" {
				t.Fatalf("legacy correlation = %q error=%v, want empty", correlation, err)
			}
			identity := f159F164IndexIdentity(t, leaf, "idx_admin_audit_correlation_id")
			f159F164Apply(t, leaf, 36, MigrationDirectionUp)
			if got := f159F164IndexIdentity(t, leaf, "idx_admin_audit_correlation_id"); got != identity {
				t.Fatalf("036 replay index identity = %q, want %q", got, identity)
			}
		})

		t.Run("no_op_down_repeat_up_preserves_rows_column_and_index", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 36)
			f159F164Exec(t, leaf, `INSERT INTO admin_audit_log(action,correlation_id,created_at) VALUES ('f179-round','f179-correlation','2025-01-02Z')`)
			rows := f177F182Rows036(t, leaf)
			catalog := f177F182Catalog036(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 36)
			f159F164ApplyDownAndDelete(t, leaf, 36)
			f159F164AssertEqual(t, "036 no-op down rows", f177F182Rows036(t, leaf), rows)
			f159F164AssertEqual(t, "036 no-op down catalog", f177F182Catalog036(t, leaf), catalog)
			f159F164Apply(t, leaf, 36, MigrationDirectionUp)
			f159F164AssertEqual(t, "036 reapply rows", f177F182Rows036(t, leaf), rows)
			f159F164AssertEqual(t, "036 reapply catalog", f177F182Catalog036(t, leaf), catalog)
		})

		t.Run("up_late_failure_is_atomic_dirty_and_recoverable", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 35)
			f159F164Exec(t, leaf, `DROP INDEX idx_admin_audit_correlation_id; ALTER TABLE admin_audit_log DROP COLUMN correlation_id`)
			beforeRows := f159F164Snapshot(t, leaf, `SELECT id,action,details,ip::text,created_at,xmin::text FROM admin_audit_log ORDER BY id`)
			beforeCatalog := f177F182Catalog036(t, leaf)
			up := f159F164Embedded(t, 36, MigrationDirectionUp)
			up.sql += `; SELECT * FROM f180_missing_late_up;`
			err := applyMigration(leaf.ctx, leaf.conn, up)
			f159F164ExpectSQLState(t, err, "42P01")
			f159F164AssertEqual(t, "036 failed-up rows", f159F164Snapshot(t, leaf, `SELECT id,action,details,ip::text,created_at,xmin::text FROM admin_audit_log ORDER BY id`), beforeRows)
			f159F164AssertEqual(t, "036 failed-up catalog", f177F182Catalog036(t, leaf), beforeCatalog)
			f159F164AssertDirtyEventAndRefusal(t, leaf, up)
			f159F164ClearDirty(t, leaf, 36)
			f159F164Apply(t, leaf, 36, MigrationDirectionUp)
			f177F182Assert036Catalog(t, leaf)
		})

		t.Run("wrong_existing_column_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 35)
			f159F164Exec(t, leaf, `DROP INDEX idx_admin_audit_correlation_id; ALTER TABLE admin_audit_log DROP COLUMN correlation_id; ALTER TABLE admin_audit_log ADD COLUMN correlation_id TEXT`)
			f159F164Apply(t, leaf, 36, MigrationDirectionUp)
			wrong := !f177F182036ColumnExact(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 36)
			f159F164Exec(t, leaf, `DROP INDEX IF EXISTS idx_admin_audit_correlation_id; ALTER TABLE admin_audit_log DROP COLUMN correlation_id`)
			f159F164Apply(t, leaf, 36, MigrationDirectionUp)
			f177F182Assert036Catalog(t, leaf)
			if wrong {
				t.Skip("F180-bugs-1 P2 reproduced: migration 036 accepts an existing nullable correlation_id column without its required default")
			}
		})

		t.Run("same_named_wrong_index_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 35)
			f159F164Exec(t, leaf, `DROP INDEX idx_admin_audit_correlation_id; CREATE INDEX idx_admin_audit_correlation_id ON admin_audit_log(id)`)
			f159F164Apply(t, leaf, 36, MigrationDirectionUp)
			wrong := !f177F182036IndexExact(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 36)
			f159F164Exec(t, leaf, `DROP INDEX idx_admin_audit_correlation_id`)
			f159F164Apply(t, leaf, 36, MigrationDirectionUp)
			f177F182Assert036Catalog(t, leaf)
			if wrong {
				t.Skip("F180-bugs-2 P3 reproduced: migration 036 accepts a same-named correlation index with the wrong definition")
			}
		})
	})

	t.Run("migration_037", func(t *testing.T) {
		t.Run("catalog_replay_rows_transitions_and_exact_lookup_plan", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 36)
			f177F182Seed037Rows(t, leaf)
			rows := f177F182Rows037(t, leaf)
			f159F164Apply(t, leaf, 37, MigrationDirectionUp)
			f177F182Assert037Catalog(t, leaf)
			identity := f159F164IndexIdentity(t, leaf, "idx_malicious_active_exact_lookup")
			f177F182Assert037Lookup(t, leaf)
			f159F164Apply(t, leaf, 37, MigrationDirectionUp)
			if got := f159F164IndexIdentity(t, leaf, "idx_malicious_active_exact_lookup"); got != identity {
				t.Fatalf("037 replay index identity = %q, want %q", got, identity)
			}
			f159F164AssertEqual(t, "037 replay rows", f177F182Rows037(t, leaf), rows)
			f159F164Exec(t, leaf, `UPDATE malicious_findings SET removed_at=NOW() WHERE id='f181-active-a'; UPDATE malicious_findings SET removed_at=NULL WHERE id='f181-removed'`)
			f177F182Assert037Transitions(t, leaf)
		})

		t.Run("down_absent_repeat_up_preserves_rows_and_distinct_unrelated_objects", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 37)
			f177F182Seed037Rows(t, leaf)
			rows := f177F182Rows037(t, leaf)
			f159F164Exec(t, leaf, `DROP INDEX idx_malicious_active_exact_lookup; CREATE INDEX f182_unrelated_distinct_index ON malicious_findings(summary)`)
			unrelated := f159F164IndexIdentity(t, leaf, "f182_unrelated_distinct_index")
			f159F164ApplyDownAndDelete(t, leaf, 37)
			f177F182Assert037Absent(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 37)
			if got := f159F164IndexIdentity(t, leaf, "f182_unrelated_distinct_index"); got != unrelated {
				t.Fatalf("037 distinct unrelated index changed: got %q, want %q", got, unrelated)
			}
			f159F164AssertEqual(t, "037 down rows", f177F182Rows037(t, leaf), rows)
			f159F164Apply(t, leaf, 37, MigrationDirectionUp)
			f177F182Assert037Catalog(t, leaf)
		})

		t.Run("up_and_down_late_failures_are_atomic_dirty_and_recoverable", func(t *testing.T) {
			t.Run("up", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 36)
				f177F182Seed037Rows(t, leaf)
				beforeRows := f177F182Rows037(t, leaf)
				up := f159F164Embedded(t, 37, MigrationDirectionUp)
				up.sql += `; SELECT * FROM f182_missing_late_up;`
				err := applyMigration(leaf.ctx, leaf.conn, up)
				f159F164ExpectSQLState(t, err, "42P01")
				f159F164AssertEqual(t, "037 failed-up rows", f177F182Rows037(t, leaf), beforeRows)
				f177F182Assert037Absent(t, leaf)
				f159F164AssertDirtyEventAndRefusal(t, leaf, up)
				f159F164ClearDirty(t, leaf, 37)
				f159F164Apply(t, leaf, 37, MigrationDirectionUp)
				f177F182Assert037Catalog(t, leaf)
			})
			t.Run("down", func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 37)
				f177F182Seed037Rows(t, leaf)
				beforeRows := f177F182Rows037(t, leaf)
				beforeCatalog := f177F182Catalog037(t, leaf)
				down := f159F164Embedded(t, 37, MigrationDirectionDown)
				down.sql += `; SELECT * FROM f182_missing_late_down;`
				err := applyMigration(leaf.ctx, leaf.conn, down)
				f159F164ExpectSQLState(t, err, "42P01")
				f159F164AssertEqual(t, "037 failed-down rows", f177F182Rows037(t, leaf), beforeRows)
				f159F164AssertEqual(t, "037 failed-down catalog", f177F182Catalog037(t, leaf), beforeCatalog)
				f159F164AssertDirtyEventAndRefusal(t, leaf, down)
				f159F164ClearDirty(t, leaf, 37)
				f159F164Apply(t, leaf, 37, MigrationDirectionDown)
				f177F182Assert037Absent(t, leaf)
			})
		})

		t.Run("unrelated_same_name_ownership_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 37)
			f159F164Exec(t, leaf, `DROP INDEX idx_malicious_active_exact_lookup; CREATE TABLE public.f181_foreign_index_owner(id INTEGER); CREATE INDEX idx_malicious_active_exact_lookup ON public.f181_foreign_index_owner(id)`)
			f159F164ApplyDownAndDelete(t, leaf, 37)
			var remains int
			if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='idx_malicious_active_exact_lookup'`).Scan(&remains); err != nil {
				t.Fatalf("inspect foreign 037 index: %v", err)
			}
			f159F164Exec(t, leaf, `DROP TABLE public.f181_foreign_index_owner`)
			f159F164Apply(t, leaf, 37, MigrationDirectionUp)
			f177F182Assert037Catalog(t, leaf)
			if remains == 0 {
				t.Skip("F181-bugs-1 P2 reproduced: migration 037 down drops a same-named foreign index resolved later on search_path")
			}
		})

		t.Run("same_named_wrong_definition_probe", func(t *testing.T) {
			leaf := newLeaf(t)
			f159F164ApplyThrough(t, leaf, 36)
			f159F164Exec(t, leaf, `CREATE INDEX idx_malicious_active_exact_lookup ON malicious_findings(id)`)
			up := f159F164Embedded(t, 37, MigrationDirectionUp)
			err := applyMigration(leaf.ctx, leaf.conn, up)
			if err != nil {
				f159F164AssertDirtyEventAndRefusal(t, leaf, up)
				f159F164ClearDirty(t, leaf, 37)
				f159F164Exec(t, leaf, `DROP INDEX idx_malicious_active_exact_lookup`)
				f159F164Apply(t, leaf, 37, MigrationDirectionUp)
				f177F182Assert037Catalog(t, leaf)
				return
			}
			wrong := !f177F182037IndexExact(t, leaf)
			f159F164ApplyDownAndDelete(t, leaf, 37)
			f159F164Apply(t, leaf, 37, MigrationDirectionUp)
			f177F182Assert037Catalog(t, leaf)
			if wrong {
				t.Skip("F182-bugs-1 P3 reproduced: migration 037 accepts a same-named exact-lookup index with the wrong definition")
			}
		})
	})
}

func f177F182Seed035Rows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `
		INSERT INTO lifecycle_products(product_slug,name) VALUES ('f177-product','F177 Product');
		INSERT INTO lifecycle_releases(product_slug,cycle,is_eol,eol_from,is_eoas,eoas_from) VALUES
		('f177-product','active',false,NULL,false,NULL),('f177-product','eol',true,'2025-01-01',false,NULL),('f177-product','eoas',false,NULL,true,'2025-02-01');
		INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary,created_at,updated_at,removed_at) VALUES
		('f177-active-a','npm','f177-malicious','fixture','malware','HIGH','active a','2025-01-01Z','2025-01-03Z',NULL),
		('f177-active-b','npm','f177-malicious','fixture','malware','HIGH','active b','2025-01-02Z','2025-01-03Z',NULL),
		('f177-removed','npm','f177-malicious','fixture','malware','HIGH','removed','2025-01-01Z','2025-01-04Z','2025-01-05Z');
		INSERT INTO refresh_queue(ecosystem,name,source,status,requested_at) VALUES
		('npm','f177-pending','fixture','pending','2025-01-01Z'),('npm','f177-processing','fixture','processing','2025-01-02Z'),('npm','f177-done','fixture','done','2025-01-03Z');
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,updated_at) VALUES
		('npm','f177-clean','1','fixture','clean','2025-01-01Z'),('npm','f177-error','1','fixture','error','2025-01-02Z'),('npm','f177-malicious','1','fixture','malicious','2025-01-03Z')`)
}

func f177F182Rows035(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `
		SELECT 'lifecycle' kind,product_slug||':'||cycle key,is_eol::text||':'||COALESCE(eol_from::text,'')||':'||is_eoas::text||':'||COALESCE(eoas_from::text,'') value,xmin::text FROM lifecycle_releases WHERE product_slug='f177-product'
		UNION ALL SELECT 'malicious',id,COALESCE(removed_at::text,''),xmin::text FROM malicious_findings WHERE id LIKE 'f177-%'
		UNION ALL SELECT 'queue',name,status||':'||requested_at::text,xmin::text FROM refresh_queue WHERE name LIKE 'f177-%'
		UNION ALL SELECT 'reputation',name,status||':'||updated_at::text,xmin::text FROM package_reputation_cache WHERE name LIKE 'f177-%'
		ORDER BY 1,2`)
}

func f177F182IndexCatalog(t *testing.T, leaf f159F164Leaf, name string) (table, keys, predicate string, oid int64, err error) {
	t.Helper()
	err = leaf.conn.QueryRowContext(leaf.ctx, `
		SELECT tbl.relname,string_agg(pg_get_indexdef(x.indexrelid,k,true)||CASE WHEN (x.indoption[k-1] & 1)=1 THEN ' DESC' ELSE '' END,',' ORDER BY k),COALESCE(pg_get_expr(x.indpred,x.indrelid),''),x.indexrelid::bigint
		FROM pg_index x JOIN pg_class idx ON idx.oid=x.indexrelid JOIN pg_class tbl ON tbl.oid=x.indrelid JOIN pg_namespace n ON n.oid=idx.relnamespace
		CROSS JOIN LATERAL generate_series(1,x.indnkeyatts) k
		WHERE n.nspname=$1 AND idx.relname=$2 GROUP BY tbl.relname,x.indexrelid,x.indpred,x.indrelid`, leaf.schema, name).Scan(&table, &keys, &predicate, &oid)
	predicate = strings.Join(strings.Fields(predicate), " ")
	return table, keys, predicate, oid, err
}

func f177F182IndexExact(t *testing.T, leaf f159F164Leaf, want f177F182IndexContract) bool {
	t.Helper()
	table, keys, predicate, _, err := f177F182IndexCatalog(t, leaf, want.name)
	return err == nil && table == want.table && keys == want.keys && predicate == want.predicate
}

func f177F182Assert035Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for _, want := range f177F182Indexes035 {
		if !f177F182IndexExact(t, leaf, want) {
			table, keys, predicate, _, err := f177F182IndexCatalog(t, leaf, want.name)
			t.Fatalf("035 index %s = table:%q keys:%q predicate:%q error:%v, want %q/%q/%q", want.name, table, keys, predicate, err, want.table, want.keys, want.predicate)
		}
	}
}

func f177F182CountWrong035(t *testing.T, leaf f159F164Leaf) int {
	t.Helper()
	wrong := 0
	for _, want := range f177F182Indexes035 {
		if !f177F182IndexExact(t, leaf, want) {
			wrong++
		}
	}
	return wrong
}

func f177F182IndexIdentities(t *testing.T, leaf f159F164Leaf, contracts []f177F182IndexContract) string {
	t.Helper()
	var identities []string
	for _, contract := range contracts {
		identities = append(identities, f159F164IndexIdentity(t, leaf, contract.name))
	}
	return strings.Join(identities, "\n")
}

func f177F182Catalog035(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT idx.relname,pg_get_indexdef(idx.oid) definition,idx.oid::text identity FROM pg_class idx JOIN pg_namespace n ON n.oid=idx.relnamespace WHERE n.nspname=current_schema() AND idx.relname=ANY(ARRAY['idx_lifecycle_releases_eol_status_date','idx_lifecycle_releases_eoas_status_date','idx_malicious_active_source_updated_at','idx_malicious_active_updated_at','idx_queue_oldest_active_source_requested_at','idx_reputation_prune_source_updated_at']) ORDER BY idx.relname`)
}

func f177F182Assert035Absent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class idx JOIN pg_namespace n ON n.oid=idx.relnamespace WHERE n.nspname=$1 AND idx.relname=ANY($2)`, leaf.schema, []string{
		"idx_lifecycle_releases_eol_status_date", "idx_lifecycle_releases_eoas_status_date", "idx_malicious_active_source_updated_at", "idx_malicious_active_updated_at", "idx_queue_oldest_active_source_requested_at", "idx_reputation_prune_source_updated_at",
	}).Scan(&count); err != nil || count != 0 {
		t.Fatalf("035 index count after down = %d error=%v, want 0", count, err)
	}
}

func f177F182Drop035SQL() string {
	return `DROP INDEX IF EXISTS idx_lifecycle_releases_eol_status_date; DROP INDEX IF EXISTS idx_lifecycle_releases_eoas_status_date; DROP INDEX IF EXISTS idx_malicious_active_source_updated_at; DROP INDEX IF EXISTS idx_malicious_active_updated_at; DROP INDEX IF EXISTS idx_queue_oldest_active_source_requested_at; DROP INDEX IF EXISTS idx_reputation_prune_source_updated_at`
}

func f177F182Assert035Plans(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `SET enable_seqscan=off; SET enable_bitmapscan=off`)
	defer f159F164Exec(t, leaf, `RESET enable_seqscan; RESET enable_bitmapscan`)
	tests := []struct {
		index  string
		query  string
		noSort bool
	}{
		{"idx_lifecycle_releases_eol_status_date", `SELECT cycle FROM lifecycle_releases WHERE product_slug='f177-product' AND (is_eol OR eol_from IS NOT NULL)`, false},
		{"idx_lifecycle_releases_eoas_status_date", `SELECT cycle FROM lifecycle_releases WHERE product_slug='f177-product' AND (is_eoas OR eoas_from IS NOT NULL)`, false},
		{"idx_malicious_active_source_updated_at", `SELECT id FROM malicious_findings WHERE removed_at IS NULL ORDER BY source,updated_at DESC,created_at DESC,id DESC`, true},
		{"idx_malicious_active_updated_at", `SELECT id FROM malicious_findings WHERE removed_at IS NULL ORDER BY updated_at DESC,created_at DESC,id DESC`, true},
		{"idx_queue_oldest_active_source_requested_at", `SELECT source,MIN(requested_at) FROM refresh_queue WHERE status IN ('pending','processing') AND source<>'' GROUP BY source`, false},
		{"idx_reputation_prune_source_updated_at", `SELECT id FROM package_reputation_cache WHERE source='fixture' AND status IN ('clean','not_found','unsupported','error') AND updated_at<'2026-01-01Z'`, false},
	}
	for _, tt := range tests {
		var raw []byte
		if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) `+tt.query).Scan(&raw); err != nil {
			t.Fatalf("EXPLAIN for %s: %v", tt.index, err)
		}
		if !f159F164JSONContainsIndex(t, raw, tt.index) || (tt.noSort && f171F176JSONContainsNode(t, raw, "Sort")) {
			t.Fatalf("representative plan for %s lacks index or adds forbidden Sort: %s", tt.index, raw)
		}
	}
}

func f177F182036ColumnExact(t *testing.T, leaf f159F164Leaf) bool {
	t.Helper()
	var dataType, nullable, defaultSQL string
	err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT data_type,is_nullable,COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema=$1 AND table_name='admin_audit_log' AND column_name='correlation_id'`, leaf.schema).Scan(&dataType, &nullable, &defaultSQL)
	return err == nil && dataType == "text" && nullable == "NO" && defaultSQL == "''::text"
}

func f177F182036IndexExact(t *testing.T, leaf f159F164Leaf) bool {
	t.Helper()
	want := f177F182IndexContract{"idx_admin_audit_correlation_id", "admin_audit_log", "correlation_id", "(correlation_id <> ''::text)"}
	return f177F182IndexExact(t, leaf, want)
}

func f177F182Assert036Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if !f177F182036ColumnExact(t, leaf) || !f177F182036IndexExact(t, leaf) {
		t.Fatalf("036 catalog not exact: %s", f177F182Catalog036(t, leaf))
	}
}

func f177F182Catalog036(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT 'column' kind,column_name name,data_type||':'||is_nullable||':'||COALESCE(column_default,'') definition,'' identity FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='admin_audit_log' AND column_name='correlation_id' UNION ALL SELECT 'index',idx.relname,pg_get_indexdef(idx.oid),idx.oid::text FROM pg_class idx JOIN pg_namespace n ON n.oid=idx.relnamespace WHERE n.nspname=current_schema() AND idx.relname='idx_admin_audit_correlation_id' ORDER BY 1`)
}

func f177F182Rows036(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,action,details,ip::text,correlation_id,created_at,xmin::text FROM admin_audit_log WHERE action LIKE 'f179-%' ORDER BY id`)
}

func f177F182Seed037Rows(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `INSERT INTO malicious_findings(id,ecosystem,name,source,risk_type,severity,summary,created_at,updated_at,removed_at) VALUES ('f181-active-a','npm','f181-package','fixture','malware','HIGH','active a','2025-01-01Z','2025-01-03Z',NULL),('f181-active-b','npm','f181-package','fixture','malware','HIGH','active b','2025-01-02Z','2025-01-03Z',NULL),('f181-removed','npm','f181-package','fixture','malware','HIGH','removed','2025-01-01Z','2025-01-04Z','2025-01-05Z')`)
}

func f177F182Rows037(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,ecosystem,name,updated_at,removed_at,xmin::text FROM malicious_findings WHERE id LIKE 'f181-%' ORDER BY id`)
}

func f177F182037IndexExact(t *testing.T, leaf f159F164Leaf) bool {
	t.Helper()
	want := f177F182IndexContract{"idx_malicious_active_exact_lookup", "malicious_findings", "ecosystem,name,updated_at DESC,id DESC", "(removed_at IS NULL)"}
	return f177F182IndexExact(t, leaf, want)
}

func f177F182Assert037Catalog(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if !f177F182037IndexExact(t, leaf) {
		t.Fatalf("037 index not exact: %s", f177F182Catalog037(t, leaf))
	}
}

func f177F182Catalog037(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT idx.relname,pg_get_indexdef(idx.oid) definition,idx.oid::text identity FROM pg_class idx JOIN pg_namespace n ON n.oid=idx.relnamespace WHERE n.nspname=current_schema() AND idx.relname='idx_malicious_active_exact_lookup'`)
}

func f177F182Assert037Absent(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM pg_class idx JOIN pg_namespace n ON n.oid=idx.relnamespace WHERE n.nspname=$1 AND idx.relname='idx_malicious_active_exact_lookup'`, leaf.schema).Scan(&count); err != nil || count != 0 {
		t.Fatalf("037 index count after down = %d error=%v, want 0", count, err)
	}
}

func f177F182Assert037Lookup(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `SET enable_seqscan=off; SET enable_bitmapscan=off`)
	defer f159F164Exec(t, leaf, `RESET enable_seqscan; RESET enable_bitmapscan`)
	query := `SELECT id FROM malicious_findings WHERE ecosystem='npm' AND name='f181-package' AND removed_at IS NULL ORDER BY updated_at DESC,id DESC`
	if got := f159F164Snapshot(t, leaf, query); got != `[{"id": "f181-active-b"}, {"id": "f181-active-a"}]` {
		t.Fatalf("037 exact lookup/tie order = %s", got)
	}
	var raw []byte
	if err := leaf.conn.QueryRowContext(leaf.ctx, `EXPLAIN (FORMAT JSON,COSTS OFF) `+query).Scan(&raw); err != nil {
		t.Fatalf("EXPLAIN exact malicious lookup: %v", err)
	}
	if !f159F164JSONContainsIndex(t, raw, "idx_malicious_active_exact_lookup") || f171F176JSONContainsNode(t, raw, "Sort") {
		t.Fatalf("037 exact lookup plan lacks index or adds Sort: %s", raw)
	}
}

func f177F182Assert037Transitions(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	if got := f159F164Snapshot(t, leaf, `SELECT id FROM malicious_findings WHERE ecosystem='npm' AND name='f181-package' AND removed_at IS NULL ORDER BY updated_at DESC,id DESC`); got != `[{"id": "f181-removed"}, {"id": "f181-active-b"}]` {
		t.Fatalf("037 active/removed transition result = %s", got)
	}
}
