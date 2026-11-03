//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestF217VulnerabilityReadsRejectQueryScanAndIterationFaults(t *testing.T) {
	_, dsn := startDockerPostgresStore(t)
	ctx := context.Background()
	packages := []db.PackageQuery{
		{Ecosystem: "pypi", Name: " F217_Read ", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "f217-read", Version: "1.0.0"},
	}

	for _, mode := range []string{"scan", "rows"} {
		t.Run(mode, func(t *testing.T) {
			store := f217VulnerabilityReadShadow(t, dsn, mode)
			single, singleErr := store.FindVulnerabilities(ctx, "pypi", " F217_Read ", "1.0.0")
			batch, batchErr := store.FindVulnerabilitiesBatch(ctx, packages)
			if single != nil || batch != nil {
				t.Fatalf("%s faults returned partial findings: single=%+v batch=%+v", mode, single, batch)
			}
			if mode == "scan" {
				for label, check := range map[string]struct {
					err    error
					prefix string
				}{
					"single": {singleErr, "postgres: scan vulnerability row:"},
					"batch":  {batchErr, "postgres: scan vulnerability batch row:"},
				} {
					if check.err == nil || !strings.HasPrefix(check.err.Error(), check.prefix) {
						t.Fatalf("%s scan error = %v, want prefix %q", label, check.err, check.prefix)
					}
				}
				return
			}

			for label, check := range map[string]struct {
				err    error
				prefix string
			}{
				"single": {singleErr, "postgres: iterate vulnerabilities:"},
				"batch":  {batchErr, "postgres: iterate vulnerabilities batch:"},
			} {
				if check.err == nil || !strings.HasPrefix(check.err.Error(), check.prefix) {
					t.Fatalf("%s iteration error = %v, want prefix %q", label, check.err, check.prefix)
				}
				f106RequirePgError(t, check.err, "P6217", "f217 vulnerability rows marker")
			}
		})
	}

	closed, err := New(ctx, dsn, nil, nil)
	if err != nil {
		t.Fatalf("open query-fault store: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close query-fault store: %v", err)
	}
	if got, err := closed.FindVulnerabilities(ctx, "pypi", "f217-read", "1"); got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: find vulnerabilities:") {
		t.Fatalf("FindVulnerabilities(closed) = %+v, %v", got, err)
	}
	if got, err := closed.FindVulnerabilitiesBatch(ctx, packages); got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: find vulnerabilities batch:") {
		t.Fatalf("FindVulnerabilitiesBatch(closed) = %+v, %v", got, err)
	}
}

func TestF217VulnerabilityWriteAtomicityOwnershipAndCacheInvalidation(t *testing.T) {
	store, dsn := startDockerPostgresStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	generation := dashboardStatsCacheGeneration(store)

	t.Run("known null-element validator gap is rejected atomically by PostgreSQL", func(t *testing.T) {
		vuln := f217CompleteVulnerability()
		vuln.ID = "GHSA-F217-NULL-DB"
		vuln.Sources[0].SourceID = vuln.ID
		vuln.AffectedPackages[0].VersionsAffected = json.RawMessage(`["1.0.0",null]`)
		err := store.UpsertVulnerability(ctx, vuln)
		if err == nil {
			t.Fatal("UpsertVulnerability(null array element) error = nil, want PostgreSQL CHECK rejection")
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("UpsertVulnerability(null array element) error = %v, want SQLSTATE 23514", err)
		}
		f217AssertVulnerabilityAbsent(t, store, vuln.ID)
		if got := dashboardStatsCacheGeneration(store); got != generation {
			t.Fatalf("cache generation after rejected null element = %d, want %d", got, generation)
		}
	})

	base := db.Vulnerability{
		ID:        "GHSA-F217-BASE",
		Summary:   "f217 committed base",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources:   []db.VulnerabilitySource{{Source: "osv", SourceID: "GHSA-F217-BASE"}},
		References: []db.VulnerabilityReference{{
			Type: "ADVISORY", URL: "https://example.test/f217-base", Source: "osv",
		}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "pypi", Name: "F217_Read",
			VersionRanges:    json.RawMessage(`[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}
	imported, deleted, err := store.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{base}, nil, nil)
	if err != nil || imported != 1 || deleted != 0 {
		t.Fatalf("ImportVulnerabilityFeed(base) = %d, %d, %v; want 1, 0, nil", imported, deleted, err)
	}
	generation++
	if got := dashboardStatsCacheGeneration(store); got != generation {
		t.Fatalf("cache generation after committed import = %d, want %d", got, generation)
	}

	findings, err := store.FindVulnerabilities(ctx, "pypi", " F217_Read ", "1.0.0")
	if err != nil || len(findings) != 1 || findings[0].AdvisoryID != base.ID || findings[0].Source != "osv" || findings[0].URL != "https://github.com/advisories/GHSA-F217-BASE" || findings[0].FixedVersion != ">= 2.0.0" || len(findings[0].Resources) != 2 || findings[0].Resources[1].URL != "https://example.test/f217-base" {
		t.Fatalf("FindVulnerabilities(committed) = %+v, %v", findings, err)
	}
	if unaffected, err := store.FindVulnerabilities(ctx, "pypi", "f217-read", "2.0.0"); err != nil || len(unaffected) != 0 {
		t.Fatalf("FindVulnerabilities(unaffected) = %+v, %v; want empty success", unaffected, err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id,summary,severity,published,modified)
		VALUES('GHSA-F217-FALLBACK','','LOW',NOW(),NOW());
		INSERT INTO affected_packages(vulnerability_id,ecosystem,name,version_ranges,versions_affected)
		VALUES('GHSA-F217-FALLBACK','npm','f217-fallback','[]','[]')`); err != nil {
		t.Fatalf("seed fallback finding: %v", err)
	}
	fallback, err := store.FindVulnerabilities(ctx, "npm", "f217-fallback", "")
	if err != nil || len(fallback) != 1 || fallback[0].Title != "GHSA-F217-FALLBACK" || fallback[0].Source != "unknown" {
		t.Fatalf("FindVulnerabilities(fallbacks) = %+v, %v", fallback, err)
	}
	batch, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: " F217_Read ", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "f217-read", Version: "1.0.0"},
		{Ecosystem: "pypi", Name: "f217-read", Version: "2.0.0"},
	})
	if err != nil || len(batch) != 1 || batch[0].Version != "1.0.0" || batch[0].AdvisoryID != base.ID {
		t.Fatalf("FindVulnerabilitiesBatch(dedup/version filter) = %+v, %v", batch, err)
	}

	t.Run("late invalid import rolls back earlier item", func(t *testing.T) {
		first := base
		first.ID = "GHSA-F217-PARTIAL-FIRST"
		first.Sources = []db.VulnerabilitySource{{Source: "osv", SourceID: first.ID}}
		first.AffectedPackages = []db.AffectedPackage{{Ecosystem: "npm", Name: "f217-partial-first"}}
		second := first
		second.ID = "GHSA-F217-PARTIAL-BAD"
		second.Sources = []db.VulnerabilitySource{{Source: "osv", SourceID: second.ID}}
		second.AffectedPackages = []db.AffectedPackage{{Ecosystem: "npm", Name: "f217-partial-bad", VersionRanges: json.RawMessage(`{}`)}}
		_, _, err := store.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{first, second}, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "GHSA-F217-PARTIAL-BAD version_ranges") {
			t.Fatalf("ImportVulnerabilityFeed(late invalid item) error = %v", err)
		}
		f217AssertVulnerabilityAbsent(t, store, first.ID)
		f217AssertVulnerabilityAbsent(t, store, second.ID)
		if got := dashboardStatsCacheGeneration(store); got != generation {
			t.Fatalf("cache generation after late validation rollback = %d, want %d", got, generation)
		}
	})

	t.Run("deferred commit fault rolls back import", func(t *testing.T) {
		const id = "GHSA-F217-COMMIT-FAIL"
		f217InstallDeferredFault(t, store.pool, "vulnerabilities", "INSERT", "f217_fail_vulnerability_commit", "NEW.id = '"+id+"'")
		item := base
		item.ID = id
		item.Sources = []db.VulnerabilitySource{{Source: "osv", SourceID: id}}
		item.AffectedPackages = []db.AffectedPackage{{Ecosystem: "npm", Name: "f217-commit-fail"}}
		_, _, err := store.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{item}, nil, nil)
		if err == nil || !strings.HasPrefix(err.Error(), "commit tx:") {
			t.Fatalf("ImportVulnerabilityFeed(commit fault) error = %v, want commit wrapper", err)
		}
		f106RequirePgError(t, err, "P6217", "f217 deferred fault")
		f217AssertVulnerabilityAbsent(t, store, id)
		if got := dashboardStatsCacheGeneration(store); got != generation {
			t.Fatalf("cache generation after failed commit = %d, want %d", got, generation)
		}
	})

	t.Run("late imported delete failure rolls back all changes", func(t *testing.T) {
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO vulnerabilities(id,summary,severity,published,modified) VALUES
				('GHSA-F217-DELETE-FIRST','first','HIGH',NOW(),NOW()),
				('GHSA-F217-DELETE-LATE','late','HIGH',NOW(),NOW());
			INSERT INTO vulnerability_sources(vulnerability_id,source,source_id) VALUES
				('GHSA-F217-DELETE-FIRST','osv','GHSA-F217-DELETE-FIRST'),
				('GHSA-F217-DELETE-LATE','osv','GHSA-F217-DELETE-LATE')`); err != nil {
			t.Fatalf("seed import-delete rollback: %v", err)
		}
		f106InstallTrigger(t, store.pool, "vulnerabilities", "UPDATE", "f217_fail_late_import_delete", "P6217", "OLD.id = 'GHSA-F217-DELETE-LATE' AND NEW.withdrawn IS NOT NULL")
		item := base
		item.ID = "GHSA-F217-DELETE-NEW"
		item.Sources = []db.VulnerabilitySource{{Source: "osv", SourceID: item.ID}}
		item.AffectedPackages = []db.AffectedPackage{{Ecosystem: "npm", Name: "f217-delete-new"}}
		_, _, err := store.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{item}, []string{"GHSA-F217-DELETE-FIRST", "GHSA-F217-DELETE-LATE"}, nil)
		if err == nil || !strings.Contains(err.Error(), "delete imported vulnerability GHSA-F217-DELETE-LATE") {
			t.Fatalf("ImportVulnerabilityFeed(late delete fault) error = %v", err)
		}
		f217AssertVulnerabilityAbsent(t, store, item.ID)
		f217AssertVulnerabilityState(t, store, "GHSA-F217-DELETE-FIRST", []string{"osv"}, false)
		f217AssertVulnerabilityState(t, store, "GHSA-F217-DELETE-LATE", []string{"osv"}, false)
		if got := dashboardStatsCacheGeneration(store); got != generation {
			t.Fatalf("cache generation after imported-delete rollback = %d, want %d", got, generation)
		}
	})

	t.Run("source ownership and delete rollback", func(t *testing.T) {
		owned := base
		owned.ID = "GHSA-F217-OWNED"
		owned.Sources = []db.VulnerabilitySource{
			{Source: "osv", SourceID: "GHSA-F217-OWNED-OSV"},
			{Source: "ghsa", SourceID: "GHSA-F217-OWNED-GHSA"},
		}
		owned.AffectedPackages = []db.AffectedPackage{{Ecosystem: "npm", Name: "f217-owned"}}
		if err := store.UpsertVulnerability(ctx, &owned); err != nil {
			t.Fatalf("UpsertVulnerability(owned): %v", err)
		}
		generation++
		if err := store.DeleteVulnerabilityForSource(ctx, owned.ID, " osv "); err != nil {
			t.Fatalf("DeleteVulnerabilityForSource(first owner): %v", err)
		}
		generation++
		f217AssertVulnerabilityState(t, store, owned.ID, []string{"ghsa"}, false)

		f217InstallDeferredFault(t, store.pool, "vulnerability_sources", "DELETE", "f217_fail_source_delete_commit", "OLD.vulnerability_id = '"+owned.ID+"' AND OLD.source = 'ghsa'")
		err := store.DeleteVulnerabilityForSource(ctx, owned.ID, "ghsa")
		if err == nil || !strings.HasPrefix(err.Error(), "commit tx:") {
			t.Fatalf("DeleteVulnerabilityForSource(commit fault) error = %v, want commit wrapper", err)
		}
		f217AssertVulnerabilityState(t, store, owned.ID, []string{"ghsa"}, false)
		if got := dashboardStatsCacheGeneration(store); got != generation {
			t.Fatalf("cache generation after source-delete commit fault = %d, want %d", got, generation)
		}

		f106InstallTrigger(t, store.pool, "vulnerabilities", "UPDATE", "f217_fail_conditional_withdraw", "P6217", "OLD.id = '"+owned.ID+"' AND NEW.withdrawn IS NOT NULL")
		err = store.DeleteVulnerabilityForSource(ctx, owned.ID, "ghsa")
		if err == nil || !strings.Contains(err.Error(), "withdraw vulnerability "+owned.ID+" after source delete") {
			t.Fatalf("DeleteVulnerabilityForSource(withdraw fault) error = %v", err)
		}
		f217AssertVulnerabilityState(t, store, owned.ID, []string{"ghsa"}, false)
		if got := dashboardStatsCacheGeneration(store); got != generation {
			t.Fatalf("cache generation after source-delete rollback = %d, want %d", got, generation)
		}
	})

	closed, err := New(ctx, dsn, nil, nil)
	if err != nil {
		t.Fatalf("open begin-fault store: %v", err)
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("close begin-fault store: %v", err)
	}
	closedGeneration := dashboardStatsCacheGeneration(closed)
	if _, _, err := closed.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{base}, nil, nil); err == nil || !strings.HasPrefix(err.Error(), "begin tx:") {
		t.Fatalf("ImportVulnerabilityFeed(begin fault) error = %v", err)
	}
	if err := closed.DeleteVulnerabilityForSource(ctx, base.ID, "osv"); err == nil || !strings.HasPrefix(err.Error(), "begin tx:") {
		t.Fatalf("DeleteVulnerabilityForSource(begin fault) error = %v", err)
	}
	if got := dashboardStatsCacheGeneration(closed); got != closedGeneration {
		t.Fatalf("closed-store cache generation = %d, want %d", got, closedGeneration)
	}
}

func f217VulnerabilityReadShadow(t *testing.T, dsn, mode string) *Store {
	t.Helper()
	return f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
		f106MirrorRelations(t, ctx, pool, schema, "vulnerabilities", "vulnerability_sources", "vulnerability_references")
		base := quoteIdentifier(schema) + ".affected_packages_base"
		if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE public.affected_packages INCLUDING ALL)", base)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`
			INSERT INTO %s.vulnerabilities(id,summary,severity,published,modified) VALUES
				('GHSA-F217-GOOD','good','HIGH',NOW()-interval '1 day',NOW()),
				('GHSA-F217-BAD','bad','HIGH',NOW()-interval '1 day',NOW()-interval '1 second');
			INSERT INTO %s.vulnerability_sources(vulnerability_id,source,source_id) VALUES
				('GHSA-F217-GOOD','osv','GHSA-F217-GOOD'),
				('GHSA-F217-BAD','osv','GHSA-F217-BAD');
			INSERT INTO %s(vulnerability_id,ecosystem,name,version_ranges,versions_affected) VALUES
				('GHSA-F217-GOOD','pypi','f217-read','[]','["1.0.0"]'),
				('GHSA-F217-BAD','pypi','f217-read','[]','["1.0.0"]')`,
			quoteIdentifier(schema), quoteIdentifier(schema), base)); err != nil {
			t.Fatal(err)
		}

		rangeExpr := "version_ranges"
		switch mode {
		case "scan":
			rangeExpr = "CASE WHEN vulnerability_id='GHSA-F217-BAD' THEN NULL::jsonb ELSE version_ranges END"
		case "rows":
			if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.f217_vulnerability_rows_marker(value jsonb,vulnerability text) RETURNS jsonb LANGUAGE plpgsql AS $fn$
			BEGIN IF vulnerability='GHSA-F217-BAD' THEN RAISE EXCEPTION USING ERRCODE='P6217',MESSAGE='f217 vulnerability rows marker'; END IF; RETURN value; END $fn$`, quoteIdentifier(schema))); err != nil {
				t.Fatal(err)
			}
			rangeExpr = fmt.Sprintf("%s.f217_vulnerability_rows_marker(version_ranges,vulnerability_id)", quoteIdentifier(schema))
		default:
			t.Fatalf("unsupported vulnerability read-shadow mode %q", mode)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE VIEW %s.affected_packages AS
			SELECT id,vulnerability_id,ecosystem,name,%s AS version_ranges,versions_affected
			FROM %s`, quoteIdentifier(schema), rangeExpr, base)); err != nil {
			t.Fatal(err)
		}
	})
}

func f217InstallDeferredFault(t *testing.T, pool *pgxpool.Pool, table, event, name, condition string) {
	t.Helper()
	query := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $fn$
	BEGIN RAISE EXCEPTION USING ERRCODE='P6217',MESSAGE='f217 deferred fault'; END $fn$;
	CREATE CONSTRAINT TRIGGER %s AFTER %s ON %s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (%s) EXECUTE FUNCTION %s()`,
		quoteIdentifier(name+"_fn"), quoteIdentifier(name), event, quoteIdentifier(table), condition, quoteIdentifier(name+"_fn"))
	if _, err := pool.Exec(context.Background(), query); err != nil {
		t.Fatalf("install deferred fault %s: %v", name, err)
	}
}

func f217AssertVulnerabilityAbsent(t *testing.T, store *Store, id string) {
	t.Helper()
	var core, sources, packages int
	if err := store.pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM vulnerabilities WHERE id=$1),
		(SELECT count(*) FROM vulnerability_sources WHERE vulnerability_id=$1),
		(SELECT count(*) FROM affected_packages WHERE vulnerability_id=$1)`, id).Scan(&core, &sources, &packages); err != nil {
		t.Fatalf("inspect absent vulnerability %s: %v", id, err)
	}
	if core != 0 || sources != 0 || packages != 0 {
		t.Fatalf("vulnerability %s partial rows = core:%d sources:%d packages:%d, want zero", id, core, sources, packages)
	}
}

func f217AssertVulnerabilityState(t *testing.T, store *Store, id string, wantSources []string, wantWithdrawn bool) {
	t.Helper()
	var sources []string
	var withdrawn bool
	if err := store.pool.QueryRow(context.Background(), `SELECT
		COALESCE(array_agg(vs.source ORDER BY vs.source) FILTER (WHERE vs.source IS NOT NULL),'{}'),
		v.withdrawn IS NOT NULL
		FROM vulnerabilities v LEFT JOIN vulnerability_sources vs ON vs.vulnerability_id=v.id
		WHERE v.id=$1 GROUP BY v.id`, id).Scan(&sources, &withdrawn); err != nil {
		t.Fatalf("inspect vulnerability %s state: %v", id, err)
	}
	if fmt.Sprint(sources) != fmt.Sprint(wantSources) || withdrawn != wantWithdrawn {
		t.Fatalf("vulnerability %s state = sources:%v withdrawn:%t, want %v/%t", id, sources, withdrawn, wantSources, wantWithdrawn)
	}
}
