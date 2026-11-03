//go:build integration

package postgres

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestF210ReputationReadFailuresReturnNoPartialResults(t *testing.T) {
	_, dsn := startDockerPostgresStore(t)
	ctx := context.Background()
	packages := []db.PackageQuery{
		{Ecosystem: "pypi", Name: " F210_Read ", Version: "1"},
		{Ecosystem: "pypi", Name: "f210-read", Version: "2"},
	}

	for _, mode := range []string{"scan", "rows"} {
		t.Run(mode, func(t *testing.T) {
			store := f210ReputationReadShadow(t, dsn, mode)
			batch, batchErr := store.FindReputationFindingsBatch(ctx, packages, db.ReputationSourceReversingLabs)
			single, singleErr := store.FindReputationFindings(ctx, "pypi", " F210_Read ", db.ReputationSourceReversingLabs)
			due, dueErr := store.ListDuePackageReputations(ctx, "pypi", " F210_Read ", db.ReputationSourceReversingLabs, 10)

			if batch != nil || single != nil || due != nil {
				t.Fatalf("%s read failures returned partial results: batch=%+v single=%+v due=%+v", mode, batch, single, due)
			}
			if mode == "scan" {
				for label, check := range map[string]struct {
					err    error
					prefix string
				}{
					"batch":  {batchErr, "postgres: scan reputation row:"},
					"single": {singleErr, "postgres: scan reputation row:"},
					"due":    {dueErr, "postgres: scan due reputation row:"},
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
				"batch":  {batchErr, "postgres: iterate reputation findings:"},
				"single": {singleErr, "postgres: iterate reputation findings:"},
				"due":    {dueErr, "postgres: iterate due reputation rows:"},
			} {
				if check.err == nil || !strings.HasPrefix(check.err.Error(), check.prefix) {
					t.Fatalf("%s iteration error = %v, want prefix %q", label, check.err, check.prefix)
				}
				f106RequirePgError(t, check.err, "P6210", "f210 reputation rows marker")
			}
		})
	}
}

func TestF210ReputationPostgresContractsAndWriteFaults(t *testing.T) {
	_, dsn := startDockerPostgresStore(t)
	store := f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
		f106MirrorRelations(t, ctx, pool, schema, "package_reputation_cache")
	})
	ctx := context.Background()
	generation := dashboardStatsCacheGeneration(store)

	f106InstallTrigger(t, store.pool, "package_reputation_cache", "INSERT", "f210_fail_reputation_write", "P6211", "NEW.name IN ('f210-upsert-fail','f210-mark-fail')")
	err := store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem: "npm", Name: "f210-upsert-fail", Version: "1", Source: db.ReputationSourceReversingLabs, Status: "clean", Severity: "LOW",
	})
	f106RequirePgError(t, err, "P6211", "forced f210_fail_reputation_write failure")
	if got := dashboardStatsCacheGeneration(store); got != generation {
		t.Fatalf("cache generation after failed upsert = %d, want %d", got, generation)
	}
	queued, err := store.MarkPackageReputationDue(ctx, &db.PackageReputation{
		Ecosystem: "npm", Name: "f210-mark-fail", Version: "1", Source: db.ReputationSourceReversingLabs,
	})
	if queued {
		t.Fatal("failed MarkPackageReputationDue returned queued=true")
	}
	f106RequirePgError(t, err, "P6211", "forced f210_fail_reputation_write failure")
	var failedRows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM package_reputation_cache WHERE name IN ('f210-upsert-fail','f210-mark-fail')`).Scan(&failedRows); err != nil || failedRows != 0 {
		t.Fatalf("failed reputation writes left %d rows, error=%v", failedRows, err)
	}
	if got := dashboardStatsCacheGeneration(store); got != generation {
		t.Fatalf("cache generation after failed mark-due = %d, want %d", got, generation)
	}

	err = store.UpsertPackageReputation(ctx, &db.PackageReputation{
		Ecosystem:   " PyPI ",
		Name:        " F210_Pkg.Name ",
		Version:     "1.0.0",
		Source:      db.ReputationSourceReversingLabs,
		Status:      " ",
		Severity:    " ",
		Summary:     "  pending package  ",
		Description: "  nullable timestamps  ",
	})
	if err != nil {
		t.Fatalf("UpsertPackageReputation(defaults): %v", err)
	}
	if got := dashboardStatsCacheGeneration(store); got != generation+1 {
		t.Fatalf("cache generation after committed upsert = %d, want %d", got, generation+1)
	}
	var ecosystem, name, status, severity, summary, description, references, evidence string
	var lastChecked, nextCheck *time.Time
	if err := store.pool.QueryRow(ctx, `
		SELECT ecosystem,name,status,severity,summary,description,reference_urls::text,evidence::text,last_checked_at,next_check_at
		FROM package_reputation_cache
		WHERE ecosystem='pypi' AND name='f210-pkg-name' AND version='1.0.0' AND source=$1`, db.ReputationSourceReversingLabs).Scan(
		&ecosystem, &name, &status, &severity, &summary, &description, &references, &evidence, &lastChecked, &nextCheck,
	); err != nil {
		t.Fatalf("read committed reputation defaults: %v", err)
	}
	if ecosystem != "pypi" || name != "f210-pkg-name" || status != reputationStatusPending || severity != "CRITICAL" || summary != "pending package" || description != "nullable timestamps" || references != `[]` || evidence != `{}` || lastChecked != nil || nextCheck != nil {
		t.Fatalf("committed reputation defaults = ecosystem=%q name=%q status=%q severity=%q summary=%q description=%q refs=%s evidence=%s last=%v next=%v", ecosystem, name, status, severity, summary, description, references, evidence, lastChecked, nextCheck)
	}

	queued, err = store.MarkPackageReputationDue(ctx, &db.PackageReputation{
		Ecosystem: "npm", Name: " F210_Mark ", Version: "1", Source: db.ReputationSourceReversingLabs, Severity: "unknown",
	})
	if err != nil || !queued {
		t.Fatalf("MarkPackageReputationDue(new) = %v, %v; want true, nil", queued, err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,next_check_at)
		VALUES
			('npm','f210-future','1',$1,'clean',NOW()+interval '1 hour'),
			('npm','f210-unsupported','1',$1,'unsupported',NOW()-interval '1 hour')`, db.ReputationSourceReversingLabs); err != nil {
		t.Fatalf("seed mark-due exclusions: %v", err)
	}
	for _, coordinate := range []string{"f210-future", "f210-unsupported"} {
		queued, err = store.MarkPackageReputationDue(ctx, &db.PackageReputation{
			Ecosystem: "npm", Name: coordinate, Version: "1", Source: db.ReputationSourceReversingLabs,
		})
		if err != nil || queued {
			t.Fatalf("MarkPackageReputationDue(%s) = %v, %v; want false, nil", coordinate, queued, err)
		}
	}

	f210SeedDueReputations(t, store)
	due, err := store.ListDuePackageReputations(ctx, "pypi", " F210_Due ", db.ReputationSourceReversingLabs, 0)
	if err != nil {
		t.Fatalf("ListDuePackageReputations(default limit): %v", err)
	}
	if len(due) != 5 {
		t.Fatalf("ListDuePackageReputations(default limit) len = %d, want 5", len(due))
	}
	for i, rep := range due {
		wantVersion := fmt.Sprintf("%d", i+1)
		if rep.Version != wantVersion || rep.LastCheckedAt != nil || rep.NextCheckAt == nil || string(rep.ReferenceURLs) != `[]` || string(rep.Evidence) != `{}` {
			t.Fatalf("due[%d] = %+v, want version %s with nullable last_checked_at and JSON defaults", i, rep, wantVersion)
		}
	}
	due, err = store.ListDuePackageReputations(ctx, "pypi", "f210-due", db.ReputationSourceReversingLabs, 1000)
	if err != nil || len(due) != 6 {
		t.Fatalf("ListDuePackageReputations(max clamp) = %d rows, %v; want 6", len(due), err)
	}

	f210SeedFindingReputations(t, store)
	findings, err := store.FindReputationFindings(ctx, "pypi", " F210_Finding ", db.ReputationSourceReversingLabs)
	if err != nil || len(findings) != 3 {
		t.Fatalf("FindReputationFindings() = %+v, %v; want three reportable rows", findings, err)
	}
	if findings[0].Version != "1" || findings[0].Type != domain.FindingTypeMalicious || findings[0].URL != "https://example.test/f210-malicious" || findings[1].Version != "2" || findings[1].RiskType != "removed_package" || findings[2].Version != "3" || findings[2].RiskType != domain.RiskTypeMalwareHistory || findings[2].Severity != domain.SeverityLow {
		t.Fatalf("FindReputationFindings() mappings/order = %+v", findings)
	}
	batch, err := store.FindReputationFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: " F210_Finding ", Version: "1"},
		{Ecosystem: "pypi", Name: "f210-finding", Version: "1"},
		{Ecosystem: "pypi", Name: "f210-finding", Version: "3"},
		{Ecosystem: "", Name: "ignored", Version: "1"},
	}, db.ReputationSourceReversingLabs)
	if err != nil || len(batch) != 2 {
		t.Fatalf("FindReputationFindingsBatch(dedup) = %+v, %v; want two findings", batch, err)
	}

	f210TestPruneRollbackAndBoundaries(t, store, generation+1)
}

func TestF210ReputationQueryAndStatementErrors(t *testing.T) {
	_, dsn := startDockerPostgresStore(t)
	store := f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
		f106MirrorRelations(t, ctx, pool, schema, "package_reputation_cache")
	})
	store.pool.Close()
	ctx := context.Background()

	if got, err := store.FindReputationFindingsBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "f210", Version: "1"}}, "source"); got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: find reputation findings batch:") {
		t.Fatalf("FindReputationFindingsBatch(closed) = %+v, %v", got, err)
	}
	if got, err := store.FindReputationFindings(ctx, "npm", "f210", "source"); got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: find reputation findings:") {
		t.Fatalf("FindReputationFindings(closed) = %+v, %v", got, err)
	}
	if got, err := store.ListDuePackageReputations(ctx, "npm", "f210", "source", 1); got != nil || err == nil || !strings.HasPrefix(err.Error(), "postgres: list due package reputations:") {
		t.Fatalf("ListDuePackageReputations(closed) = %+v, %v", got, err)
	}
	if queued, err := store.MarkPackageReputationDue(ctx, &db.PackageReputation{Ecosystem: "npm", Name: "f210", Version: "1", Source: "source"}); queued || err == nil || !strings.HasPrefix(err.Error(), "postgres: mark package reputation due:") {
		t.Fatalf("MarkPackageReputationDue(closed) = %v, %v", queued, err)
	}
	generation := dashboardStatsCacheGeneration(store)
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{Ecosystem: "npm", Name: "f210", Version: "1", Source: "source"}); err == nil || !strings.HasPrefix(err.Error(), "postgres: upsert package reputation:") {
		t.Fatalf("UpsertPackageReputation(closed) error = %v", err)
	}
	if got := dashboardStatsCacheGeneration(store); got != generation {
		t.Fatalf("cache generation after closed-pool upsert = %d, want %d", got, generation)
	}
	if pruned, err := store.PrunePackageReputation(ctx, "source", time.Hour); pruned != 0 || err == nil || !strings.HasPrefix(err.Error(), "postgres: prune package reputation cache for source:") {
		t.Fatalf("PrunePackageReputation(closed) = %d, %v", pruned, err)
	}
}

func f210ReputationReadShadow(t *testing.T, dsn, mode string) *Store {
	t.Helper()
	return f106ShadowStore(t, dsn, func(ctx context.Context, pool *pgxpool.Pool, schema string) {
		base := quoteIdentifier(schema) + ".package_reputation_cache_base"
		if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (LIKE public.package_reputation_cache INCLUDING ALL)", base)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s(
			ecosystem,name,version,source,status,severity,summary,description,reference_urls,evidence,next_check_at,updated_at
		) VALUES
			('pypi','f210-read','1','reversinglabs','removed','HIGH','good','good','[]','{}',NOW()-interval '2 hours',NOW()),
			('pypi','f210-read','2','reversinglabs','removed','HIGH','bad','bad','[]','{}',NOW()-interval '1 hour',NOW()-interval '1 second')`, base)); err != nil {
			t.Fatal(err)
		}

		summaryExpr := "summary"
		switch mode {
		case "scan":
			summaryExpr = "CASE WHEN version='2' THEN NULL::text ELSE summary END"
		case "rows":
			if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s.f210_reputation_rows_marker(value text,row_version text) RETURNS text LANGUAGE plpgsql AS $fn$
			BEGIN IF row_version='2' THEN RAISE EXCEPTION USING ERRCODE='P6210',MESSAGE='f210 reputation rows marker'; END IF; RETURN value; END $fn$`, quoteIdentifier(schema))); err != nil {
				t.Fatal(err)
			}
			summaryExpr = fmt.Sprintf("%s.f210_reputation_rows_marker(summary,version)", quoteIdentifier(schema))
		default:
			t.Fatalf("unsupported read-shadow mode %q", mode)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE VIEW %s.package_reputation_cache AS
			SELECT id,ecosystem,name,version,source,status,severity,%s AS summary,description,reference_urls,evidence,
			       last_checked_at,next_check_at,last_error,created_at,updated_at
			FROM %s`, quoteIdentifier(schema), summaryExpr, base)); err != nil {
			t.Fatal(err)
		}
	})
}

func f210SeedDueReputations(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,next_check_at)
		SELECT 'pypi','f210-due',n::text,'reversinglabs','pending',NOW()-(7-n)*interval '1 hour'
		FROM generate_series(1,6) n;
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,next_check_at) VALUES
			('pypi','f210-due','7','reversinglabs','unsupported',NOW()-interval '7 hours'),
			('pypi','f210-due','8','reversinglabs','pending',NOW()+interval '1 hour'),
			('pypi','f210-due','9','reversinglabs','pending',NULL)`); err != nil {
		t.Fatalf("seed due reputations: %v", err)
	}
}

func f210SeedFindingReputations(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,severity,summary,reference_urls,updated_at) VALUES
			('pypi','f210-finding','1',$1,'malicious','CRITICAL','malware','["https://example.test/f210-malicious"]',NOW()),
			('pypi','f210-finding','2',$1,'removed','MEDIUM','removed','[]',NOW()-interval '1 second'),
			('pypi','f210-finding','3',$1,'risk','HIGH','history','[]',NOW()-interval '2 seconds'),
			('pypi','f210-finding','4',$1,'clean','LOW','clean','[]',NOW()-interval '3 seconds')`, db.ReputationSourceReversingLabs); err != nil {
		t.Fatalf("seed finding reputations: %v", err)
	}
}

func f210TestPruneRollbackAndBoundaries(t *testing.T, store *Store, wantGeneration uint64) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO package_reputation_cache(ecosystem,name,version,source,status,updated_at) VALUES
			('npm','f210-prune-fail','1','f210-prune','clean',NOW()-interval '2 days'),
			('npm','f210-prune-clean','1','f210-prune','clean',NOW()-interval '2 days'),
			('npm','f210-prune-not-found','1','f210-prune','not_found',NOW()-interval '2 days'),
			('npm','f210-prune-unsupported','1','f210-prune','unsupported',NOW()-interval '2 days'),
			('npm','f210-prune-error','1','f210-prune','error',NOW()-interval '2 days'),
			('npm','f210-prune-malicious','1','f210-prune','malicious',NOW()-interval '2 days'),
			('npm','f210-prune-removed','1','f210-prune','removed',NOW()-interval '2 days'),
			('npm','f210-prune-risk','1','f210-prune','risk',NOW()-interval '2 days'),
			('npm','f210-prune-fresh','1','f210-prune','clean',NOW()),
			('npm','f210-prune-other-source','1','other','clean',NOW()-interval '2 days')`); err != nil {
		t.Fatalf("seed prune reputations: %v", err)
	}
	f106InstallTrigger(t, store.pool, "package_reputation_cache", "DELETE", "f210_fail_reputation_prune", "P6212", "OLD.name = 'f210-prune-fail'")
	pruned, err := store.PrunePackageReputation(ctx, "f210-prune", time.Hour)
	if pruned != 0 {
		t.Fatalf("failed PrunePackageReputation() count = %d, want 0", pruned)
	}
	f106RequirePgError(t, err, "P6212", "forced f210_fail_reputation_prune failure")
	var rows int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM package_reputation_cache WHERE source='f210-prune'`).Scan(&rows); err != nil || rows != 9 {
		t.Fatalf("prune rollback rows = %d, error=%v; want 9", rows, err)
	}
	if got := dashboardStatsCacheGeneration(store); got != wantGeneration {
		t.Fatalf("cache generation after failed prune = %d, want %d", got, wantGeneration)
	}
	if _, err := store.pool.Exec(ctx, `
		DROP TRIGGER f210_fail_reputation_prune ON package_reputation_cache;
		DROP FUNCTION f210_fail_reputation_prune_fn()`); err != nil {
		t.Fatalf("remove prune fault: %v", err)
	}
	pruned, err = store.PrunePackageReputation(ctx, " f210-prune ", time.Hour)
	if err != nil || pruned != 5 {
		t.Fatalf("PrunePackageReputation(success) = %d, %v; want 5, nil", pruned, err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM package_reputation_cache WHERE source='f210-prune'`).Scan(&rows); err != nil || rows != 4 {
		t.Fatalf("rows after successful prune = %d, error=%v; want 4", rows, err)
	}
	if got := dashboardStatsCacheGeneration(store); got != wantGeneration {
		t.Fatalf("cache generation after benign prune = %d, want %d", got, wantGeneration)
	}
}
