package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type f106Call struct {
	ctx  context.Context
	sql  string
	args []any
}

type f106ScriptedTx struct {
	pgx.Tx
	execs       []f106Call
	queries     []f106Call
	rows        []f106Call
	execErrAt   map[int]error
	execTagAt   map[int]pgconn.CommandTag
	queryErr    error
	queryResult pgx.Rows
	rowResult   pgx.Row
}

func (tx *f106ScriptedTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.execs = append(tx.execs, f106Call{ctx: ctx, sql: sql, args: append([]any(nil), args...)})
	n := len(tx.execs)
	if err := tx.execErrAt[n]; err != nil {
		return pgconn.CommandTag{}, err
	}
	if tag, ok := tx.execTagAt[n]; ok {
		return tag, nil
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (tx *f106ScriptedTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.queries = append(tx.queries, f106Call{ctx: ctx, sql: sql, args: append([]any(nil), args...)})
	return tx.queryResult, tx.queryErr
}

func (tx *f106ScriptedTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.rows = append(tx.rows, f106Call{ctx: ctx, sql: sql, args: append([]any(nil), args...)})
	return tx.rowResult
}

type f106Rows struct {
	pgx.Rows
	values    []string
	index     int
	scanErrAt int
	err       error
}

func (r *f106Rows) Close()     {}
func (r *f106Rows) Err() error { return r.err }
func (r *f106Rows) Next() bool { return r.index < len(r.values) }
func (r *f106Rows) Scan(dest ...any) error {
	r.index++
	if r.scanErrAt == r.index {
		return errors.New("sentinel scan")
	}
	*dest[0].(*string) = r.values[r.index-1]
	return nil
}

type f106Row struct {
	values []any
	err    error
}

func (r f106Row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *string:
			*d = r.values[i].(string)
		case *time.Time:
			*d = r.values[i].(time.Time)
		default:
			return fmt.Errorf("unsupported destination %T", dest[i])
		}
	}
	return nil
}

func f106SQLPrefix(sql string) string {
	return strings.Join(strings.Fields(sql)[:min(3, len(strings.Fields(sql)))], " ")
}

func TestF106LifecycleHelperBoundaries(t *testing.T) {
	t.Run("normalizes slugs defaults owners sources blanks and JSON fallbacks", func(t *testing.T) {
		products := []db.LifecycleProduct{
			{ProductSlug: "  alpha  "},
			{ProductSlug: ""},
			{ProductSlug: "alpha"},
			{ProductSlug: " beta "},
		}
		if got, want := lifecycleProductSlugs(products), []string{"alpha", "beta"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("lifecycleProductSlugs() = %q, want %q", got, want)
		}

		ctx := context.WithValue(context.Background(), f106TestContextKey("f106-marker"), "f106")
		tx := &f106ScriptedTx{}
		product := db.LifecycleProduct{ProductSlug: " product ", Releases: []db.LifecycleRelease{
			{Cycle: "  "},
			{Cycle: " 1 ", Raw: nil},
		}, PackageMaps: []db.LifecyclePackageMap{
			{Ecosystem: "", Name: "ignored"},
			{Ecosystem: "pypi", Name: " My.Pkg ", Source: ""},
		}}
		slug, ok, err := upsertLifecycleProductPhaseTx(ctx, tx, product)
		if err != nil || !ok || slug != "product" {
			t.Fatalf("upsertLifecycleProductPhaseTx() = %q, %v, %v", slug, ok, err)
		}
		if got := tx.execs[0].args; got[0] != "product" || got[1] != "product" || string(got[4].([]byte)) != "[]" || string(got[5].([]byte)) != "{}" {
			t.Fatalf("product args = %#v, want trimmed/default values", got)
		}
		if err := upsertLifecycleReleasePhaseTx(ctx, tx, slug, product.Releases); err != nil {
			t.Fatal(err)
		}
		if got := tx.execs[1].args; got[0] != "product" || got[1] != "1" || string(got[15].([]byte)) != "{}" {
			t.Fatalf("release args = %#v, want default owner and JSON", got)
		}
		if err := upsertLifecyclePackageMapPhaseTx(ctx, tx, slug, product.PackageMaps); err != nil {
			t.Fatal(err)
		}
		if got := tx.execs[2].args; got[0] != "pypi" || got[1] != "my-pkg" || got[2] != "product" || got[6] != lifecycleSource {
			t.Fatalf("map args = %#v, want canonical identity/default owner/source", got)
		}
		for _, call := range tx.execs {
			if call.ctx != ctx {
				t.Fatal("helper replaced caller context")
			}
		}
	})

	t.Run("runs every product phase in order and stops at exact failing phase", func(t *testing.T) {
		product := db.LifecycleProduct{ProductSlug: "p", Releases: []db.LifecycleRelease{{Cycle: "1"}}, PackageMaps: []db.LifecyclePackageMap{{Ecosystem: "npm", Name: "pkg"}}}
		wantPrefixes := []string{"INSERT INTO lifecycle_products", "INSERT INTO lifecycle_sync_tombstones", "DELETE FROM lifecycle_releases", "DELETE FROM lifecycle_package_map", "INSERT INTO lifecycle_releases", "INSERT INTO lifecycle_package_map", "DELETE FROM lifecycle_sync_tombstones"}
		for failAt := 0; failAt <= len(wantPrefixes); failAt++ {
			tx := &f106ScriptedTx{execErrAt: map[int]error{}}
			marker := errors.New("phase failure")
			if failAt > 0 {
				tx.execErrAt[failAt] = marker
			}
			err := upsertLifecycleProductsTx(context.Background(), tx, []db.LifecycleProduct{product})
			wantCalls := len(wantPrefixes)
			if failAt > 0 {
				wantCalls = failAt
				if !errors.Is(err, marker) {
					t.Fatalf("phase %d error = %v, want sentinel", failAt, err)
				}
			} else if err != nil {
				t.Fatalf("success error = %v", err)
			}
			if len(tx.execs) != wantCalls {
				t.Fatalf("phase %d calls = %d, want %d", failAt, len(tx.execs), wantCalls)
			}
			for i, call := range tx.execs {
				if got := f106SQLPrefix(call.sql); got != wantPrefixes[i] {
					t.Fatalf("phase %d SQL[%d] prefix = %q, want %q", failAt, i, got, wantPrefixes[i])
				}
			}
		}
	})

	t.Run("propagates stale query scan iteration tombstone and delete failures with exact cutoff", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), f106TestContextKey("f106"), "ctx")
		marker := errors.New("stale failure")
		cases := []struct {
			name       string
			tx         *f106ScriptedTx
			wantExecs  int
			wantErr    error
			wantDelete bool
		}{
			{name: "query", tx: &f106ScriptedTx{queryErr: marker}, wantErr: marker},
			{name: "scan", tx: &f106ScriptedTx{queryResult: &f106Rows{values: []string{"a"}, scanErrAt: 1}}, wantErr: errors.New("sentinel scan")},
			{name: "iterate", tx: &f106ScriptedTx{queryResult: &f106Rows{values: []string{"a"}, err: marker}}, wantErr: marker},
			{name: "first tombstone", tx: &f106ScriptedTx{queryResult: &f106Rows{values: []string{"a", "b"}}, execErrAt: map[int]error{1: marker}}, wantExecs: 1, wantErr: marker},
			{name: "late tombstone", tx: &f106ScriptedTx{queryResult: &f106Rows{values: []string{"a", "b"}}, execErrAt: map[int]error{2: marker}}, wantExecs: 2, wantErr: marker},
			{name: "delete", tx: &f106ScriptedTx{queryResult: &f106Rows{values: []string{"a", "b"}}, execErrAt: map[int]error{3: marker}}, wantExecs: 3, wantErr: marker, wantDelete: true},
		}
		for _, tc := range cases {
			_, err := deleteLifecycleProductsNotInTx(ctx, tc.tx, []string{"kept"})
			if tc.name == "scan" {
				if err == nil || !strings.Contains(err.Error(), "sentinel scan") {
					t.Fatalf("%s error = %v, want scan cause", tc.name, err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s error = %v, want %v", tc.name, err, tc.wantErr)
			}
			if len(tc.tx.execs) != tc.wantExecs {
				t.Fatalf("%s exec calls = %d, want %d", tc.name, len(tc.tx.execs), tc.wantExecs)
			}
			if len(tc.tx.queries) != 1 || tc.tx.queries[0].ctx != ctx || !reflect.DeepEqual(tc.tx.queries[0].args, []any{lifecycleSource, []string{"kept"}}) {
				t.Fatalf("%s query call = %#v", tc.name, tc.tx.queries)
			}
			for i, call := range tc.tx.execs {
				if call.ctx != ctx {
					t.Fatal("stale helper replaced context")
				}
				if i < 2 && call.args[0] != []string{"a", "b"}[i] {
					t.Fatalf("%s tombstone slug[%d] = %v", tc.name, i, call.args)
				}
			}
		}
	})

	t.Run("empty and all invalid finding batches avoid the pool", func(t *testing.T) {
		store := &Store{}
		for _, packages := range [][]db.PackageQuery{nil, {{Ecosystem: " ", Name: " "}, {Ecosystem: "npm", Name: " "}}} {
			got, err := store.FindLifecycleFindingsBatch(context.Background(), packages, time.Time{})
			if err != nil || got != nil {
				t.Fatalf("FindLifecycleFindingsBatch(%+v) = %+v, %v; want nil, nil", packages, got, err)
			}
		}
	})
}

func TestF107MaliciousHelperBoundaries(t *testing.T) {
	t.Run("version matching is fail safe for blanks and malformed ranges", func(t *testing.T) {
		if err := validateMaliciousFindingVersions("ok", json.RawMessage(`["1"]`)); err != nil {
			t.Fatal(err)
		}
		if err := validateMaliciousFindingVersions("bad", json.RawMessage(`{}`)); err == nil {
			t.Fatal("object versions unexpectedly validated")
		}
		if !maliciousFindingAffectsVersion("npm", " ", "not-json", "not-json") {
			t.Fatal("blank version must match every finding")
		}
		if !maliciousFindingAffectsVersion("npm", "1.0.0", "not-json", "[]") {
			t.Fatal("matcher error must fail safe")
		}
		if maliciousFindingAffectsVersion("npm", "2.0.0", `[]`, `["1.0.0"]`) {
			t.Fatal("unaffected concrete version matched")
		}
	})

	t.Run("empty batch avoids the pool", func(t *testing.T) {
		got, err := (&Store{}).FindMaliciousBatch(context.Background(), nil)
		if err != nil || got != nil {
			t.Fatalf("FindMaliciousBatch(nil) = %+v, %v", got, err)
		}
	})

	t.Run("public upsert rejects invalid values before database access", func(t *testing.T) {
		cases := []db.MaliciousFinding{
			{},
			{ID: "bad-eco", Ecosystem: "unknown", Name: "pkg", Source: "feed", RiskType: "malware", Severity: "HIGH"},
			{ID: "bad-risk", Ecosystem: "npm", Name: "pkg", Source: "feed", RiskType: "other", Severity: "HIGH"},
			{ID: "bad-severity", Ecosystem: "npm", Name: "pkg", Source: "feed", RiskType: "malware", Severity: "INVALID"},
			{ID: "bad-json", Ecosystem: "npm", Name: "pkg", Source: "feed", RiskType: "malware", Severity: "HIGH", Versions: json.RawMessage(`{}`)},
			{ID: "CVE-2026-1234", Ecosystem: "npm", Name: "pkg", Source: "manual", RiskType: "malware", Severity: "HIGH"},
		}
		for i := range cases {
			if err := (&Store{}).UpsertMaliciousFinding(context.Background(), &cases[i]); err == nil {
				t.Fatalf("case %q unexpectedly accepted", cases[i].ID)
			}
		}
		if err := (&Store{}).UpsertMaliciousFinding(context.Background(), nil); err == nil {
			t.Fatal("nil finding unexpectedly accepted")
		}
	})

	t.Run("public and internal source scoped deletes reject blank source", func(t *testing.T) {
		if err := (&Store{}).DeleteMaliciousFindingForSource(context.Background(), "id", " \t"); !errors.Is(err, db.ErrSourceScopedDeleteSourceRequired) {
			t.Fatalf("public blank source error = %v", err)
		}
		tx := &f106ScriptedTx{}
		if err := deleteMaliciousFindingForSourceTx(context.Background(), tx, "id", "\n"); !errors.Is(err, db.ErrSourceScopedDeleteSourceRequired) {
			t.Fatalf("internal blank source error = %v", err)
		}
		if len(tx.execs) != 0 {
			t.Fatalf("blank source executed %d statements", len(tx.execs))
		}
	})

	t.Run("ownership check rejects foreign rows and preserves query and exec causes", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), f106TestContextKey("f107"), "ctx")
		finding := &normalizedMaliciousFinding{ID: "id", Source: "feed", Ecosystem: "npm", Name: "pkg", RiskType: "malware", Severity: "HIGH", ReferenceURLs: []byte("[]")}
		marker := errors.New("ownership marker")
		cases := []struct {
			name      string
			tx        *f106ScriptedTx
			wantCause bool
			wantExecs int
		}{
			{name: "foreign", tx: &f106ScriptedTx{rowResult: f106Row{values: []any{"other"}}}},
			{name: "query", tx: &f106ScriptedTx{rowResult: f106Row{err: marker}}, wantCause: true},
			{name: "insert", tx: &f106ScriptedTx{rowResult: f106Row{err: pgx.ErrNoRows}, execErrAt: map[int]error{1: marker}}, wantCause: true, wantExecs: 1},
			{name: "success", tx: &f106ScriptedTx{rowResult: f106Row{err: pgx.ErrNoRows}}, wantExecs: 1},
		}
		for _, tc := range cases {
			err := upsertNormalizedMaliciousFindingTx(ctx, tc.tx, finding)
			if tc.name == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatalf("%s returned nil error", tc.name)
			}
			if tc.wantCause && !errors.Is(err, marker) {
				t.Fatalf("%s error = %v, want marker", tc.name, err)
			}
			if len(tc.tx.rows) != 1 || tc.tx.rows[0].ctx != ctx || len(tc.tx.execs) != tc.wantExecs {
				t.Fatalf("%s calls rows=%d execs=%d", tc.name, len(tc.tx.rows), len(tc.tx.execs))
			}
		}
	})
}

func TestF108ManualAdvisoryHelperBoundaries(t *testing.T) {
	t.Run("nil public upserts are noops", func(t *testing.T) {
		store := &Store{}
		if err := store.UpsertManualAdvisory(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if err := store.UpsertManualAdvisoryWithAudit(context.Background(), nil, nil); err != nil {
			t.Fatal(err)
		}
		for _, advisory := range []*db.ManualAdvisory{
			{ID: "CVE-2026-2", FindingType: "vulnerability"},
			{ID: "manual:invalid-type", FindingType: "other"},
		} {
			if err := store.UpsertManualAdvisory(context.Background(), advisory); err == nil {
				t.Fatalf("plain invalid advisory %+v unexpectedly accepted", advisory)
			}
			if err := store.UpsertManualAdvisoryWithAudit(context.Background(), advisory, nil); err == nil {
				t.Fatalf("audited invalid advisory %+v unexpectedly accepted", advisory)
			}
		}
	})

	t.Run("internal dispatch rejects invalid finding type before SQL", func(t *testing.T) {
		tx := &f106ScriptedTx{}
		err := upsertManualAdvisoryTx(context.Background(), tx, &db.ManualAdvisory{ID: "manual:id", FindingType: "other"})
		if err == nil || len(tx.execs) != 0 {
			t.Fatalf("invalid dispatch error=%v execs=%d", err, len(tx.execs))
		}
		input := &db.ManualAdvisory{ID: " manual:copy ", FindingType: "vulnerability"}
		normalized, err := normalizedManualAdvisory(input)
		if err != nil || normalized.ID != "manual:copy" || input.ID != " manual:copy " || normalized == input {
			t.Fatalf("normalized=%+v input=%+v err=%v", normalized, input, err)
		}
		if _, err := normalizedManualAdvisory(&db.ManualAdvisory{ID: "CVE-2026-1", FindingType: "vulnerability"}); err == nil {
			t.Fatal("feed-owned ID unexpectedly normalized")
		}
		if _, err := normalizedManualAdvisory(&db.ManualAdvisory{ID: "manual:type", FindingType: "other"}); err == nil {
			t.Fatal("invalid type unexpectedly normalized")
		}
		if err := upsertManualVulnerabilityTx(context.Background(), tx, &db.Vulnerability{ID: "manual:severity", Severity: "bad"}); err == nil {
			t.Fatal("invalid vulnerability severity unexpectedly accepted")
		}
		if err := upsertManualVulnerabilityTx(context.Background(), tx, &db.Vulnerability{ID: "manual:ecosystem", Severity: "LOW", AffectedPackages: []db.AffectedPackage{{Ecosystem: "bad", Name: "pkg"}}}); err == nil {
			t.Fatal("invalid affected ecosystem unexpectedly accepted")
		}
	})

	t.Run("blank lock ID avoids SQL", func(t *testing.T) {
		tx := &f106ScriptedTx{}
		if err := acquireManualAdvisoryLockTx(context.Background(), tx, " \t"); err != nil {
			t.Fatal(err)
		}
		if len(tx.execs) != 0 {
			t.Fatalf("blank lock executed %d statements", len(tx.execs))
		}
		marker := errors.New("lock marker")
		tx.execErrAt = map[int]error{1: marker}
		if err := acquireManualAdvisoryLockTx(context.Background(), tx, "manual:lock"); !errors.Is(err, marker) {
			t.Fatalf("lock error = %v, want marker", err)
		}
	})

	t.Run("revision accepts zero and match and rejects conflict missing and query error", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), f106TestContextKey("f108"), "ctx")
		stamp := time.Date(2026, 11, 2, 12, 0, 0, 123000, time.UTC)
		cases := []struct {
			name     string
			advisory *db.ManualAdvisory
			row      pgx.Row
			want     error
			queries  int
		}{
			{name: "nil", advisory: nil},
			{name: "zero", advisory: &db.ManualAdvisory{ID: "manual:zero"}},
			{name: "match", advisory: &db.ManualAdvisory{ID: " manual:id ", UpdatedAt: stamp}, row: f106Row{values: []any{stamp}}, queries: 1},
			{name: "conflict", advisory: &db.ManualAdvisory{ID: "manual:id", UpdatedAt: stamp}, row: f106Row{values: []any{stamp.Add(time.Second)}}, want: db.ErrConflict, queries: 1},
			{name: "missing", advisory: &db.ManualAdvisory{ID: "manual:id", UpdatedAt: stamp}, row: f106Row{err: pgx.ErrNoRows}, want: db.ErrConflict, queries: 1},
			{name: "query", advisory: &db.ManualAdvisory{ID: "manual:id", UpdatedAt: stamp}, row: f106Row{err: context.DeadlineExceeded}, want: context.DeadlineExceeded, queries: 1},
		}
		for _, tc := range cases {
			tx := &f106ScriptedTx{rowResult: tc.row}
			err := checkManualAdvisoryRevisionTx(ctx, tx, tc.advisory)
			if !errors.Is(err, tc.want) {
				t.Fatalf("%s error = %v, want %v", tc.name, err, tc.want)
			}
			if len(tx.rows) != tc.queries {
				t.Fatalf("%s queries = %d, want %d", tc.name, len(tx.rows), tc.queries)
			}
			if tc.queries == 1 && (tx.rows[0].ctx != ctx || tx.rows[0].args[0] != strings.TrimSpace(tc.advisory.ID)) {
				t.Fatalf("%s query = %#v", tc.name, tx.rows[0])
			}
		}
	})

	t.Run("delete stops on malicious and vulnerability errors and reports both missing", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), f106TestContextKey("f108-delete"), "ctx")
		marker := errors.New("delete marker")
		cases := []struct {
			name      string
			tx        *f106ScriptedTx
			wantCause error
			calls     int
		}{
			{name: "malicious error", tx: &f106ScriptedTx{execErrAt: map[int]error{1: marker}}, wantCause: marker, calls: 1},
			{name: "vulnerability error", tx: &f106ScriptedTx{execErrAt: map[int]error{2: marker}}, wantCause: marker, calls: 2},
			{name: "missing", tx: &f106ScriptedTx{execTagAt: map[int]pgconn.CommandTag{1: pgconn.NewCommandTag("UPDATE 0"), 2: pgconn.NewCommandTag("UPDATE 0")}}, calls: 2},
		}
		for _, tc := range cases {
			err := deleteManualAdvisoryTx(ctx, tc.tx, "manual:id")
			if tc.wantCause != nil {
				if !errors.Is(err, tc.wantCause) {
					t.Fatalf("%s error = %v", tc.name, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "not found") {
				t.Fatalf("missing error = %v", err)
			}
			if len(tc.tx.execs) != tc.calls {
				t.Fatalf("%s calls = %d, want %d", tc.name, len(tc.tx.execs), tc.calls)
			}
			for _, call := range tc.tx.execs {
				if call.ctx != ctx {
					t.Fatal("delete helper replaced context")
				}
			}
		}
	})
}

// f106TestContextKey marks the contexts these tests pass through, so a helper that
// substitutes its own context is detectable.
type f106TestContextKey string
