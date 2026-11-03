//go:build integration

package migrations

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/ioutils"
)

var f189F190ScoreConstraints = []struct {
	name   string
	column string
	upper  string
}{
	{"vulnerabilities_cvss_score_range_check", "cvss_score", "10"},
	{"vulnerabilities_epss_score_range_check", "epss_score", "1"},
	{"vulnerabilities_epss_percentile_range_check", "epss_percentile", "1"},
}

func TestF189F190MigrationContractsAgainstPostgres(t *testing.T) {
	instance := startMigrationPostgresInstance(t, false)
	database, err := sql.Open("pgx", instance.dsn)
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer ioutils.CloseSilently(database)
	database.SetMaxOpenConns(4)

	leafNumber := 600
	newLeaf := func(t *testing.T) f159F164Leaf {
		t.Helper()
		leafNumber++
		return f159F164PrepareLeaf(t, database, instance.dsn, leafNumber)
	}

	t.Run("populated_version_40_upgrade_preserves_valid_and_null_scores", func(t *testing.T) {
		for _, preexisting := range []bool{false, true} {
			name := "constraints_missing"
			if preexisting {
				name = "constraints_preexisting"
			}
			t.Run(name, func(t *testing.T) {
				leaf := newLeaf(t)
				f159F164ApplyThrough(t, leaf, 40)
				if !preexisting {
					f189F190DropScoreConstraints(t, leaf)
				}
				f189F190AssertScoreConstraints(t, leaf, preexisting)
				f189F190SeedScores(t, leaf)
				before := f189F190ScoreRows(t, leaf)

				f159F164Apply(t, leaf, 41, MigrationDirectionUp)

				f189F190AssertScoreConstraints(t, leaf, true)
				f159F164AssertEqual(t, "041 populated-upgrade score rows", f189F190ScoreRows(t, leaf), before)
			})
		}
	})

	t.Run("insert_and_update_acceptance_matrix", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 41)
		f189F190AssertScoreWriteMatrix(t, leaf)
	})

	t.Run("invalid_historical_score_fails_atomically_and_marks_dirty", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 40)
		f189F190DropScoreConstraints(t, leaf)
		f159F164Exec(t, leaf, `ALTER TABLE vulnerabilities ADD CONSTRAINT f190_unrelated_summary_check CHECK (summary <> '')`)
		f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,published,modified,cvss_score,epss_score,epss_percentile) VALUES ('f190-invalid-history','invalid historical score','2026-01-01Z','2026-01-01Z',-0.5,0.25,0.75)`)
		before := f189F190ScoreRows(t, leaf)

		up := f159F164Embedded(t, 41, MigrationDirectionUp)
		err := applyMigration(leaf.ctx, leaf.conn, up)
		f159F164ExpectConstraint(t, err, "vulnerabilities_cvss_score_range_check")
		f159F164AssertEqual(t, "041 failed-up score rows", f189F190ScoreRows(t, leaf), before)
		f189F190AssertScoreConstraints(t, leaf, false)
		f189F190AssertUnrelatedConstraint(t, leaf)
		f159F164AssertDirtyEventAndRefusal(t, leaf, up)

		f159F164ClearDirty(t, leaf, 41)
		f159F164Exec(t, leaf, `DELETE FROM vulnerabilities WHERE id='f190-invalid-history'`)
		f159F164Apply(t, leaf, 41, MigrationDirectionUp)
		f189F190AssertScoreConstraints(t, leaf, true)
		f189F190AssertUnrelatedConstraint(t, leaf)
	})

	t.Run("partial_repeated_down_and_up_preserve_rows_columns_and_unrelated_constraint", func(t *testing.T) {
		leaf := newLeaf(t)
		f159F164ApplyThrough(t, leaf, 41)
		f189F190SeedScores(t, leaf)
		before := f189F190ScoreRows(t, leaf)
		f159F164Exec(t, leaf, `ALTER TABLE vulnerabilities ADD CONSTRAINT f190_unrelated_summary_check CHECK (summary <> '')`)
		f159F164Exec(t, leaf, `ALTER TABLE vulnerabilities DROP CONSTRAINT vulnerabilities_epss_score_range_check`)

		f159F164ApplyDownAndDelete(t, leaf, 41)
		f189F190AssertScoreConstraints(t, leaf, false)
		f189F190AssertScoreColumns(t, leaf)
		f189F190AssertUnrelatedConstraint(t, leaf)
		f159F164AssertEqual(t, "041 partial-down score rows", f189F190ScoreRows(t, leaf), before)

		f159F164ApplyDownAndDelete(t, leaf, 41)
		f189F190AssertScoreConstraints(t, leaf, false)
		f189F190AssertScoreColumns(t, leaf)
		f189F190AssertUnrelatedConstraint(t, leaf)
		f159F164AssertEqual(t, "041 repeated-down score rows", f189F190ScoreRows(t, leaf), before)

		f159F164Apply(t, leaf, 41, MigrationDirectionUp)
		f189F190AssertScoreConstraints(t, leaf, true)
		f189F190AssertScoreColumns(t, leaf)
		f189F190AssertUnrelatedConstraint(t, leaf)
		f159F164AssertEqual(t, "041 down-up score rows", f189F190ScoreRows(t, leaf), before)
		f189F190AssertScoreWriteMatrix(t, leaf)
	})
}

func f189F190DropScoreConstraints(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for _, constraint := range f189F190ScoreConstraints {
		f159F164Exec(t, leaf, `ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS `+constraint.name)
	}
}

func f189F190SeedScores(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,published,modified,cvss_score,epss_score,epss_percentile) VALUES
		('f190-valid-zero','zero scores','2026-01-01Z','2026-01-01Z',0,0,0),
		('f190-valid-upper','upper scores','2026-01-02Z','2026-01-02Z',10,1,1),
		('f190-valid-middle','middle scores','2026-01-03Z','2026-01-03Z',5.5,0.25,0.75),
		('f190-valid-null','null scores','2026-01-04Z','2026-01-04Z',NULL,NULL,NULL)`)
}

func f189F190ScoreRows(t *testing.T, leaf f159F164Leaf) string {
	t.Helper()
	return f159F164Snapshot(t, leaf, `SELECT id,summary,cvss_score,epss_score,epss_percentile FROM vulnerabilities WHERE id LIKE 'f190-%' ORDER BY id`)
}

func f189F190AssertScoreConstraints(t *testing.T, leaf f159F164Leaf, wantPresent bool) {
	t.Helper()
	for _, constraint := range f189F190ScoreConstraints {
		var validated bool
		err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT c.convalidated FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND r.relname='vulnerabilities' AND c.conname=$2 AND c.contype='c'`, leaf.schema, constraint.name).Scan(&validated)
		if !wantPresent {
			if err != sql.ErrNoRows {
				t.Fatalf("score constraint %s after down/failure error = %v, want absent", constraint.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("read score constraint %s: %v", constraint.name, err)
		}
		if !validated {
			t.Fatalf("score constraint %s convalidated = false, want true", constraint.name)
		}
	}
}

func f189F190AssertScoreColumns(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var count int
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=$1 AND table_name='vulnerabilities' AND column_name IN ('cvss_score','epss_score','epss_percentile') AND data_type='real' AND is_nullable='YES'`, leaf.schema).Scan(&count); err != nil || count != 3 {
		t.Fatalf("041 score column count = %d error=%v, want 3 nullable real columns", count, err)
	}
}

func f189F190AssertUnrelatedConstraint(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	var validated bool
	if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT c.convalidated FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname=$1 AND r.relname='vulnerabilities' AND c.conname='f190_unrelated_summary_check'`, leaf.schema).Scan(&validated); err != nil || !validated {
		t.Fatalf("unrelated constraint missing or invalid: convalidated=%t error=%v", validated, err)
	}
}

func f189F190AssertScoreWriteMatrix(t *testing.T, leaf f159F164Leaf) {
	t.Helper()
	for _, constraint := range f189F190ScoreConstraints {
		values := []struct {
			name  string
			sql   string
			valid bool
		}{
			{"null", "NULL", true},
			{"zero", "0", true},
			{"upper", constraint.upper, true},
			{"negative", "-0.001", false},
			{"above_upper", constraint.upper + ".001", false},
			{"nan", "'NaN'::real", false},
			{"infinity", "'Infinity'::real", false},
		}
		for _, value := range values {
			for _, operation := range []string{"insert", "update"} {
				name := strings.TrimPrefix(constraint.column, "epss_") + "_" + value.name + "_" + operation
				t.Run(name, func(t *testing.T) {
					id := "f190-matrix-" + constraint.column + "-" + value.name + "-" + operation
					var err error
					if operation == "insert" {
						query := fmt.Sprintf(`INSERT INTO vulnerabilities(id,summary,published,modified,%s) VALUES ($1,'matrix insert','2026-02-01Z','2026-02-01Z',%s)`, constraint.column, value.sql)
						_, err = leaf.conn.ExecContext(leaf.ctx, query, id)
					} else {
						f159F164Exec(t, leaf, `INSERT INTO vulnerabilities(id,summary,published,modified,cvss_score,epss_score,epss_percentile) VALUES ($1,'matrix update','2026-02-01Z','2026-02-01Z',5,0.5,0.5)`, id)
						query := fmt.Sprintf(`UPDATE vulnerabilities SET %s=%s WHERE id=$1`, constraint.column, value.sql)
						_, err = leaf.conn.ExecContext(leaf.ctx, query, id)
					}

					if value.valid {
						if err != nil {
							t.Fatalf("valid %s %s=%s: %v", operation, constraint.column, value.sql, err)
						}
					} else {
						f159F164ExpectConstraint(t, err, constraint.name)
					}

					var rows int
					if err := leaf.conn.QueryRowContext(leaf.ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE id=$1`, id).Scan(&rows); err != nil {
						t.Fatalf("count matrix row %s: %v", id, err)
					}
					wantRows := 1
					if operation == "insert" && !value.valid {
						wantRows = 0
					}
					if rows != wantRows {
						t.Fatalf("matrix row count after %s %s=%s = %d, want %d", operation, constraint.column, value.sql, rows, wantRows)
					}
				})
			}
		}
	}
}
