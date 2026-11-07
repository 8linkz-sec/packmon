package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type packageNameRepairRow struct {
	count int
	err   error
}

func (r packageNameRepairRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*int) = r.count
	return nil
}

type packageNameRepairQuerier struct {
	ctx  context.Context
	sql  string
	args []any
	row  pgx.Row
}

func (q *packageNameRepairQuerier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	q.ctx = ctx
	q.sql = sql
	q.args = append([]any(nil), args...)
	return q.row
}

func TestPackageNameRepairHelpersReportCountsAndScanFailures(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("repair row scan failed")
	tests := []struct {
		name      string
		query     string
		row       pgx.Row
		run       func(context.Context, postgresQueryRower) (int, error)
		wantCount int
		wantError string
	}{
		{
			name:      "affected count",
			query:     repairAffectedPackageNamesSQL,
			row:       packageNameRepairRow{count: 4},
			run:       repairAffectedPackageNames,
			wantCount: 4,
		},
		{
			name:      "malicious count",
			query:     repairMaliciousPackageNamesSQL,
			row:       packageNameRepairRow{count: 3},
			run:       repairMaliciousPackageNames,
			wantCount: 3,
		},
		{
			name:      "affected scan failure",
			query:     repairAffectedPackageNamesSQL,
			row:       packageNameRepairRow{err: sentinel},
			run:       repairAffectedPackageNames,
			wantError: "postgres: repair affected package names",
		},
		{
			name:      "malicious scan failure",
			query:     repairMaliciousPackageNamesSQL,
			row:       packageNameRepairRow{err: sentinel},
			run:       repairMaliciousPackageNames,
			wantError: "postgres: repair malicious package names",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.WithValue(context.Background(), packageNameRepairTestContextKey{}, tc.name)
			querier := &packageNameRepairQuerier{row: tc.row}
			got, err := tc.run(ctx, querier)
			if got != tc.wantCount {
				t.Fatalf("repair count = %d, want %d", got, tc.wantCount)
			}
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("repair error = %v, want nil", err)
				}
			} else {
				if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("repair error = %v, want wrapped sentinel with %q", err, tc.wantError)
				}
			}
			if querier.ctx != ctx {
				t.Fatal("repair helper replaced the caller context")
			}
			if querier.sql != tc.query {
				t.Fatal("repair helper executed an unexpected query")
			}
			if len(querier.args) != 0 {
				t.Fatalf("repair helper query args = %#v, want none", querier.args)
			}
		})
	}
}

// packageNameRepairTestContextKey marks the context the fault tests pass through.
type packageNameRepairTestContextKey struct{}
