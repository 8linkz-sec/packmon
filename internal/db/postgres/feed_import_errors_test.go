package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestClassifyFeedImportDataError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "real underflow", err: &pgconn.PgError{Code: "22003", Message: "value out of range: underflow"}, want: true},
		{name: "nul byte in text", err: &pgconn.PgError{Code: "22021", Message: "invalid byte sequence"}, want: true},
		{name: "nul escape in jsonb", err: &pgconn.PgError{Code: "22P05", Message: "unsupported Unicode escape sequence"}, want: true},
		{name: "invalid text representation", err: &pgconn.PgError{Code: "22P02"}, want: true},
		{name: "string too long", err: &pgconn.PgError{Code: "22001"}, want: true},
		{name: "invalid datetime format", err: &pgconn.PgError{Code: "22007"}, want: true},
		{name: "datetime field overflow", err: &pgconn.PgError{Code: "22008"}, want: true},
		{name: "check violation", err: &pgconn.PgError{Code: "23514", Message: "violates check constraint"}, want: true},
		{name: "wrapped data exception", err: fmt.Errorf("enrich VulnCheck source: %w", &pgconn.PgError{Code: "22021"}), want: true},
		// Other class 22 codes point at a query or server-side problem, not at
		// the imported values, and must stay server errors.
		{name: "division by zero", err: &pgconn.PgError{Code: "22012"}, want: false},
		{name: "invalid parameter value", err: &pgconn.PgError{Code: "22023"}, want: false},
		{name: "array subscript error", err: &pgconn.PgError{Code: "2202E"}, want: false},
		{name: "generic data exception", err: &pgconn.PgError{Code: "22000"}, want: false},
		{name: "invalid escape sequence", err: &pgconn.PgError{Code: "22025"}, want: false},
		{name: "unique violation", err: &pgconn.PgError{Code: "23505"}, want: false},
		{name: "foreign key violation", err: &pgconn.PgError{Code: "23503"}, want: false},
		{name: "connection failure", err: &pgconn.PgError{Code: "08006"}, want: false},
		{name: "plain error", err: errors.New("connection refused"), want: false},
		{name: "context canceled", err: context.Canceled, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := classifyFeedImportDataError(tt.err)
			if is := errors.Is(got, db.ErrInvalidFeedImportData); is != tt.want {
				t.Fatalf("errors.Is(classify(%v), ErrInvalidFeedImportData) = %t, want %t", tt.err, is, tt.want)
			}
			if tt.err != nil && !errors.Is(got, tt.err) {
				t.Fatalf("classify(%v) = %v, want the original error kept in the chain", tt.err, got)
			}
		})
	}
}

// TestStoreSideImportValidationErrorsAreInvalidFeedImportData pins that the
// store's own record validation, which runs after the handler checks, is
// recognizable as a data rejection rather than a store failure.
func TestStoreSideImportValidationErrorsAreInvalidFeedImportData(t *testing.T) {
	t.Parallel()

	if _, err := normalizeEPSSSnapshotBatch([]db.EPSSEntry{{CVEID: "CVE-2026-0001", Score: math.Inf(1), Percentile: 0.1}}, 0); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("normalizeEPSSSnapshotBatch(invalid) error = %v, want ErrInvalidFeedImportData", err)
	}
	if _, err := stageEPSSSnapshotStream(context.Background(), func(func([]db.EPSSEntry) error) error { return nil }); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("stageEPSSSnapshotStream(empty) error = %v, want ErrInvalidFeedImportData", err)
	}
	if err := validateStoredVersionRangesJSON("GHSA-x", "version_ranges", json.RawMessage(`[{"events":[]}]`), false); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("validateStoredVersionRangesJSON(invalid) error = %v, want ErrInvalidFeedImportData", err)
	}
	if err := validateStoredStringArrayJSON("GHSA-x", "versions_affected", json.RawMessage(`[1]`), false); !errors.Is(err, db.ErrInvalidFeedImportData) {
		t.Fatalf("validateStoredStringArrayJSON(invalid) error = %v, want ErrInvalidFeedImportData", err)
	}
}
