//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"testing"
)

// TestVersionRangesCheckMatchesStoreValidationAgainstPostgres runs the shared
// case table through both the Go store pre-check and the database function
// behind the version_ranges CHECK constraints. They must agree, except that the
// SQL side may accept what Go rejects (Unicode whitespace), never the reverse:
// a value the store validated must always be storable.
func TestVersionRangesCheckMatchesStoreValidationAgainstPostgres(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	for _, tc := range storedVersionRangeCases {
		var sqlValid bool
		if err := store.pool.QueryRow(ctx, `SELECT packmon_jsonb_version_ranges_valid($1::jsonb)`, tc.raw).Scan(&sqlValid); err != nil {
			t.Fatalf("%s: packmon_jsonb_version_ranges_valid(%s) error = %v", tc.name, tc.raw, err)
		}
		goValid := validateStoredVersionRangesJSON("GHSA-case", "version_ranges", json.RawMessage(tc.raw), false) == nil

		if goValid && !sqlValid {
			t.Fatalf("%s: Go accepts %s but the CHECK constraint rejects it", tc.name, tc.raw)
		}
		if tc.goOnly {
			if goValid || !sqlValid {
				t.Fatalf("%s: go=%t sql=%t, want Go-only rejection", tc.name, goValid, sqlValid)
			}
			continue
		}
		if sqlValid != tc.valid {
			t.Fatalf("%s: packmon_jsonb_version_ranges_valid(%s) = %t, want %t", tc.name, tc.raw, sqlValid, tc.valid)
		}
	}
}
