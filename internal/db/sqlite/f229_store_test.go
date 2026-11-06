package sqlite

import (
	"context"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF229ValidateLocalStringArrayContracts(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		allowNull bool
		wantErr   string
	}{
		{name: "absent", raw: ""},
		{name: "whitespace", raw: "  "},
		{name: "allowed null", raw: "null", allowNull: true},
		{name: "rejected null", raw: "null", wantErr: "array of strings"},
		{name: "valid array", raw: `["1.0.0", "2.0.0"]`},
		{name: "null element", raw: `["1.0.0", null]`, allowNull: true, wantErr: "array of strings"},
		{name: "number element", raw: `["1.0.0", 2]`, wantErr: "array of strings"},
		{name: "boolean element", raw: `["1.0.0", false]`, wantErr: "array of strings"},
		{name: "object element", raw: `["1.0.0", {}]`, wantErr: "array of strings"},
		{name: "array element", raw: `["1.0.0", []]`, wantErr: "array of strings"},
		{name: "object", raw: `{}`, wantErr: "array of strings"},
		{name: "malformed", raw: `[`, wantErr: "array of strings"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLocalStringArray("MAL-test", "versions", tc.raw, tc.allowNull)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateLocalStringArray() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateLocalStringArray() error = %v, want %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "MAL-test") || !strings.Contains(err.Error(), "versions") {
				t.Fatalf("validateLocalStringArray() error = %v, want finding and field context", err)
			}
		})
	}
}

func TestF229LocalMaliciousVersionMatchingContracts(t *testing.T) {
	affected, err := localMaliciousAffectsVersion("MAL-all", "npm", "", `{malformed`, `{malformed`)
	if err != nil || !affected {
		t.Fatalf("versionless match = %v, %v, want true without parsing constraints", affected, err)
	}

	for _, tc := range []struct {
		name         string
		version      string
		ranges       string
		versions     string
		wantAffected bool
		wantErr      string
	}{
		{name: "exact match", version: "1.2.3", ranges: `[]`, versions: `["1.2.3"]`, wantAffected: true},
		{name: "exact miss", version: "2.0.0", ranges: `[]`, versions: `["1.2.3"]`},
		{name: "invalid ranges", version: "1.2.3", ranges: `{}`, versions: `[]`, wantErr: "version_ranges"},
		{name: "invalid versions", version: "1.2.3", ranges: `[]`, versions: `{}`, wantErr: "versions"},
		{name: "null versions element", version: "1.2.3", ranges: `[]`, versions: `["1.2.3", null]`, wantErr: "versions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := localMaliciousAffectsVersion("MAL-test", "npm", tc.version, tc.ranges, tc.versions)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("localMaliciousAffectsVersion() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.wantAffected {
				t.Fatalf("localMaliciousAffectsVersion() = %v, %v, want %v, nil", got, err, tc.wantAffected)
			}
		})
	}
}

func TestF229ApplySyncRejectsNullStringArrayElementsAtomically(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		response   *syncResponse
		wantID     string
		wantField  string
		countQuery string
	}{
		{
			name: "vulnerability versions affected",
			response: &syncResponse{Vulnerabilities: []syncVulnerability{
				{
					ID:               "GHSA-valid-sibling",
					Ecosystem:        "npm",
					Name:             "valid-vulnerability",
					VersionRanges:    `[]`,
					VersionsAffected: `["1.0.0"]`,
					Severity:         "HIGH",
				},
				{
					ID:               "GHSA-null-element",
					Ecosystem:        "npm",
					Name:             "invalid-vulnerability",
					VersionRanges:    `[]`,
					VersionsAffected: `["1.0.0", null]`,
					Severity:         "HIGH",
				},
			}},
			wantID:     "GHSA-null-element",
			wantField:  "versions_affected",
			countQuery: `SELECT COUNT(*) FROM vulnerabilities_local`,
		},
		{
			name: "malicious versions",
			response: &syncResponse{Malicious: []syncMalicious{
				{
					ID:        "MAL-valid-sibling",
					Ecosystem: "npm",
					Name:      "valid-malicious",
					Versions:  `["1.0.0"]`,
					RiskType:  "malware",
					Severity:  "CRITICAL",
				},
				{
					ID:        "MAL-null-element",
					Ecosystem: "npm",
					Name:      "invalid-malicious",
					Versions:  `["1.0.0", null]`,
					RiskType:  "malware",
					Severity:  "CRITICAL",
				},
			}},
			wantID:     "MAL-null-element",
			wantField:  "versions",
			countQuery: `SELECT COUNT(*) FROM malicious_local`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := newSQLiteTestStore(t)
			_, err := applySync(context.Background(), store, false, tc.response)
			if err == nil || !strings.Contains(err.Error(), tc.wantID) ||
				!strings.Contains(err.Error(), tc.wantField) || !strings.Contains(err.Error(), "array of strings") {
				t.Fatalf("applySync() error = %v, want ID %q, field %q, and array contract", err, tc.wantID, tc.wantField)
			}

			var count int
			if err := store.DB().QueryRow(tc.countQuery).Scan(&count); err != nil {
				t.Fatalf("count rows after rejected sync: %v", err)
			}
			if count != 0 {
				t.Fatalf("rows after rejected sync = %d, want 0 after transaction rollback", count)
			}
		})
	}
}

func TestF229PredicateDefaultsAndLocalFindingSource(t *testing.T) {
	packages := []db.PackageQuery{
		{Ecosystem: " npm ", Name: " left-pad ", Version: " 1.0.0 "},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	}

	packageChunks := localPackagePredicateChunks(packages, 0)
	if len(packageChunks) != 1 || len(packageChunks[0].args) != 2 {
		t.Fatalf("localPackagePredicateChunks(default) = %+v, want one deduplicated package", packageChunks)
	}
	reputationChunks := localReputationPackagePredicateChunks(packages, 0)
	if len(reputationChunks) != 1 || len(reputationChunks[0].args) != 3 {
		t.Fatalf("localReputationPackagePredicateChunks(default) = %+v, want one deduplicated package version", reputationChunks)
	}

	if got := localFindingSource(" \t "); got != "local" {
		t.Fatalf("localFindingSource(blank) = %q, want local", got)
	}
	if got := localFindingSource(" osv "); got != "osv" {
		t.Fatalf("localFindingSource(trimmed) = %q, want osv", got)
	}
}
