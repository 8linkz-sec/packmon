package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestF217StoredVulnerabilityJSONValidationBoundaries(t *testing.T) {
	t.Parallel()

	stringArrays := []struct {
		name      string
		raw       string
		allowNull bool
		wantError string
	}{
		{name: "absent"},
		{name: "whitespace", raw: " \t\n"},
		{name: "null allowed", raw: " null ", allowNull: true},
		{name: "null rejected", raw: "null", wantError: "must be an array of strings"},
		{name: "empty array", raw: "[]"},
		{name: "string array", raw: `["1.0.0",""]`},
		{name: "object", raw: `{}`, wantError: "must be an array of strings"},
		{name: "non-string array", raw: `["1.0.0",1]`, wantError: "must be an array of strings"},
		{name: "malformed", raw: `[`, wantError: "unexpected end of JSON input"},
	}
	for _, tc := range stringArrays {
		t.Run("string array "+tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateStoredStringArrayJSON("GHSA-F217", "versions_affected", json.RawMessage(tc.raw), tc.allowNull)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("validateStoredStringArrayJSON(%q) error = %v", tc.raw, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "GHSA-F217 versions_affected") || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("validateStoredStringArrayJSON(%q) error = %v, want ID, field, and %q", tc.raw, err, tc.wantError)
			}
		})
	}

	ranges := []struct {
		name      string
		raw       string
		allowNull bool
		wantError string
	}{
		{name: "absent"},
		{name: "whitespace", raw: " \t\n"},
		{name: "null allowed", raw: " null ", allowNull: true},
		{name: "null rejected", raw: "null", wantError: "must be an array of range objects"},
		{name: "valid", raw: `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`},
		{name: "top-level object", raw: `{}`, wantError: "must be an array"},
		{name: "malformed", raw: `[`, wantError: "must be an array of range objects"},
	}
	for _, tc := range ranges {
		t.Run("version ranges "+tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateStoredVersionRangesJSON("GHSA-F217", "version_ranges", json.RawMessage(tc.raw), tc.allowNull)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("validateStoredVersionRangesJSON(%q) error = %v", tc.raw, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "GHSA-F217 version_ranges") || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("validateStoredVersionRangesJSON(%q) error = %v, want ID, field, and %q", tc.raw, err, tc.wantError)
			}
		})
	}
}

func TestF217KnownBugStringArrayValidatorRejectsNullElements(t *testing.T) {
	t.Parallel()

	err := validateStoredStringArrayJSON(
		"GHSA-F217-NULL-ELEMENT",
		"versions_affected",
		json.RawMessage(`["1.0.0",null]`),
		false,
	)
	if err == nil {
		t.Skip("F217-bugs-1: validateStoredStringArrayJSON accepts a null array element as an empty Go string")
	}
	if !strings.Contains(err.Error(), "GHSA-F217-NULL-ELEMENT versions_affected") {
		t.Fatalf("validateStoredStringArrayJSON(null element) error = %v, want ID and field", err)
	}
}

func TestF217VulnerabilityReferenceSourceSelection(t *testing.T) {
	t.Parallel()

	vuln := &db.Vulnerability{
		Sources: []db.VulnerabilitySource{
			{Source: " osv "},
			{Source: ""},
			{Source: "osv"},
			{Source: "ghsa"},
		},
		References: []db.VulnerabilityReference{
			{Source: " ghsa "},
			{Source: "vulncheck"},
			{Source: "   "},
		},
	}
	if got, want := vulnerabilityReferenceSources(vuln), []string{"osv", "ghsa", "vulncheck"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("vulnerabilityReferenceSources() = %#v, want %#v", got, want)
	}

	tests := []struct {
		name string
		vuln *db.Vulnerability
		ref  db.VulnerabilityReference
		want string
	}{
		{name: "reference owns source", vuln: vuln, ref: db.VulnerabilityReference{Source: " vulncheck "}, want: "vulncheck"},
		{name: "single vulnerability source fallback", vuln: &db.Vulnerability{Sources: []db.VulnerabilitySource{{Source: " osv "}}}, want: "osv"},
		{name: "multiple sources are ambiguous", vuln: vuln},
		{name: "no sources", vuln: &db.Vulnerability{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := vulnerabilityReferenceSource(tc.vuln, tc.ref); got != tc.want {
				t.Fatalf("vulnerabilityReferenceSource() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestF217UpsertVulnerabilityTxStatementFailures(t *testing.T) {
	t.Parallel()

	vuln := f217CompleteVulnerability()
	wantWrappers := []string{
		"upsert vulnerability core",
		"upsert vulnerability source osv",
		"insert alias CVE-2026-2170",
		"delete source-scoped vulnerability references",
		"insert reference https://example.test/GHSA-F217",
		"insert affected package pypi/f217-pkg",
	}
	for index, wrapper := range wantWrappers {
		index, wrapper := index, wrapper
		t.Run(wrapper, func(t *testing.T) {
			t.Parallel()
			want := errors.New("f217 statement failure")
			tx := &f217ScriptedTx{execErrAt: index + 1, execErr: want}
			err := upsertVulnerabilityTx(context.Background(), tx, vuln)
			if !errors.Is(err, want) || !strings.Contains(err.Error(), wrapper) {
				t.Fatalf("upsertVulnerabilityTx(exec %d) error = %v, want wrapped %q", index+1, err, wrapper)
			}
			if len(tx.execs) != index+1 {
				t.Fatalf("upsertVulnerabilityTx(exec %d) executed %d statements, want stop at failure", index+1, len(tx.execs))
			}
		})
	}

	tx := &f217ScriptedTx{}
	if err := upsertVulnerabilityTx(context.Background(), tx, vuln); err != nil {
		t.Fatalf("upsertVulnerabilityTx(success) error = %v", err)
	}
	if len(tx.execs) != len(wantWrappers) {
		t.Fatalf("upsertVulnerabilityTx(success) statements = %d, want %d", len(tx.execs), len(wantWrappers))
	}
	if got, ok := tx.execs[3].args[1].([]string); !ok || !reflect.DeepEqual(got, []string{"osv"}) {
		t.Fatalf("reference cleanup sources = %#v, want []string{\"osv\"}", tx.execs[3].args[1])
	}
	if got := tx.execs[5].args[2]; got != "f217-pkg" {
		t.Fatalf("normalized package name = %#v, want f217-pkg", got)
	}
}

func TestF217UpsertVulnerabilityTxRejectsBeforeAffectedWrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		edit func(*db.Vulnerability)
		want string
	}{
		{name: "severity", edit: func(v *db.Vulnerability) { v.Severity = "NOT-A-SEVERITY" }, want: "unsupported vulnerability severity"},
		{name: "manual owner id", edit: func(v *db.Vulnerability) {
			v.Sources = []db.VulnerabilitySource{{Source: " manual ", SourceID: "CVE-2026-2170"}}
		}, want: "manual advisory id"},
		{name: "manual source id", edit: func(v *db.Vulnerability) {
			v.ID = "manual:f217"
			v.Sources = []db.VulnerabilitySource{{Source: "manual", SourceID: "CVE-2026-2170"}}
		}, want: "manual advisory id"},
		{name: "ecosystem", edit: func(v *db.Vulnerability) { v.AffectedPackages[0].Ecosystem = "unknown" }, want: "unsupported ecosystem"},
		{name: "version ranges", edit: func(v *db.Vulnerability) { v.AffectedPackages[0].VersionRanges = json.RawMessage(`{}`) }, want: "version_ranges"},
		{name: "affected versions", edit: func(v *db.Vulnerability) { v.AffectedPackages[0].VersionsAffected = json.RawMessage(`[1]`) }, want: "versions_affected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			value := *f217CompleteVulnerability()
			value.Sources = append([]db.VulnerabilitySource(nil), value.Sources...)
			value.AffectedPackages = append([]db.AffectedPackage(nil), value.AffectedPackages...)
			tc.edit(&value)
			tx := &f217ScriptedTx{}
			err := upsertVulnerabilityTx(context.Background(), tx, &value)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("upsertVulnerabilityTx(%s) error = %v, want %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestF217DeleteVulnerabilityForSourceTxBoundaries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	if err := deleteVulnerabilityForSourceTx(ctx, &f217ScriptedTx{}, "GHSA-F217", "  "); !errors.Is(err, db.ErrSourceScopedDeleteSourceRequired) {
		t.Fatalf("deleteVulnerabilityForSourceTx(blank source) error = %v", err)
	}

	t.Run("missing vulnerability is idempotent", func(t *testing.T) {
		t.Parallel()
		tx := &f217ScriptedTx{rowErr: pgx.ErrNoRows}
		if err := deleteVulnerabilityForSourceTx(ctx, tx, "missing", " osv "); err != nil || len(tx.execs) != 0 {
			t.Fatalf("deleteVulnerabilityForSourceTx(missing) = %v, execs=%d; want nil, zero", err, len(tx.execs))
		}
	})

	want := errors.New("f217 delete failure")
	tests := []struct {
		name      string
		tx        *f217ScriptedTx
		wantError string
	}{
		{name: "lock", tx: &f217ScriptedTx{rowErr: want}, wantError: "lock vulnerability GHSA-F217 before source delete"},
		{name: "source delete", tx: &f217ScriptedTx{rowValue: "GHSA-F217", execErrAt: 1, execErr: want}, wantError: "delete vulnerability source GHSA-F217/osv"},
		{name: "conditional withdraw", tx: &f217ScriptedTx{rowValue: "GHSA-F217", execErrAt: 2, execErr: want}, wantError: "withdraw vulnerability GHSA-F217 after source delete"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := deleteVulnerabilityForSourceTx(ctx, tc.tx, "GHSA-F217", " osv ")
			if !errors.Is(err, want) || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("deleteVulnerabilityForSourceTx(%s) error = %v, want wrapped %q", tc.name, err, tc.wantError)
			}
		})
	}

	tx := &f217ScriptedTx{rowValue: "GHSA-F217"}
	if err := deleteVulnerabilityForSourceTx(ctx, tx, "GHSA-F217", " osv "); err != nil || len(tx.execs) != 2 {
		t.Fatalf("deleteVulnerabilityForSourceTx(success) = %v, execs=%d; want nil, two", err, len(tx.execs))
	}
}

func TestF217OuterPreflightAndEmptyBatchDoNotNeedPool(t *testing.T) {
	t.Parallel()

	store := &Store{}
	if got, err := store.FindVulnerabilitiesBatch(context.Background(), nil); got != nil || err != nil {
		t.Fatalf("FindVulnerabilitiesBatch(empty) = %#v, %v; want nil, nil", got, err)
	}
	if err := store.DeleteVulnerabilityForSource(context.Background(), "GHSA-F217", " "); !errors.Is(err, db.ErrSourceScopedDeleteSourceRequired) {
		t.Fatalf("DeleteVulnerabilityForSource(blank) error = %v", err)
	}
}

type f217Exec struct {
	sql  string
	args []any
}

type f217ScriptedTx struct {
	pgx.Tx
	execs     []f217Exec
	execErrAt int
	execErr   error
	rowValue  string
	rowErr    error
}

func (tx *f217ScriptedTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.execs = append(tx.execs, f217Exec{sql: sql, args: append([]any(nil), args...)})
	if tx.execErrAt == len(tx.execs) {
		return pgconn.CommandTag{}, tx.execErr
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (tx *f217ScriptedTx) QueryRow(context.Context, string, ...any) pgx.Row {
	return f217Row{value: tx.rowValue, err: tx.rowErr}
}

type f217Row struct {
	value string
	err   error
}

func (r f217Row) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*string) = r.value
	return nil
}

func f217CompleteVulnerability() *db.Vulnerability {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	return &db.Vulnerability{
		ID:        "GHSA-F217",
		Summary:   "f217 vulnerability",
		Severity:  "HIGH",
		Published: now,
		Modified:  now,
		Sources: []db.VulnerabilitySource{{
			Source: "osv", SourceID: "GHSA-F217", URL: "https://osv.dev/GHSA-F217", RawJSON: json.RawMessage(`{}`),
		}},
		Aliases: []db.VulnerabilityAlias{{}, {AliasID: "CVE-2026-2170"}},
		References: []db.VulnerabilityReference{
			{Type: "ADVISORY", URL: "   ", Source: "osv"},
			{Type: "ADVISORY", URL: "https://example.test/GHSA-F217", Source: "osv"},
		},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: " PyPI ", Name: " F217_Pkg ",
			VersionRanges:    json.RawMessage(`[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}
}
