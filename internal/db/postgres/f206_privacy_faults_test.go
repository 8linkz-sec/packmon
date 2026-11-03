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
)

type f206QueryCall struct {
	ctx  context.Context
	sql  string
	args []any
}

type f206ScriptedTx struct {
	pgx.Tx
	rows     pgx.Rows
	queryErr error
	queries  []f206QueryCall
}

func (tx *f206ScriptedTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.queries = append(tx.queries, f206QueryCall{ctx: ctx, sql: sql, args: append([]any(nil), args...)})
	return tx.rows, tx.queryErr
}

type f206ScriptedRows struct {
	pgx.Rows
	scans  []func(...any) error
	index  int
	err    error
	closed bool
}

func (rows *f206ScriptedRows) Close() {
	rows.closed = true
}

func (rows *f206ScriptedRows) Err() error {
	return rows.err
}

func (rows *f206ScriptedRows) Next() bool {
	return rows.index < len(rows.scans)
}

func (rows *f206ScriptedRows) Scan(dest ...any) error {
	scan := rows.scans[rows.index]
	rows.index++
	return scan(dest...)
}

func f206ScanLogRow(feedVersions, findingIDs, findingSeverities string) func(...any) error {
	return func(dest ...any) error {
		*dest[0].(*string) = "scan-f206"
		*dest[1].(*string) = "org/privacy"
		*dest[2].(*time.Time) = time.Date(2026, 11, 3, 9, 8, 7, 0, time.UTC)
		*dest[3].(*int) = 17
		*dest[4].(*int) = 4
		*dest[5].(*int) = 29
		*dest[6].(*string) = "2001:db8::206"
		*dest[7].(*string) = "packmon/20.6"
		*dest[8].(*int) = 206
		*dest[9].(*string) = "privacy-key"
		*dest[10].(*string) = "corr-f206"
		*dest[11].(*string) = "idem-f206"
		*dest[12].(*string) = "sha256:request-f206"
		*dest[13].(*string) = "sha256:result-f206"
		*dest[14].(*bool) = true
		*dest[15].(*string) = "HIGH"
		*dest[16].(*string) = "healthy"
		*dest[17].(*string) = feedVersions
		*dest[18].(*string) = findingIDs
		*dest[19].(*string) = findingSeverities
		*dest[20].(*int) = 2
		return nil
	}
}

func f206AdminAuditRow(entry db.AdminAuditLogEntry, details *string) func(...any) error {
	return func(dest ...any) error {
		*dest[0].(*int) = entry.ID
		*dest[1].(*string) = entry.Action
		*dest[2].(**string) = details
		*dest[3].(*string) = entry.IP
		*dest[4].(*string) = entry.CorrelationID
		*dest[5].(*time.Time) = entry.CreatedAt
		*dest[6].(*string) = entry.PreviousDigest
		*dest[7].(*string) = entry.RowDigest
		return nil
	}
}

func TestF206QueryPrivacyScanLogsDataAndFailureBoundaries(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{ name string }{"f206"}, "context")
	selector := db.PrivacyExportSelector{Type: db.PrivacySelectorRepoName, Value: "org/privacy"}

	t.Run("empty and populated results preserve the query contract", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			rows  *f206ScriptedRows
			count int
		}{
			{name: "empty", rows: &f206ScriptedRows{}},
			{name: "populated", rows: &f206ScriptedRows{scans: []func(...any) error{f206ScanLogRow(`{"osv":"2026-11-03"}`, `["CVE-2026-0206"]`, `["HIGH"]`)}}, count: 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tx := &f206ScriptedTx{rows: tc.rows}
				got, err := queryPrivacyScanLogs(ctx, tx, selector)
				if err != nil {
					t.Fatalf("queryPrivacyScanLogs() error = %v", err)
				}
				if got == nil || len(got) != tc.count {
					t.Fatalf("queryPrivacyScanLogs() = %#v, want non-nil result with %d rows", got, tc.count)
				}
				if !tc.rows.closed {
					t.Fatal("queryPrivacyScanLogs() did not close rows")
				}
				if len(tx.queries) != 1 || tx.queries[0].ctx != ctx || !strings.Contains(tx.queries[0].sql, "WHERE repo_name = $1") || !strings.Contains(tx.queries[0].sql, "ORDER BY scanned_at DESC, id DESC") || !reflect.DeepEqual(tx.queries[0].args, []any{selector.Value}) {
					t.Fatalf("query call = %#v, want parameterized repository query with stable order", tx.queries)
				}
				if tc.count == 1 {
					entry := got[0]
					if entry.ScanID != "scan-f206" || entry.APIKeyID != 206 || entry.ClientIP != "2001:db8::206" || entry.FeedVersions["osv"] != "2026-11-03" || !reflect.DeepEqual(entry.FindingIDs, []string{"CVE-2026-0206"}) || !reflect.DeepEqual(entry.FindingSeverities, []string{"HIGH"}) {
						t.Fatalf("decoded scan row = %+v", entry)
					}
				}
			})
		}
	})

	t.Run("unsupported selector does not query", func(t *testing.T) {
		tx := &f206ScriptedTx{}
		got, err := queryPrivacyScanLogs(ctx, tx, db.PrivacyExportSelector{Type: "raw", Value: "secret"})
		if got != nil || err == nil || !strings.Contains(err.Error(), "unsupported privacy selector") || len(tx.queries) != 0 {
			t.Fatalf("queryPrivacyScanLogs() = %#v, %v; queries = %d", got, err, len(tx.queries))
		}
	})

	t.Run("query failure returns no partial result", func(t *testing.T) {
		marker := errors.New("query failed")
		tx := &f206ScriptedTx{queryErr: marker}
		got, err := queryPrivacyScanLogs(ctx, tx, selector)
		if got != nil || !errors.Is(err, marker) || !strings.Contains(err.Error(), "privacy export scan log") {
			t.Fatalf("queryPrivacyScanLogs() = %#v, %v", got, err)
		}
	})

	t.Run("scan failure closes rows and returns no partial result", func(t *testing.T) {
		marker := errors.New("scan failed")
		rows := &f206ScriptedRows{scans: []func(...any) error{func(...any) error { return marker }}}
		got, err := queryPrivacyScanLogs(ctx, &f206ScriptedTx{rows: rows}, selector)
		if got != nil || !errors.Is(err, marker) || !strings.Contains(err.Error(), "scan privacy scan log row") || !rows.closed {
			t.Fatalf("queryPrivacyScanLogs() = %#v, %v; closed = %t", got, err, rows.closed)
		}
	})

	for _, tc := range []struct {
		name       string
		feed       string
		ids        string
		severities string
		want       string
	}{
		{name: "feed versions", feed: `{`, ids: `[]`, severities: `[]`, want: "feed versions"},
		{name: "finding ids", feed: `{}`, ids: `[`, severities: `[]`, want: "finding ids"},
		{name: "finding severities", feed: `{}`, ids: `[]`, severities: `[`, want: "finding severities"},
	} {
		t.Run("invalid "+tc.name+" JSON returns no partial result", func(t *testing.T) {
			rows := &f206ScriptedRows{scans: []func(...any) error{f206ScanLogRow(tc.feed, tc.ids, tc.severities)}}
			got, err := queryPrivacyScanLogs(ctx, &f206ScriptedTx{rows: rows}, selector)
			if got != nil || err == nil || !strings.Contains(err.Error(), "decode privacy scan log "+tc.want) || !rows.closed {
				t.Fatalf("queryPrivacyScanLogs() = %#v, %v; closed = %t", got, err, rows.closed)
			}
		})
	}

	t.Run("iteration failure discards decoded rows", func(t *testing.T) {
		marker := errors.New("iteration failed")
		rows := &f206ScriptedRows{
			scans: []func(...any) error{f206ScanLogRow(`{}`, `[]`, `[]`)},
			err:   marker,
		}
		got, err := queryPrivacyScanLogs(ctx, &f206ScriptedTx{rows: rows}, selector)
		if got != nil || !errors.Is(err, marker) || !strings.Contains(err.Error(), "iterate privacy scan log rows") || !rows.closed {
			t.Fatalf("queryPrivacyScanLogs() = %#v, %v; closed = %t", got, err, rows.closed)
		}
	})
}

func TestF206QueryPrivacyAdminAuditLogsDataAndFailureBoundaries(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{ name string }{"f206-admin"}, "context")
	selector := db.PrivacyExportSelector{Type: db.PrivacySelectorCorrelationID, Value: "corr-f206"}

	t.Run("empty result is non-nil and closes rows", func(t *testing.T) {
		rows := &f206ScriptedRows{}
		tx := &f206ScriptedTx{rows: rows}
		got, err := queryPrivacyAdminAuditLogs(ctx, tx, selector)
		if err != nil || got == nil || len(got) != 0 || !rows.closed {
			t.Fatalf("queryPrivacyAdminAuditLogs() = %#v, %v; closed = %t", got, err, rows.closed)
		}
		if len(tx.queries) != 1 || tx.queries[0].ctx != ctx || !strings.Contains(tx.queries[0].sql, "correlation_id = $1") || !strings.Contains(tx.queries[0].sql, "ORDER BY created_at DESC, id DESC") || !reflect.DeepEqual(tx.queries[0].args, []any{selector.Value}) {
			t.Fatalf("query call = %#v, want parameterized correlation query with stable order", tx.queries)
		}
	})

	t.Run("nullable details and HMAC chain are exported and annotated", func(t *testing.T) {
		key := []byte("f206-fixed-admin-audit-hmac-key")
		db.SetAdminAuditDigestHMACKey(key)
		t.Cleanup(db.ClearAdminAuditDigestHMACKey)

		createdAt := time.Date(2026, 11, 3, 10, 0, 0, 123000, time.UTC)
		older := db.AdminAuditLogEntry{ID: 205, Action: "privacy.nullable", IP: "2001:db8::205", CorrelationID: selector.Value, CreatedAt: createdAt.Add(-time.Minute)}
		older.RowDigest = db.ComputeAdminAuditDigest(older)
		details := `{"repo_name":"org/privacy","safe":true}`
		newer := db.AdminAuditLogEntry{ID: 206, Action: "privacy.full", Details: json.RawMessage(details), IP: "2001:db8::206", CorrelationID: selector.Value, CreatedAt: createdAt, PreviousDigest: older.RowDigest}
		newer.RowDigest = db.ComputeAdminAuditDigest(newer)

		rows := &f206ScriptedRows{scans: []func(...any) error{
			f206AdminAuditRow(newer, &details),
			f206AdminAuditRow(older, nil),
		}}
		got, err := queryPrivacyAdminAuditLogs(ctx, &f206ScriptedTx{rows: rows}, selector)
		if err != nil || len(got) != 2 {
			t.Fatalf("queryPrivacyAdminAuditLogs() = %#v, %v", got, err)
		}
		if string(got[0].Details) != details || got[0].PreviousDigest != older.RowDigest || got[0].RowDigest != newer.RowDigest || got[0].IntegrityStatus != db.AdminAuditIntegrityVerified {
			t.Fatalf("full audit row = %+v", got[0])
		}
		if got[1].Details != nil || got[1].RowDigest != older.RowDigest || got[1].IntegrityStatus != db.AdminAuditIntegrityVerified {
			t.Fatalf("nullable audit row = %+v", got[1])
		}
	})

	t.Run("unsupported selector does not query", func(t *testing.T) {
		tx := &f206ScriptedTx{}
		got, err := queryPrivacyAdminAuditLogs(ctx, tx, db.PrivacyExportSelector{Type: "raw", Value: "secret"})
		if got != nil || err == nil || !strings.Contains(err.Error(), "unsupported privacy selector") || len(tx.queries) != 0 {
			t.Fatalf("queryPrivacyAdminAuditLogs() = %#v, %v; queries = %d", got, err, len(tx.queries))
		}
	})

	t.Run("query failure returns no partial result", func(t *testing.T) {
		marker := errors.New("query failed")
		got, err := queryPrivacyAdminAuditLogs(ctx, &f206ScriptedTx{queryErr: marker}, selector)
		if got != nil || !errors.Is(err, marker) || !strings.Contains(err.Error(), "privacy export admin audit log") {
			t.Fatalf("queryPrivacyAdminAuditLogs() = %#v, %v", got, err)
		}
	})

	t.Run("scan failure closes rows and returns no partial result", func(t *testing.T) {
		marker := errors.New("scan failed")
		rows := &f206ScriptedRows{scans: []func(...any) error{func(...any) error { return marker }}}
		got, err := queryPrivacyAdminAuditLogs(ctx, &f206ScriptedTx{rows: rows}, selector)
		if got != nil || !errors.Is(err, marker) || !strings.Contains(err.Error(), "scan privacy admin audit row") || !rows.closed {
			t.Fatalf("queryPrivacyAdminAuditLogs() = %#v, %v; closed = %t", got, err, rows.closed)
		}
	})

	t.Run("iteration failure discards decoded rows", func(t *testing.T) {
		marker := errors.New("iteration failed")
		entry := db.AdminAuditLogEntry{ID: 206, Action: "privacy", CreatedAt: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)}
		rows := &f206ScriptedRows{scans: []func(...any) error{f206AdminAuditRow(entry, nil)}, err: marker}
		got, err := queryPrivacyAdminAuditLogs(ctx, &f206ScriptedTx{rows: rows}, selector)
		if got != nil || !errors.Is(err, marker) || !strings.Contains(err.Error(), "iterate privacy admin audit rows") || !rows.closed {
			t.Fatalf("queryPrivacyAdminAuditLogs() = %#v, %v; closed = %t", got, err, rows.closed)
		}
	})
}
