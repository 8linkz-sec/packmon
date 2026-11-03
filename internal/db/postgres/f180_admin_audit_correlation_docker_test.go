//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF180AdminAuditCorrelationPersistenceAndPrivacyAgainstPostgres(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	db.SetAdminAuditDigestHMACKey([]byte("f180-fixed-admin-audit-correlation-hmac-key"))
	t.Cleanup(db.ClearAdminAuditDigestHMACKey)

	reset := func(t *testing.T) {
		t.Helper()
		if _, err := store.pool.Exec(ctx, `TRUNCATE admin_audit_log RESTART IDENTITY`); err != nil {
			t.Fatalf("reset admin audit log: %v", err)
		}
	}

	t.Run("insert_and_list_round_trip_nonempty_typed_correlation", func(t *testing.T) {
		reset(t)
		want := &db.AdminAuditEntry{
			Action:        "f180.typed.round_trip",
			Details:       json.RawMessage(`{"kind":"typed"}`),
			IP:            "2001:db8::180",
			CorrelationID: "f180-correlation-round-trip",
		}
		if err := store.InsertAdminAuditLog(ctx, want); err != nil {
			t.Fatalf("InsertAdminAuditLog() error = %v", err)
		}
		entries, err := store.ListAdminAuditLog(ctx, 10)
		if err != nil || len(entries) != 1 {
			t.Fatalf("ListAdminAuditLog() = %+v, %v; want one row", entries, err)
		}
		got := entries[0]
		var gotDetails map[string]string
		detailsErr := json.Unmarshal(got.Details, &gotDetails)
		if got.Action != want.Action || detailsErr != nil || gotDetails["kind"] != "typed" || got.IP != "2001:db8::180/128" || got.CorrelationID != want.CorrelationID || got.CreatedAt.IsZero() || got.RowDigest == "" || got.IntegrityStatus != db.AdminAuditIntegrityVerified {
			t.Fatalf("typed correlation round trip = %+v, want action/details/ip/correlation plus verified digest", got)
		}
	})

	t.Run("paged_list_preserves_typed_correlation_and_order", func(t *testing.T) {
		reset(t)
		for i := 0; i < 5; i++ {
			entry := &db.AdminAuditEntry{Action: fmt.Sprintf("f180.paged.%d", i), CorrelationID: fmt.Sprintf("f180-page-correlation-%d", i)}
			if err := store.InsertAdminAuditLog(ctx, entry); err != nil {
				t.Fatalf("InsertAdminAuditLog(%d) error = %v", i, err)
			}
		}
		first, err := store.ListAdminAuditLogPage(ctx, 2, 0)
		if err != nil || len(first) != 2 || first[0].Action != "f180.paged.4" || first[0].CorrelationID != "f180-page-correlation-4" || first[1].Action != "f180.paged.3" || first[1].CorrelationID != "f180-page-correlation-3" {
			t.Fatalf("first typed correlation page = %+v, %v", first, err)
		}
		second, err := store.ListAdminAuditLogPage(ctx, 2, 2)
		if err != nil || len(second) != 2 || second[0].Action != "f180.paged.2" || second[0].CorrelationID != "f180-page-correlation-2" || second[1].Action != "f180.paged.1" || second[1].CorrelationID != "f180-page-correlation-1" {
			t.Fatalf("second typed correlation page = %+v, %v", second, err)
		}
		last, err := store.ListAdminAuditLogPage(ctx, 2, 4)
		if err != nil || len(last) != 1 || last[0].Action != "f180.paged.0" || last[0].CorrelationID != "f180-page-correlation-0" {
			t.Fatalf("last typed correlation page = %+v, %v", last, err)
		}
	})

	t.Run("privacy_export_matches_typed_and_legacy_correlations_exactly", func(t *testing.T) {
		reset(t)
		const correlation = "f180-privacy-correlation"
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "f180.privacy.typed", Details: json.RawMessage(`{"kind":"typed"}`), CorrelationID: correlation}); err != nil {
			t.Fatalf("insert typed privacy audit: %v", err)
		}
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO admin_audit_log(action,details,correlation_id,created_at,previous_digest,row_digest) VALUES
			('f180.privacy.legacy',jsonb_build_object('correlation_id',$1::text,'kind','legacy'),'','2025-01-02Z','',''),
			('f180.privacy.unrelated',jsonb_build_object('correlation_id','other-correlation'),'other-correlation','2025-01-03Z','','')`, correlation); err != nil {
			t.Fatalf("seed legacy/unrelated privacy audits: %v", err)
		}
		selector := db.PrivacyExportSelector{Type: db.PrivacySelectorCorrelationID, Value: correlation}
		export, err := store.ExportPrivacyMetadata(ctx, selector, &db.AdminAuditEntry{Action: "f180.privacy.export", CorrelationID: "f180-export-audit"})
		if err != nil {
			t.Fatalf("ExportPrivacyMetadata() error = %v", err)
		}
		if export.ScanLogCount != 0 || export.AdminAuditCount != 2 || len(export.AdminAuditLogs) != 2 {
			t.Fatalf("privacy correlation counts = scans:%d audits:%d rows:%d, want 0/2/2", export.ScanLogCount, export.AdminAuditCount, len(export.AdminAuditLogs))
		}
		matched := map[string]db.PrivacyExportAdminAudit{}
		for _, entry := range export.AdminAuditLogs {
			matched[entry.Action] = entry
		}
		if len(matched) != 2 || matched["f180.privacy.typed"].CorrelationID != correlation || matched["f180.privacy.legacy"].CorrelationID != "" || !json.Valid(matched["f180.privacy.legacy"].Details) {
			t.Fatalf("privacy typed/legacy correlations = %+v", matched)
		}
		var legacyDetails map[string]string
		if err := json.Unmarshal(matched["f180.privacy.legacy"].Details, &legacyDetails); err != nil || legacyDetails["correlation_id"] != correlation || legacyDetails["kind"] != "legacy" {
			t.Fatalf("legacy correlation details = %v, error=%v", legacyDetails, err)
		}
		if _, leaked := matched["f180.privacy.unrelated"]; leaked {
			t.Fatal("privacy correlation export included unrelated audit")
		}
	})
}
