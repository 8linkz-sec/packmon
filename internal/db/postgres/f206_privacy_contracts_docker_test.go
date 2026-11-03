//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF206PrivacyExportPostgresContracts(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	db.SetAdminAuditDigestHMACKey([]byte("f206-fixed-admin-audit-hmac-key"))
	t.Cleanup(db.ClearAdminAuditDigestHMACKey)

	auditCount := func(t *testing.T) int {
		t.Helper()
		var count int
		if err := store.pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM admin_audit_log`).Scan(&count); err != nil {
			t.Fatalf("count admin audit rows: %v", err)
		}
		return count
	}

	t.Run("empty export is complete and audited without the raw selector", func(t *testing.T) {
		selector := db.PrivacyExportSelector{Type: db.PrivacySelectorRepoName, Value: "org/f206-absent"}
		started := time.Now().UTC()
		export, err := store.ExportPrivacyMetadata(ctx, selector, &db.AdminAuditEntry{
			Action:  "f206.privacy.empty",
			Details: json.RawMessage(`{"operator":"f206"}`),
		})
		finished := time.Now().UTC()
		if err != nil {
			t.Fatalf("ExportPrivacyMetadata(empty) error = %v", err)
		}
		if export == nil || export.Selector != selector || export.ScanLogs == nil || export.AdminAuditLogs == nil || export.ScanLogCount != 0 || export.AdminAuditCount != 0 || len(export.ScanLogs) != 0 || len(export.AdminAuditLogs) != 0 {
			t.Fatalf("empty export = %+v", export)
		}
		if export.GeneratedAt.Before(started) || export.GeneratedAt.After(finished) || export.GeneratedAt.Location() != time.UTC {
			t.Fatalf("GeneratedAt = %v, want UTC within [%v, %v]", export.GeneratedAt, started, finished)
		}

		logs, err := store.ListAdminAuditLog(ctx, 1)
		if err != nil || len(logs) != 1 {
			t.Fatalf("ListAdminAuditLog() = %+v, %v", logs, err)
		}
		if logs[0].Action != "f206.privacy.empty" || logs[0].IntegrityStatus != db.AdminAuditIntegrityVerified || !strings.HasPrefix(logs[0].RowDigest, "hmac-sha256:") {
			t.Fatalf("empty export audit = %+v", logs[0])
		}
		if strings.Contains(string(logs[0].Details), selector.Value) {
			t.Fatalf("empty export audit leaked raw selector: %s", logs[0].Details)
		}
		details := map[string]string{}
		if err := json.Unmarshal(logs[0].Details, &details); err != nil {
			t.Fatalf("decode empty export audit details: %v", err)
		}
		if details["operator"] != "f206" || details["selector_type"] != selector.Type || details["selector_digest"] != selector.Digest() || details["scan_log_count"] != "0" || details["admin_audit_count"] != "0" {
			t.Fatalf("empty export audit details = %v", details)
		}
	})

	t.Run("full nullable and empty JSON fields retain bounded metadata and HMAC evidence", func(t *testing.T) {
		selector := db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "2001:db8::206"}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
			ScanID:                "f206-nullable",
			ScannedAt:             now.Add(-time.Minute),
			ClientIP:              selector.Value,
			BlockThreshold:        "HIGH",
			FeedStatus:            "healthy",
			ManualAdvisoriesCount: 0,
		}); err != nil {
			t.Fatalf("InsertScanLog(nullable) error = %v", err)
		}
		if _, err := store.pool.Exec(ctx, `
			UPDATE scan_log
			SET repo_name = NULL,
			    client_version = NULL,
			    api_key_id = NULL,
			    api_key_name = NULL,
			    idempotency_key = NULL
			WHERE scan_id = $1`, "f206-nullable"); err != nil {
			t.Fatalf("make scan row nullable: %v", err)
		}
		apiKeyID, err := store.CreateAPIKey(ctx, "f206-key", "f206-key-hash", nil)
		if err != nil {
			t.Fatalf("CreateAPIKey() error = %v", err)
		}
		if err := store.InsertScanLog(ctx, &db.ScanLogEntry{
			ScanID:                "f206-full",
			RepoName:              "org/privacy-f206",
			ScannedAt:             now,
			PackagesCount:         21,
			FindingsCount:         3,
			DurationMs:            206,
			ClientIP:              selector.Value,
			ClientVersion:         "packmon/20.6",
			APIKeyID:              apiKeyID,
			APIKeyName:            "f206-key",
			CorrelationID:         "corr-f206-full",
			IdempotencyKey:        "idem-f206-full",
			RequestDigest:         "sha256:f206-request",
			ResultDigest:          "sha256:f206-result",
			FindingsBlocking:      true,
			BlockThreshold:        "MEDIUM",
			FeedStatus:            "healthy",
			FeedVersions:          map[string]string{"osv": "2026-11-03", "ghsa": "2026-11-02"},
			FindingIDs:            []string{"CVE-2026-0206", "GHSA-f206-test"},
			FindingSeverities:     []string{"HIGH", "MEDIUM"},
			ManualAdvisoriesCount: 1,
		}); err != nil {
			t.Fatalf("InsertScanLog(full) error = %v", err)
		}
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "f206.audit.nullable", IP: selector.Value}); err != nil {
			t.Fatalf("InsertAdminAuditLog(nullable) error = %v", err)
		}
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
			Action:        "f206.audit.full",
			Details:       json.RawMessage(`{"repo_name":"org/privacy-f206","safe":true}`),
			IP:            selector.Value,
			CorrelationID: "corr-f206-full",
		}); err != nil {
			t.Fatalf("InsertAdminAuditLog(full) error = %v", err)
		}

		export, err := store.ExportPrivacyMetadata(ctx, selector, &db.AdminAuditEntry{Action: "f206.privacy.full", Details: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatalf("ExportPrivacyMetadata(full) error = %v", err)
		}
		if export.ScanLogCount != 2 || len(export.ScanLogs) != 2 || export.AdminAuditCount != 2 || len(export.AdminAuditLogs) != 2 {
			t.Fatalf("full export counts = scans %d/%d, audits %d/%d", export.ScanLogCount, len(export.ScanLogs), export.AdminAuditCount, len(export.AdminAuditLogs))
		}

		full := export.ScanLogs[0]
		if full.ScanID != "f206-full" || full.RepoName != "org/privacy-f206" || !strings.HasPrefix(full.ClientIP, selector.Value) || full.APIKeyID != apiKeyID || full.APIKeyName != "f206-key" || full.CorrelationID != "corr-f206-full" || full.IdempotencyKey != "idem-f206-full" || full.RequestDigest != "sha256:f206-request" || full.ResultDigest != "sha256:f206-result" || !full.FindingsBlocking || full.FeedVersions["osv"] != "2026-11-03" || len(full.FindingIDs) != 2 || len(full.FindingSeverities) != 2 {
			t.Fatalf("full scan export = %+v", full)
		}
		nullable := export.ScanLogs[1]
		if nullable.ScanID != "f206-nullable" || nullable.RepoName != "" || nullable.ClientVersion != "" || nullable.APIKeyID != 0 || nullable.APIKeyName != "" || nullable.IdempotencyKey != "" || nullable.RequestDigest != "" || nullable.ResultDigest != "" || nullable.BlockThreshold != "HIGH" || nullable.FeedStatus != "healthy" || nullable.FeedVersions == nil || len(nullable.FeedVersions) != 0 || nullable.FindingIDs == nil || len(nullable.FindingIDs) != 0 || nullable.FindingSeverities == nil || len(nullable.FindingSeverities) != 0 {
			t.Fatalf("nullable scan export = %+v", nullable)
		}

		if export.AdminAuditLogs[0].Action != "f206.audit.full" || string(export.AdminAuditLogs[0].Details) != `{"safe": true, "repo_name": "org/privacy-f206"}` || export.AdminAuditLogs[0].CorrelationID != "corr-f206-full" {
			t.Fatalf("full audit export = %+v", export.AdminAuditLogs[0])
		}
		if export.AdminAuditLogs[1].Action != "f206.audit.nullable" || export.AdminAuditLogs[1].Details != nil || export.AdminAuditLogs[1].CorrelationID != "" {
			t.Fatalf("nullable audit export = %+v", export.AdminAuditLogs[1])
		}
		for i, audit := range export.AdminAuditLogs {
			if audit.IntegrityStatus != db.AdminAuditIntegrityVerified || !strings.HasPrefix(audit.RowDigest, "hmac-sha256:") {
				t.Fatalf("audit export[%d] integrity = %+v", i, audit)
			}
		}
	})

	t.Run("invalid audit details roll back without returning partial data", func(t *testing.T) {
		before := auditCount(t)
		selector := db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "2001:db8::206"}
		export, err := store.ExportPrivacyMetadata(ctx, selector, &db.AdminAuditEntry{Action: "f206.privacy.invalid-details", Details: json.RawMessage(`{`)})
		if export != nil || err == nil || !strings.Contains(err.Error(), "encode privacy export audit details") {
			t.Fatalf("ExportPrivacyMetadata(invalid details) = %+v, %v", export, err)
		}
		if after := auditCount(t); after != before {
			t.Fatalf("audit rows after invalid details = %d, want %d", after, before)
		}
	})

	t.Run("nil audit fails closed without returning partial data", func(t *testing.T) {
		before := auditCount(t)
		selector := db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "2001:db8::206"}
		export, err := store.ExportPrivacyMetadata(ctx, selector, nil)
		if export != nil || !errors.Is(err, db.ErrAdminAuditLog) || !strings.Contains(err.Error(), errNilAdminAuditEntry.Error()) {
			t.Fatalf("ExportPrivacyMetadata(nil audit) = %+v, %v", export, err)
		}
		if after := auditCount(t); after != before {
			t.Fatalf("audit rows after nil audit = %d, want %d", after, before)
		}
	})

	t.Run("invalid selector and query value fail before audit persistence", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			selector db.PrivacyExportSelector
			want     string
		}{
			{name: "unsupported selector", selector: db.PrivacyExportSelector{Type: "raw", Value: "secret"}, want: "unsupported privacy selector"},
			{name: "invalid API key ID", selector: db.PrivacyExportSelector{Type: db.PrivacySelectorAPIKeyID, Value: "not-an-integer"}, want: "privacy scan log"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				before := auditCount(t)
				export, err := store.ExportPrivacyMetadata(ctx, tc.selector, &db.AdminAuditEntry{Action: "f206.privacy.rejected", Details: json.RawMessage(`{}`)})
				if export != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("ExportPrivacyMetadata(%s) = %+v, %v", tc.name, export, err)
				}
				if after := auditCount(t); after != before {
					t.Fatalf("audit rows after %s = %d, want %d", tc.name, after, before)
				}
			})
		}
	})
}
