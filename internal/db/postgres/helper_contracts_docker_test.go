//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestDBHelperPersistenceContractsAgainstPostgres(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	t.Run("F094 audit digest chain survives reads and classifies causal tampering", func(t *testing.T) {
		db.ClearAdminAuditDigestHMACKey()
		t.Cleanup(db.ClearAdminAuditDigestHMACKey)
		actions := []string{
			"f094.legacy." + suffix,
			"f094.hmac-one." + suffix,
			"f094.hmac-two." + suffix,
		}
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
			Action: actions[0], Details: json.RawMessage(`{"ordinal":"legacy"}`), IP: "192.0.2.94",
		}); err != nil {
			t.Fatalf("InsertAdminAuditLog(legacy) error = %v", err)
		}
		key := []byte("0123456789abcdef0123456789abcdef")
		db.SetAdminAuditDigestHMACKey(key)
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
			Action: actions[1], Details: json.RawMessage(`{"ordinal":"one"}`), IP: "192.0.2.95", CorrelationID: "corr-one-" + suffix,
		}); err != nil {
			t.Fatalf("InsertAdminAuditLog(first HMAC) error = %v", err)
		}
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
			Action: actions[2], Details: json.RawMessage(`{"ordinal":"two"}`), IP: "192.0.2.96", CorrelationID: "corr-two-" + suffix,
		}); err != nil {
			t.Fatalf("InsertAdminAuditLog(second HMAC) error = %v", err)
		}

		load := func() []db.AdminAuditLogEntry {
			t.Helper()
			entries, err := store.ListAdminAuditLog(ctx, 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			filtered := make([]db.AdminAuditLogEntry, 0, 3)
			for _, entry := range entries {
				if slicesContains(actions, entry.Action) {
					filtered = append(filtered, entry)
				}
			}
			if len(filtered) != 3 {
				t.Fatalf("filtered audit entries = %+v, want 3", filtered)
			}
			return filtered
		}
		requireStatuses := func(label string, entries []db.AdminAuditLogEntry, want ...string) {
			t.Helper()
			if len(entries) != len(want) {
				t.Fatalf("%s entries = %d, want %d", label, len(entries), len(want))
			}
			for i := range want {
				if entries[i].IntegrityStatus != want[i] {
					t.Errorf("%s entry %d (%s) status = %q, want %q", label, i, entries[i].Action, entries[i].IntegrityStatus, want[i])
				}
			}
		}

		entries := load()
		requireStatuses("configured key", entries, db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityVerified)
		if !strings.HasPrefix(entries[0].RowDigest, "hmac-sha256:") || !strings.HasPrefix(entries[1].RowDigest, "hmac-sha256:") || !strings.HasPrefix(entries[2].RowDigest, "sha256:") {
			t.Fatalf("persisted digest algorithms = %q, %q, %q", entries[0].RowDigest, entries[1].RowDigest, entries[2].RowDigest)
		}
		if entries[0].PreviousDigest != entries[1].RowDigest || entries[1].PreviousDigest != entries[2].RowDigest {
			t.Fatalf("persisted digest links = %+v", entries)
		}

		db.ClearAdminAuditDigestHMACKey()
		requireStatuses("key unavailable", load(), db.AdminAuditIntegrityBroken, db.AdminAuditIntegrityBroken, db.AdminAuditIntegrityVerified)
		db.SetAdminAuditDigestHMACKey(key)
		entries = load()
		requireStatuses("key restored", entries, db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityVerified)

		middle := entries[1]
		if _, err := store.pool.Exec(ctx, `UPDATE admin_audit_log SET details = '{"tampered":true}'::jsonb WHERE id = $1`, middle.ID); err != nil {
			t.Fatalf("tamper audit details: %v", err)
		}
		requireStatuses("details tampered", load(), db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityBroken, db.AdminAuditIntegrityVerified)
		if _, err := store.pool.Exec(ctx, `UPDATE admin_audit_log SET details = $1::jsonb WHERE id = $2`, middle.Details, middle.ID); err != nil {
			t.Fatalf("restore audit details: %v", err)
		}
		requireStatuses("details restored", load(), db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityVerified)

		if _, err := store.pool.Exec(ctx, `UPDATE admin_audit_log SET row_digest = $1 WHERE id = $2`, "hmac-sha256:"+strings.Repeat("0", 64), middle.ID); err != nil {
			t.Fatalf("tamper row digest: %v", err)
		}
		requireStatuses("digest tampered", load(), db.AdminAuditIntegrityBroken, db.AdminAuditIntegrityBroken, db.AdminAuditIntegrityVerified)
		if _, err := store.pool.Exec(ctx, `UPDATE admin_audit_log SET row_digest = $1 WHERE id = $2`, middle.RowDigest, middle.ID); err != nil {
			t.Fatalf("restore row digest: %v", err)
		}
		requireStatuses("digest restored", load(), db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityVerified, db.AdminAuditIntegrityVerified)
	})

	t.Run("F096 status vocabulary persists and constraint rejects invalid raw values", func(t *testing.T) {
		for i, status := range db.FeedSyncStatusValues() {
			feedName := fmt.Sprintf("f096-%d-%s-%s", i, status, suffix)
			input := &db.FeedSyncStatus{FeedName: feedName, LastSyncStatus: status, EntriesSynced: i, EntriesTotal: i}
			if err := store.UpsertFeedSyncStatus(ctx, input); err != nil {
				t.Fatalf("UpsertFeedSyncStatus(%q) error = %v", status, err)
			}
			got, err := store.GetFeedSyncStatus(ctx, feedName)
			if err != nil || got == nil || got.LastSyncStatus != status || got.EntriesSynced != i || got.EntriesTotal != i {
				t.Fatalf("GetFeedSyncStatus(%q) = %+v, %v", status, got, err)
			}
		}

		pendingFeed := "f096-whitespace-" + suffix
		input := &db.FeedSyncStatus{FeedName: pendingFeed, LastSyncStatus: " \t\n "}
		if err := store.UpsertFeedSyncStatus(ctx, input); err != nil {
			t.Fatalf("UpsertFeedSyncStatus(whitespace) error = %v", err)
		}
		if input.LastSyncStatus != db.FeedSyncStatusPending {
			t.Fatalf("normalized input status = %q, want pending", input.LastSyncStatus)
		}
		got, err := store.GetFeedSyncStatus(ctx, pendingFeed)
		if err != nil || got == nil || got.LastSyncStatus != db.FeedSyncStatusPending {
			t.Fatalf("GetFeedSyncStatus(whitespace) = %+v, %v", got, err)
		}

		if _, err := store.pool.Exec(ctx,
			`INSERT INTO feed_sync_status(feed_name, last_sync_status) VALUES ($1, $2)`,
			"f096-invalid-"+suffix, "not-a-status"); err == nil {
			t.Fatal("raw invalid feed status insert error = nil, want database constraint rejection")
		}
		var count int
		if err := store.pool.QueryRow(ctx, `SELECT COUNT(*) FROM feed_sync_status WHERE feed_name = $1`, "f096-invalid-"+suffix).Scan(&count); err != nil {
			t.Fatalf("count rejected raw status: %v", err)
		}
		if count != 0 {
			t.Fatalf("rejected raw status rows = %d, want 0", count)
		}
	})

	t.Run("F097 persisted risk types return supply chain findings", func(t *testing.T) {
		findings := []db.MaliciousFinding{
			{ID: "F097-SUPPLY-" + suffix, Ecosystem: "npm", Name: "f097-supply-" + suffix, Versions: json.RawMessage(`["1.2.3"]`), Source: "socket", RiskType: "supply_chain", Severity: "HIGH", Summary: "supply-chain risk"},
			{ID: "F097-TYPO-" + suffix, Ecosystem: "npm", Name: "f097-typo-" + suffix, Source: "socket", RiskType: "typosquatting", Severity: "MEDIUM", Summary: "typosquatting risk"},
		}
		for i := range findings {
			if err := store.UpsertMaliciousFinding(ctx, &findings[i]); err != nil {
				t.Fatalf("UpsertMaliciousFinding(%s) error = %v", findings[i].RiskType, err)
			}
		}

		assertFinding := func(label string, got []domain.Finding, wantID, wantRisk, wantVersion string) {
			t.Helper()
			if len(got) != 1 || got[0].AdvisoryID != wantID || got[0].Type != domain.FindingTypeSupplyChainRisk || got[0].RiskType != wantRisk || got[0].Version != wantVersion {
				t.Fatalf("%s = %+v, want one %s/%s at %q", label, got, wantID, wantRisk, wantVersion)
			}
		}
		got, err := store.FindMalicious(ctx, "npm", findings[0].Name, "1.2.3")
		if err != nil {
			t.Fatalf("FindMalicious(supply_chain) error = %v", err)
		}
		assertFinding("single supply_chain", got, findings[0].ID, "supply_chain", "1.2.3")
		got, err = store.FindMalicious(ctx, "npm", findings[1].Name, "9.9.9")
		if err != nil {
			t.Fatalf("FindMalicious(typosquatting) error = %v", err)
		}
		assertFinding("single typosquatting", got, findings[1].ID, "typosquatting", "9.9.9")

		batch, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
			{Ecosystem: "npm", Name: findings[0].Name, Version: "1.2.3"},
			{Ecosystem: "npm", Name: findings[1].Name, Version: "2.0.0"},
		})
		if err != nil || len(batch) != 2 {
			t.Fatalf("FindMaliciousBatch(versioned) = %+v, %v; want 2", batch, err)
		}
		for _, finding := range batch {
			if finding.Type != domain.FindingTypeSupplyChainRisk {
				t.Errorf("versioned batch finding = %+v, want supply_chain_risk", finding)
			}
		}

		versionless, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
			{Ecosystem: "npm", Name: findings[0].Name},
			{Ecosystem: "npm", Name: findings[1].Name},
		})
		if err != nil || len(versionless) != 2 {
			t.Fatalf("FindMaliciousBatch(versionless) = %+v, %v; want 2", versionless, err)
		}
		for _, finding := range versionless {
			if finding.Type != domain.FindingTypeSupplyChainRisk || finding.Version != "" {
				t.Errorf("versionless finding = %+v", finding)
			}
		}
	})
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
