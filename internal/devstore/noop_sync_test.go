package devstore

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "github.com/8linkz-sec/packmon/internal/api/v1"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestNoopStoreFeedImportAndSync(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	apiStore := v1.NewDBStoreAdapter(store)
	handler := v1.NewHandlerWithBlockThreshold(apiStore, nil, domain.SeverityCritical)
	importHandler := v1.NewFeedImportHandler(apiStore, nil)

	importBody := map[string]any{
		"malicious": []map[string]any{
			{
				"id":        "MAL-1",
				"ecosystem": "npm",
				"name":      "left-pad-evil",
				"risk_type": "malware",
				"severity":  "CRITICAL",
				"summary":   "malicious package",
			},
		},
		"status": map[string]any{
			"last_sync_status": "success",
			"entries_synced":   1,
			"entries_total":    1,
		},
	}

	payload, err := json.Marshal(importBody)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/openssf/import", bytes.NewReader(payload))
	req.SetPathValue("feed", "openssf")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	importHandler.HandleImport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleImport() status = %d, body = %s", rec.Code, rec.Body.String())
	}

	syncReq := httptest.NewRequest(http.MethodGet, "/api/v1/sync?ecosystem=npm", nil)
	syncRec := httptest.NewRecorder()
	handler.HandleSync(syncRec, syncReq)
	if syncRec.Code != http.StatusOK {
		t.Fatalf("HandleSync() status = %d, body = %s", syncRec.Code, syncRec.Body.String())
	}

	var resp struct {
		SyncedAt  string `json:"synced_at"`
		Malicious []struct {
			ID        string `json:"id"`
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Source    string `json:"source"`
		} `json:"malicious"`
	}
	if err := json.NewDecoder(syncRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode sync response: %v", err)
	}

	if resp.SyncedAt == "" {
		t.Fatal("synced_at is empty")
	}
	if len(resp.Malicious) != 1 {
		t.Fatalf("len(resp.Malicious) = %d, want 1", len(resp.Malicious))
	}
	if resp.Malicious[0].Name != "left-pad-evil" {
		t.Fatalf("resp.Malicious[0].Name = %q, want %q", resp.Malicious[0].Name, "left-pad-evil")
	}
	if resp.Malicious[0].Source != "openssf" {
		t.Fatalf("resp.Malicious[0].Source = %q, want openssf", resp.Malicious[0].Source)
	}
}

func TestNoopStoreVulnerabilityFeedImportDeleteAndStatus(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newNoopStore()
	syncedAt := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	vuln := db.Vulnerability{
		ID:       "GHSA-noop-vuln-0001",
		Summary:  "noop vulnerability",
		Severity: "HIGH",
		Sources: []db.VulnerabilitySource{{
			Source:   "osv",
			SourceID: "GHSA-noop-vuln-0001",
		}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:        "npm",
			Name:             "left-pad",
			VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0","fixed":"1.0.1"}]}]`),
			VersionsAffected: json.RawMessage(`[]`),
		}},
	}

	imported, deleted, err := store.ImportVulnerabilityFeed(ctx, "osv", []db.Vulnerability{vuln}, nil, &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncAt:     &syncedAt,
		LastSyncStatus: db.FeedSyncStatusSuccess,
		EntriesSynced:  1,
		EntriesTotal:   1,
	})
	if err != nil {
		t.Fatalf("ImportVulnerabilityFeed(upsert) error = %v", err)
	}
	if imported != 1 || deleted != 0 {
		t.Fatalf("ImportVulnerabilityFeed(upsert) = imported %d deleted %d, want 1/0", imported, deleted)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(after import) error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("FindVulnerabilities(after import) = %+v, want one finding", findings)
	}
	if findings[0].AdvisoryID != vuln.ID || findings[0].Source != "osv" || findings[0].Severity != domain.SeverityHigh {
		t.Fatalf("imported finding = %+v, want osv HIGH %s", findings[0], vuln.ID)
	}

	status, err := store.GetFeedSyncStatus(ctx, "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(osv) error = %v", err)
	}
	if status == nil {
		t.Fatal("GetFeedSyncStatus(osv) = nil, want stored status")
	}
	if status.LastSyncAt == nil || !status.LastSyncAt.Equal(syncedAt) || status.LastSyncStatus != db.FeedSyncStatusSuccess || status.EntriesSynced != 1 || status.EntriesTotal != 1 {
		t.Fatalf("stored feed status = %+v, want successful one-entry status at %s", status, syncedAt.Format(time.RFC3339))
	}

	multiSource := vuln
	multiSource.ID = "GHSA-noop-vuln-0002"
	multiSource.Summary = "noop multi-source vulnerability"
	multiSource.Sources = []db.VulnerabilitySource{
		{Source: "osv", SourceID: "GHSA-noop-vuln-0002"},
		{Source: "ghsa", SourceID: "GHSA-noop-vuln-0002"},
	}
	multiSource.AffectedPackages = []db.AffectedPackage{{
		Ecosystem:        "npm",
		Name:             "multi-source",
		VersionRanges:    json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"}]}]`),
		VersionsAffected: json.RawMessage(`[]`),
	}}
	if err := store.UpsertVulnerability(ctx, &multiSource); err != nil {
		t.Fatalf("UpsertVulnerability(multi-source) error = %v", err)
	}

	imported, deleted, err = store.ImportVulnerabilityFeed(ctx, "osv", nil, []string{multiSource.ID}, nil)
	if err != nil {
		t.Fatalf("ImportVulnerabilityFeed(source delete) error = %v", err)
	}
	if imported != 0 || deleted != 1 {
		t.Fatalf("ImportVulnerabilityFeed(source delete) = imported %d deleted %d, want 0/1", imported, deleted)
	}
	findings, err = store.FindVulnerabilities(ctx, "npm", "multi-source", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(after source delete) error = %v", err)
	}
	if len(findings) != 1 || findings[0].Source != "ghsa" {
		t.Fatalf("FindVulnerabilities(after source delete) = %+v, want one ghsa finding", findings)
	}

	if err := store.DeleteVulnerability(ctx, vuln.ID); err != nil {
		t.Fatalf("DeleteVulnerability(%s) error = %v", vuln.ID, err)
	}
	findings, err = store.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(after ID delete) error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("FindVulnerabilities(after ID delete) = %+v, want none", findings)
	}
}
