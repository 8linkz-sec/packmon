package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/8linkz-sec/packmon/internal/api/v1"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestNoopStoreFeedImportAndSync(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	handler := v1.NewHandlerWithBlockThreshold(store, nil, domain.SeverityCritical)

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
	rec := httptest.NewRecorder()
	handler.HandleFeedImport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleFeedImport() status = %d, body = %s", rec.Code, rec.Body.String())
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
