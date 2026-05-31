package sqlite

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
)

func TestApplySyncReputationRowsAndTombstones(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeSilently(store)

	ctx := context.Background()
	resp := &syncResponse{
		Reputation: []syncReputation{
			{
				ID:        "reversinglabs:npm/left-pad@1.3.0",
				Ecosystem: "npm",
				Name:      "left-pad",
				Version:   "1.3.0",
				Type:      "supply_chain_risk",
				RiskType:  "removed_package",
				Severity:  "CRITICAL",
				Summary:   "ReversingLabs: package version was removed",
			},
		},
	}
	if err := applySync(ctx, store, false, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	findings, err := store.FindMalicious(ctx, "npm", "left-pad", "1.3.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Type != domain.FindingTypeSupplyChainRisk {
		t.Fatalf("finding type = %q, want supply_chain_risk", findings[0].Type)
	}
	if findings[0].RiskType != "removed_package" {
		t.Fatalf("risk type = %q, want removed_package", findings[0].RiskType)
	}
	if findings[0].Source != "reversinglabs" {
		t.Fatalf("source = %q, want reversinglabs", findings[0].Source)
	}

	tombstone := &syncResponse{
		Reputation: []syncReputation{
			{
				ID:        "reversinglabs:npm/left-pad@1.3.0",
				Ecosystem: "npm",
				Name:      "left-pad",
				Version:   "1.3.0",
				Withdrawn: true,
			},
		},
	}
	if err := applySync(ctx, store, false, tombstone); err != nil {
		t.Fatalf("applySync(tombstone) error = %v", err)
	}

	findings, err = store.FindMalicious(ctx, "npm", "left-pad", "1.3.0")
	if err != nil {
		t.Fatalf("FindMalicious() after tombstone error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings after tombstone = %d, want 0", len(findings))
	}
}

func TestSyncPaginatesWithOffsetAndStableSnapshot(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeSilently(store)

	type requestState struct {
		offset   string
		limit    string
		snapshot string
		since    string
	}

	var requests []requestState
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		requests = append(requests, requestState{
			offset:   q.Get("offset"),
			limit:    q.Get("limit"),
			snapshot: q.Get("snapshot"),
			since:    q.Get("since"),
		})

		resp := syncResponse{
			SyncedAt: "2026-05-30T10:00:00Z",
			Reputation: []syncReputation{
				{
					ID:        "reversinglabs:npm/left-pad@1.3.0",
					Ecosystem: "npm",
					Name:      "left-pad",
					Version:   "1.3.0",
					Type:      "supply_chain_risk",
					RiskType:  "removed_package",
					Severity:  "CRITICAL",
					Summary:   "ReversingLabs: package version was removed",
				},
			},
			Truncated: len(requests) == 1,
		}
		if len(requests) == 2 {
			resp.Reputation[0].ID = "reversinglabs:npm/other@2.0.0"
			resp.Reputation[0].Name = "other"
			resp.Reputation[0].Version = "2.0.0"
		}
		if len(requests) > 2 {
			t.Fatalf("unexpected extra sync request %d", len(requests))
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	if err := Sync(context.Background(), store, SyncConfig{
		ServerURL: server.URL,
		Full:      true,
	}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	if requests[0].limit != "1000" || requests[0].offset != "" || requests[0].snapshot != "" || requests[0].since != "" {
		t.Fatalf("first request = %+v, want limit only", requests[0])
	}
	if requests[1].limit != "1000" || requests[1].offset != "1000" || requests[1].snapshot != "2026-05-30T10:00:00Z" || requests[1].since != "" {
		t.Fatalf("second request = %+v, want offset and stable snapshot", requests[1])
	}

	for _, pkg := range []string{"left-pad", "other"} {
		findings, err := store.FindMalicious(context.Background(), "npm", pkg, map[string]string{
			"left-pad": "1.3.0",
			"other":    "2.0.0",
		}[pkg])
		if err != nil {
			t.Fatalf("FindMalicious(%s) error = %v", pkg, err)
		}
		if len(findings) != 1 {
			t.Fatalf("FindMalicious(%s) findings = %d, want 1", pkg, len(findings))
		}
	}

	lastSync, err := store.GetSyncMeta(context.Background(), syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta() error = %v", err)
	}
	if lastSync != "2026-05-30T10:00:00Z" {
		t.Fatalf("last sync = %q, want first page snapshot", lastSync)
	}
}
