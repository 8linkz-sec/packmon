package sqlite

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
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
	if _, err := applySync(ctx, store, false, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	findings, err := store.FindMalicious(ctx, "npm", "left-pad", "1.3.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("FindMalicious() = %+v, want no reputation findings on malicious path", findings)
	}
	findings, err = store.FindReputationFindings(ctx, "npm", "left-pad", db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindings() error = %v", err)
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
	if _, err := applySync(ctx, store, false, tombstone); err != nil {
		t.Fatalf("applySync(tombstone) error = %v", err)
	}

	findings, err = store.FindReputationFindings(ctx, "npm", "left-pad", db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindings() after tombstone error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings after tombstone = %d, want 0", len(findings))
	}
}

func TestFindReputationIncludesHistoricalRiskRows(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer closeSilently(store)

	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES ('reversinglabs:pypi/pillow@12.2.0', 'pypi', 'pillow', '12.2.0', 'supply_chain_risk', 'malware_history', 'HIGH', 'ReversingLabs: malware incident history')`); err != nil {
		t.Fatalf("insert reputation row: %v", err)
	}

	findings, err := store.FindMalicious(ctx, "pypi", "pillow", "12.2.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("FindMalicious() = %+v, want no reputation findings on malicious path", findings)
	}
	findings, err = store.FindReputationFindings(ctx, "pypi", "pillow", db.ReputationSourceReversingLabs)
	if err != nil {
		t.Fatalf("FindReputationFindings() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("historical risk findings = %+v, want one finding", findings)
	}
	if findings[0].Type != domain.FindingTypeSupplyChainRisk || findings[0].RiskType != "malware_history" {
		t.Fatalf("historical risk finding = %+v, want malware_history supply-chain risk", findings[0])
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
		offset                string
		vulnerabilitiesOffset string
		vulnerabilitiesCursor string
		vulnerabilitiesDone   string
		maliciousOffset       string
		maliciousDone         string
		reputationOffset      string
		reputationCursor      string
		reputationDone        string
		lifecycleOffset       string
		lifecycleDone         string
		limit                 string
		snapshot              string
		snapshotXID           string
		since                 string
	}

	var requests []requestState
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		requests = append(requests, requestState{
			offset:                q.Get("offset"),
			vulnerabilitiesOffset: q.Get("vulnerabilities_offset"),
			vulnerabilitiesCursor: q.Get("vulnerabilities_cursor"),
			vulnerabilitiesDone:   q.Get("vulnerabilities_done"),
			maliciousOffset:       q.Get("malicious_offset"),
			maliciousDone:         q.Get("malicious_done"),
			reputationOffset:      q.Get("reputation_offset"),
			reputationCursor:      q.Get("reputation_cursor"),
			reputationDone:        q.Get("reputation_done"),
			lifecycleOffset:       q.Get("lifecycle_offset"),
			lifecycleDone:         q.Get("lifecycle_done"),
			limit:                 q.Get("limit"),
			snapshot:              q.Get("snapshot"),
			snapshotXID:           q.Get("snapshot_xid"),
			since:                 q.Get("since"),
		})

		resp := syncResponse{
			SyncedAt:  "2026-05-30T10:00:00Z",
			SyncedXID: 700,
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
		if len(requests) == 1 {
			resp.NextCursor = &syncCursor{
				VulnerabilitiesDone: true,
				MaliciousDone:       true,
				ReputationCursor:    "after-left-pad",
				LifecycleDone:       true,
			}
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
		ServerURL:         server.URL,
		Full:              true,
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	if len(requests) != 2 {
		t.Fatalf("requests = %d, want 2", len(requests))
	}
	if requests[0].limit != "1000" || requests[0].offset != "" || requests[0].snapshot != "" || requests[0].since != "" {
		t.Fatalf("first request = %+v, want limit only", requests[0])
	}
	if requests[1].limit != "1000" ||
		requests[1].offset != "" ||
		requests[1].reputationOffset != "" ||
		requests[1].reputationCursor != "after-left-pad" ||
		requests[1].vulnerabilitiesDone != "true" ||
		requests[1].maliciousDone != "true" ||
		requests[1].lifecycleDone != "true" ||
		requests[1].snapshot != "2026-05-30T10:00:00Z" ||
		requests[1].snapshotXID != "700" ||
		requests[1].since != "" {
		t.Fatalf("second request = %+v, want reputation keyset cursor, done markers, stable snapshot/xid", requests[1])
	}

	for _, pkg := range []string{"left-pad", "other"} {
		findings, err := store.FindReputationFindingsBatch(context.Background(), []db.PackageQuery{{
			Ecosystem: "npm",
			Name:      pkg,
			Version: map[string]string{
				"left-pad": "1.3.0",
				"other":    "2.0.0",
			}[pkg],
		}}, db.ReputationSourceReversingLabs)
		if err != nil {
			t.Fatalf("FindReputationFindingsBatch(%s) error = %v", pkg, err)
		}
		if len(findings) != 1 {
			t.Fatalf("FindReputationFindingsBatch(%s) findings = %d, want 1", pkg, len(findings))
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
