package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAPIKeyIsExpired(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Second)
	exact := now
	future := now.Add(time.Second)

	for _, tt := range []struct {
		name string
		key  APIKey
		want bool
	}{
		{name: "no expiry", key: APIKey{}, want: false},
		{name: "past expiry", key: APIKey{ExpiresAt: &past}, want: true},
		{name: "exactly now", key: APIKey{ExpiresAt: &exact}, want: true},
		{name: "future expiry", key: APIKey{ExpiresAt: &future}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.key.IsExpired(now); got != tt.want {
				t.Fatalf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetAdminAuditDetail(t *testing.T) {
	t.Parallel()

	if err := SetAdminAuditDetail(nil, "ignored", "value"); err != nil {
		t.Fatalf("SetAdminAuditDetail(nil) error = %v", err)
	}

	entry := &AdminAuditEntry{Details: json.RawMessage(`{"existing":"old"}`)}
	if err := SetAdminAuditDetail(entry, "action", "updated"); err != nil {
		t.Fatalf("SetAdminAuditDetail() error = %v", err)
	}
	var details map[string]string
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("details JSON = %s: %v", entry.Details, err)
	}
	if details["existing"] != "old" || details["action"] != "updated" {
		t.Fatalf("details = %+v", details)
	}

	bad := &AdminAuditEntry{Details: json.RawMessage(`{"broken"`)}
	if err := SetAdminAuditDetail(bad, "x", "y"); err == nil {
		t.Fatal("SetAdminAuditDetail(invalid JSON) error = nil")
	}
}

func TestSetAdminAuditQueueJobsDetail(t *testing.T) {
	t.Parallel()

	requested := time.Date(2026, 6, 24, 12, 0, 0, 123, time.UTC)
	processed := requested.Add(time.Minute)
	entry := &AdminAuditEntry{}
	jobs := []RefreshJob{{
		ID:          7,
		Ecosystem:   "npm",
		Name:        "left-pad",
		Source:      "socket",
		Priority:    1,
		Status:      "error",
		RequestedAt: requested,
		ProcessedAt: &processed,
		Error:       strings.Repeat("x", 600),
	}}
	if err := SetAdminAuditQueueJobsDetail(entry, "jobs", jobs); err != nil {
		t.Fatalf("SetAdminAuditQueueJobsDetail() error = %v", err)
	}

	var details map[string]string
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("details JSON = %s: %v", entry.Details, err)
	}
	var rows []adminAuditQueueJob
	if err := json.Unmarshal([]byte(details["jobs"]), &rows); err != nil {
		t.Fatalf("jobs detail JSON = %s: %v", details["jobs"], err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.ID != 7 || row.Ecosystem != "npm" || row.Name != "left-pad" || row.Source != "socket" || row.Priority != 1 || row.Status != "error" {
		t.Fatalf("row identity = %+v", row)
	}
	if row.RequestedAt == "" || row.ProcessedAt == "" {
		t.Fatalf("row timestamps missing: %+v", row)
	}
	if len(row.Error) > 512 {
		t.Fatalf("row error length = %d, want bounded", len(row.Error))
	}
}

type legacyDeleteStore struct {
	Store
	vulnerabilityID string
	maliciousID     string
}

func (s *legacyDeleteStore) DeleteVulnerability(_ context.Context, id string) error {
	s.vulnerabilityID = id
	return nil
}

func (s *legacyDeleteStore) DeleteMaliciousFinding(_ context.Context, id string) error {
	s.maliciousID = id
	return nil
}

type scopedDeleteStore struct {
	legacyDeleteStore
	vulnerabilitySource string
	maliciousSource     string
}

func (s *scopedDeleteStore) DeleteVulnerabilityForSource(_ context.Context, id, source string) error {
	s.vulnerabilityID = id
	s.vulnerabilitySource = source
	return nil
}

func (s *scopedDeleteStore) DeleteMaliciousFindingForSource(_ context.Context, id, source string) error {
	s.maliciousID = id
	s.maliciousSource = source
	return nil
}

func TestDeleteForSourceUsesScopedStoreWhenAvailable(t *testing.T) {
	t.Parallel()

	store := &scopedDeleteStore{}
	if err := DeleteVulnerabilityForSource(context.Background(), store, "GHSA-1", "osv"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource() error = %v", err)
	}
	if store.vulnerabilityID != "GHSA-1" || store.vulnerabilitySource != "osv" {
		t.Fatalf("scoped vulnerability delete = id %q source %q", store.vulnerabilityID, store.vulnerabilitySource)
	}
	if err := DeleteMaliciousFindingForSource(context.Background(), store, "MAL-1", "openssf"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource() error = %v", err)
	}
	if store.maliciousID != "MAL-1" || store.maliciousSource != "openssf" {
		t.Fatalf("scoped malicious delete = id %q source %q", store.maliciousID, store.maliciousSource)
	}
}

func TestDeleteForSourceFallsBackToLegacyStore(t *testing.T) {
	t.Parallel()

	store := &legacyDeleteStore{}
	if err := DeleteVulnerabilityForSource(context.Background(), store, "GHSA-2", "ignored"); err != nil {
		t.Fatalf("DeleteVulnerabilityForSource() fallback error = %v", err)
	}
	if store.vulnerabilityID != "GHSA-2" {
		t.Fatalf("legacy vulnerability delete id = %q", store.vulnerabilityID)
	}
	if err := DeleteMaliciousFindingForSource(context.Background(), store, "MAL-2", "ignored"); err != nil {
		t.Fatalf("DeleteMaliciousFindingForSource() fallback error = %v", err)
	}
	if store.maliciousID != "MAL-2" {
		t.Fatalf("legacy malicious delete id = %q", store.maliciousID)
	}
}
