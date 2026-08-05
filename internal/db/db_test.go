package db

import (
	"context"
	"encoding/json"
	"reflect"
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
		Priority:    RefreshPriorityUnknownPackage,
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
	if row.ID != 7 || row.Ecosystem != "npm" || row.Name != "left-pad" || row.Source != "socket" || row.Priority != RefreshPriorityUnknownPackage || row.Status != "error" {
		t.Fatalf("row identity = %+v", row)
	}
	if row.RequestedAt == "" || row.ProcessedAt == "" {
		t.Fatalf("row timestamps missing: %+v", row)
	}
	if len(row.Error) > 512 {
		t.Fatalf("row error length = %d, want bounded", len(row.Error))
	}
}

func TestStoreLifecycleSyncContractRequiresAtomicReplacement(t *testing.T) {
	t.Parallel()

	storeType := reflect.TypeOf((*Store)(nil)).Elem()
	method, ok := storeType.MethodByName("ReplaceLifecycleProducts")
	if !ok {
		t.Fatal("Store is missing ReplaceLifecycleProducts; full lifecycle snapshots must use atomic replacement")
	}
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	productsType := reflect.TypeOf([]LifecycleProduct{})
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	if method.Type.NumIn() != 2 ||
		method.Type.In(0) != ctxType ||
		method.Type.In(1) != productsType ||
		method.Type.NumOut() != 2 ||
		method.Type.Out(0) != reflect.TypeOf(0) ||
		method.Type.Out(1) != errorType {
		t.Fatalf("ReplaceLifecycleProducts signature = %s, want func(context.Context, []LifecycleProduct) (int, error)", method.Type)
	}
	if _, ok := storeType.MethodByName("UpsertLifecycleProducts"); ok {
		t.Fatal("Store exposes UpsertLifecycleProducts; lifecycle full snapshots must not keep a stale-prone upsert contract")
	}
}

func TestStoreRetentionContractRequiresExplicitPruneMethods(t *testing.T) {
	t.Parallel()

	storeType := reflect.TypeOf((*Store)(nil)).Elem()
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	durationType := reflect.TypeOf(time.Duration(0))
	intType := reflect.TypeOf(0)
	errorType := reflect.TypeOf((*error)(nil)).Elem()

	for _, name := range []string{
		"PruneScanLogs",
		"PruneAdminAuditLogs",
		"PruneRefreshQueue",
		"PrunePackageCheckStatus",
	} {
		method, ok := storeType.MethodByName(name)
		if !ok {
			t.Fatalf("Store is missing %s; configured retention must not be skipped by optional assertions", name)
		}
		if method.Type.NumIn() != 2 ||
			method.Type.In(0) != ctxType ||
			method.Type.In(1) != durationType ||
			method.Type.NumOut() != 2 ||
			method.Type.Out(0) != intType ||
			method.Type.Out(1) != errorType {
			t.Fatalf("%s signature = %s, want func(context.Context, time.Duration) (int, error)", name, method.Type)
		}
	}

	method, ok := storeType.MethodByName("PrunePackageReputation")
	if !ok {
		t.Fatal("Store is missing PrunePackageReputation; configured reputation retention must not be skipped by optional assertions")
	}
	if method.Type.NumIn() != 3 ||
		method.Type.In(0) != ctxType ||
		method.Type.In(1) != reflect.TypeOf("") ||
		method.Type.In(2) != durationType ||
		method.Type.NumOut() != 2 ||
		method.Type.Out(0) != intType ||
		method.Type.Out(1) != errorType {
		t.Fatalf("PrunePackageReputation signature = %s, want func(context.Context, string, time.Duration) (int, error)", method.Type)
	}
}

func TestRefreshPriorityOptionsDefineSupportedScale(t *testing.T) {
	t.Parallel()

	want := []RefreshPriorityOption{
		{Value: RefreshPriorityManual, Label: "0 - Immediate (manual trigger)"},
		{Value: RefreshPriorityUnknownPackage, Label: "1 - High (unknown packages)"},
		{Value: RefreshPriorityKnownFinding, Label: "2 - Medium (known findings)"},
		{Value: RefreshPriorityNormal, Label: "3 - Normal (scheduled re-check)"},
	}
	got := RefreshPriorityOptions()
	if len(got) != len(want) {
		t.Fatalf("RefreshPriorityOptions() length = %d, want %d: %#v", len(got), len(want), got)
	}
	for i, option := range want {
		if got[i] != option {
			t.Fatalf("RefreshPriorityOptions()[%d] = %#v, want %#v", i, got[i], option)
		}
		if !ValidRefreshPriority(option.Value) {
			t.Fatalf("ValidRefreshPriority(%d) = false", option.Value)
		}
	}
	for _, priority := range []int{-1, RefreshPriorityNormal + 1} {
		if ValidRefreshPriority(priority) {
			t.Fatalf("ValidRefreshPriority(%d) = true, want false", priority)
		}
	}
}
