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

func TestSetAdminAuditDetailJSONBoundaries(t *testing.T) {
	t.Parallel()

	for _, initial := range []json.RawMessage{nil, {}, json.RawMessage(`null`), json.RawMessage(`{}`)} {
		entry := &AdminAuditEntry{Details: initial}
		if err := SetAdminAuditDetail(entry, "unicode", "snowman ☃"); err != nil {
			t.Fatalf("SetAdminAuditDetail(%q) error = %v", initial, err)
		}
		var got map[string]string
		if err := json.Unmarshal(entry.Details, &got); err != nil {
			t.Fatalf("details %s are invalid JSON: %v", entry.Details, err)
		}
		if !reflect.DeepEqual(got, map[string]string{"unicode": "snowman ☃"}) {
			t.Fatalf("details from %q = %#v", initial, got)
		}
	}

	entry := &AdminAuditEntry{Details: json.RawMessage(`{"same":"old","preserved":"value"}`)}
	if err := SetAdminAuditDetail(entry, "same", "new"); err != nil {
		t.Fatalf("SetAdminAuditDetail(overwrite) error = %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(entry.Details, &got); err != nil {
		t.Fatalf("details %s are invalid JSON: %v", entry.Details, err)
	}
	if !reflect.DeepEqual(got, map[string]string{"same": "new", "preserved": "value"}) {
		t.Fatalf("overwritten details = %#v", got)
	}

	for _, invalid := range []json.RawMessage{
		json.RawMessage(`[]`),
		json.RawMessage(`{"number":1}`),
		json.RawMessage(`{"nested":{}}`),
		json.RawMessage(`true`),
	} {
		entry := &AdminAuditEntry{Details: invalid}
		before := string(entry.Details)
		if err := SetAdminAuditDetail(entry, "x", "y"); err == nil {
			t.Fatalf("SetAdminAuditDetail(%s) error = nil", invalid)
		}
		if string(entry.Details) != before {
			t.Fatalf("failed update mutated details from %s to %s", before, entry.Details)
		}
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

// TestSetAdminAuditQueueJobsDetailOmitsAbsentTimestamps checks the raw JSON: a
// job that was never requested or processed has no timestamp key at all, not an
// empty string that reads like a recorded but blank time.
func TestSetAdminAuditQueueJobsDetailOmitsAbsentTimestamps(t *testing.T) {
	t.Parallel()

	requested := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	zeroProcessed := time.Time{}
	entry := &AdminAuditEntry{}
	jobs := []RefreshJob{
		{ID: 1, Ecosystem: "npm", Name: "never-processed", Source: "socket", Status: "pending", RequestedAt: requested},
		{ID: 2, Ecosystem: "npm", Name: "zero-processed", Source: "socket", Status: "pending", RequestedAt: requested, ProcessedAt: &zeroProcessed},
		{ID: 3, Ecosystem: "npm", Name: "no-timestamps", Source: "socket", Status: "pending"},
	}
	if err := SetAdminAuditQueueJobsDetail(entry, "jobs", jobs); err != nil {
		t.Fatalf("SetAdminAuditQueueJobsDetail() error = %v", err)
	}

	var details map[string]string
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("details JSON = %s: %v", entry.Details, err)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(details["jobs"]), &rows); err != nil {
		t.Fatalf("jobs detail JSON = %s: %v", details["jobs"], err)
	}
	if len(rows) != len(jobs) {
		t.Fatalf("rows = %d, want %d", len(rows), len(jobs))
	}
	wantKeys := []struct {
		requested bool
		processed bool
	}{
		{requested: true},
		{requested: true},
		{},
	}
	for i, row := range rows {
		for key, want := range map[string]bool{"requested_at": wantKeys[i].requested, "processed_at": wantKeys[i].processed} {
			raw, ok := row[key]
			if ok != want {
				t.Fatalf("row %d %s present = %t, want %t: %s", i, key, ok, want, details["jobs"])
			}
			if ok && string(raw) == `""` {
				t.Fatalf("row %d %s = \"\", want a timestamp: %s", i, key, details["jobs"])
			}
		}
		for _, key := range []string{"id", "ecosystem", "name", "source", "priority", "status", "error"} {
			if _, ok := row[key]; !ok {
				t.Fatalf("row %d missing identity key %s: %s", i, key, details["jobs"])
			}
		}
	}
}

func TestSetAdminAuditQueueJobsDetailSerializationBoundaries(t *testing.T) {
	t.Parallel()

	if err := SetAdminAuditQueueJobsDetail(nil, "jobs", nil); err != nil {
		t.Fatalf("SetAdminAuditQueueJobsDetail(nil entry) error = %v", err)
	}
	malformed := &AdminAuditEntry{Details: json.RawMessage(`{"broken"`)}
	malformedBefore := append(json.RawMessage(nil), malformed.Details...)
	if err := SetAdminAuditQueueJobsDetail(malformed, "jobs", []RefreshJob{{ID: 1}}); err == nil {
		t.Fatal("SetAdminAuditQueueJobsDetail(malformed outer JSON) error = nil")
	}
	if !reflect.DeepEqual(malformed.Details, malformedBefore) {
		t.Fatalf("failed queue detail update mutated Details from %q to %q", malformedBefore, malformed.Details)
	}

	entry := &AdminAuditEntry{Details: json.RawMessage(`{"preserved":"yes","jobs":"old"}`)}
	if err := SetAdminAuditQueueJobsDetail(entry, "jobs", nil); err != nil {
		t.Fatalf("SetAdminAuditQueueJobsDetail(nil jobs) error = %v", err)
	}
	var details map[string]string
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("details JSON = %s: %v", entry.Details, err)
	}
	if details["preserved"] != "yes" || details["jobs"] != "[]" {
		t.Fatalf("nil jobs details = %#v, want preserved field and []", details)
	}

	requested := time.Date(2026, 6, 24, 12, 0, 0, 123456789, time.FixedZone("CEST", 2*60*60))
	processed := time.Date(2026, 6, 24, 11, 0, 1, 987654321, time.UTC)
	jobs := []RefreshJob{
		{
			ID: 9, Ecosystem: "pypi", Name: "private-package", Source: "socket", Priority: 0,
			Status: "error", RequestedAt: requested, ProcessedAt: &processed,
			Error: strings.Repeat("a", 511) + "é" + strings.Repeat("z", 50),
		},
		{ID: -1, Priority: -1, Error: "line one\nline two\twith control\x00suffix"},
	}
	if err := SetAdminAuditQueueJobsDetail(entry, "jobs", jobs); err != nil {
		t.Fatalf("SetAdminAuditQueueJobsDetail(boundaries) error = %v", err)
	}
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("details JSON = %s: %v", entry.Details, err)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(details["jobs"]), &rows); err != nil {
		t.Fatalf("jobs detail JSON = %s: %v", details["jobs"], err)
	}
	if len(rows) != 2 {
		t.Fatalf("serialized jobs = %d, want 2", len(rows))
	}
	var decoded []adminAuditQueueJob
	if err := json.Unmarshal([]byte(details["jobs"]), &decoded); err != nil {
		t.Fatalf("decode jobs: %v", err)
	}
	if got, want := decoded[0].RequestedAt, "2026-06-24T10:00:00.123456789Z"; got != want {
		t.Fatalf("requested_at = %q, want %q", got, want)
	}
	if got, want := decoded[0].ProcessedAt, "2026-06-24T11:00:01.987654321Z"; got != want {
		t.Fatalf("processed_at = %q, want %q", got, want)
	}
	if len(decoded[0].Error) > 512 {
		t.Fatalf("bounded error length = %d, want at most 512 bytes", len(decoded[0].Error))
	}
	if strings.ContainsAny(decoded[1].Error, "\n\r\t\x00") {
		t.Fatalf("control characters remain in error %q", decoded[1].Error)
	}
	for _, key := range []string{"requested_at", "processed_at"} {
		if _, ok := rows[1][key]; ok {
			t.Fatalf("zero timestamp row contains %s: %s", key, details["jobs"])
		}
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
