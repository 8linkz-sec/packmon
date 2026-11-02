package db

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAdminAuditIntegrityStatus(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 6, 24, 12, 0, 0, 123456000, time.FixedZone("CEST", 2*60*60))
	entry := AdminAuditLogEntry{
		ID:             10,
		Action:         "queue.clear",
		Details:        json.RawMessage(`{"statuses":"done"}`),
		IP:             "192.0.2.10",
		CorrelationID:  "corr-admin-audit",
		CreatedAt:      created,
		PreviousDigest: "sha256:previous",
	}
	if got := AdminAuditIntegrityStatus(entry); got != AdminAuditIntegrityLegacy {
		t.Fatalf("legacy status = %q", got)
	}

	entry.RowDigest = ComputeAdminAuditDigest(entry)
	if got := AdminAuditIntegrityStatus(entry); got != AdminAuditIntegrityVerified {
		t.Fatalf("verified status = %q", got)
	}

	entry.Action = "queue.purge"
	if got := AdminAuditIntegrityStatus(entry); got != AdminAuditIntegrityBroken {
		t.Fatalf("broken status = %q", got)
	}

	entry.Action = "queue.clear"
	entry.RowDigest = ComputeAdminAuditDigest(entry)
	entry.CorrelationID = "corr-admin-audit-changed"
	if got := AdminAuditIntegrityStatus(entry); got != AdminAuditIntegrityBroken {
		t.Fatalf("correlation ID tamper status = %q, want broken", got)
	}
}

func TestAdminAuditIntegritySupportsKeyedHMACAndLegacySHA(t *testing.T) {
	t.Cleanup(ClearAdminAuditDigestHMACKey)

	created := time.Date(2026, 6, 24, 12, 0, 0, 123456000, time.UTC)
	entry := AdminAuditLogEntry{
		ID:             20,
		Action:         "api_key_create",
		Details:        json.RawMessage(`{"key_id":"42"}`),
		IP:             "192.0.2.20",
		CorrelationID:  "corr-keyed-audit",
		CreatedAt:      created,
		PreviousDigest: "sha256:previous",
	}

	ClearAdminAuditDigestHMACKey()
	legacyDigest := ComputeAdminAuditDigest(entry)
	if got, wantPrefix := legacyDigest[:len("sha256:")], "sha256:"; got != wantPrefix {
		t.Fatalf("legacy digest prefix = %q, want %q", got, wantPrefix)
	}

	SetAdminAuditDigestHMACKey([]byte("0123456789abcdef0123456789abcdef"))

	keyedDigest := ComputeAdminAuditDigest(entry)
	if got, wantPrefix := keyedDigest[:len("hmac-sha256:")], "hmac-sha256:"; got != wantPrefix {
		t.Fatalf("keyed digest prefix = %q, want %q", got, wantPrefix)
	}
	if keyedDigest == legacyDigest {
		t.Fatal("keyed digest equals legacy digest")
	}

	keyedEntry := entry
	keyedEntry.RowDigest = keyedDigest
	if got := AdminAuditIntegrityStatus(keyedEntry); got != AdminAuditIntegrityVerified {
		t.Fatalf("keyed status = %q, want verified", got)
	}

	SetAdminAuditDigestHMACKey([]byte("abcdef0123456789abcdef0123456789"))
	if got := AdminAuditIntegrityStatus(keyedEntry); got != AdminAuditIntegrityBroken {
		t.Fatalf("wrong-key status = %q, want broken", got)
	}

	SetAdminAuditDigestHMACKey([]byte("0123456789abcdef0123456789abcdef"))
	legacyEntry := entry
	legacyEntry.RowDigest = legacyDigest
	if got := AdminAuditIntegrityStatus(legacyEntry); got != AdminAuditIntegrityVerified {
		t.Fatalf("legacy status with active HMAC key = %q, want verified", got)
	}
}

func TestAnnotateAdminAuditIntegrityDetectsBrokenChain(t *testing.T) {
	t.Parallel()

	oldest := AdminAuditLogEntry{
		ID:            1,
		Action:        "login",
		Details:       json.RawMessage(`{"ok":"true"}`),
		IP:            "192.0.2.1",
		CorrelationID: "corr-oldest",
		CreatedAt:     time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC),
	}
	oldest.RowDigest = ComputeAdminAuditDigest(oldest)

	newest := AdminAuditLogEntry{
		ID:             2,
		Action:         "queue.clear",
		Details:        json.RawMessage(`{}`),
		IP:             "192.0.2.2",
		CorrelationID:  "corr-newest",
		CreatedAt:      time.Date(2026, 6, 24, 11, 0, 0, 0, time.UTC),
		PreviousDigest: "sha256:not-the-older-row",
	}
	newest.RowDigest = ComputeAdminAuditDigest(newest)

	entries := []AdminAuditLogEntry{newest, oldest, {ID: 3, Action: "legacy"}}
	AnnotateAdminAuditIntegrity(entries)
	if entries[0].IntegrityStatus != AdminAuditIntegrityBroken {
		t.Fatalf("newest integrity = %q, want broken", entries[0].IntegrityStatus)
	}
	if entries[1].IntegrityStatus != AdminAuditIntegrityVerified {
		t.Fatalf("oldest integrity = %q, want verified", entries[1].IntegrityStatus)
	}
	if entries[2].IntegrityStatus != AdminAuditIntegrityLegacy {
		t.Fatalf("legacy integrity = %q, want legacy", entries[2].IntegrityStatus)
	}
}

func TestAnnotateAdminAuditIntegrityLeavesBoundaryAndUnavailableLinksVerified(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	newest := AdminAuditLogEntry{
		ID:             3,
		Action:         "queue.clear",
		Details:        json.RawMessage(`{}`),
		IP:             "192.0.2.3",
		CreatedAt:      created,
		PreviousDigest: "sha256:unavailable-older-row",
	}
	newest.RowDigest = ComputeAdminAuditDigest(newest)

	legacy := AdminAuditLogEntry{ID: 2, Action: "legacy"}
	middle := AdminAuditLogEntry{
		ID:        1,
		Action:    "login",
		Details:   json.RawMessage(`{}`),
		IP:        "192.0.2.2",
		CreatedAt: created.Add(-time.Minute),
	}

	oldest := AdminAuditLogEntry{
		ID:             0,
		Action:         "logout",
		Details:        json.RawMessage(`{}`),
		IP:             "192.0.2.1",
		CreatedAt:      created.Add(-2 * time.Minute),
		PreviousDigest: "sha256:unloaded-older-row",
	}
	oldest.RowDigest = ComputeAdminAuditDigest(oldest)
	middle.PreviousDigest = oldest.RowDigest
	middle.RowDigest = ComputeAdminAuditDigest(middle)

	entries := []AdminAuditLogEntry{newest, legacy, middle, oldest}
	AnnotateAdminAuditIntegrity(entries)

	for _, entry := range []AdminAuditLogEntry{entries[0], entries[2], entries[3]} {
		if entry.IntegrityStatus != AdminAuditIntegrityVerified {
			t.Fatalf("entry %d integrity = %q, want verified", entry.ID, entry.IntegrityStatus)
		}
	}
	if entries[1].IntegrityStatus != AdminAuditIntegrityLegacy {
		t.Fatalf("legacy integrity = %q, want legacy", entries[1].IntegrityStatus)
	}
}

func TestAdminAuditIntegrityRejectsUnavailableKeyAndUnknownAlgorithm(t *testing.T) {
	t.Cleanup(ClearAdminAuditDigestHMACKey)

	entry := AdminAuditLogEntry{
		ID:        31,
		Action:    "settings.update",
		Details:   json.RawMessage(`{"setting":"threshold"}`),
		IP:        "192.0.2.31",
		CreatedAt: time.Date(2026, 7, 1, 10, 11, 12, 345678000, time.UTC),
	}

	SetAdminAuditDigestHMACKey([]byte("0123456789abcdef0123456789abcdef"))
	entry.RowDigest = ComputeAdminAuditDigest(entry)
	ClearAdminAuditDigestHMACKey()
	if got := AdminAuditIntegrityStatus(entry); got != AdminAuditIntegrityBroken {
		t.Fatalf("HMAC status without key = %q, want broken", got)
	}

	entry.RowDigest = "md5:0123456789abcdef"
	if got := AdminAuditIntegrityStatus(entry); got != AdminAuditIntegrityBroken {
		t.Fatalf("unknown digest algorithm status = %q, want broken", got)
	}
	entry.RowDigest = "SHA256:0123456789abcdef"
	if got := AdminAuditIntegrityStatus(entry); got != AdminAuditIntegrityBroken {
		t.Fatalf("case-changed digest algorithm status = %q, want broken", got)
	}
}

func TestAnnotateAdminAuditIntegrityHandlesNonVerifiedRowsAndPageBoundaries(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	verified := func(id int, previous string) AdminAuditLogEntry {
		entry := AdminAuditLogEntry{
			ID:             id,
			Action:         fmt.Sprintf("action-%d", id),
			Details:        json.RawMessage(`{}`),
			IP:             "192.0.2.40",
			CreatedAt:      created.Add(-time.Duration(id) * time.Minute),
			PreviousDigest: previous,
		}
		entry.RowDigest = ComputeAdminAuditDigest(entry)
		return entry
	}

	AnnotateAdminAuditIntegrity(nil)
	entries := []AdminAuditLogEntry{verified(1, "sha256:outside-page")}
	AnnotateAdminAuditIntegrity(entries)
	if entries[0].IntegrityStatus != AdminAuditIntegrityVerified {
		t.Fatalf("single page-boundary row status = %q, want verified", entries[0].IntegrityStatus)
	}

	legacy := AdminAuditLogEntry{ID: 2, Action: "legacy"}
	newest := verified(3, "sha256:different-but-unavailable")
	entries = []AdminAuditLogEntry{newest, legacy}
	AnnotateAdminAuditIntegrity(entries)
	if entries[0].IntegrityStatus != AdminAuditIntegrityVerified || entries[1].IntegrityStatus != AdminAuditIntegrityLegacy {
		t.Fatalf("verified-to-legacy statuses = %q, %q", entries[0].IntegrityStatus, entries[1].IntegrityStatus)
	}

	brokenOlder := verified(4, "")
	brokenOlder.Action = "tampered"
	newest = verified(5, brokenOlder.RowDigest)
	entries = []AdminAuditLogEntry{newest, brokenOlder}
	AnnotateAdminAuditIntegrity(entries)
	if entries[0].IntegrityStatus != AdminAuditIntegrityVerified || entries[1].IntegrityStatus != AdminAuditIntegrityBroken {
		t.Fatalf("verified-to-broken statuses = %q, %q", entries[0].IntegrityStatus, entries[1].IntegrityStatus)
	}

	older := verified(6, "")
	middleLegacy := AdminAuditLogEntry{ID: 5, Action: "legacy-middle", PreviousDigest: older.RowDigest}
	newest = verified(4, "sha256:unavailable-legacy-digest")
	entries = []AdminAuditLogEntry{newest, middleLegacy, older}
	AnnotateAdminAuditIntegrity(entries)
	if entries[0].IntegrityStatus != AdminAuditIntegrityVerified || entries[1].IntegrityStatus != AdminAuditIntegrityLegacy || entries[2].IntegrityStatus != AdminAuditIntegrityVerified {
		t.Fatalf("three-row legacy-middle statuses = %q, %q, %q", entries[0].IntegrityStatus, entries[1].IntegrityStatus, entries[2].IntegrityStatus)
	}

	middleBroken := verified(8, older.RowDigest)
	middleBroken.Action = "tampered-middle"
	newest = verified(9, middleBroken.RowDigest)
	entries = []AdminAuditLogEntry{newest, middleBroken, older}
	AnnotateAdminAuditIntegrity(entries)
	if entries[0].IntegrityStatus != AdminAuditIntegrityVerified || entries[1].IntegrityStatus != AdminAuditIntegrityBroken || entries[2].IntegrityStatus != AdminAuditIntegrityVerified {
		t.Fatalf("three-row broken-middle statuses = %q, %q, %q", entries[0].IntegrityStatus, entries[1].IntegrityStatus, entries[2].IntegrityStatus)
	}

	newest = verified(6, "sha256:wrong")
	older = verified(7, "")
	entries = []AdminAuditLogEntry{newest, older}
	AnnotateAdminAuditIntegrity(entries)
	if entries[0].IntegrityStatus != AdminAuditIntegrityBroken || entries[1].IntegrityStatus != AdminAuditIntegrityVerified {
		t.Fatalf("mismatched loaded link statuses = %q, %q", entries[0].IntegrityStatus, entries[1].IntegrityStatus)
	}
}

func TestAdminAuditDigestCanonicalVectorsAndFieldMutations(t *testing.T) {
	t.Cleanup(ClearAdminAuditDigestHMACKey)

	// The exact vectors pin canonical JSON field order, UTC microsecond time
	// formatting, and the version switch when a correlation ID is present.
	base := AdminAuditLogEntry{
		ID:             7,
		Action:         "queue.clear",
		Details:        json.RawMessage(`{"status":"done"}`),
		IP:             "192.0.2.7",
		CreatedAt:      time.Date(2026, 6, 24, 12, 0, 0, 123456789, time.FixedZone("CEST", 2*60*60)),
		PreviousDigest: "sha256:previous",
	}

	ClearAdminAuditDigestHMACKey()
	v1 := ComputeAdminAuditDigest(base)
	withCorrelation := base
	withCorrelation.CorrelationID = "corr-7"
	v2 := ComputeAdminAuditDigest(withCorrelation)
	if got, want := string(adminAuditDigestPayloadBytes(base)), `{"version":1,"id":7,"action":"queue.clear","details":"{\"status\":\"done\"}","ip":"192.0.2.7","created_at":"2026-06-24T10:00:00.123456Z","previous_digest":"sha256:previous"}`; got != want {
		t.Fatalf("version 1 canonical payload = %s, want %s", got, want)
	}
	if got, want := string(adminAuditDigestPayloadBytes(withCorrelation)), `{"version":2,"id":7,"action":"queue.clear","details":"{\"status\":\"done\"}","ip":"192.0.2.7","correlation_id":"corr-7","created_at":"2026-06-24T10:00:00.123456Z","previous_digest":"sha256:previous"}`; got != want {
		t.Fatalf("version 2 canonical payload = %s, want %s", got, want)
	}
	if want := "sha256:587b9c4a9c9070d23d5c9289dcf56e881f404404dd1761a3091bdd955d4ce58c"; v1 != want {
		t.Fatalf("version 1 SHA digest = %q, want %q", v1, want)
	}
	if want := "sha256:5b32e2e119c3d81d14a19eaa129661253f848189f531a9302adda670f08e1181"; v2 != want {
		t.Fatalf("version 2 SHA digest = %q, want %q", v2, want)
	}
	sameInstant := base
	sameInstant.CreatedAt = base.CreatedAt.In(time.FixedZone("alternate", -7*60*60))
	if got, want := string(adminAuditDigestPayloadBytes(sameInstant)), string(adminAuditDigestPayloadBytes(base)); got != want {
		t.Fatalf("same instant in alternate location payload = %s, want %s", got, want)
	}
	if got := ComputeAdminAuditDigest(sameInstant); got != v1 {
		t.Fatalf("same instant in alternate location digest = %q, want %q", got, v1)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	SetAdminAuditDigestHMACKey(key)
	hmacV1 := ComputeAdminAuditDigest(base)
	hmacV2 := ComputeAdminAuditDigest(withCorrelation)
	if want := "hmac-sha256:af7758d85fed379cc207e4c40e2b148272dd29b0e8389ee9e3572caf31c0e69f"; hmacV1 != want {
		t.Fatalf("version 1 HMAC digest = %q, want %q", hmacV1, want)
	}
	if want := "hmac-sha256:3bd768748bece5788b03c2d5b018e463ab020625ae1bea234435b668a50f852c"; hmacV2 != want {
		t.Fatalf("version 2 HMAC digest = %q, want %q", hmacV2, want)
	}

	mutations := []struct {
		name   string
		mutate func(*AdminAuditLogEntry)
	}{
		{name: "id", mutate: func(e *AdminAuditLogEntry) { e.ID++ }},
		{name: "action", mutate: func(e *AdminAuditLogEntry) { e.Action += ".changed" }},
		{name: "details", mutate: func(e *AdminAuditLogEntry) { e.Details = json.RawMessage(`{"statuses":"error"}`) }},
		{name: "ip", mutate: func(e *AdminAuditLogEntry) { e.IP = "192.0.2.43" }},
		{name: "created_at", mutate: func(e *AdminAuditLogEntry) { e.CreatedAt = e.CreatedAt.Add(time.Microsecond) }},
		{name: "previous_digest", mutate: func(e *AdminAuditLogEntry) { e.PreviousDigest += "x" }},
		{name: "correlation_id", mutate: func(e *AdminAuditLogEntry) { e.CorrelationID += "x" }},
	}
	for _, mutation := range mutations {
		entry := withCorrelation
		mutation.mutate(&entry)
		if got := ComputeAdminAuditDigest(entry); got == hmacV2 {
			t.Errorf("mutation %s did not change canonical digest", mutation.name)
		}
	}
}

func TestAdminAuditDigestKeyBuffersAndConcurrentAccess(t *testing.T) {
	t.Cleanup(ClearAdminAuditDigestHMACKey)

	entry := AdminAuditLogEntry{ID: 51, Action: "concurrent", CreatedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	key := []byte("0123456789abcdef0123456789abcdef")
	SetAdminAuditDigestHMACKey(key)
	want := ComputeAdminAuditDigest(entry)
	clear(key)
	if got := ComputeAdminAuditDigest(entry); got != want {
		t.Fatalf("digest changed after caller key buffer was cleared: %q, want %q", got, want)
	}

	returned := currentAdminAuditDigestHMACKey()
	clear(returned)
	if got := ComputeAdminAuditDigest(entry); got != want {
		t.Fatalf("digest changed after returned key copy was cleared: %q, want %q", got, want)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				switch i % 3 {
				case 0:
					SetAdminAuditDigestHMACKey([]byte("0123456789abcdef0123456789abcdef"))
				case 1:
					ClearAdminAuditDigestHMACKey()
				default:
					_ = ComputeAdminAuditDigest(entry)
					_ = AdminAuditIntegrityStatus(AdminAuditLogEntry{RowDigest: "unknown:value"})
				}
			}
		}(i)
	}
	wg.Wait()
	ClearAdminAuditDigestHMACKey()
	if got := currentAdminAuditDigestHMACKey(); got != nil {
		t.Fatalf("cleared key = %x, want nil", got)
	}
}
