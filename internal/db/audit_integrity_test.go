package db

import (
	"encoding/json"
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
	defer ClearAdminAuditDigestHMACKey()

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
