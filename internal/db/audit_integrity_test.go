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
}

func TestAnnotateAdminAuditIntegrityDetectsBrokenChain(t *testing.T) {
	t.Parallel()

	oldest := AdminAuditLogEntry{
		ID:        1,
		Action:    "login",
		Details:   json.RawMessage(`{"ok":"true"}`),
		IP:        "192.0.2.1",
		CreatedAt: time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC),
	}
	oldest.RowDigest = ComputeAdminAuditDigest(oldest)

	newest := AdminAuditLogEntry{
		ID:             2,
		Action:         "queue.clear",
		Details:        json.RawMessage(`{}`),
		IP:             "192.0.2.2",
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
