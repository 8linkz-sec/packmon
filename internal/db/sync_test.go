package db

import (
	"encoding/base64"
	"testing"
	"time"
)

// TestSyncAdvisoryCursorRoundTrip pins the versioned vulnerabilities_cursor of
// a delta paged by whole advisories: it round-trips the last advisory ID and is
// told apart from the legacy (ecosystem, name, id) row cursor, which older
// servers issued and which a delta request may still echo.
func TestSyncAdvisoryCursorRoundTrip(t *testing.T) {
	t.Parallel()

	for _, id := range []string{"GHSA-aaaa-bbbb-cccc", "manual:3f1c", `odd "id" with spaces`} {
		raw := EncodeSyncAdvisoryCursor(id)
		got, ok := DecodeSyncAdvisoryCursor(raw)
		if !ok || got != id {
			t.Fatalf("DecodeSyncAdvisoryCursor(EncodeSyncAdvisoryCursor(%q)) = %q, %v; want the ID", id, got, ok)
		}
	}

	encode := func(payload string) string { return base64.RawURLEncoding.EncodeToString([]byte(payload)) }
	for _, raw := range []string{
		encode(`["npm","left-pad","GHSA-1"]`), // legacy row cursor
		"",
		"not-base64!",
		encode(`["advisory-v2"]`),           // tag without an ID
		encode(`["advisory-v2",""]`),        // empty ID
		encode(`["other-v2","GHSA-1"]`),     // unknown tag
		encode(`["advisory-v2","a","b"]`),   // too many parts
		encode(`{"advisory-v2":"GHSA-1"}`),  // not an array
		encode(`["advisory-v2","GHSA-1"]x`), // trailing data
	} {
		if id, ok := DecodeSyncAdvisoryCursor(raw); ok {
			t.Fatalf("DecodeSyncAdvisoryCursor(%q) = %q, true; want not an advisory cursor", raw, id)
		}
	}
	if got := EncodeSyncAdvisoryCursor("GHSA-1"); got != encode(`["advisory-v2","GHSA-1"]`) {
		t.Fatalf("EncodeSyncAdvisoryCursor() = %q, want base64url of the tagged JSON array", got)
	}
}

// TestSyncAdvisoryRowCursorRoundTrip pins the vulnerabilities_cursor that
// continues an advisory too large for one page inside that advisory: it
// round-trips the advisory ID and the last delivered (ecosystem, name) row,
// and is told apart from the advisory cursor and the legacy row cursor. It
// has four parts, so an older server rejects it instead of misreading it as a
// three-part legacy row cursor.
func TestSyncAdvisoryRowCursorRoundTrip(t *testing.T) {
	t.Parallel()

	for _, row := range [][3]string{
		{"GHSA-aaaa-bbbb-cccc", "npm", "left-pad"},
		{"manual:3f1c", "maven", "org.example:lib"},
		{`odd "id"`, "pypi", "with spaces"},
	} {
		raw := EncodeSyncAdvisoryRowCursor(row[0], row[1], row[2])
		id, ecosystem, name, ok := DecodeSyncAdvisoryRowCursor(raw)
		if !ok || id != row[0] || ecosystem != row[1] || name != row[2] {
			t.Fatalf("DecodeSyncAdvisoryRowCursor(EncodeSyncAdvisoryRowCursor(%q)) = %q %q %q %v; want the row", row, id, ecosystem, name, ok)
		}
		if _, ok := DecodeSyncAdvisoryCursor(raw); ok {
			t.Fatalf("DecodeSyncAdvisoryCursor(row cursor %q) = true, want not an advisory cursor", raw)
		}
	}

	encode := func(payload string) string { return base64.RawURLEncoding.EncodeToString([]byte(payload)) }
	for _, raw := range []string{
		EncodeSyncAdvisoryCursor("GHSA-1"),
		encode(`["npm","left-pad","GHSA-1"]`), // legacy row cursor
		"",
		"not-base64!",
		encode(`["advisory-rows-v2","GHSA-1","npm"]`),
		encode(`["advisory-rows-v2","","npm","left-pad"]`),
		encode(`["advisory-rows-v2","GHSA-1","","left-pad"]`),
		encode(`["advisory-rows-v2","GHSA-1","npm",""]`),
		encode(`["advisory-v2","GHSA-1","npm","left-pad"]`),
	} {
		if id, _, _, ok := DecodeSyncAdvisoryRowCursor(raw); ok {
			t.Fatalf("DecodeSyncAdvisoryRowCursor(%q) = %q, true; want not an advisory row cursor", raw, id)
		}
	}
	if got := EncodeSyncAdvisoryRowCursor("GHSA-1", "npm", "left-pad"); got != encode(`["advisory-rows-v2","GHSA-1","npm","left-pad"]`) {
		t.Fatalf("EncodeSyncAdvisoryRowCursor() = %q, want base64url of the tagged JSON array", got)
	}
}

func TestSyncCursorZeroAndEffectiveCursor(t *testing.T) {
	t.Parallel()

	if !(SyncCursor{}).IsZero() {
		t.Fatal("empty cursor should be zero")
	}
	if (SyncCursor{Malicious: 1}).IsZero() {
		t.Fatal("cursor with offset should not be zero")
	}

	explicit := SyncCursor{Vulnerabilities: 1, Malicious: 2, Reputation: 3, Lifecycle: 4}
	if got := (SyncExportOptions{Cursor: explicit, Offset: 99}).EffectiveCursor(); got != explicit {
		t.Fatalf("EffectiveCursor(explicit) = %+v, want %+v", got, explicit)
	}
	if got := (SyncExportOptions{Offset: 25}).EffectiveCursor(); got != (SyncCursor{Vulnerabilities: 25, Malicious: 25, Reputation: 25, Lifecycle: 25}) {
		t.Fatalf("EffectiveCursor(offset) = %+v", got)
	}
	if got := (SyncExportOptions{Offset: 0, SnapshotAt: time.Now()}).EffectiveCursor(); !got.IsZero() {
		t.Fatalf("EffectiveCursor(no offset) = %+v, want zero", got)
	}
}

func TestEffectiveCursorMarksReputationDoneWhenExcluded(t *testing.T) {
	t.Parallel()

	// Legacy offset-only clients keep their offset expansion; the reputation
	// dataset is reported as exhausted so it is never queried or paginated.
	if got := (SyncExportOptions{Offset: 25, ExcludeReputation: true}).EffectiveCursor(); got != (SyncCursor{
		Vulnerabilities: 25, Malicious: 25, Reputation: 25, Lifecycle: 25, ReputationDone: true,
	}) {
		t.Fatalf("EffectiveCursor(offset, excluded) = %+v", got)
	}
	explicit := SyncCursor{VulnerabilitiesCursor: "v", ReputationCursor: "r"}
	if got := (SyncExportOptions{Cursor: explicit, ExcludeReputation: true}).EffectiveCursor(); got != (SyncCursor{
		VulnerabilitiesCursor: "v", ReputationDone: true,
	}) {
		t.Fatalf("EffectiveCursor(explicit, excluded) = %+v, want reputation cursor dropped and done", got)
	}
	if got := (SyncExportOptions{ExcludeReputation: true}).EffectiveCursor(); got != (SyncCursor{ReputationDone: true}) {
		t.Fatalf("EffectiveCursor(first page, excluded) = %+v, want only reputation done", got)
	}
}
