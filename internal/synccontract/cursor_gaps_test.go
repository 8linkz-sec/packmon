package synccontract

import (
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestCursorIsZero(t *testing.T) {
	t.Parallel()

	if !(Cursor{}).IsZero() {
		t.Fatal("Cursor{}.IsZero() = false, want true")
	}
	nonZero := []Cursor{
		{Vulnerabilities: 1},
		{Malicious: 2},
		{Reputation: 3},
		{Lifecycle: 4},
		{VulnerabilitiesCursor: "v"},
		{MaliciousCursor: "m"},
		{ReputationCursor: "r"},
		{LifecycleCursor: "l"},
		{VulnerabilitiesDone: true},
		{MaliciousDone: true},
		{ReputationDone: true},
		{LifecycleDone: true},
	}
	for i, cursor := range nonZero {
		if cursor.IsZero() {
			t.Fatalf("case %d: %+v IsZero() = true, want false", i, cursor)
		}
	}
}

func TestCursorFromDBMapsAllFieldsAndNil(t *testing.T) {
	t.Parallel()

	if got := cursorFromDB(nil); got != nil {
		t.Fatalf("cursorFromDB(nil) = %+v, want nil", got)
	}

	got := cursorFromDB(&db.SyncCursor{
		Vulnerabilities:       1,
		Malicious:             2,
		Reputation:            3,
		Lifecycle:             4,
		VulnerabilitiesCursor: "vc",
		MaliciousCursor:       "mc",
		ReputationCursor:      "rc",
		LifecycleCursor:       "lc",
		VulnerabilitiesDone:   true,
		MaliciousDone:         true,
		ReputationDone:        true,
		LifecycleDone:         true,
	})
	if got == nil {
		t.Fatal("cursorFromDB(non-nil) = nil, want cursor")
	}
	want := Cursor{
		Vulnerabilities:       1,
		Malicious:             2,
		Reputation:            3,
		Lifecycle:             4,
		VulnerabilitiesCursor: "vc",
		MaliciousCursor:       "mc",
		ReputationCursor:      "rc",
		LifecycleCursor:       "lc",
		VulnerabilitiesDone:   true,
		MaliciousDone:         true,
		ReputationDone:        true,
		LifecycleDone:         true,
	}
	if *got != want {
		t.Fatalf("cursorFromDB() = %+v, want %+v", *got, want)
	}
}
