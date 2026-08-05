package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestInsertAdminAuditLogTxRefusesANilEntry pins the fail-closed contract for the
// audit writer. Every audited store method hands a callback's return value
// straight to this function, so a callback that yields nil must surface as an
// error that rolls the surrounding transaction back -- not as a panic inside it,
// and not as a silently skipped audit row.
//
// A nil transaction is deliberate: the guard has to reject the entry before it
// touches the database at all.
func TestInsertAdminAuditLogTxRefusesANilEntry(t *testing.T) {
	t.Parallel()

	err := insertAdminAuditLogTx(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("insertAdminAuditLogTx(nil entry) error = nil, want a refusal")
	}
	if !errors.Is(err, errNilAdminAuditEntry) {
		t.Fatalf("error = %v, want it to report the nil audit entry", err)
	}
}

// TestInsertAdminAuditLogRefusesANilEntryBeforeOpeningATransaction covers the
// exported entry point. The zero-value store carries no connection pool, so the
// call can only return instead of panicking if the guard runs first.
func TestInsertAdminAuditLogRefusesANilEntryBeforeOpeningATransaction(t *testing.T) {
	t.Parallel()

	err := (&Store{}).InsertAdminAuditLog(context.Background(), nil)
	if err == nil {
		t.Fatal("InsertAdminAuditLog(nil entry) error = nil, want a refusal")
	}
	// Callers distinguish audit failures by this sentinel, so a nil entry has to
	// arrive under the same label as a failed audit write.
	if !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("error = %v, want it to match db.ErrAdminAuditLog", err)
	}
}

// TestInsertAdminAuditLogTxRefusesAnAnonymousEntry covers the residual invalid
// state after the builders moved from pointers to values.
//
// db.FeedImportAuditBuilder and db.RefreshEnqueueAuditBuilder return values, so
// "the builder produced nothing" is no longer expressible -- the compiler settles
// it. What a builder can still return is the zero value, and the action column is
// NOT NULL but accepts the empty string. A nameless audit row would satisfy the
// schema while recording nothing about what happened, so it is refused.
func TestInsertAdminAuditLogTxRefusesAnAnonymousEntry(t *testing.T) {
	t.Parallel()

	for _, action := range []string{"", "   ", "\t\n"} {
		err := insertAdminAuditLogTx(context.Background(), nil, &db.AdminAuditEntry{
			Action: action,
			IP:     "127.0.0.1",
		})
		if err == nil {
			t.Errorf("action %q was accepted", action)
			continue
		}
		if !errors.Is(err, errAnonymousAdminAuditEntry) {
			t.Errorf("action %q error = %v, want the anonymous-entry refusal", action, err)
		}
	}
}

// TestAuditBuildersReturnValuesNotPointers states the compile-time half of the
// contract. The assertion is the *assignment*: a builder literal returning
// *db.AdminAuditEntry no longer satisfies either named type, so reintroducing the
// pointer return breaks this file at compile time rather than at runtime inside
// an import transaction.
//
// Nothing here nil-checks the results, and nothing can: they are struct values,
// so "the builder produced no entry" is not a state that exists any more. That is
// the whole point of the change -- see the sibling test for the one invalid state
// that survives it.
func TestAuditBuildersReturnValuesNotPointers(t *testing.T) {
	t.Parallel()

	var feedImport db.FeedImportAuditBuilder = func(imported, deleted int) db.AdminAuditEntry {
		return db.AdminAuditEntry{Action: "feed_import"}
	}
	var enqueue db.RefreshEnqueueAuditBuilder = func(created bool, position int) db.AdminAuditEntry {
		return db.AdminAuditEntry{Action: "package_refresh_enqueue"}
	}

	if got := feedImport(1, 0); got.Action != "feed_import" {
		t.Errorf("feed import builder returned %+v", got)
	}
	if got := enqueue(true, 1); got.Action != "package_refresh_enqueue" {
		t.Errorf("enqueue builder returned %+v", got)
	}
}
