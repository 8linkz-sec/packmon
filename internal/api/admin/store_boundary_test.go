package admin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/devstore"
)

// plainDBStore exposes exactly the db.Store method set and nothing more. The
// adapter probes for optional paging and counting methods with type assertions,
// so this wrapper is how the fallback branches become reachable: embedding the
// interface hides the extension methods the concrete store happens to have.
type plainDBStore struct {
	db.Store
}

// TestAdaptAdminStoreRecognisesBothStoreShapes covers the entry point. A store
// that already speaks the admin interface must be passed through untouched;
// a plain db.Store must be wrapped; anything else must be rejected with nil
// rather than a half-working adapter.
func TestAdaptAdminStoreRecognisesBothStoreShapes(t *testing.T) {
	t.Parallel()

	dev := devstore.NewStore()

	adapted := adaptAdminStore(dev)
	if adapted == nil {
		t.Fatal("adaptAdminStore(db.Store) = nil, want an adapter")
	}
	// Adapting twice must be stable: the result is already an admin Store.
	if again := adaptAdminStore(adapted); again == nil {
		t.Fatal("adaptAdminStore(Store) = nil, want the store passed through")
	}

	if got := adaptAdminStore("not a store"); got != nil {
		t.Fatalf("adaptAdminStore(unsupported) = %v, want nil", got)
	}
	if got := adaptAdminStore(nil); got != nil {
		t.Fatalf("adaptAdminStore(nil) = %v, want nil", got)
	}
}

// TestAdminStoreAdapterUsesNativePagingWhenAvailable covers the fast path: a
// store that implements paging natively must be asked for the page rather than
// silently served the first one.
func TestAdminStoreAdapterUsesNativePagingWhenAvailable(t *testing.T) {
	t.Parallel()

	adapter := dbAdminStoreAdapter{Store: devstore.NewStore()}
	ctx := context.Background()

	if _, err := adapter.ListQueueJobsPage(ctx, "", 10, 20); err != nil {
		t.Fatalf("ListQueueJobsPage with a native pager: %v", err)
	}
	if _, err := adapter.ListAdminAuditLogPage(ctx, 10, 20); err != nil {
		t.Fatalf("ListAdminAuditLogPage with a native pager: %v", err)
	}
}

// TestAdminStoreAdapterRefusesPagingItCannotHonour is the important half. Without
// native paging support, an offset request must fail loudly: returning page one
// for page three would show the operator the wrong queue entries while the UI
// still displays the requested page number.
func TestAdminStoreAdapterRefusesPagingItCannotHonour(t *testing.T) {
	t.Parallel()

	adapter := dbAdminStoreAdapter{Store: plainDBStore{Store: devstore.NewStore()}}
	ctx := context.Background()

	if _, err := adapter.ListQueueJobsPage(ctx, "", 10, 20); err == nil {
		t.Error("ListQueueJobsPage(offset) succeeded without paging support")
	} else if !strings.Contains(err.Error(), "pagination") {
		t.Errorf("error = %v, want it to name the missing pagination", err)
	}
	if _, err := adapter.ListAdminAuditLogPage(ctx, 10, 20); err == nil {
		t.Error("ListAdminAuditLogPage(offset) succeeded without paging support")
	}

	// The first page needs no paging support and must still work.
	if _, err := adapter.ListQueueJobsPage(ctx, "", 10, 0); err != nil {
		t.Errorf("ListQueueJobsPage(first page) = %v, want the unpaged fallback", err)
	}
	if _, err := adapter.ListAdminAuditLogPage(ctx, 10, 0); err != nil {
		t.Errorf("ListAdminAuditLogPage(first page) = %v, want the unpaged fallback", err)
	}
}

// TestAdminStoreAdapterListQueueJobsConvertsRows covers the conversion from the
// store's row type to the admin view model. It is the only place the queue page
// gets its data, so a dropped field would leave a blank column in the UI.
func TestAdminStoreAdapterListQueueJobsConvertsRows(t *testing.T) {
	t.Parallel()

	adapter := dbAdminStoreAdapter{Store: devstore.NewStore()}

	jobs, err := adapter.ListQueueJobs(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs: %v", err)
	}
	// The dev store starts empty; the contract is an empty result, not an error.
	if len(jobs) != 0 {
		t.Fatalf("ListQueueJobs returned %d jobs from an empty store", len(jobs))
	}
}

// TestCountUnknownSeverityFindingsFallsBackToTheDashboardAggregate covers the
// counter used by the admin data-quality banner. A store without the dedicated
// query must derive the number from the dashboard aggregate rather than report
// zero, which would hide unclassified findings entirely.
func TestCountUnknownSeverityFindingsFallsBackToTheDashboardAggregate(t *testing.T) {
	t.Parallel()

	adapter := dbAdminStoreAdapter{Store: plainDBStore{Store: devstore.NewStore()}}

	count, err := adapter.CountUnknownSeverityFindings(context.Background())
	if err != nil {
		t.Fatalf("CountUnknownSeverityFindings: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0 from an empty dev store", count)
	}
}

// TestCountUnknownSeverityFindingsPrefersTheDedicatedCounter is the counterpart:
// a store that can answer directly must not pay for the full dashboard
// aggregate, which is a far more expensive query.
func TestCountUnknownSeverityFindingsPrefersTheDedicatedCounter(t *testing.T) {
	t.Parallel()

	counter := &countingUnknownSeverityStore{Store: devstore.NewStore(), count: 42}
	adapter := dbAdminStoreAdapter{Store: counter}

	count, err := adapter.CountUnknownSeverityFindings(context.Background())
	if err != nil {
		t.Fatalf("CountUnknownSeverityFindings: %v", err)
	}
	if count != 42 {
		t.Fatalf("count = %d, want the dedicated counter's 42", count)
	}
	if !counter.called {
		t.Fatal("the dedicated counter was not used")
	}
}

type countingUnknownSeverityStore struct {
	db.Store
	count  int
	called bool
}

func (s *countingUnknownSeverityStore) CountUnknownSeverityFindings(context.Context) (int, error) {
	s.called = true
	return s.count, nil
}

// TestAdminAuditEntryToDBClonesTheDetails guards against the admin entry and the
// stored row sharing a details buffer: a later mutation of one would silently
// rewrite an audit record that is supposed to be immutable.
func TestAdminAuditEntryToDBClonesTheDetails(t *testing.T) {
	t.Parallel()

	if got := adminAuditEntryToDB(nil); got != nil {
		t.Fatalf("adminAuditEntryToDB(nil) = %v, want nil", got)
	}

	details := json.RawMessage(`{"a":1}`)
	entry := &adminAuditEntry{Action: "test", Details: details, IP: "127.0.0.1"}

	converted := adminAuditEntryToDB(entry)
	if converted.Action != "test" || converted.IP != "127.0.0.1" {
		t.Fatalf("converted = %+v, want the fields preserved", converted)
	}
	if string(converted.Details) != `{"a":1}` {
		t.Fatalf("details = %s, want the payload preserved", converted.Details)
	}

	details[2] = 'X'
	if string(converted.Details) == string(details) {
		t.Fatal("converted details still alias the source buffer")
	}
}

// TestAdminAuditEntryToDBHandlesAbsentDetails covers the common case of an audit
// entry that carries no JSON payload at all.
func TestAdminAuditEntryToDBHandlesAbsentDetails(t *testing.T) {
	t.Parallel()

	converted := adminAuditEntryToDB(&adminAuditEntry{Action: "login_success"})
	if converted == nil {
		t.Fatal("adminAuditEntryToDB returned nil for a valid entry")
	}
	if len(converted.Details) != 0 {
		t.Fatalf("details = %s, want none", converted.Details)
	}
}

// TestAdminStoreAdapterForwardsTheAdminAuthWrite covers the password write path.
// It carries the audit entry for a password change, which is one of the few
// admin actions that must always leave a trace.
func TestAdminStoreAdapterForwardsTheAdminAuthWrite(t *testing.T) {
	t.Parallel()

	store := devstore.NewStore()
	adapter := dbAdminStoreAdapter{Store: store}
	ctx := context.Background()

	if err := adapter.UpsertAdminAuthWithAudit(ctx, "argon2id$fixture", true,
		&adminAuditEntry{Action: "admin_bootstrap", IP: "127.0.0.1"}); err != nil {
		t.Fatalf("UpsertAdminAuthWithAudit: %v", err)
	}

	record, err := store.GetAdminAuth(ctx)
	if err != nil {
		t.Fatalf("GetAdminAuth: %v", err)
	}
	if record == nil {
		t.Fatal("no admin auth record was written")
	}
	if !record.PasswordIsBootstrap {
		t.Error("PasswordIsBootstrap = false, want the bootstrap flag carried through")
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != "admin_bootstrap" {
		t.Fatalf("audit log = %+v, want the password write recorded", entries)
	}
}
