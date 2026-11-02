package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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

func TestAdaptAdminStorePreservesAdminStoreIdentity(t *testing.T) {
	t.Parallel()

	adapted := adaptAdminStore(devstore.NewStore())
	if adapted == nil {
		t.Fatal("adaptAdminStore(db.Store) = nil")
	}
	if got := adaptAdminStore(adapted); got != adapted {
		t.Fatalf("adaptAdminStore(Store) = %T %v, want identical %T %v", got, got, adapted, adapted)
	}
}

func TestAdminStoreAdapterForwardsPagingAndPreservesErrors(t *testing.T) {
	t.Parallel()

	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "paging-context")
	spy := &adminPagingSpyStore{
		Store:     devstore.NewStore(),
		queueJobs: []db.RefreshJob{{ID: 17}},
		auditRows: []db.AdminAuditLogEntry{{ID: 19}},
	}
	adapter := dbAdminStoreAdapter{Store: spy}

	jobs, err := adapter.ListQueueJobsPage(ctx, "processing", 17, 34)
	if err != nil {
		t.Fatalf("ListQueueJobsPage: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != 17 {
		t.Fatalf("queue jobs = %+v", jobs)
	}
	if spy.queueCtx != ctx || spy.queueStatus != "processing" || spy.queueLimit != 17 || spy.queueOffset != 34 {
		t.Fatalf("queue paging arguments = ctx:%v status:%q limit:%d offset:%d", spy.queueCtx == ctx, spy.queueStatus, spy.queueLimit, spy.queueOffset)
	}

	auditRows, err := adapter.ListAdminAuditLogPage(ctx, 19, 38)
	if err != nil {
		t.Fatalf("ListAdminAuditLogPage: %v", err)
	}
	if len(auditRows) != 1 || auditRows[0].ID != 19 {
		t.Fatalf("audit rows = %+v", auditRows)
	}
	if spy.auditCtx != ctx || spy.auditLimit != 19 || spy.auditOffset != 38 {
		t.Fatalf("audit paging arguments = ctx:%v limit:%d offset:%d", spy.auditCtx == ctx, spy.auditLimit, spy.auditOffset)
	}

	queueErr := errors.New("native queue paging failed")
	auditErr := errors.New("native audit paging failed")
	failingPager := &adminPagingSpyStore{Store: devstore.NewStore(), queueErr: queueErr, auditErr: auditErr}
	failingAdapter := dbAdminStoreAdapter{Store: failingPager}
	if rows, gotErr := failingAdapter.ListQueueJobsPage(ctx, "error", 5, 10); rows != nil || gotErr != queueErr {
		t.Fatalf("native queue failure = rows:%+v err:%v, want nil and sentinel", rows, gotErr)
	}
	if rows, gotErr := failingAdapter.ListAdminAuditLogPage(ctx, 5, 10); rows != nil || gotErr != auditErr {
		t.Fatalf("native audit failure = rows:%+v err:%v, want nil and sentinel", rows, gotErr)
	}

	unpagedErr := errors.New("unpaged queue failed")
	unpagedStore := plainDBStore{Store: &adminListQueueErrorStore{Store: devstore.NewStore(), err: unpagedErr}}
	unpagedAdapter := dbAdminStoreAdapter{Store: unpagedStore}
	if rows, gotErr := unpagedAdapter.ListQueueJobsPage(ctx, "pending", 7, 0); rows != nil || gotErr != unpagedErr {
		t.Fatalf("unpaged queue failure = rows:%+v err:%v, want nil and sentinel", rows, gotErr)
	}
	if rows, gotErr := unpagedAdapter.ListQueueJobsPage(ctx, "pending", 7, 1); rows != nil || gotErr == nil || !strings.Contains(gotErr.Error(), "pagination") {
		t.Fatalf("unsupported offset = rows:%+v err:%v, want nil pagination error", rows, gotErr)
	}
}

func TestAdminQueueStatsConversionAndAdapterErrors(t *testing.T) {
	t.Parallel()

	if got := adminQueueStatsFromDB(nil); got != nil {
		t.Fatalf("adminQueueStatsFromDB(nil) = %+v, want nil", got)
	}
	got := adminQueueStatsFromDB(&db.QueueStatsResult{Pending: 1, Processing: 2, Done: 3, Error: 4, Paused: 5})
	want := adminQueueStats{Pending: 1, Processing: 2, Done: 3, Error: 4, Paused: 5}
	if got == nil || *got != want {
		t.Fatalf("adminQueueStatsFromDB = %+v, want %+v", got, want)
	}

	sentinel := errors.New("queue stats failed")
	adapter := dbAdminStoreAdapter{Store: &adminQueueStatsErrorStore{Store: devstore.NewStore(), err: sentinel}}
	if stats, err := adapter.QueueStats(context.Background()); stats != nil || err != sentinel {
		t.Fatalf("QueueStats = stats:%+v err:%v, want nil and sentinel", stats, err)
	}
}

func TestAdminQueueJobsConversionCopiesEveryFieldAndTimestamp(t *testing.T) {
	t.Parallel()

	requestedAt := time.Date(2026, time.November, 2, 10, 0, 0, 0, time.UTC)
	processedAt := requestedAt.Add(5 * time.Minute)
	sourceProcessedAt := processedAt
	jobs := adminQueueJobsFromDB([]db.RefreshJob{{
		ID:          41,
		Ecosystem:   "npm",
		Name:        "left-pad",
		Source:      "socket",
		Priority:    2,
		Status:      "done",
		RequestedAt: requestedAt,
		ProcessedAt: &sourceProcessedAt,
		Error:       "safe diagnostic",
	}})
	if len(jobs) != 1 {
		t.Fatalf("jobs = %+v", jobs)
	}
	got := jobs[0]
	if got.ID != 41 || got.Ecosystem != "npm" || got.Name != "left-pad" || got.Source != "socket" ||
		got.Priority != 2 || got.Status != "done" || !got.RequestedAt.Equal(requestedAt) || got.Error != "safe diagnostic" {
		t.Fatalf("converted job dropped fields: %+v", got)
	}
	if got.ProcessedAt == nil || !got.ProcessedAt.Equal(processedAt) {
		t.Fatalf("ProcessedAt = %v, want %v", got.ProcessedAt, processedAt)
	}
	if got.ProcessedAt == &sourceProcessedAt {
		t.Fatal("ProcessedAt aliases the source pointer")
	}

	sourceProcessedAt = sourceProcessedAt.Add(time.Hour)
	if !got.ProcessedAt.Equal(processedAt) {
		t.Fatalf("ProcessedAt changed after source mutation: %v", got.ProcessedAt)
	}
}

func TestCountUnknownSeverityFindingsCoversFallbackAndErrors(t *testing.T) {
	t.Parallel()

	t.Run("nonzero dashboard fallback", func(t *testing.T) {
		store := &adminDashboardStatsStore{Store: devstore.NewStore(), stats: &db.DashboardStatsResult{BySeverity: map[string]int{"UNKNOWN": 9}}}
		count, err := (dbAdminStoreAdapter{Store: store}).CountUnknownSeverityFindings(context.Background())
		if err != nil || count != 9 {
			t.Fatalf("CountUnknownSeverityFindings = %d, %v; want 9, nil", count, err)
		}
	})

	t.Run("dashboard error", func(t *testing.T) {
		sentinel := errors.New("dashboard failed")
		store := &adminDashboardStatsStore{Store: devstore.NewStore(), err: sentinel}
		count, err := (dbAdminStoreAdapter{Store: store}).CountUnknownSeverityFindings(context.Background())
		if count != 0 || err != sentinel {
			t.Fatalf("CountUnknownSeverityFindings = %d, %v; want 0 and sentinel", count, err)
		}
	})

	t.Run("nil dashboard", func(t *testing.T) {
		store := &adminDashboardStatsStore{Store: devstore.NewStore()}
		count, err := (dbAdminStoreAdapter{Store: store}).CountUnknownSeverityFindings(context.Background())
		if count != 0 || err != nil {
			t.Fatalf("CountUnknownSeverityFindings = %d, %v; want 0, nil", count, err)
		}
	})

	t.Run("dedicated counter error does not fall back", func(t *testing.T) {
		sentinel := errors.New("dedicated counter failed")
		dashboard := &adminDashboardStatsStore{
			Store: devstore.NewStore(),
			stats: &db.DashboardStatsResult{BySeverity: map[string]int{"UNKNOWN": 99}},
		}
		store := &adminUnknownSeverityCounterStore{adminDashboardStatsStore: dashboard, err: sentinel}
		count, err := (dbAdminStoreAdapter{Store: store}).CountUnknownSeverityFindings(context.Background())
		if count != 0 || err != sentinel {
			t.Fatalf("CountUnknownSeverityFindings = %d, %v; want 0 and sentinel", count, err)
		}
		if !store.called {
			t.Fatal("dedicated counter was not called")
		}
		if dashboard.calls != 0 {
			t.Fatalf("DashboardStats called %d times after dedicated counter error", dashboard.calls)
		}
	})
}

type adminPagingSpyStore struct {
	db.Store
	queueCtx    context.Context
	queueStatus string
	queueLimit  int
	queueOffset int
	queueJobs   []db.RefreshJob
	queueErr    error
	auditCtx    context.Context
	auditLimit  int
	auditOffset int
	auditRows   []db.AdminAuditLogEntry
	auditErr    error
}

func (s *adminPagingSpyStore) ListQueueJobsPage(ctx context.Context, status string, limit, offset int) ([]db.RefreshJob, error) {
	s.queueCtx = ctx
	s.queueStatus = status
	s.queueLimit = limit
	s.queueOffset = offset
	if s.queueErr != nil {
		return nil, s.queueErr
	}
	return s.queueJobs, nil
}

func (s *adminPagingSpyStore) ListAdminAuditLogPage(ctx context.Context, limit, offset int) ([]db.AdminAuditLogEntry, error) {
	s.auditCtx = ctx
	s.auditLimit = limit
	s.auditOffset = offset
	if s.auditErr != nil {
		return nil, s.auditErr
	}
	return s.auditRows, nil
}

type adminListQueueErrorStore struct {
	db.Store
	err error
}

func (s *adminListQueueErrorStore) ListQueueJobs(context.Context, string, int) ([]db.RefreshJob, error) {
	return nil, s.err
}

type adminQueueStatsErrorStore struct {
	db.Store
	err error
}

func (s *adminQueueStatsErrorStore) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	return nil, s.err
}

type adminDashboardStatsStore struct {
	db.Store
	stats *db.DashboardStatsResult
	err   error
	calls int
}

func (s *adminDashboardStatsStore) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	s.calls++
	return s.stats, s.err
}

type adminUnknownSeverityCounterStore struct {
	*adminDashboardStatsStore
	count  int
	err    error
	called bool
}

func (s *adminUnknownSeverityCounterStore) CountUnknownSeverityFindings(context.Context) (int, error) {
	s.called = true
	return s.count, s.err
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
