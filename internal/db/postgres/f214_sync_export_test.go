package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF214ExportSyncDatasetsReturnsNoPartialPageAndStableErrorPriority(t *testing.T) {
	t.Parallel()

	snapshot := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	errs := []error{
		errors.New("vulnerability export failed"),
		errors.New("malicious export failed"),
		errors.New("reputation export failed"),
		errors.New("lifecycle export failed"),
	}

	for failing := range errs {
		failing := failing
		t.Run(errs[failing].Error(), func(t *testing.T) {
			t.Parallel()

			calls := make(chan f214DatasetCall, 4)
			exporters := syncDatasetExporters{
				vulnerabilities: func(_ context.Context, opts db.SyncExportOptions, gotSnapshot time.Time, xid uint64) (syncVulnerabilityPage, error) {
					calls <- f214DatasetCall{dataset: 0, offset: opts.Offset, limit: opts.Limit, snapshot: gotSnapshot, xid: xid}
					return syncVulnerabilityPage{rows: []db.SyncVulnerability{{ID: "partial-vulnerability"}}, hasMore: true}, errorAtF214Dataset(failing, 0, errs)
				},
				malicious: func(_ context.Context, opts db.SyncExportOptions, gotSnapshot time.Time, xid uint64) (syncRowPage[db.SyncMalicious], error) {
					calls <- f214DatasetCall{dataset: 1, offset: opts.Offset, limit: opts.Limit, snapshot: gotSnapshot, xid: xid}
					return syncRowPage[db.SyncMalicious]{rows: []db.SyncMalicious{{ID: "partial-malicious"}}, hasMore: true}, errorAtF214Dataset(failing, 1, errs)
				},
				reputation: func(_ context.Context, opts db.SyncExportOptions, gotSnapshot time.Time, xid uint64) (syncRowPage[db.SyncReputationFinding], error) {
					calls <- f214DatasetCall{dataset: 2, offset: opts.Offset, limit: opts.Limit, snapshot: gotSnapshot, xid: xid}
					return syncRowPage[db.SyncReputationFinding]{rows: []db.SyncReputationFinding{{ID: "partial-reputation"}}, hasMore: true}, errorAtF214Dataset(failing, 2, errs)
				},
				lifecycle: func(_ context.Context, opts db.SyncExportOptions, gotSnapshot time.Time, xid uint64) (syncRowPage[db.SyncLifecycleRelease], error) {
					calls <- f214DatasetCall{dataset: 3, offset: opts.Offset, limit: opts.Limit, snapshot: gotSnapshot, xid: xid}
					return syncRowPage[db.SyncLifecycleRelease]{rows: []db.SyncLifecycleRelease{{ID: "partial-lifecycle"}}, hasMore: true}, errorAtF214Dataset(failing, 3, errs)
				},
			}

			got, err := exportSyncDatasets(context.Background(), db.SyncExportOptions{Offset: 999, Limit: 10}, db.SyncCursor{
				Vulnerabilities: 11,
				Malicious:       22,
				Reputation:      33,
				Lifecycle:       44,
			}, snapshot, 4242, exporters)
			if !errors.Is(err, errs[failing]) {
				t.Fatalf("exportSyncDatasets() error = %v, want %v", err, errs[failing])
			}
			if !reflect.DeepEqual(got, syncDatasets{}) {
				t.Fatalf("exportSyncDatasets() on error = %#v, want no partial datasets", got)
			}
			close(calls)
			var called []int
			for call := range calls {
				called = append(called, call.dataset)
				wantOffset := []int{11, 22, 33, 44}[call.dataset]
				if call.offset != wantOffset || call.limit != 10 || !call.snapshot.Equal(snapshot) || call.xid != 4242 {
					t.Errorf("dataset %d inputs = offset:%d limit:%d snapshot:%v xid:%d, want %d/10/%v/4242", call.dataset, call.offset, call.limit, call.snapshot, call.xid, wantOffset, snapshot)
				}
			}
			slices.Sort(called)
			if !slices.Equal(called, []int{0, 1, 2, 3}) {
				t.Fatalf("dataset calls = %v, want all four exporters to finish", called)
			}
		})
	}

	t.Run("lowest dataset order wins regardless of completion order", func(t *testing.T) {
		t.Parallel()
		vulnerabilityRelease := make(chan struct{})
		exporters := f214SuccessfulDatasetExporters()
		exporters.vulnerabilities = func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncVulnerabilityPage, error) {
			<-vulnerabilityRelease
			return syncVulnerabilityPage{}, errs[0]
		}
		exporters.lifecycle = func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncLifecycleRelease], error) {
			close(vulnerabilityRelease)
			return syncRowPage[db.SyncLifecycleRelease]{}, errs[3]
		}
		_, err := exportSyncDatasets(context.Background(), db.SyncExportOptions{}, db.SyncCursor{}, snapshot, 4242, exporters)
		if !errors.Is(err, errs[0]) {
			t.Fatalf("exportSyncDatasets() error = %v, want first dataset error %v", err, errs[0])
		}
	})
}

func TestF214ExportSyncDatasetsSkipsCompletedDatasets(t *testing.T) {
	t.Parallel()

	panicExporter := func(string) {
		panic("completed dataset exporter called")
	}
	exporters := syncDatasetExporters{
		vulnerabilities: func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncVulnerabilityPage, error) {
			panicExporter("vulnerabilities")
			return syncVulnerabilityPage{}, nil
		},
		malicious: func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncMalicious], error) {
			panicExporter("malicious")
			return syncRowPage[db.SyncMalicious]{}, nil
		},
		reputation: func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncReputationFinding], error) {
			panicExporter("reputation")
			return syncRowPage[db.SyncReputationFinding]{}, nil
		},
		lifecycle: func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncLifecycleRelease], error) {
			panicExporter("lifecycle")
			return syncRowPage[db.SyncLifecycleRelease]{}, nil
		},
	}
	got, err := exportSyncDatasets(context.Background(), db.SyncExportOptions{}, db.SyncCursor{
		VulnerabilitiesDone: true,
		MaliciousDone:       true,
		ReputationDone:      true,
		LifecycleDone:       true,
	}, time.Time{}, 0, exporters)
	if err != nil || !reflect.DeepEqual(got, syncDatasets{}) {
		t.Fatalf("completed exportSyncDatasets() = %#v, %v; want empty success", got, err)
	}
}

func TestF214SyncCursorAndQueryBuilderErrorBoundaries(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "invalid base64", raw: "%%%", want: "decode sync cursor"},
		{name: "invalid JSON", raw: base64RawF214("{"), want: "parse sync cursor"},
		{name: "wrong number of parts", raw: encodeSyncCursorKey("npm", "pkg"), want: "has 2 parts, want 3"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeSyncCursorKey(tt.raw, 3); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("decodeSyncCursorKey(%q) error = %v, want %q", tt.raw, err, tt.want)
			}
		})
	}

	valid := encodeSyncCursorKey("", "package", "")
	parts, err := decodeSyncCursorKey(valid, 3)
	if err != nil || !slices.Equal(parts, []string{"", "package", ""}) {
		t.Fatalf("decodeSyncCursorKey(valid) = %v, %v", parts, err)
	}

	snapshot := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	invalid := "not-base64!"
	store := &Store{}
	checks := []struct {
		name string
		run  func() error
		want string
	}{
		{
			name: "vulnerability",
			run: func() error {
				_, _, err := buildExportSyncVulnerabilitiesQuery(db.SyncExportOptions{Cursor: db.SyncCursor{VulnerabilitiesCursor: invalid}}, snapshot, 0)
				return err
			},
			want: "invalid vulnerability sync cursor",
		},
		{
			name: "reputation",
			run: func() error {
				_, err := store.exportSyncReputation(context.Background(), db.SyncExportOptions{Cursor: db.SyncCursor{ReputationCursor: invalid}}, snapshot, 0)
				return err
			},
			want: "invalid reputation sync cursor",
		},
		{
			name: "malicious",
			run: func() error {
				_, err := store.exportSyncMalicious(context.Background(), db.SyncExportOptions{Cursor: db.SyncCursor{MaliciousCursor: invalid}}, snapshot, 0)
				return err
			},
			want: "invalid malicious sync cursor",
		},
		{
			name: "lifecycle",
			run: func() error {
				_, err := store.exportSyncLifecycle(context.Background(), db.SyncExportOptions{Cursor: db.SyncCursor{LifecycleCursor: invalid}}, snapshot, 0)
				return err
			},
			want: "invalid lifecycle sync cursor",
		},
	}
	for _, check := range checks {
		check := check
		t.Run(check.name, func(t *testing.T) {
			t.Parallel()
			if err := check.run(); err == nil || !strings.Contains(err.Error(), check.want) {
				t.Fatalf("%s invalid cursor error = %v, want %q", check.name, err, check.want)
			}
		})
	}
}

func TestF214VulnerabilityQueryArgumentBoundaries(t *testing.T) {
	t.Parallel()

	snapshot := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	full := newSyncVulnerabilityQueryArgs(db.SyncExportOptions{}, snapshot, ^uint64(0))
	if len(full.args) != 1 || full.args[0] != snapshot || full.changedIDsCTE() != "" {
		t.Fatalf("full query args = %#v CTE=%q, want timestamp only and no delta CTE", full.args, full.changedIDsCTE())
	}
	query := "SELECT 1"
	full.addSnapshotXIDFilters(&query)
	if query != "SELECT 1" {
		t.Fatalf("full export unexpectedly gained an XID filter: %s", query)
	}

	since := time.Date(2026, 11, 3, 14, 0, 0, 0, time.FixedZone("f214", 2*60*60))
	delta := newSyncVulnerabilityQueryArgs(db.SyncExportOptions{Since: &since}, snapshot, 0)
	if len(delta.args) != 2 || delta.args[1] != since.UTC() || delta.sinceXIDArg != 0 || delta.snapshotXIDArg != 0 {
		t.Fatalf("time-only delta args = %#v positions=%d/%d/%d", delta.args, delta.sinceArg, delta.sinceXIDArg, delta.snapshotXIDArg)
	}
	if cte := delta.changedIDsCTE(); !strings.Contains(cte, "changed_vulnerability_ids") || strings.Contains(cte, "xmin") {
		t.Fatalf("time-only changed-ID CTE = %s, want timestamps without XIDs", cte)
	}

	invalid := db.SyncExportOptions{Since: &since, Cursor: db.SyncCursor{VulnerabilitiesCursor: "invalid-delta-cursor!"}}
	if _, _, err := buildExportSyncVulnerabilitiesQuery(invalid, snapshot, 42); err == nil || !strings.Contains(err.Error(), "invalid vulnerability sync cursor") {
		t.Fatalf("buildExportSyncVulnerabilitiesQuery(%+v) error = %v, want invalid cursor", invalid.Cursor, err)
	}
}

func TestF214ScanSyncLifecycleReleasePropagatesScanError(t *testing.T) {
	t.Parallel()

	want := errors.New("f214 lifecycle scan failure")
	if got, err := scanSyncLifecycleRelease(f214FailingLifecycleScanner{err: want}); !errors.Is(err, want) || got != (db.SyncLifecycleRelease{}) {
		t.Fatalf("scanSyncLifecycleRelease() = %#v, %v; want zero row and %v", got, err, want)
	}
}

type f214FailingLifecycleScanner struct{ err error }

func (s f214FailingLifecycleScanner) Scan(...any) error { return s.err }

type f214DatasetCall struct {
	dataset  int
	offset   int
	limit    int
	snapshot time.Time
	xid      uint64
}

func errorAtF214Dataset(failing, current int, errs []error) error {
	if failing == current {
		return errs[current]
	}
	return nil
}

func f214SuccessfulDatasetExporters() syncDatasetExporters {
	return syncDatasetExporters{
		vulnerabilities: func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncVulnerabilityPage, error) {
			return syncVulnerabilityPage{}, nil
		},
		malicious: func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncMalicious], error) {
			return syncRowPage[db.SyncMalicious]{}, nil
		},
		reputation: func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncReputationFinding], error) {
			return syncRowPage[db.SyncReputationFinding]{}, nil
		},
		lifecycle: func(context.Context, db.SyncExportOptions, time.Time, uint64) (syncRowPage[db.SyncLifecycleRelease], error) {
			return syncRowPage[db.SyncLifecycleRelease]{}, nil
		},
	}
}

func base64RawF214(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
