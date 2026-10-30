//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMaliciousSnapshotAndMutationLocksSerializeWriters(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	seed := snapshotFinding("MAL-lock", "lock")
	if err := store.UpsertMaliciousFinding(ctx, &seed); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	lockConn, err := store.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire lock connection: %v", err)
	}
	defer lockConn.Release()
	tx, err := lockConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock transaction: %v", err)
	}
	if err := acquireMaliciousMutationLockTx(ctx, tx); err != nil {
		t.Fatalf("acquire global mutation lock: %v", err)
	}
	mutationDone := make(chan error, 1)
	go func() {
		mutationDone <- store.DeleteMaliciousFindingForSource(context.Background(), seed.ID, "openssf")
	}()
	assertOperationBlocked(t, mutationDone, "malicious mutation")
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("release global mutation lock: %v", err)
	}
	if err := <-mutationDone; err != nil {
		t.Fatalf("malicious mutation after lock release: %v", err)
	}

	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, openssfSnapshotLockKey); err != nil {
		t.Fatalf("acquire OpenSSF session lock: %v", err)
	}
	snapshotDone := make(chan error, 1)
	go func() {
		_, _, replaceErr := store.ReplaceMaliciousFindingsSnapshot(context.Background(), "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
			return yield([]db.MaliciousFinding{seed}, nil)
		})
		snapshotDone <- replaceErr
	}()
	assertOperationBlocked(t, snapshotDone, "OpenSSF snapshot")
	var unlocked bool
	if err := lockConn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, openssfSnapshotLockKey).Scan(&unlocked); err != nil || !unlocked {
		t.Fatalf("release OpenSSF session lock: unlocked=%v err=%v", unlocked, err)
	}
	if err := <-snapshotDone; err != nil {
		t.Fatalf("OpenSSF snapshot after lock release: %v", err)
	}
}

func TestReplaceMaliciousFindingsSnapshotReconcilesWithoutTouchingUnchangedRows(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	unchanged := snapshotFinding("MAL-snapshot-unchanged", "unchanged")
	unchanged.Ecosystem = "PyPI"
	unchanged.Name = "Example_Package.Name"
	changed := snapshotFinding("MAL-snapshot-changed", "old summary")
	absent := snapshotFinding("MAL-snapshot-absent", "absent")
	resurrected := snapshotFinding("MAL-snapshot-resurrected", "resurrected")
	explicit := snapshotFinding("MAL-snapshot-explicit", "explicit")
	otherSource := snapshotFinding("MAL-snapshot-socket", "socket")
	otherSource.Source = "socket"
	for _, finding := range []*db.MaliciousFinding{&unchanged, &changed, &absent, &resurrected, &explicit, &otherSource} {
		if err := store.UpsertMaliciousFinding(ctx, finding); err != nil {
			t.Fatalf("seed %s: %v", finding.ID, err)
		}
	}
	if err := store.DeleteMaliciousFindingForSource(ctx, resurrected.ID, "openssf"); err != nil {
		t.Fatalf("seed removed finding: %v", err)
	}

	var unchangedCTID string
	var unchangedUpdated time.Time
	if err := store.pool.QueryRow(ctx, `SELECT ctid::text, updated_at FROM malicious_findings WHERE id = $1`, unchanged.ID).Scan(&unchangedCTID, &unchangedUpdated); err != nil {
		t.Fatalf("read unchanged row identity: %v", err)
	}
	changed.Summary = "new summary"

	changedCount, withdrawnCount, err := store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		if err := yield([]db.MaliciousFinding{unchanged, changed}, nil); err != nil {
			return err
		}
		return yield([]db.MaliciousFinding{resurrected}, []string{explicit.ID})
	})
	if err != nil {
		t.Fatalf("ReplaceMaliciousFindingsSnapshot: %v", err)
	}
	if changedCount != 2 || withdrawnCount != 2 {
		t.Fatalf("changed/withdrawn = %d/%d, want 2/2", changedCount, withdrawnCount)
	}

	var gotCTID string
	var gotUpdated time.Time
	if err := store.pool.QueryRow(ctx, `SELECT ctid::text, updated_at FROM malicious_findings WHERE id = $1`, unchanged.ID).Scan(&gotCTID, &gotUpdated); err != nil {
		t.Fatalf("read unchanged row after snapshot: %v", err)
	}
	if gotCTID != unchangedCTID || !gotUpdated.Equal(unchangedUpdated) {
		t.Fatalf("unchanged row ctid/updated_at = %s/%s, want %s/%s", gotCTID, gotUpdated, unchangedCTID, unchangedUpdated)
	}

	assertMaliciousSnapshotRow(t, store, changed.ID, "openssf", "new summary", false)
	assertMaliciousSnapshotRow(t, store, resurrected.ID, "openssf", "resurrected", false)
	assertMaliciousSnapshotRow(t, store, absent.ID, "openssf", "absent", true)
	assertMaliciousSnapshotRow(t, store, explicit.ID, "openssf", "explicit", true)
	assertMaliciousSnapshotRow(t, store, otherSource.ID, "socket", "socket", false)

	secondChanged, secondWithdrawn, err := store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		return yield([]db.MaliciousFinding{unchanged, changed, resurrected}, []string{explicit.ID})
	})
	if err != nil {
		t.Fatalf("ReplaceMaliciousFindingsSnapshot(identical): %v", err)
	}
	if secondChanged != 0 || secondWithdrawn != 0 {
		t.Fatalf("identical snapshot changed/withdrawn = %d/%d, want 0/0", secondChanged, secondWithdrawn)
	}
}

func TestReplaceMaliciousFindingsSnapshotFailsClosedAndCleansSession(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	seed := snapshotFinding("MAL-snapshot-guard", "original")
	if err := store.UpsertMaliciousFinding(ctx, &seed); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	_, _, err := store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		if err := yield([]db.MaliciousFinding{seed}, nil); err != nil {
			return err
		}
		return errors.New("parse failed after first batch")
	})
	if err == nil || !strings.Contains(err.Error(), "parse failed") {
		t.Fatalf("stream failure = %v, want parse failure", err)
	}
	assertMaliciousSnapshotRow(t, store, seed.ID, "openssf", "original", false)

	_, _, err = store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(func([]db.MaliciousFinding, []string) error) error {
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "at least one active finding") {
		t.Fatalf("empty snapshot error = %v", err)
	}
	assertMaliciousSnapshotRow(t, store, seed.ID, "openssf", "original", false)

	oversized := make([]db.MaliciousFinding, db.MaliciousSnapshotBatchSize+1)
	_, _, err = store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		return yield(oversized, nil)
	})
	if err == nil || !strings.Contains(err.Error(), "maximum is") {
		t.Fatalf("oversized snapshot batch error = %v", err)
	}
	assertMaliciousSnapshotRow(t, store, seed.ID, "openssf", "original", false)

	_, _, err = store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		if yieldErr := yield([]db.MaliciousFinding{seed}, nil); yieldErr != nil {
			return yieldErr
		}
		return yield(nil, []string{seed.ID})
	})
	if err == nil || !strings.Contains(err.Error(), "both active and withdrawn") {
		t.Fatalf("cross-set duplicate error = %v", err)
	}
	assertMaliciousSnapshotRow(t, store, seed.ID, "openssf", "original", false)

	collision := snapshotFinding("MAL-snapshot-collision", "socket owns this")
	collision.Source = "socket"
	if err := store.UpsertMaliciousFinding(ctx, &collision); err != nil {
		t.Fatalf("seed cross-source finding: %v", err)
	}
	collision.Source = "openssf"
	_, _, err = store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		return yield([]db.MaliciousFinding{seed, collision}, nil)
	})
	if err == nil || !strings.Contains(err.Error(), "owned by source socket") {
		t.Fatalf("cross-source collision error = %v", err)
	}
	assertMaliciousSnapshotRow(t, store, collision.ID, "socket", "socket owns this", false)

	changed, withdrawn, err := store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		return yield([]db.MaliciousFinding{seed}, nil)
	})
	if err != nil {
		t.Fatalf("retry after failed snapshots: %v", err)
	}
	if changed != 0 || withdrawn != 0 {
		t.Fatalf("retry changed/withdrawn = %d/%d, want 0/0", changed, withdrawn)
	}
}

func TestOpenSSFLegacyWriterWaitsForSnapshotAndIsNotPruned(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	snapshotRow := snapshotFinding("MAL-snapshot-serialized", "snapshot")
	lateWriter := snapshotFinding("MAL-snapshot-late-writer", "legacy writer")

	staged := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	snapshotDone := make(chan error, 1)
	go func() {
		_, _, err := store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
			if err := yield([]db.MaliciousFinding{snapshotRow}, nil); err != nil {
				return err
			}
			close(staged)
			<-releaseSnapshot
			return nil
		})
		snapshotDone <- err
	}()
	<-staged

	writerDone := make(chan error, 1)
	go func() {
		writerDone <- store.UpsertMaliciousFinding(ctx, &lateWriter)
	}()
	assertOperationBlocked(t, writerDone, "OpenSSF legacy writer")
	close(releaseSnapshot)
	if err := <-snapshotDone; err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := <-writerDone; err != nil {
		t.Fatalf("legacy writer after snapshot: %v", err)
	}

	assertMaliciousSnapshotRow(t, store, snapshotRow.ID, "openssf", "snapshot", false)
	assertMaliciousSnapshotRow(t, store, lateWriter.ID, "openssf", "legacy writer", false)
}

func TestSocketWriterCollisionDuringOpenSSFSnapshotFailsClosed(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	collision := snapshotFinding("MAL-snapshot-concurrent-collision", "openssf")
	anchor := snapshotFinding("MAL-snapshot-concurrent-anchor", "anchor")

	staged := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	snapshotDone := make(chan error, 1)
	go func() {
		_, _, err := store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
			if err := yield([]db.MaliciousFinding{anchor, collision}, nil); err != nil {
				return err
			}
			close(staged)
			<-releaseSnapshot
			return nil
		})
		snapshotDone <- err
	}()
	<-staged

	socket := collision
	socket.Source = "socket"
	socket.Summary = "socket owns collision"
	if err := store.UpsertMaliciousFinding(ctx, &socket); err != nil {
		t.Fatalf("concurrent Socket writer: %v", err)
	}
	close(releaseSnapshot)
	if err := <-snapshotDone; err == nil || !strings.Contains(err.Error(), "owned by source socket") {
		t.Fatalf("snapshot collision error = %v, want Socket ownership refusal", err)
	}
	assertMaliciousSnapshotRow(t, store, socket.ID, "socket", socket.Summary, false)

	if err := store.UpsertMaliciousFinding(ctx, &collision); err == nil || !strings.Contains(err.Error(), "owned by source socket") {
		t.Fatalf("OpenSSF overwrite of Socket row error = %v, want ownership refusal", err)
	}
}

func TestMaliciousSnapshotFailurePathsDiscardPhysicalConnection(t *testing.T) {
	_, dsn := startDockerPostgresStore(t)
	store, err := New(context.Background(), dsn, nil, &PoolConfig{MaxConns: 1, MinConns: 1})
	if err != nil {
		t.Fatalf("New(single connection): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	tests := []struct {
		name             string
		cancelAfterStage bool
		hooks            func() *maliciousSnapshotHooks
		stream           func(context.Context, db.MaliciousFinding, func([]db.MaliciousFinding, []string) error) error
	}{
		{
			name: "stage",
			stream: func(_ context.Context, finding db.MaliciousFinding, yield func([]db.MaliciousFinding, []string) error) error {
				if err := yield([]db.MaliciousFinding{finding}, nil); err != nil {
					return err
				}
				return errors.New("forced stage error")
			},
		},
		{
			name:             "cancel",
			cancelAfterStage: true,
		},
		{
			name: "finalize",
			hooks: func() *maliciousSnapshotHooks {
				return &maliciousSnapshotHooks{beforeFinalize: func() error { return errors.New("forced finalize error") }}
			},
		},
		{
			name: "ambiguous_commit",
			hooks: func() *maliciousSnapshotHooks {
				return &maliciousSnapshotHooks{commit: func(ctx context.Context, tx pgx.Tx) error {
					if err := tx.Commit(ctx); err != nil {
						return err
					}
					return errors.New("forced ambiguous commit result")
				}}
			},
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finding := snapshotFinding(fmt.Sprintf("MAL-snapshot-discard-%d", i), tt.name)
			var operationPID int
			hooks := &maliciousSnapshotHooks{}
			if tt.hooks != nil {
				hooks = tt.hooks()
			}
			hooks.afterAcquire = func(ctx context.Context, conn *pgxpool.Conn) error {
				return conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&operationPID)
			}
			stream := func(yield func([]db.MaliciousFinding, []string) error) error {
				if tt.stream != nil {
					return tt.stream(ctx, finding, yield)
				}
				if err := yield([]db.MaliciousFinding{finding}, nil); err != nil {
					return err
				}
				if tt.cancelAfterStage {
					cancel()
					return ctx.Err()
				}
				return nil
			}
			_, _, err := store.replaceMaliciousFindingsSnapshot(ctx, "openssf", stream, hooks)
			if err == nil {
				t.Fatal("snapshot error = nil, want forced failure")
			}
			assertPoolUsesNewBackend(t, store, operationPID)

			retry := snapshotFinding(fmt.Sprintf("MAL-snapshot-discard-retry-%d", i), "retry")
			if _, _, retryErr := store.ReplaceMaliciousFindingsSnapshot(context.Background(), "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
				return yield([]db.MaliciousFinding{retry}, nil)
			}); retryErr != nil {
				t.Fatalf("retry after discarded connection: %v", retryErr)
			}
		})
	}
}

func TestMaliciousSnapshotCleanupFailureAfterCommitReturnsSuccessAndDiscardsConnection(t *testing.T) {
	_, dsn := startDockerPostgresStore(t)
	store, err := New(context.Background(), dsn, nil, &PoolConfig{MaxConns: 1, MinConns: 1})
	if err != nil {
		t.Fatalf("New(single connection): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	finding := snapshotFinding("MAL-snapshot-cleanup-failure", "committed")
	var operationPID int
	hooks := &maliciousSnapshotHooks{
		afterAcquire: func(ctx context.Context, conn *pgxpool.Conn) error {
			return conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&operationPID)
		},
		cleanup: func(*pgxpool.Conn, bool) error {
			return errors.New("forced cleanup failure")
		},
	}
	changed, withdrawn, err := store.replaceMaliciousFindingsSnapshot(context.Background(), "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		return yield([]db.MaliciousFinding{finding}, nil)
	}, hooks)
	if err != nil || changed != 1 || withdrawn != 0 {
		t.Fatalf("snapshot result = %d/%d err=%v, want 1/0 success", changed, withdrawn, err)
	}
	assertPoolUsesNewBackend(t, store, operationPID)
	assertMaliciousSnapshotRow(t, store, finding.ID, "openssf", "committed", false)
	if _, _, retryErr := store.ReplaceMaliciousFindingsSnapshot(context.Background(), "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		return yield([]db.MaliciousFinding{finding}, nil)
	}); retryErr != nil {
		t.Fatalf("retry after post-commit cleanup failure: %v", retryErr)
	}
}

func TestMaliciousSnapshotInvalidatesDashboardCacheOnceAfterCommitBeforeCleanup(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	before := dashboardStatsGeneration(store)
	cleanupObserved := false
	hooks := &maliciousSnapshotHooks{
		commit: func(ctx context.Context, tx pgx.Tx) error {
			if got := dashboardStatsGeneration(store); got != before {
				t.Errorf("generation before commit = %d, want %d", got, before)
			}
			return tx.Commit(ctx)
		},
		cleanup: func(conn *pgxpool.Conn, unlock bool) error {
			cleanupObserved = true
			if got := dashboardStatsGeneration(store); got != before+1 {
				t.Errorf("generation during cleanup = %d, want %d", got, before+1)
			}
			return cleanupMaliciousSnapshotConnection(conn, unlock)
		},
	}
	finding := snapshotFinding("MAL-snapshot-cache-invalidation", "committed")
	changed, withdrawn, err := store.replaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		return yield([]db.MaliciousFinding{finding}, nil)
	}, hooks)
	if err != nil || changed != 1 || withdrawn != 0 {
		t.Fatalf("snapshot result = %d/%d err=%v, want 1/0 success", changed, withdrawn, err)
	}
	if !cleanupObserved {
		t.Fatal("successful snapshot did not run cleanup hook")
	}
	if got := dashboardStatsGeneration(store); got != before+1 {
		t.Fatalf("generation after successful snapshot = %d, want %d", got, before+1)
	}

	beforeFailure := dashboardStatsGeneration(store)
	cleanupObserved = false
	failingHooks := &maliciousSnapshotHooks{
		commit: func(context.Context, pgx.Tx) error {
			if got := dashboardStatsGeneration(store); got != beforeFailure {
				t.Errorf("generation before failed commit = %d, want %d", got, beforeFailure)
			}
			return errors.New("forced commit failure")
		},
		cleanup: func(conn *pgxpool.Conn, unlock bool) error {
			cleanupObserved = true
			return cleanupMaliciousSnapshotConnection(conn, unlock)
		},
	}
	failingFinding := snapshotFinding("MAL-snapshot-cache-no-invalidation", "not committed")
	if _, _, err := store.replaceMaliciousFindingsSnapshot(ctx, "openssf", func(yield func([]db.MaliciousFinding, []string) error) error {
		return yield([]db.MaliciousFinding{failingFinding}, nil)
	}, failingHooks); err == nil {
		t.Fatal("snapshot commit error = nil, want forced failure")
	}
	if cleanupObserved {
		t.Fatal("failed snapshot used successful cleanup path")
	}
	if got := dashboardStatsGeneration(store); got != beforeFailure {
		t.Fatalf("generation after failed snapshot = %d, want %d", got, beforeFailure)
	}
}

func dashboardStatsGeneration(store *Store) uint64 {
	store.dashboardStatsCache.mu.Lock()
	defer store.dashboardStatsCache.mu.Unlock()
	return store.dashboardStatsCache.generation
}

func TestMaliciousSnapshotRepresentativeScalePreservesUnchangedRows(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	const findingCount = 5000
	findings := make([]db.MaliciousFinding, findingCount)
	for i := range findings {
		findings[i] = snapshotFinding(fmt.Sprintf("MAL-scale-%05d", i), "representative scale")
	}

	stream := func(yield func([]db.MaliciousFinding, []string) error) error {
		for start := 0; start < len(findings); start += db.MaliciousSnapshotBatchSize {
			end := min(start+db.MaliciousSnapshotBatchSize, len(findings))
			if err := yield(findings[start:end], nil); err != nil {
				return err
			}
		}
		return nil
	}
	started := time.Now()
	changed, withdrawn, err := store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", stream)
	firstDuration := time.Since(started)
	if err != nil || changed != findingCount || withdrawn != 0 {
		t.Fatalf("initial scale snapshot = %d/%d err=%v, want %d/0", changed, withdrawn, err, findingCount)
	}
	var beforeCTID string
	var beforeUpdated time.Time
	if err := store.pool.QueryRow(ctx, `SELECT ctid::text, updated_at FROM malicious_findings WHERE id = $1`, findings[findingCount/2].ID).Scan(&beforeCTID, &beforeUpdated); err != nil {
		t.Fatalf("read scale sample before repeat: %v", err)
	}

	started = time.Now()
	changed, withdrawn, err = store.ReplaceMaliciousFindingsSnapshot(ctx, "openssf", stream)
	secondDuration := time.Since(started)
	if err != nil || changed != 0 || withdrawn != 0 {
		t.Fatalf("unchanged scale snapshot = %d/%d err=%v, want 0/0", changed, withdrawn, err)
	}
	var afterCTID string
	var afterUpdated time.Time
	if err := store.pool.QueryRow(ctx, `SELECT ctid::text, updated_at FROM malicious_findings WHERE id = $1`, findings[findingCount/2].ID).Scan(&afterCTID, &afterUpdated); err != nil {
		t.Fatalf("read scale sample after repeat: %v", err)
	}
	if beforeCTID != afterCTID || !beforeUpdated.Equal(afterUpdated) {
		t.Fatalf("unchanged scale sample changed ctid/updated_at: %s/%s -> %s/%s", beforeCTID, beforeUpdated, afterCTID, afterUpdated)
	}
	t.Logf("representative %d-row snapshot: initial=%s unchanged=%s", findingCount, firstDuration, secondDuration)
}

func snapshotFinding(id, summary string) db.MaliciousFinding {
	return db.MaliciousFinding{
		ID:            id,
		Ecosystem:     "npm",
		Name:          strings.ToLower(id),
		Source:        "openssf",
		RiskType:      "malware",
		Severity:      "CRITICAL",
		Summary:       summary,
		ReferenceURLs: []byte(`[]`),
		OriginRef:     id + ".json",
		CreatedBy:     "feed-sync",
	}
}

func assertOperationBlocked(t *testing.T, done <-chan error, operation string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s completed while lock was held: %v", operation, err)
	case <-time.After(150 * time.Millisecond):
	}
}

func assertPoolUsesNewBackend(t *testing.T, store *Store, discardedPID int) {
	t.Helper()
	var currentPID int
	if err := store.pool.QueryRow(context.Background(), `SELECT pg_backend_pid()`).Scan(&currentPID); err != nil {
		t.Fatalf("read replacement backend PID: %v", err)
	}
	if currentPID == discardedPID {
		t.Fatalf("pool reused backend PID %d after snapshot connection should have been discarded", currentPID)
	}
}

func assertMaliciousSnapshotRow(t *testing.T, store *Store, id, source, summary string, removed bool) {
	t.Helper()
	var gotSource, gotSummary string
	var gotRemoved bool
	if err := store.pool.QueryRow(context.Background(), `
		SELECT source, summary, removed_at IS NOT NULL
		FROM malicious_findings
		WHERE id = $1`, id).Scan(&gotSource, &gotSummary, &gotRemoved); err != nil {
		t.Fatalf("read malicious row %s: %v", id, err)
	}
	if gotSource != source || gotSummary != summary || gotRemoved != removed {
		t.Fatalf("row %s = source %q summary %q removed %v, want %q/%q/%v", id, gotSource, gotSummary, gotRemoved, source, summary, removed)
	}
}
