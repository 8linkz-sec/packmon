//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF075PostgresEPSSAuditFailureRollsBack(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	updatedCVE := seedEnrichmentCVE(t, store, "CVE-2026-10751")
	staleCVE := seedEnrichmentCVE(t, store, "CVE-2026-10752")
	if updated, err := store.SetEPSSScores(ctx, []db.EPSSEntry{
		{CVEID: updatedCVE, Score: 0.31, Percentile: 0.41},
		{CVEID: staleCVE, Score: 0.51, Percentile: 0.61},
	}); err != nil || updated != 2 {
		t.Fatalf("SetEPSSScores(seed) = %d, %v; want 2, nil", updated, err)
	}

	oldSyncAt := time.Date(2026, 10, 31, 10, 11, 12, 0, time.UTC)
	oldDuration := 17 * time.Second
	oldStatusInput := &db.FeedSyncStatus{
		FeedName:         "epss",
		LastSyncAt:       &oldSyncAt,
		LastSyncDuration: &oldDuration,
		LastSyncStatus:   db.FeedSyncStatusSuccess,
		LastError:        "old diagnostic",
		EntriesSynced:    2,
		EntriesTotal:     2,
		LastETag:         "old-etag",
		LastCommitHash:   "old-commit",
		Metadata:         json.RawMessage(`{"generation":"old"}`),
	}
	if err := store.UpsertFeedSyncStatus(ctx, oldStatusInput); err != nil {
		t.Fatalf("UpsertFeedSyncStatus(seed): %v", err)
	}
	oldStatus, err := store.GetFeedSyncStatus(ctx, "epss")
	if err != nil || oldStatus == nil {
		t.Fatalf("GetFeedSyncStatus(seed) = %+v, %v", oldStatus, err)
	}
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "feed.epss.rollback.seed", IP: "127.0.0.1"}); err != nil {
		t.Fatalf("InsertAdminAuditLog(seed): %v", err)
	}
	var auditCountBefore int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log`).Scan(&auditCountBefore); err != nil {
		t.Fatalf("count seed audit rows: %v", err)
	}

	newSyncAt := oldSyncAt.Add(24 * time.Hour)
	newDuration := 29 * time.Second
	updated, cleared, total, err := store.ImportEPSSStreamWithAudit(ctx, "epss",
		func(yield func([]db.EPSSEntry) error) (*db.FeedSyncStatus, error) {
			if yieldErr := yield([]db.EPSSEntry{{CVEID: updatedCVE, Score: 0.81, Percentile: 0.91}}); yieldErr != nil {
				return nil, yieldErr
			}
			return &db.FeedSyncStatus{
				FeedName:         "epss",
				LastSyncAt:       &newSyncAt,
				LastSyncDuration: &newDuration,
				LastSyncStatus:   db.FeedSyncStatusSuccess,
				EntriesSynced:    1,
				EntriesTotal:     1,
				LastETag:         "new-etag",
				LastCommitHash:   "new-commit",
				Metadata:         json.RawMessage(`{"generation":"new"}`),
			}, nil
		},
		func(imported, deleted int) db.AdminAuditEntry {
			return db.AdminAuditEntry{
				Action:  "feed.epss.rollback.f075",
				Details: json.RawMessage(`{"test":"audit rollback"}`),
				IP:      "not-an-ip",
			}
		})
	if !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("ImportEPSSStreamWithAudit error = %v, want ErrAdminAuditLog", err)
	}
	if updated <= 0 || cleared <= 0 || total != 1 {
		t.Fatalf("ImportEPSSStreamWithAudit counts = updated %d cleared %d total %d, want positive/positive/1", updated, cleared, total)
	}

	score, percentile, _, _ := readEnrichment(t, store, updatedCVE)
	assertEnrichmentFloat(t, "updated CVE score after rollback", score, 0.31)
	assertEnrichmentFloat(t, "updated CVE percentile after rollback", percentile, 0.41)
	staleScore, stalePercentile, _, _ := readEnrichment(t, store, staleCVE)
	assertEnrichmentFloat(t, "stale CVE score after rollback", staleScore, 0.51)
	assertEnrichmentFloat(t, "stale CVE percentile after rollback", stalePercentile, 0.61)

	statusAfter, err := store.GetFeedSyncStatus(ctx, "epss")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(after rollback): %v", err)
	}
	if !reflect.DeepEqual(statusAfter, oldStatus) {
		t.Fatalf("feed status changed after rollback\ngot:  %+v\nwant: %+v", statusAfter, oldStatus)
	}
	var (
		auditCountAfter  int
		failedActionRows int
	)
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log`).Scan(&auditCountAfter); err != nil {
		t.Fatalf("count audit rows after rollback: %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log WHERE action = $1`, "feed.epss.rollback.f075").Scan(&failedActionRows); err != nil {
		t.Fatalf("count failed-action audit rows: %v", err)
	}
	if auditCountAfter != auditCountBefore || failedActionRows != 0 {
		t.Fatalf("audit rows after rollback count/action = %d/%d, want %d/0", auditCountAfter, failedActionRows, auditCountBefore)
	}
}
