package devstore

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

// TestFeedImportsWithAuditRecordStatusAndAudit covers the four keyed-feed import
// entry points of the development store. They store nothing -- that is the point
// of the dev store -- but they must still record the sync status and the admin
// audit entry, and they must report zero imports rather than pretending the data
// landed. An audit trail claiming a successful import against a store that keeps
// nothing would be actively misleading.
func TestFeedImportsWithAuditRecordStatusAndAudit(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		feed   string
		invoke func(*Store, context.Context, *db.FeedSyncStatus, db.FeedImportAuditBuilder) error
	}{
		"vulncheck": {
			feed: "vulncheck",
			invoke: func(s *Store, ctx context.Context, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) error {
				imported, err := s.ImportVulnCheckWithAudit(ctx, "vulncheck", []db.VulnCheckEntry{{CVEID: "CVE-1"}}, status, audit)
				if err == nil && imported != 0 {
					t.Fatalf("ImportVulnCheckWithAudit() imported = %d, want 0", imported)
				}
				return err
			},
		},
		"cisakev import": {
			feed: "cisakev",
			invoke: func(s *Store, ctx context.Context, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) error {
				imported, err := s.ImportCISAKEVWithAudit(ctx, "cisakev", []string{"CVE-1"}, status, audit)
				if err == nil && imported != 0 {
					t.Fatalf("ImportCISAKEVWithAudit() imported = %d, want 0", imported)
				}
				return err
			},
		},
		"cisakev replace": {
			feed: "cisakev",
			invoke: func(s *Store, ctx context.Context, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) error {
				imported, deleted, err := s.ReplaceCISAKEVWithAudit(ctx, "cisakev", []string{"CVE-1"}, status, audit)
				if err == nil && (imported != 0 || deleted != 0) {
					t.Fatalf("ReplaceCISAKEVWithAudit() = (%d,%d), want (0,0)", imported, deleted)
				}
				return err
			},
		},
		"epss": {
			feed: "epss",
			invoke: func(s *Store, ctx context.Context, status *db.FeedSyncStatus, audit db.FeedImportAuditBuilder) error {
				imported, deleted, err := s.ImportEPSSWithAudit(ctx, "epss", []db.EPSSEntry{{CVEID: "CVE-1", Score: 0.5, Percentile: 0.9}}, status, audit)
				if err == nil && (imported != 0 || deleted != 0) {
					t.Fatalf("ImportEPSSWithAudit() = (%d,%d), want (0,0)", imported, deleted)
				}
				return err
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := newNoopStore()
			ctx := context.Background()

			var gotImported, gotDeleted int
			auditCalled := false
			audit := func(imported, deleted int) db.AdminAuditEntry {
				auditCalled = true
				gotImported, gotDeleted = imported, deleted
				return db.AdminAuditEntry{
					Action:  "feed_import",
					Details: json.RawMessage(`{"feed":"` + tt.feed + `"}`),
					IP:      "127.0.0.1",
				}
			}
			status := &db.FeedSyncStatus{
				FeedName:       tt.feed,
				LastSyncStatus: "success",
				EntriesSynced:  0,
				EntriesTotal:   1,
			}

			if err := tt.invoke(store, ctx, status, audit); err != nil {
				t.Fatalf("import error = %v", err)
			}

			if !auditCalled {
				t.Fatal("audit callback was not invoked; the import would go unrecorded")
			}
			if gotImported != 0 || gotDeleted != 0 {
				t.Fatalf("audit callback received (%d,%d), want (0,0) because the dev store persists nothing",
					gotImported, gotDeleted)
			}

			gotStatus, err := store.GetFeedSyncStatus(ctx, tt.feed)
			if err != nil {
				t.Fatalf("GetFeedSyncStatus() error = %v", err)
			}
			if gotStatus == nil || gotStatus.LastSyncStatus != "success" {
				t.Fatalf("GetFeedSyncStatus() = %+v, want the recorded sync status", gotStatus)
			}

			entries, err := store.ListAdminAuditLog(ctx, 10)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if len(entries) != 1 || entries[0].Action != "feed_import" {
				t.Fatalf("ListAdminAuditLog() = %+v, want the feed_import entry", entries)
			}
		})
	}
}

// TestFeedImportsWithAuditToleratePartialArguments pins the optional-argument
// behaviour. Callers that neither track sync status nor audit must not be forced
// to supply either, and passing nil must not panic.
func TestFeedImportsWithAuditToleratePartialArguments(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if _, err := store.ImportVulnCheckWithAudit(ctx, "vulncheck", nil, nil, nil); err != nil {
		t.Fatalf("ImportVulnCheckWithAudit(nil, nil) error = %v", err)
	}
	if _, err := store.ImportCISAKEVWithAudit(ctx, "cisakev", nil, nil, nil); err != nil {
		t.Fatalf("ImportCISAKEVWithAudit(nil, nil) error = %v", err)
	}
	if _, _, err := store.ReplaceCISAKEVWithAudit(ctx, "cisakev", nil, nil, nil); err != nil {
		t.Fatalf("ReplaceCISAKEVWithAudit(nil, nil) error = %v", err)
	}
	if _, _, err := store.ImportEPSSWithAudit(ctx, "epss", nil, nil, nil); err != nil {
		t.Fatalf("ImportEPSSWithAudit(nil, nil) error = %v", err)
	}

	entries, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ListAdminAuditLog() = %+v, want no entries without an audit callback", entries)
	}
}
