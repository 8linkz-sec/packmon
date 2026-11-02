package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestReadLocalFeedStateFailureAndNormalization(t *testing.T) {
	t.Run("closed store", func(t *testing.T) {
		store, _ := newTestSQLiteStore(t, t.TempDir())
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}

		status, versions, err := readLocalFeedState(context.Background(), store)
		if err == nil || !strings.Contains(err.Error(), "read local feed status") {
			t.Fatalf("readLocalFeedState() error = %v, want feed-status read context", err)
		}
		if status != "" || versions != nil {
			t.Fatalf("readLocalFeedState() = (%q, %#v), want zero values on error", status, versions)
		}
	})

	t.Run("blank status ignores malformed versions", func(t *testing.T) {
		store, _ := newTestSQLiteStore(t, t.TempDir())
		if err := store.SetSyncMeta(context.Background(), localDBSyncMetaFeedStatus, " \t "); err != nil {
			t.Fatalf("set feed status: %v", err)
		}
		if err := store.SetSyncMeta(context.Background(), localDBSyncMetaFeedVersions, "{"); err != nil {
			t.Fatalf("set malformed feed versions: %v", err)
		}

		status, versions, err := readLocalFeedState(context.Background(), store)
		if err != nil {
			t.Fatalf("readLocalFeedState() error = %v", err)
		}
		if status != "" || versions != nil {
			t.Fatalf("readLocalFeedState() = (%q, %#v), want blank status and nil versions", status, versions)
		}
	})

	t.Run("null versions column fails deterministically", func(t *testing.T) {
		store, _ := newTestSQLiteStore(t, t.TempDir())
		if _, err := store.DB().ExecContext(context.Background(), `
			DROP TABLE sync_meta;
			CREATE TABLE sync_meta (key TEXT PRIMARY KEY, value TEXT);
			INSERT INTO sync_meta(key, value) VALUES ('feed_status', ' healthy '), ('feed_versions', NULL);`); err != nil {
			t.Fatalf("replace sync_meta with nullable fixture: %v", err)
		}

		status, versions, err := readLocalFeedState(context.Background(), store)
		if err == nil || !strings.Contains(err.Error(), "read local feed versions") {
			t.Fatalf("readLocalFeedState() error = %v, want feed-versions read context", err)
		}
		if status != "" || versions != nil {
			t.Fatalf("readLocalFeedState() = (%q, %#v), want zero values on error", status, versions)
		}
	})

	t.Run("malformed versions", func(t *testing.T) {
		store, _ := newTestSQLiteStore(t, t.TempDir())
		if err := store.SetSyncMeta(context.Background(), localDBSyncMetaFeedStatus, " degraded "); err != nil {
			t.Fatalf("set feed status: %v", err)
		}
		if err := store.SetSyncMeta(context.Background(), localDBSyncMetaFeedVersions, "{"); err != nil {
			t.Fatalf("set malformed feed versions: %v", err)
		}

		status, versions, err := readLocalFeedState(context.Background(), store)
		if err == nil || !strings.Contains(err.Error(), "parse local feed versions") {
			t.Fatalf("readLocalFeedState() error = %v, want feed-versions parse context", err)
		}
		if status != "" || versions != nil {
			t.Fatalf("readLocalFeedState() = (%q, %#v), want zero values on error", status, versions)
		}
	})

	for _, tt := range []struct {
		name        string
		versions    string
		seedVersion bool
	}{
		{name: "json null", versions: "null", seedVersion: true},
		{name: "absent versions"},
		{name: "blank versions", versions: " \t ", seedVersion: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestSQLiteStore(t, t.TempDir())
			if err := store.SetSyncMeta(context.Background(), localDBSyncMetaFeedStatus, " healthy "); err != nil {
				t.Fatalf("set feed status: %v", err)
			}
			if tt.seedVersion {
				if err := store.SetSyncMeta(context.Background(), localDBSyncMetaFeedVersions, tt.versions); err != nil {
					t.Fatalf("set feed versions: %v", err)
				}
			}

			status, versions, err := readLocalFeedState(context.Background(), store)
			if err != nil {
				t.Fatalf("readLocalFeedState() error = %v", err)
			}
			if status != "healthy" {
				t.Fatalf("status = %q, want trimmed healthy", status)
			}
			if versions == nil || len(versions) != 0 {
				t.Fatalf("versions = %#v, want a non-nil empty map", versions)
			}
		})
	}
}

func TestApplyLocalDBFreshnessPropagatesMalformedFeedState(t *testing.T) {
	t.Setenv("PACKMON_DB_WARN_AFTER_DAYS", "1")
	store, _ := newTestSQLiteStore(t, t.TempDir())
	ctx := context.Background()
	if err := store.SetSyncMeta(ctx, "last_sync_at", time.Now().UTC().Add(-72*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("set last sync: %v", err)
	}
	if err := store.SetSyncMeta(ctx, localDBSyncMetaFeedStatus, "degraded"); err != nil {
		t.Fatalf("set feed status: %v", err)
	}
	if err := store.SetSyncMeta(ctx, localDBSyncMetaFeedVersions, "{"); err != nil {
		t.Fatalf("set malformed feed versions: %v", err)
	}

	wantVersions := map[string]string{"sentinel": "unchanged"}
	result := &domain.ScanResult{
		Mode:         domain.ScanModeLocal,
		FeedStatus:   "sentinel-status",
		FeedVersions: wantVersions,
	}
	err := applyLocalDBFreshness(ctx, store, result)
	if err == nil || !strings.Contains(err.Error(), "parse local feed versions") {
		t.Fatalf("applyLocalDBFreshness() error = %v, want malformed feed-state error", err)
	}
	if result.DBAgeDays == nil || *result.DBAgeDays < 2 {
		t.Fatalf("DBAgeDays = %v, want the already-computed stale age", result.DBAgeDays)
	}
	if !result.DBStale {
		t.Fatal("DBStale = false, want true before feed-state parsing")
	}
	if result.FeedStatus != "sentinel-status" {
		t.Fatalf("FeedStatus = %q, want unchanged sentinel", result.FeedStatus)
	}
	if len(result.FeedVersions) != 1 || result.FeedVersions["sentinel"] != "unchanged" {
		t.Fatalf("FeedVersions = %#v, want unchanged sentinel map", result.FeedVersions)
	}
}

func TestReadLocalSyncAgeDeterministicallyClampsFarFutureTimestamp(t *testing.T) {
	for _, tt := range []struct {
		name   string
		offset time.Duration
	}{
		{name: "far future", offset: 72 * time.Hour},
		{name: "less than one day", offset: 23 * time.Hour},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestSQLiteStore(t, t.TempDir())
			future := time.Now().UTC().Add(tt.offset).Truncate(time.Second)
			if err := store.SetSyncMeta(context.Background(), "last_sync_at", future.Format(time.RFC3339)); err != nil {
				t.Fatalf("set future sync timestamp: %v", err)
			}

			gotTimestamp, gotAge, err := readLocalSyncAge(context.Background(), store)
			if err != nil {
				t.Fatalf("readLocalSyncAge() error = %v", err)
			}
			if gotTimestamp == nil || !gotTimestamp.Equal(future) {
				t.Fatalf("timestamp = %v, want %v", gotTimestamp, future)
			}
			if gotAge == nil || *gotAge != 0 {
				t.Fatalf("age = %v, want zero", gotAge)
			}
		})
	}
}

func TestExportLocalDBAlwaysUsesBasenameWithoutMutatingStorePath(t *testing.T) {
	nested := filepath.Join(t.TempDir(), "private", "nested")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatalf("create nested database directory: %v", err)
	}
	store, originalPath := newTestSQLiteStore(t, nested)

	var output bytes.Buffer
	if err := exportLocalDB(context.Background(), store, &output); err != nil {
		t.Fatalf("exportLocalDB() error = %v", err)
	}
	var payload localDBExport
	if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
		t.Fatalf("decode export: %v\n%s", err, output.String())
	}
	if payload.Info == nil {
		t.Fatal("export info = nil")
	}
	wantBase := filepath.Base(originalPath)
	if payload.Info.Path != wantBase || filepath.Base(payload.Info.Path) != payload.Info.Path || filepath.Dir(payload.Info.Path) != "." {
		t.Fatalf("export path = %q, want basename %q without a directory component", payload.Info.Path, wantBase)
	}
	if store.Path() != originalPath {
		t.Fatalf("store path = %q, want unchanged %q", store.Path(), originalPath)
	}
}
