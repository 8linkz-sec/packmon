//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF215SystemSettingsStateAuditAndRollbackAgainstPostgres(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if got, err := store.GetSystemSettings(ctx); err != nil || got != nil {
		t.Fatalf("GetSystemSettings(empty) = %+v, %v; want nil, nil", got, err)
	}

	if _, err := store.pool.Exec(ctx, `INSERT INTO system_settings DEFAULT VALUES`); err != nil {
		t.Fatalf("insert default system settings: %v", err)
	}
	defaults, err := store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings(defaults) error = %v", err)
	}
	f215RequireSystemSettings(t, defaults, "CRITICAL", 60, 60, 30*24*time.Hour, 30*24*time.Hour)
	if defaults.UpdatedAt.IsZero() || defaults.ExpectedUpdatedAt != nil {
		t.Fatalf("default timestamps = updated:%v expected:%v, want nonzero/nil", defaults.UpdatedAt, defaults.ExpectedUpdatedAt)
	}

	if _, err := store.pool.Exec(ctx, `ALTER TABLE system_settings ALTER COLUMN updated_at DROP NOT NULL`); err != nil {
		t.Fatalf("make updated_at nullable for scan fault: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE system_settings SET updated_at = NULL WHERE id = 1`); err != nil {
		t.Fatalf("seed nullable updated_at scan fault: %v", err)
	}
	if got, err := store.GetSystemSettings(ctx); err == nil || got != nil || !strings.Contains(err.Error(), "postgres: get system settings") {
		t.Fatalf("GetSystemSettings(nullable updated_at) = %+v, %v; want nil wrapped scan error", got, err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE system_settings SET updated_at = NOW() WHERE id = 1`); err != nil {
		t.Fatalf("restore updated_at value: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `ALTER TABLE system_settings ALTER COLUMN updated_at SET NOT NULL`); err != nil {
		t.Fatalf("restore updated_at nullability: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `DELETE FROM system_settings`); err != nil {
		t.Fatalf("remove default system settings: %v", err)
	}
	direct := &db.SystemSettings{
		BlockThreshold:      "LOW",
		RateLimitPerMinute:  75,
		RateLimitBurst:      15,
		ScanLogRetention:    2 * time.Hour,
		AdminAuditRetention: 3 * time.Hour,
	}
	if err := store.UpsertSystemSettings(ctx, direct); err != nil {
		t.Fatalf("UpsertSystemSettings() error = %v", err)
	}
	directLoaded, err := store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings(direct) error = %v", err)
	}
	f215RequireSystemSettings(t, directLoaded, "LOW", 75, 15, 2*time.Hour, 3*time.Hour)
	if _, err := store.pool.Exec(ctx, `DELETE FROM system_settings`); err != nil {
		t.Fatalf("remove direct system settings: %v", err)
	}

	zeroRevision := time.Time{}
	initialDetails := json.RawMessage(`{"previous":"unset","new":"HIGH","scan_retention":"0"}`)
	initial := &db.SystemSettings{
		BlockThreshold:      "HIGH",
		RateLimitPerMinute:  120,
		RateLimitBurst:      30,
		ScanLogRetention:    0,
		AdminAuditRetention: 45 * 24 * time.Hour,
		ExpectedUpdatedAt:   &zeroRevision,
	}
	initialAudit := &db.AdminAuditEntry{
		Action:        "f215_settings_initial",
		Details:       initialDetails,
		IP:            "127.0.0.215",
		CorrelationID: "f215-initial",
	}
	if err := store.UpsertSystemSettingsWithAudit(ctx, initial, initialAudit); err != nil {
		t.Fatalf("UpsertSystemSettingsWithAudit(initial) error = %v", err)
	}
	current, err := store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings(initial) error = %v", err)
	}
	f215RequireSystemSettings(t, current, "HIGH", 120, 30, 0, 45*24*time.Hour)
	if current.UpdatedAt.IsZero() || current.ExpectedUpdatedAt != nil {
		t.Fatalf("initial timestamps = updated:%v expected:%v, want committed revision/nil", current.UpdatedAt, current.ExpectedUpdatedAt)
	}
	f215RequireLatestSettingsAudit(t, store, ctx, *initialAudit, map[string]string{
		"previous":       "unset",
		"new":            "HIGH",
		"scan_retention": "0",
	})

	committed := *current
	committedRevision := current.UpdatedAt
	staleRevision := committedRevision.Add(-time.Microsecond)
	stale := db.SystemSettings{
		BlockThreshold:      "LOW",
		RateLimitPerMinute:  10,
		RateLimitBurst:      5,
		ScanLogRetention:    time.Hour,
		AdminAuditRetention: 2 * time.Hour,
		ExpectedUpdatedAt:   &staleRevision,
	}
	if err := store.UpsertSystemSettingsWithAudit(ctx, &stale, &db.AdminAuditEntry{Action: "f215_settings_stale", IP: "127.0.0.1"}); !errors.Is(err, db.ErrConflict) {
		t.Fatalf("UpsertSystemSettingsWithAudit(stale) error = %v, want ErrConflict", err)
	}
	f215RequireCommittedSettingsAndAuditCount(t, store, ctx, &committed, 1)

	for _, tc := range []struct {
		name  string
		audit *db.AdminAuditEntry
	}{
		{name: "nil audit", audit: nil},
		{name: "anonymous audit", audit: &db.AdminAuditEntry{IP: "127.0.0.1"}},
		{name: "malformed details", audit: &db.AdminAuditEntry{Action: "f215_settings_malformed", Details: json.RawMessage(`{"broken"`), IP: "127.0.0.1"}},
		{name: "invalid audit IP", audit: &db.AdminAuditEntry{Action: "f215_settings_bad_ip", Details: json.RawMessage(`{"kind":"failure"}`), IP: "not-an-ip"}},
	} {
		t.Run(tc.name+" rolls back settings", func(t *testing.T) {
			candidate := stale
			candidate.ExpectedUpdatedAt = &committedRevision
			err := store.UpsertSystemSettingsWithAudit(ctx, &candidate, tc.audit)
			if !errors.Is(err, db.ErrAdminAuditLog) {
				t.Fatalf("UpsertSystemSettingsWithAudit(%s) error = %v, want ErrAdminAuditLog", tc.name, err)
			}
			f215RequireCommittedSettingsAndAuditCount(t, store, ctx, &committed, 1)
		})
	}

	matched := db.SystemSettings{
		BlockThreshold:      "MEDIUM",
		RateLimitPerMinute:  180,
		RateLimitBurst:      45,
		ScanLogRetention:    7 * 24 * time.Hour,
		AdminAuditRetention: 14 * 24 * time.Hour,
		ExpectedUpdatedAt:   &committedRevision,
	}
	matchedAudit := &db.AdminAuditEntry{
		Action:        "f215_settings_update",
		Details:       json.RawMessage(`{"previous":"HIGH","new":"MEDIUM"}`),
		IP:            "2001:db8::215",
		CorrelationID: "f215-update",
	}
	if err := store.UpsertSystemSettingsWithAudit(ctx, &matched, matchedAudit); err != nil {
		t.Fatalf("UpsertSystemSettingsWithAudit(matched) error = %v", err)
	}
	current, err = store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings(matched) error = %v", err)
	}
	f215RequireSystemSettings(t, current, "MEDIUM", 180, 45, 7*24*time.Hour, 14*24*time.Hour)
	f215RequireLatestSettingsAudit(t, store, ctx, *matchedAudit, map[string]string{"previous": "HIGH", "new": "MEDIUM"})
	if got := f215SystemSettingsAuditCount(t, store, ctx); got != 2 {
		t.Fatalf("audit count after matched save = %d, want 2", got)
	}

	committed = *current
	committedRevision = current.UpdatedAt
	if _, err := store.pool.Exec(ctx, `CREATE TABLE f215_allowed_threshold (value TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("create deferred commit-fault target: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO f215_allowed_threshold (value) VALUES ($1)`, committed.BlockThreshold); err != nil {
		t.Fatalf("seed deferred commit-fault target: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		ALTER TABLE system_settings
		ADD CONSTRAINT f215_settings_commit_failure
		FOREIGN KEY (block_threshold) REFERENCES f215_allowed_threshold(value)
		DEFERRABLE INITIALLY DEFERRED`); err != nil {
		t.Fatalf("install deferred commit fault: %v", err)
	}
	commitFailure := db.SystemSettings{
		BlockThreshold:      "CRITICAL",
		RateLimitPerMinute:  999,
		RateLimitBurst:      99,
		ScanLogRetention:    time.Hour,
		AdminAuditRetention: time.Hour,
		ExpectedUpdatedAt:   &committedRevision,
	}
	err = store.UpsertSystemSettingsWithAudit(ctx, &commitFailure, &db.AdminAuditEntry{
		Action:  "f215_settings_commit_failure",
		Details: json.RawMessage(`{"must":"roll back"}`),
		IP:      "127.0.0.1",
	})
	if err == nil || !strings.Contains(err.Error(), "commit tx") {
		t.Fatalf("UpsertSystemSettingsWithAudit(commit failure) error = %v, want wrapped commit failure", err)
	}
	f215RequireCommittedSettingsAndAuditCount(t, store, ctx, &committed, 2)

	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got, err := store.GetSystemSettings(ctx); err == nil || got != nil || !strings.Contains(err.Error(), "postgres: get system settings") {
		t.Fatalf("GetSystemSettings(closed) = %+v, %v; want nil wrapped query failure", got, err)
	}
	if err := store.UpsertSystemSettingsWithAudit(ctx, &commitFailure, &db.AdminAuditEntry{Action: "f215_closed"}); err == nil || !strings.Contains(err.Error(), "begin tx") {
		t.Fatalf("UpsertSystemSettingsWithAudit(closed) error = %v, want begin failure", err)
	}
}

func f215RequireSystemSettings(t *testing.T, got *db.SystemSettings, threshold string, perMinute, burst int, scanRetention, auditRetention time.Duration) {
	t.Helper()
	if got == nil || got.BlockThreshold != threshold || got.RateLimitPerMinute != perMinute || got.RateLimitBurst != burst ||
		got.ScanLogRetention != scanRetention || got.AdminAuditRetention != auditRetention {
		t.Fatalf("system settings = %+v, want threshold=%s rate=%d/%d retention=%s/%s", got, threshold, perMinute, burst, scanRetention, auditRetention)
	}
}

func f215RequireLatestSettingsAudit(t *testing.T, store *Store, ctx context.Context, want db.AdminAuditEntry, wantDetails map[string]string) {
	t.Helper()
	entries, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil || len(entries) != 1 {
		t.Fatalf("ListAdminAuditLog() = %+v, %v; want one row", entries, err)
	}
	got := entries[0]
	details := map[string]string{}
	if err := json.Unmarshal(got.Details, &details); err != nil {
		t.Fatalf("decode settings audit details: %v", err)
	}
	if got.Action != want.Action || !reflect.DeepEqual(details, wantDetails) || got.CorrelationID != want.CorrelationID ||
		got.CreatedAt.IsZero() || got.RowDigest == "" || got.IntegrityStatus != db.AdminAuditIntegrityVerified || !strings.HasPrefix(got.IP, strings.TrimSuffix(want.IP, "/128")) {
		t.Fatalf("settings audit = %+v details=%#v, want action=%q details=%#v correlation=%q verified", got, details, want.Action, wantDetails, want.CorrelationID)
	}
}

func f215RequireCommittedSettingsAndAuditCount(t *testing.T, store *Store, ctx context.Context, want *db.SystemSettings, wantAudits int) {
	t.Helper()
	got, err := store.GetSystemSettings(ctx)
	if err != nil {
		t.Fatalf("GetSystemSettings(after failed save) error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settings after failed save = %+v, want committed %+v", got, want)
	}
	if gotAudits := f215SystemSettingsAuditCount(t, store, ctx); gotAudits != wantAudits {
		t.Fatalf("audit count after failed save = %d, want %d", gotAudits, wantAudits)
	}
}

func f215SystemSettingsAuditCount(t *testing.T, store *Store, ctx context.Context) int {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM admin_audit_log`).Scan(&count); err != nil {
		t.Fatalf("count settings audit rows: %v", err)
	}
	return count
}
