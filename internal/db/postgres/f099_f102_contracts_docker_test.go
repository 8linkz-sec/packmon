//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestF099F102PostgresContracts(t *testing.T) {
	store, dsn := startDockerPostgresStore(t)
	ctx := context.Background()

	t.Run("admin auth lifecycle and stale CAS", func(t *testing.T) {
		f099ResetContractTables(t, store)
		if got, err := store.GetAdminAuth(ctx); err != nil || got != nil {
			t.Fatalf("GetAdminAuth(empty) = %+v, %v; want nil, nil", got, err)
		}

		if err := store.UpsertAdminAuthWithAudit(ctx, "bootstrap-hash", true, &db.AdminAuditEntry{Action: "password_bootstrap", CorrelationID: "corr-bootstrap"}); err != nil {
			t.Fatalf("UpsertAdminAuthWithAudit(bootstrap) error = %v", err)
		}
		initial, err := store.GetAdminAuth(ctx)
		if err != nil || initial == nil || initial.PasswordHash != "bootstrap-hash" || !initial.PasswordIsBootstrap || initial.PasswordChangedAt != nil || initial.LastLoginAt != nil || initial.CreatedAt.IsZero() {
			t.Fatalf("GetAdminAuth(bootstrap) = %+v, %v", initial, err)
		}

		audit := &db.AdminAuditEntry{Action: "password_change", Details: json.RawMessage(`{"phase":"rotate"}`), IP: "2001:db8::99", CorrelationID: "corr-auth-lifecycle"}
		if err := store.ChangeAdminPasswordWithAudit(ctx, "rotated-hash", "bootstrap-hash", audit); err != nil {
			t.Fatalf("ChangeAdminPasswordWithAudit() error = %v", err)
		}
		rotated, err := store.GetAdminAuth(ctx)
		if err != nil || rotated == nil || rotated.PasswordHash != "rotated-hash" || rotated.PasswordIsBootstrap || rotated.PasswordChangedAt == nil || rotated.PasswordChangedAt.Before(initial.CreatedAt) {
			t.Fatalf("GetAdminAuth(rotated) = %+v, %v", rotated, err)
		}
		if err := store.ChangeAdminPasswordWithAudit(ctx, "stale-write", "bootstrap-hash", &db.AdminAuditEntry{Action: "password_change"}); !errors.Is(err, db.ErrAdminAuthConflict) {
			t.Fatalf("stale ChangeAdminPasswordWithAudit() = %v, want ErrAdminAuthConflict", err)
		}
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "login_success", Details: json.RawMessage(`{"result":"ok"}`), IP: "2001:db8::100", CorrelationID: "corr-login"}); err != nil {
			t.Fatalf("InsertAdminAuditLog(login_success) error = %v", err)
		}
		loggedIn, err := store.GetAdminAuth(ctx)
		if err != nil || loggedIn == nil || loggedIn.LastLoginAt == nil || loggedIn.LastLoginAt.Before(*rotated.PasswordChangedAt) {
			t.Fatalf("GetAdminAuth(after login) = %+v, %v", loggedIn, err)
		}
		audits, err := store.ListAdminAuditLog(ctx, 10)
		if err != nil || len(audits) != 3 || audits[0].Action != "login_success" || audits[1].Action != "password_change" || audits[2].Action != "password_bootstrap" {
			t.Fatalf("ListAdminAuditLog() = %+v, %v", audits, err)
		}
	})

	t.Run("concurrent auth and audit writers serialize", func(t *testing.T) {
		f099ResetContractTables(t, store)
		if err := store.UpsertAdminAuth(ctx, "shared-old", false); err != nil {
			t.Fatalf("seed admin auth: %v", err)
		}

		results := f099RunBounded(t, []func(context.Context) error{
			func(runCtx context.Context) error {
				return store.ChangeAdminPasswordWithAudit(runCtx, "winner-a", "shared-old", &db.AdminAuditEntry{Action: "password_change", CorrelationID: "corr-winner-a"})
			},
			func(runCtx context.Context) error {
				return store.ChangeAdminPasswordWithAudit(runCtx, "winner-b", "shared-old", &db.AdminAuditEntry{Action: "password_change", CorrelationID: "corr-winner-b"})
			},
		})
		successes, conflicts := 0, 0
		for _, err := range results {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, db.ErrAdminAuthConflict):
				conflicts++
			default:
				t.Fatalf("concurrent password result = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("password results successes=%d conflicts=%d, want 1/1", successes, conflicts)
		}

		writers := make([]func(context.Context) error, 8)
		for i := range writers {
			i := i
			writers[i] = func(runCtx context.Context) error {
				return store.InsertAdminAuditLog(runCtx, &db.AdminAuditEntry{Action: fmt.Sprintf("concurrent_%02d", i), CorrelationID: fmt.Sprintf("corr-%02d", i)})
			}
		}
		for i, err := range f099RunBounded(t, writers) {
			if err != nil {
				t.Fatalf("concurrent audit writer %d error = %v", i, err)
			}
		}
		audits, err := store.ListAdminAuditLog(ctx, 20)
		if err != nil || len(audits) != 9 {
			t.Fatalf("ListAdminAuditLog() len=%d, error=%v; want 9", len(audits), err)
		}
		for i := range audits {
			if audits[i].IntegrityStatus != db.AdminAuditIntegrityVerified {
				t.Fatalf("audit[%d] integrity = %q, row=%+v", i, audits[i].IntegrityStatus, audits[i])
			}
		}
	})

	t.Run("audit pagination HMAC and pruning", func(t *testing.T) {
		f099ResetContractTables(t, store)
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO admin_audit_log(action, created_at) VALUES
				('tie_oldest', '2026-01-01T00:00:00Z'),
				('tie_middle', '2026-01-01T00:00:00Z'),
				('tie_newest', '2026-01-01T00:00:00Z')`); err != nil {
			t.Fatalf("seed tied audit rows: %v", err)
		}
		tied, err := store.ListAdminAuditLogPage(ctx, 3, 0)
		if err != nil || len(tied) != 3 || tied[0].Action != "tie_newest" || tied[1].Action != "tie_middle" || tied[2].Action != "tie_oldest" {
			t.Fatalf("tied audit order = %+v, %v", tied, err)
		}
		if _, err := store.pool.Exec(ctx, `DELETE FROM admin_audit_log`); err != nil {
			t.Fatalf("clear tied audit rows: %v", err)
		}
		db.SetAdminAuditDigestHMACKey([]byte("0123456789abcdef0123456789abcdef"))
		defer db.ClearAdminAuditDigestHMACKey()
		if pruned, err := store.PruneAdminAuditLogs(ctx, 0); err != nil || pruned != 0 {
			t.Fatalf("PruneAdminAuditLogs(nonpositive) = %d, %v; want 0, nil", pruned, err)
		}
		for i := 0; i < 205; i++ {
			entry := &db.AdminAuditEntry{
				Action:        fmt.Sprintf("paged_%03d", i),
				Details:       json.RawMessage(fmt.Sprintf(`{"ordinal":"%03d"}`, i)),
				IP:            "2001:db8::101",
				CorrelationID: fmt.Sprintf("corr-page-%03d", i),
			}
			if err := store.InsertAdminAuditLog(ctx, entry); err != nil {
				t.Fatalf("InsertAdminAuditLog(%d) error = %v", i, err)
			}
		}
		first, err := store.ListAdminAuditLogPage(ctx, 3, -9)
		if err != nil || len(first) != 3 || first[0].Action != "paged_204" || first[2].Action != "paged_202" {
			t.Fatalf("first audit page = %+v, %v", first, err)
		}
		for _, entry := range first {
			if entry.IntegrityStatus != db.AdminAuditIntegrityVerified || !strings.HasPrefix(entry.RowDigest, "hmac-sha256:") || !strings.HasPrefix(entry.IP, "2001:db8::101") || entry.CorrelationID == "" || len(entry.Details) == 0 {
				t.Fatalf("audit round trip = %+v", entry)
			}
		}
		zeroOffset, err := store.ListAdminAuditLogPage(ctx, 3, 0)
		if err != nil || !f099SameAuditIDs(first, zeroOffset) {
			t.Fatalf("negative audit offset page = %+v, zero page = %+v, error=%v", first, zeroOffset, err)
		}
		defaultPage, err := store.ListAdminAuditLogPage(ctx, 0, 0)
		if err != nil || len(defaultPage) != 100 {
			t.Fatalf("default audit page len=%d, error=%v; want 100", len(defaultPage), err)
		}
		maxPage, err := store.ListAdminAuditLogPage(ctx, 999, 0)
		if err != nil || len(maxPage) != 200 {
			t.Fatalf("max audit page len=%d, error=%v; want 200", len(maxPage), err)
		}
		last, err := store.ListAdminAuditLogPage(ctx, 10, 203)
		if err != nil || len(last) != 2 || last[0].Action != "paged_001" || last[1].Action != "paged_000" {
			t.Fatalf("last audit page = %+v, %v", last, err)
		}
		exhausted, err := store.ListAdminAuditLogPage(ctx, 10, 205)
		if err != nil || len(exhausted) != 0 {
			t.Fatalf("exhausted audit page = %+v, %v", exhausted, err)
		}
		pruned, err := store.PruneAdminAuditLogs(ctx, time.Nanosecond)
		if err != nil || pruned != 205 {
			t.Fatalf("PruneAdminAuditLogs() = %d, %v; want 205, nil", pruned, err)
		}
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "post_prune", CorrelationID: "corr-post-prune"}); err != nil {
			t.Fatalf("InsertAdminAuditLog(post prune) error = %v", err)
		}
		post, err := store.ListAdminAuditLog(ctx, 1)
		if err != nil || len(post) != 1 || post[0].PreviousDigest != "" || post[0].IntegrityStatus != db.AdminAuditIntegrityVerified {
			t.Fatalf("post-prune chain = %+v, %v", post, err)
		}
	})

	t.Run("late audit failure rolls back auth mutation", func(t *testing.T) {
		f099ResetContractTables(t, store)
		if err := store.UpsertAdminAuth(ctx, "before-trigger", false); err != nil {
			t.Fatalf("seed auth: %v", err)
		}
		locker, err := store.pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire audit table locker: %v", err)
		}
		lockTx, err := locker.Begin(ctx)
		if err != nil {
			locker.Release()
			t.Fatalf("begin audit table locker: %v", err)
		}
		if _, err := lockTx.Exec(ctx, `LOCK TABLE admin_audit_log IN ACCESS EXCLUSIVE MODE`); err != nil {
			_ = lockTx.Rollback(ctx)
			locker.Release()
			t.Fatalf("lock admin audit table: %v", err)
		}
		lockCtx, cancelLock := context.WithTimeout(ctx, 100*time.Millisecond)
		lockErr := store.InsertAdminAuditLog(lockCtx, &db.AdminAuditEntry{Action: "blocked_table_lock"})
		cancelLock()
		if err := lockTx.Rollback(ctx); err != nil {
			locker.Release()
			t.Fatalf("rollback audit table locker: %v", err)
		}
		locker.Release()
		if lockErr == nil || !strings.Contains(lockErr.Error(), "lock admin audit log") {
			t.Fatalf("InsertAdminAuditLog(blocked table lock) = %v, want lock error", lockErr)
		}
		restore := f099InstallRejectingTrigger(t, store, "f099_reject_audit", "admin_audit_log")
		defer restore()
		err = store.ChangeAdminPasswordWithAudit(ctx, "must-rollback", "before-trigger", &db.AdminAuditEntry{Action: "password_change"})
		if !errors.Is(err, db.ErrAdminAuditLog) {
			t.Fatalf("ChangeAdminPasswordWithAudit(trigger) = %v, want ErrAdminAuditLog", err)
		}
		authInfo, getErr := store.GetAdminAuth(ctx)
		if getErr != nil || authInfo == nil || authInfo.PasswordHash != "before-trigger" {
			t.Fatalf("auth after rollback = %+v, %v", authInfo, getErr)
		}
		restore()
	})

	t.Run("audit listing discards a partial scan", func(t *testing.T) {
		f099ResetContractTables(t, store)
		if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{Action: "valid_before_null"}); err != nil {
			t.Fatalf("seed valid audit: %v", err)
		}
		restore := f099MakeColumnNullable(t, store, "admin_audit_log", "action", `DELETE FROM admin_audit_log WHERE action IS NULL`)
		defer restore()
		if _, err := store.pool.Exec(ctx, `INSERT INTO admin_audit_log(action, created_at) VALUES (NULL, NOW() + INTERVAL '1 second')`); err != nil {
			t.Fatalf("insert nullable audit row: %v", err)
		}
		rows, err := store.ListAdminAuditLog(ctx, 10)
		if err == nil || rows != nil || !strings.Contains(err.Error(), "scan admin audit row") {
			t.Fatalf("ListAdminAuditLog(nullable action) = %+v, %v; want nil scan error", rows, err)
		}
		restore()
		if _, err := store.pool.Exec(ctx, `DELETE FROM admin_audit_log`); err != nil {
			t.Fatalf("clear audit scan fixture: %v", err)
		}
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO admin_audit_log(action, created_at) VALUES
				('iteration_valid', NOW() + INTERVAL '2 seconds'),
				('iteration_fault', NOW() + INTERVAL '1 second')`); err != nil {
			t.Fatalf("seed audit iteration fixture: %v", err)
		}
		restoreView := f099SwapTableForFaultView(t, store, "admin_audit_log", "admin_audit_log_f099_base",
			[]string{`DROP FUNCTION IF EXISTS f099_fail_audit_text(text)`},
			`CREATE FUNCTION f099_fail_audit_text(value text) RETURNS text LANGUAGE plpgsql STABLE AS $$ BEGIN RAISE EXCEPTION 'forced audit iteration failure'; END $$`,
			`CREATE VIEW admin_audit_log AS
			 SELECT id,
				CASE WHEN action = 'iteration_fault' THEN f099_fail_audit_text(action) ELSE action END AS action,
				details, ip, correlation_id, created_at, previous_digest, row_digest
			 FROM admin_audit_log_f099_base`,
		)
		defer restoreView()
		rows, err = store.ListAdminAuditLog(ctx, 10)
		if err == nil || rows != nil || !strings.Contains(err.Error(), "iterate admin audit log") {
			t.Fatalf("ListAdminAuditLog(iteration fault) = %+v, %v; want nil iteration error", rows, err)
		}
		restoreView()
	})

	t.Run("API key lifecycle is audited and rolls back", func(t *testing.T) {
		f099ResetContractTables(t, store)
		keyID, err := store.CreateAPIKeyWithAudit(ctx, "ci-contract", "hash-contract", nil, &db.AdminAuditEntry{Action: "api_key_create", Details: json.RawMessage(`{"name":"ci-contract"}`)})
		if err != nil || keyID == 0 {
			t.Fatalf("CreateAPIKeyWithAudit() = %d, %v", keyID, err)
		}
		if _, err := store.CreateAPIKeyWithAudit(ctx, "duplicate", "hash-contract", nil, &db.AdminAuditEntry{Action: "api_key_create"}); err == nil {
			t.Fatal("duplicate CreateAPIKeyWithAudit() error = nil")
		}
		if _, err := store.CreateAPIKeyWithAudit(ctx, "bad-details", "hash-bad-details", nil, &db.AdminAuditEntry{Action: "api_key_create", Details: json.RawMessage(`{`)}); err == nil {
			t.Fatal("malformed-details CreateAPIKeyWithAudit() error = nil")
		}
		if got, err := store.FindAPIKeyByHash(ctx, "hash-bad-details"); err != nil || got != nil {
			t.Fatalf("malformed-details key = %+v, %v; want rollback", got, err)
		}
		if err := store.RevokeAPIKeyWithAudit(ctx, keyID, &db.AdminAuditEntry{Action: "api_key_revoke"}); err != nil {
			t.Fatalf("RevokeAPIKeyWithAudit() error = %v", err)
		}
		if err := store.RevokeAPIKeyWithAudit(ctx, keyID, &db.AdminAuditEntry{Action: "api_key_revoke"}); err == nil {
			t.Fatal("repeated RevokeAPIKeyWithAudit() error = nil")
		}
		if err := store.DeleteAPIKeyWithAudit(ctx, keyID, &db.AdminAuditEntry{Action: "api_key_delete"}); err != nil {
			t.Fatalf("DeleteAPIKeyWithAudit() error = %v", err)
		}
		if err := store.DeleteAPIKeyWithAudit(ctx, keyID, &db.AdminAuditEntry{Action: "api_key_delete"}); err == nil {
			t.Fatal("repeated DeleteAPIKeyWithAudit() error = nil")
		}
		keys, err := store.ListAPIKeys(ctx)
		if err != nil || len(keys) != 0 {
			t.Fatalf("ListAPIKeys(after delete) = %+v, %v", keys, err)
		}
		plainID, err := store.CreateAPIKey(ctx, "plain-lifecycle", "hash-plain-lifecycle", nil)
		if err != nil || plainID == 0 {
			t.Fatalf("CreateAPIKey() = %d, %v", plainID, err)
		}
		if err := store.TouchAPIKeyLastUsed(ctx, plainID); err != nil {
			t.Fatalf("TouchAPIKeyLastUsed() error = %v", err)
		}
		plain, err := store.FindAPIKeyByHash(ctx, "hash-plain-lifecycle")
		if err != nil || plain == nil || plain.LastUsedAt == nil {
			t.Fatalf("FindAPIKeyByHash(plain) = %+v, %v", plain, err)
		}
		if err := store.RevokeAPIKey(ctx, plainID); err != nil {
			t.Fatalf("RevokeAPIKey() error = %v", err)
		}
		if err := store.DeleteAPIKey(ctx, plainID); err != nil {
			t.Fatalf("DeleteAPIKey() error = %v", err)
		}
		if keys, err := store.ListAPIKeys(ctx); err != nil || len(keys) != 0 {
			t.Fatalf("ListAPIKeys(after plain delete) = %+v, %v", keys, err)
		}
		audits, err := store.ListAdminAuditLog(ctx, 10)
		if err != nil || len(audits) != 3 || audits[0].Action != "api_key_delete" || audits[1].Action != "api_key_revoke" || audits[2].Action != "api_key_create" {
			t.Fatalf("API lifecycle audits = %+v, %v", audits, err)
		}
	})

	t.Run("API key pagination and inactive boundaries", func(t *testing.T) {
		f099ResetContractTables(t, store)
		restoreConstraint := f099RelaxDeletedRequiresRevoked(t, store)
		defer restoreConstraint()
		const seed = `
			INSERT INTO api_keys(name, key_hash, created_at, expires_at, revoked_at, deleted_at)
			VALUES
				('active-low', 'hash-active-low', '2026-01-01T00:00:00Z', NULL, NULL, NULL),
				('active-high', 'hash-active-high', '2026-01-01T00:00:00Z', NULL, NULL, NULL),
				('expired-boundary', 'hash-expired-boundary', NOW() - INTERVAL '1 day', NOW(), NULL, NULL),
				('deleted-only', 'hash-deleted-only', NOW() - INTERVAL '2 days', NULL, NULL, NOW())`
		if _, err := store.pool.Exec(ctx, seed); err != nil {
			t.Fatalf("seed API key boundaries: %v", err)
		}
		for _, hash := range []string{"hash-expired-boundary", "hash-deleted-only"} {
			if got, err := store.FindAPIKeyByHash(ctx, hash); err != nil || got != nil {
				t.Fatalf("FindAPIKeyByHash(%q) = %+v, %v; want inactive", hash, got, err)
			}
		}
		if got, err := store.FindAPIKeyByHash(ctx, "hash-active-high"); err != nil || got == nil || got.Name != "active-high" {
			t.Fatalf("FindAPIKeyByHash(active) = %+v, %v", got, err)
		}
		page, err := store.ListAPIKeysPage(ctx, 2, -4)
		if err != nil || len(page) != 2 || page[0].Name != "expired-boundary" || page[1].Name != "deleted-only" {
			t.Fatalf("ListAPIKeysPage(negative) = %+v, %v", page, err)
		}
		zeroPage, err := store.ListAPIKeysPage(ctx, 2, 0)
		if err != nil || !f099SameAPIKeyIDs(page, zeroPage) {
			t.Fatalf("negative API key offset page = %+v, zero page = %+v, error=%v", page, zeroPage, err)
		}
		allKeys, err := store.ListAPIKeysPage(ctx, 10, 0)
		if err != nil || len(allKeys) != 4 || allKeys[2].Name != "active-high" || allKeys[3].Name != "active-low" || allKeys[2].CreatedAt != allKeys[3].CreatedAt || allKeys[2].ID <= allKeys[3].ID {
			t.Fatalf("tied API key ordering = %+v, %v", allKeys, err)
		}
		if none, err := store.ListAPIKeysPage(ctx, 0, 0); err != nil || none != nil {
			t.Fatalf("ListAPIKeysPage(nonpositive) = %+v, %v; want nil, nil", none, err)
		}
		if none, err := store.ListAPIKeysPage(ctx, 2, 99); err != nil || len(none) != 0 {
			t.Fatalf("ListAPIKeysPage(exhausted) = %+v, %v", none, err)
		}
		restoreConstraint()
	})

	t.Run("API key listings discard partial rows", func(t *testing.T) {
		f099ResetContractTables(t, store)
		restore := f099MakeColumnNullable(t, store, "api_keys", "key_hash", `DELETE FROM api_keys WHERE key_hash IS NULL`)
		defer restore()
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO api_keys(name, key_hash, created_at) VALUES
			('valid-first', 'hash-valid-first', NOW() + INTERVAL '2 seconds'),
			('invalid-second', NULL, NOW() + INTERVAL '1 second')`); err != nil {
			t.Fatalf("seed nullable API keys: %v", err)
		}
		if rows, err := store.ListAPIKeys(ctx); err == nil || rows != nil || !strings.Contains(err.Error(), "scan API key row") {
			t.Fatalf("ListAPIKeys(nullable hash) = %+v, %v; want nil scan error", rows, err)
		}
		if rows, err := store.ListAPIKeysPage(ctx, 10, 0); err == nil || rows != nil || !strings.Contains(err.Error(), "scan API key page row") {
			t.Fatalf("ListAPIKeysPage(nullable hash) = %+v, %v; want nil scan error", rows, err)
		}
		restore()
		if _, err := store.pool.Exec(ctx, `DELETE FROM api_keys`); err != nil {
			t.Fatalf("clear API key scan fixtures: %v", err)
		}
		if _, err := store.pool.Exec(ctx, `
			INSERT INTO api_keys(name, key_hash, created_at) VALUES
				('iteration-valid', 'iteration-valid-hash', NOW() + INTERVAL '2 seconds'),
				('iteration-fault', 'iteration-fault-hash', NOW() + INTERVAL '1 second')`); err != nil {
			t.Fatalf("seed API key iteration fixture: %v", err)
		}
		restoreView := f099SwapTableForFaultView(t, store, "api_keys", "api_keys_f101_base",
			[]string{`DROP FUNCTION IF EXISTS f101_fail_key_text(text)`},
			`CREATE FUNCTION f101_fail_key_text(value text) RETURNS text LANGUAGE plpgsql STABLE AS $$ BEGIN RAISE EXCEPTION 'forced API key iteration failure'; END $$`,
			`CREATE VIEW api_keys AS
			 SELECT id, name,
				CASE WHEN name = 'iteration-fault' THEN f101_fail_key_text(key_hash) ELSE key_hash END AS key_hash,
				created_at, revoked_at, last_used_at, expires_at, deleted_at
			 FROM api_keys_f101_base`,
		)
		defer restoreView()
		if rows, err := store.ListAPIKeys(ctx); err == nil || rows != nil || !strings.Contains(err.Error(), "iterate API keys") {
			t.Fatalf("ListAPIKeys(iteration fault) = %+v, %v; want nil iteration error", rows, err)
		}
		if rows, err := store.ListAPIKeysPage(ctx, 10, 0); err == nil || rows != nil || !strings.Contains(err.Error(), "iterate API key page") {
			t.Fatalf("ListAPIKeysPage(iteration fault) = %+v, %v; want nil iteration error", rows, err)
		}
		restoreView()
	})

	t.Run("recent vulnerabilities defaults and selection", func(t *testing.T) {
		f102RecentVulnerabilityContracts(t, store)
	})

	t.Run("daily scan buckets stay UTC across sessions and DST", func(t *testing.T) {
		f102DailyScanContracts(t, store, dsn)
	})

	t.Run("dashboard categories and unknown severity are exact", func(t *testing.T) {
		f102DashboardCategoryContracts(t, store)
	})

	t.Run("dashboard defensive database outcomes", func(t *testing.T) {
		f102DashboardDefensiveContracts(t, store, dsn)
	})
}

func f099RunBounded(t *testing.T, work []func(context.Context) error) []error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, len(work))
	var workers sync.WaitGroup
	workers.Add(len(work))
	for _, fn := range work {
		fn := fn
		go func() {
			defer workers.Done()
			<-start
			results <- fn(ctx)
		}()
	}
	close(start)
	closed := make(chan struct{})
	go func() {
		workers.Wait()
		close(results)
		close(closed)
	}()
	out := make([]error, 0, len(work))
	for len(out) < len(work) {
		select {
		case err, ok := <-results:
			if ok {
				out = append(out, err)
			}
		case <-ctx.Done():
			cancel()
			select {
			case <-closed:
				for err := range results {
					out = append(out, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("concurrent PostgreSQL operations did not drain after deadline: %v", ctx.Err())
			}
			t.Fatalf("concurrent PostgreSQL operations exceeded 30 seconds: %v", ctx.Err())
		}
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent PostgreSQL operations produced results but workers did not finish")
	}
	for err := range results {
		out = append(out, err)
	}
	if len(out) != len(work) {
		t.Fatalf("concurrent PostgreSQL operations returned %d results, want %d", len(out), len(work))
	}
	return out
}

func f099SameAuditIDs(left, right []db.AdminAuditLogEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].ID != right[i].ID {
			return false
		}
	}
	return true
}

func f099SameAPIKeyIDs(left, right []db.APIKey) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].ID != right[i].ID {
			return false
		}
	}
	return true
}

func f099ResetContractTables(t *testing.T, store *Store) {
	t.Helper()
	t.Cleanup(store.invalidateDashboardStats)
	db.ClearAdminAuditDigestHMACKey()
	statements := []string{
		`DELETE FROM admin_audit_log`,
		`DELETE FROM admin_auth`,
		`DELETE FROM scan_log`,
		`DELETE FROM api_keys`,
		`DELETE FROM affected_packages`,
		`DELETE FROM vulnerabilities`,
		`DELETE FROM malicious_findings`,
		`DELETE FROM package_reputation_cache`,
		`DELETE FROM lifecycle_package_map`,
		`DELETE FROM lifecycle_releases`,
		`DELETE FROM lifecycle_products`,
	}
	f099Transaction(t, store, statements...)
	store.invalidateDashboardStats()
}

func f099Transaction(t *testing.T, store *Store, statements ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin test transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatalf("execute test transaction statement %q: %v", statement, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit test transaction: %v", err)
	}
}

func f099InstallRejectingTrigger(t *testing.T, store *Store, name, table string) func() {
	t.Helper()
	functionName := name + "_fn"
	restore := func() {
		f099Transaction(t, store,
			fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s`, name, table),
			fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, functionName),
		)
		verifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var count int
		if err := store.pool.QueryRow(verifyCtx, `SELECT COUNT(*) FROM pg_trigger WHERE tgname = $1 AND NOT tgisinternal`, name).Scan(&count); err != nil || count != 0 {
			t.Fatalf("trigger restore verification count=%d, error=%v", count, err)
		}
	}
	t.Cleanup(restore)
	f099Transaction(t, store,
		fmt.Sprintf(`CREATE OR REPLACE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced contract failure'; END $$`, functionName),
		fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, table, functionName),
	)
	return restore
}

func f099MakeColumnNullable(t *testing.T, store *Store, table, column, deleteInvalid string) func() {
	t.Helper()
	restore := func() {
		f099Transaction(t, store, deleteInvalid, fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN %s SET NOT NULL`, table, column))
		verifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var notNull bool
		if err := store.pool.QueryRow(verifyCtx, `
			SELECT attnotnull FROM pg_attribute
			WHERE attrelid = $1::regclass AND attname = $2 AND NOT attisdropped`, table, column).Scan(&notNull); err != nil || !notNull {
			t.Fatalf("restore %s.%s not-null = %t, error=%v", table, column, notNull, err)
		}
	}
	t.Cleanup(restore)
	f099Transaction(t, store, fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN %s DROP NOT NULL`, table, column))
	return restore
}

func f099RelaxDeletedRequiresRevoked(t *testing.T, store *Store) func() {
	t.Helper()
	const constraint = "api_keys_deleted_requires_revoked_check"
	restore := func() {
		f099Transaction(t, store,
			`DELETE FROM api_keys WHERE deleted_at IS NOT NULL AND revoked_at IS NULL`,
			`ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_deleted_requires_revoked_check`,
			`ALTER TABLE api_keys ADD CONSTRAINT api_keys_deleted_requires_revoked_check CHECK (deleted_at IS NULL OR revoked_at IS NOT NULL) NOT VALID`,
			`ALTER TABLE api_keys VALIDATE CONSTRAINT api_keys_deleted_requires_revoked_check`,
		)
		verifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var valid bool
		var definition string
		if err := store.pool.QueryRow(verifyCtx, `SELECT convalidated, pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = $1`, constraint).Scan(&valid, &definition); err != nil || !valid || !strings.Contains(definition, "deleted_at IS NULL") || !strings.Contains(definition, "revoked_at IS NOT NULL") {
			t.Fatalf("restored API key constraint valid=%t definition=%q error=%v", valid, definition, err)
		}
	}
	t.Cleanup(restore)
	f099Transaction(t, store, `ALTER TABLE api_keys DROP CONSTRAINT api_keys_deleted_requires_revoked_check`)
	return restore
}

func f099SwapTableForFaultView(t *testing.T, store *Store, table, backup string, restoreExtra []string, createStatements ...string) func() {
	t.Helper()
	restore := func() {
		statements := []string{fmt.Sprintf(`
			DO $$
			BEGIN
				IF EXISTS (
					SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
					WHERE n.nspname = current_schema() AND c.relname = '%s' AND c.relkind = 'v'
				) THEN
					EXECUTE 'DROP VIEW %s';
				END IF;
				IF to_regclass('%s') IS NOT NULL THEN
					EXECUTE 'ALTER TABLE %s RENAME TO %s';
				END IF;
			END $$`, table, table, backup, backup, table)}
		statements = append(statements, restoreExtra...)
		f099Transaction(t, store, statements...)
		verifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var kind string
		var backupExists bool
		if err := store.pool.QueryRow(verifyCtx, `
			SELECT c.relkind::text, to_regclass($2) IS NOT NULL
			FROM pg_class c
			WHERE c.oid = to_regclass($1)`, table, backup).Scan(&kind, &backupExists); err != nil || kind != "r" || backupExists {
			t.Fatalf("restore %s catalog kind=%q backup_exists=%t error=%v", table, kind, backupExists, err)
		}
	}
	t.Cleanup(restore)
	statements := []string{fmt.Sprintf(`ALTER TABLE %s RENAME TO %s`, table, backup)}
	statements = append(statements, createStatements...)
	f099Transaction(t, store, statements...)
	return restore
}

func f102RecentVulnerabilityContracts(t *testing.T, store *Store) {
	t.Helper()
	f099ResetContractTables(t, store)
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		SELECT 'F102-RECENT-' || lpad(g::text, 2, '0'), 'recent ' || g, 'HIGH', NOW() - INTERVAL '1 hour', NOW()
		FROM generate_series(1, 22) AS g;
		INSERT INTO vulnerabilities(id, summary, severity, published, modified, withdrawn) VALUES
			('F102-RECENT-WITHDRAWN', 'withdrawn', 'HIGH', NOW(), NOW(), NOW()),
			('F102-RECENT-OLD', 'old', 'HIGH', NOW() - INTERVAL '8 days', NOW(), NULL);
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected) VALUES
			('F102-RECENT-22', 'npm', 'sparse-choice', '[]', '["1.0.0"]'),
			('F102-RECENT-22', 'pypi', 'rich-choice', '[]', '["1.0.0","1.1.0","1.2.0","1.3.0"]');
	`); err != nil {
		t.Fatalf("seed recent vulnerabilities: %v", err)
	}

	rows, err := store.ListRecentVulnerabilities(ctx, 0, 0)
	if err != nil || len(rows) != 20 {
		t.Fatalf("ListRecentVulnerabilities(defaults) len=%d, error=%v; want 20", len(rows), err)
	}
	if rows[0].ID != "F102-RECENT-22" || rows[0].Ecosystem != "pypi" || rows[0].Name != "rich-choice" || rows[0].Affected != "1.0.0, 1.1.0, 1.2.0 (+1 more)" {
		t.Fatalf("best affected-package row = %+v", rows[0])
	}
	if rows[1].ID != "F102-RECENT-21" || rows[1].Ecosystem != "" || rows[1].Name != "" || rows[1].Affected != "" {
		t.Fatalf("missing affected-package row = %+v", rows[1])
	}
	if rows[len(rows)-1].ID != "F102-RECENT-03" {
		t.Fatalf("last default-limited row = %+v, want F102-RECENT-03", rows[len(rows)-1])
	}
	for _, row := range rows {
		if row.ID == "F102-RECENT-WITHDRAWN" || row.ID == "F102-RECENT-OLD" {
			t.Fatalf("excluded vulnerability returned: %+v", row)
		}
	}
	limited, err := store.ListRecentVulnerabilities(ctx, 7, 2)
	if err != nil || len(limited) != 2 || limited[0].ID != "F102-RECENT-22" || limited[1].ID != "F102-RECENT-21" {
		t.Fatalf("ListRecentVulnerabilities(limit=2) = %+v, %v", limited, err)
	}
	restore := f099MakeColumnNullable(t, store, "vulnerabilities", "severity", `DELETE FROM vulnerabilities WHERE id = 'F102-RECENT-NULL-SEVERITY'`)
	defer restore()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified)
		VALUES ('F102-RECENT-NULL-SEVERITY', 'invalid scan fixture', NULL, NOW() + INTERVAL '1 second', NOW())`); err != nil {
		t.Fatalf("insert nullable recent severity: %v", err)
	}
	if got, err := store.ListRecentVulnerabilities(ctx, 7, 20); err == nil || got != nil || !strings.Contains(err.Error(), "scan recent vulnerability row") {
		t.Fatalf("ListRecentVulnerabilities(nullable severity) = %+v, %v; want nil scan error", got, err)
	}
	restore()
	restoreIterationFault := f099SwapTableForFaultView(t, store, "vulnerabilities", "vulnerabilities_f102_base",
		[]string{`DROP FUNCTION IF EXISTS f102_fail_recent_text(text)`},
		`CREATE FUNCTION f102_fail_recent_text(value text) RETURNS text LANGUAGE plpgsql STABLE AS $$ BEGIN RAISE EXCEPTION 'forced recent iteration failure'; END $$`,
		`CREATE VIEW vulnerabilities AS
		 SELECT id,
			CASE WHEN id = 'F102-RECENT-21' THEN f102_fail_recent_text(summary) ELSE summary END AS summary,
			severity, published, withdrawn
		 FROM vulnerabilities_f102_base`,
	)
	defer restoreIterationFault()
	if _, err := store.ListRecentVulnerabilities(ctx, 7, 20); err == nil || !strings.Contains(err.Error(), "forced recent iteration failure") {
		t.Fatalf("ListRecentVulnerabilities(iteration fault) error = %v; want forced iteration failure", err)
	}
	restoreIterationFault()
}

func f102DailyScanContracts(t *testing.T, store *Store, dsn string) {
	t.Helper()
	f099ResetContractTables(t, store)
	ctx := context.Background()

	first, err := store.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire first UTC session: %v", err)
	}
	second, err := store.pool.Acquire(ctx)
	if err != nil {
		first.Release()
		t.Fatalf("acquire second UTC session: %v", err)
	}
	for i, conn := range []*pgxpool.Conn{first, second} {
		if _, err := conn.Exec(ctx, `SET TIME ZONE 'UTC'`); err != nil {
			second.Release()
			first.Release()
			t.Fatalf("set UTC on pooled session %d: %v", i, err)
		}
		var zone string
		if err := conn.QueryRow(ctx, `SHOW TIME ZONE`).Scan(&zone); err != nil || zone != "UTC" {
			second.Release()
			first.Release()
			t.Fatalf("pooled session %d time zone = %q, error=%v; want UTC", i, zone, err)
		}
	}
	second.Release()
	first.Release()

	var today time.Time
	if err := store.pool.QueryRow(ctx, `SELECT date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`).Scan(&today); err != nil {
		t.Fatalf("read database UTC day: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO scan_log(scan_id, scanned_at, packages_count, findings_count, duration_ms) VALUES
			('f102-day-old', $1, 2, 4, 1),
			('f102-day-boundary-a', $2, 1, 1500000000, 1),
			('f102-day-boundary-b', $3, 1, 1500000000, 1),
			('f102-dst-spring-before', '2026-03-28T23:59:59Z', 1, 1, 1),
			('f102-dst-spring-after', '2026-03-29T00:00:00Z', 1, 2, 1),
			('f102-dst-autumn-before', '2026-10-24T23:59:59Z', 1, 3, 1),
			('f102-dst-autumn-after', '2026-10-25T00:00:00Z', 1, 4, 1)`,
		today.Add(-2*24*time.Hour), today, today.Add(24*time.Hour-time.Nanosecond)); err != nil {
		t.Fatalf("seed daily scans: %v", err)
	}

	days, err := store.CountScansByDay(ctx, 3)
	if err != nil || len(days) != 3 {
		t.Fatalf("CountScansByDay(3) = %+v, %v", days, err)
	}
	if !days[0].Date.Equal(today.Add(-2*24*time.Hour)) || days[0].ScanCount != 1 || days[0].FindingsCount != 4 {
		t.Fatalf("old UTC day = %+v", days[0])
	}
	if !days[1].Date.Equal(today.Add(-24*time.Hour)) || days[1].ScanCount != 0 || days[1].FindingsCount != 0 {
		t.Fatalf("zero-filled UTC day = %+v", days[1])
	}
	if !days[2].Date.Equal(today) || days[2].ScanCount != 2 || int64(days[2].FindingsCount) != 3_000_000_000 {
		t.Fatalf("current UTC day = %+v, want two scans and bigint findings", days[2])
	}
	defaultDays, err := store.CountScansByDay(ctx, 0)
	if err != nil || len(defaultDays) != 7 || !defaultDays[6].Date.Equal(today) {
		t.Fatalf("CountScansByDay(nonpositive) = %+v, %v; want seven UTC days ending today", defaultDays, err)
	}

	dstStore, err := New(ctx, dsn, nil, &PoolConfig{MaxConns: 1, MinConns: 1})
	if err != nil {
		t.Fatalf("New(single-session DST store) error = %v", err)
	}
	defer func() {
		if err := dstStore.Close(); err != nil {
			t.Errorf("Close(single-session DST store) error = %v", err)
		}
	}()
	dstConn, err := dstStore.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire DST session: %v", err)
	}
	if _, err := dstConn.Exec(ctx, `SET TIME ZONE 'Europe/Berlin'`); err != nil {
		dstConn.Release()
		t.Fatalf("set DST session zone: %v", err)
	}
	var nonUTCZone string
	if err := dstConn.QueryRow(ctx, `SHOW TIME ZONE`).Scan(&nonUTCZone); err != nil || nonUTCZone != "Europe/Berlin" {
		dstConn.Release()
		t.Fatalf("non-UTC session time zone = %q, error=%v; want Europe/Berlin", nonUTCZone, err)
	}
	dstConn.Release()
	nonUTCDays, err := dstStore.CountScansByDay(ctx, 3)
	if err != nil || len(nonUTCDays) != 3 || nonUTCDays[2].ScanCount != 2 || int64(nonUTCDays[2].FindingsCount) != 3_000_000_000 {
		t.Fatalf("CountScansByDay(non-UTC session, recent window) = %+v, %v", nonUTCDays, err)
	}
	dstConn, err = dstStore.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("reacquire DST session for reset: %v", err)
	}
	if _, err := dstConn.Exec(ctx, `RESET TIME ZONE`); err != nil {
		dstConn.Release()
		t.Fatalf("reset DST session zone: %v", err)
	}
	var resetZone string
	if err := dstConn.QueryRow(ctx, `SHOW TIME ZONE`).Scan(&resetZone); err != nil || resetZone != "UTC" {
		dstConn.Release()
		t.Fatalf("reset session time zone = %q, error=%v; want UTC", resetZone, err)
	}
	dstConn.Release()
	dstDays, err := dstStore.CountScansByDay(ctx, 400)
	if err != nil {
		t.Fatalf("CountScansByDay(DST session) error = %v", err)
	}
	byDate := make(map[string]db.DailyScanStats, len(dstDays))
	for _, day := range dstDays {
		byDate[day.Date.Format("2006-01-02")] = day
	}
	for date, want := range map[string]struct{ scans, findings int }{
		"2026-03-28": {1, 1},
		"2026-03-29": {1, 2},
		"2026-10-24": {1, 3},
		"2026-10-25": {1, 4},
	} {
		got, ok := byDate[date]
		if !ok || got.ScanCount != want.scans || got.FindingsCount != want.findings {
			t.Fatalf("DST UTC bucket %s = %+v (present=%t), want scans=%d findings=%d", date, got, ok, want.scans, want.findings)
		}
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO scan_log(scan_id, scanned_at, packages_count, findings_count, duration_ms) VALUES
			('f102-daily-iteration-valid', NOW(), 1, 1, 1),
			('f102-daily-iteration-fault', NOW(), 1, 1, 1)`); err != nil {
		t.Fatalf("seed daily iteration fixtures: %v", err)
	}
	restoreView := f099SwapTableForFaultView(t, store, "scan_log", "scan_log_f102_base",
		[]string{`DROP FUNCTION IF EXISTS f102_fail_daily_int(integer)`},
		`CREATE FUNCTION f102_fail_daily_int(value integer) RETURNS integer LANGUAGE plpgsql STABLE AS $$ BEGIN RAISE EXCEPTION 'forced daily iteration failure'; END $$`,
		`CREATE VIEW scan_log AS
		 SELECT id, scanned_at,
			CASE WHEN scan_id = 'f102-daily-iteration-fault' THEN f102_fail_daily_int(findings_count) ELSE findings_count END AS findings_count
		 FROM scan_log_f102_base`,
	)
	defer restoreView()
	if got, err := store.CountScansByDay(ctx, 7); err == nil || got != nil || !strings.Contains(err.Error(), "iterate daily stats") {
		t.Fatalf("CountScansByDay(iteration fault) = %+v, %v; want nil iteration error", got, err)
	}
	restoreView()
}

func f102DashboardCategoryContracts(t *testing.T, store *Store) {
	t.Helper()
	f099ResetContractTables(t, store)
	ctx := context.Background()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO vulnerabilities(id, summary, severity, published, modified, withdrawn) VALUES
			('F102-DASH-ACTIVE', 'active', 'CRITICAL', NOW(), NOW(), NULL),
			('F102-DASH-WITHDRAWN', 'withdrawn', 'HIGH', NOW(), NOW(), NOW());
		INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected) VALUES
			('F102-DASH-ACTIVE', 'npm', 'f102-dash-vuln', '[]', '[]'),
			('F102-DASH-WITHDRAWN', 'npm', 'f102-dash-withdrawn', '[]', '[]');
		INSERT INTO malicious_findings(id, ecosystem, name, source, risk_type, severity, summary, reference_urls, removed_at) VALUES
			('F102-DASH-MAL', 'npm', 'f102-dash-mal', 'openssf', 'malware', 'UNKNOWN', 'active unknown', '[]', NULL),
			('F102-DASH-REMOVED', 'npm', 'f102-dash-removed', 'openssf', 'malware', 'UNKNOWN', 'removed unknown', '[]', NOW());
		INSERT INTO package_reputation_cache(ecosystem, name, version, source, status, severity) VALUES
			('npm', 'f102-rep-mal', '', 'reversinglabs', 'malicious', 'CRITICAL'),
			('npm', 'f102-rep-removed', '', 'reversinglabs', 'removed', 'MEDIUM'),
			('npm', 'f102-rep-risk', '', 'reversinglabs', 'risk', 'HIGH'),
			('npm', 'f102-rep-clean', '', 'reversinglabs', 'clean', 'HIGH');
		INSERT INTO lifecycle_products(product_slug, name) VALUES ('f102-product', 'F102 Product');
		INSERT INTO lifecycle_package_map(ecosystem, name, product_slug) VALUES ('npm', 'f102-lifecycle', 'f102-product');
		INSERT INTO lifecycle_releases(product_slug, cycle, eol_from) VALUES
			('f102-product', '1', CURRENT_DATE - 1),
			('f102-product', '2', CURRENT_DATE + 30),
			('f102-product', '3', CURRENT_DATE),
			('f102-product', '4', CURRENT_DATE + 90),
			('f102-product', '5', CURRENT_DATE + 91);
	`); err != nil {
		t.Fatalf("seed dashboard categories: %v", err)
	}
	store.invalidateDashboardStats()
	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if stats.TotalPackages != 6 || stats.TotalVulnerabilities != 1 || stats.TotalMalicious != 2 || stats.TotalSupplyChainRisk != 4 || stats.TotalLifecycle != 2 {
		t.Fatalf("DashboardStats totals = %+v, want packages=6 vulnerabilities=1 malicious=2 supply=4 lifecycle=2", stats)
	}
	wantSeverity := map[string]int{"CRITICAL": 2, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 1}
	if len(stats.BySeverity) != len(wantSeverity) {
		t.Fatalf("DashboardStats BySeverity = %+v", stats.BySeverity)
	}
	for severity, want := range wantSeverity {
		if got := stats.BySeverity[severity]; got != want {
			t.Fatalf("DashboardStats BySeverity[%s] = %d, want %d; all=%+v", severity, got, want, stats.BySeverity)
		}
	}
	unknown, err := store.CountUnknownSeverityFindings(ctx)
	if err != nil || unknown != 1 {
		t.Fatalf("CountUnknownSeverityFindings() = %d, %v; want one active UNKNOWN malicious row", unknown, err)
	}
}

func f102DashboardDefensiveContracts(t *testing.T, store *Store, dsn string) {
	t.Helper()
	f099ResetContractTables(t, store)
	ctx := context.Background()
	restoreView := f102InstallEmptyScanTotalsView(t, store)
	defer restoreView()
	totals, err := store.ScanTotals(ctx)
	if err != nil || totals == nil || totals.PackagesScanned != 0 || totals.Findings != 0 {
		t.Fatalf("ScanTotals(empty view) = %+v, %v; want zero totals", totals, err)
	}
	restoreView()
	if totals, err := store.ScanTotals(ctx); err != nil || totals == nil || totals.PackagesScanned != 0 || totals.Findings != 0 {
		t.Fatalf("ScanTotals(restored view) = %+v, %v; want zero totals", totals, err)
	}

	restore := f099MakeColumnNullable(t, store, "malicious_findings", "severity", `DELETE FROM malicious_findings WHERE severity IS NULL`)
	defer restore()
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO malicious_findings(id, ecosystem, name, source, risk_type, severity, summary, reference_urls)
		VALUES ('F102-NULL-SEVERITY', 'npm', 'f102-null-severity', 'openssf', 'malware', NULL, 'null severity', '[]')`); err != nil {
		t.Fatalf("insert nullable severity: %v", err)
	}
	store.invalidateDashboardStats()
	if stats, err := store.DashboardStats(ctx); err == nil || stats != nil || !strings.Contains(err.Error(), "scan dashboard severity row") {
		t.Fatalf("DashboardStats(nullable severity) = %+v, %v; want nil scan error", stats, err)
	}
	restore()
	store.invalidateDashboardStats()
	if stats, err := store.DashboardStats(ctx); err != nil || stats == nil {
		t.Fatalf("DashboardStats(after restore) = %+v, %v", stats, err)
	}
	if _, err := store.pool.Exec(ctx, `
		INSERT INTO malicious_findings(id, ecosystem, name, source, risk_type, severity, summary, reference_urls) VALUES
			('F102-DASH-ITERATION-VALID', 'npm', 'f102-dashboard-iteration-valid', 'openssf', 'malware', 'LOW', 'valid', '[]'),
			('F102-DASH-ITERATION-FAULT', 'npm', 'f102-dashboard-iteration-fault', 'openssf', 'malware', 'LOW', 'fault', '[]')`); err != nil {
		t.Fatalf("seed dashboard iteration fixtures: %v", err)
	}
	restoreDashboardView := f099SwapTableForFaultView(t, store, "malicious_findings", "malicious_findings_f102_base",
		[]string{`DROP FUNCTION IF EXISTS f102_fail_dashboard_text(text)`},
		`CREATE FUNCTION f102_fail_dashboard_text(value text) RETURNS text LANGUAGE plpgsql STABLE AS $$ BEGIN RAISE EXCEPTION 'forced dashboard iteration failure'; END $$`,
		`CREATE VIEW malicious_findings AS
		 SELECT id, ecosystem, name, removed_at,
			CASE WHEN id = 'F102-DASH-ITERATION-FAULT' THEN f102_fail_dashboard_text(severity) ELSE severity END AS severity
		 FROM malicious_findings_f102_base`,
	)
	defer restoreDashboardView()
	store.invalidateDashboardStats()
	if stats, err := store.DashboardStats(ctx); err == nil || stats != nil || !strings.Contains(err.Error(), "iterate dashboard severities") {
		t.Fatalf("DashboardStats(iteration fault) = %+v, %v; want nil iteration error", stats, err)
	}
	restoreDashboardView()
	store.invalidateDashboardStats()
	restoreTotalsFault := f099SwapTableForFaultView(t, store, "malicious_findings", "malicious_findings_f102_totals_base", nil,
		`CREATE VIEW malicious_findings AS
		 SELECT id, ecosystem, removed_at, severity
		 FROM malicious_findings_f102_totals_base`,
	)
	defer restoreTotalsFault()
	if stats, err := store.DashboardStats(ctx); err == nil || stats != nil || !strings.Contains(err.Error(), "dashboard totals") {
		t.Fatalf("DashboardStats(totals query fault) = %+v, %v; want totals error", stats, err)
	}
	restoreTotalsFault()
	store.invalidateDashboardStats()
	restoreSeverityQueryFault := f099SwapTableForFaultView(t, store, "malicious_findings", "malicious_findings_f102_query_base", nil,
		`CREATE VIEW malicious_findings AS
		 SELECT id, ecosystem, name, removed_at
		 FROM malicious_findings_f102_query_base`,
	)
	defer restoreSeverityQueryFault()
	if stats, err := store.DashboardStats(ctx); err == nil || stats != nil || !strings.Contains(err.Error(), "dashboard severities") {
		t.Fatalf("DashboardStats(severity query fault) = %+v, %v; want severity query error", stats, err)
	}
	restoreSeverityQueryFault()
	store.invalidateDashboardStats()

	closedStore, err := New(ctx, dsn, nil, &PoolConfig{MaxConns: 1, MinConns: 1})
	if err != nil {
		t.Fatalf("New(closed fault store) error = %v", err)
	}
	if err := closedStore.Close(); err != nil {
		t.Fatalf("Close(fault store) error = %v", err)
	}
	faults := []struct {
		name string
		call func() error
	}{
		{name: "admin auth query", call: func() error { _, err := closedStore.GetAdminAuth(ctx); return err }},
		{name: "audit list query", call: func() error { _, err := closedStore.ListAdminAuditLogPage(ctx, 10, 0); return err }},
		{name: "API list query", call: func() error { _, err := closedStore.ListAPIKeys(ctx); return err }},
		{name: "API page query", call: func() error { _, err := closedStore.ListAPIKeysPage(ctx, 10, 0); return err }},
		{name: "API touch query", call: func() error { return closedStore.TouchAPIKeyLastUsed(ctx, 1) }},
		{name: "API create query", call: func() error { _, err := closedStore.CreateAPIKey(ctx, "closed", "closed-hash", nil); return err }},
		{name: "API revoke query", call: func() error { return closedStore.RevokeAPIKey(ctx, 1) }},
		{name: "API delete query", call: func() error { return closedStore.DeleteAPIKey(ctx, 1) }},
		{name: "recent query", call: func() error { _, err := closedStore.ListRecentVulnerabilities(ctx, 7, 20); return err }},
		{name: "daily query", call: func() error { _, err := closedStore.CountScansByDay(ctx, 7); return err }},
		{name: "totals query", call: func() error { _, err := closedStore.ScanTotals(ctx); return err }},
		{name: "dashboard begin", call: func() error { _, err := closedStore.DashboardStats(ctx); return err }},
		{name: "unknown query", call: func() error { _, err := closedStore.CountUnknownSeverityFindings(ctx); return err }},
	}
	for _, fault := range faults {
		if err := fault.call(); err == nil {
			t.Errorf("%s error = nil, want closed-pool failure", fault.name)
		}
	}
}

func f102InstallEmptyScanTotalsView(t *testing.T, store *Store) func() {
	t.Helper()
	const productionView = `
		CREATE VIEW scan_log_totals AS
		SELECT
			TRUE AS id,
			COALESCE(SUM(packages_count), 0)::BIGINT AS packages_scanned,
			COALESCE(SUM(findings_count), 0)::BIGINT AS findings,
			COALESCE(MAX(scanned_at), NOW()) AS updated_at
		FROM scan_log`
	restore := func() {
		f099Transaction(t, store, `DROP VIEW IF EXISTS scan_log_totals`, productionView)
		verifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var definition string
		if err := store.pool.QueryRow(verifyCtx, `SELECT pg_get_viewdef('scan_log_totals'::regclass, true)`).Scan(&definition); err != nil || !strings.Contains(definition, "sum(packages_count)") || !strings.Contains(definition, "sum(findings_count)") {
			t.Fatalf("restored scan_log_totals definition = %q, error=%v", definition, err)
		}
	}
	t.Cleanup(restore)
	f099Transaction(t, store,
		`DROP VIEW scan_log_totals`,
		`CREATE VIEW scan_log_totals AS SELECT TRUE AS id, 0::bigint AS packages_scanned, 0::bigint AS findings, NOW() AS updated_at WHERE FALSE`,
	)
	return restore
}
