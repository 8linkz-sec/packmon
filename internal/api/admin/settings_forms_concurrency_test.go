package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/web"
)

// pausingSystemSettingsStore commits the first system-settings save and then
// parks that request inside the store call until release is closed, which
// models request A having committed but not yet published its values.
type pausingSystemSettingsStore struct {
	*adminFlowStoreStub
	release chan struct{}
	calls   int
}

func (s *pausingSystemSettingsStore) UpsertSystemSettingsWithAudit(ctx context.Context, settings *db.SystemSettings, audit *db.AdminAuditEntry) error {
	err := s.adminFlowStoreStub.UpsertSystemSettingsWithAudit(ctx, settings, audit)
	s.mu.Lock()
	s.calls++
	first := s.calls == 1
	s.mu.Unlock()
	if first {
		<-s.release
	}
	return err
}

func (s *pausingSystemSettingsStore) committed() db.SystemSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.systemSettings
}

// TestSystemSettingsSaveOverlappingRequestsKeepRuntimeEqualToLastCommit forces
// the interleaving in which request A commits, request B then commits and
// publishes newer settings, and only afterwards A reaches its publication. The
// live runtime must end up equal to the last committed row, policy and
// retention alike, instead of A's older values.
func TestSystemSettingsSaveOverlappingRequestsKeepRuntimeEqualToLastCommit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		store := &pausingSystemSettingsStore{adminFlowStoreStub: newAdminStoreStub(), release: make(chan struct{})}
		cfg := adminFlowConfig()
		runtime := config.NewRuntimeSettingsFromConfig(cfg)
		sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		handler := NewAdminHandler(ctx, store, sm, web.NewRendererWithLayoutLinks(web.TemplateFS(), false, web.LayoutLinks{}), logger, cfg, runtime, nil)

		save := func(values url.Values) *httptest.ResponseRecorder {
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", values)
			rec := httptest.NewRecorder()
			handler.HandleSystemSettingsSave(rec, req)
			return rec
		}

		var wg sync.WaitGroup
		var recA, recB *httptest.ResponseRecorder
		wg.Go(func() {
			recA = save(url.Values{
				"block_threshold":            {"HIGH"},
				"rate_limit_per_minute":      {"100"},
				"rate_limit_burst":           {"50"},
				"scan_log_retention_days":    {"10"},
				"admin_audit_retention_days": {"20"},
			})
		})
		// Barrier: A has committed and is parked before its publication.
		synctest.Wait()
		revisionA := store.committed().UpdatedAt

		// B renders the form after A's commit and saves on top of it.
		wg.Go(func() {
			recB = save(url.Values{
				"block_threshold":            {"LOW"},
				"rate_limit_per_minute":      {"200"},
				"rate_limit_burst":           {"80"},
				"scan_log_retention_days":    {"5"},
				"admin_audit_retention_days": {"6"},
				"updated_at":                 {revisionA.Format(time.RFC3339Nano)},
			})
		})
		// Barrier: B has either finished or is waiting behind A.
		synctest.Wait()
		close(store.release)
		wg.Wait()

		for name, rec := range map[string]*httptest.ResponseRecorder{"A": recA, "B": recB} {
			if got := rec.Header().Get("Location"); !strings.Contains(got, "msg=") {
				t.Fatalf("request %s Location = %q, want saved message", name, got)
			}
		}

		committed := store.committed()
		if committed.BlockThreshold != "LOW" {
			t.Fatalf("committed block threshold = %q, want B's LOW as the last commit", committed.BlockThreshold)
		}
		perMinute, burst := runtime.RateLimit()
		retention := runtime.Retention()
		if runtime.BlockThreshold() != committed.BlockThreshold ||
			perMinute != committed.RateLimitPerMinute ||
			burst != committed.RateLimitBurst ||
			retention.ScanLog != committed.ScanLogRetention ||
			retention.AdminAuditLog != committed.AdminAuditRetention {
			t.Fatalf("runtime = %s %d/%d %v/%v, want last commit %s %d/%d %v/%v",
				runtime.BlockThreshold(), perMinute, burst, retention.ScanLog, retention.AdminAuditLog,
				committed.BlockThreshold, committed.RateLimitPerMinute, committed.RateLimitBurst,
				committed.ScanLogRetention, committed.AdminAuditRetention)
		}
		cancel()
	})
}

// TestSystemSettingsSaveCommitSlotWaitFailureUsesGenericSaveMessage pins the
// response contract for a settings save that cannot acquire the runtime commit
// slot before its audit context is cancelled or reaches its deadline. Neither
// context error is an audit-write failure or an optimistic-lock conflict, and
// neither may expose concurrency details to the admin response.
func TestSystemSettingsSaveCommitSlotWaitFailureUsesGenericSaveMessage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cancelRoot bool
	}{
		{name: "cancelled", cancelRoot: true},
		{name: "deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rootCtx, cancelRoot := context.WithCancel(context.Background())
				defer cancelRoot()

				store := &f070SettingsStore{adminFlowStoreStub: newAdminStoreStub()}
				cfg := adminFlowConfig()
				runtime := config.NewRuntimeSettingsFromConfig(cfg)
				sm := auth.NewSessionManagerWithIdleTimeout(rootCtx, time.Hour, auth.DefaultAdminIdleTimeout, false)
				logger := slog.New(slog.NewTextHandler(io.Discard, nil))
				handler := NewAdminHandler(rootCtx, store, sm, web.NewRendererWithLayoutLinks(web.TemplateFS(), false, web.LayoutLinks{}), logger, cfg, runtime, nil)

				releaseSlot := make(chan struct{})
				slotAcquired := make(chan struct{})
				blockerDone := make(chan error, 1)
				go func() {
					blockerDone <- runtime.CommitAndPublish(context.Background(), config.SystemSettingsValues{}, func() error {
						close(slotAcquired)
						<-releaseSlot
						return nil
					})
				}()
				<-slotAcquired

				req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", f070ValidSettingsFormWithRetention("1", "2"))
				rec := httptest.NewRecorder()
				saveDone := make(chan struct{})
				startedAt := time.Now()
				go func() {
					handler.HandleSystemSettingsSave(rec, req)
					close(saveDone)
				}()
				if tc.cancelRoot {
					cancelRoot()
				}
				<-saveDone
				if !tc.cancelRoot && time.Since(startedAt) < adminAuditWriteTimeout {
					t.Fatalf("settings save returned after %s, want it to wait for the %s commit-slot deadline", time.Since(startedAt), adminAuditWriteTimeout)
				}

				assertF070Redirect(t, rec, web.Message("admin.settings.error.save"), true)
				if store.upsertCalls != 0 {
					t.Fatalf("settings upsert calls = %d, want none while the commit slot is unavailable", store.upsertCalls)
				}

				close(releaseSlot)
				if err := <-blockerDone; err != nil {
					t.Fatalf("commit-slot blocker error = %v", err)
				}
			})
		})
	}
}
