package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/web"
)

// lockoutAuditGateStore parks the first login_lockout audit write until
// release is closed, which holds that request inside the audit-write interval
// while other requests run. With failFirst, the parked write then fails.
type lockoutAuditGateStore struct {
	*adminFlowStoreStub
	release      chan struct{}
	failFirst    bool
	gateMu       sync.Mutex
	lockoutCalls int
}

func (s *lockoutAuditGateStore) InsertAdminAuditLog(ctx context.Context, entry *db.AdminAuditEntry) error {
	if entry != nil && entry.Action == "login_lockout" {
		s.gateMu.Lock()
		s.lockoutCalls++
		first := s.lockoutCalls == 1
		s.gateMu.Unlock()
		if first {
			<-s.release
			if s.failFirst {
				return errors.New("audit store unavailable")
			}
		}
	}
	return s.adminFlowStoreStub.InsertAdminAuditLog(ctx, entry)
}

func (s *lockoutAuditGateStore) lockoutRows(t *testing.T) int {
	t.Helper()
	entries, err := s.ListAdminAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	count := 0
	for _, entry := range entries {
		if entry.Action == "login_lockout" {
			count++
		}
	}
	return count
}

type lockedOutAdminRequest func(t *testing.T, h *AdminHandler, sm *auth.SessionManager)

// lockedOutAdminRequests are the three handlers that audit a request from a
// locked-out principal. Each request comes from lockoutTestIP.
func lockedOutAdminRequests() map[string]lockedOutAdminRequest {
	return map[string]lockedOutAdminRequest{
		"login": func(t *testing.T, h *AdminHandler, sm *auth.SessionManager) {
			postAdminLogin(t, h, sm, lockoutTestIP, "admin", "anything")
		},
		"api key create step-up": func(t *testing.T, h *AdminHandler, sm *auth.SessionManager) {
			req, sess := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
				"name":             {"ci-lockout"},
				"expires_in_days":  {validAPIKeyExpiryFormValue()},
				"current_password": {"anything"},
				"create_nonce":     {"lockout-nonce"},
			})
			sm.SetFlash(sess.ID, "api_key_create_nonce", "lockout-nonce")
			req.RemoteAddr = lockoutTestIP + ":12345"
			h.HandleKeyCreate(httptest.NewRecorder(), req)
		},
		"password change": func(t *testing.T, h *AdminHandler, sm *auth.SessionManager) {
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
				"current_password": {"anything"},
				"new_password":     {"new-password-1234567890"},
				"confirm_password": {"new-password-1234567890"},
			})
			req.RemoteAddr = lockoutTestIP + ":12345"
			h.HandlePasswordChange(httptest.NewRecorder(), req)
		},
	}
}

const lockoutTestIP = "10.0.0.70"

// runLockoutAuditRace runs request A until it is parked in its lockout audit
// write, then runs request B to completion (or until it blocks), releases A,
// and finally runs request C after both. It returns the number of
// login_lockout rows. Every handler and channel lives in one synctest bubble,
// so synctest.Wait is the barrier and no timing is involved.
func runLockoutAuditRace(t *testing.T, request lockedOutAdminRequest, failFirst bool) int {
	t.Helper()
	var rows int
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		base := newAdminStoreStub()
		hash, err := auth.HashPassword("current-password")
		if err != nil {
			t.Fatalf("HashPassword() error = %v", err)
		}
		base.adminAuth = &db.AdminAuth{PasswordHash: hash}
		store := &lockoutAuditGateStore{adminFlowStoreStub: base, release: make(chan struct{}), failFirst: failFirst}
		cfg := adminFlowConfig()
		sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		h := NewAdminHandler(ctx, store, sm, web.NewRendererWithLayoutLinks(web.TemplateFS(), false, web.LayoutLinks{}), logger, cfg, nil, nil)

		h.loginMu.Lock()
		h.loginAttempts[lockoutTestIP] = &loginAttempt{count: loginMaxAttempts, lockedAt: time.Now()}
		h.loginMu.Unlock()

		var wg sync.WaitGroup
		wg.Go(func() { request(t, h, sm) })
		synctest.Wait()
		store.gateMu.Lock()
		parked := store.lockoutCalls == 1
		store.gateMu.Unlock()
		if !parked {
			t.Fatal("request A did not reach its login_lockout audit write")
		}

		wg.Go(func() { request(t, h, sm) })
		synctest.Wait()
		close(store.release)
		wg.Wait()

		request(t, h, sm)
		rows = store.lockoutRows(t)
		cancel()
	})
	return rows
}

func TestLockoutAuditConcurrentRequestsWriteOneRowPerWindow(t *testing.T) {
	for name, request := range lockedOutAdminRequests() {
		t.Run(name, func(t *testing.T) {
			if got := runLockoutAuditRace(t, request, false); got != 1 {
				t.Fatalf("login_lockout rows = %d, want exactly 1 for one lockout window", got)
			}
		})
	}
}

func TestLockoutAuditFailedWriteReleasesClaimForLaterAttempt(t *testing.T) {
	for name, request := range lockedOutAdminRequests() {
		t.Run(name, func(t *testing.T) {
			// A's audit write fails, B ran while A held the claim, and C runs
			// after A released it: C must write the window's single row.
			if got := runLockoutAuditRace(t, request, true); got != 1 {
				t.Fatalf("login_lockout rows = %d, want exactly 1 written by the later attempt", got)
			}
		})
	}
}
