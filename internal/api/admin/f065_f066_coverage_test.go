package admin

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"testing/synctest"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/web"
)

type f065F066Store struct {
	*adminErrorStore
	dailyScans       []db.DailyScanStats
	dailyScansErr    error
	unknownCount     int
	unknownCountErr  error
	apiKeyPageLimit  int
	apiKeyPageOffset int
}

func newF065F066Store() *f065F066Store {
	return &f065F066Store{adminErrorStore: newAdminErrorStore()}
}

func (s *f065F066Store) CountScansByDay(context.Context, int) ([]db.DailyScanStats, error) {
	return append([]db.DailyScanStats(nil), s.dailyScans...), s.dailyScansErr
}

func (s *f065F066Store) CountUnknownSeverityFindings(context.Context) (int, error) {
	return s.unknownCount, s.unknownCountErr
}

func (s *f065F066Store) ListAPIKeysPage(ctx context.Context, limit, offset int) ([]db.APIKey, error) {
	s.apiKeyPageLimit = limit
	s.apiKeyPageOffset = offset
	return s.adminErrorStore.ListAPIKeysPage(ctx, limit, offset)
}

type f066StoreOnly struct {
	Store
}

type f066DBStoreOnly struct {
	db.Store
}

type f066APIKeyPager struct {
	Store
	source *f065F066Store
}

func (s *f066APIKeyPager) ListAPIKeysPage(ctx context.Context, limit, offset int) ([]db.APIKey, error) {
	return s.source.ListAPIKeysPage(ctx, limit, offset)
}

func f065F066Renderer(name, body string) *web.Renderer {
	return web.NewRendererWithLayoutLinks(fstest.MapFS{
		"templates/layout.html": {Data: []byte(`{{define "layout"}}{{template "content" .}}{{end}}`)},
		"templates/" + name:     {Data: []byte(`{{define "content"}}` + body + `{{end}}`)},
	}, true, web.LayoutLinks{})
}

func f065F066EmptyRenderer() *web.Renderer {
	return web.NewRendererWithLayoutLinks(fstest.MapFS{}, true, web.LayoutLinks{})
}

func f065LoginRequest(t *testing.T, sm *auth.SessionManager, values url.Values) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	sess, err := sm.CreatePreAuth(rec)
	if err != nil {
		t.Fatalf("CreatePreAuth: %v", err)
	}
	token, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}
	values.Set(auth.CSRFFieldName, token)
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func assertNoAdminSessionCookie(t *testing.T, sm *auth.SessionManager, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name != auth.SessionCookieName || cookie.Value == "" {
			continue
		}
		lookup := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		lookup.AddCookie(cookie)
		if sess := sm.Get(lookup); sess != nil && sess.Admin {
			t.Fatalf("response established an admin session: %+v", cookie)
		}
	}
}

func TestF065LoginFailuresRemainUnauthenticated(t *testing.T) {
	t.Run("malformed and oversized forms", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			body string
			want int
		}{
			{name: "malformed", body: "%zz", want: http.StatusBadRequest},
			{name: "oversized", body: "x=" + strings.Repeat("a", maxAdminFormBytes+1), want: http.StatusRequestEntityTooLarge},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h, sm := testHandler(t, &adminStoreStub{})
				req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rec := httptest.NewRecorder()
				h.HandleLogin(rec, req)
				if rec.Code != tc.want || !strings.Contains(rec.Body.String(), "invalid form payload") {
					t.Fatalf("status/body = %d %q, want %d and generic form error", rec.Code, rec.Body.String(), tc.want)
				}
				assertNoAdminSessionCookie(t, sm, rec)
			})
		}
	})

	t.Run("csrf generation seam", func(t *testing.T) {
		h, sm := testHandler(t, &adminStoreStub{})
		h.csrfToken = func(*auth.Session) (string, error) { return "", errors.New("csrf unavailable") }
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "internal server error") {
			t.Fatalf("status/body = %d %q, want generic 500", rec.Code, rec.Body.String())
		}
		assertNoAdminSessionCookie(t, sm, rec)
	})

	t.Run("login render failure", func(t *testing.T) {
		h, sm := testHandler(t, &adminStoreStub{})
		h.renderer = f065F066EmptyRenderer()
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "internal server error") {
			t.Fatalf("status/body = %d %q, want generic 500", rec.Code, rec.Body.String())
		}
		assertNoAdminSessionCookie(t, sm, rec)
	})

	t.Run("auth store failure", func(t *testing.T) {
		store := newF065F066Store()
		store.fail["GetAdminAuth"] = errors.New("database secret detail")
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		req := f065LoginRequest(t, sm, url.Values{"username": {"admin"}, "password": {"password"}})
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret detail") {
			t.Fatalf("status/body = %d %q, want redacted 500", rec.Code, rec.Body.String())
		}
		assertNoAdminSessionCookie(t, sm, rec)
	})

	t.Run("rejection audit failure", func(t *testing.T) {
		store := newF065F066Store()
		store.fail["InsertAdminAuditLog"] = errors.New("audit unavailable")
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		req := f065LoginRequest(t, sm, url.Values{"username": {"someone"}, "password": {"password"}})
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "failed to record audit log") || strings.Contains(rec.Body.String(), "audit unavailable") {
			t.Fatalf("status/body = %d %q, want redacted audit 500", rec.Code, rec.Body.String())
		}
		assertNoAdminSessionCookie(t, sm, rec)
	})
}

func TestF065DashboardAndAuthenticatedNotFoundFailures(t *testing.T) {
	t.Run("daily activity failure is visible", func(t *testing.T) {
		store := newF065F066Store()
		store.dailyScansErr = errors.New("daily aggregation failed")
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		h.renderer = f065F066Renderer("admin/dashboard.html", `{{.ScanCountLoadError}}|{{.TotalScans7d}}`)
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")
		rec := httptest.NewRecorder()
		h.HandleDashboard(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), web.Message("dashboard.error.scan_activity")+"|0") {
			t.Fatalf("status/body = %d %q, want activity error and zero sum", rec.Code, rec.Body.String())
		}
	})

	t.Run("seven day sum and stored bootstrap warning", func(t *testing.T) {
		store := newF065F066Store()
		store.dailyScans = []db.DailyScanStats{{ScanCount: 3}, {ScanCount: 4}}
		store.adminAuth = &db.AdminAuth{PasswordIsBootstrap: true}
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		h.renderer = f065F066Renderer("admin/dashboard.html", `{{.TotalScans7d}}|{{.BootstrapWarning}}`)
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")
		rec := httptest.NewRecorder()
		h.HandleDashboard(rec, req)
		if got := strings.TrimSpace(rec.Body.String()); got != "7|true" {
			t.Fatalf("dashboard body = %q, want 7|true", got)
		}
	})

	t.Run("dashboard render failure", func(t *testing.T) {
		h, sm := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
		h.renderer = f065F066EmptyRenderer()
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/")
		rec := httptest.NewRecorder()
		h.HandleDashboard(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("authenticated exact not found", func(t *testing.T) {
		h, sm := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
		h.renderer = f065F066Renderer("not_found.html", `not-found`)
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/missing")
		rec := httptest.NewRecorder()
		h.HandleNotFound(rec, req)
		if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != "not-found" {
			t.Fatalf("status/body = %d %q, want exact 404 page", rec.Code, rec.Body.String())
		}
	})

	t.Run("authenticated not found render failure", func(t *testing.T) {
		h, sm := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
		h.renderer = f065F066EmptyRenderer()
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/missing")
		rec := httptest.NewRecorder()
		h.HandleNotFound(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("unauthenticated not found redirects", func(t *testing.T) {
		h, _ := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
		rec := httptest.NewRecorder()
		h.HandleNotFound(rec, httptest.NewRequest(http.MethodGet, "/admin/missing", nil))
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/admin/login") {
			t.Fatalf("status/location = %d %q, want login redirect", rec.Code, rec.Header().Get("Location"))
		}
	})
}

func TestF065LogoutCleanupTickerAndAuditContext(t *testing.T) {
	t.Run("malformed and oversized logout", func(t *testing.T) {
		for _, tc := range []struct {
			body string
			want int
		}{
			{body: "%zz", want: http.StatusBadRequest},
			{body: "x=" + strings.Repeat("a", maxAdminFormBytes+1), want: http.StatusRequestEntityTooLarge},
		} {
			h, _ := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
			req := httptest.NewRequest(http.MethodPost, "/admin/logout", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			h.HandleLogout(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		}
	})

	t.Run("logout audit failure retains session", func(t *testing.T) {
		store := newF065F066Store()
		store.fail["InsertAdminAuditLog"] = errors.New("audit unavailable")
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/logout", url.Values{})
		rec := httptest.NewRecorder()
		h.HandleLogout(rec, req)
		if rec.Code != http.StatusInternalServerError || sm.Get(req) == nil {
			t.Fatalf("status/session = %d %+v, want 500 with existing session", rec.Code, sm.Get(req))
		}
	})

	t.Run("real cleanup ticker", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			now := time.Now()
			h := &AdminHandler{loginAttempts: map[string]*loginAttempt{
				"nil":     nil,
				"partial": {count: 1, lastFailedAt: now.Add(-loginLockoutDuration - time.Nanosecond)},
				"locked":  {count: loginMaxAttempts, lockedAt: now.Add(-loginLockoutDuration - time.Nanosecond)},
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				h.cleanupAttempts(ctx)
				close(done)
			}()
			synctest.Wait()
			time.Sleep(5 * time.Minute)
			synctest.Wait()
			if len(h.loginAttempts) != 0 {
				t.Fatalf("login attempts after tick = %+v, want empty", h.loginAttempts)
			}
			cancel()
			synctest.Wait()
			select {
			case <-done:
			default:
				t.Fatal("cleanupAttempts did not stop after cancellation")
			}
		})
	})

	t.Run("audit contexts", func(t *testing.T) {
		h := &AdminHandler{}
		ctx, cancel := h.adminAuditContext()
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Sub(time.Now()) < adminAuditWriteTimeout-time.Second || deadline.Sub(time.Now()) > adminAuditWriteTimeout {
			cancel()
			t.Fatalf("nil-root deadline = %v ok=%t, want approximately %s", deadline, ok, adminAuditWriteTimeout)
		}
		cancel()

		root, rootCancel := context.WithCancel(context.Background())
		h.rootCtx = root
		rootCancel()
		ctx, cancel = h.adminAuditContext()
		defer cancel()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("root-cancelled context error = %v, want canceled", ctx.Err())
		}

		store := newF065F066Store()
		h, _ = newAdminHandlerForStore(t, store, adminFlowConfig())
		req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		requestCtx, requestCancel := context.WithCancel(req.Context())
		requestCancel()
		if err := h.auditLog(req.WithContext(requestCtx), "request_cancel_ignored", map[string]string{}); err != nil {
			t.Fatalf("auditLog with canceled request = %v, want independent root context", err)
		}
	})
}

func TestF066APIKeyStepUpFailures(t *testing.T) {
	passwordHash, err := auth.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	stepUpRequest := func(password string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/admin/keys/create", strings.NewReader(url.Values{
			"current_password": {password},
			"expires_in_days":  {"30"},
		}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "127.0.0.1:12345"
		if err := req.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		return req
	}

	t.Run("locked principal audit succeeds", func(t *testing.T) {
		store := newF065F066Store()
		h, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
		now := time.Now()
		h.loginAttempts["127.0.0.1"] = &loginAttempt{count: loginMaxAttempts, lockedAt: now}
		rec := httptest.NewRecorder()
		if h.requireAPIKeyCreateStepUp(rec, stepUpRequest("irrelevant"), "ci") {
			t.Fatal("locked step-up returned true")
		}
		if !strings.Contains(strings.ToLower(rec.Header().Get("Location")), "too+many") {
			t.Fatalf("Location = %q, want lockout error", rec.Header().Get("Location"))
		}
		if _, ok := h.claimLockoutAudit("127.0.0.1"); ok {
			t.Fatal("successful lockout audit left a reusable claim")
		}
	})

	t.Run("locked principal audit failure releases claim", func(t *testing.T) {
		store := newF065F066Store()
		store.fail["InsertAdminAuditLog"] = errors.New("audit unavailable")
		h, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
		h.loginAttempts["127.0.0.1"] = &loginAttempt{count: loginMaxAttempts, lockedAt: time.Now()}
		rec := httptest.NewRecorder()
		if h.requireAPIKeyCreateStepUp(rec, stepUpRequest("irrelevant"), "ci") {
			t.Fatal("locked step-up returned true")
		}
		claim, ok := h.claimLockoutAudit("127.0.0.1")
		if !ok {
			t.Fatal("failed lockout audit did not release claim")
		}
		h.releaseLockoutAudit(claim)
	})

	for _, tc := range []struct {
		name      string
		configure func(*f065F066Store)
	}{
		{name: "auth read error", configure: func(s *f065F066Store) { s.fail["GetAdminAuth"] = errors.New("db down") }},
		{name: "missing auth", configure: func(*f065F066Store) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newF065F066Store()
			tc.configure(store)
			h, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
			rec := httptest.NewRecorder()
			if h.requireAPIKeyCreateStepUp(rec, stepUpRequest("irrelevant"), "ci") {
				t.Fatal("unverifiable step-up returned true")
			}
			if !strings.Contains(rec.Header().Get("Location"), "verify") {
				t.Fatalf("Location = %q, want verification error", rec.Header().Get("Location"))
			}
		})
	}

	t.Run("wrong password audit failure counts attempt", func(t *testing.T) {
		store := newF065F066Store()
		store.adminAuth = &db.AdminAuth{PasswordHash: passwordHash}
		store.fail["InsertAdminAuditLog"] = errors.New("audit unavailable")
		h, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
		rec := httptest.NewRecorder()
		if h.requireAPIKeyCreateStepUp(rec, stepUpRequest("wrong-password"), "ci") {
			t.Fatal("wrong-password step-up returned true")
		}
		if got := h.loginAttempts["127.0.0.1"]; got == nil || got.count != 1 {
			t.Fatalf("IP failure accounting = %+v, want count 1", got)
		}
		if got := h.loginAttempts[adminLoginAccountKey]; got == nil || got.count != 1 {
			t.Fatalf("account failure accounting = %+v, want count 1", got)
		}
		if len(store.apiKeys) != 0 || !strings.Contains(rec.Header().Get("Location"), "audit") {
			t.Fatalf("keys/location = %+v %q, want no key and audit error", store.apiKeys, rec.Header().Get("Location"))
		}
	})
}

func TestF066PasswordRejectionAuditFailures(t *testing.T) {
	const currentPassword = "current-password-long-enough"
	passwordHash, err := auth.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	run := func(t *testing.T, store *f065F066Store, values url.Values, locked bool) (*AdminHandler, *auth.SessionManager, *http.Request, *httptest.ResponseRecorder) {
		t.Helper()
		store.adminAuth = &db.AdminAuth{PasswordHash: passwordHash}
		store.fail["InsertAdminAuditLog"] = errors.New("audit unavailable")
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/password", values)
		req.RemoteAddr = "127.0.0.1:12345"
		if locked {
			h.loginAttempts["127.0.0.1"] = &loginAttempt{count: loginMaxAttempts, lockedAt: time.Now()}
		}
		rec := httptest.NewRecorder()
		h.HandlePasswordChange(rec, req)
		return h, sm, req, rec
	}

	t.Run("lockout audit failure", func(t *testing.T) {
		store := newF065F066Store()
		h, sm, req, rec := run(t, store, url.Values{}, true)
		if !strings.Contains(rec.Header().Get("Location"), "audit") || store.adminAuth.PasswordHash != passwordHash || sm.Get(req) == nil {
			t.Fatalf("location/hash/session = %q %t %+v, want audit error and unchanged auth", rec.Header().Get("Location"), store.adminAuth.PasswordHash == passwordHash, sm.Get(req))
		}
		if _, ok := h.claimLockoutAudit("127.0.0.1"); !ok {
			t.Fatal("failed password lockout audit did not release claim")
		}
	})

	t.Run("wrong current password audit failure", func(t *testing.T) {
		store := newF065F066Store()
		h, sm, req, rec := run(t, store, url.Values{
			"current_password": {"wrong-password"},
			"new_password":     {"new-password-long-enough"},
			"confirm_password": {"new-password-long-enough"},
		}, false)
		if !strings.Contains(rec.Header().Get("Location"), "audit") || store.adminAuth.PasswordHash != passwordHash || sm.Get(req) == nil {
			t.Fatalf("location/hash/session = %q %t %+v, want audit error and unchanged auth", rec.Header().Get("Location"), store.adminAuth.PasswordHash == passwordHash, sm.Get(req))
		}
		if got := h.loginAttempts["127.0.0.1"]; got == nil || got.count != 1 {
			t.Fatalf("failure accounting = %+v, want count 1", got)
		}
	})

	t.Run("reused password audit failure", func(t *testing.T) {
		store := newF065F066Store()
		h, sm, req, rec := run(t, store, url.Values{
			"current_password": {currentPassword},
			"new_password":     {currentPassword},
			"confirm_password": {currentPassword},
		}, false)
		if !strings.Contains(rec.Header().Get("Location"), "audit") || store.adminAuth.PasswordHash != passwordHash || sm.Get(req) == nil {
			t.Fatalf("location/hash/session = %q %t %+v, want audit error and unchanged auth", rec.Header().Get("Location"), store.adminAuth.PasswordHash == passwordHash, sm.Get(req))
		}
		if len(h.loginAttempts) != 0 {
			t.Fatalf("password reuse changed failed-attempt accounting: %+v", h.loginAttempts)
		}
	})
}

func TestF066NonceAndAPIKeyPaging(t *testing.T) {
	t.Run("expired and wrong nonce redirects", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			expected string
			newKey   string
			want     string
		}{
			{name: "expired", want: "expired"},
			{name: "wrong", expected: "expected", want: "expired"},
			{name: "retry after success", expected: "expected", newKey: "plaintext", want: "created"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h, sm := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
				req, sess := authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/keys/create")
				req.PostForm = url.Values{apiKeyCreateNonceField: {"submitted"}}
				if tc.expected != "" {
					sm.SetFlash(sess.ID, apiKeyCreateNonceFlashKey, tc.expected)
				}
				if tc.newKey != "" {
					sm.SetFlash(sess.ID, "newkey", tc.newKey)
				}
				rec := httptest.NewRecorder()
				if h.consumeAPIKeyCreateNonce(rec, req, sess) {
					t.Fatal("invalid nonce was accepted")
				}
				if !strings.Contains(strings.ToLower(rec.Header().Get("Location")), tc.want) {
					t.Fatalf("Location = %q, want marker %q", rec.Header().Get("Location"), tc.want)
				}
			})
		}
	})

	t.Run("custom expiry preservation is sanitized", func(t *testing.T) {
		if got := apiKeySelectedExpiryDays(apiKeyExpiresCustomValue); got != 0 {
			t.Fatalf("apiKeySelectedExpiryDays(custom) = %d, want 0", got)
		}
		req := httptest.NewRequest(http.MethodPost, "/admin/keys/create", nil)
		req.PostForm = url.Values{
			"expires_in_days":     {apiKeyExpiresCustomValue},
			"expires_custom_days": {"45"},
		}
		rec := httptest.NewRecorder()
		redirectAPIKeyCreateError(rec, req, "failed", "  CI key  ")
		location, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse Location: %v", err)
		}
		if got := location.Query(); got.Get("name") != "CI key" || got.Get("expires_in_days") != "custom" || got.Get("expires_custom_days") != "45" {
			t.Fatalf("preserved query = %v, want safe custom selection", got)
		}
	})

	t.Run("native page lister receives bounded window", func(t *testing.T) {
		store := newF065F066Store()
		for i := 0; i < adminAPIKeyPageSize+8; i++ {
			store.apiKeys = append(store.apiKeys, db.APIKey{ID: i + 1})
		}
		h := &AdminHandler{store: &f066APIKeyPager{Store: adaptAdminStore(f066DBStoreOnly{Store: store}), source: store}}
		keys, hasNext, err := h.listAPIKeyPage(context.Background(), 7)
		if err != nil || len(keys) != adminAPIKeyPageSize || !hasNext {
			t.Fatalf("page = len %d next %t err %v, want %d/true/nil", len(keys), hasNext, err, adminAPIKeyPageSize)
		}
		if store.apiKeyPageLimit != adminAPIKeyPageSize+1 || store.apiKeyPageOffset != 7 {
			t.Fatalf("pager args = %d/%d, want %d/7", store.apiKeyPageLimit, store.apiKeyPageOffset, adminAPIKeyPageSize+1)
		}
	})

	t.Run("Store-only wrapper uses bounded in-memory fallback", func(t *testing.T) {
		base := newAdminStoreStub()
		for i := 0; i < adminAPIKeyPageSize+5; i++ {
			base.apiKeys = append(base.apiKeys, db.APIKey{ID: i + 1})
		}
		h := &AdminHandler{store: adaptAdminStore(f066DBStoreOnly{Store: base})}
		keys, hasNext, err := h.listAPIKeyPage(context.Background(), adminAPIKeyPageSize)
		if err != nil || len(keys) != 5 || hasNext {
			t.Fatalf("fallback page = len %d next %t err %v, want 5/false/nil", len(keys), hasNext, err)
		}
		keys, hasNext, err = h.listAPIKeyPage(context.Background(), 999)
		if err != nil || len(keys) != 0 || hasNext {
			t.Fatalf("out-of-range page = len %d next %t err %v, want empty/false/nil", len(keys), hasNext, err)
		}
	})
}

func TestF066AdminPageAuthMethodAndRenderFailures(t *testing.T) {
	t.Run("unauthenticated pages do not reach store", func(t *testing.T) {
		h, _ := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
		h.store = f066StoreOnly{}
		for name, handler := range map[string]http.HandlerFunc{
			"feeds":    h.HandleAdminFeeds,
			"scans":    h.HandleAdminScans,
			"keys":     h.HandleAdminKeys,
			"audit":    h.HandleAdminAudit,
			"settings": h.HandleAdminSettings,
		} {
			t.Run(name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				handler(rec, httptest.NewRequest(http.MethodGet, "/admin/"+name, nil))
				if rec.Code != http.StatusSeeOther {
					t.Fatalf("status = %d, want 303", rec.Code)
				}
			})
		}
	})

	t.Run("scans rejects wrong method before auth", func(t *testing.T) {
		h, _ := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
		rec := httptest.NewRecorder()
		h.HandleAdminScans(rec, httptest.NewRequest(http.MethodPost, "/admin/scans", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})

	for _, partial := range []string{"flash", "runtime"} {
		t.Run(partial+" partial render failure", func(t *testing.T) {
			h, sm := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
			h.renderer = f065F066EmptyRenderer()
			req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds?partial="+partial)
			req.Header.Set("HX-Request", "true")
			rec := httptest.NewRecorder()
			h.HandleAdminFeeds(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
		})
	}

	t.Run("full render failure with explicit status", func(t *testing.T) {
		h, _ := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
		h.renderer = f065F066EmptyRenderer()
		rec := httptest.NewRecorder()
		h.renderAdminWithStatus(rec, "admin/settings.html", map[string]any{}, http.StatusTeapot)
		if rec.Code != http.StatusTeapot || !strings.Contains(rec.Body.String(), "internal server error") {
			t.Fatalf("status/body = %d %q, want preserved status and generic render error", rec.Code, rec.Body.String())
		}
	})

	t.Run("bootstrap feed flash render failure", func(t *testing.T) {
		h, sm := newAdminHandlerForStore(t, newF065F066Store(), adminFlowConfig())
		h.renderer = f065F066EmptyRenderer()
		cookieRec := httptest.NewRecorder()
		if _, err := sm.CreateAdmin(cookieRec, true); err != nil {
			t.Fatalf("CreateAdmin: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/admin/feeds/save", nil)
		req.Header.Set("HX-Request", "true")
		for _, cookie := range cookieRec.Result().Cookies() {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		if h.requireBootstrapPasswordRotated(rec, req, "/admin/feeds") {
			t.Fatal("bootstrap session was accepted")
		}
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "internal server error") {
			t.Fatalf("status/body = %d %q, want forbidden render failure", rec.Code, rec.Body.String())
		}
	})
}

func TestF066FeedCountBootstrapAndRetentionBoundaries(t *testing.T) {
	t.Run("unknown count failure is logged without inventing a count", func(t *testing.T) {
		store := newF065F066Store()
		store.unknownCount = 99
		store.unknownCountErr = errors.New("counter unavailable")
		store.adminAuth = &db.AdminAuth{PasswordIsBootstrap: true}
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		var logs bytes.Buffer
		h.logger = slog.New(slog.NewTextHandler(&logs, nil))
		h.renderer = f065F066Renderer("admin/feeds.html", `{{.UnknownSeverityCount}}|{{.BootstrapWarning}}`)
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds")
		rec := httptest.NewRecorder()
		h.HandleAdminFeeds(rec, req)
		if got := strings.TrimSpace(rec.Body.String()); got != "0|true" {
			t.Fatalf("body = %q, want zero count and stored bootstrap warning", got)
		}
		if !strings.Contains(logs.String(), "unknown severity count failed") {
			t.Fatalf("logs = %q, want counter failure", logs.String())
		}
		state := h.adminBootstrapPageState(context.Background(), req, &auth.Session{AuthenticatedWithBootstrap: true}, "test")
		if !state.Warning {
			t.Fatal("session bootstrap warning = false, want true")
		}
	})

	for _, tc := range []struct {
		name      string
		retention time.Duration
		want      int
	}{
		{name: "negative", retention: -time.Hour, want: 0},
		{name: "zero", retention: 0, want: 0},
		{name: "exact day", retention: 24 * time.Hour, want: 1},
		{name: "ceil partial day", retention: 24*time.Hour + time.Nanosecond, want: 2},
		{name: "clamp maximum", retention: (MaxAdminRetentionDays + 1) * 24 * time.Hour, want: MaxAdminRetentionDays},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := retentionDurationDays(tc.retention); got != tc.want {
				t.Fatalf("retentionDurationDays(%s) = %d, want %d", tc.retention, got, tc.want)
			}
		})
	}
}

func TestF066APIKeyAuditMetadataAndURLs(t *testing.T) {
	t.Run("metadata read error and unknown ID", func(t *testing.T) {
		store := newF065F066Store()
		h, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
		store.fail["ListAPIKeys"] = errors.New("read failed")
		if _, err := h.apiKeyAuditDetails(context.Background(), 1); err == nil {
			t.Fatal("metadata read error = nil")
		}
		delete(store.fail, "ListAPIKeys")
		if _, err := h.apiKeyAuditDetails(context.Background(), 404); err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("unknown key error = %v, want ID", err)
		}
	})

	t.Run("all optional timestamps", func(t *testing.T) {
		now := time.Date(2026, time.November, 2, 12, 0, 0, 0, time.FixedZone("test", 2*60*60))
		store := newF065F066Store()
		store.apiKeys = []db.APIKey{
			{ID: 6, Name: "other", CreatedAt: now},
			{
				ID: 7, Name: "ci", CreatedAt: now,
				LastUsedAt: &now, ExpiresAt: &now, RevokedAt: &now, DeletedAt: &now,
			},
		}
		h, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
		details, err := h.apiKeyAuditDetails(context.Background(), 7)
		if err != nil {
			t.Fatalf("apiKeyAuditDetails: %v", err)
		}
		for _, key := range []string{"key_id", "name", "created_at", "last_used_at", "expires_at", "revoked_at", "deleted_at"} {
			if details[key] == "" {
				t.Fatalf("details[%q] is empty: %v", key, details)
			}
		}
		if details["created_at"] != now.UTC().Format(time.RFC3339) {
			t.Fatalf("created_at = %q, want UTC", details["created_at"])
		}
	})

	t.Run("admin key URL combinations", func(t *testing.T) {
		for _, tc := range []struct {
			offset int
			param  string
			value  string
			want   string
		}{
			{want: "/admin/keys"},
			{offset: 100, want: "/admin/keys?offset=100"},
			{param: "err", value: "failed", want: "/admin/keys?err=failed"},
			{offset: 100, param: "msg", value: "done", want: "/admin/keys?msg=done&offset=100"},
		} {
			if got := adminKeysURL(tc.offset, tc.param, tc.value); got != tc.want {
				t.Fatalf("adminKeysURL(%d,%q,%q) = %q, want %q", tc.offset, tc.param, tc.value, got, tc.want)
			}
		}
	})

	t.Run("mutation failure preserves offset and state", func(t *testing.T) {
		store := newF065F066Store()
		store.apiKeys = []db.APIKey{{ID: 1, Name: "ci", CreatedAt: time.Now().UTC()}}
		store.fail["RevokeAPIKey"] = errors.New("mutation failed")
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/keys/revoke", url.Values{
			"key_id":        {"1"},
			"return_offset": {"100"},
		})
		rec := httptest.NewRecorder()
		h.HandleKeyRevoke(rec, req)
		location, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse Location: %v", err)
		}
		if location.Query().Get("offset") != "100" || location.Query().Get("err") == "" || store.apiKeys[0].RevokedAt != nil {
			t.Fatalf("location/key = %q %+v, want offset/error and no mutation", rec.Header().Get("Location"), store.apiKeys[0])
		}
	})
}

func TestF066AuditFallbackAndIntegrityPresentation(t *testing.T) {
	t.Run("legacy fallback is bounded and refuses positive offset", func(t *testing.T) {
		base := newAdminStoreStub()
		for i := 0; i < adminAuditPageSize+1; i++ {
			base.audit = append(base.audit, db.AdminAuditLogEntry{ID: i + 1})
		}
		h := &AdminHandler{store: f066StoreOnly{Store: adaptAdminStore(f066DBStoreOnly{Store: base})}}
		entries, hasNext, err := h.listAdminAuditPage(context.Background(), 0)
		if err != nil || len(entries) != adminAuditPageSize || !hasNext {
			t.Fatalf("fallback page = len %d next %t err %v, want %d/true/nil", len(entries), hasNext, err, adminAuditPageSize)
		}
		if _, _, err := h.listAdminAuditPage(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "pagination") {
			t.Fatalf("positive-offset error = %v, want explicit pagination error", err)
		}
	})

	t.Run("integrity labels classes and action classes", func(t *testing.T) {
		for _, tc := range []struct {
			status    string
			wantLabel string
			wantClass string
		}{
			{status: db.AdminAuditIntegrityVerified, wantLabel: "Verified", wantClass: "pm-badge-status-healthy"},
			{status: db.AdminAuditIntegrityBroken, wantLabel: "Broken", wantClass: "pm-badge-status-error"},
			{status: "", wantLabel: "Legacy", wantClass: "pm-badge-status-default"},
		} {
			if got := adminAuditIntegrityLabel(tc.status); got != tc.wantLabel {
				t.Fatalf("label(%q) = %q, want %q", tc.status, got, tc.wantLabel)
			}
			if got := adminAuditIntegrityClass(tc.status); got != tc.wantClass {
				t.Fatalf("class(%q) = %q, want %q", tc.status, got, tc.wantClass)
			}
		}
		for action, want := range map[string]string{
			"login_success": "pm-badge-status-configured",
			"login_failed":  "pm-badge-status-error",
			"login_lockout": "pm-badge-status-warning",
			"other":         "pm-badge-status-default",
		} {
			if got := (auditLogView{AdminAuditLogEntry: db.AdminAuditLogEntry{Action: action}}).ActionClass(); got != want {
				t.Fatalf("ActionClass(%q) = %q, want %q", action, got, want)
			}
		}
	})

	t.Run("empty and null details render as dash", func(t *testing.T) {
		store := newF065F066Store()
		store.audit = []db.AdminAuditLogEntry{
			{ID: 1, Details: nil},
			{ID: 2, Details: []byte("null")},
		}
		h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		h.renderer = f065F066Renderer("admin/audit.html", `{{range .Entries}}{{.DetailsStr}}|{{end}}`)
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/audit")
		rec := httptest.NewRecorder()
		h.HandleAdminAudit(rec, req)
		if got := strings.TrimSpace(rec.Body.String()); got != "-|-|" {
			t.Fatalf("audit details body = %q, want dashes", got)
		}
	})
}
