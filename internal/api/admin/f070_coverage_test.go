package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/web"
)

type f070SettingsStore struct {
	*adminFlowStoreStub
	getErr        error
	upsertErr     error
	getCalls      int
	upsertCalls   int
	lastSubmitted *db.SystemSettings
}

func (s *f070SettingsStore) GetSystemSettings(ctx context.Context) (*db.SystemSettings, error) {
	s.mu.Lock()
	s.getCalls++
	err := s.getErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.adminFlowStoreStub.GetSystemSettings(ctx)
}

func (s *f070SettingsStore) UpsertSystemSettingsWithAudit(ctx context.Context, settings *db.SystemSettings, audit *db.AdminAuditEntry) error {
	s.mu.Lock()
	s.upsertCalls++
	s.lastSubmitted = cloneF070Settings(settings)
	err := s.upsertErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.adminFlowStoreStub.UpsertSystemSettingsWithAudit(ctx, settings, audit)
}

type f070RuntimeSnapshot struct {
	blockThreshold      string
	rateLimitPerMinute  int
	rateLimitBurst      int
	scanLogRetention    time.Duration
	adminAuditRetention time.Duration
}

func TestSystemSettingsParsingAndFallbackBoundaries(t *testing.T) {
	t.Parallel()

	const key = "retention"
	fallback := 17 * adminRetentionDay
	retentionCases := []struct {
		name   string
		values url.Values
		want   time.Duration
		ok     bool
	}{
		{name: "omitted", values: url.Values{}, want: fallback, ok: true},
		{name: "empty slice", values: url.Values{key: []string{}}, ok: false},
		{name: "blank", values: url.Values{key: {" \t"}}, ok: false},
		{name: "nonnumeric", values: url.Values{key: {"many"}}, ok: false},
		{name: "negative", values: url.Values{key: {"-1"}}, ok: false},
		{name: "over maximum", values: url.Values{key: {strconv.Itoa(MaxAdminRetentionDays + 1)}}, ok: false},
		{name: "zero", values: url.Values{key: {"0"}}, want: 0, ok: true},
		{name: "maximum", values: url.Values{key: {strconv.Itoa(MaxAdminRetentionDays)}}, want: MaxAdminRetentionDays * adminRetentionDay, ok: true},
	}
	for _, tc := range retentionCases {
		t.Run("retention "+tc.name, func(t *testing.T) {
			got, ok := parseRetentionDaysSetting(tc.values, key, fallback)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("parseRetentionDaysSetting() = %v, %v, want %v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}

	for _, raw := range []string{"1", " true ", "YeS", "ON"} {
		if !acknowledgedSetting(raw) {
			t.Errorf("acknowledgedSetting(%q) = false, want true", raw)
		}
	}
	for _, raw := range []string{"", "0", "false", "no", "off", "truthy"} {
		if acknowledgedSetting(raw) {
			t.Errorf("acknowledgedSetting(%q) = true, want false", raw)
		}
	}

	for _, raw := range []string{"", " \t"} {
		got, ok := parseAdminFormRevision(raw)
		if !ok || !got.IsZero() {
			t.Errorf("parseAdminFormRevision(%q) = %v, %v, want zero, true", raw, got, ok)
		}
	}
	if _, ok := parseAdminFormRevision("not-a-revision"); ok {
		t.Fatal("parseAdminFormRevision(malformed) ok = true")
	}
	offsetRevision := "2026-08-09T11:12:13.123456789+02:30"
	wantRevision := time.Date(2026, 8, 9, 8, 42, 13, 123456789, time.UTC)
	if got, ok := parseAdminFormRevision(offsetRevision); !ok || !got.Equal(wantRevision) || got.Location() != time.UTC {
		t.Fatalf("parseAdminFormRevision(offset) = %v, %v, want %v UTC", got, ok, wantRevision)
	}

	if scan, audit := (*AdminHandler)(nil).effectiveSystemMetadataRetention(nil); scan != adminMetadataRetentionDefault || audit != adminMetadataRetentionDefault {
		t.Fatalf("nil handler retention = %v/%v, want defaults", scan, audit)
	}
	cfg := adminFlowConfig()
	cfg.Retention.ScanLog = 11 * adminRetentionDay
	cfg.Retention.AdminAuditLog = 12 * adminRetentionDay
	h := &AdminHandler{cfg: cfg}
	if scan, audit := h.effectiveSystemMetadataRetention(nil); scan != 11*adminRetentionDay || audit != 12*adminRetentionDay {
		t.Fatalf("config retention = %v/%v, want 11d/12d", scan, audit)
	}
	runtime := config.NewRuntimeSettings("HIGH", 70, 8)
	runtime.UpdateRetention(21*adminRetentionDay, 22*adminRetentionDay)
	h.runtime = runtime
	if scan, audit := h.effectiveSystemMetadataRetention(nil); scan != 21*adminRetentionDay || audit != 22*adminRetentionDay {
		t.Fatalf("runtime retention = %v/%v, want 21d/22d", scan, audit)
	}
	previous := &db.SystemSettings{ScanLogRetention: 31 * adminRetentionDay, AdminAuditRetention: 32 * adminRetentionDay}
	if scan, audit := h.effectiveSystemMetadataRetention(previous); scan != 31*adminRetentionDay || audit != 32*adminRetentionDay {
		t.Fatalf("previous retention = %v/%v, want 31d/32d", scan, audit)
	}
	previous.ScanLogRetention = -1
	previous.AdminAuditRetention = -1
	if scan, audit := h.effectiveSystemMetadataRetention(previous); scan != 21*adminRetentionDay || audit != 22*adminRetentionDay {
		t.Fatalf("negative previous retention = %v/%v, want runtime fallback", scan, audit)
	}
	previous.ScanLogRetention = 0
	previous.AdminAuditRetention = 0
	if scan, audit := h.effectiveSystemMetadataRetention(previous); scan != 0 || audit != 0 {
		t.Fatalf("zero previous retention = %v/%v, want zero", scan, audit)
	}
	cfg.Retention.ScanLog = -1
	cfg.Retention.AdminAuditLog = -1
	h = &AdminHandler{cfg: cfg}
	if scan, audit := h.effectiveSystemMetadataRetention(nil); scan != adminMetadataRetentionDefault || audit != adminMetadataRetentionDefault {
		t.Fatalf("negative config retention = %v/%v, want defaults", scan, audit)
	}
	cfg.Retention.ScanLog = 0
	cfg.Retention.AdminAuditLog = 0
	if scan, audit := h.effectiveSystemMetadataRetention(nil); scan != 0 || audit != 0 {
		t.Fatalf("zero config retention = %v/%v, want zero", scan, audit)
	}
}

func TestHandleSystemSettingsSaveRejectsLoadAndMalformedInputsWithoutMutation(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*f070SettingsStore, url.Values)
		message   string
	}{
		{
			name: "load failure",
			configure: func(store *f070SettingsStore, _ url.Values) {
				store.getErr = errors.New("settings unavailable")
			},
			message: web.Message("admin.settings.error.load_system_settings"),
		},
		{
			name: "invalid scan retention",
			configure: func(_ *f070SettingsStore, values url.Values) {
				values.Set("scan_log_retention_days", "invalid")
			},
			message: web.Message("admin.settings.error.invalid_scan_log_retention"),
		},
		{
			name: "invalid audit retention",
			configure: func(_ *f070SettingsStore, values url.Values) {
				values.Set("admin_audit_retention_days", "-1")
			},
			message: web.Message("admin.settings.error.invalid_admin_audit_retention"),
		},
		{
			name: "malformed revision",
			configure: func(_ *f070SettingsStore, values url.Values) {
				values.Set("updated_at", "not-a-revision")
			},
			message: web.Message("admin.settings.error.invalid_revision"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			previous := f070Settings("LOW", 71, 17, 9, 10)
			store := &f070SettingsStore{adminFlowStoreStub: newAdminStoreStub()}
			store.systemSettings = cloneF070Settings(previous)
			handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
			beforeRuntime := snapshotF070Runtime(handler.runtime)
			values := f070ValidSettingsForm()
			tc.configure(store, values)

			rec := saveF070Settings(t, handler, sm, values)
			assertF070Redirect(t, rec, tc.message, true)
			assertF070Unchanged(t, store, handler, previous, beforeRuntime)
		})
	}
}

func TestHandleSystemSettingsSaveRetentionRevisionAndNilRuntime(t *testing.T) {
	maxDays := MaxAdminRetentionDays
	tests := []struct {
		name         string
		previous     *db.SystemSettings
		values       url.Values
		nilRuntime   bool
		wantScan     time.Duration
		wantAudit    time.Duration
		wantRevision *time.Time
	}{
		{
			name:     "omitted retention preserves previous",
			previous: f070Settings("LOW", 71, 17, 12, 13),
			values:   f070ValidSettingsFormWithoutRetention(),
			wantScan: 12 * adminRetentionDay, wantAudit: 13 * adminRetentionDay,
		},
		{
			name:     "zero disables pruning",
			previous: f070Settings("LOW", 71, 17, 12, 13),
			values:   f070ValidSettingsFormWithRetention("0", "0"),
			wantScan: 0, wantAudit: 0,
		},
		{
			name:     "maximum retention succeeds",
			previous: f070Settings("LOW", 71, 17, 12, 13),
			values:   f070ValidSettingsFormWithRetention(strconv.Itoa(maxDays), strconv.Itoa(maxDays)),
			wantScan: time.Duration(maxDays) * adminRetentionDay, wantAudit: time.Duration(maxDays) * adminRetentionDay,
		},
		{
			name: "offset revision matches UTC row",
			previous: func() *db.SystemSettings {
				settings := f070Settings("LOW", 71, 17, 12, 13)
				settings.UpdatedAt = time.Date(2026, 8, 9, 8, 42, 13, 123456000, time.UTC)
				return settings
			}(),
			values: func() url.Values {
				values := f070ValidSettingsFormWithRetention("15", "16")
				values.Set("updated_at", "2026-08-09T11:12:13.123456+02:30")
				return values
			}(),
			wantScan: 15 * adminRetentionDay, wantAudit: 16 * adminRetentionDay,
			wantRevision: func() *time.Time {
				revision := time.Date(2026, 8, 9, 8, 42, 13, 123456000, time.UTC)
				return &revision
			}(),
		},
		{
			name:       "nil runtime commits directly",
			previous:   nil,
			values:     f070ValidSettingsFormWithRetention("7", "8"),
			nilRuntime: true,
			wantScan:   7 * adminRetentionDay, wantAudit: 8 * adminRetentionDay,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &f070SettingsStore{adminFlowStoreStub: newAdminStoreStub()}
			store.systemSettings = cloneF070Settings(tc.previous)
			handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
			if tc.nilRuntime {
				handler.runtime = nil
			}

			rec := saveF070Settings(t, handler, sm, tc.values)
			assertF070Redirect(t, rec, web.Message("admin.settings.flash.saved"), false)
			stored, err := store.GetSystemSettings(context.Background())
			if err != nil {
				t.Fatalf("GetSystemSettings() error = %v", err)
			}
			if stored == nil || stored.BlockThreshold != "HIGH" || stored.RateLimitPerMinute != 120 || stored.RateLimitBurst != 25 ||
				stored.ScanLogRetention != tc.wantScan || stored.AdminAuditRetention != tc.wantAudit || stored.ExpectedUpdatedAt != nil {
				t.Fatalf("stored settings = %+v, want HIGH 120/25 %v/%v without expected revision", stored, tc.wantScan, tc.wantAudit)
			}
			if store.lastSubmitted == nil {
				t.Fatal("store did not receive submitted settings")
			}
			if tc.wantRevision == nil {
				if store.lastSubmitted.ExpectedUpdatedAt != nil {
					t.Fatalf("submitted expected revision = %v, want nil", store.lastSubmitted.ExpectedUpdatedAt)
				}
			} else if store.lastSubmitted.ExpectedUpdatedAt == nil ||
				!store.lastSubmitted.ExpectedUpdatedAt.Equal(*tc.wantRevision) ||
				store.lastSubmitted.ExpectedUpdatedAt.Location() != time.UTC {
				t.Fatalf("submitted expected revision = %v, want %v UTC", store.lastSubmitted.ExpectedUpdatedAt, *tc.wantRevision)
			}
			assertF070SingleSettingsAudit(t, store, tc.previous, stored)
			if !tc.nilRuntime {
				assertF070Runtime(t, handler.runtime, f070RuntimeSnapshot{
					blockThreshold: "HIGH", rateLimitPerMinute: 120, rateLimitBurst: 25,
					scanLogRetention: tc.wantScan, adminAuditRetention: tc.wantAudit,
				})
			}
		})
	}
}

func TestHandleSystemSettingsSaveAliasesAndUnsetAuditDetails(t *testing.T) {
	store := &f070SettingsStore{adminFlowStoreStub: newAdminStoreStub()}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
	values := url.Values{
		"block_threshold":            {" none "},
		"ack_block_threshold_none":   {" YeS "},
		"rate_limit_per_minute":      {" 120 "},
		"rate_limit_burst":           {" 25 "},
		"scan_log_retention_days":    {" 7 "},
		"admin_audit_retention_days": {" 8 "},
	}

	rec := saveF070Settings(t, handler, sm, values)
	assertF070Redirect(t, rec, web.Message("admin.settings.flash.saved"), false)
	if len(store.audit) != 1 || store.audit[0].Action != "system_settings_save" {
		t.Fatalf("audit entries = %+v, want exactly one system_settings_save", store.audit)
	}
	want := map[string]string{
		"previous_block_threshold":       "unset",
		"previous_rate_limit_per_minute": "unset",
		"previous_rate_limit_burst":      "unset",
		"previous_scan_log_retention":    "unset",
		"previous_admin_audit_retention": "unset",
		"new_block_threshold":            "NONE",
		"new_rate_limit_per_minute":      "120",
		"new_rate_limit_burst":           "25",
		"new_scan_log_retention":         (7 * adminRetentionDay).String(),
		"new_admin_audit_retention":      (8 * adminRetentionDay).String(),
	}
	assertF070ExactAuditDetails(t, store.audit[0], want)
}

func TestHandleSystemSettingsSaveFailuresPreserveEntireRuntime(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		message string
	}{
		{name: "audit", err: errors.Join(db.ErrAdminAuditLog, errors.New("audit unavailable")), message: web.Message("admin.settings.error.audit_log")},
		{name: "persist", err: errors.New("settings unavailable"), message: web.Message("admin.settings.error.save")},
		{name: "conflict", err: db.ErrConflict, message: web.Message("admin.settings.error.conflict")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			previous := f070Settings("MEDIUM", 81, 19, 18, 19)
			previous.UpdatedAt = time.Date(2026, 8, 1, 2, 3, 4, 5000, time.UTC)
			store := &f070SettingsStore{adminFlowStoreStub: newAdminStoreStub(), upsertErr: tc.err}
			store.systemSettings = cloneF070Settings(previous)
			handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
			handler.runtime.Update("LOW", 77, 18)
			handler.runtime.UpdateRetention(16*adminRetentionDay, 17*adminRetentionDay)
			beforeRuntime := snapshotF070Runtime(handler.runtime)
			values := f070ValidSettingsFormWithRetention("1", "2")
			values.Set("updated_at", previous.UpdatedAt.Format(time.RFC3339Nano))

			rec := saveF070Settings(t, handler, sm, values)
			assertF070Redirect(t, rec, tc.message, true)
			if store.upsertCalls != 1 {
				t.Fatalf("upsert calls = %d, want exactly 1 failed attempt", store.upsertCalls)
			}
			assertF070Unchanged(t, store, handler, previous, beforeRuntime)
		})
	}
}

func TestHandleSystemSettingsSaveEnforcesAuthenticationAndFormLimit(t *testing.T) {
	t.Run("unauthenticated", func(t *testing.T) {
		store := &f070SettingsStore{adminFlowStoreStub: newAdminStoreStub()}
		handler, _ := newAdminHandlerForStore(t, store, adminFlowConfig())
		beforeRuntime := snapshotF070Runtime(handler.runtime)
		values := f070ValidSettingsForm()
		req := httptest.NewRequest(http.MethodPost, "/admin/settings/system", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler.HandleSystemSettingsSave(rec, req)

		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login" {
			t.Fatalf("unauthenticated response = %d %q, want 303 /admin/login", rec.Code, rec.Header().Get("Location"))
		}
		if store.getCalls != 0 || store.upsertCalls != 0 || len(store.audit) != 0 {
			t.Fatalf("unauthenticated store calls = get %d upsert %d audit %d, want none", store.getCalls, store.upsertCalls, len(store.audit))
		}
		assertF070Runtime(t, handler.runtime, beforeRuntime)
	})

	t.Run("oversized authenticated form", func(t *testing.T) {
		store := &f070SettingsStore{adminFlowStoreStub: newAdminStoreStub()}
		handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
		beforeRuntime := snapshotF070Runtime(handler.runtime)
		cookieRec := httptest.NewRecorder()
		sess, err := sm.CreateAdmin(cookieRec, false)
		if err != nil {
			t.Fatalf("CreateAdmin() error = %v", err)
		}
		token, err := auth.CSRFToken(sess)
		if err != nil {
			t.Fatalf("CSRFToken() error = %v", err)
		}
		body := auth.CSRFFieldName + "=" + url.QueryEscape(token) + "&padding=" + strings.Repeat("x", maxAdminFormBytes)
		req := httptest.NewRequest(http.MethodPost, "/admin/settings/system", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range cookieRec.Result().Cookies() {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		handler.HandleSystemSettingsSave(rec, req)

		assertF070Redirect(t, rec, adminInvalidFormMessage, true)
		if store.getCalls != 0 || store.upsertCalls != 0 || len(store.audit) != 0 {
			t.Fatalf("oversized form store calls = get %d upsert %d audit %d, want none", store.getCalls, store.upsertCalls, len(store.audit))
		}
		assertF070Runtime(t, handler.runtime, beforeRuntime)
	})
}

func f070Settings(threshold string, perMinute, burst, scanDays, auditDays int) *db.SystemSettings {
	return &db.SystemSettings{
		BlockThreshold: threshold, RateLimitPerMinute: perMinute, RateLimitBurst: burst,
		ScanLogRetention:    time.Duration(scanDays) * adminRetentionDay,
		AdminAuditRetention: time.Duration(auditDays) * adminRetentionDay,
	}
}

func cloneF070Settings(settings *db.SystemSettings) *db.SystemSettings {
	if settings == nil {
		return nil
	}
	copyValue := *settings
	if settings.ExpectedUpdatedAt != nil {
		revision := *settings.ExpectedUpdatedAt
		copyValue.ExpectedUpdatedAt = &revision
	}
	return &copyValue
}

func f070ValidSettingsForm() url.Values {
	return f070ValidSettingsFormWithRetention("7", "8")
}

func f070ValidSettingsFormWithoutRetention() url.Values {
	return url.Values{
		"block_threshold":       {"HIGH"},
		"rate_limit_per_minute": {"120"},
		"rate_limit_burst":      {"25"},
	}
}

func f070ValidSettingsFormWithRetention(scan, audit string) url.Values {
	values := f070ValidSettingsFormWithoutRetention()
	values.Set("scan_log_retention_days", scan)
	values.Set("admin_audit_retention_days", audit)
	return values
}

func saveF070Settings(t *testing.T, handler *AdminHandler, sm *auth.SessionManager, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", values)
	rec := httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	return rec
}

func snapshotF070Runtime(runtime *config.RuntimeSettings) f070RuntimeSnapshot {
	perMinute, burst := runtime.RateLimit()
	retention := runtime.Retention()
	return f070RuntimeSnapshot{
		blockThreshold: runtime.BlockThreshold(), rateLimitPerMinute: perMinute, rateLimitBurst: burst,
		scanLogRetention: retention.ScanLog, adminAuditRetention: retention.AdminAuditLog,
	}
}

func assertF070Runtime(t *testing.T, runtime *config.RuntimeSettings, want f070RuntimeSnapshot) {
	t.Helper()
	if got := snapshotF070Runtime(runtime); got != want {
		t.Fatalf("runtime = %+v, want %+v", got, want)
	}
}

func assertF070Redirect(t *testing.T, rec *httptest.ResponseRecorder, message string, isError bool) {
	t.Helper()
	key := "msg"
	if isError {
		key = "err"
	}
	want := "/admin/settings?" + key + "=" + url.QueryEscape(message)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
		t.Fatalf("response = %d %q, want 303 %q", rec.Code, rec.Header().Get("Location"), want)
	}
}

func assertF070Unchanged(t *testing.T, store *f070SettingsStore, handler *AdminHandler, wantSettings *db.SystemSettings, wantRuntime f070RuntimeSnapshot) {
	t.Helper()
	stored, err := store.adminFlowStoreStub.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if !reflect.DeepEqual(stored, wantSettings) {
		t.Fatalf("stored settings = %+v, want unchanged %+v", stored, wantSettings)
	}
	if store.upsertCalls != 0 && store.upsertErr == nil {
		t.Fatalf("successful upsert calls = %d, want none", store.upsertCalls)
	}
	if len(store.audit) != 0 {
		t.Fatalf("audit entries = %+v, want none", store.audit)
	}
	assertF070Runtime(t, handler.runtime, wantRuntime)
}

func assertF070SingleSettingsAudit(t *testing.T, store *f070SettingsStore, previous, next *db.SystemSettings) {
	t.Helper()
	if len(store.audit) != 1 || store.audit[0].Action != "system_settings_save" {
		t.Fatalf("audit entries = %+v, want exactly one system_settings_save", store.audit)
	}
	want := systemSettingsAuditDetails(previous, next)
	assertF070ExactAuditDetails(t, store.audit[0], want)
}

func assertF070ExactAuditDetails(t *testing.T, entry db.AdminAuditLogEntry, want map[string]string) {
	t.Helper()
	var got map[string]string
	if err := json.Unmarshal(entry.Details, &got); err != nil {
		t.Fatalf("audit details JSON = %q: %v", string(entry.Details), err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("audit details = %v, want exactly %v", got, want)
	}
}
