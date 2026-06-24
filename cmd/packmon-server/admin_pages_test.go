package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/api/admin"
	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/web"
)

func TestAdminFeedsPageShowsRuntimeConfig(t *testing.T) {
	store := newNoopStore()
	now := time.Now().UTC()
	duration := 2 * time.Second
	if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{
		FeedName:         "ghsa",
		LastSyncAt:       &now,
		LastSyncDuration: &duration,
		LastSyncStatus:   "success",
		EntriesSynced:    12,
		EntriesTotal:     42,
	}); err != nil {
		t.Fatalf("upsert feed sync status: %v", err)
	}
	runningStarted := now.Add(-2 * time.Minute)
	if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{
		FeedName:       "osv",
		LastSyncAt:     &runningStarted,
		LastSyncStatus: "running",
		EntriesSynced:  12,
		EntriesTotal:   42,
	}); err != nil {
		t.Fatalf("upsert running feed sync status: %v", err)
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds")
	rec := httptest.NewRecorder()

	handler.HandleAdminFeeds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/feeds status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"Current Runtime",
		"Saved Configuration",
		"GHSA",
		"OpenSSF Malicious",
		"external",
		"15m (default)",
		"success",
		"running for",
		"2s",
		"VulnCheck",
		"configured",
		"Sync now",
		"Socket.dev",
		"ReversingLabs",
		"disabled",
		"not configured",
		"PACKMON_FEED_*",
		`src="/static/auto-refresh.js"`,
		`data-auto-refresh-control`,
		`data-auto-refresh-event="admin-feed-runtime-refresh"`,
		`aria-controls="admin-feed-runtime"`,
		`Pause auto-refresh`,
		`hx-trigger="admin-feed-runtime-refresh from:body, feed-runtime-refresh from:body"`,
		`id="admin-feed-flash"`,
		`aria-live="polite"`,
		`aria-atomic="true"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/feeds body missing %q\nbody=%s", want, body)
		}
	}
	if strings.Contains(body, `every 10s`) {
		t.Fatalf("GET /admin/feeds still uses direct interval polling without pause control\nbody=%s", body)
	}
	rlRowStart := strings.Index(body, `data-feed-key="reversinglabs"`)
	if rlRowStart < 0 {
		t.Fatalf("GET /admin/feeds body missing ReversingLabs editable row\nbody=%s", body)
	}
	rlRowEnd := strings.Index(body[rlRowStart+1:], `data-feed-key="`)
	if rlRowEnd < 0 {
		rlRowEnd = len(body) - rlRowStart
	} else {
		rlRowEnd++
	}
	rlRow := body[rlRowStart : rlRowStart+rlRowEnd]
	if strings.Contains(rlRow, `value="external"`) {
		t.Fatalf("ReversingLabs row rendered unsupported external option: %s", rlRow)
	}
}

func TestAdminFeedsPageShowsQueueDrivenFeedConfiguredWithoutSyncStatus(t *testing.T) {
	store := newNoopStore()
	cfg := testAdminConfig()
	cfg.Feeds.ReversingLabsEnabled = true
	cfg.Feeds.ReversingLabsAPIKey = testFeedToken()

	handler, sm := newAdminTestHandler(t, store, cfg)
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/feeds?partial=runtime")
	rec := httptest.NewRecorder()

	handler.HandleAdminFeeds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/feeds partial status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	rlRow := tableRowContaining(body, "ReversingLabs")
	if rlRow == "" {
		t.Fatalf("GET /admin/feeds runtime body missing ReversingLabs row\nbody=%s", body)
	}
	if strings.Contains(rlRow, ">pending</span>") {
		t.Fatalf("ReversingLabs runtime row status = pending, want configured\nrow=%s", rlRow)
	}
	configuredStatus := regexp.MustCompile(`(?s)<td class="px-5 py-2">\s*<span[^>]*>configured</span>\s*</td>`)
	if !configuredStatus.MatchString(rlRow) {
		t.Fatalf("ReversingLabs runtime row missing configured status\nrow=%s", rlRow)
	}
}

func TestAdminSettingsPageShowsRuntimeValues(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings")
	rec := httptest.NewRecorder()

	handler.HandleAdminSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/settings status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"development",
		"15m",
		"45m",
		"127.0.0.1:9100",
		"db.internal",
		"packmon_test",
		"disable",
		"never",
		`name="ack_block_threshold_none"`,
		"Vulnerability Block Threshold",
		`aria-describedby="block-threshold-help block-threshold-runtime"`,
		"NONE disables vulnerability blocking",
		"NONE - do not block vulnerabilities",
		"Malicious and active supply-chain risk findings always block regardless of this threshold.",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/settings body missing %q\nbody=%s", want, body)
		}
	}
	if strings.Contains(body, "0001-01-01") {
		t.Fatalf("GET /admin/settings body contains zero timestamp: %s", body)
	}
}

func TestAdminSettingsServerInfoValuesWrapOnNarrowViewports(t *testing.T) {
	store := newNoopStore()
	cfg := testAdminConfig()
	cfg.Metrics.Host = "metrics-" + strings.Repeat("very-long-segment-", 8) + "internal.example.test"
	cfg.DB.Host = "postgres-" + strings.Repeat("cluster-endpoint-", 8) + "internal.example.test"
	cfg.DB.Name = "packmon_" + strings.Repeat("tenant_", 10) + "production"
	handler, sm := newAdminTestHandler(t, store, cfg)
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings")
	rec := httptest.NewRecorder()

	handler.HandleAdminSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/settings status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`class="flex justify-between gap-3 sm:block"`,
		`class="min-w-0 break-words text-right font-medium sm:text-left"`,
		cfg.Metrics.Addr(),
		cfg.DB.Host,
		cfg.DB.Name,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/settings body missing responsive server-info marker %q\nbody=%s", want, body)
		}
	}
}

func TestAdminSettingsPasswordFormUsesServerMinimumLength(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings")
	rec := httptest.NewRecorder()

	handler.HandleAdminSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/settings status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `id="password-length-help"`) ||
		!strings.Contains(body, "Use at least 12 characters.") {
		t.Fatalf("GET /admin/settings body missing password length help text\nbody=%s", body)
	}
	for _, field := range []string{`name="new_password"`, `name="confirm_password"`} {
		start := strings.Index(body, field)
		if start < 0 {
			t.Fatalf("GET /admin/settings body missing %s\nbody=%s", field, body)
		}
		inputEnd := strings.Index(body[start:], ">")
		if inputEnd < 0 {
			t.Fatalf("GET /admin/settings input %s is not closed\nbody=%s", field, body)
		}
		input := body[start : start+inputEnd]
		if !strings.Contains(input, `minlength="12"`) {
			t.Fatalf("GET /admin/settings input %s = %s, want minlength 12", field, input)
		}
		if !strings.Contains(input, `aria-describedby="password-length-help"`) {
			t.Fatalf("GET /admin/settings input %s = %s, want password help association", field, input)
		}
	}
}

func TestAdminKeysExpiryHelpIsProgrammaticallyAssociated(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/keys")
	rec := httptest.NewRecorder()

	handler.HandleAdminKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/keys status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `id="key-expires-at-help"`) ||
		!strings.Contains(body, "Use RFC3339 UTC") ||
		!strings.Contains(body, "Maximum lifetime is 90 days") {
		t.Fatalf("GET /admin/keys body missing expiry help text\nbody=%s", body)
	}
	idStart := strings.Index(body, `id="key-expires-at"`)
	if idStart < 0 {
		t.Fatalf("GET /admin/keys body missing expiry input\nbody=%s", body)
	}
	start := strings.LastIndex(body[:idStart], "<input")
	if start < 0 {
		t.Fatalf("GET /admin/keys expiry id is not inside an input\nbody=%s", body)
	}
	inputEnd := strings.Index(body[start:], ">")
	if inputEnd < 0 {
		t.Fatalf("GET /admin/keys expiry input is not closed\nbody=%s", body)
	}
	input := body[start : start+inputEnd]
	if !strings.Contains(input, `aria-describedby="key-expires-at-help"`) {
		t.Fatalf("GET /admin/keys expiry input = %s, want help association", input)
	}
	for _, want := range []string{
		`type="text"`,
		`placeholder="2026-06-19T15:00:00Z"`,
	} {
		if !strings.Contains(input, want) {
			t.Fatalf("GET /admin/keys expiry input = %s, want %s", input, want)
		}
	}
	if strings.Contains(input, `type="datetime-local"`) {
		t.Fatalf("GET /admin/keys expiry input still uses datetime-local: %s", input)
	}

	nameIDStart := strings.Index(body, `id="key-name"`)
	if nameIDStart < 0 {
		t.Fatalf("GET /admin/keys body missing key name input\nbody=%s", body)
	}
	nameStart := strings.LastIndex(body[:nameIDStart], "<input")
	if nameStart < 0 {
		t.Fatalf("GET /admin/keys key name id is not inside an input\nbody=%s", body)
	}
	nameEnd := strings.Index(body[nameStart:], ">")
	if nameEnd < 0 {
		t.Fatalf("GET /admin/keys key name input is not closed\nbody=%s", body)
	}
	nameInput := body[nameStart : nameStart+nameEnd]
	for _, want := range []string{
		`dir="auto"`,
		`maxlength="128"`,
		`aria-describedby="key-name-help"`,
	} {
		if !strings.Contains(nameInput, want) {
			t.Fatalf("GET /admin/keys key name input = %s, want %s", nameInput, want)
		}
	}
	if !strings.Contains(body, `name="current_password"`) || !strings.Contains(body, `autocomplete="current-password"`) {
		t.Fatalf("GET /admin/keys body missing current password step-up field\nbody=%s", body)
	}
}

func TestAdminSettingsPasswordFormHasDuplicateSubmitGuard(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings")
	rec := httptest.NewRecorder()

	handler.HandleAdminSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/settings status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`action="/admin/settings/password"`,
		`data-submit-lock`,
		`data-submit-lock-button`,
		`data-submit-lock-label="Changing password"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/settings body missing %q\nbody=%s", want, body)
		}
	}
}

func TestAdminLoginExposesPrivacyNoticeLinks(t *testing.T) {
	store := newNoopStore()
	cfg := testAdminConfig()
	cfg.Web.PrivacyURL = "/privacy"
	cfg.Web.LegalURL = "https://example.test/legal"
	handler, _ := newAdminTestHandler(t, store, cfg)

	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	rec := httptest.NewRecorder()
	handler.HandleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/login status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`href="/privacy"`,
		`Privacy`,
		`href="https://example.test/legal"`,
		`Legal Notice`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/login body missing %q\nbody=%s", want, body)
		}
	}
}

func TestAdminLoginUnconfiguredStateShowsRecoveryInstructions(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())

	preAuthRec := httptest.NewRecorder()
	sess, err := sm.CreatePreAuth(preAuthRec)
	if err != nil {
		t.Fatalf("CreatePreAuth() error = %v", err)
	}
	csrfToken, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken() error = %v", err)
	}

	form := url.Values{
		"username": {"admin"},
		"password": {"secret"},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range preAuthRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.HandleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /admin/login status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Admin account has not been configured.",
		"PACKMON_ADMIN_INITIAL_PASSWORD",
		"restart the server",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("unconfigured login body missing %q\nbody=%s", want, body)
		}
	}
	if strings.Contains(body, "secret") {
		t.Fatalf("unconfigured login body leaked submitted password\nbody=%s", body)
	}
}

func TestAdminWritePagesShowBootstrapRecoveryAndSuppressWriteControls(t *testing.T) {
	store := newNoopStore()
	hash, err := auth.HashPassword("bootstrap-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if err := store.UpsertAdminAuth(context.Background(), hash, true); err != nil {
		t.Fatalf("UpsertAdminAuth() error = %v", err)
	}
	if _, err := store.CreateAPIKey(context.Background(), "ci-pipeline", "hash-active", nil); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	created, _, err := store.EnqueueRefresh(context.Background(), &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "left-pad",
		Source:    "socket",
		Priority:  3,
		Status:    "pending",
	})
	if err != nil {
		t.Fatalf("EnqueueRefresh() error = %v", err)
	}
	if !created {
		t.Fatal("EnqueueRefresh() created = false, want true")
	}
	if err := store.UpsertManualAdvisory(context.Background(), &db.ManualAdvisory{
		ID:          "manual:vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "manual vulnerability",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory() error = %v", err)
	}
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())

	for _, tc := range []struct {
		name    string
		target  string
		call    func(http.ResponseWriter, *http.Request)
		notWant []string
		want    []string
	}{
		{
			name:   "feeds",
			target: "/admin/feeds",
			call:   handler.HandleAdminFeeds,
			notWant: []string{
				`action="/admin/feeds/save"`,
				`action="/admin/feeds/reset"`,
				`action="/admin/feeds/sync"`,
			},
		},
		{
			name:   "queue",
			target: "/admin/queue",
			call:   handler.HandleAdminQueue,
			notWant: []string{
				`action="/admin/queue/purge"`,
				`action="/admin/queue/clear"`,
				`action="/admin/queue/priority"`,
				`action="/admin/queue/pause"`,
			},
		},
		{
			name:   "keys",
			target: "/admin/keys",
			call:   handler.HandleAdminKeys,
			notWant: []string{
				`action="/admin/keys/create"`,
				`action="/admin/keys/revoke"`,
				`action="/admin/keys/delete"`,
			},
		},
		{
			name:   "advisories",
			target: "/admin/advisories",
			call:   handler.HandleAdminAdvisories,
			notWant: []string{
				`action="/admin/advisories/create"`,
				`action="/admin/advisories/delete"`,
				`href="/admin/advisories?edit=`,
			},
		},
		{
			name:   "settings",
			target: "/admin/settings",
			call:   handler.HandleAdminSettings,
			notWant: []string{
				`action="/admin/settings/system"`,
			},
			want: []string{
				`action="/admin/settings/password"`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, tc.target)
			rec := httptest.NewRecorder()
			tc.call(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200; body=%s", tc.target, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range append([]string{
				"Bootstrap password still active",
				`href="/admin/settings"`,
				"Change admin password",
			}, tc.want...) {
				if !strings.Contains(body, want) {
					t.Fatalf("GET %s body missing %q\nbody=%s", tc.target, want, body)
				}
			}
			for _, notWant := range tc.notWant {
				if strings.Contains(body, notWant) {
					t.Fatalf("GET %s body contains enabled bootstrap-blocked control %q\nbody=%s", tc.target, notWant, body)
				}
			}
		})
	}
}

func TestHandlePasswordChangeAcceptsExactlyMinimumLength(t *testing.T) {
	store := newNoopStore()
	currentPassword := "current-password"
	hash, err := auth.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if err := store.UpsertAdminAuth(context.Background(), hash, true); err != nil {
		t.Fatalf("UpsertAdminAuth() error = %v", err)
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	newPassword := "newpass12345"
	if len(newPassword) != 12 {
		t.Fatalf("test password length = %d, want 12", len(newPassword))
	}
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {currentPassword},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	rec := httptest.NewRecorder()

	handler.HandlePasswordChange(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/settings/password status = %d, want 303", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "/admin/settings?msg=Password+changed+successfully" {
		t.Fatalf("Location = %q, want password changed success redirect", location)
	}
	adminAuth, err := store.GetAdminAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if adminAuth == nil || !auth.CheckPassword(adminAuth.PasswordHash, newPassword) {
		t.Fatal("stored admin password does not match the 12-character new password")
	}
}

func TestHandleSystemSettingsSavePersistsSettings(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":       {"HIGH"},
		"rate_limit_per_minute": {"120"},
		"rate_limit_burst":      {"25"},
	})
	rec := httptest.NewRecorder()

	handler.HandleSystemSettingsSave(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/settings/system status = %d, want 303", rec.Code)
	}

	settings, err := store.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings == nil {
		t.Fatal("GetSystemSettings() = nil, want saved settings")
	}
	if settings.BlockThreshold != "HIGH" {
		t.Fatalf("BlockThreshold = %q, want HIGH", settings.BlockThreshold)
	}
	if settings.RateLimitPerMinute != 120 {
		t.Fatalf("RateLimitPerMinute = %d, want 120", settings.RateLimitPerMinute)
	}
	if settings.RateLimitBurst != 25 {
		t.Fatalf("RateLimitBurst = %d, want 25", settings.RateLimitBurst)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "system_settings_save" {
		t.Fatalf("audit entries = %+v, want system_settings_save", audit)
	}
}

func TestAdminSettingsPageShowsUpdatedRuntimePolicyAfterSave(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	saveReq := newAuthenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":       {"HIGH"},
		"rate_limit_per_minute": {"120"},
		"rate_limit_burst":      {"25"},
	})
	saveRec := httptest.NewRecorder()

	handler.HandleSystemSettingsSave(saveRec, saveReq)

	if saveRec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/settings/system status = %d, want 303", saveRec.Code)
	}

	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings")
	rec := httptest.NewRecorder()
	handler.HandleAdminSettings(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/settings status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Saved values apply immediately and are persisted for future server starts.",
		"Runtime: HIGH",
		"Runtime: 120",
		"Runtime: 25",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/settings body missing %q\nbody=%s", want, body)
		}
	}
}

func TestHandleKeyCreateStoresExpiration(t *testing.T) {
	store := newNoopStore()
	setNoopAdminPassword(t, store, "current-password", false)
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	expiresAt := testAPIKeyExpiryFormValue()
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":             {"ci-short-lived"},
		"expires_at":       {expiresAt},
		"current_password": {"current-password"},
	})
	rec := httptest.NewRecorder()

	handler.HandleKeyCreate(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/keys/create status = %d, want 303", rec.Code)
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("ListAPIKeys() len = %d, want 1", len(keys))
	}
	if keys[0].ExpiresAt == nil {
		t.Fatal("ExpiresAt = nil, want parsed expiration")
	}
	if got := keys[0].ExpiresAt.UTC().Format(time.RFC3339); got != expiresAt {
		t.Fatalf("ExpiresAt = %q, want %s", got, expiresAt)
	}
}

func TestAdminKeysPageRendersNewKeyAsKeyboardCopyableControl(t *testing.T) {
	store := newNoopStore()
	setNoopAdminPassword(t, store, "current-password", false)
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	createReq := newAuthenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":             {"ci"},
		"expires_at":       {testAPIKeyExpiryFormValue()},
		"current_password": {"current-password"},
	})
	createRec := httptest.NewRecorder()

	handler.HandleKeyCreate(createRec, createReq)

	if createRec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/keys/create status = %d, want 303", createRec.Code)
	}

	keysReq := httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	for _, cookie := range createReq.Cookies() {
		keysReq.AddCookie(cookie)
	}
	keysRec := httptest.NewRecorder()

	handler.HandleAdminKeys(keysRec, keysReq)

	if keysRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/keys status = %d, want 200", keysRec.Code)
	}

	body := keysRec.Body.String()
	if !strings.Contains(body, `data-no-print`) || !strings.Contains(body, `no-print`) {
		t.Fatalf("GET /admin/keys new API key secret banner is not marked as non-printable\nbody=%s", body)
	}

	inputStart := strings.Index(body, `id="new-api-key"`)
	if inputStart < 0 {
		t.Fatalf("GET /admin/keys body missing new API key input\nbody=%s", body)
	}
	inputEnd := strings.Index(body[inputStart:], ">")
	if inputEnd < 0 {
		t.Fatalf("GET /admin/keys new API key input is not closed\nbody=%s", body)
	}
	input := body[inputStart : inputStart+inputEnd]
	for _, want := range []string{
		`name="new_api_key"`,
		`readonly`,
		`type="text"`,
		`autocomplete="off"`,
		`spellcheck="false"`,
		`data-select-on-focus`,
		`aria-label="New API key"`,
	} {
		if !strings.Contains(input, want) {
			t.Fatalf("new API key input missing %q\ninput=%s", want, input)
		}
	}
	if !regexp.MustCompile(`value="[0-9a-f]{64}"`).MatchString(input) {
		t.Fatalf("new API key input does not render 64-character key value\ninput=%s", input)
	}
	for _, want := range []string{
		`type="button"`,
		`aria-label="Copy API key"`,
		`data-copy-target="#new-api-key"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/keys body missing copy control marker %q\nbody=%s", want, body)
		}
	}
	if strings.Contains(body, "<code") {
		t.Fatalf("GET /admin/keys still renders one-time key in non-focusable code block\nbody=%s", body)
	}
}

func TestAdminKeysPageConfirmationsIncludeKeyIdentity(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())

	activeID, err := store.CreateAPIKey(context.Background(), "ci-pipeline", "hash-active", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(active) error = %v", err)
	}
	revokedID, err := store.CreateAPIKey(context.Background(), "n8n-scanner", "hash-revoked", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(revoked) error = %v", err)
	}
	if err := store.RevokeAPIKey(context.Background(), revokedID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/keys")
	rec := httptest.NewRecorder()
	handler.HandleAdminKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/keys status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		fmt.Sprintf(`Revoke API key <bdi dir="auto">ci-pipeline</bdi> (ID %d)?`, activeID),
		fmt.Sprintf(`Mark revoked API key <bdi dir="auto">n8n-scanner</bdi> (ID %d) deleted?`, revokedID),
		"Confirm revoke",
		"Confirm mark deleted",
		`data-submit-lock`,
		`data-submit-lock-button`,
		`data-submit-lock-label="Generating key"`,
		`data-submit-lock-label="Revoking key"`,
		`data-submit-lock-label="Deleting key"`,
		`<bdi dir="auto">ci-pipeline</bdi>`,
		`<bdi dir="auto">n8n-scanner</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/keys body missing confirmation %q\nbody=%s", want, body)
		}
	}
	for _, notWant := range []string{
		`confirm(`,
		`opacity-50`,
		`opacity-60`,
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("GET /admin/keys body contains blocked key-management marker %q\nbody=%s", notWant, body)
		}
	}
}

func TestAdminInteractiveRowControlsHaveAccessibleNamesAndTouchTargets(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())

	activeID, err := store.CreateAPIKey(context.Background(), "ci-pipeline", "hash-active", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(active) error = %v", err)
	}
	revokedID, err := store.CreateAPIKey(context.Background(), "n8n-scanner", "hash-revoked", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(revoked) error = %v", err)
	}
	if err := store.RevokeAPIKey(context.Background(), revokedID); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
	if err := store.UpsertManualAdvisory(context.Background(), &db.ManualAdvisory{
		ID:          "manual:vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "manual vulnerability",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory() error = %v", err)
	}

	for _, tc := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
		want   []string
	}{
		{
			name:   "keys",
			target: "/admin/keys",
			call:   handler.HandleAdminKeys,
			want: []string{
				fmt.Sprintf(`aria-label="Revoke API key ci-pipeline (ID %d)"`, activeID),
				fmt.Sprintf(`aria-label="Mark revoked API key n8n-scanner (ID %d) deleted"`, revokedID),
				`min-h-11`,
				`px-3 py-2`,
			},
		},
		{
			name:   "advisories",
			target: "/admin/advisories",
			call:   handler.HandleAdminAdvisories,
			want: []string{
				`aria-label="Edit manual advisory manual:vuln for npm/left-pad"`,
				`aria-label="Delete manual advisory manual:vuln for npm/left-pad"`,
				`min-h-11`,
				`px-3 py-2`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, tc.target)
			rec := httptest.NewRecorder()
			tc.call(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200; body=%s", tc.target, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("GET %s body missing %q\nbody=%s", tc.target, want, body)
				}
			}
		})
	}
}

func TestAdminFeedAndQueueControlsHaveProgrammaticLabels(t *testing.T) {
	store := newNoopStore()
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName: "vulncheck",
		Enabled:  true,
		Mode:     "self",
		APIKey:   testFeedToken(),
	}); err != nil {
		t.Fatalf("UpsertFeedConfig() error = %v", err)
	}

	for _, job := range []*db.RefreshJob{
		{Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 3},
		{Ecosystem: "npm", Name: "express", Source: "socket", Priority: 2, Status: "paused"},
		{Ecosystem: "npm", Name: "broken", Source: "socket", Priority: 4, Status: "error", Error: "upstream timeout"},
	} {
		created, _, err := store.EnqueueRefresh(context.Background(), job)
		if err != nil {
			t.Fatalf("EnqueueRefresh(%s) error = %v", job.Name, err)
		}
		if !created {
			t.Fatalf("EnqueueRefresh(%s) created = false, want true", job.Name)
		}
	}
	jobs, err := store.ListQueueJobs(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	jobIDByName := map[string]int{}
	for _, job := range jobs {
		jobIDByName[job.Name] = job.ID
	}
	for _, name := range []string{"left-pad", "express", "broken"} {
		if jobIDByName[name] == 0 {
			t.Fatalf("ListQueueJobs() missing %s: %+v", name, jobs)
		}
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	for _, tc := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
		want   []string
	}{
		{
			name:   "feeds",
			target: "/admin/feeds",
			call:   handler.HandleAdminFeeds,
			want: []string{
				`<legend class="sr-only">VulnCheck feed settings</legend>`,
				`<label for="feed-vulncheck-api-key"`,
				`id="feed-vulncheck-api-key"`,
				`name="api_key"`,
				`autocomplete="off"`,
				`confirm_clear_api_key`,
				`confirm_reset`,
				`Saving an environment-provided key stores it with this database override.`,
				`aria-label="Save VulnCheck feed settings"`,
				`aria-label="Sync VulnCheck now"`,
				`aria-label="Reset VulnCheck feed settings"`,
			},
		},
		{
			name:   "queue",
			target: "/admin/queue",
			call:   handler.HandleAdminQueue,
			want: []string{
				fmt.Sprintf(`aria-label="Priority for queue job %d npm/left-pad"`, jobIDByName["left-pad"]),
				fmt.Sprintf(`aria-label="Save priority for queue job %d npm/left-pad"`, jobIDByName["left-pad"]),
				fmt.Sprintf(`aria-label="Pause queue job %d npm/left-pad"`, jobIDByName["left-pad"]),
				fmt.Sprintf(`aria-label="Resume queue job %d npm/express"`, jobIDByName["express"]),
				fmt.Sprintf(`aria-label="Retry queue job %d npm/broken"`, jobIDByName["broken"]),
				`min-h-11`,
				`px-3 py-2`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, tc.target)
			rec := httptest.NewRecorder()
			tc.call(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200; body=%s", tc.target, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("GET %s body missing %q\nbody=%s", tc.target, want, body)
				}
			}
		})
	}
}

func TestAdminOperationalDiagnosticsExposeFullTextWithoutTitleOnly(t *testing.T) {
	store := newNoopStore()
	feedError := "feed failed while parsing upstream response for ecosystem npm package very-long-feed-diagnostic-context with retry hint and operator remediation detail"
	queueError := "queue refresh failed for npm/very-long-package-name after upstream timeout with retry-after 120 seconds and diagnostic request correlation abcdefghijklmnopqrstuvwxyz"
	if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{
		FeedName:       "ghsa",
		LastSyncStatus: "error",
		LastError:      feedError,
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}
	if _, _, err := store.EnqueueRefresh(context.Background(), &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "very-long-package-name",
		Source:    "socket",
		Priority:  1,
		Status:    "error",
		Error:     queueError,
	}); err != nil {
		t.Fatalf("EnqueueRefresh(error) error = %v", err)
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	for _, tc := range []struct {
		name         string
		target       string
		call         func(http.ResponseWriter, *http.Request)
		fullText     string
		disclosure   string
		forbiddenTip string
	}{
		{
			name:         "feeds",
			target:       "/admin/feeds",
			call:         handler.HandleAdminFeeds,
			fullText:     feedError,
			disclosure:   `Show full feed error for GHSA`,
			forbiddenTip: `title="feed failed while parsing upstream response`,
		},
		{
			name:         "queue",
			target:       "/admin/queue",
			call:         handler.HandleAdminQueue,
			fullText:     queueError,
			disclosure:   `Show full queue error for job`,
			forbiddenTip: `title="queue refresh failed for npm/very-long-package-name`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, tc.target)
			rec := httptest.NewRecorder()

			tc.call(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200; body=%s", tc.target, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range []string{`<details`, `<summary`, `<pre`, tc.disclosure, tc.fullText} {
				if !strings.Contains(body, want) {
					t.Fatalf("GET %s missing accessible diagnostic fragment %q\nbody=%s", tc.target, want, body)
				}
			}
			if strings.Contains(body, tc.forbiddenTip) {
				t.Fatalf("GET %s exposes diagnostic through title-only tooltip\nbody=%s", tc.target, body)
			}
		})
	}
}

func TestAdminQueueBulkActionsWrapAndUseInlineConfirmations(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/queue")
	rec := httptest.NewRecorder()

	handler.HandleAdminQueue(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/queue status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`data-admin-queue-bulk-actions`,
		`class="flex flex-wrap gap-3"`,
		`class="w-full sm:w-auto"`,
		`aria-label="Purge completed and errored queue jobs"`,
		`aria-label="Confirm purge completed and errored queue jobs"`,
		`Purge Completed/Errored`,
		`Confirm purge`,
		`Confirm clear pending`,
		`Confirm clear paused`,
		`Purge all completed and errored jobs?`,
		`Clear all pending jobs?`,
		`Clear all paused jobs?`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/queue body missing %q\nbody=%s", want, body)
		}
	}
	for _, notWant := range []string{
		`onclick=`,
		`confirm(`,
		`class="flex gap-3"`,
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("GET /admin/queue body contains %q\nbody=%s", notWant, body)
		}
	}
}

func TestAdminQueuePriorityControlsMatchDocumentedLevels(t *testing.T) {
	store := newNoopStore()
	created, _, err := store.EnqueueRefresh(context.Background(), &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "left-pad",
		Source:    "socket",
		Priority:  3,
		Status:    "pending",
	})
	if err != nil {
		t.Fatalf("EnqueueRefresh() error = %v", err)
	}
	if !created {
		t.Fatal("EnqueueRefresh() created = false, want true")
	}
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/queue")
	rec := httptest.NewRecorder()

	handler.HandleAdminQueue(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/queue status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<option value="0"`,
		`<option value="1"`,
		`<option value="2"`,
		`<option value="3"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/queue body missing %q\nbody=%s", want, body)
		}
	}
	for _, notWant := range []string{
		`<option value="4"`,
		`<option value="5"`,
		`<option value="6"`,
		`<option value="7"`,
		`<option value="8"`,
		`<option value="9"`,
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("GET /admin/queue body contains %q\nbody=%s", notWant, body)
		}
	}
}

func TestAdminQueueRowActionsUseSubmitLocks(t *testing.T) {
	store := newNoopStore()
	for _, job := range []*db.RefreshJob{
		{Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 3, Status: "pending"},
		{Ecosystem: "npm", Name: "express", Source: "socket", Priority: 2, Status: "paused"},
		{Ecosystem: "npm", Name: "broken", Source: "socket", Priority: 1, Status: "error", Error: "upstream timeout"},
	} {
		created, _, err := store.EnqueueRefresh(context.Background(), job)
		if err != nil {
			t.Fatalf("EnqueueRefresh(%s) error = %v", job.Name, err)
		}
		if !created {
			t.Fatalf("EnqueueRefresh(%s) created = false, want true", job.Name)
		}
	}
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/queue")
	rec := httptest.NewRecorder()

	handler.HandleAdminQueue(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/queue status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`data-submit-lock-label="Saving priority"`,
		`data-submit-lock-label="Pausing job"`,
		`data-submit-lock-label="Resuming job"`,
		`data-submit-lock-label="Retrying job"`,
		`data-submit-lock-button`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/queue body missing %q\nbody=%s", want, body)
		}
	}
}

func TestAdminRowActionsHaveMobileReachableLists(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())

	keyID, err := store.CreateAPIKey(context.Background(), "ci-pipeline", "hash-active", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey(active) error = %v", err)
	}
	jobCreated, _, err := store.EnqueueRefresh(context.Background(), &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "left-pad",
		Source:    "socket",
		Priority:  3,
		Status:    "pending",
	})
	if err != nil {
		t.Fatalf("EnqueueRefresh() error = %v", err)
	}
	if !jobCreated {
		t.Fatal("EnqueueRefresh() created = false, want true")
	}
	jobs, err := store.ListQueueJobs(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	var jobID int
	for _, job := range jobs {
		if job.Name == "left-pad" {
			jobID = job.ID
			break
		}
	}
	if jobID == 0 {
		t.Fatalf("left-pad queue job missing: %+v", jobs)
	}
	if err := store.UpsertManualAdvisory(context.Background(), &db.ManualAdvisory{
		ID:          "manual:vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "manual vulnerability",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory() error = %v", err)
	}

	for _, tc := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
		marker string
		want   []string
	}{
		{
			name:   "queue",
			target: "/admin/queue",
			call:   handler.HandleAdminQueue,
			marker: "queue",
			want: []string{
				`npm/left-pad`,
				fmt.Sprintf(`aria-label="Pause queue job %d npm/left-pad"`, jobID),
				fmt.Sprintf(`aria-label="Save priority for queue job %d npm/left-pad"`, jobID),
			},
		},
		{
			name:   "keys",
			target: "/admin/keys",
			call:   handler.HandleAdminKeys,
			marker: "keys",
			want: []string{
				`ci-pipeline`,
				fmt.Sprintf(`aria-label="Revoke API key ci-pipeline (ID %d)"`, keyID),
			},
		},
		{
			name:   "advisories",
			target: "/admin/advisories",
			call:   handler.HandleAdminAdvisories,
			marker: "advisories",
			want: []string{
				`manual:vuln`,
				`aria-label="Edit manual advisory manual:vuln for npm/left-pad"`,
				`aria-label="Delete manual advisory manual:vuln for npm/left-pad"`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, tc.target)
			rec := httptest.NewRecorder()
			tc.call(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200; body=%s", tc.target, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			section := htmlSection(body, fmt.Sprintf(`data-admin-mobile-actions="%s"`, tc.marker), fmt.Sprintf(`data-admin-desktop-table="%s"`, tc.marker))
			if section == "" {
				t.Fatalf("GET %s body missing mobile actions section %q\nbody=%s", tc.target, tc.marker, body)
			}
			if !strings.Contains(section, `md:hidden`) {
				t.Fatalf("GET %s mobile actions section is not mobile-only\nsection=%s", tc.target, section)
			}
			for _, want := range tc.want {
				if !strings.Contains(section, want) {
					t.Fatalf("GET %s mobile actions section missing %q\nsection=%s", tc.target, want, section)
				}
			}
		})
	}
}

func TestHandleKeyCreateRejectsPastExpiration(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":       {"ci-expired"},
		"expires_at": {"2000-01-01T00:00:00Z"},
	})
	rec := httptest.NewRecorder()

	handler.HandleKeyCreate(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/keys/create status = %d, want 303", rec.Code)
	}
	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListAPIKeys() len = %d, want 0 after invalid expiration", len(keys))
	}
	if location := rec.Header().Get("Location"); !strings.Contains(location, "expiration+must+be+in+the+future") {
		t.Fatalf("Location = %q, want expiration error", location)
	}
}

func TestHandleFeedConfigSaveAppliesRuntimeConfig(t *testing.T) {
	store := newNoopStore()
	cfg := testAdminConfig()
	cfg.Feeds.VulnCheckEnabled = false
	cfg.Feeds.VulnCheckMode = config.FeedModeSelf

	var applied config.FeedSettings
	applyCalls := 0
	handler, sm := newAdminTestHandler(t, store, cfg)
	handler.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		applyCalls++
		applied = feed
		return nil
	})

	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name": {"vulncheck"},
		"enabled":   {"on"},
		"mode":      {"self"},
		"api_key":   {"vc-live-key"},
	})
	rec := httptest.NewRecorder()

	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/feeds/save status = %d, want 303", rec.Code)
	}
	if applyCalls != 1 {
		t.Fatalf("apply calls = %d, want 1", applyCalls)
	}
	if applied.Name != "vulncheck" || !applied.Enabled || applied.APIKey != "vc-live-key" {
		t.Fatalf("applied feed = %+v, want enabled vulncheck with api key", applied)
	}
	if location := rec.Header().Get("Location"); location != "/admin/feeds?msg=Feed+configuration+saved+and+applied." {
		t.Fatalf("Location = %q, want saved-and-applied redirect", location)
	}
}

func TestQueueAdminActionsManagePriorityPauseResumeRetryAndClear(t *testing.T) {
	store := newNoopStore()
	created, _, err := store.EnqueueRefresh(context.Background(), &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "lodash",
		Source:    "socket",
		Priority:  3,
	})
	if err != nil {
		t.Fatalf("EnqueueRefresh() error = %v", err)
	}
	if !created {
		t.Fatal("EnqueueRefresh() created = false, want true")
	}

	jobs, err := store.ListQueueJobs(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	jobID := jobs[0].ID

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	rec := httptest.NewRecorder()
	handler.HandleQueuePriorityUpdate(rec, newAuthenticatedAdminFormRequest(t, sm, "/admin/queue/priority", url.Values{
		"job_id":   {strconv.Itoa(jobID)},
		"priority": {"0"},
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/queue/priority status = %d, want 303", rec.Code)
	}

	jobs, _ = store.ListQueueJobs(context.Background(), "", 10)
	if jobs[0].Priority != 0 {
		t.Fatalf("priority = %d, want 0", jobs[0].Priority)
	}

	rec = httptest.NewRecorder()
	handler.HandleQueuePause(rec, newAuthenticatedAdminFormRequest(t, sm, "/admin/queue/pause", url.Values{
		"job_id": {strconv.Itoa(jobID)},
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/queue/pause status = %d, want 303", rec.Code)
	}
	stats, _ := store.QueueStats(context.Background())
	if stats.Paused != 1 {
		t.Fatalf("QueueStats().Paused = %d, want 1", stats.Paused)
	}
	dequeued, err := store.DequeueRefresh(context.Background(), "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh() error = %v", err)
	}
	if dequeued != nil {
		t.Fatalf("DequeueRefresh() returned paused job %+v, want nil", *dequeued)
	}

	rec = httptest.NewRecorder()
	handler.HandleQueueResume(rec, newAuthenticatedAdminFormRequest(t, sm, "/admin/queue/resume", url.Values{
		"job_id": {strconv.Itoa(jobID)},
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/queue/resume status = %d, want 303", rec.Code)
	}
	jobs, _ = store.ListQueueJobs(context.Background(), "", 10)
	if jobs[0].Status != "pending" {
		t.Fatalf("status after resume = %q, want pending", jobs[0].Status)
	}

	dequeued, err = store.DequeueRefresh(context.Background(), "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh() error = %v", err)
	}
	if dequeued == nil {
		t.Fatal("DequeueRefresh() = nil, want processing job")
	}
	if err := store.CompleteRefresh(context.Background(), dequeued.ID, io.ErrUnexpectedEOF); err != nil {
		t.Fatalf("CompleteRefresh() error = %v", err)
	}

	rec = httptest.NewRecorder()
	handler.HandleQueueRetry(rec, newAuthenticatedAdminFormRequest(t, sm, "/admin/queue/retry", url.Values{
		"job_id": {strconv.Itoa(jobID)},
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/queue/retry status = %d, want 303", rec.Code)
	}
	jobs, _ = store.ListQueueJobs(context.Background(), "", 10)
	if jobs[0].Status != "pending" || jobs[0].Error != "" {
		t.Fatalf("job after retry = %+v, want pending with empty error", jobs[0])
	}

	rec = httptest.NewRecorder()
	handler.HandleQueueClear(rec, newAuthenticatedAdminFormRequest(t, sm, "/admin/queue/clear", url.Values{
		"status": {"pending"},
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/queue/clear status = %d, want 303", rec.Code)
	}
	jobs, _ = store.ListQueueJobs(context.Background(), "", 10)
	if len(jobs) != 0 {
		t.Fatalf("jobs after clear = %+v, want empty queue", jobs)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	for _, want := range []string{"queue_priority_update", "queue_pause", "queue_resume", "queue_retry", "queue_clear"} {
		if !auditContainsAction(audit, want) {
			t.Fatalf("audit log missing %q: %+v", want, audit)
		}
	}
}

func TestHandleAdvisoryCreateGeneratesManualUUID(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"finding_type": {"malicious"},
		"ecosystem":    {"npm"},
		"name":         {"left-pad"},
		"severity":     {"HIGH"},
		"risk_type":    {"other"},
		"summary":      {"manual advisory without upstream CVE"},
		"description":  {"operator-created advisory"},
	})
	rec := httptest.NewRecorder()

	handler.HandleAdvisoryCreate(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/advisories/create status = %d, want 303", rec.Code)
	}
	advisories, err := store.ListMaliciousFindings(context.Background(), "manual", 10)
	if err != nil {
		t.Fatalf("ListMaliciousFindings() error = %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("manual advisories len = %d, want 1", len(advisories))
	}
	id := advisories[0].ID
	if !strings.HasPrefix(id, "manual:") || len(id) != len("manual:00000000-0000-0000-0000-000000000000") {
		t.Fatalf("manual advisory ID = %q, want manual:<uuid>", id)
	}
}

func TestHandleAdvisoryCreatePersistsVulnerabilityAdvisory(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"finding_type": {"vulnerability"},
		"ecosystem":    {"npm"},
		"name":         {"left-pad"},
		"severity":     {"HIGH"},
		"summary":      {"manual vulnerability advisory"},
		"description":  {"operator-created non-malicious advisory"},
	})
	rec := httptest.NewRecorder()

	handler.HandleAdvisoryCreate(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/advisories/create status = %d, want 303", rec.Code)
	}

	advisories, err := store.ListManualAdvisories(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("manual advisories len = %d, want 1", len(advisories))
	}
	advisory := advisories[0]
	if advisory.FindingType != "vulnerability" {
		t.Fatalf("FindingType = %q, want vulnerability", advisory.FindingType)
	}
	if !strings.HasPrefix(advisory.ID, "manual:") {
		t.Fatalf("manual advisory ID = %q, want manual:<uuid>", advisory.ID)
	}

	malicious, err := store.ListMaliciousFindings(context.Background(), "manual", 10)
	if err != nil {
		t.Fatalf("ListMaliciousFindings() error = %v", err)
	}
	if len(malicious) != 0 {
		t.Fatalf("manual malicious findings len = %d, want 0", len(malicious))
	}

	findings, err := store.FindVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("vulnerability findings len = %d, want 1", len(findings))
	}
	if string(findings[0].Type) != "vulnerability" || findings[0].Source != "manual" || findings[0].AdvisoryID != advisory.ID {
		t.Fatalf("unexpected vulnerability finding = %+v", findings[0])
	}
}

func TestHandleAdvisoryCreateRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
	}{
		{
			name: "invalid severity",
			form: url.Values{
				"finding_type": {"vulnerability"}, "ecosystem": {"npm"},
				"name": {"left-pad"}, "severity": {"BOGUS"}, "summary": {"s"},
			},
		},
		{
			name: "unknown ecosystem",
			form: url.Values{
				"finding_type": {"vulnerability"}, "ecosystem": {"rubygemsX"},
				"name": {"left-pad"}, "severity": {"HIGH"}, "summary": {"s"},
			},
		},
		{
			name: "operator id outside manual namespace",
			form: url.Values{
				"id": {"CVE-2021-23337"}, "finding_type": {"vulnerability"},
				"ecosystem": {"npm"}, "name": {"left-pad"}, "severity": {"HIGH"}, "summary": {"s"},
			},
		},
		{
			name: "invalid finding type",
			form: url.Values{
				"finding_type": {"other"}, "ecosystem": {"npm"},
				"name": {"left-pad"}, "severity": {"HIGH"}, "summary": {"s"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newNoopStore()
			handler, sm := newAdminTestHandler(t, store, testAdminConfig())
			req := newAuthenticatedAdminFormRequest(t, sm, "/admin/advisories/create", tc.form)
			rec := httptest.NewRecorder()

			handler.HandleAdvisoryCreate(rec, req)

			// Invalid input must not be persisted in either backing table.
			vulns, err := store.ListManualAdvisories(context.Background(), 10)
			if err != nil {
				t.Fatalf("ListManualAdvisories() error = %v", err)
			}
			mal, err := store.ListMaliciousFindings(context.Background(), "manual", 10)
			if err != nil {
				t.Fatalf("ListMaliciousFindings() error = %v", err)
			}
			if len(vulns)+len(mal) != 0 {
				t.Fatalf("invalid advisory was persisted: manual=%d malicious=%d", len(vulns), len(mal))
			}
		})
	}
}

func TestAdminAdvisoriesPageShowsManualFindingTypes(t *testing.T) {
	store := newNoopStore()
	if err := store.UpsertManualAdvisory(context.Background(), &db.ManualAdvisory{
		ID:          "manual:vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "MEDIUM",
		Summary:     "manual vuln",
		Description: "non-malicious manual advisory",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(vulnerability) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(context.Background(), &db.ManualAdvisory{
		ID:          "manual:malicious",
		FindingType: "malicious",
		Ecosystem:   "pypi",
		Name:        "evil",
		Severity:    "CRITICAL",
		RiskType:    "malware",
		Summary:     "manual malicious",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(malicious) error = %v", err)
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
	rec := httptest.NewRecorder()

	handler.HandleAdminAdvisories(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/advisories status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"vulnerability",
		"malicious",
		`<bdi dir="auto">left-pad</bdi>`,
		`<bdi dir="auto">evil</bdi>`,
		`<bdi dir="auto">manual vuln</bdi>`,
		`<bdi dir="auto">manual malicious</bdi>`,
		`value="actions"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/advisories body missing %q\nbody=%s", want, body)
		}
	}
}

func TestAdminAdvisoriesCreateFormDefaultsToVulnerabilityAndLocksSubmit(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
	rec := httptest.NewRecorder()

	handler.HandleAdminAdvisories(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/advisories status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<form action="/admin/advisories/create" method="POST" class="space-y-4" data-submit-lock data-submit-lock-label="Saving advisory">`,
		`<option value="vulnerability" selected>vulnerability</option>`,
		`name="name" id="adv-name" required maxlength="256" dir="auto"`,
		`name="summary" id="adv-summary" required maxlength="1000" dir="auto"`,
		`name="description" id="adv-description" rows="3" maxlength="8000" dir="auto"`,
		`Manual advisories created here apply to all versions of the selected package`,
		`data-submit-lock-button`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/advisories body missing %q\nbody=%s", want, body)
		}
	}
	if strings.Contains(body, `<option value="malicious" selected>malicious</option>`) {
		t.Fatalf("GET /admin/advisories defaults to malicious\nbody=%s", body)
	}
	if strings.Contains(body, `name="risk_type"`) {
		t.Fatalf("vulnerability create form rendered malicious risk-type control\nbody=%s", body)
	}
	if strings.Contains(body, "Vulnerability advisories created here") {
		t.Fatalf("GET /admin/advisories still renders vulnerability-only guidance\nbody=%s", body)
	}
}

func TestAdminAdvisoriesEditVulnerabilityFormOmitsRiskTypeControl(t *testing.T) {
	store := newNoopStore()
	if err := store.UpsertManualAdvisory(context.Background(), &db.ManualAdvisory{
		ID:          "manual:vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "manual vuln",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory() error = %v", err)
	}
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?edit=manual:vuln")
	rec := httptest.NewRecorder()

	handler.HandleAdminAdvisories(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/advisories edit status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `name="risk_type"`) {
		t.Fatalf("vulnerability edit form rendered malicious risk-type control\nbody=%s", body)
	}
	for _, want := range []string{
		`href="/admin/advisories" class="inline-flex min-h-11 items-center rounded-md border border-gray-500 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 ml-3"`,
		`name="name" id="adv-name" required maxlength="256" dir="auto"`,
		`name="summary" id="adv-summary" required maxlength="1000" dir="auto"`,
		`name="description" id="adv-description" rows="3" maxlength="8000" dir="auto"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/advisories edit body missing %q\nbody=%s", want, body)
		}
	}
}

func TestAdminAdvisoriesDeleteUsesConfirmationAndSubmitLock(t *testing.T) {
	store := newNoopStore()
	if err := store.UpsertManualAdvisory(context.Background(), &db.ManualAdvisory{
		ID:          "manual:vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "manual vuln",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory() error = %v", err)
	}
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
	rec := httptest.NewRecorder()

	handler.HandleAdminAdvisories(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/advisories status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`name="confirm_id" value="manual:vuln"`,
		`data-submit-lock data-submit-lock-label="Deleting advisory"`,
		`data-submit-lock-button`,
		`Confirm delete`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/advisories body missing %q\nbody=%s", want, body)
		}
	}
}

func TestHandleAdvisoryDeleteRemovesManualVulnerabilityAdvisory(t *testing.T) {
	store := newNoopStore()
	if err := store.UpsertManualAdvisory(context.Background(), &db.ManualAdvisory{
		ID:          "manual:vuln-delete",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Severity:    "HIGH",
		Summary:     "manual vulnerability",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory() error = %v", err)
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{
		"id":         {"manual:vuln-delete"},
		"confirm_id": {"manual:vuln-delete"},
	})
	rec := httptest.NewRecorder()

	handler.HandleAdvisoryDelete(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/advisories/delete status = %d, want 303", rec.Code)
	}

	findings, err := store.FindVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("vulnerability findings len = %d, want 0", len(findings))
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "advisory_delete" {
		t.Fatalf("audit entries = %+v, want advisory_delete", audit)
	}
}

func TestHandleFeedSyncNowTriggersRegisteredSelfSyncFeeds(t *testing.T) {
	for _, feedName := range []string{"ghsa", "nvd", "endoflife"} {
		t.Run(feedName, func(t *testing.T) {
			store := newNoopStore()
			syncCalled := make(chan string, 1)
			cfg := testAdminConfig()
			cfg.Feeds.GHSAMode = config.FeedModeSelf
			cfg.Feeds.NVDEnabled = true
			cfg.Feeds.NVDMode = config.FeedModeSelf
			cfg.Feeds.EndOfLifeEnabled = true
			cfg.Feeds.EndOfLifeMode = config.FeedModeSelf
			handler, sm := newAdminTestHandler(t, store, cfg, func(_ context.Context, feedName string) error {
				syncCalled <- feedName
				return nil
			})
			req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{
				"feed_name": {feedName},
			})
			rec := httptest.NewRecorder()

			handler.HandleFeedSyncNow(rec, req)

			if rec.Code != http.StatusSeeOther {
				t.Fatalf("POST /admin/feeds/sync status = %d, want 303", rec.Code)
			}

			select {
			case got := <-syncCalled:
				if got != feedName {
					t.Fatalf("sync feedName = %q, want %s", got, feedName)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("manual sync was not triggered")
			}

			audit, err := store.ListAdminAuditLog(context.Background(), 1)
			if err != nil {
				t.Fatalf("ListAdminAuditLog() error = %v", err)
			}
			if len(audit) != 1 || audit[0].Action != "feed_sync_trigger" {
				t.Fatalf("audit entries = %+v, want feed_sync_trigger", audit)
			}
		})
	}
}

func TestHandleFeedSyncNowHTMXDoesNotRedirectAndMarksRunning(t *testing.T) {
	store := newNoopStore()
	block := make(chan struct{})
	syncCalled := make(chan string, 1)
	handler, sm := newAdminTestHandler(t, store, testAdminConfig(), func(_ context.Context, feedName string) error {
		syncCalled <- feedName
		<-block
		return nil
	})
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{
		"feed_name": {"osv"},
	})
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()

	handler.HandleFeedSyncNow(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HTMX POST /admin/feeds/sync status = %d, want 200", rec.Code)
	}
	for _, want := range []string{
		`role="status"`,
		`aria-live="polite"`,
		`OSV sync started with current runtime settings.`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("HTMX POST /admin/feeds/sync body missing %q: %s", want, rec.Body.String())
		}
	}
	if trigger := rec.Header().Get("HX-Trigger"); !strings.Contains(trigger, "feed-runtime-refresh") {
		t.Fatalf("HX-Trigger = %q, want feed-runtime-refresh", trigger)
	}

	status, err := store.GetFeedSyncStatus(context.Background(), "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "running" {
		t.Fatalf("feed sync status = %+v, want running", status)
	}

	select {
	case feedName := <-syncCalled:
		if feedName != "osv" {
			t.Fatalf("sync feedName = %q, want osv", feedName)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("manual sync was not triggered")
	}

	close(block)
}

func TestHandleAdminFeedsHTMXWithoutSessionRedirectsToLogin(t *testing.T) {
	store := newNoopStore()
	handler, _ := newAdminTestHandler(t, store, testAdminConfig())
	req := httptest.NewRequest(http.MethodGet, "/admin/feeds?partial=runtime", nil)
	req.Header.Set("HX-Request", "true")
	req.AddCookie(&http.Cookie{ //nolint:gosec // test injects a stale session cookie.
		Name:  auth.SessionCookieName,
		Value: "stale-session",
		Path:  "/",
	})
	rec := httptest.NewRecorder()

	handler.HandleAdminFeeds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/feeds?partial=runtime status = %d, want 200", rec.Code)
	}
	if redirect := rec.Header().Get("HX-Redirect"); redirect != "/admin/login?next=%2Fadmin%2Ffeeds%3Fpartial%3Druntime" {
		t.Fatalf("HX-Redirect = %q, want login redirect with admin target", redirect)
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Fatalf("Location = %q, want empty for HTMX redirect", location)
	}
}

func TestAdminLoginFormHasDuplicateSubmitGuard(t *testing.T) {
	store := newNoopStore()
	handler, _ := newAdminTestHandler(t, store, testAdminConfig())
	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	rec := httptest.NewRecorder()

	handler.HandleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/login status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`data-submit-lock`, `data-submit-lock-button`, `data-submit-lock-label="Signing in"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("login body missing %s\nbody=%s", want, body)
		}
	}
}

func TestHandleFeedConfigSavePersistsOverride(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"socket"},
		"enabled":       {"on"},
		"mode":          {"external"},
		"api_key":       {"socket-test-key"},
		"clear_api_key": {""},
	})
	rec := httptest.NewRecorder()

	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/feeds/save status = %d, want 303", rec.Code)
	}

	override, err := store.GetFeedConfig(context.Background(), "socket")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override == nil {
		t.Fatal("GetFeedConfig() = nil, want override")
	}
	if !override.Enabled || override.Mode != "external" || override.APIKey != "socket-test-key" {
		t.Fatalf("unexpected override = %+v", *override)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "feed_config_save" {
		t.Fatalf("audit entries = %+v, want feed_config_save", audit)
	}
}

func TestHandleFeedConfigSaveParsesSyncInterval(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"ghsa"},
		"enabled":       {"on"},
		"mode":          {"self"},
		"sync_interval": {"2h30m"},
	})
	rec := httptest.NewRecorder()

	handler.HandleFeedConfigSave(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/feeds/save status = %d, want 303", rec.Code)
	}

	override, err := store.GetFeedConfig(context.Background(), "ghsa")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override == nil || override.SyncInterval == nil {
		t.Fatalf("GetFeedConfig() = %+v, want sync interval override", override)
	}
	if *override.SyncInterval != 150*time.Minute {
		t.Fatalf("override.SyncInterval = %s, want 2h30m", *override.SyncInterval)
	}
}

func TestHandleFeedConfigResetDeletesOverride(t *testing.T) {
	store := newNoopStore()
	interval := 30 * time.Minute
	if err := store.UpsertFeedConfig(context.Background(), &db.FeedConfig{
		FeedName:     "ghsa",
		Enabled:      true,
		Mode:         "external",
		SyncInterval: &interval,
	}); err != nil {
		t.Fatalf("UpsertFeedConfig() error = %v", err)
	}

	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
		"feed_name":     {"ghsa"},
		"confirm_reset": {"on"},
	})
	rec := httptest.NewRecorder()

	handler.HandleFeedConfigReset(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/feeds/reset status = %d, want 303", rec.Code)
	}

	override, err := store.GetFeedConfig(context.Background(), "ghsa")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override != nil {
		t.Fatalf("GetFeedConfig() = %+v, want nil after reset", *override)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(audit) != 1 || audit[0].Action != "feed_config_reset" {
		t.Fatalf("audit entries = %+v, want feed_config_reset", audit)
	}
}

func auditContainsAction(entries []db.AdminAuditLogEntry, action string) bool {
	for _, entry := range entries {
		if entry.Action == action {
			return true
		}
	}
	return false
}

func testAPIKeyExpiryFormValue() string {
	return time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
}

func setNoopAdminPassword(t *testing.T, store *noopStore, password string, isBootstrap bool) {
	t.Helper()

	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if err := store.UpsertAdminAuth(context.Background(), hash, isBootstrap); err != nil {
		t.Fatalf("UpsertAdminAuth() error = %v", err)
	}
}

func newAdminTestHandler(t *testing.T, store *noopStore, cfg *config.Config, syncFeed ...admin.FeedSyncFunc) (*admin.AdminHandler, *auth.SessionManager) {
	t.Helper()

	renderer := web.NewRendererWithLayoutLinks(web.TemplateFS(), false, web.LayoutLinks{
		PrivacyURL: cfg.Web.PrivacyURL,
		LegalURL:   cfg.Web.LegalURL,
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sm := auth.NewSessionManager(context.Background(), time.Hour, false)
	var trigger admin.FeedSyncFunc
	if len(syncFeed) > 0 {
		trigger = syncFeed[0]
	}
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	return admin.NewAdminHandler(context.Background(), store, sm, renderer, logger, cfg, runtime, trigger), sm
}

func newAuthenticatedAdminRequest(t *testing.T, sm *auth.SessionManager, method, target string) *http.Request {
	t.Helper()

	cookieRec := httptest.NewRecorder()
	_, err := sm.Create(cookieRec)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	req := httptest.NewRequest(method, target, nil)
	for _, cookie := range cookieRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func newAuthenticatedAdminFormRequest(t *testing.T, sm *auth.SessionManager, target string, values url.Values) *http.Request {
	t.Helper()

	cookieRec := httptest.NewRecorder()
	sess, err := sm.Create(cookieRec)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	csrfToken, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("csrf token: %v", err)
	}
	values.Set(auth.CSRFFieldName, csrfToken)

	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookieRec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func tableRowContaining(body, needle string) string {
	index := strings.Index(body, needle)
	if index < 0 {
		return ""
	}
	start := strings.LastIndex(body[:index], "<tr")
	end := strings.Index(body[index:], "</tr>")
	if start < 0 || end < 0 {
		return ""
	}
	return body[start : index+end+len("</tr>")]
}

func htmlSection(body, startMarker, endMarker string) string {
	index := strings.Index(body, startMarker)
	if index < 0 {
		return ""
	}
	start := strings.LastIndex(body[:index], "<div")
	if start < 0 {
		start = index
	}
	end := strings.Index(body[index:], endMarker)
	if end < 0 {
		return body[start:]
	}
	return body[start : index+end]
}

func testAdminConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Mode: config.ModeDevelopment,
		},
		DB: config.DBConfig{
			Host:    "db.internal",
			Name:    "packmon_test",
			SSLMode: "disable",
		},
		Metrics: config.MetricsConfig{
			Host: "127.0.0.1",
			Port: 9100,
		},
		Admin: config.AdminConfig{
			SessionTimeout: 45 * time.Minute,
		},
		FeedSync: config.FeedSyncConfig{
			Interval:  15 * time.Minute,
			OnStartup: false,
		},
		Feeds: config.FeedsConfig{
			OSVEnabled:           true,
			OSVMode:              config.FeedModeSelf,
			GHSAEnabled:          true,
			GHSAMode:             config.FeedModeExternal,
			OpenSSFEnabled:       true,
			OpenSSFMode:          config.FeedModeSelf,
			VulnCheckEnabled:     true,
			VulnCheckMode:        config.FeedModeExternal,
			VulnCheckAPIKey:      testFeedToken(),
			SocketEnabled:        false,
			SocketMode:           config.FeedModeSelf,
			ReversingLabsEnabled: false,
			ReversingLabsMode:    config.FeedModeSelf,
			CISAKEVEnabled:       true,
			CISAKEVMode:          config.FeedModeSelf,
			EPSSEnabled:          true,
			EPSSMode:             config.FeedModeExternal,
		},
	}
}

func testFeedToken() string {
	return string([]byte{'t', 'e', 's', 't', '-', 'f', 'e', 'e', 'd', '-', 't', 'o', 'k', 'e', 'n'})
}
