package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestAPIKeyViewAccessorsAndExpiry(t *testing.T) {
	t.Parallel()

	lastUsed := time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC)
	expires := time.Now().UTC().Add(-time.Hour)
	deleted := time.Now().UTC()
	view := apiKeyView{APIKey: db.APIKey{
		LastUsedAt: &lastUsed,
		ExpiresAt:  &expires,
		DeletedAt:  &deleted,
	}}

	if !view.DerefLastUsedAt().Equal(lastUsed) {
		t.Fatalf("DerefLastUsedAt() = %v, want %v", view.DerefLastUsedAt(), lastUsed)
	}
	if !view.DerefExpiresAt().Equal(expires) {
		t.Fatalf("DerefExpiresAt() = %v, want %v", view.DerefExpiresAt(), expires)
	}
	if !view.IsExpired() {
		t.Fatal("IsExpired() = false for past expiry")
	}
	if !view.IsDeleted() {
		t.Fatal("IsDeleted() = false for deleted key")
	}

	empty := apiKeyView{}
	if !empty.DerefLastUsedAt().IsZero() || !empty.DerefExpiresAt().IsZero() {
		t.Fatalf("empty accessors = %v / %v", empty.DerefLastUsedAt(), empty.DerefExpiresAt())
	}
}

func TestAPIKeyViewStatusPresentation(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	for _, tc := range []struct {
		name      string
		key       db.APIKey
		wantLabel string
		wantClass string
	}{
		{
			name: "deleted",
			key: db.APIKey{
				DeletedAt: &now,
				RevokedAt: &past,
			},
			wantLabel: "deleted",
			wantClass: "pm-badge-status-disabled",
		},
		{
			name: "revoked",
			key: db.APIKey{
				RevokedAt: &past,
			},
			wantLabel: "revoked",
			wantClass: "pm-badge-status-error",
		},
		{
			name: "expired",
			key: db.APIKey{
				ExpiresAt: &past,
			},
			wantLabel: "expired",
			wantClass: "pm-badge-status-warning",
		},
		{
			name:      "active",
			key:       db.APIKey{},
			wantLabel: "active",
			wantClass: "pm-badge-status-healthy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			view := apiKeyView{APIKey: tc.key}
			if got := view.StatusLabel(); got != tc.wantLabel {
				t.Fatalf("StatusLabel() = %q, want %q", got, tc.wantLabel)
			}
			if got := view.StatusClass(); got != tc.wantClass {
				t.Fatalf("StatusClass() = %q, want %q", got, tc.wantClass)
			}
		})
	}
}

func TestAdminQueueStatusClassUsesSemanticBadges(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status string
		want   string
	}{
		{db.RefreshStatusPending, "pm-badge-status-pending"},
		{db.RefreshStatusProcessing, "pm-badge-status-running"},
		{db.RefreshStatusDone, "pm-badge-status-healthy"},
		{db.RefreshStatusPaused, "pm-badge-status-disabled"},
		{db.RefreshStatusError, "pm-badge-status-error"},
		{"not-a-status", "pm-badge-status-error"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			t.Parallel()

			if got := adminQueueStatusClass(tc.status); got != tc.want {
				t.Fatalf("adminQueueStatusClass(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestParseAPIKeyExpiresInDays(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)

	if _, err := parseAPIKeyExpiresInDays("", "", now); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("blank duration error = %v, want required", err)
	}

	got, err := parseAPIKeyExpiresInDays("30", "", now)
	if err != nil {
		t.Fatalf("parseAPIKeyExpiresInDays(30): %v", err)
	}
	if got == nil || got.Location() != time.UTC || !got.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("parseAPIKeyExpiresInDays(30) = %v, want %v", got, now.Add(30*24*time.Hour))
	}

	// The custom field is used only when the dropdown value is "custom".
	custom, err := parseAPIKeyExpiresInDays(apiKeyExpiresCustomValue, "200", now)
	if err != nil {
		t.Fatalf("parseAPIKeyExpiresInDays(custom,200): %v", err)
	}
	if custom == nil || !custom.Equal(now.Add(200*24*time.Hour)) {
		t.Fatalf("parseAPIKeyExpiresInDays(custom,200) = %v, want now+200d", custom)
	}
	// A preset selection ignores whatever sits in the custom field.
	if preset, _ := parseAPIKeyExpiresInDays("7", "999", now); preset == nil || !preset.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("preset selection honored custom field = %v, want now+7d", preset)
	}

	if _, err := parseAPIKeyExpiresInDays(apiKeyExpiresCustomValue, "", now); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("custom with blank days error = %v, want required", err)
	}
	for _, raw := range []string{"tomorrow", "30.5", "-"} {
		if _, err := parseAPIKeyExpiresInDays(raw, "", now); err == nil || !strings.Contains(err.Error(), "whole number") {
			t.Fatalf("parseAPIKeyExpiresInDays(%q) error = %v, want whole-number error", raw, err)
		}
	}
	if _, err := parseAPIKeyExpiresInDays("0", "", now); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("zero-day error = %v, want future error", err)
	}
	if _, err := parseAPIKeyExpiresInDays("366", "", now); err == nil || !strings.Contains(err.Error(), "365 days") {
		t.Fatalf("too-far error = %v, want 365-day error", err)
	}
	if _, err := parseAPIKeyExpiresInDays(apiKeyExpiresCustomValue, "1000", now); err == nil || !strings.Contains(err.Error(), "365 days") {
		t.Fatalf("custom too-far error = %v, want 365-day error", err)
	}
}

func TestNormalizeAPIKeyName(t *testing.T) {
	t.Parallel()

	got, err := normalizeAPIKeyName("  ci-pipeline  ")
	if err != nil {
		t.Fatalf("normalizeAPIKeyName(valid) error = %v", err)
	}
	if got != "ci-pipeline" {
		t.Fatalf("normalizeAPIKeyName(valid) = %q, want trimmed name", got)
	}

	if _, err := normalizeAPIKeyName(""); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("blank name error = %v, want required error", err)
	}
	if _, err := normalizeAPIKeyName(strings.Repeat("a", maxAPIKeyNameLength+1)); err == nil || !strings.Contains(err.Error(), "128 characters") {
		t.Fatalf("long name error = %v, want max length error", err)
	}
}

func TestManualAdvisoryHelpers(t *testing.T) {
	t.Parallel()

	if got, ok := normalizeAdvisoryFindingType(" vulnerability "); !ok || got != "vulnerability" {
		t.Fatalf("normalizeAdvisoryFindingType(vulnerability) = %q, %v", got, ok)
	}
	if got, ok := normalizeAdvisoryFindingType(""); !ok || got != "vulnerability" {
		t.Fatalf("normalizeAdvisoryFindingType(blank) = %q, %v", got, ok)
	}
	if got, ok := normalizeAdvisoryFindingType("malicious"); !ok || got != "malicious" {
		t.Fatalf("normalizeAdvisoryFindingType(malicious) = %q, %v", got, ok)
	}
	if got, ok := normalizeAdvisoryFindingType("other"); ok || got != "" {
		t.Fatalf("normalizeAdvisoryFindingType(other) = %q, %v; want invalid", got, ok)
	}

	id, err := generateManualAdvisoryID()
	if err != nil {
		t.Fatalf("generateManualAdvisoryID: %v", err)
	}
	if !strings.HasPrefix(id, domain.ManualAdvisoryIDPrefix) || len(id) != len(domain.ManualAdvisoryIDPrefix+"00000000-0000-0000-0000-000000000000") {
		t.Fatalf("manual advisory id = %q", id)
	}

	if got := sha256Hash("packmon"); got != "fc421186ab1df78decadd876aecf1eb89f138ae7b3ae30968c0ae9b709d16dad" {
		t.Fatalf("sha256Hash(packmon) = %q", got)
	}
}

func TestSettingsFormHelpers(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"critical", " HIGH ", "medium", "low", "none"} {
		got, ok := normalizeSystemBlockThreshold(raw)
		if !ok || got != strings.ToUpper(strings.TrimSpace(raw)) {
			t.Fatalf("normalizeSystemBlockThreshold(%q) = %q, %v", raw, got, ok)
		}
	}
	if _, ok := normalizeSystemBlockThreshold("urgent"); ok {
		t.Fatal("normalizeSystemBlockThreshold(invalid) ok = true")
	}

	if got, ok := parsePositiveSettingInt("42"); !ok || got != 42 {
		t.Fatalf("parsePositiveSettingInt(42) = %d, %v", got, ok)
	}
	for _, raw := range []string{"0", "-1", "many", strconv.Itoa(MaxAdminRateLimit + 1)} {
		if _, ok := parsePositiveSettingInt(raw); ok {
			t.Fatalf("parsePositiveSettingInt(%q) ok = true", raw)
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/settings", nil)
	redirectSettings(rec, req, "Saved ok", false)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/settings?msg=Saved+ok" {
		t.Fatalf("success redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	rec = httptest.NewRecorder()
	redirectSettings(rec, req, "Bad value", true)
	if rec.Header().Get("Location") != "/admin/settings?err=Bad+value" {
		t.Fatalf("error redirect location = %q", rec.Header().Get("Location"))
	}
}

func TestBuildAdminSettingsPageDataPreservesTemplateContract(t *testing.T) {
	store := newAdminStoreStub()
	lastLoginAt := time.Date(2026, 6, 1, 8, 30, 0, 0, time.UTC)
	passwordChangedAt := time.Date(2026, 6, 2, 9, 45, 0, 0, time.UTC)
	systemUpdatedAt := time.Date(2026, 6, 3, 10, 15, 30, 123, time.UTC)
	store.adminAuth = &db.AdminAuth{
		PasswordHash:        "hash",
		PasswordIsBootstrap: true,
		LastLoginAt:         &lastLoginAt,
		PasswordChangedAt:   &passwordChangedAt,
	}
	store.systemSettings = &db.SystemSettings{
		BlockThreshold:      "LOW",
		RateLimitPerMinute:  123,
		RateLimitBurst:      45,
		ScanLogRetention:    45 * 24 * time.Hour,
		AdminAuditRetention: 14 * 24 * time.Hour,
		UpdatedAt:           systemUpdatedAt,
	}
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	req, sess := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/settings?msg=Saved&err=Bad")

	data := handler.buildAdminSettingsPageData(context.Background(), req, sess, "csrf-test", req.URL.Query())

	want := map[string]any{
		"ActiveNav":                      "admin",
		"CSRFToken":                      "csrf-test",
		"ServerMode":                     "development",
		"SyncInterval":                   "1h",
		"FeedSyncOnStartup":              "true",
		"AdminSessionTimeout":            "1h",
		"MetricsAddr":                    "127.0.0.1:9090",
		"DatabaseHost":                   "db.internal",
		"DatabaseName":                   "packmon",
		"DatabaseSSLMode":                "disable",
		"RuntimeBlockThreshold":          "CRITICAL",
		"RuntimeRateLimitPerMinute":      60,
		"RuntimeRateLimitBurst":          60,
		"RuntimeScanLogRetentionDays":    30,
		"RuntimeAdminAuditRetentionDays": 30,
		"SystemBlockThreshold":           "LOW",
		"SystemRateLimitPerMinute":       123,
		"SystemRateLimitBurst":           45,
		"SystemScanLogRetentionDays":     45,
		"SystemAdminAuditRetentionDays":  14,
		"MaxAdminRateLimit":              MaxAdminRateLimit,
		"MaxAdminRetentionDays":          MaxAdminRetentionDays,
		"HasSystemSettings":              true,
		"SystemSettingsUpdatedAt":        systemUpdatedAt,
		"SystemSettingsRevision":         systemUpdatedAt.UTC().Format(time.RFC3339Nano),
		"HasSystemSettingsUpdatedAt":     true,
		"LastLoginAt":                    lastLoginAt,
		"HasLastLoginAt":                 true,
		"PasswordChangedAt":              passwordChangedAt,
		"HasPasswordChangedAt":           true,
		"AdminAuthLoadError":             "",
		"BootstrapWarning":               true,
		"MinPasswordLength":              adminPasswordMinLength,
		"Message":                        "Saved",
		"Error":                          "Bad",
	}
	for key, value := range want {
		if got := data[key]; got != value {
			t.Fatalf("settings data[%q] = %#v, want %#v", key, got, value)
		}
	}
	if _, ok := data["SystemSettingsLoadError"]; !ok {
		t.Fatal("settings data missing SystemSettingsLoadError")
	}
}
