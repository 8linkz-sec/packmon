package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

func TestAPIKeyViewAccessorsAndExpiry(t *testing.T) {
	t.Parallel()

	lastUsed := time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC)
	expires := time.Now().UTC().Add(-time.Hour)
	view := apiKeyView{APIKey: db.APIKey{
		LastUsedAt: &lastUsed,
		ExpiresAt:  &expires,
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

	empty := apiKeyView{}
	if !empty.DerefLastUsedAt().IsZero() || !empty.DerefExpiresAt().IsZero() {
		t.Fatalf("empty accessors = %v / %v", empty.DerefLastUsedAt(), empty.DerefExpiresAt())
	}
}

func TestParseAPIKeyExpiresAt(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	if got, err := parseAPIKeyExpiresAt("", now); err != nil || got != nil {
		t.Fatalf("blank expiry = %v, %v", got, err)
	}

	for _, raw := range []string{"2026-06-01", "2026-06-01T13:45", "2026-06-01T13:45:00Z"} {
		got, err := parseAPIKeyExpiresAt(raw, now)
		if err != nil {
			t.Fatalf("parseAPIKeyExpiresAt(%q): %v", raw, err)
		}
		if got == nil || !got.After(now) {
			t.Fatalf("parseAPIKeyExpiresAt(%q) = %v, want future time", raw, got)
		}
	}

	if _, err := parseAPIKeyExpiresAt("2026-05-01", now); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("past expiry error = %v", err)
	}
	if _, err := parseAPIKeyExpiresAt("tomorrow", now); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid expiry error = %v", err)
	}
}

func TestManualAdvisoryHelpers(t *testing.T) {
	t.Parallel()

	if got := normalizeAdvisoryFindingType(" vulnerability "); got != "vulnerability" {
		t.Fatalf("normalizeAdvisoryFindingType(vulnerability) = %q", got)
	}
	if got := normalizeAdvisoryFindingType("other"); got != "malicious" {
		t.Fatalf("normalizeAdvisoryFindingType(other) = %q", got)
	}

	id, err := generateManualAdvisoryID()
	if err != nil {
		t.Fatalf("generateManualAdvisoryID: %v", err)
	}
	if !strings.HasPrefix(id, "manual:") || len(id) != len("manual:00000000-0000-0000-0000-000000000000") {
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
	for _, raw := range []string{"0", "-1", "many", "100001"} {
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
