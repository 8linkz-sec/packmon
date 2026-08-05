package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
)

func TestAdminSystemSettingsValidationBranches(t *testing.T) {
	store := newAdminErrorStore()
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, CreatedAt: time.Now().UTC()}
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/settings/system")
	req.Body = http.NoBody
	rec := httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bad CSRF status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); !strings.HasPrefix(got, "/admin/settings?") || !strings.Contains(got, "err=") {
		t.Fatalf("bad CSRF Location = %q, want settings error redirect", got)
	}

	cases := []struct {
		name   string
		values url.Values
		want   string
	}{
		{
			name:   "invalid threshold",
			values: url.Values{"block_threshold": {"INFO"}, "rate_limit_per_minute": {"60"}, "rate_limit_burst": {"10"}},
			want:   "Invalid+block+threshold",
		},
		{
			name:   "none without acknowledgement",
			values: url.Values{"block_threshold": {"NONE"}, "rate_limit_per_minute": {"60"}, "rate_limit_burst": {"10"}},
			want:   "Block+threshold+NONE+requires+explicit+acknowledgement",
		},
		{
			name:   "invalid rate per minute",
			values: url.Values{"block_threshold": {"HIGH"}, "rate_limit_per_minute": {"0"}, "rate_limit_burst": {"10"}},
			want:   "Invalid+rate+limit+per+minute",
		},
		{
			name:   "invalid burst",
			values: url.Values{"block_threshold": {"HIGH"}, "rate_limit_per_minute": {"60"}, "rate_limit_burst": {"100001"}},
			want:   "Invalid+rate+limit+burst",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", tt.values)
			rec := httptest.NewRecorder()
			handler.HandleSystemSettingsSave(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			if got := rec.Header().Get("Location"); !strings.Contains(got, tt.want) {
				t.Fatalf("Location = %q, want containing %q", got, tt.want)
			}
		})
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":          {"NONE"},
		"ack_block_threshold_none": {"true"},
		"rate_limit_per_minute":    {"60"},
		"rate_limit_burst":         {"10"},
	})
	rec = httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("acknowledged NONE status = %d, want 303", rec.Code)
	}
	settings, err := store.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings == nil || settings.BlockThreshold != "NONE" || handler.runtime.BlockThreshold() != "NONE" {
		t.Fatalf("acknowledged NONE settings = %+v runtime=%q, want NONE", settings, handler.runtime.BlockThreshold())
	}
}

func TestAdminBootstrapRotationHelperErrorAndHTMXBranches(t *testing.T) {
	store := newAdminErrorStore()
	store.fail["GetAdminAuth"] = errors.New("db down")
	handler, sm := newAdminHandlerForStore(t, store, adminFlowConfig())

	req, _ := authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/settings/system")
	rec := httptest.NewRecorder()
	if handler.requireBootstrapPasswordRotated(rec, req, "/admin/settings") {
		t.Fatal("requireBootstrapPasswordRotated(load error) = true, want false")
	}
	if got := rec.Header().Get("Location"); !strings.Contains(got, "Failed+to+verify") {
		t.Fatalf("Location = %q, want verify error", got)
	}

	store.fail = map[string]error{}
	store.adminAuth = &db.AdminAuth{PasswordIsBootstrap: true, CreatedAt: time.Now().UTC()}
	req, _ = authenticatedAdminRequest(t, sm, http.MethodPost, "/admin/feeds/save")
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	if handler.requireBootstrapPasswordRotated(rec, req, "/admin/feeds") {
		t.Fatal("requireBootstrapPasswordRotated(bootstrap) = true, want false")
	}
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), bootstrapRotationRequiredMessage) {
		t.Fatalf("HTMX bootstrap response = %d %q", rec.Code, rec.Body.String())
	}
}
