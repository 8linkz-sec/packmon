package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
)

// TestAdminPagesRenderConfiguredFooterLinks guards the shared footer on the
// admin surface: the admin renderer must receive the same privacy, legal and
// terms links as the public pages (SECURITY.md, PACKMON_WEB_TERMS_URL).
func TestAdminPagesRenderConfiguredFooterLinks(t *testing.T) {
	store := newAdminStoreStub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := adminFlowConfig()
	cfg.Web = config.WebConfig{
		PrivacyURL: "/privacy",
		LegalURL:   "https://example.invalid/impressum",
		TermsURL:   "https://example.invalid/terms-of-use",
	}
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	mux := http.NewServeMux()
	RegisterRoutes(ctx, mux, store, sm, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg, runtime, nil, nil, nil)

	loginReq := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	authedReq, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/missing-page")
	for _, tt := range []struct {
		name string
		req  *http.Request
	}{
		{name: "login", req: loginReq},
		{name: "authenticated admin page", req: authedReq},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, tt.req)
			body := rec.Body.String()
			for _, want := range []string{
				`href="/privacy"`,
				`href="https://example.invalid/impressum"`,
				`href="https://example.invalid/terms-of-use"`,
			} {
				if !strings.Contains(body, want) {
					t.Fatalf("%s footer missing %q (status %d):\n%s", tt.req.URL.Path, want, rec.Code, body)
				}
			}
		})
	}
}
