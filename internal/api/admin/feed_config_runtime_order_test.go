package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
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

// requestBSaveInterval is the sync interval request B saves; its runtime
// apply parks on applyGate. Request A always saves 2h.
const requestBSaveInterval = 3 * time.Hour

// feedConfigGateStore parks feed config writes until their gate is closed, so
// a test can hold one request inside its persistence step while another runs.
// Saves are matched by the sync interval they write; resets use resetGate.
// applyGate parks request B inside its runtime apply step (see
// newFeedConfigRuntimeHandler).
type feedConfigGateStore struct {
	*adminFlowStoreStub
	saveGates map[time.Duration]chan struct{}
	resetGate chan struct{}
	applyGate chan struct{}

	gateMu sync.Mutex
	parked int
}

func (s *feedConfigGateStore) park(gate chan struct{}) {
	if gate == nil {
		return
	}
	s.gateMu.Lock()
	s.parked++
	s.gateMu.Unlock()
	<-gate
}

func (s *feedConfigGateStore) parkedSteps() int {
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	return s.parked
}

func (s *feedConfigGateStore) UpsertFeedConfigWithAudit(ctx context.Context, cfg *db.FeedConfig, audit *db.AdminAuditEntry) error {
	if cfg != nil && cfg.SyncInterval != nil {
		s.park(s.saveGates[*cfg.SyncInterval])
	}
	return s.adminFlowStoreStub.UpsertFeedConfigWithAudit(ctx, cfg, audit)
}

func (s *feedConfigGateStore) DeleteFeedConfigWithAudit(ctx context.Context, feedName string, expectedUpdatedAt *time.Time, audit *db.AdminAuditEntry) error {
	s.park(s.resetGate)
	return s.adminFlowStoreStub.DeleteFeedConfigWithAudit(ctx, feedName, expectedUpdatedAt, audit)
}

// newFeedConfigRuntimeHandler builds a handler whose apply and reset
// callbacks really mutate cfg, the runtime feed configuration the tests check.
// It returns the default osv settings the reset callback applies.
func newFeedConfigRuntimeHandler(t *testing.T, ctx context.Context, store *feedConfigGateStore, cfg *config.Config) (*AdminHandler, *auth.SessionManager, config.FeedSettings) {
	t.Helper()

	defaults, ok := cfg.FeedSettings("osv")
	if !ok {
		t.Fatal("osv feed settings missing from test config")
	}
	sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewAdminHandler(ctx, store, sm, web.NewRendererWithLayoutLinks(web.TemplateFS(), false, web.LayoutLinks{}), logger, cfg, nil, nil)
	h.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		if feed.SyncInterval == requestBSaveInterval {
			store.park(store.applyGate)
		}
		return cfg.SetFeedSettings(feed)
	})
	h.SetFeedConfigResetFunc(func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
		if config.NormalizeFeedName(feedName) != "osv" {
			return config.FeedSettings{}, false, nil
		}
		store.park(store.applyGate)
		return defaults, true, cfg.SetFeedSettings(defaults)
	})
	return h, sm, defaults
}

func postFeedConfigSave(t *testing.T, h *AdminHandler, sm *auth.SessionManager, interval string) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"osv"},
		"mode":          {"self"},
		"enabled":       {"on"},
		"sync_interval": {interval},
	})
	rec := httptest.NewRecorder()
	h.HandleFeedConfigSave(rec, req)
	return rec
}

func postFeedConfigReset(t *testing.T, h *AdminHandler, sm *auth.SessionManager) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
		"feed_name":     {"osv"},
		"confirm_reset": {"on"},
	})
	rec := httptest.NewRecorder()
	h.HandleFeedConfigReset(rec, req)
	return rec
}

// runFeedConfigRuntimeRace interleaves request B and a 2h save A so that,
// without ordering, B snapshots the runtime before A applies, B applies after
// A, A commits first and B then loses the revision race and rolls the runtime
// back to its stale snapshot:
//
//  1. B starts and parks inside its runtime apply step.
//  2. A starts (and, unordered, applies and parks in its persistence step).
//  3. B is released into its apply and persistence steps; A commits; B commits.
//
// Every handler and channel lives in one synctest bubble, so synctest.Wait is
// the barrier and no timing is involved. Exactly one request must lose with
// the conflict message. It returns the runtime osv settings, the default osv
// settings, and the persisted override after both requests finished.
func runFeedConfigRuntimeRace(t *testing.T, seed *db.FeedConfig, requestB func(*testing.T, *AdminHandler, *auth.SessionManager) *httptest.ResponseRecorder) (config.FeedSettings, config.FeedSettings, *db.FeedConfig) {
	t.Helper()

	var runtimeFeed, defaults config.FeedSettings
	var persisted *db.FeedConfig
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		gateA := make(chan struct{})
		gateB := make(chan struct{})
		store := &feedConfigGateStore{
			adminFlowStoreStub: newAdminStoreStub(),
			saveGates:          map[time.Duration]chan struct{}{2 * time.Hour: gateA, requestBSaveInterval: gateB},
			resetGate:          gateB,
			applyGate:          make(chan struct{}),
		}
		cfg := adminFlowConfig()
		var h *AdminHandler
		var sm *auth.SessionManager
		h, sm, defaults = newFeedConfigRuntimeHandler(t, ctx, store, cfg)
		if seed != nil {
			store.feedConfigs["osv"] = *seed
			// Startup reload applied the persisted override to the runtime.
			osv, _ := cfg.FeedSettings("osv")
			osv.SyncInterval = *seed.SyncInterval
			if err := cfg.SetFeedSettings(osv); err != nil {
				t.Fatalf("SetFeedSettings(seed) error = %v", err)
			}
		}

		var wg sync.WaitGroup
		var recA, recB *httptest.ResponseRecorder
		wg.Go(func() { recB = requestB(t, h, sm) })
		synctest.Wait()
		if got := store.parkedSteps(); got != 1 {
			t.Fatalf("parked steps after B started = %d, want B parked in its runtime apply", got)
		}

		wg.Go(func() { recA = postFeedConfigSave(t, h, sm, "2h") })
		synctest.Wait()
		close(store.applyGate)
		synctest.Wait()
		close(gateA)
		synctest.Wait()
		close(gateB)
		wg.Wait()

		conflict := "/admin/feeds?" + url.Values{"err": {web.Message("admin.feeds.error.save_conflict")}, "feed": {"osv"}}.Encode() + "#feed-osv"
		conflicts := 0
		for name, rec := range map[string]*httptest.ResponseRecorder{"A": recA, "B": recB} {
			loc := rec.Header().Get("Location")
			switch {
			case rec.Code != http.StatusSeeOther:
				t.Fatalf("request %s status = %d, want 303", name, rec.Code)
			case loc == conflict:
				conflicts++
			case !strings.Contains(loc, "msg="):
				t.Fatalf("request %s Location = %q, want success or the save-conflict redirect", name, loc)
			}
		}
		if conflicts != 1 {
			t.Fatalf("conflicting requests = %d, want exactly one loser of the revision race", conflicts)
		}

		runtimeFeed, _ = cfg.FeedSettings("osv")
		stored, err := store.GetFeedConfig(context.Background(), "osv")
		if err != nil {
			t.Fatalf("GetFeedConfig() error = %v", err)
		}
		persisted = stored
		cancel()
	})
	return runtimeFeed, defaults, persisted
}

// assertRuntimeMatchesPersistedFeedConfig requires the runtime to reflect the
// committed override, or the defaults when the override was reset.
func assertRuntimeMatchesPersistedFeedConfig(t *testing.T, runtimeFeed, defaults config.FeedSettings, persisted *db.FeedConfig) {
	t.Helper()
	want := defaults.SyncInterval
	if persisted != nil {
		if persisted.SyncInterval == nil {
			t.Fatalf("persisted override = %+v, want a sync interval", persisted)
		}
		want = *persisted.SyncInterval
	}
	if runtimeFeed.SyncInterval != want {
		t.Fatalf("runtime osv sync interval = %s, want %s (persisted %+v): the losing request restored a stale runtime snapshot over the committed config", runtimeFeed.SyncInterval, want, persisted)
	}
}

func TestFeedConfigSaveConflictKeepsRuntimeOnLastCommittedConfig(t *testing.T) {
	runtimeFeed, defaults, persisted := runFeedConfigRuntimeRace(t, nil, func(t *testing.T, h *AdminHandler, sm *auth.SessionManager) *httptest.ResponseRecorder {
		return postFeedConfigSave(t, h, sm, requestBSaveInterval.String())
	})
	assertRuntimeMatchesPersistedFeedConfig(t, runtimeFeed, defaults, persisted)
}

func TestFeedConfigChangesGiveUpWhenContextEndsWhileWaitingForOrderingSlot(t *testing.T) {
	t.Parallel()

	store := newAdminStoreStub()
	cfg := adminFlowConfig()
	handler, sm, _ := newAdminFlowHandler(t, store, cfg)
	applied := 0
	handler.SetFeedConfigApplyFunc(func(context.Context, config.FeedSettings) error {
		applied++
		return nil
	})
	handler.SetFeedConfigResetFunc(func(context.Context, string) (config.FeedSettings, bool, error) {
		applied++
		return config.FeedSettings{}, false, nil
	})

	release, err := handler.acquireFeedConfigSlot(t.Context())
	if err != nil {
		t.Fatalf("acquireFeedConfigSlot() error = %v", err)
	}
	defer release()

	for _, tt := range []struct {
		name    string
		target  string
		values  url.Values
		serve   func(http.ResponseWriter, *http.Request)
		wantMsg string
	}{
		{
			name:    "save",
			target:  "/admin/feeds/save",
			values:  url.Values{"feed_name": {"osv"}, "mode": {"self"}, "enabled": {"on"}},
			serve:   handler.HandleFeedConfigSave,
			wantMsg: web.Message("admin.feeds.error.save_persist"),
		},
		{
			name:    "reset",
			target:  "/admin/feeds/reset",
			values:  url.Values{"feed_name": {"osv"}, "confirm_reset": {"on"}},
			serve:   handler.HandleFeedConfigReset,
			wantMsg: web.Message("admin.feeds.error.reset_persist"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, tt.values)
			ctx, cancel := context.WithCancel(req.Context())
			cancel()
			rec := httptest.NewRecorder()

			tt.serve(rec, req.WithContext(ctx))

			want := adminFeedsRedirectURL("err", tt.wantMsg, "osv")
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
				t.Fatalf("%s = %d %q, want %q", tt.name, rec.Code, rec.Header().Get("Location"), want)
			}
		})
	}
	if applied != 0 {
		t.Fatalf("runtime apply/reset calls = %d, want none while another change holds the ordering slot", applied)
	}
	if stored, err := store.GetFeedConfig(t.Context(), "osv"); err != nil || stored != nil {
		t.Fatalf("persisted osv override = %+v, %v; want none", stored, err)
	}
}

func TestFeedConfigResetConflictKeepsRuntimeOnLastCommittedConfig(t *testing.T) {
	interval := 4 * time.Hour
	seed := &db.FeedConfig{
		FeedName:     "osv",
		Enabled:      true,
		Mode:         string(config.FeedModeSelf),
		SyncInterval: &interval,
		UpdatedAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	runtimeFeed, defaults, persisted := runFeedConfigRuntimeRace(t, seed, postFeedConfigReset)
	assertRuntimeMatchesPersistedFeedConfig(t, runtimeFeed, defaults, persisted)
}
