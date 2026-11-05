package server

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
	"time"

	v1 "github.com/8linkz-sec/packmon/internal/api/v1"
	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/health"
)

type f368FeedConfigStore struct {
	db.Store
	mu      sync.Mutex
	configs map[string]db.FeedConfig
}

func (*f368FeedConfigStore) GetAdminAuth(context.Context) (*db.AdminAuth, error) {
	return &db.AdminAuth{PasswordIsBootstrap: false}, nil
}

func (s *f368FeedConfigStore) GetFeedConfig(_ context.Context, feedName string) (*db.FeedConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.configs[config.NormalizeFeedName(feedName)]
	if !ok {
		return nil, nil
	}
	copyValue := stored
	return &copyValue, nil
}

func (s *f368FeedConfigStore) UpsertFeedConfigWithAudit(_ context.Context, feed *db.FeedConfig, _ *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *feed
	copyValue.UpdatedAt = time.Now().UTC()
	s.configs[config.NormalizeFeedName(feed.FeedName)] = copyValue
	return nil
}

func (s *f368FeedConfigStore) DeleteFeedConfigWithAudit(_ context.Context, feedName string, _ *time.Time, _ *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.configs, config.NormalizeFeedName(feedName))
	return nil
}

type f368ReputationStore struct {
	db.Store
	marked chan db.PackageReputation
}

func (s *f368ReputationStore) MarkPackageReputationDue(_ context.Context, rep *db.PackageReputation) (bool, error) {
	s.marked <- *rep
	return false, nil
}

func (*f368ReputationStore) UpsertPackageReputation(context.Context, *db.PackageReputation) error {
	return nil
}

func (*f368ReputationStore) EnqueueRefresh(context.Context, *db.RefreshJob) (bool, int, error) {
	return false, 0, nil
}

func f368RouteConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Mode: config.ModeDevelopment, BlockThreshold: "CRITICAL"},
		Admin:  config.AdminConfig{SessionTimeout: time.Hour},
		Feeds: config.FeedsConfig{
			VulnCheckMode: config.FeedModeSelf,
		},
		FeedSync: config.FeedSyncConfig{Interval: time.Hour},
	}
}

func f368AdminFormRequest(t *testing.T, sm *auth.SessionManager, target string, values url.Values) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	session, err := sm.CreateAdmin(rec, false)
	if err != nil {
		t.Fatalf("CreateAdmin(): %v", err)
	}
	token, err := auth.CSRFToken(session)
	if err != nil {
		t.Fatalf("CSRFToken(): %v", err)
	}
	values.Set(auth.CSRFFieldName, token)
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req
}

func TestF368RegisterRoutesRefreshesAPIFeedHandlersAfterSaveAndReset(t *testing.T) {
	t.Run("save", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cfg := f368RouteConfig()
		store := &f368FeedConfigStore{configs: make(map[string]db.FeedConfig)}
		mux := http.NewServeMux()
		sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
		var applied config.FeedSettings
		registerRoutes(routeDependencies{
			ctx:            ctx,
			mux:            mux,
			healthChecker:  health.NewChecker(routePinger{}),
			cfg:            cfg,
			runtime:        config.NewRuntimeSettings("CRITICAL", 60, 60),
			store:          store,
			sessionManager: sm,
			logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			applyFeedConfig: func(_ context.Context, feed config.FeedSettings) error {
				applied = feed
				return cfg.SetFeedSettings(feed)
			},
		})

		req := f368AdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
			"feed_name":     {"vulncheck"},
			"enabled":       {"on"},
			"mode":          {"self"},
			"api_key":       {"runtime-key"},
			"sync_interval": {"1h"},
		})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("save status = %d, want 303; body=%s", rec.Code, rec.Body.String())
		}
		if applied.Name != "vulncheck" || applied.APIKey != "runtime-key" {
			t.Fatalf("applied feed = %+v", applied)
		}
	})

	t.Run("reset", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cfg := f368RouteConfig()
		store := &f368FeedConfigStore{configs: make(map[string]db.FeedConfig)}
		mux := http.NewServeMux()
		sm := auth.NewSessionManagerWithIdleTimeout(ctx, time.Hour, auth.DefaultAdminIdleTimeout, false)
		var resetName string
		registerRoutes(routeDependencies{
			ctx:            ctx,
			mux:            mux,
			healthChecker:  health.NewChecker(routePinger{}),
			cfg:            cfg,
			runtime:        config.NewRuntimeSettings("CRITICAL", 60, 60),
			store:          store,
			sessionManager: sm,
			logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			resetFeedConfig: func(_ context.Context, feedName string) (config.FeedSettings, bool, error) {
				resetName = feedName
				feed, ok := cfg.FeedSettings(feedName)
				return feed, ok, nil
			},
		})

		req := f368AdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{
			"feed_name":     {"vulncheck"},
			"confirm_reset": {"on"},
		})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("reset status = %d, want 303; body=%s", rec.Code, rec.Body.String())
		}
		if resetName != "vulncheck" {
			t.Fatalf("reset feed = %q, want vulncheck", resetName)
		}
	})
}

func TestF368FeedConfigurationAndReputationSchedulerBoundaries(t *testing.T) {
	t.Parallel()

	configureAPIFeedHandlers(nil, nil, config.FeedsConfig{}, false)
	var nilScheduler *apiReputationScheduler
	nilScheduler.ScheduleReversingLabsAsync(context.Background(), nil, nil)

	store := &f368ReputationStore{marked: make(chan db.PackageReputation, 1)}
	scheduler := newAPIReputationScheduler(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if scheduler == nil {
		t.Fatal("newAPIReputationScheduler() = nil for reputation store")
	}
	scheduler.Configure(v1.ReputationSchedulerConfig{ReversingLabsActive: true, ReversingLabsMaxSchedulePerCheck: 1})
	scheduler.ScheduleReversingLabsAsync(context.Background(), []domain.Package{{
		Ecosystem: domain.EcosystemNPM,
		Name:      "left-pad",
		Version:   "1.0.0",
	}}, nil)
	select {
	case marked := <-store.marked:
		if marked.Name != "left-pad" || marked.Source != db.ReputationSourceReversingLabs {
			t.Fatalf("marked reputation = %+v", marked)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reputation scheduling")
	}
}
