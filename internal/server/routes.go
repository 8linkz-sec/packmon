package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/8linkz-sec/packmon/internal/api/admin"
	v1 "github.com/8linkz-sec/packmon/internal/api/v1"
	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/config"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/feed/packagefilter"
	"github.com/8linkz-sec/packmon/internal/feed/reputation"
	"github.com/8linkz-sec/packmon/internal/feed/socket"
	"github.com/8linkz-sec/packmon/internal/health"
	"github.com/8linkz-sec/packmon/internal/web"
)

// routeDependencies groups the collaborators needed to wire HTTP routes.
type routeDependencies struct {
	ctx             context.Context
	mux             *http.ServeMux
	healthChecker   *health.Checker
	cfg             *config.Config
	runtime         *config.RuntimeSettings
	store           db.Store
	sessionManager  *auth.SessionManager
	logger          *slog.Logger
	buildInfo       BuildInfo
	syncFeed        admin.FeedSyncFunc
	applyFeedConfig admin.FeedConfigApplyFunc
	resetFeedConfig admin.FeedConfigResetFunc
}

// registerRoutes wires all HTTP routes on the given mux. The context is
// forwarded to subsystems that start background goroutines.
func registerRoutes(deps routeDependencies) {
	ctx := deps.ctx
	mux := deps.mux
	hc := deps.healthChecker
	cfg := deps.cfg
	runtime := deps.runtime
	store := deps.store
	sm := deps.sessionManager
	logger := deps.logger
	buildInfo := deps.buildInfo
	syncFeed := deps.syncFeed
	applyFeedConfig := deps.applyFeedConfig
	resetFeedConfig := deps.resetFeedConfig

	apiStore := v1.NewDBStoreAdapter(store)
	api := v1.NewHandlerWithRuntime(apiStore, logger, runtime)
	var feedImportStore v1.FeedImportStore
	if apiStore != nil {
		feedImportStore = apiStore
	}
	feedImport := v1.NewFeedImportHandler(feedImportStore, logger)
	api.ConfigureReputationScheduler(newAPIReputationScheduler(store, logger))
	api.ConfigurePackageRefreshProvider(&apiSocketRefreshProvider{})
	api.ConfigureBackgroundContext(ctx)
	if cfg != nil {
		configureAPIFeedHandlers(api, feedImport, cfg.FeedsSnapshot(), cfg.Server.Mode == config.ModeProduction)
	}
	applyAndRefreshAPI := applyFeedConfig
	if applyFeedConfig != nil {
		applyAndRefreshAPI = func(ctx context.Context, feed config.FeedSettings) error {
			if err := applyFeedConfig(ctx, feed); err != nil {
				return err
			}
			if cfg != nil {
				configureAPIFeedHandlers(api, feedImport, cfg.FeedsSnapshot(), cfg.Server.Mode == config.ModeProduction)
			}
			return nil
		}
	}
	resetAndRefreshAPI := resetFeedConfig
	if resetFeedConfig != nil {
		resetAndRefreshAPI = func(ctx context.Context, feedName string) (config.FeedSettings, bool, error) {
			settings, ok, err := resetFeedConfig(ctx, feedName)
			if err != nil {
				return settings, ok, err
			}
			if cfg != nil {
				configureAPIFeedHandlers(api, feedImport, cfg.FeedsSnapshot(), cfg.Server.Mode == config.ModeProduction)
			}
			return settings, ok, nil
		}
	}

	// -- Operations (no auth required) ----------------------------------------
	mux.HandleFunc("GET /healthz", hc.LiveHandler())
	mux.HandleFunc("GET /readyz", hc.ReadyHandler())
	mux.HandleFunc("GET /version", versionHandler(buildInfo))

	// -- API v1 ---------------------------------------------------------------
	mux.HandleFunc("/api/v1/check", api.HandleCheck)
	mux.HandleFunc("/api/v1/feeds/status", api.HandleFeedStatus)
	mux.HandleFunc("/api/v1/feeds/{feed}/import", feedImport.HandleImport)
	// The {name...} wildcard must be at the end of the pattern in Go's
	// ServeMux. We register a single catch-all and dispatch to the detail
	// or refresh handler based on the HTTP method and whether the trailing
	// path segment is "refresh". See HandlePackage.
	mux.HandleFunc("/api/v1/packages/{ecosystem}/{rest...}", api.HandlePackage)
	mux.HandleFunc("/api/v1/sync", api.HandleSync)
	mux.HandleFunc("/api/v1", v1.HandleNotFound)
	mux.HandleFunc("/api/v1/{path...}", v1.HandleNotFound)

	// -- Admin (session-protected) --------------------------------------------
	admin.RegisterRoutes(ctx, mux, store, sm, logger, cfg, runtime, syncFeed, applyAndRefreshAPI, resetAndRefreshAPI)

	// -- Web GUI (public pages: dashboard, search, package, feeds) -----------
	renderer := web.NewRendererWithLayoutLinks(web.TemplateFS(), false, serverLayoutLinks(cfg))
	web.RegisterRoutes(mux, web.NewDBStoreAdapter(store), renderer, logger)
}

func configureAPIFeedHandlers(api *v1.Handler, feedImport *v1.FeedImportHandler, feeds config.FeedsConfig, production bool) {
	if api == nil {
		return
	}
	api.ConfigureReversingLabs(feeds)
	api.ConfigureSocketRefresh(feeds)
	if feedImport != nil {
		feedImport.ConfigureFeedImportSecret(feeds.FeedImportSecret, production)
	}
}

func serverLayoutLinks(cfg *config.Config) web.LayoutLinks {
	if cfg == nil {
		return web.LayoutLinks{}
	}
	return web.LayoutLinks{
		PrivacyURL: cfg.Web.PrivacyURL,
		LegalURL:   cfg.Web.LegalURL,
		TermsURL:   cfg.Web.TermsURL,
	}
}

type apiReputationScheduler struct {
	inner *reputation.Scheduler
}

func newAPIReputationScheduler(store db.Store, logger *slog.Logger) *apiReputationScheduler {
	schedulerStore, ok := any(store).(reputation.Store)
	if !ok {
		return nil
	}
	return &apiReputationScheduler{
		inner: reputation.NewScheduler(schedulerStore, logger, reputation.Config{}),
	}
}

func (s *apiReputationScheduler) Configure(cfg v1.ReputationSchedulerConfig) {
	if s == nil || s.inner == nil {
		return
	}
	s.inner.Configure(reputation.Config{
		ReversingLabsActive:              cfg.ReversingLabsActive,
		ReversingLabsMaxSchedulePerCheck: cfg.ReversingLabsMaxSchedulePerCheck,
		ReversingLabsExcludedNamespaces:  cfg.ReversingLabsExcludedNamespaces,
	})
}

func (s *apiReputationScheduler) ScheduleReversingLabsAsync(ctx context.Context, packages []domain.Package, findings []domain.Finding) {
	if s == nil || s.inner == nil {
		return
	}
	s.inner.ScheduleReversingLabsAsync(ctx, packages, findings)
}

type apiSocketRefreshProvider struct {
	active   atomic.Bool
	excluded atomic.Value
}

func (p *apiSocketRefreshProvider) Configure(cfg v1.PackageRefreshProviderConfig) {
	if p == nil {
		return
	}
	p.active.Store(cfg.Active)
	p.excluded.Store(append([]string(nil), cfg.ExcludedNamespaces...))
}

func (p *apiSocketRefreshProvider) Active() bool {
	return p != nil && p.active.Load()
}

func (p *apiSocketRefreshProvider) Source() string {
	return socket.FeedName
}

func (p *apiSocketRefreshProvider) SupportsEcosystem(ecosystem string) bool {
	return socket.SupportsEcosystem(ecosystem)
}

func (p *apiSocketRefreshProvider) ExcludedByPolicy(ecosystem, name string) bool {
	if p == nil {
		return false
	}
	raw := p.excluded.Load()
	prefixes, _ := raw.([]string)
	return packagefilter.ExcludedByNamespace(prefixes, ecosystem, name)
}

// BuildInfo is injected at build time via ldflags.
type BuildInfo struct {
	Version       string
	Commit        string
	Date          string
	SchemaVersion uint
}

func versionHandler(bi BuildInfo) http.HandlerFunc {
	payload, _ := json.Marshal(map[string]string{
		"version": bi.Version,
		"commit":  bi.Commit,
		"date":    bi.Date,
	})
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(payload)
	}
}
