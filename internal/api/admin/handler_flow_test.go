package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/web"
)

type adminFlowStoreStub struct {
	db.Store
	mu             sync.Mutex
	adminAuth      *db.AdminAuth
	apiKeys        []db.APIKey
	nextAPIKeyID   int
	audit          []db.AdminAuditLogEntry
	nextAuditID    int
	feedStatuses   map[string]db.FeedSyncStatus
	feedConfigs    map[string]db.FeedConfig
	systemSettings *db.SystemSettings
	manual         map[string]db.ManualAdvisory
	queueJobs      []db.RefreshJob
	nextJobID      int
	dashboard      *db.DashboardStatsResult
}

func newAdminStoreStub() *adminFlowStoreStub {
	return &adminFlowStoreStub{
		feedStatuses: make(map[string]db.FeedSyncStatus),
		feedConfigs:  make(map[string]db.FeedConfig),
		manual:       make(map[string]db.ManualAdvisory),
		dashboard:    &db.DashboardStatsResult{BySeverity: map[string]int{}},
	}
}

func (s *adminFlowStoreStub) GetAdminAuth(context.Context) (*db.AdminAuth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.adminAuth == nil {
		return nil, nil
	}
	copyValue := *s.adminAuth
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertAdminAuth(_ context.Context, passwordHash string, isBootstrap bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if s.adminAuth == nil {
		s.adminAuth = &db.AdminAuth{CreatedAt: now}
	}
	s.adminAuth.PasswordHash = passwordHash
	s.adminAuth.PasswordIsBootstrap = isBootstrap
	s.adminAuth.PasswordChangedAt = &now
	return nil
}

func (s *adminFlowStoreStub) InsertAdminAuditLog(_ context.Context, entry *db.AdminAuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextAuditID++
	s.audit = append(s.audit, db.AdminAuditLogEntry{
		ID:        s.nextAuditID,
		Action:    entry.Action,
		Details:   append([]byte(nil), entry.Details...),
		IP:        entry.IP,
		CreatedAt: time.Now().UTC(),
	})
	if entry.Action == "login_success" && s.adminAuth != nil {
		now := time.Now().UTC()
		s.adminAuth.LastLoginAt = &now
	}
	return nil
}

func (s *adminFlowStoreStub) ListAdminAuditLog(_ context.Context, limit int) ([]db.AdminAuditLogEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > len(s.audit) {
		limit = len(s.audit)
	}
	out := make([]db.AdminAuditLogEntry, 0, limit)
	for i := len(s.audit) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.audit[i])
	}
	return out, nil
}

func (s *adminFlowStoreStub) ListAPIKeys(context.Context) ([]db.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]db.APIKey(nil), s.apiKeys...)
	return out, nil
}

func (s *adminFlowStoreStub) CreateAPIKey(_ context.Context, name, keyHash string, expiresAt *time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextAPIKeyID++
	s.apiKeys = append(s.apiKeys, db.APIKey{
		ID:        s.nextAPIKeyID,
		Name:      name,
		KeyHash:   keyHash,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	})
	return s.nextAPIKeyID, nil
}

func (s *adminFlowStoreStub) RevokeAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.apiKeys {
		if s.apiKeys[i].ID == keyID {
			now := time.Now().UTC()
			s.apiKeys[i].RevokedAt = &now
			return nil
		}
	}
	return nil
}

func (s *adminFlowStoreStub) DeleteAPIKey(_ context.Context, keyID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.apiKeys {
		if s.apiKeys[i].ID == keyID {
			s.apiKeys = append(s.apiKeys[:i], s.apiKeys[i+1:]...)
			return nil
		}
	}
	return nil
}

func (s *adminFlowStoreStub) GetFeedSyncStatus(_ context.Context, feedName string) (*db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.feedStatuses[config.NormalizeFeedName(feedName)]
	if !ok {
		return nil, nil
	}
	copyValue := status
	if status.Metadata != nil {
		copyValue.Metadata = append([]byte(nil), status.Metadata...)
	}
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *status
	if status.Metadata != nil {
		copyValue.Metadata = append([]byte(nil), status.Metadata...)
	}
	s.feedStatuses[config.NormalizeFeedName(status.FeedName)] = copyValue
	return nil
}

func (s *adminFlowStoreStub) ListFeedSyncStatuses(context.Context) ([]db.FeedSyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.FeedSyncStatus, 0, len(s.feedStatuses))
	for _, status := range s.feedStatuses {
		out = append(out, status)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FeedName < out[j].FeedName })
	return out, nil
}

func (s *adminFlowStoreStub) GetFeedConfig(_ context.Context, feedName string) (*db.FeedConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.feedConfigs[config.NormalizeFeedName(feedName)]
	if !ok {
		return nil, nil
	}
	copyValue := cfg
	if cfg.SyncInterval != nil {
		duration := *cfg.SyncInterval
		copyValue.SyncInterval = &duration
	}
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertFeedConfig(_ context.Context, cfg *db.FeedConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *cfg
	copyValue.FeedName = config.NormalizeFeedName(cfg.FeedName)
	copyValue.UpdatedAt = time.Now().UTC()
	if cfg.SyncInterval != nil {
		duration := *cfg.SyncInterval
		copyValue.SyncInterval = &duration
	}
	s.feedConfigs[copyValue.FeedName] = copyValue
	return nil
}

func (s *adminFlowStoreStub) DeleteFeedConfig(_ context.Context, feedName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.feedConfigs, config.NormalizeFeedName(feedName))
	return nil
}

func (s *adminFlowStoreStub) ListFeedConfigs(context.Context) ([]db.FeedConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.FeedConfig, 0, len(s.feedConfigs))
	for _, cfg := range s.feedConfigs {
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FeedName < out[j].FeedName })
	return out, nil
}

func (s *adminFlowStoreStub) GetSystemSettings(context.Context) (*db.SystemSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.systemSettings == nil {
		return nil, nil
	}
	copyValue := *s.systemSettings
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertSystemSettings(_ context.Context, settings *db.SystemSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *settings
	copyValue.UpdatedAt = time.Now().UTC()
	s.systemSettings = &copyValue
	return nil
}

func (s *adminFlowStoreStub) DashboardStats(context.Context) (*db.DashboardStatsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *s.dashboard
	copyValue.BySeverity = map[string]int{}
	for severity, count := range s.dashboard.BySeverity {
		copyValue.BySeverity[severity] = count
	}
	return &copyValue, nil
}

func (s *adminFlowStoreStub) UpsertManualAdvisory(_ context.Context, advisory *db.ManualAdvisory) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyValue := *advisory
	s.manual[copyValue.ID] = copyValue
	return nil
}

func (s *adminFlowStoreStub) DeleteManualAdvisory(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.manual, id)
	return nil
}

func (s *adminFlowStoreStub) ListManualAdvisories(context.Context, int) ([]db.ManualAdvisory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.ManualAdvisory, 0, len(s.manual))
	for _, advisory := range s.manual {
		out = append(out, advisory)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *adminFlowStoreStub) QueueStats(context.Context) (*db.QueueStatsResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := &db.QueueStatsResult{}
	for _, job := range s.queueJobs {
		switch job.Status {
		case "pending":
			stats.Pending++
		case "paused":
			stats.Paused++
		case "done":
			stats.Done++
		case "error":
			stats.Error++
		}
	}
	return stats, nil
}

func (s *adminFlowStoreStub) ListQueueJobs(_ context.Context, status string, limit int) ([]db.RefreshJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]db.RefreshJob, 0, len(s.queueJobs))
	for _, job := range s.queueJobs {
		if status != "" && job.Status != status {
			continue
		}
		out = append(out, job)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *adminFlowStoreStub) PurgeQueue(context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	purged := 0
	kept := s.queueJobs[:0]
	for _, job := range s.queueJobs {
		if job.Status == "done" || job.Status == "error" {
			purged++
			continue
		}
		kept = append(kept, job)
	}
	s.queueJobs = kept
	return purged, nil
}

func (s *adminFlowStoreStub) UpdateQueueJobPriority(_ context.Context, jobID, priority int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.queueJobs {
		if s.queueJobs[i].ID == jobID {
			s.queueJobs[i].Priority = priority
			return nil
		}
	}
	return nil
}

func (s *adminFlowStoreStub) PauseQueueJob(ctx context.Context, jobID int) error {
	return s.setQueueStatus(ctx, jobID, "paused")
}

func (s *adminFlowStoreStub) ResumeQueueJob(ctx context.Context, jobID int) error {
	return s.setQueueStatus(ctx, jobID, "pending")
}

func (s *adminFlowStoreStub) RetryQueueJob(ctx context.Context, jobID int) error {
	return s.setQueueStatus(ctx, jobID, "pending")
}

func (s *adminFlowStoreStub) setQueueStatus(_ context.Context, jobID int, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.queueJobs {
		if s.queueJobs[i].ID == jobID {
			s.queueJobs[i].Status = status
			s.queueJobs[i].Error = ""
			return nil
		}
	}
	return nil
}

func (s *adminFlowStoreStub) ClearQueue(_ context.Context, statuses []string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	allowed := map[string]struct{}{}
	for _, status := range statuses {
		allowed[status] = struct{}{}
	}
	cleared := 0
	kept := s.queueJobs[:0]
	for _, job := range s.queueJobs {
		if _, ok := allowed[job.Status]; ok {
			cleared++
			continue
		}
		kept = append(kept, job)
	}
	s.queueJobs = kept
	return cleared, nil
}

func (s *adminFlowStoreStub) addQueueJob(status string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextJobID++
	s.queueJobs = append(s.queueJobs, db.RefreshJob{
		ID:          s.nextJobID,
		Ecosystem:   "npm",
		Name:        "left-pad",
		Source:      "socket",
		Priority:    3,
		Status:      status,
		RequestedAt: time.Now().UTC(),
	})
	return s.nextJobID
}

func newAdminFlowHandler(t *testing.T, store *adminFlowStoreStub, cfg *config.Config, syncFeed ...FeedSyncFunc) (*AdminHandler, *auth.SessionManager, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sm := auth.NewSessionManager(ctx, time.Hour, false)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime := config.NewRuntimeSettings(cfg.Server.BlockThreshold, cfg.Server.RateLimitPerMinute, cfg.Server.RateLimitBurst)
	var syncFn FeedSyncFunc
	if len(syncFeed) > 0 {
		syncFn = syncFeed[0]
	}
	handler := NewAdminHandler(ctx, store, sm, web.NewRenderer(web.TemplateFS(), false), logger, cfg, runtime, syncFn)
	return handler, sm, cancel
}

func adminFlowConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Mode:               config.ModeDevelopment,
			BlockThreshold:     "CRITICAL",
			RateLimitPerMinute: 60,
			RateLimitBurst:     60,
		},
		DB:      config.DBConfig{Host: "db.internal", Name: "packmon", SSLMode: "disable"},
		Metrics: config.MetricsConfig{Host: "127.0.0.1", Port: 9090},
		Admin:   config.AdminConfig{SessionTimeout: time.Hour},
		FeedSync: config.FeedSyncConfig{
			Interval:  time.Hour,
			OnStartup: true,
		},
		// #nosec G101 -- this test fixture uses fake feed credentials.
		Feeds: config.FeedsConfig{
			OSVEnabled:           true,
			OSVMode:              config.FeedModeSelf,
			GHSAEnabled:          true,
			GHSAMode:             config.FeedModeSelf,
			OpenSSFEnabled:       true,
			OpenSSFMode:          config.FeedModeSelf,
			VulnCheckEnabled:     true,
			VulnCheckMode:        config.FeedModeExternal,
			VulnCheckAPIKey:      "runtime-vc-key",
			SocketEnabled:        false,
			SocketMode:           config.FeedModeSelf,
			ReversingLabsEnabled: false,
			ReversingLabsMode:    config.FeedModeSelf,
			CISAKEVEnabled:       true,
			CISAKEVMode:          config.FeedModeSelf,
			EPSSEnabled:          true,
			EPSSMode:             config.FeedModeSelf,
			NVDEnabled:           true,
			NVDMode:              config.FeedModeSelf,
		},
	}
}

func authenticatedAdminRequest(t *testing.T, sm *auth.SessionManager, method, target string) (*http.Request, *auth.Session) {
	t.Helper()

	rec := httptest.NewRecorder()
	sess, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.Admin = true

	req := httptest.NewRequest(method, target, nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req, sess
}

func authenticatedAdminFormRequest(t *testing.T, sm *auth.SessionManager, target string, values url.Values) (*http.Request, *auth.Session) {
	t.Helper()

	rec := httptest.NewRecorder()
	sess, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.Admin = true
	token, err := auth.CSRFToken(sess)
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}
	values.Set(auth.CSRFFieldName, token)

	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	return req, sess
}

func TestAdminPagesRenderWithAuthenticatedSession(t *testing.T) {
	store := newAdminStoreStub()
	now := time.Now().UTC()
	duration := 2 * time.Second
	if err := store.UpsertFeedSyncStatus(context.Background(), &db.FeedSyncStatus{
		FeedName:         "osv",
		LastSyncAt:       &now,
		LastSyncDuration: &duration,
		LastSyncStatus:   "success",
		EntriesSynced:    3,
		EntriesTotal:     4,
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}
	store.dashboard = &db.DashboardStatsResult{
		TotalPackages:        2,
		TotalVulnerabilities: 1,
		TotalMalicious:       1,
		BySeverity:           map[string]int{"HIGH": 1, "UNKNOWN": 2},
	}
	hash, err := auth.HashPassword("current-password")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, PasswordIsBootstrap: true, CreatedAt: now}
	store.addQueueJob("pending")
	store.audit = append(store.audit, db.AdminAuditLogEntry{ID: 1, Action: "login_success", Details: []byte(`{"ip":"127.0.0.1"}`), CreatedAt: now})
	store.manual["manual:existing"] = db.ManualAdvisory{ID: "manual:existing", FindingType: "vulnerability", Ecosystem: "npm", Name: "left-pad", Severity: "HIGH", Summary: "manual"}

	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	for _, tt := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
		want   string
	}{
		{name: "dashboard", target: "/admin/", call: handler.HandleDashboard, want: "Dashboard"},
		{name: "feeds", target: "/admin/feeds", call: handler.HandleAdminFeeds, want: "OSV"},
		{name: "queue", target: "/admin/queue", call: handler.HandleAdminQueue, want: "left-pad"},
		{name: "keys", target: "/admin/keys", call: handler.HandleAdminKeys, want: "API Keys"},
		{name: "advisories", target: "/admin/advisories", call: handler.HandleAdminAdvisories, want: "manual:existing"},
		{name: "audit", target: "/admin/audit", call: handler.HandleAdminAudit, want: "login_success"},
		{name: "settings", target: "/admin/settings", call: handler.HandleAdminSettings, want: "development"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, tt.target)
			rec := httptest.NewRecorder()
			tt.call(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, want 200; body=%s", tt.target, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.want) {
				t.Fatalf("%s body missing %q\nbody=%s", tt.target, tt.want, rec.Body.String())
			}
		})
	}
}

func TestAdminKeyLifecycleUsesFlashAndAudit(t *testing.T) {
	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, sess := authenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":       {"ci"},
		"expires_at": {"2030-01-02"},
	})
	rec := httptest.NewRecorder()
	handler.HandleKeyCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyCreate status = %d, want 303", rec.Code)
	}
	if newKey := sm.GetFlash(sess.ID, "newkey"); len(newKey) != 64 {
		t.Fatalf("flash newkey length = %d, want 64 hex chars", len(newKey))
	}

	keys, err := store.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0].ExpiresAt == nil {
		t.Fatalf("keys after create = %+v, want one expiring key", keys)
	}
	keyID := strconv.Itoa(keys[0].ID)

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/revoke", url.Values{"key_id": {keyID}})
	rec = httptest.NewRecorder()
	handler.HandleKeyRevoke(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyRevoke status = %d, want 303", rec.Code)
	}
	keys, _ = store.ListAPIKeys(context.Background())
	if keys[0].RevokedAt == nil {
		t.Fatal("key RevokedAt = nil after revoke")
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/keys/delete", url.Values{"key_id": {keyID}})
	rec = httptest.NewRecorder()
	handler.HandleKeyDelete(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleKeyDelete status = %d, want 303", rec.Code)
	}
	keys, _ = store.ListAPIKeys(context.Background())
	if len(keys) != 0 {
		t.Fatalf("keys after delete = %+v, want empty", keys)
	}

	audit, err := store.ListAdminAuditLog(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	for _, want := range []string{"api_key_create", "api_key_revoke", "api_key_delete"} {
		if !adminFlowAuditContains(audit, want) {
			t.Fatalf("audit missing %q: %+v", want, audit)
		}
	}
}

func TestAdminFeedConfigSaveResetAndSyncNow(t *testing.T) {
	store := newAdminStoreStub()
	syncCalled := make(chan string, 1)
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig(), func(_ context.Context, feedName string) error {
		syncCalled <- feedName
		return nil
	})

	var applied config.FeedSettings
	handler.SetFeedConfigApplyFunc(func(_ context.Context, feed config.FeedSettings) error {
		applied = feed
		return nil
	})
	var resetFeed string
	handler.SetFeedConfigResetFunc(func(_ context.Context, feedName string) error {
		resetFeed = feedName
		return nil
	})

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/feeds/save", url.Values{
		"feed_name":     {"vulncheck"},
		"enabled":       {"on"},
		"mode":          {"self"},
		"api_key":       {"override-key"},
		"sync_interval": {"45m"},
	})
	rec := httptest.NewRecorder()
	handler.HandleFeedConfigSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigSave status = %d, want 303", rec.Code)
	}
	if applied.Name != "vulncheck" || !applied.Enabled || applied.Mode != config.FeedModeSelf || applied.APIKey != "override-key" {
		t.Fatalf("applied feed = %+v, want saved vulncheck settings", applied)
	}
	override, err := store.GetFeedConfig(context.Background(), "vulncheck")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if override == nil || override.APIKey != "override-key" {
		t.Fatalf("stored override = %+v, want api key override", override)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/reset", url.Values{"feed_name": {"vulncheck"}})
	rec = httptest.NewRecorder()
	handler.HandleFeedConfigReset(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleFeedConfigReset status = %d, want 303", rec.Code)
	}
	if resetFeed != "vulncheck" {
		t.Fatalf("reset feed = %q, want vulncheck", resetFeed)
	}
	override, _ = store.GetFeedConfig(context.Background(), "vulncheck")
	if override != nil {
		t.Fatalf("override after reset = %+v, want nil", override)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{"feed_name": {"osv"}})
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.HandleFeedSyncNow(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleFeedSyncNow status = %d, want 200", rec.Code)
	}
	if trigger := rec.Header().Get("HX-Trigger"); !strings.Contains(trigger, "feed-runtime-refresh") {
		t.Fatalf("HX-Trigger = %q, want feed-runtime-refresh", trigger)
	}
	select {
	case got := <-syncCalled:
		if got != "osv" {
			t.Fatalf("sync feed = %q, want osv", got)
		}
	case <-time.After(time.Second):
		t.Fatal("sync callback was not called")
	}
	status, err := store.GetFeedSyncStatus(context.Background(), "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || status.LastSyncStatus != "running" {
		t.Fatalf("feed status = %+v, want running", status)
	}
}

func TestAdminSystemSettingsPasswordAndAdvisoryFlows(t *testing.T) {
	store := newAdminStoreStub()
	currentPassword := "current-password"
	hash, err := auth.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	store.adminAuth = &db.AdminAuth{PasswordHash: hash, CreatedAt: time.Now().UTC()}

	cfg := adminFlowConfig()
	handler, sm, _ := newAdminFlowHandler(t, store, cfg)

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/settings/system", url.Values{
		"block_threshold":       {"HIGH"},
		"rate_limit_per_minute": {"120"},
		"rate_limit_burst":      {"25"},
	})
	rec := httptest.NewRecorder()
	handler.HandleSystemSettingsSave(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleSystemSettingsSave status = %d, want 303", rec.Code)
	}
	settings, err := store.GetSystemSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSystemSettings() error = %v", err)
	}
	if settings == nil || settings.BlockThreshold != "HIGH" || handler.runtime.BlockThreshold() != "HIGH" {
		t.Fatalf("settings = %+v runtime threshold=%q, want HIGH", settings, handler.runtime.BlockThreshold())
	}

	newPassword := "newpass12345"
	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/settings/password", url.Values{
		"current_password": {currentPassword},
		"new_password":     {newPassword},
		"confirm_password": {newPassword},
	})
	rec = httptest.NewRecorder()
	handler.HandlePasswordChange(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandlePasswordChange status = %d, want 303", rec.Code)
	}
	adminAuth, err := store.GetAdminAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminAuth() error = %v", err)
	}
	if adminAuth == nil || !auth.CheckPassword(adminAuth.PasswordHash, newPassword) {
		t.Fatal("new admin password was not stored")
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"id":           {"manual:one"},
		"finding_type": {"vulnerability"},
		"ecosystem":    {"npm"},
		"name":         {"left-pad"},
		"severity":     {"HIGH"},
		"summary":      {"manual vulnerability"},
	})
	rec = httptest.NewRecorder()
	handler.HandleAdvisoryCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryCreate status = %d, want 303", rec.Code)
	}
	advisories, err := store.ListManualAdvisories(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(advisories) != 1 || advisories[0].ID != "manual:one" {
		t.Fatalf("advisories = %+v, want manual:one", advisories)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{"id": {"manual:one"}})
	rec = httptest.NewRecorder()
	handler.HandleAdvisoryDelete(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleAdvisoryDelete status = %d, want 303", rec.Code)
	}
	advisories, _ = store.ListManualAdvisories(context.Background(), 10)
	if len(advisories) != 0 {
		t.Fatalf("advisories after delete = %+v, want empty", advisories)
	}
}

func TestAdminQueueActions(t *testing.T) {
	store := newAdminStoreStub()
	doneJob := store.addQueueJob("done")
	pendingJob := store.addQueueJob("pending")
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/queue/purge", url.Values{})
	rec := httptest.NewRecorder()
	handler.HandleQueuePurge(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleQueuePurge status = %d, want 303", rec.Code)
	}
	if jobs, _ := store.ListQueueJobs(context.Background(), "", 10); len(jobs) != 1 || jobs[0].ID == doneJob {
		t.Fatalf("jobs after purge = %+v, want done job removed", jobs)
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/queue/priority", url.Values{
		"job_id":   {strconv.Itoa(pendingJob)},
		"priority": {"1"},
	})
	rec = httptest.NewRecorder()
	handler.HandleQueuePriorityUpdate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleQueuePriorityUpdate status = %d, want 303", rec.Code)
	}
	jobs, _ := store.ListQueueJobs(context.Background(), "", 10)
	if jobs[0].Priority != 1 {
		t.Fatalf("priority after update = %d, want 1", jobs[0].Priority)
	}

	for _, tt := range []struct {
		name   string
		target string
		call   func(http.ResponseWriter, *http.Request)
		status string
	}{
		{name: "pause", target: "/admin/queue/pause", call: handler.HandleQueuePause, status: "paused"},
		{name: "resume", target: "/admin/queue/resume", call: handler.HandleQueueResume, status: "pending"},
		{name: "retry", target: "/admin/queue/retry", call: handler.HandleQueueRetry, status: "pending"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := authenticatedAdminFormRequest(t, sm, tt.target, url.Values{"job_id": {strconv.Itoa(pendingJob)}})
			rec := httptest.NewRecorder()
			tt.call(rec, req)
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("%s status = %d, want 303", tt.target, rec.Code)
			}
			jobs, _ := store.ListQueueJobs(context.Background(), "", 10)
			if jobs[0].Status != tt.status {
				t.Fatalf("job status = %q, want %q", jobs[0].Status, tt.status)
			}
		})
	}

	req, _ = authenticatedAdminFormRequest(t, sm, "/admin/queue/clear", url.Values{"status": {"pending"}})
	rec = httptest.NewRecorder()
	handler.HandleQueueClear(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("HandleQueueClear status = %d, want 303", rec.Code)
	}
	jobs, _ = store.ListQueueJobs(context.Background(), "", 10)
	if len(jobs) != 0 {
		t.Fatalf("jobs after clear = %+v, want empty", jobs)
	}
}

func adminFlowAuditContains(entries []db.AdminAuditLogEntry, action string) bool {
	for _, entry := range entries {
		if entry.Action == action {
			return true
		}
	}
	return false
}
