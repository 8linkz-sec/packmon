package main

import (
	"context"
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

	"github.com/8linkz/packmon/internal/api/admin"
	"github.com/8linkz/packmon/internal/auth"
	"github.com/8linkz/packmon/internal/config"
	"github.com/8linkz/packmon/internal/db"
	"github.com/8linkz/packmon/internal/web"
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
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/feeds body missing %q\nbody=%s", want, body)
		}
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
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("GET /admin/settings body missing %q\nbody=%s", want, body)
		}
	}
	if strings.Contains(body, "0001-01-01") {
		t.Fatalf("GET /admin/settings body contains zero timestamp: %s", body)
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

func TestHandleKeyCreateStoresExpiration(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":       {"ci-short-lived"},
		"expires_at": {"2030-01-02"},
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
	if got := keys[0].ExpiresAt.UTC().Format("2006-01-02"); got != "2030-01-02" {
		t.Fatalf("ExpiresAt date = %q, want 2030-01-02", got)
	}
}

func TestHandleKeyCreateRejectsPastExpiration(t *testing.T) {
	store := newNoopStore()
	handler, sm := newAdminTestHandler(t, store, testAdminConfig())
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/keys/create", url.Values{
		"name":       {"ci-expired"},
		"expires_at": {"2000-01-01"},
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
		"ecosystem":   {"npm"},
		"name":        {"left-pad"},
		"severity":    {"HIGH"},
		"risk_type":   {"other"},
		"summary":     {"manual advisory without upstream CVE"},
		"description": {"operator-created advisory"},
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
	for _, want := range []string{"vulnerability", "malicious", "left-pad", "evil"} {
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
		"id": {"manual:vuln-delete"},
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

func TestHandleFeedSyncNowTriggersSync(t *testing.T) {
	store := newNoopStore()
	syncCalled := make(chan string, 1)
	handler, sm := newAdminTestHandler(t, store, testAdminConfig(), func(_ context.Context, feedName string) error {
		syncCalled <- feedName
		return nil
	})
	req := newAuthenticatedAdminFormRequest(t, sm, "/admin/feeds/sync", url.Values{
		"feed_name": {"ghsa"},
	})
	rec := httptest.NewRecorder()

	handler.HandleFeedSyncNow(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /admin/feeds/sync status = %d, want 303", rec.Code)
	}

	select {
	case feedName := <-syncCalled:
		if feedName != "ghsa" {
			t.Fatalf("sync feedName = %q, want ghsa", feedName)
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
	if rec.Body.String() != "" {
		t.Fatalf("HTMX POST /admin/feeds/sync body = %q, want empty body on success", rec.Body.String())
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
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: "stale-session",
		Path:  "/",
	})
	rec := httptest.NewRecorder()

	handler.HandleAdminFeeds(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/feeds?partial=runtime status = %d, want 200", rec.Code)
	}
	if redirect := rec.Header().Get("HX-Redirect"); redirect != "/admin/login" {
		t.Fatalf("HX-Redirect = %q, want /admin/login", redirect)
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Fatalf("Location = %q, want empty for HTMX redirect", location)
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
		"feed_name": {"ghsa"},
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

func newAdminTestHandler(t *testing.T, store *noopStore, cfg *config.Config, syncFeed ...admin.FeedSyncFunc) (*admin.AdminHandler, *auth.SessionManager) {
	t.Helper()

	renderer := web.NewRenderer(web.TemplateFS(), false)
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
	sess, err := sm.Create(cookieRec)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	sess.Admin = true

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
	sess.Admin = true

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
