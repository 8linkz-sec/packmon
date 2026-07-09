package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestAdminQueueTemplateUsesStatusViewModel(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("../../web/templates/admin/queue.html")
	if err != nil {
		t.Fatalf("read queue template: %v", err)
	}
	text := string(src)
	for _, forbidden := range []string{
		`eq .Status "pending"`,
		`eq .Status "processing"`,
		`eq .Status "paused"`,
		`eq .Status "done"`,
		`eq .Status "error"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("queue template still branches on raw status value %q", forbidden)
		}
	}
	for _, want := range []string{
		".StatusClass",
		".StatusLabel",
		".CanPause",
		".CanResume",
		".CanRetry",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("queue template missing status view-model field %s", want)
		}
	}
}

func TestAdminAPIKeyTemplateUsesStatusViewModel(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("../../web/templates/admin/keys.html")
	if err != nil {
		t.Fatalf("read keys template: %v", err)
	}
	text := string(src)
	for _, forbidden := range []string{
		`bg-gray-200 text-gray-800">deleted`,
		`bg-red-100 text-red-800">revoked`,
		`bg-amber-100 text-amber-800">expired`,
		`bg-green-100 text-green-800">active`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("keys template still hardcodes API-key status badge %q", forbidden)
		}
	}
	for _, want := range []string{
		".StatusClass",
		".StatusLabel",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("keys template missing API-key status view-model field %s", want)
		}
	}
}

func TestAdminAPIKeyHandlersUseMessageCatalogForFlashText(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("pages.go")
	if err != nil {
		t.Fatalf("read pages.go: %v", err)
	}
	text := string(src)
	for _, want := range []string{
		`web.Message("admin.keys.flash.created")`,
		`web.Message("admin.keys.error.generate")`,
		`web.Message("admin.keys.error.create")`,
		`web.Message("admin.keys.error.create_expired")`,
		`web.Message("admin.keys.error.audit_log")`,
		`web.Message("admin.keys.error.too_many_attempts")`,
		`web.Message("admin.keys.error.verify_current_password")`,
		`web.Message("admin.keys.error.current_password_incorrect")`,
		`web.Message("admin.keys.error.invalid_id")`,
		`web.Message("admin.keys.flash.revoked")`,
		`web.Message("admin.keys.flash.deleted")`,
		`web.Message("admin.keys.error.revoke")`,
		`web.Message("admin.keys.error.delete")`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("pages.go missing API-key message catalog marker %q", want)
		}
	}
	for _, forbidden := range []string{
		`"Failed to generate key"`,
		`"Failed to create API key"`,
		`"API key created"`,
		`"Key creation request expired. Reload the page and try again."`,
		`"Too many failed password attempts. Please try again later."`,
		`"Current password is incorrect"`,
		`"Invalid key ID"`,
		`"Key revoked"`,
		`"Key deleted"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("pages.go still hardcodes API-key handler text %q", forbidden)
		}
	}
}

func TestAdminSettingsHandlersUseMessageCatalogForFlashText(t *testing.T) {
	t.Parallel()

	targets := map[string][]string{
		"settings_forms.go": {
			`web.Message("admin.settings.error.invalid_block_threshold")`,
			`web.Message("admin.settings.error.block_threshold_none_ack")`,
			`web.Message("admin.settings.error.invalid_rate_limit_per_minute")`,
			`web.Message("admin.settings.error.invalid_rate_limit_burst")`,
			`web.Message("admin.settings.error.load_system_settings")`,
			`web.Message("admin.settings.error.invalid_scan_log_retention")`,
			`web.Message("admin.settings.error.invalid_admin_audit_retention")`,
			`web.Message("admin.settings.error.invalid_revision")`,
			`web.Message("admin.settings.error.conflict")`,
			`web.Message("admin.settings.error.audit_log")`,
			`web.Message("admin.settings.error.save")`,
			`web.Message("admin.settings.flash.saved")`,
		},
		"pages.go": {
			`web.Message("admin.settings.error.auth_state")`,
			`web.Message("admin.settings.error.system_settings_load")`,
			`web.Message("admin.settings.error.password.too_many_attempts")`,
			`web.Message("admin.settings.error.audit_log")`,
			`web.Message("admin.settings.error.password.mismatch")`,
			`web.Message("admin.settings.error.password.too_short"`,
			`web.Message("admin.settings.error.password.verify_current")`,
			`web.Message("admin.settings.error.password.current_incorrect")`,
			`web.Message("admin.settings.error.password.reused")`,
			`web.Message("admin.settings.error.password.update")`,
			`web.Message("admin.settings.flash.password_changed")`,
		},
	}
	for path, wants := range targets {
		path := path
		wants := wants
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			text := string(src)
			for _, want := range wants {
				if !strings.Contains(text, want) {
					t.Fatalf("%s missing settings message catalog marker %q", path, want)
				}
			}
		})
	}
	for path, forbidden := range map[string][]string{
		"settings_forms.go": {
			`"Invalid block threshold"`,
			`"Block threshold NONE requires explicit acknowledgement"`,
			`"Invalid rate limit per minute"`,
			`"Invalid rate limit burst"`,
			`"Failed to load system settings"`,
			`"Invalid scan log retention"`,
			`"Invalid admin audit retention"`,
			`"Invalid system settings revision"`,
			`"System settings saved and applied."`,
		},
		"pages.go": {
			`"System settings could not be loaded. Reload after the database is healthy before saving policy changes."`,
			`"New passwords do not match"`,
			`"Failed to verify current password"`,
			`"Current password is incorrect"`,
			`"Failed to update password"`,
			`"Password changed successfully"`,
		},
	} {
		path := path
		forbidden := forbidden
		t.Run(path+"_forbidden_literals", func(t *testing.T) {
			t.Parallel()

			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			text := string(src)
			for _, blocked := range forbidden {
				if strings.Contains(text, blocked) {
					t.Fatalf("%s still hardcodes settings handler text %q", path, blocked)
				}
			}
		})
	}
}

func TestAdminFeedHandlersUseMessageCatalogForFlashText(t *testing.T) {
	t.Parallel()

	targets := map[string][]string{
		"feed_forms.go": {
			`web.Message("admin.feeds.error.load_config")`,
			`web.Message("admin.feeds.error.invalid_mode")`,
			`web.Message("admin.feeds.error.invalid_sync_interval")`,
			`web.Message("admin.feeds.error.ambiguous_api_key_action")`,
			`web.Message("admin.feeds.error.unconfirmed_api_key_clear")`,
			`web.Message("admin.feeds.error.save_apply_failed")`,
			`web.Message("admin.feeds.error.apply_unavailable")`,
			`web.Message("admin.feeds.error.save_conflict")`,
			`web.Message("admin.feeds.error.audit_log")`,
			`web.Message("admin.feeds.error.save_persist")`,
			`web.Message("admin.feeds.flash.saved_applied")`,
			`web.Message("admin.feeds.flash.saved")`,
			`web.Message("admin.feeds.error.unknown_feed")`,
			`web.Message("admin.feeds.error.confirm_reset")`,
			`web.Message("admin.feeds.error.reset_apply_failed")`,
			`web.Message("admin.feeds.error.reset_unavailable")`,
			`web.Message("admin.feeds.error.reset_persist")`,
			`web.Message("admin.feeds.flash.reset_applied")`,
			`web.Message("admin.feeds.flash.reset")`,
			`web.Message("admin.feeds.sync.error.unavailable_for_feed")`,
			`web.Message("admin.feeds.sync.error.enabled_self_only")`,
			`web.Message("admin.feeds.sync.error.unavailable_mode")`,
			`web.Message("admin.feeds.sync.error.already_running"`,
			`web.Message("admin.feeds.sync.flash.started"`,
		},
		"runtime_config.go": {
			`web.Message("admin.feeds.form.sync_interval.self_label")`,
			`web.Message("admin.feeds.form.sync_interval.cadence_label")`,
			`web.Message("admin.feeds.form.sync_interval.self_help"`,
			`web.Message("admin.feeds.form.sync_interval.external_help"`,
			`web.Message("admin.feeds.form.sync_interval.queue_driven_help")`,
			`web.Message("admin.feeds.form.api_key.vulncheck_help"`,
			`web.Message("admin.feeds.status.key.configured")`,
			`web.Message("admin.feeds.status.key.missing")`,
			`web.Message("admin.feeds.status.key.not_configured")`,
			`web.Message("admin.feeds.status.key.not_required")`,
			`web.Message("admin.feeds.status.queue_driven")`,
			`web.Message("admin.feeds.status.runtime_unknown")`,
			`web.Message("admin.feeds.status.runtime_default"`,
			`web.Message("admin.feeds.status.runtime_override"`,
		},
	}
	for path, wants := range targets {
		path := path
		wants := wants
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			text := string(src)
			for _, want := range wants {
				if !strings.Contains(text, want) {
					t.Fatalf("%s missing feed message catalog marker %q", path, want)
				}
			}
		})
	}
	for path, forbidden := range map[string][]string{
		"feed_forms.go": {
			`"Failed to load feed configuration"`,
			`"Invalid feed mode"`,
			`"Invalid sync interval"`,
			`"Choose either a new API key or clear the stored key"`,
			`"Confirm API key removal"`,
			`"Feed configuration saved and applied."`,
			`"Feed configuration reset."`,
			`"Manual sync is not available for this feed"`,
			`"Manual sync is available only for enabled self-managed feeds."`,
			`"Failed to record feed sync status"`,
			`" sync is already running."`,
			`" sync started with current runtime settings."`,
		},
		"runtime_config.go": {
			`"Self-sync interval"`,
			`"Sync cadence"`,
			`"This feed does not run on a periodic timer. It is queue-driven."`,
			`"Required when VulnCheck is enabled.`,
			`"configured"`,
			`"not configured"`,
			`"not required"`,
			`"queue-driven"`,
			`"unknown"`,
			`" (default)"`,
			`" (override)"`,
		},
	} {
		path := path
		forbidden := forbidden
		t.Run(path+"_forbidden_literals", func(t *testing.T) {
			t.Parallel()

			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			text := string(src)
			for _, blocked := range forbidden {
				if strings.Contains(text, blocked) {
					t.Fatalf("%s still hardcodes feed handler text %q", path, blocked)
				}
			}
		})
	}
}

func TestAdminManualAdvisoryHandlersUseMessageCatalogForFlashText(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("advisories.go")
	if err != nil {
		t.Fatalf("read advisories.go: %v", err)
	}
	text := string(src)
	for _, want := range []string{
		`web.Message("admin.advisories.error.load")`,
		`web.Message("admin.advisories.error.not_found")`,
		`web.Message("admin.advisories.error.prepare_form")`,
		`web.Message("admin.advisories.error.load_existing")`,
		`web.Message("admin.advisories.error.invalid_revision")`,
		`web.Message("admin.advisories.field.finding_type")`,
		`web.Message("admin.advisories.error.invalid_finding_type")`,
		`web.Message("admin.advisories.error.required_fields")`,
		`web.Message("admin.advisories.error.invalid_severity")`,
		`web.Message("admin.advisories.error.unknown_ecosystem")`,
		`web.Message("admin.advisories.error.docker_unsupported")`,
		`web.Message("admin.advisories.field.max_length"`,
		`web.Message("admin.advisories.error.max_length")`,
		`web.Message("admin.advisories.error.generate_id")`,
		`web.Message("admin.advisories.error.id_prefix")`,
		`web.Message("admin.advisories.error.save_default")`,
		`web.Message("admin.advisories.error.audit_log")`,
		`web.Message("admin.advisories.error.conflict")`,
		`web.Message("admin.advisories.error.update")`,
		`web.Message("admin.advisories.error.create")`,
		`web.Message("admin.advisories.flash.created")`,
		`web.Message("admin.advisories.flash.updated")`,
		`web.Message("admin.advisories.error.load_delete")`,
		`web.Message("admin.advisories.error.delete_not_found")`,
		`web.Message("admin.advisories.error.delete")`,
		`web.Message("admin.advisories.flash.deleted")`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("advisories.go missing manual-advisory message catalog marker %q", want)
		}
	}
	for _, forbidden := range []string{
		`"Manual advisories could not be loaded.`,
		`"Manual advisory not found"`,
		`"Failed to prepare manual advisory form. Reload the page and try again."`,
		`"Failed to load existing advisory"`,
		`"Invalid advisory revision"`,
		`"Invalid finding type"`,
		`"All required fields must be filled"`,
		`"Invalid severity"`,
		`"Unknown ecosystem"`,
		`"Docker is inventory-only and cannot be used for manual scan advisories"`,
		`"Field exceeds maximum length"`,
		`"Failed to generate advisory ID"`,
		`"Advisory ID must start with manual:"`,
		`"Manual advisory could not be saved"`,
		`"Failed to record audit log"`,
		`"Failed to update advisory"`,
		`"Failed to create advisory"`,
		`"Advisory created"`,
		`"Advisory updated"`,
		`"Failed to load advisory"`,
		`"Advisory not found"`,
		`"Failed to delete advisory"`,
		`"Advisory deleted"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("advisories.go still hardcodes manual-advisory handler text %q", forbidden)
		}
	}
}

func TestAdminQueueHandlersUseMessageCatalogForFlashText(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("queue_pages.go")
	if err != nil {
		t.Fatalf("read queue_pages.go: %v", err)
	}
	text := string(src)
	for _, want := range []string{
		`web.Message("admin.queue.error.stats_load")`,
		`web.Message("admin.queue.error.jobs_load")`,
		`web.Message("admin.queue.error.purge")`,
		`web.Message("admin.queue.flash.purged"`,
		`web.Message("admin.queue.error.invalid_priority")`,
		`web.Message("admin.queue.error.priority_update")`,
		`web.Message("admin.queue.flash.priority_updated")`,
		`web.Message("admin.queue.flash.job_paused")`,
		`web.Message("admin.queue.flash.job_resumed")`,
		`web.Message("admin.queue.flash.job_retry")`,
		`web.Message("admin.queue.error.invalid_status")`,
		`web.Message("admin.queue.error.clear")`,
		`web.Message("admin.queue.flash.cleared"`,
		`web.Message("admin.queue.error.invalid_job_id")`,
		`web.Message("admin.queue.error.status_filter_unknown")`,
		`web.Message("admin.queue.empty.page.title")`,
		`web.Message("admin.queue.empty.filtered.title"`,
		`web.Message("admin.queue.count.pending.singular"`,
		`web.Message("admin.queue.count.purge.plural"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("queue_pages.go missing queue message catalog marker %q", want)
		}
	}
	for _, forbidden := range []string{
		`"Queue stats could not be loaded.`,
		`"Queue jobs could not be loaded.`,
		`"Purge failed"`,
		`"Purged %d completed/errored jobs."`,
		`"Invalid priority"`,
		`"Priority update failed"`,
		`"Priority updated"`,
		`"Job paused"`,
		`"Job resumed"`,
		`"Job queued for retry"`,
		`message+" failed"`,
		`"Invalid queue status"`,
		`"Queue clear failed"`,
		`"Cleared %d queue jobs."`,
		`"Invalid queue job ID"`,
		`"Unknown queue status filter; showing all jobs."`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("queue_pages.go still hardcodes queue handler text %q", forbidden)
		}
	}
}

func TestAdminAuditTemplateUsesActionClassViewModel(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("../../web/templates/admin/audit.html")
	if err != nil {
		t.Fatalf("read audit template: %v", err)
	}
	text := string(src)
	for _, forbidden := range []string{
		`eq .Action "login_success"`,
		`eq .Action "login_failed"`,
		`eq .Action "login_lockout"`,
		`bg-blue-100 text-blue-800`,
		`bg-red-100 text-red-800`,
		`bg-amber-100 text-amber-800`,
		`bg-gray-100 text-gray-800`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("audit template still hardcodes audit action badge %q", forbidden)
		}
	}
	if !strings.Contains(text, ".ActionClass") {
		t.Fatal("audit template missing audit action view-model field .ActionClass")
	}
}

func TestHandleAdvisoryCreateDelegatesValidationAndPersistence(t *testing.T) {
	t.Parallel()

	funcs := parseAdminFunctions(t, "advisories.go", "feed_forms.go")
	handler := funcs["HandleAdvisoryCreate"]
	if handler == nil {
		t.Fatal("advisories.go missing HandleAdvisoryCreate")
	}
	gate := funcs["requireAdminPost"]
	if gate == nil {
		t.Fatal("admin package missing requireAdminPost")
	}

	for _, name := range []string{
		"requireAdminPost",
		"parseManualAdvisoryForm",
		"loadExistingManualAdvisory",
		"validateManualAdvisoryInput",
		"buildManualAdvisoryRecord",
		"saveManualAdvisoryAndRedirect",
	} {
		if funcs[name] == nil {
			t.Fatalf("pages.go missing %s helper", name)
		}
	}

	calls := functionCallNames(handler)
	for _, want := range []string{
		"requireAdminPost",
		"parseManualAdvisoryForm",
		"loadExistingManualAdvisory",
		"validateManualAdvisoryInput",
		"buildManualAdvisoryRecord",
		"saveManualAdvisoryAndRedirect",
	} {
		if !calls[want] {
			t.Fatalf("HandleAdvisoryCreate missing orchestration call %s", want)
		}
	}
	for _, forbidden := range []string{
		"findManualAdvisoryByID",
		"generateManualAdvisoryID",
		"normalizeAdvisoryFindingType",
		"requireAdmin",
		"parseAdminForm",
		"ValidateCSRF",
		"requireBootstrapPasswordRotated",
		"manualAdvisoryAuditDetails",
		"manualAdvisoryUpdateAuditDetails",
		"upsertManualAdvisoryWithAudit",
		"adminAuditEntry",
	} {
		if calls[forbidden] {
			t.Fatalf("HandleAdvisoryCreate still contains validation/persistence call %s", forbidden)
		}
	}

	gateCalls := functionCallNames(gate)
	for _, want := range []string{
		"requireAdmin",
		"parseAdminPostForm",
		"ValidateCSRF",
		"rejectInvalidAdminCSRF",
		"requireBootstrapPasswordRotated",
	} {
		if !gateCalls[want] {
			t.Fatalf("requireAdminPost missing gate call %s", want)
		}
	}
}

func TestAdminQueueMutationsRequireAuditedStoreBoundary(t *testing.T) {
	t.Parallel()

	interfaces := parseAdminInterfaces(t, "handler.go")
	mutationStore := interfaces["AdminMutationStore"]
	if mutationStore == nil {
		t.Fatal("handler.go missing AdminMutationStore interface")
	}
	store := interfaces["Store"]
	if store == nil {
		t.Fatal("handler.go missing Store interface")
	}

	auditedMethods := interfaceMethodNames(mutationStore)
	for _, want := range []string{
		"PurgeQueueWithAudit",
		"UpdateQueueJobPriorityWithAudit",
		"PauseQueueJobWithAudit",
		"ResumeQueueJobWithAudit",
		"RetryQueueJobWithAudit",
		"ClearQueueWithAudit",
	} {
		if !auditedMethods[want] {
			t.Fatalf("AdminMutationStore missing required audited queue method %s", want)
		}
	}

	storeMethods := interfaceMethodNames(store)
	for _, forbidden := range []string{
		"PurgeQueue",
		"UpdateQueueJobPriority",
		"PauseQueueJob",
		"ResumeQueueJob",
		"RetryQueueJob",
		"ClearQueue",
	} {
		if storeMethods[forbidden] {
			t.Fatalf("Store exposes non-atomic queue mutation %s; queue admin writes must require *WithAudit methods", forbidden)
		}
	}

	funcs := parseAdminFunctions(t, "queue_pages.go")
	for _, fnName := range []string{
		"HandleQueuePurge",
		"HandleQueuePriorityUpdate",
		"HandleQueuePause",
		"HandleQueueResume",
		"HandleQueueRetry",
		"HandleQueueClear",
	} {
		fn := funcs[fnName]
		if fn == nil {
			t.Fatalf("pages.go missing %s", fnName)
		}
		calls := functionCallNames(fn)
		for _, forbidden := range []string{
			"PurgeQueue",
			"UpdateQueueJobPriority",
			"PauseQueueJob",
			"ResumeQueueJob",
			"RetryQueueJob",
			"ClearQueue",
			"writeAdminAuditLog",
		} {
			if calls[forbidden] {
				t.Fatalf("%s still calls non-atomic queue audit fallback %s", fnName, forbidden)
			}
		}
	}
}

func TestAdminQueueHandlersStayInQueuePagesModule(t *testing.T) {
	t.Parallel()

	queueFuncs := parseAdminFunctions(t, "queue_pages.go")
	pagesFuncs := parseAdminFunctions(t, "pages.go")
	for _, name := range []string{
		"HandleAdminQueue",
		"listQueueJobsPage",
		"HandleQueuePurge",
		"HandleQueuePriorityUpdate",
		"HandleQueuePause",
		"HandleQueueResume",
		"HandleQueueRetry",
		"HandleQueueClear",
		"handleQueueJobAction",
		"queueJobIDFromForm",
		"redirectQueue",
		"queueReturnState",
		"buildAdminQueueFilters",
		"buildAdminQueueStatCards",
		"adminQueueFilterCount",
		"buildAdminQueueClearActions",
		"adminQueuePurgeCount",
		"adminQueuePurgePhrase",
		"adminQueueCountPhrase",
		"buildAdminQueueEmptyState",
		"adminQueueJobViews",
		"adminQueueStatusClass",
		"adminQueueStatusFilter",
		"adminQueueURL",
		"adminQueuePageURL",
		"adminQueueURLWithOffset",
	} {
		if queueFuncs[name] == nil {
			t.Fatalf("queue_pages.go missing queue-only function %s", name)
		}
		if pagesFuncs[name] != nil {
			t.Fatalf("pages.go still declares queue-only function %s", name)
		}
	}
}

func TestAdminManualAdvisoryHandlersStayInAdvisoriesModule(t *testing.T) {
	t.Parallel()

	advisoryFuncs := parseAdminFunctions(t, "advisories.go")
	pagesFuncs := parseAdminFunctions(t, "pages.go")
	for _, name := range []string{
		"HandleAdminAdvisories",
		"renderAdminAdvisoriesPage",
		"HandleAdvisoryCreate",
		"parseManualAdvisoryForm",
		"loadExistingManualAdvisory",
		"validateManualAdvisoryInput",
		"renderManualAdvisoryValidationError",
		"buildManualAdvisoryRecord",
		"saveManualAdvisoryAndRedirect",
		"redirectAdvisoryError",
		"advisoryReturnOffset",
		"adminAdvisoryURL",
		"normalizeAdvisoryFindingType",
		"generateManualAdvisoryID",
		"manualAdvisoryToView",
		"manualAdvisoryInputToView",
		"invalidManualAdvisoryFindingType",
		"invalidManualAdvisoryEcosystem",
		"invalidManualAdvisorySeverity",
		"listManualAdvisoryPage",
		"findManualAdvisoryByID",
		"manualAdvisoryAuditDetails",
		"manualAdvisoryUpdateAuditDetails",
		"addManualAdvisoryAuditDetails",
		"upsertManualAdvisoryWithAudit",
		"deleteManualAdvisoryWithAudit",
		"HandleAdvisoryDelete",
	} {
		if advisoryFuncs[name] == nil {
			t.Fatalf("advisories.go missing manual-advisory function %s", name)
		}
		if pagesFuncs[name] != nil {
			t.Fatalf("pages.go still declares manual-advisory function %s", name)
		}
	}
}

func TestAdminQueueBoundaryDoesNotExposeDatabaseDTOs(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"handler.go", "pages.go", "queue_pages.go"} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(src)
		for _, forbidden := range []string{
			"db.QueueStatsResult",
			"db.RefreshJob",
			"db.AdminAuditEntry",
			"auditedQueueStore",
			"adminQueueJobPageLister",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s exposes database queue/audit DTO %q", path, forbidden)
			}
		}
	}
}

func TestAdminRequestErrorLogsIncludeCorrelationID(t *testing.T) {
	t.Parallel()

	targets := map[string][]string{
		"handler.go": {
			"admin csrf token generation failed",
			"failed to create login session",
			"failed to render login template",
			"login attempt from locked out principal",
			"CSRF validation failed on login",
			"failed to get admin auth",
			"login attempt but no admin account exists",
			"failed to create admin session",
		},
		"feed_forms.go": {
			"admin feeds: failed to load previous config",
			"admin feeds: manual sync failed",
			"admin feeds: manual sync finished",
			"admin feeds: failed to mark sync as running",
		},
		"advisories.go": {
			"admin advisories: failed to list advisories",
			"admin advisories: failed to load edit advisory",
			"admin advisories: failed to load advisory before save",
			"admin advisories: failed to generate advisory ID",
			"admin advisories: failed to save advisory",
			"admin advisories: failed to load advisory before delete",
			"admin advisories: failed to delete advisory",
		},
		"queue_pages.go": {
			"admin queue: failed to load stats",
			"admin queue: failed to load jobs",
			"admin queue purge failed",
			"admin queue priority update failed",
			"admin queue clear failed",
			"admin queue action failed",
		},
		"pages.go": {
			"admin keys: failed to load keys",
			"admin keys: failed to generate key",
			"admin keys: failed to create key",
			"admin keys: failed to load key metadata",
			"admin keys: failed to mutate key",
			"admin settings: failed to get auth info",
			"admin settings: failed to get system settings",
			"password change attempt from locked out principal",
			"admin settings: failed to hash new password",
			"admin settings: failed to update password",
			"admin settings: failed to rotate admin session",
		},
		"settings_forms.go": {
			"admin settings: failed to load previous system settings",
			"admin settings: failed to save system settings",
		},
	}

	for path, messages := range targets {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			calls := adminLoggerCallsByMessage(t, path)
			for _, msg := range messages {
				matches := calls[msg]
				if len(matches) == 0 {
					t.Fatalf("%s missing admin log call %q", path, msg)
				}
				for _, call := range matches {
					if !adminLogCallIncludesCorrelationID(call) {
						t.Fatalf("%s log %q lacks request correlation ID", path, msg)
					}
				}
			}
		})
	}
}

func parseAdminFunctions(t *testing.T, paths ...string) map[string]*ast.FuncDecl {
	t.Helper()

	funcs := make(map[string]*ast.FuncDecl)
	fset := token.NewFileSet()
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			funcs[fn.Name.Name] = fn
		}
	}
	return funcs
}

func parseAdminInterfaces(t *testing.T, paths ...string) map[string]*ast.InterfaceType {
	t.Helper()

	interfaces := make(map[string]*ast.InterfaceType)
	fset := token.NewFileSet()
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				iface, ok := typeSpec.Type.(*ast.InterfaceType)
				if ok {
					interfaces[typeSpec.Name.Name] = iface
				}
			}
		}
	}
	return interfaces
}

func adminLoggerCallsByMessage(t *testing.T, path string) map[string][]*ast.CallExpr {
	t.Helper()

	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	calls := make(map[string][]*ast.CallExpr)
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 || !isAdminLoggerCall(call) {
			return true
		}
		msg, ok := stringLiteralValue(call.Args[0])
		if ok {
			calls[msg] = append(calls[msg], call)
		}
		return true
	})
	return calls
}

func isAdminLoggerCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Error", "Warn", "Info":
	default:
		return false
	}
	loggerSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok || loggerSel.Sel.Name != "logger" {
		return false
	}
	receiver, ok := loggerSel.X.(*ast.Ident)
	return ok && receiver.Name == "h"
}

func adminLogCallIncludesCorrelationID(call *ast.CallExpr) bool {
	for _, arg := range call.Args[1:] {
		if expressionContainsStringLiteral(arg, "correlation_id") || expressionCallsAny(arg, "adminLogAttrs", "adminLogAttrsForCorrelationID") {
			return true
		}
	}
	return false
}

func interfaceMethodNames(iface *ast.InterfaceType) map[string]bool {
	methods := make(map[string]bool)
	if iface == nil || iface.Methods == nil {
		return methods
	}
	for _, field := range iface.Methods.List {
		for _, name := range field.Names {
			methods[name.Name] = true
		}
	}
	return methods
}

func functionCallNames(fn *ast.FuncDecl) map[string]bool {
	calls := make(map[string]bool)
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, name := range callExpressionNames(call.Fun) {
			calls[name] = true
		}
		return true
	})
	return calls
}

func expressionContainsStringLiteral(expr ast.Expr, want string) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if found {
			return false
		}
		if e, ok := node.(ast.Expr); ok {
			value, ok := stringLiteralValue(e)
			if ok && value == want {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func expressionCallsAny(expr ast.Expr, names ...string) bool {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, name := range callExpressionNames(call.Fun) {
			if allowed[name] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func stringLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func callExpressionNames(expr ast.Expr) []string {
	switch fun := expr.(type) {
	case *ast.Ident:
		return []string{fun.Name}
	case *ast.SelectorExpr:
		names := callExpressionNames(fun.X)
		names = append(names, fun.Sel.Name)
		if len(names) >= 2 {
			names = append(names, strings.Join(names[len(names)-2:], "."))
		}
		return names
	default:
		return nil
	}
}
