package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrackedMarkdownDoesNotReferenceIgnoredLocalDocs(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	skipFiles := map[string]struct{}{
		"CLAUDE.md": {},
		"Todo.txt":  {},
	}
	skipDirs := map[string]struct{}{
		".build":       {},
		".git":         {},
		".gotmp":       {},
		".claude":      {},
		".openai":      {},
		".superpowers": {},
		"docs":         {},
		"node_modules": {},
	}
	forbidden := []string{"CLAUDE.md"}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if _, skip := skipDirs[name]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if _, skip := skipFiles[name]; skip {
			return nil
		}
		if !strings.HasSuffix(name, ".md") {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // repository markdown fixture path
		if err != nil {
			return err
		}
		text := string(data)
		for _, marker := range forbidden {
			if strings.Contains(text, marker) {
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				t.Fatalf("%s references ignored local documentation marker %q", filepath.ToSlash(rel), marker)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk markdown files: %v", err)
	}
}

func TestContributingGuideIsTrackedDocumentation(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	gitignoreData, err := os.ReadFile(filepath.Join(root, ".gitignore")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	if ignorePatternContains(string(gitignoreData), "CONTRIBUTING.md") {
		t.Fatal(".gitignore must not hide CONTRIBUTING.md")
	}
	if _, err := os.Stat(filepath.Join(root, "CONTRIBUTING.md")); err != nil {
		t.Fatalf("CONTRIBUTING.md is not present: %v", err)
	}
}

func TestCanonicalDocsAreNotIgnoredAndExist(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	gitignoreData, err := os.ReadFile(filepath.Join(root, ".gitignore")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	gitignore := string(gitignoreData)
	for _, pattern := range []string{"Audit.md", "docs/"} {
		if ignorePatternContains(gitignore, pattern) {
			t.Fatalf(".gitignore must not hide canonical documentation pattern %q", pattern)
		}
	}
	for _, rel := range []string{
		"DESIGN.md",
		"ARCHITECTURE.md",
		"SECURITY.md",
		"README.md",
		filepath.Join("docs", "runbook.md"),
		filepath.Join("docs", "adr", "ADR-0028-backup-restore.md"),
		filepath.Join("docs", "adr", "ADR-0030-observability-metrics.md"),
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("canonical documentation %s is not present: %v", rel, err)
		}
	}
}

func TestSubsystemAgentGuidesDoNotRetainResolvedLandmines(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	forbiddenByFile := map[string][]string{
		filepath.Join("internal", "api", "AGENTS.md"): {
			"saved system settings do NOT take effect until restart",
			"advisory create/edit does not validate `severity`/`ecosystem`",
			"an invalid severity\n  ranks 0 and silently never blocks",
		},
		filepath.Join("internal", "db", "AGENTS.md"): {
			"there are no DB-backed tests for `manual_advisories`, `system_settings`",
			"operator-supplied advisory ID that collides with a feed CVE",
			"overwrites feed data",
		},
		filepath.Join("internal", "server", "AGENTS.md"): {
			"`GET /admin/login` mints a stored 8h session per visit",
			"Bearer key compare is not constant-time",
			"`X-Forwarded-Proto` (HTTPS redirect) is not gated",
		},
	}
	for rel, forbiddenMarkers := range forbiddenByFile {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository documentation path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, marker := range forbiddenMarkers {
			if strings.Contains(text, marker) {
				t.Fatalf("%s still documents resolved landmine %q", rel, marker)
			}
		}
	}
}

func TestAgentGuidesDocumentDevModeWriteGuard(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	files := []string{
		"cmd/packmon-server/AGENTS.md",
		"internal/server/AGENTS.md",
	}
	for _, rel := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		data, err := os.ReadFile(path) //nolint:gosec // static repository documentation path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, forbidden := range []string{
			"Re-introduce a guard",
			"do not let dev mode expose writes",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still contains stale dev-mode auth guidance %q", rel, forbidden)
			}
		}
		for _, want := range []string{"loopback", "non-loopback", "feed imports"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing current dev-mode write guard wording %q", rel, want)
			}
		}
	}
}

func TestRunbookListsAlertWorthyMetricFamilies(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbook.md"))
	if err != nil {
		t.Fatalf("read docs/runbook.md: %v", err)
	}
	text := string(data)
	for _, metric := range []string{
		"packmon_http_requests_total",
		"packmon_http_request_duration_seconds_count",
		"packmon_http_request_duration_seconds_sum",
		"packmon_auth_login_failures_total",
		"packmon_degraded_responses_total",
		"packmon_db_migration_version",
		"packmon_db_pool_connections",
		"packmon_packages_total",
		"packmon_packages_scanned_total",
		"packmon_scan_findings_total",
		"packmon_findings_total",
		"packmon_findings_by_severity",
		"packmon_feed_last_sync_timestamp",
		"packmon_feed_entries_age_seconds",
		"packmon_feed_sync_timeout_total",
		"packmon_queue_size",
		"packmon_queue_oldest_job_seconds",
		"packmon_queue_error_total",
		"packmon_queue_stuck_jobs_recovered_total",
	} {
		if !strings.Contains(text, "`"+metric+"`") {
			t.Fatalf("docs/runbook.md missing alert metric family %s", metric)
		}
	}
}

func TestRunbookRestoreUsesCleanDatabase(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbook.md"))
	if err != nil {
		t.Fatalf("read docs/runbook.md: %v", err)
	}
	text := string(data)
	restoreIndex := strings.Index(text, "## Restore")
	if restoreIndex < 0 {
		t.Fatal("docs/runbook.md missing Restore section")
	}
	restoreText := text[restoreIndex:]
	for _, want := range []string{
		"dropdb --if-exists packmon",
		"createdb packmon",
		"pg_restore --single-transaction --no-owner --no-privileges -d packmon",
		"clean target database",
	} {
		if !strings.Contains(restoreText, want) {
			t.Fatalf("Restore runbook missing clean-restore marker %q", want)
		}
	}
}

func TestSecurityPolicyDocumentsReportingAndSupportedVersions(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	rootSecurity, err := os.ReadFile(filepath.Join(root, "SECURITY.md")) //nolint:gosec // static repository documentation path.
	if err != nil {
		t.Fatalf("read SECURITY.md: %v", err)
	}
	githubSecurity, err := os.ReadFile(filepath.Join(root, ".github", "SECURITY.md")) //nolint:gosec // static repository documentation path.
	if err != nil {
		t.Fatalf("read .github/SECURITY.md: %v", err)
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md")) //nolint:gosec // static repository documentation path.
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}

	rootText := string(rootSecurity)
	for _, want := range []string{
		"## Reporting a Vulnerability",
		"GitHub Private Vulnerability Reporting",
		"Do not file public issues",
		"## Supported Versions",
		"latest released Packmon version",
		"24 hours",
		"72 hours",
		"final report",
		"good-faith",
	} {
		if !strings.Contains(rootText, want) {
			t.Fatalf("SECURITY.md missing security policy marker %q", want)
		}
	}
	if !strings.Contains(string(githubSecurity), "GitHub Private Vulnerability Reporting") ||
		!strings.Contains(string(githubSecurity), "SECURITY.md") {
		t.Fatal(".github/SECURITY.md must point reporters to the private reporting policy")
	}
	if !strings.Contains(string(readme), ".github/SECURITY.md") {
		t.Fatal("README.md must link the repository security reporting policy")
	}
}

func TestReadmeContainsNVDApiAttributionNotice(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	const want = "This product uses the NVD API but is not endorsed or certified by the NVD."
	if !strings.Contains(string(data), want) {
		t.Fatalf("README.md missing NVD API attribution notice %q", want)
	}
}

func TestSystemSettingsDocsDescribeLiveApply(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	files := []string{
		filepath.Join("docs", "runbook.md"),
		filepath.Join("internal", "api", "AGENTS.md"),
		filepath.Join("internal", "web", "templates", "admin", "settings.html"),
	}
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository documentation/template path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if !strings.Contains(text, "applied immediately") && !strings.Contains(text, "apply immediately") {
			t.Fatalf("%s must say saved system settings apply immediately", rel)
		}
		if !strings.Contains(text, "future server starts") && !strings.Contains(text, "startup reload") {
			t.Fatalf("%s must say saved system settings are persisted for future starts", rel)
		}
		for _, forbidden := range []string{
			"saved system settings do NOT take effect until restart",
			"read during server startup, so restart",
			"loaded on server start.",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s still contains stale restart/startup-only wording %q", rel, forbidden)
			}
		}
	}
}

func TestRunbookStaleDBSyncHTTPCommandUsesExplicitOptIn(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbook.md"))
	if err != nil {
		t.Fatalf("read docs/runbook.md: %v", err)
	}
	text := string(data)
	sectionIndex := strings.Index(text, "### CLI warns that the local DB is stale")
	if sectionIndex < 0 {
		t.Fatal("docs/runbook.md missing stale local DB troubleshooting section")
	}
	section := text[sectionIndex:]
	if nextSection := strings.Index(section[len("### "):], "\n### "); nextSection >= 0 {
		section = section[:len("### ")+nextSection]
	}
	if strings.Contains(section, "packmon db sync --server http://") &&
		!strings.Contains(section, "--insecure-allow-http") {
		t.Fatal("stale local DB sync command uses http:// without --insecure-allow-http")
	}
	if !strings.Contains(section, "plain HTTP") || !strings.Contains(section, "local-only") {
		t.Fatal("stale local DB sync section must label plain HTTP as local-only")
	}
}

func TestRunbookFeedStatusTroubleshootingShowsProductionAuthHeaders(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbook.md"))
	if err != nil {
		t.Fatalf("read docs/runbook.md: %v", err)
	}
	text := string(data)
	sectionIndex := strings.Index(text, "### Server reports degraded feed status")
	if sectionIndex < 0 {
		t.Fatal("docs/runbook.md missing degraded feed status troubleshooting section")
	}
	section := text[sectionIndex:]
	if nextSection := strings.Index(section[len("### "):], "\n### "); nextSection >= 0 {
		section = section[:len("### ")+nextSection]
	}
	for _, want := range []string{
		"/api/v1/feeds/status",
		"Authorization: Bearer",
		"User-Agent:",
		"packmon-cli/",
	} {
		if !strings.Contains(section, want) {
			t.Fatalf("degraded feed status runbook section missing %q", want)
		}
	}
}
