package devstore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestNoopStoreFindingsBatchSearchAndStats(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "manual:vuln",
		Severity: "high",
		Summary:  "manual vuln",
		Sources:  []db.VulnerabilitySource{{Source: "manual"}},
		AffectedPackages: []db.AffectedPackage{
			{Ecosystem: "npm", Name: "left-pad"},
		},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "M-1",
		Ecosystem: "npm",
		Name:      "left-pad",
		Versions:  []byte(`["1.0.0"]`),
		Severity:  "CRITICAL",
		RiskType:  "malware",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "M-2",
		Ecosystem: "npm",
		Name:      "left-pad",
		Versions:  []byte(`["2.0.0"]`),
		Severity:  "HIGH",
		RiskType:  "typosquatting",
		Summary:   "wrong version",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(M-2) error = %v", err)
	}

	vulns, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].Severity != "HIGH" || vulns[0].Source != "manual" {
		t.Fatalf("vulnerability batch = %+v, want normalized manual finding", vulns)
	}

	malicious, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
	})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "M-1" || malicious[0].Type != domain.FindingTypeMalicious || malicious[0].Version != "1.0.0" {
		t.Fatalf("malicious batch = %+v, want only matching version with requested package version", malicious)
	}

	results, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "left", Severity: "CRITICAL", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages() error = %v", err)
	}
	if len(results) != 1 || results[0].Name != "left-pad" || results[0].FindingsCount != 1 {
		t.Fatalf("SearchPackages() = %+v, want one critical malicious result", results)
	}

	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if stats.TotalPackages != 1 || stats.TotalVulnerabilities != 1 || stats.TotalMalicious != 2 || stats.BySeverity["CRITICAL"] != 1 || stats.BySeverity["HIGH"] != 2 {
		t.Fatalf("DashboardStats() = %+v, want vulnerability and malicious dashboard counts", stats)
	}
}

func TestNoopStoreQueuePositionUsesPriorityOrder(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	createdLow, posLow, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "slow", Source: "socket", Priority: 5})
	if err != nil {
		t.Fatalf("EnqueueRefresh(low) error = %v", err)
	}
	createdHigh, posHigh, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "fast", Source: "socket", Priority: 1})
	if err != nil {
		t.Fatalf("EnqueueRefresh(high) error = %v", err)
	}
	createdLowAgain, posLowAgain, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "slow", Source: "socket", Priority: 5})
	if err != nil {
		t.Fatalf("EnqueueRefresh(low again) error = %v", err)
	}

	if !createdLow || !createdHigh || createdLowAgain {
		t.Fatalf("created flags = low:%v high:%v low-again:%v", createdLow, createdHigh, createdLowAgain)
	}
	if posLow != 1 || posHigh != 1 || posLowAgain != 2 {
		t.Fatalf("queue positions = low:%d high:%d low-again:%d, want 1,1,2 by priority order", posLow, posHigh, posLowAgain)
	}
}

func TestNoopStoreSearchAndDashboardIncludeVulnerabilities(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "GHSA-noop-search",
		Severity: "high",
		Summary:  "noop search vulnerability",
		Sources:  []db.VulnerabilitySource{{Source: "ghsa"}},
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem: "npm",
			Name:      "alpha",
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "M-noop-search",
		Ecosystem: "npm",
		Name:      "alpha",
		Severity:  "HIGH",
		Source:    "openssf",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}

	results, err := store.SearchPackages(ctx, db.PackageSearchParams{Query: "alp", Severity: "HIGH", FindingType: "vulnerability", Limit: 10})
	if err != nil {
		t.Fatalf("SearchPackages(vulnerability) error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("SearchPackages(vulnerability) len = %d, want 1: %+v", len(results), results)
	}
	got := results[0]
	if got.Ecosystem != "npm" || got.Name != "alpha" || got.FindingsCount != 1 ||
		got.VulnerabilityCount != 1 || got.VulnerabilityIDs != "GHSA-noop-search" ||
		got.FindingTypes != "vulnerability" || got.Sources != "ghsa" {
		t.Fatalf("SearchPackages(vulnerability) = %+v, want vulnerability package aggregate", got)
	}

	stats, err := store.DashboardStats(ctx)
	if err != nil {
		t.Fatalf("DashboardStats() error = %v", err)
	}
	if stats.TotalPackages != 1 || stats.TotalVulnerabilities != 1 || stats.TotalMalicious != 1 || stats.BySeverity["HIGH"] != 2 {
		t.Fatalf("DashboardStats() = %+v, want one package with vulnerability and malicious counts", stats)
	}
}

func TestNoopStoreVulnerabilitiesRespectVersionRanges(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "GHSA-noop-range",
		Severity: "HIGH",
		Summary:  "fixed vulnerability",
		AffectedPackages: []db.AffectedPackage{{
			Ecosystem:     "npm",
			Name:          "left-pad",
			VersionRanges: json.RawMessage(`[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`),
		}},
	}); err != nil {
		t.Fatalf("UpsertVulnerability() error = %v", err)
	}

	affected, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(affected) error = %v", err)
	}
	if len(affected) != 1 || affected[0].AdvisoryID != "GHSA-noop-range" {
		t.Fatalf("FindVulnerabilities(affected) = %+v, want GHSA-noop-range", affected)
	}

	unaffected, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "2.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(unaffected) error = %v", err)
	}
	if len(unaffected) != 0 {
		t.Fatalf("FindVulnerabilities(unaffected) = %+v, want no findings", unaffected)
	}

	batch, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.5.0"},
		{Ecosystem: "npm", Name: "left-pad", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(batch) != 1 || batch[0].AdvisoryID != "GHSA-noop-range" {
		t.Fatalf("FindVulnerabilitiesBatch() = %+v, want only affected version", batch)
	}
}

func TestNoopStoreNormalizesCaseInsensitivePackageNames(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "manual:pypi-normalized",
		Severity: "HIGH",
		AffectedPackages: []db.AffectedPackage{
			{Ecosystem: "pypi", Name: "My.Pkg_Name"},
		},
	}); err != nil {
		t.Fatalf("UpsertVulnerability(pypi) error = %v", err)
	}
	if err := store.UpsertVulnerability(ctx, &db.Vulnerability{
		ID:       "manual:nuget-normalized",
		Severity: "HIGH",
		AffectedPackages: []db.AffectedPackage{
			{Ecosystem: "nuget", Name: "Newtonsoft.Json"},
		},
	}); err != nil {
		t.Fatalf("UpsertVulnerability(nuget) error = %v", err)
	}
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:        "MAL-pypi-normalized",
		Ecosystem: "pypi",
		Name:      "Django",
		Versions:  []byte(`["4.2.11"]`),
		Severity:  "CRITICAL",
		RiskType:  "malware",
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding(pypi) error = %v", err)
	}

	vulns, err := store.FindVulnerabilities(ctx, "pypi", "my-pkg-name", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(pypi) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "manual:pypi-normalized" || vulns[0].Name != "my-pkg-name" {
		t.Fatalf("pypi findings = %+v, want normalized match", vulns)
	}
	vulns, err = store.FindVulnerabilities(ctx, "nuget", "newtonsoft.json", "13.0.3")
	if err != nil {
		t.Fatalf("FindVulnerabilities(nuget) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "manual:nuget-normalized" || vulns[0].Name != "newtonsoft.json" {
		t.Fatalf("nuget findings = %+v, want normalized match", vulns)
	}
	malicious, err := store.FindMalicious(ctx, "pypi", "django", "4.2.11")
	if err != nil {
		t.Fatalf("FindMalicious(pypi) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-pypi-normalized" || malicious[0].Name != "django" {
		t.Fatalf("pypi malicious = %+v, want normalized match", malicious)
	}
}

func TestNoopStoreQueueLifecycleAndStuckReset(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	createdLow, posLow, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "slow", Source: "socket", Priority: 3})
	if err != nil {
		t.Fatalf("EnqueueRefresh(low) error = %v", err)
	}
	createdHigh, posHigh, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "fast", Source: "socket", Priority: 0})
	if err != nil {
		t.Fatalf("EnqueueRefresh(high) error = %v", err)
	}
	if !createdLow || !createdHigh || posLow <= 0 || posHigh <= 0 {
		t.Fatalf("created/positions = low(%v,%d) high(%v,%d), want created jobs with positive positions", createdLow, posLow, createdHigh, posHigh)
	}

	first, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh() error = %v", err)
	}
	if first == nil || first.Name != "fast" || first.Status != "processing" {
		t.Fatalf("first dequeued job = %+v, want fast processing", first)
	}

	old := time.Now().UTC().Add(-10 * time.Minute)
	store.mu.Lock()
	for i := range store.refreshJobs {
		if store.refreshJobs[i].ID == first.ID {
			store.refreshJobs[i].ProcessedAt = &old
		}
	}
	store.mu.Unlock()
	reset, err := store.ResetStuckJobs(ctx, "socket", time.Minute)
	if err != nil {
		t.Fatalf("ResetStuckJobs() error = %v", err)
	}
	if reset != 1 {
		t.Fatalf("ResetStuckJobs() = %d, want 1", reset)
	}

	if err := store.UpdateQueueJobPriority(ctx, first.ID, 2); err != nil {
		t.Fatalf("UpdateQueueJobPriority() error = %v", err)
	}
	if err := store.PauseQueueJob(ctx, first.ID); err != nil {
		t.Fatalf("PauseQueueJob() error = %v", err)
	}
	if err := store.RetryQueueJob(ctx, first.ID); err != nil {
		t.Fatalf("RetryQueueJob(paused) error = %v", err)
	}
	job, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh(after retry) error = %v", err)
	}
	if job == nil {
		t.Fatal("DequeueRefresh(after retry) = nil, want job")
	}
	if err := store.CompleteRefresh(ctx, job.ID, errors.New(`upstream token=query-secret C:\Users\Admin\packmon\queue.json`)); err != nil {
		t.Fatalf("CompleteRefresh(error) error = %v", err)
	}
	jobs, err := store.ListQueueJobs(ctx, db.RefreshStatusError, 10)
	if err != nil {
		t.Fatalf("ListQueueJobs(error) error = %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("error jobs = %+v, want one job", jobs)
	}
	for _, leaked := range []string{"query-secret", `C:\Users\Admin\packmon\queue.json`} {
		if strings.Contains(jobs[0].Error, leaked) {
			t.Fatalf("stored queue error leaked %q in %q", leaked, jobs[0].Error)
		}
	}
	for _, want := range []string{"token=[redacted]", "(redacted-path)"} {
		if !strings.Contains(jobs[0].Error, want) {
			t.Fatalf("stored queue error missing %q in %q", want, jobs[0].Error)
		}
	}
	stats, err := store.QueueStats(ctx)
	if err != nil {
		t.Fatalf("QueueStats() error = %v", err)
	}
	if stats.Error != 1 {
		t.Fatalf("QueueStats().Error = %d, want 1", stats.Error)
	}
	purged, err := store.PurgeQueue(ctx)
	if err != nil {
		t.Fatalf("PurgeQueue() error = %v", err)
	}
	if purged != 1 {
		t.Fatalf("PurgeQueue() = %d, want 1", purged)
	}
	cleared, err := store.ClearQueue(ctx, []string{"pending", "bogus"})
	if err != nil {
		t.Fatalf("ClearQueue() error = %v", err)
	}
	if cleared != 1 {
		t.Fatalf("ClearQueue() = %d, want remaining pending job cleared", cleared)
	}
}

func TestNoopCompleteClaimedRefreshIgnoresStaleClaim(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()
	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "pkg", Source: "socket", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh() error = %v", err)
	}

	first, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh(first) error = %v", err)
	}
	if first == nil || first.ProcessedAt == nil {
		t.Fatalf("DequeueRefresh(first) = %+v, want claimed job", first)
	}
	firstClaim := *first.ProcessedAt

	time.Sleep(time.Millisecond)
	if reset, err := store.ResetStuckJobs(ctx, "socket", time.Nanosecond); err != nil || reset != 1 {
		t.Fatalf("ResetStuckJobs() = %d, %v; want 1 nil", reset, err)
	}
	second, err := store.DequeueRefresh(ctx, "socket")
	if err != nil {
		t.Fatalf("DequeueRefresh(second) error = %v", err)
	}
	if second == nil || second.ProcessedAt == nil {
		t.Fatalf("DequeueRefresh(second) = %+v, want reclaimed job", second)
	}

	if err := store.CompleteClaimedRefresh(ctx, first.ID, &firstClaim, nil); err != nil {
		t.Fatalf("CompleteClaimedRefresh(stale) error = %v", err)
	}
	stats, err := store.QueueStats(ctx)
	if err != nil {
		t.Fatalf("QueueStats(after stale complete) error = %v", err)
	}
	if stats.Processing != 1 || stats.Done != 0 {
		t.Fatalf("QueueStats(after stale complete) = %+v, want still processing", stats)
	}

	if err := store.CompleteClaimedRefresh(ctx, second.ID, second.ProcessedAt, nil); err != nil {
		t.Fatalf("CompleteClaimedRefresh(current) error = %v", err)
	}
	stats, err = store.QueueStats(ctx)
	if err != nil {
		t.Fatalf("QueueStats(after current complete) error = %v", err)
	}
	if stats.Done != 1 {
		t.Fatalf("QueueStats(after current complete) = %+v, want done", stats)
	}
}

func TestNoopPruneRefreshQueueOnlyRemovesOldTerminalJobs(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	recent := now.Add(-time.Hour)

	for _, job := range []db.RefreshJob{
		{Ecosystem: "npm", Name: "old-done", Source: "socket", Priority: 1},
		{Ecosystem: "npm", Name: "old-error", Source: "socket", Priority: 1},
		{Ecosystem: "npm", Name: "recent-done", Source: "socket", Priority: 1},
		{Ecosystem: "npm", Name: "old-pending", Source: "socket", Priority: 1},
		{Ecosystem: "npm", Name: "old-paused", Source: "socket", Priority: 1},
	} {
		if _, _, err := store.EnqueueRefresh(ctx, &job); err != nil {
			t.Fatalf("EnqueueRefresh(%s) error = %v", job.Name, err)
		}
	}

	store.mu.Lock()
	for i := range store.refreshJobs {
		job := &store.refreshJobs[i]
		switch job.Name {
		case "old-done":
			job.Status = "done"
			job.ProcessedAt = &old
		case "old-error":
			job.Status = "error"
			job.ProcessedAt = &old
			job.Error = "failed"
		case "recent-done":
			job.Status = "done"
			job.ProcessedAt = &recent
		case "old-pending":
			job.RequestedAt = old
		case "old-paused":
			job.Status = "paused"
			job.RequestedAt = old
		}
	}
	store.mu.Unlock()

	pruned, err := store.PruneRefreshQueue(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("PruneRefreshQueue() error = %v", err)
	}
	if pruned != 2 {
		t.Fatalf("PruneRefreshQueue() = %d, want old done/error jobs", pruned)
	}

	jobs, err := store.ListQueueJobs(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListQueueJobs() error = %v", err)
	}
	names := make(map[string]string, len(jobs))
	for _, job := range jobs {
		names[job.Name] = job.Status
	}
	for _, name := range []string{"recent-done", "old-pending", "old-paused"} {
		if _, ok := names[name]; !ok {
			t.Fatalf("ListQueueJobs() missing %s after prune: %+v", name, jobs)
		}
	}
	for _, name := range []string{"old-done", "old-error"} {
		if _, ok := names[name]; ok {
			t.Fatalf("ListQueueJobs() retained %s after prune: %+v", name, jobs)
		}
	}
}

func TestNoopQueueClearAndPurgeAuditPreserveJobIdentities(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "npm", Name: "left-pad", Source: "socket", Priority: 2}); err != nil {
		t.Fatalf("EnqueueRefresh(pending) error = %v", err)
	}
	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{Ecosystem: "pypi", Name: "django", Source: "reversinglabs", Priority: 1}); err != nil {
		t.Fatalf("EnqueueRefresh(error target) error = %v", err)
	}
	if err := store.CompleteRefresh(ctx, 2, errors.New("upstream token=query-secret failed")); err != nil {
		t.Fatalf("CompleteRefresh(error target) error = %v", err)
	}

	cleared, err := store.ClearQueueWithAudit(ctx, []string{"pending"}, &db.AdminAuditEntry{Action: "queue_clear"})
	if err != nil {
		t.Fatalf("ClearQueueWithAudit() error = %v", err)
	}
	if cleared != 1 {
		t.Fatalf("ClearQueueWithAudit() = %d, want 1", cleared)
	}
	audit, err := store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(clear) error = %v", err)
	}
	clearedJobs := queueAuditJobsFromEntry(t, audit[0], "cleared_jobs")
	if len(clearedJobs) != 1 {
		t.Fatalf("cleared_jobs len = %d, want 1: %+v", len(clearedJobs), clearedJobs)
	}
	if job := clearedJobs[0]; job.ID != 1 || job.Ecosystem != "npm" || job.Name != "left-pad" || job.Source != "socket" || job.Priority != 2 || job.Status != "pending" || job.RequestedAt == "" {
		t.Fatalf("cleared_jobs[0] = %+v, want pending left-pad identity", job)
	}

	purged, err := store.PurgeQueueWithAudit(ctx, &db.AdminAuditEntry{Action: "queue_purge"})
	if err != nil {
		t.Fatalf("PurgeQueueWithAudit() error = %v", err)
	}
	if purged != 1 {
		t.Fatalf("PurgeQueueWithAudit() = %d, want 1", purged)
	}
	audit, err = store.ListAdminAuditLog(ctx, 1)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(purge) error = %v", err)
	}
	purgedJobs := queueAuditJobsFromEntry(t, audit[0], "purged_jobs")
	if len(purgedJobs) != 1 {
		t.Fatalf("purged_jobs len = %d, want 1: %+v", len(purgedJobs), purgedJobs)
	}
	if job := purgedJobs[0]; job.ID != 2 || job.Ecosystem != "pypi" || job.Name != "django" || job.Source != "reversinglabs" || job.Priority != 1 || job.Status != "error" || job.RequestedAt == "" || job.ProcessedAt == "" {
		t.Fatalf("purged_jobs[0] = %+v, want errored django identity", job)
	}
	if strings.Contains(purgedJobs[0].Error, "query-secret") {
		t.Fatalf("purged_jobs[0].error leaked secret: %q", purgedJobs[0].Error)
	}
	if !strings.Contains(purgedJobs[0].Error, "token=[redacted]") {
		t.Fatalf("purged_jobs[0].error = %q, want redacted token marker", purgedJobs[0].Error)
	}
}

type queueAuditJobFixture struct {
	ID          int    `json:"id"`
	Ecosystem   string `json:"ecosystem"`
	Name        string `json:"name"`
	Source      string `json:"source"`
	Priority    int    `json:"priority"`
	Status      string `json:"status"`
	RequestedAt string `json:"requested_at"`
	ProcessedAt string `json:"processed_at"`
	Error       string `json:"error"`
}

func queueAuditJobsFromEntry(t *testing.T, entry db.AdminAuditLogEntry, key string) []queueAuditJobFixture {
	t.Helper()

	details := map[string]string{}
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("audit details unmarshal error = %v; raw=%s", err, entry.Details)
	}
	raw, ok := details[key]
	if !ok {
		t.Fatalf("audit details missing %q: %v", key, details)
	}
	var jobs []queueAuditJobFixture
	if err := json.Unmarshal([]byte(raw), &jobs); err != nil {
		t.Fatalf("audit detail %q unmarshal error = %v; raw=%s", key, err, raw)
	}
	return jobs
}

func TestNoopStoreMaliciousFindingsAreDeepCopied(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	published := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	versionRanges := json.RawMessage(`[{"type":"ECOSYSTEM"}]`)
	versions := json.RawMessage(`["1.0.0"]`)
	references := json.RawMessage(`["https://example.test/advisory"]`)
	if err := store.UpsertMaliciousFinding(ctx, &db.MaliciousFinding{
		ID:            "MAL-copy",
		Ecosystem:     "npm",
		Name:          "copy-me",
		VersionRanges: versionRanges,
		Versions:      versions,
		ReferenceURLs: references,
		Source:        "openssf",
		RiskType:      "malware",
		Severity:      "CRITICAL",
		Published:     &published,
	}); err != nil {
		t.Fatalf("UpsertMaliciousFinding() error = %v", err)
	}

	versionRanges[0] = '['
	versions[0] = '['
	references[0] = '['
	published = published.Add(24 * time.Hour)

	rows, err := store.ListMaliciousFindings(ctx, "openssf", 10)
	if err != nil {
		t.Fatalf("ListMaliciousFindings() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ListMaliciousFindings() len = %d, want 1", len(rows))
	}
	if string(rows[0].VersionRanges) != `[{"type":"ECOSYSTEM"}]` || string(rows[0].Versions) != `["1.0.0"]` || string(rows[0].ReferenceURLs) != `["https://example.test/advisory"]` {
		t.Fatalf("malicious finding was mutated through write input: %+v", rows[0])
	}
	if rows[0].Published == nil || rows[0].Published.Equal(published) {
		t.Fatalf("malicious finding Published = %v, want independent pre-mutation timestamp", rows[0].Published)
	}

	rows[0].VersionRanges[0] = '['
	rows[0].Versions[0] = '['
	rows[0].ReferenceURLs[0] = '['
	*rows[0].Published = rows[0].Published.Add(48 * time.Hour)

	rowsAgain, err := store.ListMaliciousFindings(ctx, "openssf", 10)
	if err != nil {
		t.Fatalf("ListMaliciousFindings(second) error = %v", err)
	}
	if len(rowsAgain) != 1 || string(rowsAgain[0].VersionRanges) != `[{"type":"ECOSYSTEM"}]` || string(rowsAgain[0].Versions) != `["1.0.0"]` || string(rowsAgain[0].ReferenceURLs) != `["https://example.test/advisory"]` {
		t.Fatalf("malicious finding was mutated through read result: %+v", rowsAgain)
	}
}

func TestNoopStoreAdminAuditLogEntriesAreDeepCopied(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	details := json.RawMessage(`{"key":"value"}`)
	if err := store.InsertAdminAuditLog(ctx, &db.AdminAuditEntry{
		Action:  "settings_update",
		Details: details,
		IP:      "127.0.0.1",
	}); err != nil {
		t.Fatalf("InsertAdminAuditLog() error = %v", err)
	}
	details[0] = '['

	entries, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog() error = %v", err)
	}
	if len(entries) != 1 || string(entries[0].Details) != `{"key":"value"}` {
		t.Fatalf("audit log after write mutation = %+v, want original details", entries)
	}

	entries[0].Details[0] = '['
	entriesAgain, err := store.ListAdminAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAdminAuditLog(second) error = %v", err)
	}
	if len(entriesAgain) != 1 || string(entriesAgain[0].Details) != `{"key":"value"}` {
		t.Fatalf("audit log after read mutation = %+v, want original details", entriesAgain)
	}
}

func TestNoopStoreFeedStatusConfigScanAndAPIKeyHelpers(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	metadata := []byte(`{"etag":"one"}`)
	now := time.Now().UTC()
	duration := 2 * time.Second
	if err := store.UpsertFeedSyncStatus(ctx, &db.FeedSyncStatus{
		FeedName:         "osv",
		LastSyncAt:       &now,
		LastSyncStatus:   "success",
		EntriesSynced:    2,
		EntriesTotal:     3,
		Metadata:         metadata,
		LastCommitHash:   "abc",
		LastETag:         "etag",
		LastSyncDuration: &duration,
	}); err != nil {
		t.Fatalf("UpsertFeedSyncStatus() error = %v", err)
	}
	metadata[0] = '['
	now = now.Add(24 * time.Hour)
	duration = 10 * time.Second
	status, err := store.GetFeedSyncStatus(ctx, "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus() error = %v", err)
	}
	if status == nil || string(status.Metadata) != `{"etag":"one"}` {
		t.Fatalf("feed status = %+v, want copied metadata", status)
	}
	if status.LastSyncAt == nil || !status.LastSyncAt.Before(now) {
		t.Fatalf("feed status LastSyncAt = %v, want independent pre-mutation timestamp", status.LastSyncAt)
	}
	if status.LastSyncDuration == nil || *status.LastSyncDuration != 2*time.Second {
		t.Fatalf("feed status LastSyncDuration = %v, want copied duration", status.LastSyncDuration)
	}
	status.Metadata[0] = '['
	*status.LastSyncAt = status.LastSyncAt.Add(48 * time.Hour)
	*status.LastSyncDuration = 30 * time.Second
	statusAgain, err := store.GetFeedSyncStatus(ctx, "osv")
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(second) error = %v", err)
	}
	if statusAgain == nil || string(statusAgain.Metadata) != `{"etag":"one"}` {
		t.Fatalf("feed status after read mutation = %+v, want stored metadata unchanged", statusAgain)
	}
	if statusAgain.LastSyncDuration == nil || *statusAgain.LastSyncDuration != 2*time.Second {
		t.Fatalf("feed status duration after read mutation = %v, want stored duration unchanged", statusAgain.LastSyncDuration)
	}
	statuses, err := store.ListFeedSyncStatuses(ctx)
	if err != nil {
		t.Fatalf("ListFeedSyncStatuses() error = %v", err)
	}
	if len(statuses) != 1 || statuses[0].FeedName != "osv" {
		t.Fatalf("ListFeedSyncStatuses() = %+v", statuses)
	}
	statuses[0].Metadata[0] = '['
	listedAgain, err := store.ListFeedSyncStatuses(ctx)
	if err != nil {
		t.Fatalf("ListFeedSyncStatuses(second) error = %v", err)
	}
	if len(listedAgain) != 1 || string(listedAgain[0].Metadata) != `{"etag":"one"}` {
		t.Fatalf("ListFeedSyncStatuses after mutation = %+v, want stored metadata unchanged", listedAgain)
	}

	interval := 30 * time.Minute
	if err := store.UpsertFeedConfig(ctx, &db.FeedConfig{FeedName: " GHSA ", Enabled: true, Mode: "self", SyncInterval: &interval}); err != nil {
		t.Fatalf("UpsertFeedConfig() error = %v", err)
	}
	cfg, err := store.GetFeedConfig(ctx, "ghsa")
	if err != nil {
		t.Fatalf("GetFeedConfig() error = %v", err)
	}
	if cfg == nil || cfg.FeedName != "ghsa" || cfg.SyncInterval == nil || *cfg.SyncInterval != interval {
		t.Fatalf("feed config = %+v", cfg)
	}
	configs, err := store.ListFeedConfigs(ctx)
	if err != nil {
		t.Fatalf("ListFeedConfigs() error = %v", err)
	}
	if len(configs) != 1 || configs[0].FeedName != "ghsa" {
		t.Fatalf("ListFeedConfigs() = %+v", configs)
	}
	if err := store.DeleteFeedConfig(ctx, "ghsa"); err != nil {
		t.Fatalf("DeleteFeedConfig() error = %v", err)
	}
	if cfg, _ := store.GetFeedConfig(ctx, "ghsa"); cfg != nil {
		t.Fatalf("GetFeedConfig(after delete) = %+v, want nil", cfg)
	}

	oldScanTime := time.Now().UTC().Add(-2 * time.Hour)
	recentScanTime := time.Now().UTC().Add(-30 * time.Minute)
	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{ScanID: "scan-1", ScannedAt: oldScanTime, PackagesCount: 4, FindingsCount: 1}); err != nil {
		t.Fatalf("InsertScanLog(1) error = %v", err)
	}
	if err := store.InsertScanLog(ctx, &db.ScanLogEntry{ScanID: "scan-2", ScannedAt: recentScanTime, PackagesCount: 6, FindingsCount: 2}); err != nil {
		t.Fatalf("InsertScanLog(2) error = %v", err)
	}
	recent, err := store.ListRecentScans(ctx, 1, 0)
	if err != nil {
		t.Fatalf("ListRecentScans() error = %v", err)
	}
	if len(recent) != 1 || recent[0].ScanID != "scan-2" {
		t.Fatalf("ListRecentScans() = %+v, want newest scan", recent)
	}
	totals, err := store.ScanTotals(ctx)
	if err != nil {
		t.Fatalf("ScanTotals() error = %v", err)
	}
	if totals.PackagesScanned != 10 || totals.Findings != 3 {
		t.Fatalf("ScanTotals() = %+v, want cumulative counts", totals)
	}
	prunedScans, err := store.PruneScanLogs(ctx, time.Hour)
	if err != nil {
		t.Fatalf("PruneScanLogs() error = %v", err)
	}
	if prunedScans != 1 {
		t.Fatalf("PruneScanLogs() = %d, want oldest scan pruned", prunedScans)
	}
	recent, err = store.ListRecentScans(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListRecentScans(after prune) error = %v", err)
	}
	if len(recent) != 1 || recent[0].ScanID != "scan-2" {
		t.Fatalf("ListRecentScans(after prune) = %+v, want only scan-2", recent)
	}
	daily, err := store.CountScansByDay(ctx, 1)
	if err != nil {
		t.Fatalf("CountScansByDay() error = %v", err)
	}
	if len(daily) != 1 {
		t.Fatalf("CountScansByDay() len = %d, want 1", len(daily))
	}

	expires := time.Now().UTC().Add(time.Hour)
	keyID, err := store.CreateAPIKey(ctx, "ci", "hash", &expires)
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	key, err := store.FindAPIKeyByHash(ctx, "hash")
	if err != nil {
		t.Fatalf("FindAPIKeyByHash() error = %v", err)
	}
	if key == nil || key.ID != keyID {
		t.Fatalf("FindAPIKeyByHash() = %+v, want key id %d", key, keyID)
	}
	if err := store.TouchAPIKeyLastUsed(ctx, keyID); err != nil {
		t.Fatalf("TouchAPIKeyLastUsed() error = %v", err)
	}
	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0].LastUsedAt == nil {
		t.Fatalf("ListAPIKeys() = %+v, want touched key", keys)
	}
}

func TestNoopStoreManualAdvisoryAndNoopMethods(t *testing.T) {
	t.Parallel()

	store := newNoopStore()
	ctx := context.Background()

	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          domain.ManualAdvisoryIDPrefix + "vuln",
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "left-pad",
		Summary:     "manual vuln",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(vulnerability) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          domain.ManualAdvisoryIDPrefix + "mal",
		FindingType: "malicious",
		Ecosystem:   "pypi",
		Name:        "evil",
		Severity:    "HIGH",
	}); err != nil {
		t.Fatalf("UpsertManualAdvisory(malicious) error = %v", err)
	}
	if err := store.UpsertManualAdvisory(ctx, &db.ManualAdvisory{
		ID:          domain.ManualAdvisoryIDPrefix + "bad-type",
		FindingType: "typo",
		Ecosystem:   "npm",
		Name:        "bad-type",
		Summary:     "bad type",
	}); err == nil {
		t.Fatal("UpsertManualAdvisory(unsupported finding type) error = nil")
	}
	advisories, err := store.ListManualAdvisories(ctx, 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories() error = %v", err)
	}
	if len(advisories) != 2 {
		t.Fatalf("ListManualAdvisories() len = %d, want 2", len(advisories))
	}
	if err := store.DeleteManualAdvisory(ctx, domain.ManualAdvisoryIDPrefix+"vuln"); err != nil {
		t.Fatalf("DeleteManualAdvisory() error = %v", err)
	}
	advisories, err = store.ListManualAdvisories(ctx, 10)
	if err != nil {
		t.Fatalf("ListManualAdvisories(after delete) error = %v", err)
	}
	if len(advisories) != 1 || advisories[0].ID != domain.ManualAdvisoryIDPrefix+"mal" {
		t.Fatalf("manual advisories after delete = %+v, want only malicious advisory", advisories)
	}

	if reps, err := store.FindReputationFindingsBatch(ctx, nil, "reversinglabs"); err != nil || reps != nil {
		t.Fatalf("FindReputationFindingsBatch() = %+v, %v; want nil nil", reps, err)
	}
	if queued, err := store.MarkPackageReputationDue(ctx, &db.PackageReputation{}); err != nil || queued {
		t.Fatalf("MarkPackageReputationDue() = %v, %v; want false nil", queued, err)
	}
	if due, err := store.ListDuePackageReputations(ctx, "npm", "left-pad", "reversinglabs", 10); err != nil || due != nil {
		t.Fatalf("ListDuePackageReputations() = %+v, %v; want nil nil", due, err)
	}
	if err := store.UpsertPackageReputation(ctx, &db.PackageReputation{}); err != nil {
		t.Fatalf("UpsertPackageReputation() error = %v", err)
	}
	if updated, err := store.PropagateSeverityViaAliases(ctx); err != nil || updated != 0 {
		t.Fatalf("PropagateSeverityViaAliases() = %d, %v; want 0 nil", updated, err)
	}
	if updated, err := store.SetCISAKEV(ctx, nil); err != nil || updated != 0 {
		t.Fatalf("SetCISAKEV() = %d, %v; want 0 nil", updated, err)
	}
	if cleared, err := store.ClearCISAKEV(ctx, nil); err != nil || cleared != 0 {
		t.Fatalf("ClearCISAKEV() = %d, %v; want 0 nil", cleared, err)
	}
	if updated, cleared, err := store.ReplaceCISAKEV(ctx, nil); err != nil || updated != 0 || cleared != 0 {
		t.Fatalf("ReplaceCISAKEV() = %d, %d, %v; want 0 0 nil", updated, cleared, err)
	}
	if updated, err := store.SetEPSSScores(ctx, nil); err != nil || updated != 0 {
		t.Fatalf("SetEPSSScores() = %d, %v; want 0 nil", updated, err)
	}
	if updated, cleared, err := store.ReplaceEPSSScores(ctx, nil); err != nil || updated != 0 || cleared != 0 {
		t.Fatalf("ReplaceEPSSScores() = %d, %d, %v; want 0 0 nil", updated, cleared, err)
	}
	if updated, err := store.EnrichVulnCheck(ctx, nil); err != nil || updated != 0 {
		t.Fatalf("EnrichVulnCheck() = %d, %v; want 0 nil", updated, err)
	}
	if cveIDs, err := store.FindUnknownSeverityCVEIDs(ctx, "", 100); err != nil || cveIDs != nil {
		t.Fatalf("FindUnknownSeverityCVEIDs() = %+v, %v; want nil nil", cveIDs, err)
	}
	if err := store.UpdateSeverityByCVE(ctx, "CVE-2026-0001", "HIGH", 7.5); err != nil {
		t.Fatalf("UpdateSeverityByCVE() error = %v", err)
	}
	if status, err := store.GetPackageCheckStatus(ctx, "npm", "left-pad", "socket"); err != nil || status != nil {
		t.Fatalf("GetPackageCheckStatus() = %+v, %v; want nil nil", status, err)
	}
	if err := store.UpsertPackageCheckStatus(ctx, &db.PackageCheckStatus{}); err != nil {
		t.Fatalf("UpsertPackageCheckStatus() error = %v", err)
	}
	if vulns, err := store.ListRecentVulnerabilities(ctx, 7, 10); err != nil || vulns != nil {
		t.Fatalf("ListRecentVulnerabilities() = %+v, %v; want nil nil", vulns, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := (&noopPinger{}).Ping(ctx); err != nil {
		t.Fatalf("noopPinger.Ping() error = %v", err)
	}
}
