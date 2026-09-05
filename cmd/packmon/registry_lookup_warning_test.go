package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/dockerimage"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func hasWarningContaining(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// TestRefusedRegistryRequestsAreCounted covers the signal that actually matters:
// a registry that refuses to answer (429, 5xx, network error). Counting HTTP
// requests rather than rows is deliberate -- a cached lookup issues no request,
// so it cannot be refused.
func TestRefusedRegistryRequestsAreCounted(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	ctx, counter := withRegistryLookupPhase(context.Background(), 0)
	for _, name := range []string{"alpha", "beta"} {
		_ = fetchNPMLatestFromBase(ctx, server.URL, name)
	}

	if got := counter.refusedCount(); got != 2 {
		t.Fatalf("refused requests = %d, want 2", got)
	}
}

// TestNotFoundRegistryResponsesAreNotFailures is the correction that matters
// most here. A 404 is a definitive answer: the package does not exist on this
// registry, which is the normal case for a workspace-local or private package.
// Counting those as failures blamed a rate limit for something that was never
// rate limited.
func TestNotFoundRegistryResponsesAreNotFailures(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, counter := withRegistryLookupPhase(context.Background(), 0)
	if got := fetchNPMLatestFromBase(ctx, server.URL, "@acme/workspace-only"); got != "" {
		t.Fatalf("lookup = %q, want empty", got)
	}

	if got := counter.refusedCount(); got != 0 {
		t.Fatalf("refused requests = %d, want 0 for a 404", got)
	}
}

// TestSuccessfulRequestsAreNotCounted keeps the counter honest.
func TestSuccessfulRequestsAreNotCounted(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.0.0"}`))
	}))
	defer server.Close()

	ctx, counter := withRegistryLookupPhase(context.Background(), 0)
	if got := fetchNPMLatestFromBase(ctx, server.URL, "alpha"); got != "1.0.0" {
		t.Fatalf("lookup = %q, want 1.0.0", got)
	}
	if got := counter.refusedCount(); got != 0 {
		t.Fatalf("refused requests = %d, want 0", got)
	}
}

// TestRefusedLookupsProduceReportWarning wires the counter through to the
// report so an incomplete inventory is visible instead of silently rendering as
// an unknown latest version.
func TestRefusedLookupsProduceReportWarning(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	resolver := packageUpdateResolver{}
	resolver.latestRegistry.NPMRegistryBaseURL = server.URL

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{
		{Name: "alpha", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
	}, nil, "repo", 30, listAllPackageReportOptions{resolver: resolver})

	if !hasWarningContaining(report.Warnings, "refused") {
		t.Fatalf("warnings = %#v, want one reporting refused registry requests", report.Warnings)
	}
}

// TestNotFoundLookupsProduceNoReportWarning is the end-to-end guard for the
// exxperts case: workspace packages that are simply absent from the public
// registry must not raise a rate-limit warning.
func TestNotFoundLookupsProduceNoReportWarning(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resolver := packageUpdateResolver{}
	resolver.latestRegistry.NPMRegistryBaseURL = server.URL

	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{
		{Name: "@acme/workspace-only", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
	}, nil, "repo", 30, listAllPackageReportOptions{resolver: resolver})

	if hasWarningContaining(report.Warnings, "refused") {
		t.Fatalf("warnings = %#v, want none for packages the registry does not carry", report.Warnings)
	}
}

func TestRegistryGetSkipsWhenBreakerOpen(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, phase := withRegistryLookupPhase(context.Background(), 0)
	for i := 0; i < registryBreakerThreshold; i++ {
		phase.recordRefusal()
	}
	if _, err := registryGet(ctx, server.URL); err == nil {
		t.Fatal("registryGet succeeded although the breaker is open")
	}
	if requests != 0 {
		t.Fatalf("breaker-open request reached the server %d times, want 0", requests)
	}
	if got := phase.skippedCount(); got != 1 {
		t.Fatalf("skippedCount() = %d, want 1", got)
	}
}

func TestRegistryGetSuccessResetsBreakerStreak(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ctx, phase := withRegistryLookupPhase(context.Background(), 0)
	for i := 0; i < registryBreakerThreshold-1; i++ {
		phase.recordRefusal()
	}
	if _, err := registryGet(ctx, server.URL); err != nil {
		t.Fatalf("registryGet: %v", err)
	}
	phase.recordRefusal()
	if phase.breakerOpen() {
		t.Fatal("breaker open although a 200 reset the streak")
	}
}

func TestRegistryGet404ResetsBreakerStreakAndCountsNoRefusal(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, phase := withRegistryLookupPhase(context.Background(), 0)
	for i := 0; i < registryBreakerThreshold-1; i++ {
		phase.recordRefusal()
	}
	if _, err := registryGet(ctx, server.URL); err == nil {
		t.Fatal("registryGet on 404 must return an error")
	}
	if got := phase.refusedCount(); got != registryBreakerThreshold-1 {
		t.Fatalf("refusedCount() = %d, want %d (404 is not a refusal)", got, registryBreakerThreshold-1)
	}
	phase.recordRefusal()
	if phase.breakerOpen() {
		t.Fatal("breaker open although a 404 answer reset the streak")
	}
}

func TestRegistryGetParentCancellationRecordsNothing(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, phase := withRegistryLookupPhase(context.Background(), 0)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := registryGet(ctx, server.URL); err == nil {
		t.Fatal("registryGet on canceled context must return an error")
	}
	if phase.refusedCount() != 0 || phase.skippedCount() != 0 {
		t.Fatalf("canceled request recorded refused=%d skipped=%d, want 0/0",
			phase.refusedCount(), phase.skippedCount())
	}
}

func TestRegistryGetAppliesPerRequestTimeout(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, phase := withRegistryLookupPhase(context.Background(), 1)
	start := time.Now()
	_, err := registryGet(ctx, server.URL)
	if err == nil {
		t.Fatal("registryGet against a hanging server must fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("request took %v, want ~1s per-request timeout", elapsed)
	}
	<-started
	if got := phase.refusedCount(); got != 1 {
		t.Fatalf("refusedCount() = %d, want 1 (a per-request timeout is a refusal)", got)
	}
}

func TestPerRequestLookupContextBoundsGitLookups(t *testing.T) {
	t.Parallel()
	parent, phase := withRegistryLookupPhase(context.Background(), 7)
	_ = phase
	ctx, cancel := perRequestLookupContext(parent)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("perRequestLookupContext set no deadline")
	}
	if until := time.Until(deadline); until > 8*time.Second || until < 5*time.Second {
		t.Fatalf("deadline in %v, want ~7s from --timeout", until)
	}

	bounded, boundedCancel := context.WithTimeout(context.Background(), time.Hour)
	defer boundedCancel()
	same, sameCancel := perRequestLookupContext(bounded)
	defer sameCancel()
	if d, _ := same.Deadline(); !d.Equal(func() time.Time { t2, _ := bounded.Deadline(); return t2 }()) {
		t.Fatal("existing deadline must be preserved, not replaced")
	}
}

func TestAnnounceLookupPhase(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	announceLookupPhase(&buf, 1311, 0, false)
	got := buf.String()
	if !strings.Contains(got, "1311 packages") || !strings.Contains(got, "rate-limited") {
		t.Fatalf("announcement = %q", got)
	}

	buf.Reset()
	announceLookupPhase(&buf, 1, 0, false)
	got = buf.String()
	if !strings.Contains(got, "1 package (") || strings.Contains(got, "1 packages") {
		t.Fatalf("singular announcement = %q, want \"1 package\"", got)
	}

	buf.Reset()
	announceLookupPhase(&buf, 1311, 0, true)
	if buf.Len() != 0 {
		t.Fatalf("quiet mode wrote %q", buf.String())
	}

	buf.Reset()
	announceLookupPhase(&buf, 0, 0, false)
	if buf.Len() != 0 {
		t.Fatalf("zero packages wrote %q", buf.String())
	}
}

// TestGitRemoteTagsRecordsRefusalOnCommandError proves the git lookup path
// feeds the honest-warning counters the same way the HTTP path does: an
// actual git invocation failure (which also covers a per-request timeout --
// the outer context, captured before the per-request wrap, is not canceled)
// counts as a refusal, but a policy rejection that never reaches git does not.
func TestGitRemoteTagsRecordsRefusalOnCommandError(t *testing.T) {
	// Not parallel: swaps the package-level gitCommandOutput stub.
	original := gitCommandOutput
	t.Cleanup(func() { gitCommandOutput = original })
	gitCommandOutput = func(context.Context, ...string) ([]byte, error) {
		return nil, errors.New("git command failed")
	}

	ctx, phase := withRegistryLookupPhase(context.Background(), 0)
	if _, err := gitRemoteTags(ctx, "https://example.test/repo.git"); err == nil {
		t.Fatal("gitRemoteTags() error = nil, want the stubbed command failure")
	}
	if got := phase.refusedCount(); got != 1 {
		t.Fatalf("refusedCount() = %d, want 1 after a git command error", got)
	}

	ctx, phase = withRegistryLookupPhase(context.Background(), 0)
	if _, err := gitRemoteTags(ctx, "not a safe remote"); err == nil {
		t.Fatal("gitRemoteTags(unsafe remote) error = nil, want a rejection")
	}
	if got := phase.refusedCount(); got != 0 {
		t.Fatalf("refusedCount() = %d, want 0 for a policy rejection that never reached git", got)
	}
}

// TestGitRemoteTagCommitRecordsRefusalOnCommandError mirrors
// TestGitRemoteTagsRecordsRefusalOnCommandError for the other git lookup entry
// point, which has its own argument guards ahead of the git invocation.
func TestGitRemoteTagCommitRecordsRefusalOnCommandError(t *testing.T) {
	// Not parallel: swaps the package-level gitCommandOutput stub.
	original := gitCommandOutput
	t.Cleanup(func() { gitCommandOutput = original })
	gitCommandOutput = func(context.Context, ...string) ([]byte, error) {
		return nil, errors.New("git command failed")
	}

	ctx, phase := withRegistryLookupPhase(context.Background(), 0)
	if _, ok := gitRemoteTagCommit(ctx, "https://example.test/repo.git", "v1.0.0"); ok {
		t.Fatal("gitRemoteTagCommit() ok = true, want false on a command failure")
	}
	if got := phase.refusedCount(); got != 1 {
		t.Fatalf("refusedCount() = %d, want 1 after a git command error", got)
	}

	ctx, phase = withRegistryLookupPhase(context.Background(), 0)
	if _, ok := gitRemoteTagCommit(ctx, "https://example.test/repo.git", "bad tag with spaces"); ok {
		t.Fatal("gitRemoteTagCommit(bad tag) ok = true, want false")
	}
	if got := phase.refusedCount(); got != 0 {
		t.Fatalf("refusedCount() = %d, want 0 for a policy rejection that never reached git", got)
	}
}

// TestDockerDigestResolutionRecordsRefusalOnResolveError proves the docker
// digest path on the list-all report feeds the same counters: an attempted
// resolution that errors counts as a refusal, but a deliberate skip (here, a
// local/-prefixed image, which never reaches the resolver) does not.
func TestDockerDigestResolutionRecordsRefusalOnResolveError(t *testing.T) {
	t.Parallel()

	resolver := &countingDigestResolver{err: errors.New("registry unreachable")}
	ctx, phase := withRegistryLookupPhase(context.Background(), 0)
	remote := listAllPackage{Name: "ghcr.io/org/app", Version: "v1", Ecosystem: domain.EcosystemDocker}
	status := resolveDockerImageStatusWithDigestResolver(ctx, remote, nil, resolver)
	if !status.Unknown {
		t.Fatalf("status = %+v, want Unknown after a digest resolution error", status)
	}
	if got := phase.refusedCount(); got != 1 {
		t.Fatalf("refusedCount() = %d, want 1 after a digest resolution error", got)
	}

	ctx, phase = withRegistryLookupPhase(context.Background(), 0)
	local := listAllPackage{Name: "local/app", Version: "v1", Ecosystem: domain.EcosystemDocker}
	_ = resolveDockerImageStatusWithDigestResolver(ctx, local, nil, resolver)
	if got := phase.refusedCount(); got != 0 {
		t.Fatalf("refusedCount() = %d, want 0 for a deliberate local-image skip", got)
	}
}

// TestDockerDigestResolutionSkipsRefusalForPolicyRejection proves the
// over-broad-counting fix: a resolver error that carries
// dockerimage.ErrRegistryUnsupported (an unallowlisted registry host and
// friends, none of which ever attempted a network request) must not be
// counted as a refusal, or every scan with private-registry images would
// falsely raise the "rate limit or slow registry" warning.
func TestDockerDigestResolutionSkipsRefusalForPolicyRejection(t *testing.T) {
	t.Parallel()

	policyErr := fmt.Errorf("%w: %w: unsupported docker registry host %s",
		dockerimage.ErrDigestUnavailable, dockerimage.ErrRegistryUnsupported, "attacker.example.test")
	resolver := &countingDigestResolver{err: policyErr}

	ctx, phase := withRegistryLookupPhase(context.Background(), 0)
	remote := listAllPackage{Name: "attacker.example.test/org/app", Version: "v1", Ecosystem: domain.EcosystemDocker}
	status := resolveDockerImageStatusWithDigestResolver(ctx, remote, nil, resolver)
	if !status.Unknown {
		t.Fatalf("status = %+v, want Unknown after a policy rejection", status)
	}
	if got := phase.refusedCount(); got != 0 {
		t.Fatalf("refusedCount() = %d, want 0 for an unsupported-registry policy rejection", got)
	}
}

func TestHumanLookupEstimate(t *testing.T) {
	t.Parallel()
	cases := map[time.Duration]string{
		5 * time.Second:   "under a minute",
		66 * time.Second:  "about 1 minute",
		150 * time.Second: "about 3 minutes",
	}
	for d, want := range cases {
		if got := humanLookupEstimate(d); got != want {
			t.Fatalf("humanLookupEstimate(%v) = %q, want %q", d, got, want)
		}
	}
}
