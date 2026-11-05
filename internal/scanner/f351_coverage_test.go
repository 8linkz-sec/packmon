package scanner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

type f351FailingLocalChecker struct {
	err error
}

func (c f351FailingLocalChecker) FindVulnerabilities(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, c.err
}

func (f351FailingLocalChecker) FindMalicious(context.Context, string, string, string) ([]domain.Finding, error) {
	return nil, nil
}

func (f351FailingLocalChecker) FindReputationFindingsBatch(context.Context, []PackageLookup, string) ([]domain.Finding, error) {
	return nil, nil
}

func (f351FailingLocalChecker) FindLifecycleFindingsBatch(context.Context, []PackageLookup, time.Time) ([]domain.Finding, error) {
	return nil, nil
}

func TestF351CheckerFailureModesRemainOperationalErrors(t *testing.T) {
	t.Parallel()

	packages := []domain.Package{{Ecosystem: domain.EcosystemNPM, Name: "left-pad", Version: "1.0.0"}}
	localErr := errors.New("local store unavailable")

	local := &Scanner{
		cfg:          Config{Mode: ModeLocal},
		localChecker: f351FailingLocalChecker{err: localErr},
	}
	if _, err := local.executeLocalCheckMode(context.Background(), packages); err == nil || !strings.Contains(err.Error(), "local check failed") {
		t.Fatalf("executeLocalCheckMode() error = %v, want wrapped local failure", err)
	}

	withoutFallback := &Scanner{cfg: Config{Mode: ModeAuto}}
	if _, err := withoutFallback.executeAutoCheckMode(context.Background(), packages); err == nil || !strings.Contains(err.Error(), "no local advisory data") {
		t.Fatalf("executeAutoCheckMode() without fallback error = %v", err)
	}

	failedFallback := &Scanner{
		cfg:          Config{Mode: ModeAuto},
		localChecker: f351FailingLocalChecker{err: localErr},
	}
	if _, err := failedFallback.executeAutoCheckMode(context.Background(), packages); err == nil || !strings.Contains(err.Error(), "remote and local check failed") {
		t.Fatalf("executeAutoCheckMode() failed fallback error = %v", err)
	}
}

func TestF351ResultAndRemoteValidationBranches(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Scanner{cfg: Config{Logger: logger, FailOn: domain.SeverityHigh}}
	if got := s.log(); got != logger {
		t.Fatal("log() did not return configured logger")
	}

	result := s.buildSuccessfulScanResult(
		"scan-local",
		time.Now().Add(-time.Millisecond),
		collectedScanPackages{Collection: &PackageCollection{}},
		checkModeResult{Mode: ModeLocal},
	)
	if result.Findings == nil || result.FeedVersions == nil {
		t.Fatalf("buildSuccessfulScanResult() left nil collections: %+v", result)
	}
	if result.FeedStatus != string(domain.ScanFeedStatusHealthy) {
		t.Fatalf("FeedStatus = %q, want healthy", result.FeedStatus)
	}

	deferredErr := errors.New("deferred CA load failure")
	s = &Scanner{cfg: Config{ServerURL: "https://server.example"}, clientErr: deferredErr}
	if _, err := s.checkRemoteResult(context.Background(), nil); !errors.Is(err, deferredErr) {
		t.Fatalf("checkRemoteResult() error = %v, want deferred client error", err)
	}

	s = &Scanner{cfg: Config{ServerURL: "http://[::1", AllowInsecureHTTP: true}}
	if _, err := s.checkRemoteResult(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "invalid server URL") {
		t.Fatalf("checkRemoteResult() malformed URL error = %v", err)
	}

	s = &Scanner{}
	if _, err := s.postRemoteCheck(context.Background(), "://bad-endpoint", nil); err == nil || !strings.Contains(err.Error(), "create request") {
		t.Fatalf("postRemoteCheck() malformed endpoint error = %v", err)
	}
}

func TestF351RemoteClientStatusAndStringEdges(t *testing.T) {
	t.Parallel()

	deferredErr := errors.New("client initialization failed")
	s := &Scanner{clientErr: deferredErr}
	if err := s.ensureRemoteHTTPClient(); !errors.Is(err, deferredErr) {
		t.Fatalf("ensureRemoteHTTPClient() error = %v, want deferred error", err)
	}

	s = &Scanner{client: &http.Client{Transport: &http.Transport{}}}
	if err := s.ensureRemoteHTTPClient(); err != nil {
		t.Fatalf("ensureRemoteHTTPClient() error = %v", err)
	}
	transport := s.client.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion == 0 {
		t.Fatalf("TLS client config = %+v, want initialized minimum version", transport.TLSClientConfig)
	}

	if got := mergeRemoteFeedStatus(string(domain.ScanFeedStatusDegraded), string(domain.ScanFeedStatusDegraded)); got != string(domain.ScanFeedStatusDegraded) {
		t.Fatalf("mergeRemoteFeedStatus(degraded, degraded) = %q", got)
	}
	if got := mergeRemoteFeedStatus("unknown-a", "unknown-b"); got != string(domain.ScanFeedStatusDegraded) {
		t.Fatalf("mergeRemoteFeedStatus(unknown, unknown) = %q", got)
	}
	if got := remoteScanRepo(&domain.RepoInfo{Name: " \t "}); got != nil {
		t.Fatalf("remoteScanRepo(blank) = %+v, want nil", got)
	}
	if got := truncate("é", 1); got != "é" {
		t.Fatalf("truncate(single rune, 1) = %q", got)
	}
	if got := truncate("abc", -1); got != "..." {
		t.Fatalf("truncate(negative max) = %q, want ellipsis", got)
	}
}
