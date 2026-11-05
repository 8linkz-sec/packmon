package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/dockerimage"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestF032RunListAllReturnsPipelineFailureBeforeInventoryOutput(t *testing.T) {
	isolatedListAllEnv(t)
	t.Setenv("PACKMON_HISTORY_ENABLED", "not-a-boolean")
	root := t.TempDir()
	writeListAllPackageLock(t, root, listAllLockPackage{Name: "kept", Version: "1.0.0"})
	settings := listAllSettings(root, false)
	settings.ListAllOffline = true

	var exitCode int
	var runErr error
	stdout := captureStdout(t, func() {
		captureScanStderr(t, func() {
			exitCode, runErr = runListAll(context.Background(), settings)
		})
	})
	if runErr == nil || exitCode != ExitOperational {
		t.Fatalf("runListAll() = exit %d, err %v; want operational pipeline failure", exitCode, runErr)
	}
	var historyErr *scanHistoryRecordError
	if errors.As(runErr, &historyErr) {
		t.Fatalf("runListAll() error = %v, want non-history pipeline failure", runErr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("stdout = %q, want no inventory output after pipeline failure", stdout)
	}
}

func TestF032WriteListAllOutputPhaseReportsHTMLAndTerminalFailures(t *testing.T) {
	t.Run("HTML failure", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "not-a-directory")
		writeFile(t, blocker, "x")
		settings := scanSettings{
			Path:           t.TempDir(),
			ListAllOffline: true,
			Quiet:          true,
			OutputHTML:     filepath.Join(blocker, "report.html"),
		}
		exitCode, err := writeListAllOutputPhase(context.Background(), settings, listAllScanPhaseResult{exitCode: ExitBlocking}, listAllInventoryPhaseResult{})
		if err == nil || exitCode != ExitBlocking {
			t.Fatalf("writeListAllOutputPhase() = exit %d, err %v; want preserved blocking exit and HTML error", exitCode, err)
		}
		if !strings.Contains(err.Error(), "prepare HTML output") {
			t.Fatalf("HTML error = %q, want output preparation context", err)
		}
	})

	t.Run("terminal failure remains non-fatal", func(t *testing.T) {
		readEnd, writeEnd, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := writeEnd.Close(); err != nil {
			t.Fatal(err)
		}
		oldStdout := os.Stdout
		os.Stdout = readEnd
		t.Cleanup(func() {
			os.Stdout = oldStdout
			_ = readEnd.Close()
		})

		var exitCode int
		var runErr error
		stderr := captureStderr(t, func() {
			exitCode, runErr = writeListAllOutputPhase(
				context.Background(),
				scanSettings{Path: t.TempDir(), ListAllOffline: true},
				listAllScanPhaseResult{result: &domain.ScanResult{}, exitCode: ExitOK},
				listAllInventoryPhaseResult{},
			)
		})
		if runErr != nil || exitCode != ExitOK {
			t.Fatalf("writeListAllOutputPhase() = exit %d, err %v; want successful reporting despite terminal failure", exitCode, runErr)
		}
		if !strings.Contains(stderr, "error writing list-all findings output:") {
			t.Fatalf("stderr = %q, want terminal write diagnostic", stderr)
		}
	})
}

func TestF032DockerStatusCoversRemoteFailureAndMissingDigest(t *testing.T) {
	pkg := listAllPackage{
		Name:      "docker.io/acme/app",
		Version:   "stable",
		Ecosystem: domain.EcosystemDocker,
	}
	t.Run("registry failure", func(t *testing.T) {
		ctx, phase := withRegistryLookupPhase(context.Background(), 1)
		resolver := &countingDigestResolver{err: errors.New("registry unavailable")}
		got := resolveDockerImageStatusWithDigestResolver(ctx, pkg, map[string]string{}, resolver)
		if !got.Unknown || got.Latest != "unknown" || got.Update != "unknown" {
			t.Fatalf("status = %+v, want unknown remote status", got)
		}
		if phase.refusedCount() != 1 {
			t.Fatalf("refused requests = %d, want 1", phase.refusedCount())
		}
	})

	t.Run("empty registry digest", func(t *testing.T) {
		ctx, phase := withRegistryLookupPhase(context.Background(), 1)
		got := resolveDockerImageStatusWithDigestResolver(ctx, pkg, map[string]string{}, &countingDigestResolver{})
		if !got.Unknown || got.Latest != "unknown" || got.Update != "unknown" {
			t.Fatalf("status = %+v, want unknown empty-digest status", got)
		}
		if phase.refusedCount() != 0 {
			t.Fatalf("refused requests = %d, want 0 for an empty successful response", phase.refusedCount())
		}
	})
}

func TestF032NilDockerDigestCacheUsesDefaultResolver(t *testing.T) {
	oldFactory := newDockerRegistryClientFunc
	t.Cleanup(func() { newDockerRegistryClientFunc = oldFactory })
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newDockerRegistryClientFunc = func(*http.Client) *dockerimage.RegistryClient {
		client := dockerimage.NewRegistryClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Docker-Content-Digest": []string{digest}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})})
		client.LookupIP = func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return client
	}

	ref, ok := dockerimage.ParseRef("docker.io/acme/app:stable")
	if !ok {
		t.Fatal("fixture Docker reference did not parse")
	}
	var lookup *cachedDockerDigestLookup
	got, err := lookup.ResolveDigest(context.Background(), ref)
	if err != nil || got != digest {
		t.Fatalf("nil cached lookup ResolveDigest() = %q, %v; want default resolver digest", got, err)
	}
}

func TestF032DefensiveHelpersRejectIncompleteInputs(t *testing.T) {
	packages, warnings, err := listAllPackagesFromCollection(nil)
	if err != nil || packages != nil || warnings != nil {
		t.Fatalf("listAllPackagesFromCollection(nil) = %#v, %#v, %v", packages, warnings, err)
	}

	if rows, gotWarnings, err := collectDockerPackagesWithWarnings(t.TempDir(), scanSettings{Ecosystems: []string{"npm"}}); err != nil || rows != nil || gotWarnings != nil {
		t.Fatalf("excluded Docker collection = %#v, %#v, %v", rows, gotWarnings, err)
	}
	if rows, gotWarnings, err := collectChocolateyPackagesWithWarnings(t.TempDir(), scanSettings{Ecosystems: []string{"npm"}}); err != nil || rows != nil || gotWarnings != nil {
		t.Fatalf("excluded Chocolatey collection = %#v, %#v, %v", rows, gotWarnings, err)
	}
	if got := inspectListAllLocalDockerDigests(context.Background(), []listAllPackage{
		{Name: "bad ref", Ecosystem: domain.EcosystemDocker},
		{Name: "local/acme", Version: "latest", Ecosystem: domain.EcosystemDocker},
		{Name: "docker.io/acme/app", Version: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Ecosystem: domain.EcosystemDocker},
	}); got != nil {
		t.Fatalf("local digests = %#v, want nil when every Docker row is deliberately skipped", got)
	}

	status := resolveListAllLatestWithCachedDockerLookup(context.Background(), listAllPackage{
		Name: "Private.Package", Ecosystem: domain.EcosystemNuGet,
	}, directPackageUpdateLookup(), nil, nil)
	if !status.Unknown || status.Latest != "unknown" || status.Update != "-" {
		t.Fatalf("private NuGet status = %+v, want lookup-policy unknown", status)
	}
	status = resolveDockerImageStatusWithDigestResolver(context.Background(), listAllPackage{
		Name: "", Version: "", Ecosystem: domain.EcosystemDocker,
	}, map[string]string{}, &countingDigestResolver{})
	if !status.Unknown || status.Update != "unknown" {
		t.Fatalf("invalid Docker status = %+v, want unknown", status)
	}

	sources := listAllSortAndDedupSources([]listAllSourceRow{
		{},
		{Kind: " SBOM ", Path: " inventory.cdx.json "},
		{Kind: "sbom", Path: "inventory.cdx.json"},
	})
	if len(sources) != 1 || sources[0] != (listAllSourceRow{Kind: "sbom", Path: "inventory.cdx.json"}) {
		t.Fatalf("sources = %#v, want one normalized row", sources)
	}

	if got := listAllScopeSummaries(listAllPackageReport{ScopeCounts: map[string]int{"runtime": 0, "ignored": -1}}); len(got) != 0 {
		t.Fatalf("scope summaries = %#v, want no entries after non-positive counts", got)
	}
	if got := humanizeListAllToken("---"); got != "---" {
		t.Fatalf("humanizeListAllToken(---) = %q, want unchanged separator-only token", got)
	}
	if got := humanizeListAllToken(" "); got != "-" {
		t.Fatalf("humanizeListAllToken(blank) = %q, want dash", got)
	}
	if _, ok := dockerTagRefFromPinnedRef(dockerimage.Ref{Original: "registry.example/acme/app:stable"}); ok {
		t.Fatal("dockerTagRefFromPinnedRef() accepted a reference without a digest separator")
	}
}

func TestF032StaleStatusPropagatesWriterFailure(t *testing.T) {
	age := 10
	writer := &failListAllTerminalWriter{failAt: 1}
	err := writeListAllTerminalFindingStatusMessages(writer, &domain.ScanResult{
		Mode:      domain.ScanModeLocal,
		DBStale:   true,
		DBAgeDays: &age,
	})
	if !errors.Is(err, errListAllTerminalWrite) {
		t.Fatalf("writeListAllTerminalFindingStatusMessages() error = %v, want sentinel", err)
	}
}
