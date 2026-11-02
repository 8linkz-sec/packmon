package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/8linkz-sec/packmon/internal/dockerimage"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

func TestRunListAllScanOutputPhaseReturnsNonHistoryPipelineErrorBeforeArtifacts(t *testing.T) {
	isolatedListAllEnv(t)
	t.Setenv("PACKMON_HISTORY_ENABLED", "not-a-boolean")
	root := t.TempDir()
	writeListAllPackageLock(t, root, listAllLockPackage{Name: "kept", Version: "1.0.0"})
	out := t.TempDir()
	settings := listAllSettings(root, true)
	settings.OutputJSON = filepath.Join(out, "result.json")
	settings.OutputSARIF = filepath.Join(out, "result.sarif")
	settings.OutputJUnit = filepath.Join(out, "result.xml")

	var scan listAllScanPhaseResult
	var err error
	stdout := captureStdout(t, func() {
		captureScanStderr(t, func() {
			scan, err = runListAllScanOutputPhase(context.Background(), settings)
		})
	})
	if err == nil || scan.result == nil || scan.collection == nil || scan.exitCode != ExitOperational {
		t.Fatalf("scan = %+v, err = %v, want completed result/collection and operational non-history error", scan, err)
	}
	var historyErr *scanHistoryRecordError
	if errors.As(err, &historyErr) {
		t.Fatalf("error = %v, want configuration failure rather than history write failure", err)
	}
	for _, path := range []string{settings.OutputJSON, settings.OutputSARIF, settings.OutputJUnit} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("artifact %s exists or returned unexpected error: %v", path, statErr)
		}
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("stdout announced success or an artifact after the pre-artifact failure: %q", stdout)
	}
}

func TestRunListAllScanOutputPhasePreservesOperationalCollectionFailureResult(t *testing.T) {
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")
	rootFile := filepath.Join(t.TempDir(), "root-file")
	writeFile(t, rootFile, "not a directory")
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	settings := listAllSettings(rootFile, true)
	settings.Mode = "remote"
	settings.ServerURL = server.URL
	settings.APIKey = "test-key"
	settings.InsecureHTTP = true

	scan, err := runListAllScanOutputPhase(context.Background(), settings)
	if err != nil {
		t.Fatalf("runListAllScanOutputPhase() error = %v, want operational result", err)
	}
	if scan.result == nil || scan.collection != nil || scan.exitCode != ExitOperational {
		t.Fatalf("scan = %+v, want result, nil collection, and operational exit", scan)
	}
	if !strings.Contains(strings.ToLower(scan.result.ScanError), "walk") {
		t.Fatalf("ScanError = %q, want collection/walk context", scan.result.ScanError)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("checker requests = %d, want 0 after collection failure", got)
	}
}

func TestRunListAllScanOutputPhaseMarksArtifactFailureOperationalAndContinuesArtifacts(t *testing.T) {
	isolatedListAllEnv(t)
	t.Setenv("PACKMON_HISTORY_ENABLED", "false")
	root := t.TempDir()
	writeListAllPackageLock(t, root, listAllLockPackage{Name: "kept", Version: "1.0.0"})
	out := t.TempDir()
	settings := listAllSettings(root, true)
	settings.OutputJSON = out
	settings.OutputSARIF = filepath.Join(out, "result.sarif")
	settings.OutputJUnit = filepath.Join(out, "result.xml")

	var scan listAllScanPhaseResult
	var err error
	stderr := captureScanStderr(t, func() {
		scan, err = runListAllScanOutputPhase(context.Background(), settings)
	})
	if err != nil || scan.result == nil || scan.collection == nil || scan.exitCode != ExitOperational {
		t.Fatalf("scan = %+v, err = %v, want retained result/collection and operational artifact failure", scan, err)
	}
	if !strings.Contains(stderr, "error writing JSON output:") || !strings.Contains(stderr, "write file") {
		t.Fatalf("stderr = %q, want contextual JSON write failure", stderr)
	}
	if strings.Contains(stderr, "error writing SARIF output:") || strings.Contains(stderr, "error writing JUnit output:") {
		t.Fatalf("later artifacts failed after JSON failure: %q", stderr)
	}
	sarifData, readErr := os.ReadFile(settings.OutputSARIF) // #nosec G304 -- test reads its own artifact.
	if readErr != nil || !json.Valid(sarifData) {
		t.Fatalf("SARIF artifact = %q, err = %v, want valid JSON", sarifData, readErr)
	}
	junitData, readErr := os.ReadFile(settings.OutputJUnit) // #nosec G304 -- test reads its own artifact.
	if readErr != nil {
		t.Fatalf("read JUnit artifact: %v", readErr)
	}
	var junit struct {
		XMLName xml.Name
	}
	if unmarshalErr := xml.Unmarshal(junitData, &junit); unmarshalErr != nil {
		t.Fatalf("parse JUnit XML: %v", unmarshalErr)
	}
	if junit.XMLName.Local == "" {
		t.Fatal("JUnit artifact has no root element")
	}
}

func TestCollectListAllInventoryPhaseRetainsBaseInventoryWhenOptionalCollectorsFail(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "root-file")
	writeFile(t, rootFile, "not a directory")
	collection := &scanner.PackageCollection{Entries: []scanner.CollectedPackage{{
		Package:    domain.Package{Name: "kept", Version: "1.0.0", Ecosystem: domain.EcosystemNPM, Direct: true},
		SourceFile: "package-lock.json", SourceType: "lockfile",
	}}}

	var inventory listAllInventoryPhaseResult
	var err error
	stderr := captureStderr(t, func() {
		inventory, err = collectListAllInventoryPhase(scanSettings{Path: rootFile, MaxDepth: 3}, collection)
	})
	if err != nil || len(inventory.packages) != 1 || inventory.packages[0].Name != "kept" {
		t.Fatalf("inventory = %+v, err = %v, want preserved base row", inventory, err)
	}
	if len(inventory.warnings) != 2 || !strings.HasPrefix(inventory.warnings[0], "docker inventory error:") || !strings.HasPrefix(inventory.warnings[1], "chocolatey inventory error:") {
		t.Fatalf("warnings = %#v, want exactly the two optional inventory errors", inventory.warnings)
	}
	if strings.Contains(stderr, "\x1b") || !strings.Contains(stderr, "warning: docker inventory error:") || !strings.Contains(stderr, "warning: chocolatey inventory error:") {
		t.Fatalf("stderr = %q, want terminal-safe optional collector warnings", stderr)
	}
}

func TestCollectListAllInventoryPhaseRetainsValidDockerAndChocolateyRowsWithSanitizedParseWarnings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.23\n")
	writeFile(t, filepath.Join(root, "compose.yml"), "services:\n  broken: [\x1b")
	writeFile(t, filepath.Join(root, "install.ps1"), "choco install git --version 2.47.0 -y\n")
	if err := os.MkdirAll(filepath.Join(root, "broken"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "broken", "config.xml"), "<config><packages><package name=\"private\x1b\"")

	var inventory listAllInventoryPhaseResult
	var err error
	stderr := captureStderr(t, func() {
		inventory, err = collectListAllInventoryPhase(scanSettings{Path: root, MaxDepth: 4}, &scanner.PackageCollection{})
	})
	if err != nil {
		t.Fatalf("collectListAllInventoryPhase() error = %v", err)
	}
	var dockerRows, chocoRows int
	for _, row := range inventory.packages {
		switch row.Ecosystem {
		case domain.EcosystemDocker:
			dockerRows++
		case domain.EcosystemChocolatey:
			chocoRows++
		}
	}
	if dockerRows != 1 || chocoRows != 1 {
		t.Fatalf("packages = %#v, want one valid Docker and Chocolatey row", inventory.packages)
	}
	var dockerWarnings, chocoWarnings int
	for _, warning := range inventory.warnings {
		if strings.HasPrefix(warning, "docker parse error in ") {
			dockerWarnings++
		}
		if strings.HasPrefix(warning, "chocolatey parse error in ") {
			chocoWarnings++
		}
		if strings.Contains(warning, root) {
			t.Fatalf("warning leaked absolute root: %q", warning)
		}
	}
	if dockerWarnings != 1 || chocoWarnings != 1 {
		t.Fatalf("warnings = %#v, want exactly one parse warning per optional collector", inventory.warnings)
	}
	if strings.Contains(stderr, "\x1b") || strings.Contains(stderr, root) {
		t.Fatalf("stderr leaked terminal controls or absolute root: %q", stderr)
	}
}

func TestCollectListAllInventoryPhaseRejectsFatalBaseCollectionBeforeOptionalCollectors(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "root-file")
	writeFile(t, rootFile, "not a directory")
	inventory, err := collectListAllInventoryPhase(scanSettings{Path: rootFile, MaxDepth: 2}, &scanner.PackageCollection{
		Entries:          []scanner.CollectedPackage{{Package: domain.Package{Name: "discarded", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}}},
		FatalParseErrors: []string{"fatal base parse"},
	})
	if err == nil || exitCodeForError(err) != ExitParser {
		t.Fatalf("error = %v, want parser exit %d", err, ExitParser)
	}
	if len(inventory.packages) != 0 || len(inventory.warnings) != 0 || strings.Contains(err.Error(), "inventory error") {
		t.Fatalf("inventory = %+v, err = %v, want fatal short circuit before optional collectors", inventory, err)
	}
}

func TestResolveDockerImageStatusPinnedLookupFailuresStayPinnedAndAccountHonestly(t *testing.T) {
	policyErr := fmt.Errorf("%w: %w", dockerimage.ErrDigestUnavailable, dockerimage.ErrRegistryUnsupported)
	tests := []struct {
		name        string
		dockerRef   string
		err         error
		digest      string
		cancel      bool
		wantCalls   int
		wantRefused int
	}{
		{name: "ordinary error", dockerRef: "ghcr.io/acme/app:v1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", err: errors.New("registry unavailable"), wantCalls: 1, wantRefused: 1},
		{name: "unsupported policy", dockerRef: "ghcr.io/acme/app:v1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", err: policyErr, wantCalls: 1},
		{name: "canceled context", dockerRef: "ghcr.io/acme/app:v1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", err: context.Canceled, cancel: true, wantCalls: 1},
		{name: "empty digest", dockerRef: "ghcr.io/acme/app:v1@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", wantCalls: 1},
		{name: "no recoverable tag", dockerRef: "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, phase := withRegistryLookupPhase(context.Background(), 1)
			if tt.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			resolver := &countingDigestResolver{digest: tt.digest, err: tt.err}
			status := resolveDockerImageStatusWithDigestResolver(ctx, listAllPackage{Ecosystem: domain.EcosystemDocker, DockerRef: tt.dockerRef}, nil, resolver)
			if status.Latest != "-" || status.Update != "pinned" || status.Unknown {
				t.Fatalf("status = %+v, want pinned non-unknown fallback", status)
			}
			if resolver.callCount() != tt.wantCalls || phase.refusedCount() != tt.wantRefused || phase.oversizedCount() != 0 || phase.skippedCount() != 0 {
				t.Fatalf("calls/refused/oversized/skipped = %d/%d/%d/%d, want %d/%d/0/0", resolver.callCount(), phase.refusedCount(), phase.oversizedCount(), phase.skippedCount(), tt.wantCalls, tt.wantRefused)
			}
		})
	}
}

func TestWriteListAllTerminalSummaryAndTableEdgeContracts(t *testing.T) {
	result := &domain.ScanResult{
		Findings:      []domain.Finding{{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityLow}},
		FindingsCount: 1, FindingsBlocking: true, PackagesScanned: 2,
	}
	var summary strings.Builder
	if err := writeListAllTerminalFindingSummary(&summary, result, domain.SeverityCritical); err != nil {
		t.Fatal(err)
	}
	if got := summary.String(); got != "\nFound 1 finding (1 blocking) in 2 packages\n" {
		t.Fatalf("summary = %q", got)
	}
	var table strings.Builder
	if err := writeListAllTerminalFindingTable(&table, []listAllFindingRow{{Severity: "LOW", Package: "pkg", Advisory: "ADV", Title: "title"}}, true); err != nil {
		t.Fatal(err)
	}
	output := table.String()
	for _, want := range []string{"SEVERITY", "PACKAGE", "ADVISORY", "FINDING", "ACTION", "Details: Action: -; Type: -; Risk: -; Installed: -; Ecosystem: -; Source: -; Scope: -; Relation: -; Fixed Version: -"} {
		if !strings.Contains(output, want) {
			t.Fatalf("table missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "\x1b") {
		t.Fatalf("no-color table contains ANSI: %q", output)
	}
}

func TestListAllSourceKindAndOperationalStatusContracts(t *testing.T) {
	sourceCases := []struct {
		name string
		row  listAllRow
		want string
	}{
		{"dockerfile", listAllRow{Source: "Dockerfile"}, "docker"},
		{"compose", listAllRow{Source: "compose"}, "docker"},
		{"docker", listAllRow{Source: "docker"}, "docker"},
		{"config xml", listAllRow{Source: "config.xml"}, "chocolatey"},
		{"choco install", listAllRow{Source: "choco-install"}, "chocolatey"},
		{"chocolatey", listAllRow{Source: "chocolatey"}, "chocolatey"},
		{"explicit sbom", listAllRow{Source: "sbom"}, "sbom"},
		{"explicit lockfile", listAllRow{Source: "lockfile"}, "lockfile"},
		{"docker ecosystem", listAllRow{Ecosystem: string(domain.EcosystemDocker)}, "docker"},
		{"chocolatey ecosystem", listAllRow{Ecosystem: string(domain.EcosystemChocolatey)}, "chocolatey"},
		{"sbom scope", listAllRow{Scope: "sbom"}, "sbom"},
		{"cyclonedx suffix", listAllRow{LockFile: "bom.cdx.json"}, "sbom"},
		{"spdx json suffix", listAllRow{LockFile: "bom.spdx.json"}, "sbom"},
		{"spdx suffix", listAllRow{LockFile: "bom.spdx"}, "sbom"},
		{"default", listAllRow{LockFile: "package-lock.json"}, "lockfile"},
	}
	for _, tt := range sourceCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := listAllInventorySourceKind(tt.row); got != tt.want {
				t.Fatalf("listAllInventorySourceKind(%+v) = %q, want %q", tt.row, got, tt.want)
			}
		})
	}
	statusCases := []struct {
		name   string
		result *domain.ScanResult
		want   string
	}{
		{"nil", nil, ""},
		{"blank", &domain.ScanResult{}, ""},
		{"healthy", &domain.ScanResult{FeedStatus: "healthy"}, ""},
		{"degraded", &domain.ScanResult{FeedStatus: "degraded"}, ""},
		{"arbitrary", &domain.ScanResult{FeedStatus: "maintenance"}, "maintenance"},
		{"scan error", &domain.ScanResult{FeedStatus: "maintenance", ScanError: "  precise failure  "}, "precise failure"},
	}
	for _, tt := range statusCases {
		t.Run("status "+tt.name, func(t *testing.T) {
			if got := listAllOperationalStatusForResult(tt.result); got != tt.want {
				t.Fatalf("status = %q, want %q", got, tt.want)
			}
		})
	}
	age := 99
	result := &domain.ScanResult{Mode: domain.ScanModeLocal, DBStale: true, DBAgeDays: &age, FeedStatus: "degraded", ScanError: " precise failure "}
	var output strings.Builder
	if err := writeListAllTerminalFindingStatusMessages(&output, result); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "ATTENTION") || !strings.Contains(got, "precise failure") || strings.Contains(got, scanner.DegradedFeedStatusWarning(result.Mode)) {
		t.Fatalf("status output = %q, want stale and precise error without generic degraded warning", got)
	}
}

func TestListAllFindingActionAndSeverityClassContracts(t *testing.T) {
	actions := []struct {
		name string
		row  listAllFindingRow
		want string
	}{
		{"fixed precedence", listAllFindingRow{FixedVersion: " 2.0.0 ", Type: "Malicious"}, "Fix 2.0.0"},
		{"malicious", listAllFindingRow{Type: "Malicious"}, "Remove package"},
		{"malware history", listAllFindingRow{Type: "Supply-chain", RiskType: " Malware history "}, "Review history"},
		{"supply chain", listAllFindingRow{Type: "Supply-chain"}, "Review package"},
		{"lifecycle", listAllFindingRow{Type: "Lifecycle"}, "Review lifecycle"},
		{"reputation", listAllFindingRow{Type: "Reputation info"}, "Review history"},
		{"vulnerability", listAllFindingRow{Type: "Vulnerability"}, "Review advisory"},
		{"unknown", listAllFindingRow{Type: "Other"}, "Review finding"},
	}
	for _, tt := range actions {
		t.Run(tt.name, func(t *testing.T) {
			if got := listAllFindingAction(tt.row); got != tt.want {
				t.Fatalf("action = %q, want %q", got, tt.want)
			}
		})
	}
	classes := map[domain.Severity]string{
		domain.SeverityCritical:    "sev-critical",
		domain.SeverityHigh:        "sev-high",
		domain.SeverityMedium:      "sev-medium",
		domain.SeverityLow:         "sev-low",
		domain.Severity("UNKNOWN"): "sev-unknown",
	}
	for severity, want := range classes {
		if got := listAllSeverityClass(severity); got != want {
			t.Errorf("listAllSeverityClass(%q) = %q, want %q", severity, got, want)
		}
	}
}
