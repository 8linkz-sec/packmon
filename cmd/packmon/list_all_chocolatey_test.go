package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

const chocolateyTestConfigXML = `<?xml version="1.0" encoding="utf-8"?>
<config>
    <packages>
        <package name="7zip.vm"/>
        <package name="vcredist-all"/>
    </packages>
</config>
`

func TestRunListAllIncludesChocolateyPackages(t *testing.T) {
	isolatedListAllEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.xml"), []byte(chocolateyTestConfigXML), 0o600); err != nil {
		t.Fatalf("write config.xml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lint.ps1"), []byte("choco install psscriptanalyzer --version 1.23.0 --no-progress\n"), 0o600); err != nil {
		t.Fatalf("write lint.ps1: %v", err)
	}

	resolver := stubLatestVersion(t, func(_ context.Context, eco domain.Ecosystem, name string) string {
		if eco != domain.EcosystemChocolatey {
			t.Fatalf("unexpected lookup for %s/%s", eco, name)
		}
		switch name {
		case "7zip.vm":
			return "23.1.0.20250902"
		case "vcredist-all":
			return "1.0.1"
		case "psscriptanalyzer":
			return "1.24.0"
		}
		return ""
	})

	output := captureStdout(t, func() {
		if _, err := runListAll(context.Background(), listAllSettingsWithResolver(dir, false, resolver)); err != nil {
			t.Fatalf("runListAll: %v", err)
		}
	})

	for _, want := range []string{
		"7zip.vm", "vcredist-all", "psscriptanalyzer",
		"chocolatey", "config.xml", "choco-install", "lint.ps1",
		"23.1.0.20250902", "1.24.0", "unpinned",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("list-all output missing %q:\n%s", want, output)
		}
	}
	// One pinned row (1.23.0 -> 1.24.0) is an update; unpinned rows are not.
	if !strings.Contains(output, "1 with update,") {
		t.Fatalf("list-all summary must count only the pinned chocolatey update:\n%s", output)
	}
}

func TestBuildListAllReportRendersUnpinnedChocolateyRows(t *testing.T) {
	isolatedListAllEnv(t)
	resolver := stubLatestVersion(t, func(_ context.Context, _ domain.Ecosystem, name string) string {
		if name == "missing.vm" {
			return ""
		}
		return "2.0.0"
	})
	report := buildListAllPackageReportWithOptions(context.Background(), []listAllPackage{
		{Name: "7zip.vm", Version: "", Ecosystem: domain.EcosystemChocolatey, LockFile: "config.xml", SourceType: "config.xml", Direct: true, Scope: "runtime", Relation: "declared", Flags: "unpinned"},
		{Name: "git", Version: "1.0.0", Ecosystem: domain.EcosystemChocolatey, LockFile: "setup.ps1", SourceType: "choco-install", Direct: true, Scope: "runtime", Relation: "declared"},
		{Name: "current", Version: "2.0.0", Ecosystem: domain.EcosystemChocolatey, LockFile: "setup.ps1", SourceType: "choco-install", Direct: true, Scope: "runtime", Relation: "declared"},
		{Name: "missing.vm", Version: "", Ecosystem: domain.EcosystemChocolatey, LockFile: "config.xml", SourceType: "config.xml", Direct: true, Scope: "runtime", Relation: "declared", Flags: "unpinned"},
	}, nil, "repo", 1, listAllPackageReportOptions{resolver: resolver})

	rows := map[string]listAllRow{}
	for _, row := range report.Rows {
		rows[row.Name] = row
	}
	if row := rows["7zip.vm"]; row.Installed != "-" || row.Latest != "2.0.0" || row.Update != "unpinned" || row.Flags != "unpinned" {
		t.Fatalf("unpinned row = %+v, want installed '-', latest 2.0.0, update 'unpinned'", row)
	}
	if row := rows["git"]; row.Update != "yes" || row.Latest != "2.0.0" {
		t.Fatalf("pinned outdated row = %+v, want update yes", row)
	}
	if row := rows["current"]; row.Update != "-" {
		t.Fatalf("pinned current row = %+v, want update '-'", row)
	}
	if row := rows["missing.vm"]; row.Installed != "-" || row.Latest != "unknown" || row.Update != "unpinned" {
		t.Fatalf("unpinned unknown row = %+v, want latest unknown and update 'unpinned'", row)
	}
	if report.WithUpdates != 1 {
		t.Fatalf("WithUpdates = %d, want 1 (unpinned rows are never counted as updates)", report.WithUpdates)
	}
	if report.Unknown != 1 {
		t.Fatalf("Unknown = %d, want 1 (only the row whose feed lookup failed)", report.Unknown)
	}
	for _, name := range []string{"7zip.vm", "missing.vm"} {
		if got := listAllHTMLPackageStatus(rows[name], nil); got != "Unpinned" {
			t.Fatalf("HTML status for %s = %q, want Unpinned", name, got)
		}
	}
	for _, source := range []string{"config.xml", "choco-install"} {
		if got := listAllInventorySourceKind(listAllRow{Source: source, Ecosystem: "chocolatey"}); got != "chocolatey" {
			t.Fatalf("listAllInventorySourceKind(%s) = %q, want chocolatey", source, got)
		}
	}
	if got := listAllPackageSource(listAllPackage{Ecosystem: domain.EcosystemChocolatey}); got != "chocolatey" {
		t.Fatalf("listAllPackageSource(chocolatey without source type) = %q, want chocolatey", got)
	}
}

func TestPlainScanDoesNotSendChocolateyInventoryPackages(t *testing.T) {
	t.Setenv("PACKMON_API_KEY", "test")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.xml"), []byte(chocolateyTestConfigXML), 0o600); err != nil {
		t.Fatalf("write config.xml: %v", err)
	}
	writeListAllPackageLock(t, dir, listAllLockPackage{Name: "left-pad", Version: "1.3.0"})
	handlerErrors := make(chan string, 1)
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/check" {
			reportHandlerError(w, handlerErrors, http.StatusNotFound, "unexpected path %s", r.URL.Path)
			return
		}
		select {
		case requests <- struct{}{}:
		default:
		}
		var req struct {
			Packages []domain.Package `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reportHandlerError(w, handlerErrors, http.StatusBadRequest, "decode request: %v", err)
			return
		}
		var sawNPM bool
		for _, pkg := range req.Packages {
			if pkg.Ecosystem == domain.EcosystemNPM && pkg.Name == "left-pad" && pkg.Version == "1.3.0" {
				sawNPM = true
			}
			if pkg.Ecosystem == domain.EcosystemChocolatey {
				reportHandlerError(w, handlerErrors, http.StatusBadRequest, "plain scan request included chocolatey package: %#v", pkg)
				return
			}
		}
		if !sawNPM {
			reportHandlerError(w, handlerErrors, http.StatusBadRequest, "plain scan request packages = %#v, want npm left-pad", req.Packages)
			return
		}
		if err := writeJSONResponseForTest(w, domain.ScanResult{ScanID: "scan", Mode: "remote"}); err != nil {
			reportHandlerError(w, handlerErrors, http.StatusInternalServerError, "encode JSON response: %v", err)
			return
		}
	}))
	defer server.Close()

	cmd := newScanCmd()
	cmd.SetArgs([]string{"--mode", "remote", "--server", server.URL, "--insecure-allow-http", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	assertNoHandlerError(t, handlerErrors)
	select {
	case <-requests:
	default:
		t.Fatal("plain scan did not call remote check; test would not prove chocolatey exclusion")
	}
}

func TestListAllSkipsChocolateyWhenEcosystemFilterExcludesIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.xml"), []byte(chocolateyTestConfigXML), 0o600); err != nil {
		t.Fatalf("write config.xml: %v", err)
	}
	rows, warnings, err := collectChocolateyPackagesWithWarnings(dir, scanSettings{MaxDepth: 5, Ecosystems: []string{"npm"}})
	if err != nil || len(rows) != 0 || len(warnings) != 0 {
		t.Fatalf("filtered collect = %v rows, %v warnings, err %v; want nothing", rows, warnings, err)
	}
	rows, _, err = collectChocolateyPackagesWithWarnings(dir, scanSettings{MaxDepth: 5, Ecosystems: []string{"npm", "chocolatey"}})
	if err != nil || len(rows) != 2 {
		t.Fatalf("collect with chocolatey filter = %d rows (err %v), want 2", len(rows), err)
	}
	if rows[0].Ecosystem != domain.EcosystemChocolatey || rows[0].SourceType != "config.xml" || rows[0].Scope != "runtime" || rows[0].Relation != "declared" || rows[0].Flags != "unpinned" || !rows[0].Direct {
		t.Fatalf("row = %+v, want chocolatey/config.xml/runtime/declared/unpinned/direct", rows[0])
	}
}
