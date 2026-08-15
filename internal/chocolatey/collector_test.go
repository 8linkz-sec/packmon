package chocolatey

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/8linkz-sec/packmon/internal/domain"
)

const flareConfigXML = `<?xml version="1.0" encoding="utf-8"?>
<!--
 Copyright 2017 Google LLC
 Licensed under the Apache License, Version 2.0 (the "License");
-->

<config>
    <envs>
        <env name="VM_COMMON_DIR" value="%ProgramData%\_VM"/>
    </envs>
    <packages>
        <package name="010editor.vm"/>
        <package name="7zip.vm"/>
        <package name="dotnet3.5"/> <!-- To run old .NET binaries -->
        <package name="Vcredist-All"/>
        <package name="7zip.vm"/>
        <package name=""/>
        <package/>
    </packages>
    <apps>
        <app name="notepad" />
    </apps>
</config>
`

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func packageByKey(pkgs []Package, name, version, sourceFile string) (Package, bool) {
	for _, pkg := range pkgs {
		if pkg.Name == name && pkg.Version == version && pkg.SourceFile == sourceFile {
			return pkg, true
		}
	}
	return Package{}, false
}

func TestCollectFindsConfigXMLPackagesAndChocoInstallLines(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "config.xml"), flareConfigXML)
	writeTestFile(t, filepath.Join(dir, "scripts", "lint.ps1"), "\ufeff# lint helper\r\nchoco install psscriptanalyzer --version 1.23.0 --no-progress\r\nInvoke-ScriptAnalyzer -Path .\r\n")
	writeTestFile(t, filepath.Join(dir, "install.ps1"), strings.Join([]string{
		`if (-not $ok) { choco upgrade chocolatey }`,
		`choco install common.vm -y --force`,
		`choco install -y <package_name>`,
		`choco install $pkg "$quoted"`,
		`choco search 7zip -e -r`,
		`choco sources add -n="vm-packages" -s "https://www.myget.org/F/vm-packages/api/v2" --priority 1`,
		`cinst git.install sysinternals --version=2024.1.1 -y ; Write-Host done`,
		`choco.exe upgrade Notepadplusplus --source https://community.chocolatey.org/api/v2 --params '"/NoDesktopShortcut"'`,
		`# choco install commented-out`,
	}, "\n"))
	writeTestFile(t, filepath.Join(dir, "setup.cmd"), "@echo off\r\nchoco install 7zip.install --version 23.1.0 -y\r\n")
	writeTestFile(t, filepath.Join(dir, "other", "config.xml"), `<?xml version="1.0"?><configuration><appSettings><add key="x" value="y"/></appSettings></configuration>`)
	writeTestFile(t, filepath.Join(dir, "notes.txt"), "choco install ignored-because-not-a-script\n")

	collection, err := Collect(dir, 10)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.ParseErrors) != 0 {
		t.Fatalf("ParseErrors = %v, want none", collection.ParseErrors)
	}
	if len(collection.DiscoveryWarnings) != 0 {
		t.Fatalf("DiscoveryWarnings = %v, want none", collection.DiscoveryWarnings)
	}

	want := []struct {
		name, version, source string
		sourceType            SourceType
		flags                 string
	}{
		{"010editor.vm", "", "config.xml", SourceConfigXML, "unpinned"},
		{"7zip.vm", "", "config.xml", SourceConfigXML, "unpinned"},
		{"dotnet3.5", "", "config.xml", SourceConfigXML, "unpinned"},
		{"vcredist-all", "", "config.xml", SourceConfigXML, "unpinned"},
		{"psscriptanalyzer", "1.23.0", "scripts/lint.ps1", SourceChocoInstall, ""},
		{"chocolatey", "", "install.ps1", SourceChocoInstall, "unpinned"},
		{"common.vm", "", "install.ps1", SourceChocoInstall, "unpinned"},
		{"git.install", "2024.1.1", "install.ps1", SourceChocoInstall, ""},
		{"sysinternals", "2024.1.1", "install.ps1", SourceChocoInstall, ""},
		{"notepadplusplus", "", "install.ps1", SourceChocoInstall, "unpinned"},
		{"7zip.install", "23.1.0", "setup.cmd", SourceChocoInstall, ""},
	}
	if len(collection.Packages) != len(want) {
		names := make([]string, 0, len(collection.Packages))
		for _, pkg := range collection.Packages {
			names = append(names, pkg.SourceFile+":"+pkg.Name+"@"+pkg.Version)
		}
		t.Fatalf("Packages = %d %v, want %d", len(collection.Packages), names, len(want))
	}
	for _, w := range want {
		pkg, ok := packageByKey(collection.Packages, w.name, w.version, w.source)
		if !ok {
			t.Fatalf("missing package %s@%q from %s: %+v", w.name, w.version, w.source, collection.Packages)
		}
		if pkg.SourceType != w.sourceType {
			t.Errorf("%s source type = %q, want %q", w.name, pkg.SourceType, w.sourceType)
		}
		if got := strings.Join(pkg.Flags, ","); got != w.flags {
			t.Errorf("%s flags = %q, want %q", w.name, got, w.flags)
		}
	}
	if collection.Files != 5 {
		t.Fatalf("Files = %d, want 5 candidate files (2 config.xml, 2 ps1, 1 cmd)", collection.Files)
	}
}

func TestPackageConvertsToChocolateyDomainPackage(t *testing.T) {
	t.Parallel()

	pkg := Package{Name: "7zip.vm", Version: "", SourceFile: "config.xml", SourceType: SourceConfigXML}
	got := pkg.Package()
	if got.Ecosystem != domain.EcosystemChocolatey || got.Name != "7zip.vm" || got.Version != "" || !got.Direct {
		t.Fatalf("Package() = %+v, want direct chocolatey package", got)
	}
	if !got.Ecosystem.InventoryOnly() {
		t.Fatalf("chocolatey must be inventory-only")
	}
}

func TestCollectIgnoresConfigXMLWithoutChocolateyPackages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "config.xml"), `<config><envs><env name="a" value="b"/></envs></config>`)
	writeTestFile(t, filepath.Join(dir, "broken", "config.xml"), `<config><packages><package name="x"`)
	writeTestFile(t, filepath.Join(dir, "garbage", "config.xml"), "not xml at all <<<")

	collection, err := Collect(dir, 10)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.Packages) != 0 {
		t.Fatalf("Packages = %+v, want none", collection.Packages)
	}
	// A file that identifies itself as a <config> with <packages> but is
	// truncated is a real parse error; unrelated XML and non-XML are silent.
	if len(collection.ParseErrors) != 1 || !strings.Contains(collection.ParseErrors[0], "broken/config.xml") {
		t.Fatalf("ParseErrors = %v, want exactly one for broken/config.xml", collection.ParseErrors)
	}
}

func TestCollectRejectsOversizedInputsWithoutParsing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	big := strings.Repeat("choco install a-package\n", (maxScriptFileSize/24)+2)
	writeTestFile(t, filepath.Join(dir, "big.ps1"), big)
	writeTestFile(t, filepath.Join(dir, "config.xml"), "<config><packages>"+strings.Repeat(`<package name="p"/>`, (maxConfigFileSize/len(`<package name="p"/>`))+2)+"</packages></config>")

	collection, err := Collect(dir, 10)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.Packages) != 0 {
		t.Fatalf("Packages = %d, want none from oversized inputs", len(collection.Packages))
	}
	if len(collection.ParseErrors) != 2 {
		t.Fatalf("ParseErrors = %v, want two size-limit errors", collection.ParseErrors)
	}
	for _, msg := range collection.ParseErrors {
		if !strings.Contains(msg, "exceeds maximum") || strings.Contains(msg, dir) {
			t.Fatalf("parse error %q must mention the size limit and not leak absolute paths", msg)
		}
	}
}

func TestCollectSkipsHiddenAndVendorDirectoriesAndHonoursDepth(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, ".git", "hooks", "x.ps1"), "choco install hidden\n")
	writeTestFile(t, filepath.Join(dir, "node_modules", "y.ps1"), "choco install vendored\n")
	writeTestFile(t, filepath.Join(dir, "a", "b", "c", "deep.ps1"), "choco install deep\n")
	writeTestFile(t, filepath.Join(dir, "a", "shallow.ps1"), "choco install shallow\n")

	collection, err := Collect(dir, 1)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.Packages) != 1 || collection.Packages[0].Name != "shallow" {
		t.Fatalf("Packages = %+v, want only shallow", collection.Packages)
	}
}

func TestCollectRejectsSymlinkOutsideRoot(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	outside := t.TempDir()
	writeTestFile(t, filepath.Join(outside, "config.xml"), flareConfigXML)
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "config.xml"), filepath.Join(dir, "config.xml")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	collection, err := Collect(dir, 10)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.Packages) != 0 {
		t.Fatalf("Packages = %+v, want none through symlink escaping the root", collection.Packages)
	}
}

func TestParseChocoInstallLineShapes(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		line string
		want []string // name@version
	}{
		{`choco install 7zip`, []string{"7zip@"}},
		{`choco install 7zip --version 23.1.0`, []string{"7zip@23.1.0"}},
		{`choco install 7zip --version=23.1.0`, []string{"7zip@23.1.0"}},
		{`choco install 7zip --version "23.1.0"`, []string{"7zip@23.1.0"}},
		{`choco upgrade 7zip git -y`, []string{"7zip@", "git@"}},
		{`cinst 7zip`, []string{"7zip@"}},
		{`cup all`, nil},
		{`choco install all`, nil},
		{`choco install`, nil},
		{`choco install --version 1.0`, nil},
		{`choco install 7zip; choco install git`, []string{"7zip@", "git@"}},
		{`choco install 7zip && choco install git`, []string{"7zip@", "git@"}},
		{`& choco install 7zip | Out-Null`, []string{"7zip@"}},
		{`Write-Host "run choco install 7zip"`, nil},
		{`choco install ..\evil`, nil},
		{`choco install pkg/with/slash`, nil},
		{`choco install UPPER.Case`, []string{"upper.case@"}},
		{`choco install 7zip --source=https://example.invalid/api/v2`, []string{"7zip@"}},
		{`choco install 7zip -s https://example.invalid/api/v2`, []string{"7zip@"}},
		{`chocolatey install 7zip`, nil},
		{`choco uninstall 7zip`, nil},
	} {
		got := parseChocoInstallLine(tt.line)
		var keys []string
		for _, entry := range got {
			keys = append(keys, entry.name+"@"+entry.version)
		}
		if strings.Join(keys, " ") != strings.Join(tt.want, " ") {
			t.Errorf("parseChocoInstallLine(%q) = %v, want %v", tt.line, keys, tt.want)
		}
	}
}

func TestDecodeScriptHandlesUTF16(t *testing.T) {
	t.Parallel()

	encoded := []byte{0xFF, 0xFE}
	for _, unit := range utf16.Encode([]rune("choco install utf16pkg\r\n")) {
		encoded = binary.LittleEndian.AppendUint16(encoded, unit)
	}
	pkgs, err := ParseScript(strings.NewReader(string(encoded)), "x.ps1")
	if err != nil {
		t.Fatalf("ParseScript() error = %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "utf16pkg" {
		t.Fatalf("ParseScript(utf16) = %+v, want utf16pkg", pkgs)
	}
}
