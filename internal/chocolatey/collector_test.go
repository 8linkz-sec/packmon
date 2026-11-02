package chocolatey

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

func TestCollectAppliesLineContinuationPerScriptType(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Each file uses the other dialect's continuation marker first, which must
	// not join lines, then its own marker, which must.
	writeTestFile(t, filepath.Join(dir, "install.ps1"), "choco install ps-a ^\r\nchoco install ps-b `\r\n ps-c\r\n")
	writeTestFile(t, filepath.Join(dir, "Module.psm1"), "choco install psm-a ^\r\nchoco install psm-b\r\n")
	writeTestFile(t, filepath.Join(dir, "setup.bat"), "choco install bat-a `\r\nchoco install bat-b ^\r\n bat-c\r\n")
	writeTestFile(t, filepath.Join(dir, "setup.cmd"), "choco install cmd-a `\r\nchoco install cmd-b\r\n")

	collection, err := Collect(dir, 10)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.ParseErrors) != 0 {
		t.Fatalf("ParseErrors = %v, want none", collection.ParseErrors)
	}
	got := make([]string, 0, len(collection.Packages))
	for _, pkg := range collection.Packages {
		got = append(got, pkg.SourceFile+":"+pkg.Name)
	}
	sort.Strings(got)
	want := []string{
		"Module.psm1:psm-a", "Module.psm1:psm-b",
		"install.ps1:ps-a", "install.ps1:ps-b", "install.ps1:ps-c",
		"setup.bat:bat-a", "setup.bat:bat-b", "setup.bat:bat-c",
		"setup.cmd:cmd-a", "setup.cmd:cmd-b",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("Packages = %v, want %v", got, want)
	}
}

func TestCollectIgnoresConfigXMLWithoutChocolateyPackages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "config.xml"), `<config><envs><env name="a" value="b"/></envs></config>`)
	writeTestFile(t, filepath.Join(dir, "broken", "config.xml"), `<config><packages><package name="x"`)
	writeTestFile(t, filepath.Join(dir, "garbage", "config.xml"), "not xml at all <<<")
	writeTestFile(t, filepath.Join(dir, "truncated-envs", "config.xml"), `<config><envs>`)

	collection, err := Collect(dir, 10)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if len(collection.Packages) != 0 {
		t.Fatalf("Packages = %+v, want none", collection.Packages)
	}
	// A file that identifies itself as a <config> with <packages> but is
	// truncated is a real parse error; unrelated XML, a malformed <config>
	// without a <packages> section, and non-XML are silent.
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

func TestCollectReturnsDiscoveryErrorForMissingRoot(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing-root")
	collection, err := Collect(missing, 1)
	if err == nil {
		t.Fatalf("Collect(%q) error = nil, want missing-root error", missing)
	}
	if collection != nil {
		t.Fatalf("Collect(%q) collection = %+v, want nil", missing, collection)
	}
}

func TestCollectRejectsFileRoot(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "inventory.ps1")
	writeTestFile(t, root, "choco install alpha\n")

	collection, err := Collect(root, 1)
	if !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("Collect(%q) error = %v, want fs.ErrInvalid", root, err)
	}
	if collection != nil {
		t.Fatalf("Collect(%q) collection = %+v, want nil", root, collection)
	}
}

func TestCollectFailsWhenRootDisappearsAfterDiscovery(t *testing.T) {
	// not parallel: swaps the package-level walk hook
	root := t.TempDir()
	withFakeWalk(t, func(walkRoot string, _ fs.WalkDirFunc) error {
		if err := os.RemoveAll(walkRoot); err != nil {
			t.Fatalf("RemoveAll(%q): %v", walkRoot, err)
		}
		return nil
	})

	collection, err := Collect(root, 1)
	if err == nil {
		t.Fatal("Collect() error = nil, want root-open failure")
	}
	if collection != nil {
		t.Fatalf("Collect() collection = %+v, want nil", collection)
	}
}

func TestParseFileFromRootSkipsNonRegularFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "directory.ps1"), 0o750); err != nil {
		t.Fatalf("Mkdir(directory.ps1): %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })

	packages, err := parseFileFromRoot(root, File{RelPath: "directory.ps1", Kind: KindPowerShellScript})
	if err != nil {
		t.Fatalf("parseFileFromRoot() error = %v", err)
	}
	if packages != nil {
		t.Fatalf("parseFileFromRoot() packages = %+v, want nil", packages)
	}
}

func TestDedupPackagesMergesFlagsWithinIdentity(t *testing.T) {
	t.Parallel()

	packages := []Package{
		{Name: "alpha", Version: "1.0", SourceFile: "one.ps1", Flags: []string{"direct", ""}},
		{Name: "alpha", Version: "1.0", SourceFile: "one.ps1", Flags: []string{"direct", "reviewed"}},
		{Name: "alpha", Version: "2.0", SourceFile: "one.ps1", Flags: []string{"pinned"}},
		{Name: "alpha", Version: "1.0", SourceFile: "two.ps1", Flags: []string{"other-source"}},
	}

	got := dedupPackages(packages)
	if len(got) != 3 {
		t.Fatalf("dedupPackages() = %+v, want three distinct identities", got)
	}
	if got[0].Name != "alpha" || got[0].Version != "1.0" || got[0].SourceFile != "one.ps1" {
		t.Fatalf("dedupPackages()[0] = %+v, want first identity preserved", got[0])
	}
	if flags := strings.Join(got[0].Flags, ","); flags != "direct,reviewed" {
		t.Fatalf("dedupPackages()[0].Flags = %q, want %q", flags, "direct,reviewed")
	}
	if got[1].Version != "2.0" || got[2].SourceFile != "two.ps1" {
		t.Fatalf("dedupPackages() reordered or merged distinct identities: %+v", got)
	}
}

func TestCollectContinuesAfterWarningsAndParseErrors(t *testing.T) {
	// not parallel: swaps the package-level walk hook
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "broken", "config.xml"), `<config><packages><package name="broken"`)
	writeTestFile(t, filepath.Join(dir, "good.ps1"), "choco install good --version 1.2.3\n")
	withFakeWalk(t, func(root string, fn fs.WalkDirFunc) error {
		if err := fn(filepath.Join(root, "unreadable"), nil, &fs.PathError{Op: "open", Path: filepath.Join(root, "unreadable"), Err: fs.ErrPermission}); err != nil {
			return err
		}
		if err := fn(filepath.Join(root, "broken", "config.xml"), fakeDirEntry{name: "config.xml"}, nil); err != nil {
			return err
		}
		return fn(filepath.Join(root, "good.ps1"), fakeDirEntry{name: "good.ps1"}, nil)
	})

	collection, err := Collect(dir, 5)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if collection.Files != 2 {
		t.Fatalf("Files = %d, want 2", collection.Files)
	}
	if len(collection.DiscoveryWarnings) != 1 || !strings.HasPrefix(collection.DiscoveryWarnings[0], "unreadable: ") {
		t.Fatalf("DiscoveryWarnings = %v, want one relative unreadable warning", collection.DiscoveryWarnings)
	}
	if len(collection.ParseErrors) != 1 || !strings.HasPrefix(collection.ParseErrors[0], "broken/config.xml: ") {
		t.Fatalf("ParseErrors = %v, want one relative broken/config.xml error", collection.ParseErrors)
	}
	if len(collection.Packages) != 1 || collection.Packages[0].Name != "good" || collection.Packages[0].Version != "1.2.3" {
		t.Fatalf("Packages = %+v, want valid file after parse failure", collection.Packages)
	}
	for _, message := range append(collection.DiscoveryWarnings, collection.ParseErrors...) {
		if strings.Contains(message, dir) || strings.Contains(message, filepath.ToSlash(dir)) {
			t.Fatalf("diagnostic %q leaks root %q", message, dir)
		}
	}
}

func TestCollectAcceptsInputsAtExactSizeLimits(t *testing.T) {
	for _, tt := range []struct {
		name        string
		path        string
		prefix      string
		padding     string
		limit       int
		packageName string
	}{
		{
			name:        "script",
			path:        "exact.ps1",
			prefix:      "choco install exact-script\n#",
			padding:     "x",
			limit:       maxScriptFileSize,
			packageName: "exact-script",
		},
		{
			name:        "config",
			path:        "config.xml",
			prefix:      `<config><packages><package name="exact-config"/></packages></config>`,
			padding:     " ",
			limit:       maxConfigFileSize,
			packageName: "exact-config",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			content := tt.prefix + strings.Repeat(tt.padding, tt.limit-len(tt.prefix))
			writeTestFile(t, filepath.Join(dir, tt.path), content)

			collection, err := Collect(dir, 1)
			if err != nil {
				t.Fatalf("Collect() error = %v", err)
			}
			if len(collection.ParseErrors) != 0 || len(collection.DiscoveryWarnings) != 0 {
				t.Fatalf("ParseErrors = %v, DiscoveryWarnings = %v, want none", collection.ParseErrors, collection.DiscoveryWarnings)
			}
			if len(collection.Packages) != 1 || collection.Packages[0].Name != tt.packageName {
				t.Fatalf("Packages = %+v, want %q", collection.Packages, tt.packageName)
			}
			if info, statErr := os.Stat(filepath.Join(dir, tt.path)); statErr != nil || info.Size() != int64(tt.limit) {
				t.Fatalf("Stat(%q) = (%v, %v), want size %d", tt.path, info, statErr, tt.limit)
			}
		})
	}
}

func TestParseFileFromRootRejectsInvalidFileInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "known.ps1"), "choco install known\n")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })

	for _, tt := range []struct {
		name string
		file File
		want string
	}{
		{
			name: "root escape",
			file: File{RelPath: "../outside.ps1", Kind: KindPowerShellScript},
			want: "escapes scan root",
		},
		{
			name: "missing file",
			file: File{RelPath: "missing.ps1", Kind: KindPowerShellScript},
			want: "missing.ps1",
		},
		{
			name: "unsupported kind",
			file: File{RelPath: "known.ps1", Kind: Kind("unknown")},
			want: "unsupported chocolatey inventory file kind",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			packages, err := parseFileFromRoot(root, tt.file)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseFileFromRoot(%+v) error = %v, want %q", tt.file, err, tt.want)
			}
			if packages != nil {
				t.Fatalf("parseFileFromRoot(%+v) packages = %+v, want nil", tt.file, packages)
			}
			if strings.Contains(err.Error(), dir) {
				t.Fatalf("parseFileFromRoot(%+v) error leaks root %q: %v", tt.file, dir, err)
			}
		})
	}
}

func TestMergeStringsKeepsFirstOccurrenceAndDropsEmptyValues(t *testing.T) {
	t.Parallel()

	got := mergeStrings([]string{"unpinned", "direct", "unpinned", ""}, []string{"", "direct", "transitive", "unpinned"})
	want := []string{"unpinned", "direct", "transitive"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("mergeStrings() = %v, want %v", got, want)
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
		got := parseChocoInstallLine(KindPowerShellScript, tt.line)
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
	pkgs, err := ParseScript(strings.NewReader(string(encoded)), "x.ps1", KindPowerShellScript)
	if err != nil {
		t.Fatalf("ParseScript() error = %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "utf16pkg" {
		t.Fatalf("ParseScript(utf16) = %+v, want utf16pkg", pkgs)
	}
}
