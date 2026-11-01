package chocolatey

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzParseConfigXML(f *testing.F) {
	f.Add([]byte(flareConfigXML))
	f.Add([]byte(`<config><packages><package name="x"`))
	f.Add([]byte(`<configuration/>`))
	f.Add([]byte(``))
	f.Add([]byte("\ufeff<config><packages><package name=\"a\"/></packages></config>"))
	f.Add([]byte(utf16LE(`<?xml version="1.0" encoding="utf-16"?><config><packages><package name="a"/></packages></config>`)))
	f.Add([]byte(`<?xml version="1.0" encoding="windows-1252"?><config><packages><package Name="a"/></packages></config>`))
	f.Add([]byte(`<!DOCTYPE config [<!ENTITY a "aaaa">]><config><packages><package name="&a;"/></packages></config>`))
	f.Add([]byte("<config><packages>" + strings.Repeat("<a>", 64) + "</packages></config>"))
	f.Add([]byte{0xFF, 0xFE, '<', 0})
	f.Add([]byte{0xFE, 0xFF, 0, '<', 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		pkgs, err := ParseConfigXML(bytes.NewReader(data), "config.xml")
		if err != nil {
			if !strings.HasPrefix(err.Error(), "config.xml: ") || strings.ContainsAny(err.Error(), "<>") {
				t.Fatalf("error %q leaks content or lacks the source prefix", err)
			}
			if len(pkgs) != 0 {
				t.Fatalf("packages returned alongside error: %+v", pkgs)
			}
		}
		for _, pkg := range pkgs {
			if !packageIDPattern.MatchString(pkg.Name) || pkg.Name != strings.ToLower(pkg.Name) || pkg.Name == "all" {
				t.Fatalf("invalid package id %q", pkg.Name)
			}
		}
	})
}

func FuzzParseScript(f *testing.F) {
	f.Add([]byte("choco install 7zip --version 1.0 -y\n"))
	f.Add([]byte("if ($x) { choco upgrade a b --source=\"x\" }\r\n"))
	f.Add([]byte{0xFF, 0xFE, 'c', 0, 'h', 0})
	f.Add([]byte{0xFE, 0xFF, 0, 'c', 0, 'h'})
	f.Add([]byte(``))
	f.Add([]byte("choco install 7zip `\r\n  --version 1.0 `\r\n  -y\r\n"))
	f.Add([]byte("Write-Host @\"\nchoco install foo\n\"@\nchoco install bar\n"))
	f.Add([]byte("<#\nchoco install foo\n#>\nchoco install bar <# x #> baz\n"))
	f.Add([]byte("choco install 7zip >nul 2>&1 | Out-Null\n"))
	f.Add([]byte("@call choco.exe install 7zip /y --params '\"/x\"' # c\n"))
	f.Add([]byte("$null = & 'C:\\ProgramData\\chocolatey\\bin\\choco.exe' upgrade all --except foo\n"))
	f.Add([]byte("choco install a `"))
	f.Add([]byte("choco install \"unterminated\n"))
	f.Add([]byte("\xff\xfe\xfd choco install x\n"))
	f.Add([]byte("REM note ^\r\n:: x `\r\nchoco install a # b ^\r\n c\r\n"))
	f.Add([]byte("echo 'note & choco install b c'\r\nchoco install 'a' b\r\n"))
	f.Add([]byte("echo x ^& choco install b ^| x ^< y ^> z\r\necho ^\"x & choco install c\r\n"))
	f.Add([]byte("choco install a --params \"x ^\r\nchoco install b ^^\r\nchoco install c ^^^\r\n d ^ \r\n"))
	f.Add([]byte("choco install sev^\r\nen ^\r\n& x ^\r\n\"y ^\r\n^\r\n^"))
	f.Add([]byte("echo x;choco install a ; b { c } = d && e || f | g\r\nset x = choco install --version='1.0' h --version=^\"2.0^\" i\r\n"))
	f.Add([]byte(">nul choco install a >nul b 2>&1 1>&2 c *> $null d 2>> \"e f.log\" g < 'h i' j >\r\n"))
	f.Add([]byte("choco install a --params ^\"/x >nul y^\" b ^\"c & choco install d --params ^\"/x \"y z\" \"\"\r\n"))
	f.Add([]byte("for /f \"tokens=*\" %%a in (list.txt) do @call choco install %%a b\r\n) do choco install c\r\nfor %%i in (x & choco install d\r\n"))
	f.Add([]byte("@if /i not \"%1\"==\"\" if exist %ProgramFiles(x86)%\\x if %x% equ 1 (choco install a) else choco install b\r\n"))
	f.Add([]byte("if \"a==\" == b choco install c & if errorlevel 1 if cmdextversion 2 echo 50% & choco install d\r\n"))
	f.Add([]byte("echo Installing (x86) choco install a & @(choco install b >out(1).log c)else(x)\r\nif exist x (\r\n echo (y^) ^\"(z\r\n) else (for %%i in(1) do(choco install d))\r\n) e\r\n"))
	f.Add([]byte("try { if ($x) { choco install a } elseif ($y) { foreach ($p in $l) { choco install b > #x\r\n& ${env:ProgramFiles(x86)}\\c\\choco.exe install c ${ d\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, kind := range []Kind{KindPowerShellScript, KindBatchScript} {
			pkgs, err := ParseScript(bytes.NewReader(data), "x", kind)
			if err != nil {
				t.Fatalf("ParseScript() error = %v", err)
			}
			for _, pkg := range pkgs {
				if !packageIDPattern.MatchString(pkg.Name) || pkg.Name != strings.ToLower(pkg.Name) || pkg.Name == "all" {
					t.Fatalf("invalid package id %q", pkg.Name)
				}
				if pkg.Version != "" && !versionPattern.MatchString(pkg.Version) {
					t.Fatalf("invalid version %q", pkg.Version)
				}
				if (pkg.Version == "") != (len(pkg.Flags) == 1 && pkg.Flags[0] == FlagUnpinned) {
					t.Fatalf("flags %v inconsistent with version %q", pkg.Flags, pkg.Version)
				}
			}
		}
	})
}
