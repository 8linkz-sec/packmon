package chocolatey

import (
	"strings"
	"testing"
)

func lineKeys(entries []installEntry) string {
	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		keys = append(keys, entry.name+"@"+entry.version)
	}
	return strings.Join(keys, " ")
}

func TestParseChocoInstallLineEdgeCases(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		line string
		want []string // name@version
	}{
		// redirection must not leak file names or descriptors as package IDs
		{"redirect stdout", `choco install 7zip > out.log`, []string{"7zip@"}},
		{"redirect append and stderr merge", `choco install 7zip >> out.log 2>&1`, []string{"7zip@"}},
		{"stderr merge then pipe", `choco install 7zip 2>&1 | Out-Null`, []string{"7zip@"}},
		{"stderr redirect", `choco install 7zip 2> err.log`, []string{"7zip@"}},
		{"powershell all-stream redirect", `choco install 7zip *> $null`, []string{"7zip@"}},
		{"batch nul redirect", `choco install 7zip >nul 2>&1`, []string{"7zip@"}},
		{"redirect before id", `choco install > out.log 7zip`, nil},
		// placeholders and variables
		{"angle placeholder", `choco install -y <package_name>`, nil},
		{"variable version is unpinned", `choco install 7zip --version $ver`, []string{"7zip@"}},
		{"placeholder version is unpinned", `choco install 7zip --version=<version>`, []string{"7zip@"}},
		{"garbage version is unpinned", `choco install 7zip --version "1.0 or later"`, []string{"7zip@"}},
		{"prerelease version kept", `choco install 7zip --version 1.0.0-beta.1`, []string{"7zip@1.0.0-beta.1"}},
		// batch and PowerShell command prefixes
		{"batch @ prefix", `@choco install 7zip`, []string{"7zip@"}},
		{"batch call", `call choco install 7zip`, []string{"7zip@"}},
		{"batch @call", `@call choco install 7zip -y`, []string{"7zip@"}},
		{"sudo prefix", `sudo choco install 7zip`, []string{"7zip@"}},
		{"call operator with quoted path", `& 'C:\ProgramData\chocolatey\bin\choco.exe' install 7zip`, []string{"7zip@"}},
		{"forward slash path", `& "$env:ChocolateyInstall/bin/choco.exe" upgrade 7zip`, []string{"7zip@"}},
		{"assignment of output", `$out = choco install 7zip`, []string{"7zip@"}},
		{"null assignment", `$null = choco install 7zip -y`, []string{"7zip@"}},
		// options
		{"trace is a flag", `choco install --trace 7zip`, []string{"7zip@"}},
		{"except takes value", `choco upgrade all --except foo`, nil},
		{"except with equals", `choco upgrade all --except="a,b"`, nil},
		{"slash options", `choco install 7zip /y /source internal`, []string{"7zip@"}},
		{"parameters alias takes value", `choco install 7zip --parameters "/x" git`, []string{"7zip@", "git@"}},
		{"installarguments takes value", `choco install 7zip --installarguments "/S" git`, []string{"7zip@", "git@"}},
		{"quoted option token", `choco install 7zip '--version=1.2'`, []string{"7zip@1.2"}},
		{"nested quoted params", `choco install 7zip --params '"/x /y"' git`, []string{"7zip@", "git@"}},
		{"capitalised option", `choco install 7zip -Version 1.0`, []string{"7zip@1.0"}},
		{"version without value at end", `choco install 7zip -y --version`, []string{"7zip@"}},
		{"version applies to all ids", `choco install 7zip --version 1.0 git`, []string{"7zip@1.0", "git@1.0"}},
		{"colon version", `choco install 7zip --version:1.0`, []string{"7zip@1.0"}},
		{"quoted ids", `choco install "7zip" 'git'`, []string{"7zip@", "git@"}},
		{"source with equals then id", `choco install 7zip --source="https://x/api/v2" git`, []string{"7zip@", "git@"}},
		{"cup with version", `cup 7zip --version 1.0`, []string{"7zip@1.0"}},
		{"cup all", `cup all -y`, nil},
		{"uppercase verb", `CHOCO INSTALL 7Zip`, []string{"7zip@"}},
		// separators and comments
		{"no-space semicolon", `choco install a;choco install b`, []string{"a@", "b@"}},
		{"or separator", `choco install a || choco install b`, []string{"a@", "b@"}},
		{"if else blocks", `if ($x) { choco install a } else { choco install b }`, []string{"a@", "b@"}},
		{"trailing comment", `choco install 7zip # installs 7zip`, []string{"7zip@"}},
		{"hash inside quotes", `choco install 7zip --params "/a#b" git`, []string{"7zip@", "git@"}},
		{"hash mid token is not a comment", `choco install 7zip --params=/a#b git`, []string{"7zip@", "git@"}},
		{"batch rem", `REM choco install 7zip`, nil},
		{"batch @rem", `@REM choco install 7zip`, nil},
		{"batch double colon", `:: choco install 7zip`, nil},
		{"invoke expression string", `Invoke-Expression "choco install 7zip"`, nil},
		{"pipe to tee", `choco install 7zip | Tee-Object -FilePath x.log`, []string{"7zip@"}},
		{"empty", `   `, nil},
		{"install only option", `choco install --version 1.0`, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := lineKeys(parseChocoInstallLine(tt.line))
			if got != strings.Join(tt.want, " ") {
				t.Errorf("parseChocoInstallLine(%q) = %q, want %q", tt.line, got, strings.Join(tt.want, " "))
			}
		})
	}
}

func scriptKeys(t *testing.T, script string) string {
	t.Helper()
	pkgs, err := ParseScript(strings.NewReader(script), "x.ps1")
	if err != nil {
		t.Fatalf("ParseScript() error = %v", err)
	}
	keys := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		keys = append(keys, pkg.Name+"@"+pkg.Version+"["+strings.Join(pkg.Flags, ",")+"]")
	}
	return strings.Join(keys, " ")
}

func TestParseScriptMultiLineConstructs(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "backtick continuation",
			script: "choco install 7zip `\r\n  --version 1.0 `\r\n  -y\r\nchoco install git\r\n",
			want:   "7zip@1.0[] git@[unpinned]",
		},
		{
			name:   "batch caret continuation",
			script: "choco install 7zip ^\r\n --version 1.0\r\n",
			want:   "7zip@1.0[]",
		},
		{
			name:   "continuation at eof",
			script: "choco install 7zip `",
			want:   "7zip@[unpinned]",
		},
		{
			name:   "double-quoted here-string is skipped",
			script: "Write-Host @\"\nchoco install foo\n    choco install -y <package_name>\n\"@\nchoco install bar\n",
			want:   "bar@[unpinned]",
		},
		{
			name:   "single-quoted here-string is skipped",
			script: "$usage = @'\nchoco install foo\n'@\nchoco install bar\n",
			want:   "bar@[unpinned]",
		},
		{
			name:   "unterminated here-string swallows rest",
			script: "$usage = @\"\nchoco install foo\n",
			want:   "",
		},
		{
			name:   "block comment is skipped",
			script: "<#\nchoco install foo\n#>\nchoco install bar\n",
			want:   "bar@[unpinned]",
		},
		{
			name:   "block comment inline",
			script: "<# choco install foo #> choco install bar <# choco install baz #>\n",
			want:   "bar@[unpinned]",
		},
		{
			name:   "block comment ends mid line",
			script: "<# doc\ncomment #> choco install bar\n",
			want:   "bar@[unpinned]",
		},
		{
			name:   "block comment start inside quotes does not open a comment",
			script: "Write-Host \"<#\"\nchoco install bar\n",
			want:   "bar@[unpinned]",
		},
		{
			name:   "same package pinned twice yields two rows",
			script: "choco install a --version 1.0\nchoco install a\n",
			want:   "a@1.0[] a@[unpinned]",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scriptKeys(t, tt.script); got != tt.want {
				t.Errorf("ParseScript(%q) = %q, want %q", tt.script, got, tt.want)
			}
		})
	}
}
