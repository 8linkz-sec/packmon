package chocolatey

import (
	"errors"
	"reflect"
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
		{"redirect before id", `choco install > out.log 7zip`, []string{"7zip@"}},
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
		{"invoke expression string", `Invoke-Expression "choco install 7zip"`, nil},
		{"pipe to tee", `choco install 7zip | Tee-Object -FilePath x.log`, []string{"7zip@"}},
		// quoted separator characters are argument text, never separators
		{"quoted semicolon argument before choco", `Write-Host ';' choco install fake`, nil},
		{"double-quoted pipe argument before choco", `Write-Host "|" choco install fake`, nil},
		{"quoted brace argument before choco", `Write-Host '}' choco install fake`, nil},
		{"quoted equals argument before choco", `Write-Host '=' choco install fake`, nil},
		{"quoted ampersand argument before choco", `Write-Host "&" choco install fake`, nil},
		{"quoted semicolon option value", `choco install a --params ';' b`, []string{"a@", "b@"}},
		{"quoted redirect option value", `choco install a --installargs ">" b`, []string{"a@", "b@"}},
		{"quoted semicolon argument", `choco install a ';' b`, []string{"a@", "b@"}},
		{"unquoted separator after quoted text", `Write-Host ';'; choco install real`, []string{"real@"}},
		{"quoted digit before redirect is an argument", `choco install a '2'> out.log`, []string{"a@", "2@"}},
		{"empty", `   `, nil},
		{"install only option", `choco install --version 1.0`, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := lineKeys(parseChocoInstallLine(KindPowerShellScript, tt.line))
			if got != strings.Join(tt.want, " ") {
				t.Errorf("parseChocoInstallLine(%q) = %q, want %q", tt.line, got, strings.Join(tt.want, " "))
			}
		})
	}
}

func TestParseChocoInstallLineCommentsFollowScriptKind(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		kind Kind
		line string
		want []string // name@version
	}{
		{"batch rem", KindBatchScript, `REM choco install 7zip`, nil},
		{"batch @rem", KindBatchScript, `@REM choco install 7zip`, nil},
		{"batch double colon", KindBatchScript, `:: choco install 7zip`, nil},
		{"batch hash is an argument", KindBatchScript, `choco install a # b`, []string{"a@", "b@"}},
		{"batch hash line is a command", KindBatchScript, `# x & choco install a`, []string{"a@"}},
		{"powershell hash comment", KindPowerShellScript, `# choco install 7zip`, nil},
		{"powershell trailing hash comment", KindPowerShellScript, `choco install a # b`, []string{"a@"}},
		{"powershell rem is a command word", KindPowerShellScript, `REM x; choco install a`, []string{"a@"}},
		{"powershell double colon is a command word", KindPowerShellScript, `:: x; choco install a`, []string{"a@"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := lineKeys(parseChocoInstallLine(tt.kind, tt.line))
			if got != strings.Join(tt.want, " ") {
				t.Errorf("parseChocoInstallLine(%q, %q) = %q, want %q", tt.kind, tt.line, got, strings.Join(tt.want, " "))
			}
		})
	}
}

func TestParseScriptRejectsNonScriptKind(t *testing.T) {
	t.Parallel()

	pkgs, err := ParseScript(strings.NewReader("choco install a\n"), "config.xml", KindConfigXML)
	if err == nil || !strings.Contains(err.Error(), "config.xml: unsupported chocolatey script kind") {
		t.Fatalf("ParseScript(KindConfigXML) error = %v, want unsupported script kind", err)
	}
	if pkgs != nil {
		t.Fatalf("ParseScript(KindConfigXML) packages = %+v, want nil", pkgs)
	}
}

func TestParseScriptReadErrorsDiscardPartialPackages(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("script reader failed")
	for _, tt := range []struct {
		name string
		data string
	}{
		{"immediate error", ""},
		{"partial command", "choco install do-not-return\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			packages, err := ParseScript(&failingReader{data: []byte(tt.data), err: sentinel}, "scripts/install.ps1", KindPowerShellScript)
			if !errors.Is(err, sentinel) {
				t.Fatalf("ParseScript() error = %v, want sentinel", err)
			}
			if packages != nil {
				t.Fatalf("ParseScript() packages = %+v, want nil", packages)
			}
			if got := err.Error(); got != sentinel.Error() || strings.Contains(got, "do-not-return") {
				t.Fatalf("ParseScript() error = %q, want generic content-free error", got)
			}
		})
	}
}

func TestParseChocoInstallLineBareChocoIsIgnored(t *testing.T) {
	t.Parallel()

	if got := parseChocoInstallLine(KindPowerShellScript, "choco"); got != nil {
		t.Fatalf("parseChocoInstallLine(%q) = %+v, want nil", "choco", got)
	}
}

func TestDecodeTextBytesUTF16Boundaries(t *testing.T) {
	t.Parallel()

	surrogatePair := "A" + string(rune(0x1F642))
	for _, tt := range []struct {
		name string
		data []byte
		want string
	}{
		{"little endian surrogate pair", []byte(utf16LE(surrogatePair)), surrogatePair},
		{"big endian surrogate pair", []byte(utf16BE(surrogatePair)), surrogatePair},
		{"little endian truncated unit", []byte{0xFF, 0xFE, 0x41, 0x00, 0xFF}, "A"},
		{"big endian truncated unit", []byte{0xFE, 0xFF, 0x00, 0x41, 0xFF}, "A"},
		{"unpaired surrogate", []byte{0xFF, 0xFE, 0x00, 0xD8}, "\uFFFD"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := decodeTextBytes(tt.data); got != tt.want {
				t.Fatalf("decodeTextBytes(%x) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestParseScriptUTF16BEProducesExactPackage(t *testing.T) {
	t.Parallel()

	packages, err := ParseScript(strings.NewReader(utf16BE("choco install Git.Install --version 2.47.0\r\n")), "scripts/install.ps1", KindPowerShellScript)
	if err != nil {
		t.Fatalf("ParseScript() error = %v", err)
	}
	want := []Package{{
		Name:       "git.install",
		Version:    "2.47.0",
		SourceFile: "scripts/install.ps1",
		SourceType: SourceChocoInstall,
	}}
	if !reflect.DeepEqual(packages, want) {
		t.Fatalf("ParseScript() packages = %#v, want %#v", packages, want)
	}
}

func TestParseChocoInstallLineVersionLengthBoundaries(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		version string
		want    string
	}{
		{"64 bytes accepted", strings.Repeat("1", 64), strings.Repeat("1", 64)},
		{"65 bytes rejected", strings.Repeat("1", 65), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseChocoInstallLine(KindPowerShellScript, "choco install package --version "+tt.version)
			if len(got) != 1 || got[0] != (installEntry{name: "package", version: tt.want}) {
				t.Fatalf("parseChocoInstallLine() = %+v, want package@%q", got, tt.want)
			}
		})
	}
}

func scriptKeys(t *testing.T, kind Kind, script string) string {
	t.Helper()
	if kind == "" {
		kind = KindPowerShellScript
	}
	pkgs, err := ParseScript(strings.NewReader(script), "x", kind)
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
		kind   Kind
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
			kind:   KindBatchScript,
			script: "choco install 7zip ^\r\n --version 1.0\r\n",
			want:   "7zip@1.0[]",
		},
		{
			name:   "batch caret continuation at eof",
			kind:   KindBatchScript,
			script: "choco install 7zip ^",
			want:   "7zip@[unpinned]",
		},
		{
			name:   "powershell caret does not continue",
			script: "choco install a ^\r\nchoco install b\r\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "batch backtick does not continue",
			kind:   KindBatchScript,
			script: "choco install a `\r\nchoco install b\r\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "batch hash is not a comment",
			kind:   KindBatchScript,
			script: "choco install a # b\r\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "batch hash is an argument and the caret still continues",
			kind:   KindBatchScript,
			script: "choco install a # note ^\r\n b\r\n",
			want:   "a@[unpinned] note@[unpinned] b@[unpinned]",
		},
		{
			name:   "batch has no block comments",
			kind:   KindBatchScript,
			script: "<#\r\nchoco install a\r\n#>\r\n",
			want:   "a@[unpinned]",
		},
		{
			name:   "batch has no here-strings",
			kind:   KindBatchScript,
			script: "echo @\"\r\nchoco install a\r\n",
			want:   "a@[unpinned]",
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
			name:   "backtick in line comment does not continue",
			script: "# note `\nchoco install git\n",
			want:   "git@[unpinned]",
		},
		{
			name:   "backtick in indented line comment does not continue",
			script: "  # note `\r\nchoco install git\r\n",
			want:   "git@[unpinned]",
		},
		{
			name:   "backtick in trailing comment does not continue",
			script: "choco install a # note `\nchoco install git\n",
			want:   "a@[unpinned] git@[unpinned]",
		},
		{
			name:   "backtick in comment after a continued line ends the command",
			script: "choco install a `\n# note `\nchoco install git\n",
			want:   "a@[unpinned] git@[unpinned]",
		},
		{
			name:   "backtick in unterminated block comment does not continue",
			script: "choco install a <# note `\n#> choco install git\n",
			want:   "a@[unpinned] git@[unpinned]",
		},
		{
			name:   "backtick inside multi-line block comment does not continue",
			script: "<#\nnote `\n#>\nchoco install git\n",
			want:   "git@[unpinned]",
		},
		{
			name:   "backtick after a closed block comment continues",
			script: "<# note #> choco install a `\n b\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "backtick after a block comment closed on this line continues",
			script: "<# doc\ncomment #> choco install a `\n b\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "hash inside quotes before backtick continues",
			script: "choco install a --params \"#x\" `\n b\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "hash mid token before backtick continues",
			script: "choco install a --params=/a#b `\n b\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "quote spanning a continuation hides a hash",
			script: "choco install a --params \"x `\n #y\" `\n b\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "braced variable before a continuation keeps the separator",
			script: "Write-Host ${env:ProgramFiles(x86)} `\n; choco install a\n",
			want:   "a@[unpinned]",
		},
		{
			name:   "multiline quote keeps comments and separators as argument text",
			script: "choco install a --params \"x `\n#not-a-comment; still-quoted\" `\n; choco install b\n",
			want:   "a@[unpinned] b@[unpinned]",
		},
		{
			name:   "batch comment continuation stays a comment",
			kind:   KindBatchScript,
			script: "REM choco install hidden ^\r\nchoco install still-hidden\r\nchoco install visible\r\n",
			want:   "visible@[unpinned]",
		},
		{
			name:   "same package pinned twice yields two rows",
			script: "choco install a --version 1.0\nchoco install a\n",
			want:   "a@1.0[] a@[unpinned]",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scriptKeys(t, tt.kind, tt.script); got != tt.want {
				t.Errorf("ParseScript(%q) = %q, want %q", tt.script, got, tt.want)
			}
		})
	}
}

// TestParseScriptLongContinuationIsLinear guards against rebuilding the
// pending logical line for every continued physical line: a script near the
// 1 MiB size bound made of caret (or backtick) continuations must finish
// quickly instead of copying the growing line once per physical line.
func TestParseScriptLongContinuationIsLinear(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		kind   Kind
		marker string
	}{
		{KindBatchScript, "^"},
		{KindPowerShellScript, "`"},
	} {
		t.Run(string(tt.kind), func(t *testing.T) {
			t.Parallel()
			script := "choco install a " + tt.marker + "\r\n" +
				strings.Repeat("b "+tt.marker+"\r\n", 200_000) + "c\r\n"
			if got, want := scriptKeys(t, tt.kind, script), "a@[unpinned]"+strings.Repeat(" b@[unpinned]", 200_000)+" c@[unpinned]"; got != want {
				t.Errorf("ParseScript(long %s continuation) returned %d bytes of keys, want %d", tt.kind, len(got), len(want))
			}
		})
	}
}

// TestParseScriptSeparatorsAndOptionQuotesFollowScriptKind pins which
// characters separate commands in each language and how option values are
// unquoted. cmd.exe starts a new command only after an unquoted, unescaped
// `&`, `&&`, `||`, `|`, a redirection, or a block parenthesis; `;`, `{`, `}`
// and `=` are ordinary argument text there. cmd.exe passes single quotes to
// choco.exe unchanged (only double quotes group on its command line), so a
// batch `--version='1.0'` is not a version literal.
func TestParseScriptSeparatorsAndOptionQuotesFollowScriptKind(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		script     string
		powerShell string
		batch      string
	}{
		{"semicolon", "echo x ; choco install a\r\n", "a@[unpinned]", ""},
		{"semicolon without spaces", "echo x;choco install a\r\n", "a@[unpinned]", ""},
		{"semicolon inside the package list", "choco install a ; b\r\n", "a@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"opening brace", "echo { choco install a }\r\n", "a@[unpinned]", ""},
		{"closing brace", "echo } choco install a\r\n", "a@[unpinned]", ""},
		{"equals", "set x = choco install a\r\n", "a@[unpinned]", ""},
		{"ampersand", "echo x & choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"double ampersand", "echo x && choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"double pipe", "echo x || choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"pipe", "echo x | choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"redirection then ampersand", "choco install a >nul & choco install b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"block parentheses", "if exist x (choco install a) else (choco install b)\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"ampersand ends the package list", "choco install a & b\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"single-quoted version value", "choco install a --version='1.0'\r\n", "a@1.0[]", "a@[unpinned]"},
		{"single-quoted separate version value", "choco install a --version '1.0'\r\n", "a@1.0[]", "a@[unpinned]"},
		{"single-quoted option token", "choco install a '--version=1.0'\r\n", "a@1.0[]", "a@[unpinned]"},
		{"double-quoted version value", "choco install a --version=\"1.0\"\r\n", "a@1.0[]", "a@1.0[]"},
		{"double-quoted separate version value", "choco install a --version \"1.0\"\r\n", "a@1.0[]", "a@1.0[]"},
		{"escaped double quotes around version value", "choco install a --version=^\"1.0^\"\r\n", "a@[unpinned]", "a@1.0[]"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scriptKeys(t, KindPowerShellScript, tt.script); got != tt.powerShell {
				t.Errorf("ParseScript(%q, powershell) = %q, want %q", tt.script, got, tt.powerShell)
			}
			if got := scriptKeys(t, KindBatchScript, tt.script); got != tt.batch {
				t.Errorf("ParseScript(%q, batch) = %q, want %q", tt.script, got, tt.batch)
			}
		})
	}
}

// TestParseScriptQuotingAndEscapingFollowScriptKind pins the cmd.exe quoting
// and caret-escape rules for batch files against the unchanged PowerShell
// rules: in batch files only double quotes group, a caret inside double
// quotes is literal, an unquoted caret makes the next character literal (a
// doubled caret is a literal caret), and a caret that ends the line joins the
// next line without a space and escapes its first character.
func TestParseScriptQuotingAndEscapingFollowScriptKind(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		script     string
		powerShell string
		batch      string
	}{
		{
			name:       "single quotes group only in powershell",
			script:     "choco install 'a' b\r\n",
			powerShell: "a@[unpinned] b@[unpinned]",
			batch:      "b@[unpinned]",
		},
		{
			name:       "single quotes do not hide a batch separator",
			script:     "echo 'note & choco install b c'\r\n",
			powerShell: "",
			batch:      "b@[unpinned]",
		},
		{
			name:       "double quotes group in both",
			script:     "echo \"note & choco install b\"\r\n",
			powerShell: "",
			batch:      "",
		},
		{
			name:       "escaped ampersand is a batch argument",
			script:     "echo x ^& choco install b\r\n",
			powerShell: "b@[unpinned]",
			batch:      "",
		},
		{
			name:       "escaped pipe is a batch argument",
			script:     "echo x ^| choco install b\r\n",
			powerShell: "b@[unpinned]",
			batch:      "",
		},
		{
			name:       "escaped output redirect is a batch argument",
			script:     "choco install a ^> b\r\n",
			powerShell: "a@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "escaped input redirect is a batch argument",
			script:     "choco install a ^< b\r\n",
			powerShell: "a@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "escaped double quote does not open a batch quote",
			script:     "echo ^\"x & choco install b\r\n",
			powerShell: "",
			batch:      "b@[unpinned]",
		},
		{
			name:       "escaped space still separates batch arguments",
			script:     "choco install a^ b\r\n",
			powerShell: "b@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "caret inside double quotes is literal",
			script:     "choco install a --params \"^&\" b\r\n",
			powerShell: "a@[unpinned] b@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "caret inside double quotes does not continue",
			script:     "choco install a --params \"x ^\r\nchoco install b\r\n",
			powerShell: "a@[unpinned] b@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "caret after a closed double quote continues in batch",
			script:     "choco install a --params \"x^\" ^\r\n b\r\n",
			powerShell: "a@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "caret after a single quote continues in batch",
			script:     "choco install a 'x ^\r\n b\r\n",
			powerShell: "a@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "doubled caret at line end does not continue",
			script:     "choco install a ^^\r\nchoco install b\r\n",
			powerShell: "a@[unpinned] b@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "escaped trailing caret continues",
			script:     "choco install a ^^^\r\n b\r\n",
			powerShell: "a@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "caret followed by trailing whitespace does not continue",
			script:     "choco install a ^ \r\nchoco install b\r\n",
			powerShell: "a@[unpinned] b@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "continuation joins without a space",
			script:     "choco install sev^\r\nen\r\n",
			powerShell: "",
			batch:      "seven@[unpinned]",
		},
		{
			name:       "continuation escapes the first separator of the next line",
			script:     "echo x ^\r\n& choco install b\r\n",
			powerShell: "b@[unpinned]",
			batch:      "",
		},
		{
			name:       "continuation escapes the first quote of the next line",
			script:     "echo ^\r\n\"x & choco install b\r\n",
			powerShell: "",
			batch:      "b@[unpinned]",
		},
		{
			name:       "continuation escapes a leading caret of the next line",
			script:     "choco install a ^\r\n^\r\nchoco install b\r\n",
			powerShell: "a@[unpinned] b@[unpinned]",
			batch:      "a@[unpinned] b@[unpinned]",
		},
		{
			name:       "terminal percent sign is not an expansion",
			script:     "choco install a %\r\n",
			powerShell: "a@[unpinned]",
			batch:      "a@[unpinned]",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scriptKeys(t, KindPowerShellScript, tt.script); got != tt.powerShell {
				t.Errorf("ParseScript(%q, powershell) = %q, want %q", tt.script, got, tt.powerShell)
			}
			if got := scriptKeys(t, KindBatchScript, tt.script); got != tt.batch {
				t.Errorf("ParseScript(%q, batch) = %q, want %q", tt.script, got, tt.batch)
			}
		})
	}
}
