package chocolatey

import (
	"strings"
	"testing"
	"time"
)

type dialectCase struct {
	name       string
	script     string
	powerShell string
	batch      string
}

func runDialectCases(t *testing.T, cases []dialectCase) {
	t.Helper()
	for _, tt := range cases {
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

// TestParseScriptRedirectionsFollowScriptKind pins how redirections are read:
// both shells remove a redirection operator together with its target from
// anywhere on the command line before the command runs, so a redirection
// neither ends the package list nor puts the next word into command position,
// and its target is never a package ID. A stream duplication such as `2>&1`
// takes no target.
func TestParseScriptRedirectionsFollowScriptKind(t *testing.T) {
	t.Parallel()

	runDialectCases(t, []dialectCase{
		{"redirection before the command", ">nul choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"redirections before the command", ">nul 2>&1 choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"nul redirect inside the package list", "choco install a >nul b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"spaced output redirect", "choco install a > out.log b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"append redirect", "choco install a >> out.log b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"input redirect", "choco install a < answers.txt b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"stderr redirect", "choco install a 2> err.log b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"stderr append redirect", "choco install a 2>> err.log b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"stderr to stdout", "choco install a 2>&1 b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"stdout to stderr", "choco install a 1>&2 b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"all-stream redirect", "choco install a *> $null b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"attached null target", "choco install a >$null b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"double-quoted target", "choco install a > \"out file.log\" b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"attached double-quoted target", "choco install a >\"C:\\logs\\x.log\" b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"redirect after the verb", "choco install >nul a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"redirect target is no package", "choco install a > b\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"redirect target is no command", "echo x > choco install a\r\n", "", ""},
		{"redirect without target", "choco install a >\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"redirects then separator", "choco install a 2>nul >nul & choco install b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"redirect before a separator", "echo x >nul & choco install b\r\n", "b@[unpinned]", "b@[unpinned]"},
		{"single-quoted target", "choco install a > 'x y' b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"single quotes group a target only in powershell", "choco install a > 'x y b\r\n", "a@[unpinned]", "a@[unpinned] y@[unpinned] b@[unpinned]"},
		{"hash after redirect", "choco install a > #x\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"braced variable target", "choco install a > ${env:TEMP}\\x.log b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"escaped redirect takes no batch target", "choco install a ^> nul b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] nul@[unpinned] b@[unpinned]"},
		{"caret-escaped blank stays inside a batch target", "choco install a > out^ file.log b\r\n", "a@[unpinned] file.log@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
	})
}

// TestParseScriptBatchEscapedQuotesGroupArguments pins that a caret-escaped
// double quote groups words for choco.exe's own argument splitting although
// it opens no cmd.exe quote: `--params ^"/x y^"` reaches choco.exe as one
// quoted argument, while `&` and `|` still separate commands after it.
func TestParseScriptBatchEscapedQuotesGroupArguments(t *testing.T) {
	t.Parallel()

	runDialectCases(t, []dialectCase{
		{"escaped quotes group an option value", "choco install a --params ^\"/x y z^\" b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"escaped quotes group a trailing option value", "choco install a --params ^\"/x y z^\"\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"escaped quotes around a package id", "choco install ^\"a^\" b\r\n", "b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"escaped quote keeps the ampersand a separator", "choco install a --params ^\"/x & choco install b\r\n", "a@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"escaped quote keeps the pipe a separator", "echo ^\"x | choco install b\r\n", "", "b@[unpinned]"},
		{"escaped quote keeps a redirection", "choco install a --params ^\"/x >nul y^\" b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"escaped space inside escaped quotes groups", "choco install a --params ^\"/x^ y^\" b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"real quote closes an escaped-quote group", "choco install a --params ^\"/x \"y b c\r\n", "a@[unpinned] b@[unpinned] c@[unpinned]", "a@[unpinned] b@[unpinned] c@[unpinned]"},
		// PowerShell reads `b` as the version on purpose: Windows PowerShell
		// (and PowerShell 7 with $PSNativeCommandArgumentPassing = 'Legacy')
		// drops an empty "" argument when it starts a native program, so
		// choco.exe receives `--version b`. cmd.exe passes the "" through.
		{"empty double quotes are an argument", "choco install a --version \"\" b\r\n", "a@b[]", "a@[unpinned] b@[unpinned]"},
	})
}

// TestParseScriptCommandPositionFollowsScriptKind pins where a control
// statement hands command position on: in batch files after `for ... in
// (...) do`, after the condition of `if` (`exist`, `defined`, `errorlevel`,
// `cmdextversion`, `==` and the `EQU`-style comparisons, each optionally with
// `/i` and `not`), and after an `else` that follows a closing parenthesis; in
// PowerShell inside the `{ ... }` blocks of `if`, `foreach`, `try` and
// friends. A batch `%name%` expansion and a PowerShell `${name}` variable are
// one word, so parentheses inside them split nothing.
func TestParseScriptCommandPositionFollowsScriptKind(t *testing.T) {
	t.Parallel()

	runDialectCases(t, []dialectCase{
		{"for do", "for %%i in (1 2) do choco install a\r\n", "", "a@[unpinned]"},
		{"for do with a loop variable", "for %%p in (git 7zip) do choco install %%p -y\r\n", "", ""},
		{"for /l do with echo prefix", "for /l %%i in (1,1,3) do @choco install a\r\n", "", "a@[unpinned]"},
		{"for /f do", "for /f \"tokens=*\" %%a in (list.txt) do choco install %%a b\r\n", "", "b@[unpinned]"},
		{"for do call", "FOR %%i IN (1) DO call choco install a\r\n", "", "a@[unpinned]"},
		{"for do block", "for %%i in (1) do (choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"for set is data", "for %%i in (choco install x) do echo %%i\r\n", "x@[unpinned]", ""},
		{"for without do", "for %%i in (x) choco install a\r\n", "a@[unpinned]", ""},
		{"for header ends at a separator", "for %%i in (x & choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"do closing a multi-line for set", "for %%i in (1\r\n2) do choco install a\r\n", "", "a@[unpinned]"},
		{"do as a package id", "choco install a do b\r\n", "a@[unpinned] do@[unpinned] b@[unpinned]", "a@[unpinned] do@[unpinned] b@[unpinned]"},
		{"do without a closing parenthesis", "do choco install a\r\n", "", ""},
		{"if exist", "if exist C:\\x choco install a\r\n", "", "a@[unpinned]"},
		{"if not exist", "if not exist C:\\x choco install a\r\n", "", "a@[unpinned]"},
		{"if errorlevel", "if errorlevel 1 choco install a\r\n", "", "a@[unpinned]"},
		{"if not errorlevel", "IF NOT ERRORLEVEL 1 choco install a\r\n", "", "a@[unpinned]"},
		{"if defined", "@if defined x choco install a\r\n", "", "a@[unpinned]"},
		{"if cmdextversion", "if cmdextversion 2 choco install a\r\n", "", "a@[unpinned]"},
		{"if case-insensitive comparison", "if /i \"%x%\"==\"y\" choco install a\r\n", "", "a@[unpinned]"},
		{"if empty-string comparison", "if \"%1\"==\"\" choco install a\r\n", "", "a@[unpinned]"},
		{"if spaced comparison", "if \"%1\" == \"\" choco install a\r\n", "", "a@[unpinned]"},
		{"if comparison with a trailing equals", "if %x%== y choco install a\r\n", "", "a@[unpinned]"},
		{"if comparison with a leading equals", "if %x% ==y choco install a\r\n", "", "a@[unpinned]"},
		{"if quoted equals is no comparison", "if \"a==\" == b choco install a\r\n", "", "a@[unpinned]"},
		{"if not comparison", "if not %x%==y choco install a\r\n", "", "a@[unpinned]"},
		{"if compare operator", "if %x% equ 1 choco install a\r\n", "", "a@[unpinned]"},
		{"if condition operand is no command", "if exist choco.exe echo choco install a\r\n", "", ""},
		{"if comparison operand is no command", "if choco==x echo install a\r\n", "", ""},
		{"if block", "if exist x (choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"else without block", "if exist x (choco install a) else choco install b\r\n", "a@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"else if", "if exist x (echo y) else if exist z choco install b\r\n", "", "b@[unpinned]"},
		{"nested if", "if exist x if not exist y choco install a\r\n", "", "a@[unpinned]"},
		{"if inside a block", "(if exist x choco install a)\r\n", "", "a@[unpinned]"},
		{"if with an unquoted percent expansion", "if exist %ProgramFiles(x86)%\\x choco install a\r\n", "", "a@[unpinned]"},
		{"percent expansion with parentheses is one word", "echo %ProgramFiles(x86)%\\choco.exe install a\r\n", "a@[unpinned]", ""},
		{"choco path with a percent expansion", "%ProgramFiles(x86)%\\Chocolatey\\bin\\choco.exe install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"percent sign without a closing percent", "echo 50% & choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"powershell if block", "if (Test-Path x) { choco install a }\r\n", "a@[unpinned]", ""},
		{"powershell if elseif else blocks", "if ($x) { choco install a } elseif ($y) { choco install b } else { choco install c }\r\n", "a@[unpinned] b@[unpinned] c@[unpinned]", ""},
		{"powershell foreach block", "foreach ($p in $list) { choco install a }\r\n", "a@[unpinned]", ""},
		{"powershell try catch finally", "try { choco install a } catch { choco install b } finally { choco install c }\r\n", "a@[unpinned] b@[unpinned] c@[unpinned]", ""},
		{"powershell braced variable with parentheses is one word", "Write-Host ${env:ProgramFiles(x86)} choco install a\r\n", "", ""},
		{"powershell call of a braced variable path", "& ${env:ProgramFiles(x86)}\\Chocolatey\\bin\\choco.exe install a\r\n", "a@[unpinned]", "a@[unpinned]"},
	})
}

// TestParseScriptBatchParenthesesFollowBlockDepth pins the cmd.exe block
// rules for batch files: a `(` opens a block only where a command starts (at
// the start of a line, after `&`, `|`, or another `(`, after an `if`
// condition, after `else` or `do` that follows a closing parenthesis, and as
// the set of a `for` header), and a `)` closes one only while a block is open,
// which a multi-line block keeps open across lines. Anywhere else both are
// ordinary argument text, so `echo Installing (x86) choco install a` is one
// echo command and a `^"...^"` group keeps its parentheses. PowerShell keeps
// reading parentheses as separators.
func TestParseScriptBatchParenthesesFollowBlockDepth(t *testing.T) {
	t.Parallel()

	runDialectCases(t, []dialectCase{
		{"parenthesized echo text is no separator", "echo Installing (x86) choco install a\r\n", "a@[unpinned]", ""},
		{"parenthesized argument stays in the package list", "choco install a (x86) b\r\n", "a@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"block", "(choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"echo-suppressed block", "@(choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"multi-line block", "(\r\n  choco install a\r\n)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"if else blocks", "if exist x (choco install a) else (choco install b)\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"if with an escaped blank in the operand", "if exist x^ y choco install a\r\n", "", "a@[unpinned]"},
		{"if block with an escaped blank in the operand", "if not exist C:\\Program^ Files\\Git (choco install git)\r\n", "git@[unpinned]", "git@[unpinned]"},
		{"if exist block with an escaped blank", "if exist x^ y (choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"if defined block with an escaped blank", "if defined A^ B (choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"if comparison with an escaped blank", "if a==b^ c (choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"escaped blank in the command still separates", "if exist x choco^ install a\r\n", "", "a@[unpinned]"},
		{"bare echo-suppression prefix", "@ choco install a\r\n", "", "a@[unpinned]"},
		{"bare echo-suppression prefix before a block", "@ (choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"tolerated if else blocks without spaces", "if exist x (choco install a)else(choco install b)\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"multi-line if else blocks", "if exist x (\r\n  choco install a\r\n) else (\r\n  choco install b\r\n)\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"nested blocks", "if exist x (if exist y (choco install a) else (choco install b))\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"nested multi-line blocks", "if exist x (\r\n  if exist y (\r\n    choco install a\r\n  )\r\n  echo done (ok^)\r\n  choco install b\r\n)\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"closing parenthesis inside a block ends it", "if exist x (\r\n  echo Installing (x86)\r\n  choco install a\r\n)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"tolerated for do block without a space", "for %%i in (1) do(choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"tolerated for set without a space", "for %%i in(1 2) do choco install a\r\n", "", "a@[unpinned]"},
		{"multi-line for set", "for %%i in (\r\n  1 2\r\n) do choco install a\r\n", "", "a@[unpinned]"},
		{"unbalanced closing parenthesis is text", "echo done) & choco install b\r\n", "b@[unpinned]", "b@[unpinned]"},
		{"unbalanced closing parenthesis at a command start", ") choco install a\r\n", "a@[unpinned]", ""},
		{"unbalanced do at a command start", ") do choco install a\r\n", "", ""},
		{"parenthesis after a separator", "choco install a & echo (x)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"block after a separator", "choco install a & (choco install b)\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"block after a redirection", ">nul (choco install a)\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"parenthesized if operands", "if (%1)==() choco install a\r\n", "a@[unpinned]", "a@[unpinned]"},
		{"escaped-quote group with parentheses", "choco install a --params ^\"/InstallDir:C:\\Program Files (x86)\\x^\" b\r\n", "a@[unpinned] b@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"redirection target with parentheses", "choco install a >out(1).log b\r\n", "a@[unpinned]", "a@[unpinned] b@[unpinned]"},
		{"block closes a redirection target", "(choco install a >nul)\r\n", "a@[unpinned]", "a@[unpinned]"},
	})
}

// TestParseScriptLongShellSyntaxIsLinear guards the lookahead added for
// redirection targets, percent expansions, braced variables, and `for` / `if`
// headers: a single logical line near the 1 MiB size bound that repeats one of
// these constructs without ever closing it must finish quickly in both
// dialects instead of rescanning the rest of the line for every repetition.
// The same holds for batch block parentheses, opened or left as text, and for
// a batch `if` whose long operand is followed by many caret-escaped blanks:
// the tokenizer asks at every escaped blank whether the condition is complete
// and must not rescan the operand to answer. A linear parse of one such line
// takes a few seconds at most, even under -race with every subtest running in
// parallel; a quadratic one takes minutes to hours, so linearParseDeadline
// leaves ample room for a loaded machine and still fails such a regression
// instead of hanging until the test binary's own timeout.
func TestParseScriptLongShellSyntaxIsLinear(t *testing.T) {
	t.Parallel()

	const linearParseDeadline = 2 * time.Minute
	scripts := map[string]string{}
	for _, unit := range []string{
		"%a ", "%", "${", "${ x", "for ", "if ", "if not ", "> ", ">", "2>&", "^\"a ", "do ", ") do ", "\"a==\" ",
		"(", ")", "( ", ") ", "(a ", "a) ", "if exist x (", ") else (", "@(", "for %%i in (", "^\"(a ", ">x(",
	} {
		scripts[unit] = "choco install a " + strings.Repeat(unit, 1<<20/len(unit))
	}
	// The `if` stands in command position here, so its condition stays open
	// across all the escaped blanks that follow the long operand. Splitting
	// the 1 MiB bound evenly between both maximizes the work of a parser that
	// rescans the operand at every escaped blank.
	operand := strings.Repeat("a", 1<<19)
	escapedBlanks := strings.Repeat("x^ ", (1<<20-len(operand))/len("x^ "))
	scripts["if operand then escaped blanks"] = "if " + operand + " " + escapedBlanks
	scripts["if comparison then escaped blanks"] = "if " + operand + " == " + escapedBlanks
	scripts["if case-insensitive not operand then escaped blanks"] = "if /i not " + operand + " " + escapedBlanks
	for name, body := range scripts {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			script := body + "\r\n"
			for _, kind := range []Kind{KindPowerShellScript, KindBatchScript} {
				done := make(chan error, 1)
				go func() {
					_, err := ParseScript(strings.NewReader(script), "x", kind)
					done <- err
				}()
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("ParseScript(%s) error = %v", kind, err)
					}
				case <-time.After(linearParseDeadline):
					t.Fatalf("ParseScript(%s) did not finish within %s", kind, linearParseDeadline)
				}
			}
		})
	}
}
