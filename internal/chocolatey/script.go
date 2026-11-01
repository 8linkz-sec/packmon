package chocolatey

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ParseScript scans a Windows script (PowerShell, batch) line by line for
// `choco install|upgrade` / `cinst` / `cup` invocations and returns the
// package IDs (and `--version` pins) they name. kind selects the language:
// KindPowerShellScript (.ps1, .psm1) groups single- and double-quoted text,
// joins backtick line continuations (a backtick inside a `#` or `<# ... #>`
// comment is comment text) and skips `#` comments, `<# ... #>` block
// comments, and here-strings; KindBatchScript (.bat, .cmd) follows cmd.exe:
// only double quotes group, an unquoted caret makes the next character
// literal, a caret that ends the line joins the next line, only `&`, `|`, and
// block parentheses separate commands (a `(` opens a block only where a
// command starts, a `)` closes one only while a block is open, possibly from
// an earlier line, and any other parenthesis is argument text), `for ... in
// (...) do`, `if <condition>`, and `else` hand command position on, and `REM`
// and `::` comment lines are skipped. In both languages a redirection and its
// target are removed from wherever they stand without ending the command. Any
// other kind is an error. UTF-8/UTF-16 byte-order marks and CRLF line endings
// are tolerated.
//
// Not modeled: variables are never resolved (a `for` loop variable or `$p`
// names no package), delayed `!name!` expansion, `%name%` values that hold
// parentheses closing an enclosing block, cmd.exe ignoring the rest of a line
// after a `)` that starts a command outside any block (such a `)` is read as
// an ordinary command word), PowerShell backtick escapes inside a line, and
// choco.exe's backslash-quote argument rules.
func ParseScript(r io.Reader, sourceFile string, kind Kind) ([]Package, error) {
	if kind != KindPowerShellScript && kind != KindBatchScript {
		return nil, fmt.Errorf("%s: unsupported chocolatey script kind %q", sourceFile, kind)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	text := decodeTextBytes(data)

	var packages []Package
	add := func(entries []installEntry) {
		for _, entry := range entries {
			pkg := Package{
				Name:       entry.name,
				Version:    entry.version,
				SourceFile: sourceFile,
				SourceType: SourceChocoInstall,
			}
			if pkg.Version == "" {
				pkg.Flags = []string{FlagUnpinned}
			}
			packages = append(packages, pkg)
		}
	}
	scanner := scriptScanner{kind: kind}
	for _, line := range strings.Split(text, "\n") {
		add(scanner.feed(line))
	}
	add(scanner.flush())
	return packages, nil
}

// decodeTextBytes converts UTF-16 (BOM-marked) text bytes to a Go string,
// strips a UTF-8 BOM, and replaces invalid UTF-8 sequences so downstream
// parsers only ever see valid UTF-8.
func decodeTextBytes(data []byte) string {
	switch {
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		return decodeUTF16(data[2:], false)
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		return decodeUTF16(data[2:], true)
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if !utf8.Valid(data) {
		return string(bytes.ToValidUTF8(data, []byte("?")))
	}
	return string(data)
}

func decodeUTF16(data []byte, bigEndian bool) string {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		if bigEndian {
			units = append(units, uint16(data[i])<<8|uint16(data[i+1]))
		} else {
			units = append(units, uint16(data[i+1])<<8|uint16(data[i]))
		}
	}
	return string(utf16.Decode(units))
}

type installEntry struct {
	name    string
	version string
}

// scriptScanner carries the multi-line state needed to read a script one
// physical line at a time: pending line continuations, an open PowerShell
// here-string, and an open `<# ... #>` block comment.
type scriptScanner struct {
	kind           Kind // KindPowerShellScript or KindBatchScript
	pending        strings.Builder
	hasPending     bool
	pendingQuote   byte // quote left open by the pending continuation, else 0
	hereString     byte // '"' or '\'' while inside a here-string, else 0
	inBlockComment bool
	// pendingComment records that the batch logical line being read is a
	// `REM` or `::` comment line. Its first physical line decides: that line
	// keeps its trailing caret, so text appended after the caret can never
	// turn a command into a comment or back.
	pendingComment bool
	// blockDepth counts the batch blocks (and `for` sets) opened by a `(` and
	// not yet closed by a `)`, so a block that spans lines keeps its
	// parentheses balanced (see tokenizeBatch).
	blockDepth int
}

// feed consumes one physical line and returns the install entries of any
// logical line it completes.
func (s *scriptScanner) feed(rawLine string) []installEntry {
	line := strings.TrimRight(rawLine, "\r")
	if s.hereString != 0 {
		trimmed := strings.TrimLeft(line, " \t")
		if len(trimmed) >= 2 && trimmed[0] == s.hereString && trimmed[1] == '@' {
			s.hereString = 0
		}
		return nil
	}
	if !s.powerShell() {
		return s.feedBatch(line)
	}
	if body, ok := continuationBody(line, '`'); ok && s.continues(line) {
		s.pending.WriteString(body)
		s.pending.WriteByte(' ')
		s.hasPending = true
		return nil
	}
	if s.hasPending {
		s.pending.WriteString(line)
		line = s.pending.String()
		s.pending.Reset()
		s.hasPending = false
		s.pendingQuote = 0
	}
	return s.parseLine(line)
}

// flush completes a dangling continuation at end of input.
func (s *scriptScanner) flush() []installEntry {
	if !s.hasPending {
		return nil
	}
	line := s.pending.String()
	s.pending.Reset()
	s.hasPending = false
	s.pendingQuote = 0
	return s.parseLine(line)
}

// powerShell reports whether the scanner reads PowerShell syntax; otherwise
// it reads cmd.exe batch syntax.
func (s *scriptScanner) powerShell() bool {
	return s.kind == KindPowerShellScript
}

// feedBatch is feed for batch files. A batch continuation keeps the whole
// physical line, caret included, and the next line is appended without a
// separator: cmd.exe joins the lines directly and treats the first character
// of the appended line as escaped, which is exactly what tokenizeBatch does
// with the kept caret. A caret at end of input escapes nothing and is
// ignored.
func (s *scriptScanner) feedBatch(line string) []installEntry {
	if !s.hasPending {
		s.pendingComment = isBatchComment(line)
	}
	if s.batchContinues(line) {
		s.pending.WriteString(line)
		s.hasPending = true
		return nil
	}
	if s.hasPending {
		s.pending.WriteString(line)
		line = s.pending.String()
		s.pending.Reset()
		s.hasPending = false
	}
	return s.parseLine(line)
}

// batchContinues reports whether the physical batch line ends with a caret
// continuation. On `REM` and `::` comment lines a trailing caret, even one
// followed by spaces, keeps continuing the comment onto the next line: cmd.exe
// parses comment lines with special rules that are not modelled here, so they
// keep the previous behavior. On any other line only a caret that is the very
// last character, outside double quotes and not itself escaped, continues.
func (s *scriptScanner) batchContinues(line string) bool {
	if s.pendingComment {
		_, ok := continuationBody(line, '^')
		return ok
	}
	return batchLineContinues(line, s.hasPending)
}

// batchLineContinues applies tokenizeBatch's quote and escape rules to one
// physical batch line and reports whether it ends with an unquoted, unescaped
// caret. escaped reports that the line's first character is escaped by the
// previous line's continuation. A double quote cannot stay open across a
// continuation, because a caret inside double quotes is literal.
func batchLineContinues(line string, escaped bool) bool {
	inQuote := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case escaped:
			escaped = false
		case inQuote:
			if ch == '"' {
				inQuote = false
			}
		case ch == '"':
			inQuote = true
		case ch == '^':
			if i == len(line)-1 {
				return true
			}
			escaped = true
		}
	}
	return false
}

// continuationBody reports whether line ends with the continuation marker,
// ignoring trailing spaces and tabs, and returns the line without it.
func continuationBody(line string, marker byte) (string, bool) {
	trimmed := strings.TrimRight(line, " \t")
	if trimmed == "" || trimmed[len(trimmed)-1] != marker {
		return "", false
	}
	return trimmed[:len(trimmed)-1], true
}

// continues reports whether the PowerShell backtick that ends line is code
// rather than comment text, and records the quote the line leaves open for
// the next physical line. A backtick inside a `#` line comment or a
// `<# ... #>` block comment is comment text.
func (s *scriptScanner) continues(line string) bool {
	// A pending continuation never ends inside a block comment, so the block
	// comment state only carries over into the first physical line.
	inBlock := s.inBlockComment && !s.hasPending
	quote, lineComment, blockComment := lineEndState(line, s.pendingQuote, inBlock)
	if lineComment || blockComment {
		return false
	}
	s.pendingQuote = quote
	return true
}

// lineEndState applies tokenize's quote and comment rules to one physical
// line that starts inside quote (0 for none) and, if inBlock, inside a
// `<# ... #>` block comment. It reports the quote still open at the end of the
// line and whether the line ends inside a `#` line comment or a block comment.
func lineEndState(line string, quote byte, inBlock bool) (byte, bool, bool) {
	inToken := quote != 0
	lastBrace := strings.LastIndexByte(line, '}')
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if !inBlock && quote == 0 {
			if end := bracedVariableEnd(line, i, lastBrace); end > 0 {
				i = end - 1
				inToken = true
				continue
			}
		}
		switch {
		case inBlock:
			if ch == '#' && i+1 < len(line) && line[i+1] == '>' {
				inBlock = false
				i++
			}
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				inToken = true
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '#' && !inToken:
			return 0, true, false
		case ch == '<' && i+1 < len(line) && line[i+1] == '#':
			inBlock = true
			inToken = false
			i++
		case strings.IndexByte(" \t\r<>;|&(){}", ch) >= 0:
			inToken = false
		default:
			inToken = true
		}
	}
	return quote, false, inBlock
}

// parseLine skips whole-line comments of the script's language (`#` in
// PowerShell, `REM` and `::` in batch files) and extracts the install entries
// of any other logical line.
func (s *scriptScanner) parseLine(line string) []installEntry {
	if !s.inBlockComment {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return nil
		}
		if s.powerShell() {
			if strings.HasPrefix(trimmed, "#") {
				return nil
			}
		} else if isBatchComment(trimmed) {
			return nil
		}
	}
	if !s.powerShell() {
		return parseChocoTokens(tokenizeBatch(line, &s.blockDepth), true)
	}
	return parseChocoTokens(s.tokenize(line), false)
}

// isBatchComment reports whether a batch line is a `REM` or `::` comment line.
func isBatchComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "::") || isBatchRem(strings.ToLower(trimmed))
}

func isBatchRem(lower string) bool {
	lower = strings.TrimPrefix(lower, "@")
	return lower == "rem" || strings.HasPrefix(lower, "rem ") || strings.HasPrefix(lower, "rem\t")
}

// parseChocoInstallLine extracts package IDs from `choco install|upgrade`,
// `cinst`, and `cup` invocations on one self-contained script line. It is the
// stateless entry point used when no multi-line context is available.
func parseChocoInstallLine(kind Kind, line string) []installEntry {
	s := scriptScanner{kind: kind}
	return s.parseLine(line)
}

// chocoOptionsWithValue lists choco options whose value is the next token
// when not written as --option=value; those tokens must never be read as
// package IDs.
var chocoOptionsWithValue = map[string]bool{
	"version": true, "s": true, "source": true,
	"params": true, "parameters": true, "pkgparameters": true, "packageparameters": true,
	"package-parameters": true, "package-parameters-sensitive": true,
	"p": true, "ia": true, "installargs": true, "installarguments": true, "install-args": true,
	"install-arguments": true, "install-arguments-sensitive": true,
	"checksum": true, "checksum64": true, "checksum-type": true, "checksumtype": true,
	"checksum-type64": true, "checksumtype64": true,
	"u": true, "user": true, "password": true, "cert": true, "certpassword": true,
	"c": true, "cache": true, "cache-location": true, "cachelocation": true,
	"proxy": true, "proxy-user": true, "proxy-password": true, "proxy-bypass-list": true,
	"t": true, "timeout": true, "execution-timeout": true,
	"download-checksum": true, "download-checksum64": true,
	"download-checksum-type": true, "download-checksum-type64": true,
	"log-file": true, "pin-reason": true, "pinreason": true, "except": true,
	"arch": true, "architecture": true, "output-directory": true, "od": true, "outputdirectory": true,
}

// commandPrefixes are wrapper words that may precede the choco executable
// while leaving it in command position.
var commandPrefixes = map[string]bool{"call": true, "sudo": true}

// scriptToken is one token of a logical script line. literal records that
// the token is argument text that never separates commands: in PowerShell a
// token with quoted text, so a quoted `;` or `|` is an argument; in batch
// files every word token, because tokenizeBatch alone recognizes the cmd.exe
// separators and so `;`, `{`, `}`, `=` and any quoted or caret-escaped text
// stay argument text. raw is the source text of a batch word, quotes and
// carets included, which tells an unquoted `==` in an `if` condition from a
// quoted one; PowerShell tokens leave it empty.
type scriptToken struct {
	text    string
	literal bool
	raw     string
}

func (t scriptToken) isSeparator() bool {
	if t.literal {
		return false
	}
	switch t.text {
	case ";", "|", "&", "(", ")", "{", "}", "&&", "||", "=":
		return true
	}
	return false
}

// commandTracker follows command position through the tokens of one logical
// line, one token at a time. parseChocoTokens reads the finished tokens with
// it, and tokenizeBatch runs its own copy over the tokens it has emitted so
// far to decide whether a `(` opens a block; both see the same tokens in the
// same order, so they always agree.
type commandTracker struct {
	batch bool
	// command reports that the next word stands in command position: at the
	// start of the line, after a command separator, or after a wrapper such
	// as `call`.
	command bool
	// forHeader is set while reading a batch `for` header (`for %%i in
	// (set)`), whose words are loop syntax and data rather than commands. Its
	// `do` hands command position to the loop body; `&` or `|` ends a header
	// that has none. forSet records that the header's set has been opened.
	forHeader bool
	forSet    bool
	// ifStart is the index of the batch `if` whose condition is being read,
	// else -1. ifComplete caches whether that condition has all its words
	// after the tokens consumed so far, as batchIfCommandStart reports it. It
	// is computed once per consumed token, never per character, because the
	// tokenizer asks for it at every `(` and escaped blank and rescanning a
	// long operand each time would make a line quadratic.
	ifStart    int
	ifComplete bool
}

func newCommandTracker(batch bool) commandTracker {
	return commandTracker{batch: batch, command: true, ifStart: -1}
}

// next consumes tokens[i], the token after those already consumed (tokens
// past i are never read), and reports whether it is a word in command
// position, the only place a choco verb counts. batch selects the cmd.exe
// rules: a `for` header up to its `) do`, the condition of an `if`, and an
// `else` or `do` right after a closing parenthesis all hand command position
// on, and a bare `@` echo-suppression prefix keeps it.
func (c *commandTracker) next(tokens []scriptToken, i int) bool {
	token := tokens[i]
	if c.forHeader {
		switch {
		case token.isSeparator() && (token.text == "&" || token.text == "|"), isBatchKeywordAfterParen(tokens, i, "do"):
			c.forHeader = false
			c.command = true
		case token.isSeparator() && token.text == "(":
			c.forSet = true
		}
		return false
	}
	if token.isSeparator() {
		c.command = true
		c.ifStart, c.ifComplete = -1, false
		return false
	}
	if c.ifStart >= 0 {
		if end, complete := batchIfCommandStart(tokens[:i+1], c.ifStart); end > i {
			c.ifComplete = complete
			return false
		}
		// tokens[i] is the command the `if` runs.
		c.ifStart, c.ifComplete = -1, false
	}
	if !c.command {
		return false
	}
	word := strings.ToLower(strings.TrimPrefix(token.text, "@"))
	if commandPrefixes[word] {
		return false
	}
	if c.batch {
		switch {
		case token.text == "@", isBatchKeywordAfterParen(tokens, i, "do"), isBatchKeywordAfterParen(tokens, i, "else"):
			return false
		case word == "for":
			c.forHeader, c.forSet = true, false
			return false
		case word == "if":
			// A bare `if` has no condition words yet.
			c.ifStart, c.ifComplete = i, false
			return false
		}
	}
	c.command = false
	return true
}

// opensBlock reports whether a batch `(` that starts a word right after the
// tokens the tracker has consumed opens a block: cmd.exe reads it so
// only where the next command starts (after an `if` condition that is
// complete) or as the set of a `for` header. Anywhere else it is argument
// text, so `echo Installing (x86)` and `if (%1)==()` open nothing.
func (c *commandTracker) opensBlock() bool {
	switch {
	case c.forHeader:
		return !c.forSet
	case c.ifStart >= 0:
		return c.ifComplete
	}
	return c.command
}

// readsIfCondition reports whether the word that follows the tokens the
// tracker has consumed still belongs to the condition of a batch `if`,
// because the condition is not complete yet.
func (c *commandTracker) readsIfCondition() bool {
	return c.ifStart >= 0 && !c.ifComplete
}

// parseChocoTokens walks a tokenized logical line and extracts package IDs
// from every choco install/upgrade command it contains. The choco verb must
// be in command position (see commandTracker) so text inside strings such as
// `Write-Host "run choco install x"` is ignored. The tokenizers have already
// removed redirections with their targets, so a redirection is transparent
// here. batch selects the cmd.exe rules: command position follows the batch
// `for`, `if`, `else` and `do` syntax, and only double quotes are stripped
// from `--option=value` values, because cmd.exe hands single quotes to
// choco.exe unchanged (only double quotes group on a Windows command line,
// so `--version='1.0'` carries the value `'1.0'`, which is not a version
// literal; see splitOption).
func parseChocoTokens(tokens []scriptToken, batch bool) []installEntry {
	valueQuotes := `"'`
	if batch {
		valueQuotes = `"`
	}
	var entries []installEntry
	tracker := newCommandTracker(batch)
	for i := 0; i < len(tokens); i++ {
		if !tracker.next(tokens, i) {
			continue
		}
		argStart, ok := chocoCommandArgStart(tokens, i)
		if !ok {
			continue
		}
		var ids []string
		version := ""
		j := argStart
		for ; j < len(tokens); j++ {
			if tokens[j].isSeparator() {
				break
			}
			token := tokens[j].text
			if isOptionToken(token) {
				option, value, hasValue := splitOption(token, valueQuotes)
				if !hasValue && chocoOptionsWithValue[option] && j+1 < len(tokens) && !tokens[j+1].isSeparator() {
					j++
					value = tokens[j].text
					hasValue = true
				}
				if option == "version" && hasValue {
					version = normalizeVersion(value)
				}
				continue
			}
			if id, ok := normalizePackageID(token); ok {
				ids = append(ids, id)
			}
		}
		for _, id := range ids {
			entries = append(entries, installEntry{name: id, version: version})
		}
		i = j - 1
	}
	return entries
}

// versionPattern accepts NuGet/SemVer style version literals; anything else
// (variables, placeholders, prose) is treated as unpinned.
var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]*$`)

func normalizeVersion(raw string) string {
	version := strings.TrimSpace(raw)
	if version == "" || len(version) > 64 || !versionPattern.MatchString(version) {
		return ""
	}
	return version
}

func isOptionToken(token string) bool {
	return strings.HasPrefix(token, "-") || strings.HasPrefix(token, "/")
}

// chocoCommandArgStart reports the index of the first argument after a choco
// install/upgrade verb starting at tokens[i], if tokens[i] begins one. The
// executable may be written with a path (`C:\...\bin\choco.exe`), an `.exe`
// suffix, or a batch `@` echo-suppression prefix.
func chocoCommandArgStart(tokens []scriptToken, i int) (int, bool) {
	switch commandName(tokens[i].text) {
	case "choco":
		if i+1 >= len(tokens) {
			return 0, false
		}
		switch strings.ToLower(tokens[i+1].text) {
		case "install", "upgrade":
			return i + 2, true
		}
		return 0, false
	case "cinst", "cup":
		return i + 1, true
	}
	return 0, false
}

// commandName reduces an executable token to its lowercase base name
// without a `.exe` suffix or a leading batch `@`.
func commandName(token string) string {
	name := strings.TrimPrefix(token, "@")
	if idx := strings.LastIndexAny(name, `\/`); idx >= 0 {
		name = name[idx+1:]
	}
	name = strings.ToLower(name)
	return strings.TrimSuffix(name, ".exe")
}

// splitOption normalizes `--version=1.2`, `--version:1.2`, `-y`, `/y` style
// option tokens into (name, value, hasValue). Leading and trailing
// valueQuotes characters are stripped from the value: `"'` in PowerShell,
// only `"` in batch files.
func splitOption(token, valueQuotes string) (string, string, bool) {
	name := strings.TrimLeft(token, "-/")
	if idx := strings.IndexAny(name, "=:"); idx >= 0 {
		return strings.ToLower(name[:idx]), strings.Trim(name[idx+1:], valueQuotes), true
	}
	return strings.ToLower(name), "", false
}

// isRedirectPrefix reports whether a token that directly precedes `<` or `>`
// is a stream selector (`2>&1`, `*>`) rather than an argument.
func isRedirectPrefix(token string) bool {
	if token == "*" {
		return true
	}
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return false
		}
	}
	return true
}

func isBlank(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r'
}

// redirectionOperatorEnd returns the index just past the redirection
// operator (`<`, `>`, or `>>`) at line[i] and reports whether the operator
// duplicates a stream onto another (`>&1`, as in `2>&1`), which takes no
// target. A stream selector before the operator (`2`, `*`) is the caller's.
func redirectionOperatorEnd(line string, i int) (int, bool) {
	if line[i] == '>' && i+1 < len(line) && line[i+1] == '>' {
		i++
	}
	i++
	if i+1 < len(line) && line[i] == '&' && line[i+1] >= '0' && line[i+1] <= '9' {
		return i + 2, true
	}
	return i, false
}

// powerShellRedirectionEnd returns the index just past the PowerShell
// redirection that starts at line[i]: its operator and, unless it duplicates
// a stream, its target. The target may follow after blanks, single and double
// quotes group it, a `${name}` variable is part of it (lastBrace as for
// bracedVariableEnd), and it ends at the next unquoted blank or separator
// character. A `#` comment or `@"` / `@'` here-string opener where the target
// would start is left to the caller, matching lineEndState.
func powerShellRedirectionEnd(line string, i, lastBrace int) int {
	i, dup := redirectionOperatorEnd(line, i)
	if dup {
		return i
	}
	for i < len(line) && isBlank(line[i]) {
		i++
	}
	if i < len(line) && (line[i] == '#' || line[i] == '@' && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\'')) {
		return i
	}
	quote := byte(0)
	for ; i < len(line); i++ {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case isBlank(ch) || strings.IndexByte("<>;|&(){}", ch) >= 0:
			return i
		default:
			if end := bracedVariableEnd(line, i, lastBrace); end > 0 {
				i = end - 1
			}
		}
	}
	return len(line)
}

// bracedVariableEnd returns the index just past the `}` that closes the
// PowerShell `${name}` variable starting at line[i], or -1 if line[i] does
// not start one. lastBrace is the index of the last `}` in line, so an
// unclosed `${` costs no search and the scan stays linear.
func bracedVariableEnd(line string, i, lastBrace int) int {
	if line[i] != '$' || i+1 >= len(line) || line[i+1] != '{' || lastBrace <= i+1 {
		return -1
	}
	return i + 3 + strings.IndexByte(line[i+2:], '}')
}

// tokenize splits a PowerShell line into tokens: whitespace separates,
// single/double quotes group (quotes removed, the token marked literal), a
// `${name}` variable is one word, the unquoted characters ; | & ( ) { }
// become standalone separator tokens, a redirection (`>`, `>>`, `<`, with a
// stream selector such as `2` or `*`, a duplication such as `2>&1`, and its
// target) is removed without separating anything, an unquoted `#` at token
// start starts a comment that ends the line, `<# ... #>` block comments are
// skipped (possibly across lines), and a trailing `@"` / `@'` opens a
// here-string that suppresses following lines until the matching `"@` / `'@`
// terminator.
func (s *scriptScanner) tokenize(line string) []scriptToken {
	var tokens []scriptToken
	var current strings.Builder
	quoted := false
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, scriptToken{text: current.String(), literal: quoted})
			current.Reset()
		}
		quoted = false
	}
	quote := byte(0)
	lastBrace := strings.LastIndexByte(line, '}')
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case s.inBlockComment:
			if ch == '#' && i+1 < len(line) && line[i+1] == '>' {
				s.inBlockComment = false
				i++
			}
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				current.WriteByte(ch)
			}
		case ch == '"' || ch == '\'':
			quote = ch
			quoted = true
		case ch == '@' && current.Len() == 0 && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\'') &&
			strings.TrimSpace(line[i+2:]) == "":
			s.hereString = line[i+1]
			flush()
			return tokens
		case ch == '#' && current.Len() == 0:
			flush()
			return tokens
		case ch == '<' && i+1 < len(line) && line[i+1] == '#':
			flush()
			s.inBlockComment = true
			i++
		case isBlank(ch):
			flush()
		case ch == '<' || ch == '>':
			if !quoted && isRedirectPrefix(current.String()) {
				current.Reset()
			}
			flush()
			i = powerShellRedirectionEnd(line, i, lastBrace) - 1
		case ch == ';' || ch == '|' || ch == '&' || ch == '(' || ch == ')' || ch == '{' || ch == '}':
			flush()
			tokens = append(tokens, scriptToken{text: string(ch)})
		default:
			if end := bracedVariableEnd(line, i, lastBrace); end > 0 {
				current.WriteString(line[i:end])
				i = end - 1
				continue
			}
			current.WriteByte(ch)
		}
	}
	flush()
	return tokens
}

// tokenizeBatch splits a batch logical line into tokens with cmd.exe quoting
// and escaping rules: whitespace separates; only double quotes group (quotes
// removed), and inside them every character, including a caret, is literal; a
// single quote is ordinary text. An unquoted caret is removed and makes the
// next character literal, so `^&`, `^|`, `^<` and `^>` are argument text and
// `^^` is a literal caret; an escaped space or tab still separates arguments,
// because the invoked program splits its command line on it, except inside
// an `if` condition, which cmd.exe reads itself: there it stays part of the
// operand, so `if exist C:\Program^ Files\Git (` tests one path. A caret with
// nothing after it escapes nothing. Only the unquoted, unescaped cmd.exe
// command separators & | (which also form && and ||) and the block
// parentheses ( ) become standalone separator tokens; `;`, `{`, `}` and `=`
// are ordinary text, and every word token is marked literal so its text can
// never read as a separator. A redirection (`>`, `>>`, `<`, with a handle
// such as `2`, a duplication such as `2>&1`, and its target) is removed
// without separating anything, as cmd.exe removes it before running the
// command. A `%name%` expansion is one word (see batchVariableEnd).
//
// Parentheses follow the cmd.exe block rules. A `(` opens a block (depth
// goes up) only where it starts a word in command position, which the
// tokenizer learns by running a commandTracker over the tokens it has
// emitted (see commandTracker.opensBlock); an `@`, `else`, `do`, or `for` set
// `in` written directly before the `(` is split off first, so `@(` opens one
// as in cmd.exe, and `)else(`, `do(`, and `in(`, which cmd.exe rejects as a
// syntax error, are tolerated and conservatively read as block openers too
// (see opensAfterWord). A `)` closes a block (depth goes down) wherever it
// stands while depth is above zero. Any other parenthesis is argument text,
// so `echo Installing (x86) choco install a` is one echo command and an
// unbalanced `)` at depth zero splits nothing. depth carries the open blocks
// from one logical line to the next.
//
// Word splitting follows the invoked program, which sees every double quote
// that reaches it: an escaped `^"` opens no cmd.exe quote, so `&` and `|`
// still separate commands after it, but it still groups words for choco.exe,
// so `--params ^"/x y^"` is one argument. argQuote tracks that grouping
// separately from the cmd.exe quote state and ends with the command at a
// separator. An empty `""` is an (empty) argument. Batch files have no inline
// comments, block comments, or here-strings.
func tokenizeBatch(line string, depth *int) []scriptToken {
	var tokens []scriptToken
	tracker := newCommandTracker(true)
	emit := func(token scriptToken) {
		tokens = append(tokens, token)
		tracker.next(tokens, len(tokens)-1)
	}
	var current strings.Builder
	quoted := false // the current word has quoted or escaped text
	start := -1     // index in line where the current word starts, else -1
	begin := func(at int) {
		if start < 0 {
			start = at
		}
	}
	flush := func(end int) {
		if current.Len() > 0 || quoted {
			emit(scriptToken{text: current.String(), literal: true, raw: line[start:end]})
			current.Reset()
		}
		quoted = false
		start = -1
	}
	inQuote := false  // inside a cmd.exe double quote
	argQuote := false // inside a double quote as choco.exe splits its arguments
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case ch == '"':
			begin(i)
			inQuote = !inQuote
			argQuote = !argQuote
			quoted = true
		case isBlank(ch) && !argQuote:
			flush(i)
		case inQuote || isBlank(ch):
			begin(i)
			current.WriteByte(ch)
		case ch == '^':
			if i+1 >= len(line) {
				continue
			}
			begin(i)
			i++
			switch next := line[i]; {
			case next == '"':
				argQuote = !argQuote
				quoted = true
			case isBlank(next) && !argQuote && !tracker.readsIfCondition():
				flush(i - 1)
			default:
				current.WriteByte(next)
				quoted = true
			}
		case ch == '%':
			begin(i)
			end := batchVariableEnd(line, i)
			current.WriteString(line[i:end])
			i = end - 1
		case ch == '<' || ch == '>':
			// Inside an escaped-quote group the redirection is removed from
			// the middle of the argument, which goes on after it.
			if !argQuote {
				if !quoted && isRedirectPrefix(current.String()) {
					current.Reset()
				}
				flush(i)
			}
			i = batchRedirectionEnd(line, i, *depth > 0) - 1
		case ch == '(' && start >= 0 && !quoted && opensAfterWord(current.String(), tokens, &tracker):
			flush(i)
			fallthrough
		case ch == '(' && start < 0 && tracker.opensBlock(), ch == ')' && *depth > 0:
			flush(i)
			argQuote = false
			if ch == '(' {
				*depth++
			} else {
				*depth--
			}
			emit(scriptToken{text: string(ch)})
		case ch == '|' || ch == '&':
			flush(i)
			argQuote = false
			emit(scriptToken{text: string(ch)})
		default:
			begin(i)
			current.WriteByte(ch)
		}
	}
	flush(len(line))
	return tokens
}

// opensAfterWord reports whether a batch `(` written directly after word, an
// unquoted word tokenizeBatch has not emitted yet, opens a block once the word
// is split off: an `@` echo-suppression prefix in command position (`@(`,
// which cmd.exe accepts), an `else` or `do` right after a closing block
// parenthesis (`)else(`, `do(`), or the `in` of a `for` header before its set
// (`in(`). cmd.exe rejects the last three with a syntax error; they are
// tolerated and read as block openers anyway, so a script written that way
// over-reports rather than hides its packages.
func opensAfterWord(word string, tokens []scriptToken, tracker *commandTracker) bool {
	afterParen := len(tokens) > 0 && tokens[len(tokens)-1].isSeparator() && tokens[len(tokens)-1].text == ")"
	switch {
	case word == "@":
		return tracker.opensBlock()
	case strings.EqualFold(word, "do"):
		return afterParen
	case strings.EqualFold(word, "else"):
		return afterParen && !tracker.forHeader
	case strings.EqualFold(word, "in"):
		return tracker.forHeader && !tracker.forSet
	}
	return false
}

// batchRedirectionEnd returns the index just past the batch redirection that
// starts at line[i]: its operator and, unless it duplicates a handle, its
// target. The target may follow after blanks and runs to the next blank or
// cmd.exe separator that is neither quoted nor caret-escaped; a `)` ends it
// only inBlock, while a block is open, and a `(` never does.
func batchRedirectionEnd(line string, i int, inBlock bool) int {
	i, dup := redirectionOperatorEnd(line, i)
	if dup {
		return i
	}
	for i < len(line) && isBlank(line[i]) {
		i++
	}
	inQuote := false
	for ; i < len(line); i++ {
		ch := line[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case inQuote:
		case ch == '^':
			i++
		case isBlank(ch) || strings.IndexByte("<>|&", ch) >= 0 || ch == ')' && inBlock:
			return i
		}
	}
	return len(line)
}

// batchVariableEnd returns the index just past the percent expression that
// starts at line[i]: a doubled `%%` (as in a `%%i` loop variable), or a whole
// `%name%` expansion whose name holds no blank, double quote, caret, `&`,
// `|`, `<`, or `>`. cmd.exe expands such a variable before it splits the
// line, so `%ProgramFiles(x86)%` is one word and its parentheses close no
// block. Any other percent sign, including a `%1` / `%~dp0` / `%*` argument
// reference, is a single ordinary character. Each search stops at the next
// percent sign, so a line is scanned in linear time.
func batchVariableEnd(line string, i int) int {
	if i+1 >= len(line) {
		return i + 1
	}
	switch next := line[i+1]; {
	case next == '%':
		return i + 2
	case next == '~' || next == '*' || next >= '0' && next <= '9':
		return i + 1
	}
	k := strings.IndexByte(line[i+1:], '%')
	if k < 0 || strings.ContainsAny(line[i+1:i+1+k], " \t\r\"^&|<>") {
		return i + 1
	}
	return i + k + 2
}

// isBatchKeywordAfterParen reports whether tokens[i] is the batch keyword
// (`do`, `else`) written directly after a closing block parenthesis, the only
// place where cmd.exe reads it as a keyword: `for ... in (set) do command`
// and `if ... (command) else command`.
func isBatchKeywordAfterParen(tokens []scriptToken, i int, keyword string) bool {
	return i > 0 && !tokens[i].isSeparator() && strings.EqualFold(tokens[i].text, keyword) &&
		tokens[i-1].isSeparator() && tokens[i-1].text == ")"
}

// batchIfConditions are the batch `if` conditions that take one operand.
var batchIfConditions = map[string]bool{"exist": true, "defined": true, "errorlevel": true, "cmdextversion": true}

// batchCompareOps are the extended batch `if` comparison operators.
var batchCompareOps = map[string]bool{"equ": true, "neq": true, "lss": true, "leq": true, "gtr": true, "geq": true}

// batchIfCommandStart returns the index of the command that the batch `if`
// at tokens[i] runs. It skips `/i`, `not`, and the condition: `exist`,
// `defined`, `errorlevel`, or `cmdextversion` with one operand, a
// `string1==string2` comparison written as one to three words, or a
// `string1 OP string2` comparison with an `EQU`-style operator. Keywords and
// `==` count only unquoted (they are read from the raw word), so
// `if "%1"=="" ...` is a whole comparison. A separator ends the condition
// early; a malformed condition hands command position to its second word.
// complete reports that the condition has all its words, so the next token
// is the command; it is false when tokens end (or a separator comes) first,
// which tells commandTracker.opensBlock that a `(` there is still part of the
// condition, as in `if (%1)==() ...`.
func batchIfCommandStart(tokens []scriptToken, i int) (end int, complete bool) {
	isWord := func(k int) bool { return k < len(tokens) && !tokens[k].isSeparator() }
	keyword := func(k int) string { return strings.ToLower(tokens[k].raw) }
	// operand returns the end of a condition whose last part, the operand
	// at k, is optional in the token list.
	operand := func(k int) (int, bool) {
		if isWord(k) {
			return k + 1, true
		}
		return k, false
	}
	j := i + 1
	if isWord(j) && keyword(j) == "/i" {
		j++
	}
	if isWord(j) && keyword(j) == "not" {
		j++
	}
	if !isWord(j) {
		return j, false
	}
	if batchIfConditions[keyword(j)] {
		return operand(j + 1)
	}
	if found, tail := unquotedEquals(tokens[j].raw); found {
		if tail {
			return j + 1, true
		}
		return operand(j + 1)
	}
	j++
	if !isWord(j) {
		return j, false
	}
	if found, tail := unquotedEquals(tokens[j].raw); found || batchCompareOps[keyword(j)] {
		if tail {
			return j + 1, true
		}
		return operand(j + 1)
	}
	return j, true
}

// unquotedEquals reports whether a raw batch word holds `==` outside double
// quotes and caret escapes, and whether any text follows the first one.
func unquotedEquals(raw string) (found, tail bool) {
	inQuote := false
	for k := 0; k < len(raw); k++ {
		switch {
		case raw[k] == '"':
			inQuote = !inQuote
		case inQuote:
		case raw[k] == '^':
			k++
		case raw[k] == '=' && k+1 < len(raw) && raw[k+1] == '=':
			return true, k+2 < len(raw)
		}
	}
	return false, false
}
