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
// KindPowerShellScript (.ps1, .psm1) joins backtick line continuations (a
// backtick inside a `#` or `<# ... #>` comment is comment text) and skips `#`
// comments, `<# ... #>` block comments, and here-strings; KindBatchScript
// (.bat, .cmd) joins caret line continuations and skips `REM` and `::`
// comment lines. Any other kind is an error. UTF-8/UTF-16 byte-order marks
// and CRLF line endings are tolerated.
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
	if body, ok := continuationBody(line, s.continuationMarker()); ok && s.continues(line) {
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

// continuationMarker is the line-continuation character of the script's
// language: a backtick in PowerShell, a caret in batch files.
func (s *scriptScanner) continuationMarker() byte {
	if s.powerShell() {
		return '`'
	}
	return '^'
}

// continuationBody reports whether line ends with the continuation marker
// and returns the line without it.
func continuationBody(line string, marker byte) (string, bool) {
	trimmed := strings.TrimRight(line, " \t")
	if trimmed == "" || trimmed[len(trimmed)-1] != marker {
		return "", false
	}
	return trimmed[:len(trimmed)-1], true
}

// continues reports whether the continuation marker that ends line is code
// rather than comment text, and in PowerShell records the quote the line
// leaves open for the next physical line. A PowerShell backtick inside a `#`
// line comment or a `<# ... #>` block comment is comment text. Batch files
// have neither comment form, so a batch caret always continues.
func (s *scriptScanner) continues(line string) bool {
	if !s.powerShell() {
		return true
	}
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
	for i := 0; i < len(line); i++ {
		ch := line[i]
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
		} else if strings.HasPrefix(trimmed, "::") || isBatchRem(strings.ToLower(trimmed)) {
			return nil
		}
	}
	tokens := s.tokenize(line)
	return parseChocoTokens(tokens)
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

// scriptToken is one token of a logical script line. quoted records that
// some of its text came from inside single or double quotes: quoted text is
// always an argument, so a quoted `;` or `|` never separates commands.
type scriptToken struct {
	text   string
	quoted bool
}

func (t scriptToken) isSeparator() bool {
	if t.quoted {
		return false
	}
	switch t.text {
	case ";", "|", "&", "(", ")", "{", "}", "&&", "||", "<", ">", "=":
		return true
	}
	return false
}

// parseChocoTokens walks a tokenized logical line and extracts package IDs
// from every choco install/upgrade command it contains. The choco verb must
// be in command position (start of line, right after a command separator or
// redirection, or after a wrapper such as `call`) so text inside strings such
// as `Write-Host "run choco install x"` is ignored.
func parseChocoTokens(tokens []scriptToken) []installEntry {
	var entries []installEntry
	commandPosition := true
	for i := 0; i < len(tokens); i++ {
		if tokens[i].isSeparator() {
			commandPosition = true
			continue
		}
		if !commandPosition {
			continue
		}
		if commandPrefixes[strings.ToLower(strings.TrimPrefix(tokens[i].text, "@"))] {
			continue
		}
		commandPosition = false
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
				option, value, hasValue := splitOption(token)
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
// option tokens into (name, value, hasValue).
func splitOption(token string) (string, string, bool) {
	name := strings.TrimLeft(token, "-/")
	if idx := strings.IndexAny(name, "=:"); idx >= 0 {
		return strings.ToLower(name[:idx]), strings.Trim(name[idx+1:], `"'`), true
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

// tokenize splits a shell/PowerShell line into tokens: whitespace separates,
// single/double quotes group (quotes removed, the token marked quoted), the
// unquoted characters ; | & ( ) { } < > become standalone separator tokens
// (stream selectors such as `2>` are dropped). In PowerShell only, an unquoted
// `#` at token start starts a comment that ends the line, `<# ... #>` block
// comments are skipped (possibly across lines), and a trailing `@"` / `@'`
// opens a here-string that suppresses following lines until the matching
// `"@` / `'@` terminator.
func (s *scriptScanner) tokenize(line string) []scriptToken {
	var tokens []scriptToken
	var current strings.Builder
	quoted := false
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, scriptToken{text: current.String(), quoted: quoted})
			current.Reset()
		}
		quoted = false
	}
	quote := byte(0)
	powerShell := s.powerShell()
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
		case powerShell && ch == '@' && current.Len() == 0 && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\'') &&
			strings.TrimSpace(line[i+2:]) == "":
			s.hereString = line[i+1]
			flush()
			return tokens
		case powerShell && ch == '#' && current.Len() == 0:
			flush()
			return tokens
		case powerShell && ch == '<' && i+1 < len(line) && line[i+1] == '#':
			flush()
			s.inBlockComment = true
			i++
		case ch == ' ' || ch == '\t' || ch == '\r':
			flush()
		case ch == '<' || ch == '>':
			if !quoted && isRedirectPrefix(current.String()) {
				current.Reset()
			}
			flush()
			tokens = append(tokens, scriptToken{text: string(ch)})
		case ch == ';' || ch == '|' || ch == '&' || ch == '(' || ch == ')' || ch == '{' || ch == '}':
			flush()
			tokens = append(tokens, scriptToken{text: string(ch)})
		default:
			current.WriteByte(ch)
		}
	}
	flush()
	return tokens
}
