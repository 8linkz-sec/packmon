package chocolatey

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ParseScript scans a Windows script (PowerShell, batch) line by line for
// `choco install|upgrade` / `cinst` / `cup` invocations and returns the
// package IDs (and `--version` pins) they name. It tolerates UTF-8/UTF-16
// byte-order marks and CRLF line endings, joins backtick (PowerShell) and
// caret (batch) line continuations, and skips PowerShell here-strings and
// `<# ... #>` block comments.
func ParseScript(r io.Reader, sourceFile string) ([]Package, error) {
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
	var scanner scriptScanner
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
	pending        strings.Builder
	hasPending     bool
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
	if !s.inBlockComment {
		if body, ok := continuationBody(line); ok {
			s.pending.WriteString(body)
			s.pending.WriteByte(' ')
			s.hasPending = true
			return nil
		}
	}
	if s.hasPending {
		s.pending.WriteString(line)
		line = s.pending.String()
		s.pending.Reset()
		s.hasPending = false
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
	return s.parseLine(line)
}

// continuationBody reports whether line ends with a PowerShell backtick or
// batch caret continuation marker and returns the line without it.
func continuationBody(line string) (string, bool) {
	trimmed := strings.TrimRight(line, " \t")
	if trimmed == "" {
		return "", false
	}
	switch trimmed[len(trimmed)-1] {
	case '`', '^':
		return trimmed[:len(trimmed)-1], true
	}
	return "", false
}

func (s *scriptScanner) parseLine(line string) []installEntry {
	if !s.inBlockComment {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "::") ||
			isBatchRem(lower) {
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
func parseChocoInstallLine(line string) []installEntry {
	var s scriptScanner
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

func isSeparatorToken(token string) bool {
	switch token {
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
func parseChocoTokens(tokens []string) []installEntry {
	var entries []installEntry
	commandPosition := true
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if isSeparatorToken(token) {
			commandPosition = true
			continue
		}
		if !commandPosition {
			continue
		}
		if commandPrefixes[strings.ToLower(strings.TrimPrefix(token, "@"))] {
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
			token := tokens[j]
			if isSeparatorToken(token) {
				break
			}
			if isOptionToken(token) {
				option, value, hasValue := splitOption(token)
				if !hasValue && chocoOptionsWithValue[option] && j+1 < len(tokens) && !isSeparatorToken(tokens[j+1]) {
					j++
					value = tokens[j]
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
func chocoCommandArgStart(tokens []string, i int) (int, bool) {
	switch commandName(tokens[i]) {
	case "choco":
		if i+1 >= len(tokens) {
			return 0, false
		}
		switch strings.ToLower(tokens[i+1]) {
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
// single/double quotes group (quotes removed), the characters ; | & ( ) { }
// < > become standalone separator tokens (stream selectors such as `2>` are
// dropped), an unquoted `#` at token start starts a comment that ends the
// line, `<# ... #>` block comments are skipped (possibly across lines), and a
// trailing `@"` / `@'` opens a here-string that suppresses following lines
// until the matching `"@` / `'@` terminator.
func (s *scriptScanner) tokenize(line string) []string {
	var tokens []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	quote := byte(0)
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
		case ch == ' ' || ch == '\t' || ch == '\r':
			flush()
		case ch == '<' || ch == '>':
			if isRedirectPrefix(current.String()) {
				current.Reset()
			}
			flush()
			tokens = append(tokens, string(ch))
		case ch == ';' || ch == '|' || ch == '&' || ch == '(' || ch == ')' || ch == '{' || ch == '}':
			flush()
			tokens = append(tokens, string(ch))
		default:
			current.WriteByte(ch)
		}
	}
	flush()
	return tokens
}
