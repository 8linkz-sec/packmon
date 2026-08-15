package chocolatey

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ParseScript scans a Windows script (PowerShell, batch) line by line for
// `choco install|upgrade` / `cinst` / `cup` invocations and returns the
// package IDs (and `--version` pins) they name. It tolerates UTF-8/UTF-16
// byte-order marks and CRLF line endings.
func ParseScript(r io.Reader, sourceFile string) ([]Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	text := decodeScriptBytes(data)

	var packages []Package
	for _, line := range strings.Split(text, "\n") {
		for _, entry := range parseChocoInstallLine(line) {
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
	return packages, nil
}

// decodeScriptBytes converts UTF-16 (BOM-marked) script bytes to a Go string
// and strips a UTF-8 BOM; other content is returned as-is.
func decodeScriptBytes(data []byte) string {
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

// chocoOptionsWithValue lists choco options whose value is the next token
// when not written as --option=value; those tokens must never be read as
// package IDs.
var chocoOptionsWithValue = map[string]bool{
	"version": true, "s": true, "source": true, "params": true, "package-parameters": true,
	"p": true, "ia": true, "install-arguments": true, "installargs": true, "checksum": true,
	"checksum64": true, "checksum-type": true, "checksumtype": true, "checksum-type64": true,
	"u": true, "user": true, "password": true, "cert": true, "certpassword": true,
	"c": true, "cache-location": true, "cachelocation": true, "proxy": true, "proxy-user": true,
	"proxy-password": true, "proxy-bypass-list": true, "t": true, "timeout": true,
	"execution-timeout": true, "download-checksum": true, "download-checksum64": true,
	"download-checksum-type": true, "download-checksum-type64": true, "log-file": true,
	"pin-reason": true, "arch": true, "architecture": true, "output-directory": true,
	"od": true, "outputdirectory": true, "trace": true,
}

func isSeparatorToken(token string) bool {
	switch token {
	case ";", "|", "&", "(", ")", "{", "}", "&&", "||":
		return true
	}
	return false
}

// parseChocoInstallLine extracts package IDs from `choco install|upgrade`,
// `cinst`, and `cup` invocations on one script line. The choco verb must be in
// command position (start of line or right after a command separator) so
// text inside strings such as `Write-Host "run choco install x"` is ignored.
func parseChocoInstallLine(line string) []installEntry {
	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "::") ||
		lower == "rem" || strings.HasPrefix(lower, "rem ") {
		return nil
	}
	tokens := tokenizeScriptLine(trimmed)

	var entries []installEntry
	for i := 0; i < len(tokens); i++ {
		if i > 0 && !isSeparatorToken(tokens[i-1]) {
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
			token := tokens[j]
			if isSeparatorToken(token) {
				break
			}
			if strings.HasPrefix(token, "-") {
				option, value, hasValue := splitOption(token)
				if !hasValue && chocoOptionsWithValue[option] && j+1 < len(tokens) && !isSeparatorToken(tokens[j+1]) {
					j++
					value = tokens[j]
					hasValue = true
				}
				if option == "version" && hasValue {
					version = strings.TrimSpace(value)
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

// chocoCommandArgStart reports the index of the first argument after a choco
// install/upgrade verb starting at tokens[i], if tokens[i] begins one.
func chocoCommandArgStart(tokens []string, i int) (int, bool) {
	switch strings.ToLower(tokens[i]) {
	case "choco", "choco.exe":
		if i+1 >= len(tokens) {
			return 0, false
		}
		switch strings.ToLower(tokens[i+1]) {
		case "install", "upgrade":
			return i + 2, true
		}
		return 0, false
	case "cinst", "cinst.exe", "cup", "cup.exe":
		return i + 1, true
	}
	return 0, false
}

// splitOption normalizes `--version=1.2`, `--version:1.2`, `-y`, `/y` style
// option tokens into (name, value, hasValue).
func splitOption(token string) (string, string, bool) {
	name := strings.TrimLeft(token, "-")
	if idx := strings.IndexAny(name, "=:"); idx >= 0 {
		return strings.ToLower(name[:idx]), strings.Trim(name[idx+1:], `"'`), true
	}
	return strings.ToLower(name), "", false
}

// tokenizeScriptLine splits a shell/PowerShell line into tokens: whitespace
// separates, single/double quotes group (quotes removed), the characters
// ; | & ( ) { } become standalone separator tokens, and an unquoted `#`
// starts a comment that ends the line.
func tokenizeScriptLine(line string) []string {
	var tokens []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	quote := rune(0)
	for _, ch := range line {
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				current.WriteRune(ch)
			}
		case ch == '"' || ch == '\'':
			quote = ch
		case ch == '#':
			flush()
			return tokens
		case ch == ' ' || ch == '\t' || ch == '\r':
			flush()
		case ch == ';' || ch == '|' || ch == '&' || ch == '(' || ch == ')' || ch == '{' || ch == '}':
			flush()
			tokens = append(tokens, string(ch))
		default:
			current.WriteRune(ch)
		}
	}
	flush()
	return tokens
}
