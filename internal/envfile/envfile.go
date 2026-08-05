// Package envfile reads, merges, and atomically writes .env files while
// preserving key order and comments. Output is always UTF-8 without BOM and
// LF-terminated, so files written inside a Linux container are correct on
// every host OS.
package envfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Entry is one line of a .env file. Comment and blank lines have Key == "" and
// carry their original text in Raw. Key/value lines have Key set.
type Entry struct {
	Key   string
	Value string
	Raw   string
}

// Parse splits data into entries, preserving order and non-assignment lines.
func Parse(data []byte) []Entry {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	// A trailing newline yields a final empty element; drop it so Render round-trips.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	entries := make([]Entry, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		eq := strings.Index(line, "=")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || eq < 0 {
			entries = append(entries, Entry{Raw: line})
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if key == "" {
			entries = append(entries, Entry{Raw: line})
			continue
		}
		entries = append(entries, Entry{Key: key, Value: strings.TrimSpace(line[eq+1:])})
	}
	return entries
}

// Value returns the value for key and whether it was present.
func Value(entries []Entry, key string) (string, bool) {
	for _, e := range entries {
		if e.Key == key {
			return e.Value, true
		}
	}
	return "", false
}

// Upsert updates key in place or appends it if absent.
func Upsert(entries []Entry, key, value string) []Entry {
	for i := range entries {
		if entries[i].Key == key {
			entries[i].Value = value
			return entries
		}
	}
	return append(entries, Entry{Key: key, Value: value})
}

// Render serializes entries with LF endings and no BOM.
func Render(entries []Entry) []byte {
	var b bytes.Buffer
	for _, e := range entries {
		if e.Key == "" {
			b.WriteString(e.Raw)
		} else {
			b.WriteString(e.Key)
			b.WriteByte('=')
			b.WriteString(e.Value)
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// IsBlank reports whether a value counts as unset: empty, whitespace-only, or a
// bare empty quote pair.
func IsBlank(value string) bool {
	v := strings.TrimSpace(value)
	return v == "" || v == `""` || v == `''`
}

// Load reads path into entries. A missing file returns (nil, nil).
func Load(path string) ([]Entry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-controlled local path.
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(data), nil
}

// WriteAtomic writes data to path via a temp file in the same directory plus a
// rename, so readers never observe a half-written file.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".env-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
