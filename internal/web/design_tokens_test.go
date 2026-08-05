package web

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Raw Tailwind palette classes (bg-gray-50, text-red-700, ...) bypass the
// design tokens in tailwind.input.css. A page that uses them stays light when
// the user picks the dark theme, because dark mode is a token override, not a
// `dark:` variant. This guard keeps the migration from rotting: 716 such
// classes were removed in one pass, and a single new one would reintroduce the
// split.
//
// Templates and the Go files that emit class strings are both in scope.

var rawColorClassPattern = regexp.MustCompile(
	`\b(?:[a-z-]+:)*(?:bg|text|border|ring|divide|placeholder|from|via|to|outline|shadow|accent|caret|fill|stroke)-` +
		`(?:gray|slate|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|white|black)` +
		`(?:-(?:\d{2,3}))?\b`,
)

func TestTemplatesUseDesignTokensNotRawPaletteClasses(t *testing.T) {
	t.Parallel()

	var offenders []string

	err := filepath.WalkDir("templates", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		offenders = append(offenders, rawColorClassOffenders(t, path)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}

	if len(offenders) > 0 {
		t.Fatalf("templates use %d raw palette class(es); use semantic tokens (bg-surface, text-muted, ...):\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}

// render.go and the admin handlers build class strings in Go. They are compiled
// into the same pages and must follow the same rule.
func TestGoSourcesUseDesignTokensNotRawPaletteClasses(t *testing.T) {
	t.Parallel()

	var offenders []string
	for _, dir := range []string{".", filepath.Join("..", "api", "admin")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			offenders = append(offenders, rawColorClassOffenders(t, filepath.Join(dir, name))...)
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("Go sources emit %d raw palette class(es); use semantic tokens:\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}

// rawColorClassOffenders returns "path:line: class" for each raw palette class.
// Lines that only mention a class inside a comment still count: a commented-out
// class is a class waiting to be pasted back in.
func rawColorClassOffenders(t *testing.T, path string) []string {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // test-only read of repository sources.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var offenders []string
	for i, line := range strings.Split(string(data), "\n") {
		for _, match := range rawColorClassPattern.FindAllString(line, -1) {
			// CSS variables (var(--color-gray-200)) and Go identifiers are not
			// class names; the word boundary already excludes them, but the
			// dark-mode documentation comment mentions one on purpose.
			if strings.Contains(line, "var(--color-") || strings.Contains(line, "used to live here") {
				continue
			}
			offenders = append(offenders, fmt.Sprintf("%s:%d: %s", path, i+1, match))
		}
	}
	return offenders
}
