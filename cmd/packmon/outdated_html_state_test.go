package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	htmlnode "golang.org/x/net/html"
)

func TestOutdatedHTMLRendersMissingAndUnparseableTimestampFallbacks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		scannedAt        string
		scannedDateTime  string
		wantMetaText     string
		wantTime         bool
		wantTimeDateTime string
	}{
		{
			name:         "missing timestamp has no orphaned separator",
			wantMetaText: "Packmon Outdated Report · 1 package",
		},
		{
			name:         "unparseable display timestamp stays visible text",
			scannedAt:    `not-a-time <script>alert("timestamp")</script>`,
			wantMetaText: `Packmon Outdated Report · 1 package · not-a-time <script>alert("timestamp")</script>`,
		},
		{
			name:             "explicit invalid machine timestamp keeps a time fallback",
			scannedAt:        "invalid timestamp fallback",
			scannedDateTime:  `not-a-date" onmouseover="alert(1)`,
			wantMetaText:     "Packmon Outdated Report · 1 package · invalid timestamp fallback",
			wantTime:         true,
			wantTimeDateTime: `not-a-date" onmouseover="alert(1)`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := renderF040OutdatedDocument(t, outdatedReport{
				ScannedAt:         tt.scannedAt,
				ScannedAtDateTime: tt.scannedDateTime,
				Total:             1,
				PackageWord:       "package",
			})
			meta := f040SingleElementByClass(t, doc, "meta")
			if got := f040NormalizedText(meta); got != tt.wantMetaText {
				t.Fatalf("metadata text = %q, want %q", got, tt.wantMetaText)
			}
			times := f040ElementsByName(meta, "time")
			if tt.wantTime {
				if len(times) != 1 {
					t.Fatalf("metadata time element count = %d, want 1", len(times))
				}
				if got, _ := f040NodeAttr(times[0], "datetime"); got != tt.wantTimeDateTime {
					t.Fatalf("time datetime = %q, want %q", got, tt.wantTimeDateTime)
				}
				return
			}
			if len(times) != 0 {
				t.Fatalf("metadata contains %d time element(s), want none", len(times))
			}
		})
	}
}

func TestOutdatedHTMLRendersAllCurrentEmptyStateWithoutOutdatedViews(t *testing.T) {
	t.Parallel()

	doc := renderF040OutdatedDocument(t, outdatedReport{
		Total:       3,
		UpToDate:    3,
		Unknown:     0,
		LockFiles:   2,
		SBOMFiles:   1,
		PackageWord: "packages",
	})

	badges := f040ElementsByClass(doc, "badge")
	if len(badges) != 3 {
		t.Fatalf("summary badge count = %d, want 3", len(badges))
	}
	wantBadges := []string{"0 outdated", "3 up to date", "0 unknown"}
	for i, want := range wantBadges {
		if got := f040NormalizedText(badges[i]); got != want {
			t.Errorf("badge %d text = %q, want %q", i, got, want)
		}
	}
	empty := f040SingleElementByClass(t, doc, "empty")
	if got := f040NormalizedText(empty); got != "All 3 packages are up to date." {
		t.Errorf("empty-state text = %q", got)
	}
	if f040HasClass(empty, "empty-unknown") {
		t.Error("all-current empty state unexpectedly has empty-unknown class")
	}
	for _, forbiddenClass := range []string{"provenance-legend", "mobile-list", "mobile-card", "table-scroll"} {
		if got := len(f040ElementsByClass(doc, forbiddenClass)); got != 0 {
			t.Errorf("all-current report renders %d .%s element(s)", got, forbiddenClass)
		}
	}
	for _, forbiddenElement := range []string{"table", "thead", "tbody", "th", "td"} {
		if got := len(f040ElementsByName(doc, forbiddenElement)); got != 0 {
			t.Errorf("all-current report renders %d <%s> element(s)", got, forbiddenElement)
		}
	}
	footer := f040SingleElementByClass(t, doc, "footer")
	if got := f040NormalizedText(footer); got != "2 lockfiles · 1 SBOM files" {
		t.Errorf("footer text = %q, want %q", got, "2 lockfiles · 1 SBOM files")
	}
}

func renderF040OutdatedDocument(t *testing.T, report outdatedReport) *htmlnode.Node {
	t.Helper()
	path := filepath.Join(t.TempDir(), "outdated.html")
	if err := writeOutdatedHTML(path, report); err != nil {
		t.Fatalf("write outdated HTML: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: test reads its own generated report.
	if err != nil {
		t.Fatalf("read outdated HTML: %v", err)
	}
	return parseF040HTMLDocument(t, data)
}

func parseF040HTMLDocument(t *testing.T, data []byte) *htmlnode.Node {
	t.Helper()
	doc, err := htmlnode.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse generated HTML: %v", err)
	}
	return doc
}

func f040ElementsByClass(root *htmlnode.Node, class string) []*htmlnode.Node {
	var matches []*htmlnode.Node
	for _, node := range f040AllElements(root) {
		if f040HasClass(node, class) {
			matches = append(matches, node)
		}
	}
	return matches
}

func f040SingleElementByClass(t *testing.T, root *htmlnode.Node, class string) *htmlnode.Node {
	t.Helper()
	matches := f040ElementsByClass(root, class)
	if len(matches) != 1 {
		t.Fatalf(".%s element count = %d, want 1", class, len(matches))
	}
	return matches[0]
}

func f040HasClass(node *htmlnode.Node, class string) bool {
	value, ok := f040NodeAttr(node, "class")
	if !ok {
		return false
	}
	for _, field := range strings.Fields(value) {
		if field == class {
			return true
		}
	}
	return false
}

func f040NodeAttr(node *htmlnode.Node, name string) (string, bool) {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return attr.Val, true
		}
	}
	return "", false
}

func f040NodeText(root *htmlnode.Node) string {
	var builder strings.Builder
	var walk func(*htmlnode.Node)
	walk = func(node *htmlnode.Node) {
		if node.Type == htmlnode.TextNode {
			builder.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return builder.String()
}

func f040NormalizedText(root *htmlnode.Node) string {
	return strings.Join(strings.Fields(f040NodeText(root)), " ")
}
