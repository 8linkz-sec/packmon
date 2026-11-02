package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	htmlnode "golang.org/x/net/html"
)

func TestOutdatedHTMLEscapesHostilePackageMetadata(t *testing.T) {
	t.Parallel()

	privateParent := filepath.Join(t.TempDir(), "private-student-123")
	target := filepath.Join(privateParent, "target-&-onload=alert(1)")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("create private target: %v", err)
	}
	lockRelative := filepath.Join("nested", `lock-<img src=javascript:alert(9) onerror=steal()>.json`)
	lockAbsolute := filepath.Join(target, lockRelative)
	values := map[string]string{
		"target":    filepath.Base(target),
		"name":      `name-</h2><script>alert("name")</script>`,
		"installed": `installed-<svg onload=alert(2)>`,
		"latest":    `latest-" onmouseover=alert(3) x="`,
		"ecosystem": `ecosystem-<iframe src=javascript:alert(4)>`,
		"scope":     `scope-</dd><details open ontoggle=alert(5)>`,
		"relation":  `relation-<math href=javascript:alert(6)>`,
		"via":       `via-<video poster=https://user:password@example.invalid/x onerror=alert(7)>`,
		"flags":     `flags-<object data=javascript:alert(8)>`,
		"lockfile":  filepath.ToSlash(lockRelative),
	}
	report := outdatedReport{
		Target:      target,
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      values["name"],
			Installed: values["installed"],
			Latest:    values["latest"],
			Ecosystem: values["ecosystem"],
			Scope:     values["scope"],
			Relation:  values["relation"],
			Via:       values["via"],
			Flags:     values["flags"],
			LockFile:  lockAbsolute,
		}},
	}
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	if err := writeOutdatedHTML(htmlPath, report); err != nil {
		t.Fatalf("write outdated HTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) //nolint:gosec // G304: test reads its own generated report.
	if err != nil {
		t.Fatalf("read outdated HTML: %v", err)
	}
	doc := parseF040HTMLDocument(t, data)
	visible := f040NodeText(doc)
	for field, value := range values {
		if !strings.Contains(visible, value) {
			t.Errorf("decoded visible HTML missing hostile %s value %q", field, value)
		}
	}

	wantElementCounts := map[string]int{"script": 1, "details": 1, "summary": 1}
	for name, want := range wantElementCounts {
		if got := len(f040ElementsByName(doc, name)); got != want {
			t.Errorf("generated HTML %s element count = %d, want %d", name, got, want)
		}
	}
	script := f040ElementsByName(doc, "script")[0]
	wantScriptBody := strings.TrimSuffix(strings.TrimPrefix(generatedHTMLReportLocaleScript, "<script>"), "</script>")
	if got := f040NodeText(script); got != wantScriptBody {
		t.Error("generated HTML's sole script is not the byte-identical locale script")
	}
	summary := f040ElementsByName(doc, "summary")[0]
	if summary.Parent == nil || summary.Parent.Data != "details" || f040NormalizedText(summary) != "Provenance and source" {
		t.Errorf("generated HTML summary is not the legitimate provenance disclosure: parent=%v text=%q", summary.Parent, f040NormalizedText(summary))
	}
	for _, forbidden := range []string{"img", "svg", "iframe", "object", "video", "math", "a"} {
		if got := len(f040ElementsByName(doc, forbidden)); got != 0 {
			t.Errorf("generated HTML contains %d attacker-created <%s> element(s)", got, forbidden)
		}
	}
	for _, node := range f040AllElements(doc) {
		for _, attr := range node.Attr {
			name := strings.ToLower(attr.Key)
			if strings.HasPrefix(name, "on") {
				t.Errorf("generated <%s> contains event-handler attribute %s=%q", node.Data, attr.Key, attr.Val)
			}
			if f040URLAttribute(name) {
				t.Errorf("generated <%s> contains unexpected URL attribute %s=%q", node.Data, attr.Key, attr.Val)
			}
		}
	}

	out := string(data)
	for _, private := range []string{
		privateParent,
		filepath.ToSlash(privateParent),
		target,
		filepath.ToSlash(target),
		lockAbsolute,
		filepath.ToSlash(lockAbsolute),
		"private-student-123",
	} {
		if strings.Contains(out, private) {
			t.Errorf("generated HTML leaked private path fragment %q", private)
		}
	}
}

func f040URLAttribute(name string) bool {
	switch name {
	case "action", "formaction", "href", "poster", "src", "xlink:href":
		return true
	default:
		return false
	}
}

func f040AllElements(root *htmlnode.Node) []*htmlnode.Node {
	var elements []*htmlnode.Node
	var walk func(*htmlnode.Node)
	walk = func(node *htmlnode.Node) {
		if node.Type == htmlnode.ElementNode {
			elements = append(elements, node)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return elements
}

func f040ElementsByName(root *htmlnode.Node, name string) []*htmlnode.Node {
	var matches []*htmlnode.Node
	for _, node := range f040AllElements(root) {
		if node.Data == name {
			matches = append(matches, node)
		}
	}
	return matches
}
